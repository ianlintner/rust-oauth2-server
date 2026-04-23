use actix::prelude::*;
use lru::LruCache;
use oauth2_events::{AuthEvent, EventBusHandle, EventEnvelope, EventSeverity, EventType};
use oauth2_observability::annotate_span_with_trace_ids;
use oauth2_ports::DynStorage;
use rand::{Rng, SeedableRng};
use std::num::NonZeroUsize;
use std::time::{Duration, Instant};
use tracing::Instrument;

use oauth2_core::{Client, ClientRegistration, OAuth2Error};

const CLIENT_CACHE_MAX_ENTRIES: usize = 10_000;
const CLIENT_CACHE_TTL_SECS: u64 = 300; // 5 minutes
#[cfg(feature = "redis-cache")]
const REDIS_CLIENT_PREFIX: &str = "oauth2:client:";

struct CachedClient {
    client: Client,
    inserted_at: Instant,
}

/// Optional Redis connection for L2 caching behind the in-process LRU.
#[cfg(feature = "redis-cache")]
type ClientRedisConn = Option<oauth2_observability::TracedRedis>;
#[cfg(not(feature = "redis-cache"))]
type ClientRedisConn = ();

pub struct ClientActor {
    db: DynStorage,
    event_bus: Option<EventBusHandle>,
    cache: LruCache<String, CachedClient>,
    cache_ttl: Duration,
    #[allow(dead_code)]
    redis: ClientRedisConn,
}

impl ClientActor {
    pub fn new(db: DynStorage) -> Self {
        Self {
            db,
            event_bus: None,
            cache: LruCache::new(NonZeroUsize::new(CLIENT_CACHE_MAX_ENTRIES).expect("non-zero")),
            cache_ttl: Duration::from_secs(CLIENT_CACHE_TTL_SECS),
            redis: Default::default(),
        }
    }

    pub fn with_events(db: DynStorage, event_bus: EventBusHandle) -> Self {
        Self {
            db,
            event_bus: Some(event_bus),
            cache: LruCache::new(NonZeroUsize::new(CLIENT_CACHE_MAX_ENTRIES).expect("non-zero")),
            cache_ttl: Duration::from_secs(CLIENT_CACHE_TTL_SECS),
            redis: Default::default(),
        }
    }

    /// Attach a Redis connection manager for L2 caching. The handle is
    /// wrapped in [`oauth2_observability::TracedRedis`] so each Redis command
    /// emits an OTel-semconv `redis.command` child span.
    #[cfg(feature = "redis-cache")]
    pub fn with_redis(mut self, conn: oauth2_observability::TracedRedis) -> Self {
        self.redis = Some(conn);
        self
    }

    fn get_cached_client(&mut self, client_id: &str) -> Option<Client> {
        let ttl = self.cache_ttl;
        let entry = self.cache.get(client_id);
        match entry {
            Some(cached) if cached.inserted_at.elapsed() < ttl => Some(cached.client.clone()),
            Some(_) => {
                // Expired — evict eagerly.
                self.cache.pop(client_id);
                None
            }
            None => None,
        }
    }

    fn insert_cached_client(&mut self, client: Client) {
        self.cache.put(
            client.client_id.clone(),
            CachedClient {
                client,
                inserted_at: Instant::now(),
            },
        );
    }
}

impl Actor for ClientActor {
    type Context = Context<Self>;
}

#[derive(Message)]
#[rtype(result = "Result<Client, OAuth2Error>")]
pub struct RegisterClient {
    pub registration: ClientRegistration,
    pub span: tracing::Span,
}

/// Internal message to insert a client into the LRU cache from an async context.
#[derive(Message)]
#[rtype(result = "()")]
pub struct CacheClient {
    pub client: Client,
}

impl Handler<CacheClient> for ClientActor {
    type Result = ();

    fn handle(&mut self, msg: CacheClient, _: &mut Self::Context) {
        self.insert_cached_client(msg.client);
    }
}

impl Handler<RegisterClient> for ClientActor {
    type Result = ResponseFuture<Result<Client, OAuth2Error>>;

    fn handle(&mut self, msg: RegisterClient, ctx: &mut Self::Context) -> Self::Result {
        let db = self.db.clone();
        let event_bus = self.event_bus.clone();
        let self_addr = ctx.address();

        let parent_span = msg.span.clone();
        let actor_span = tracing::info_span!(
            parent: &parent_span,
            "actor.client.register",
            trace_id = tracing::field::Empty,
            span_id = tracing::field::Empty,
            client_name = %msg.registration.client_name,
            scope = %msg.registration.scope
        );
        annotate_span_with_trace_ids(&actor_span);

        Box::pin(
            async move {
                // Generate client credentials.
                // Public clients (`token_endpoint_auth_method == "none"`) receive a
                // placeholder secret that is never checked; they authenticate via PKCE.
                let client_id = format!("client_{}", uuid::Uuid::new_v4());
                let is_public = msg.registration.token_endpoint_auth_method == "none";
                let client_secret = if is_public {
                    String::new()
                } else {
                    generate_secret()
                };

                let mut client = Client::new(
                    client_id.clone(),
                    client_secret,
                    msg.registration.redirect_uris,
                    msg.registration.grant_types,
                    msg.registration.scope.clone(),
                    msg.registration.client_name.clone(),
                );
                client.token_endpoint_auth_method =
                    msg.registration.token_endpoint_auth_method.clone();

                // RFC 7591 metadata fields
                if !msg.registration.response_types.is_empty() {
                    client.response_types =
                        serde_json::to_string(&msg.registration.response_types).unwrap_or_default();
                }
                if !msg.registration.contacts.is_empty() {
                    client.contacts =
                        serde_json::to_string(&msg.registration.contacts).unwrap_or_default();
                }
                if let Some(ref uri) = msg.registration.logo_uri {
                    client.logo_uri = uri.clone();
                }
                if let Some(ref uri) = msg.registration.client_uri {
                    client.client_uri = uri.clone();
                }
                if let Some(ref uri) = msg.registration.policy_uri {
                    client.policy_uri = uri.clone();
                }
                if let Some(ref uri) = msg.registration.tos_uri {
                    client.tos_uri = uri.clone();
                }
                if let Some(ref jwks_val) = msg.registration.jwks {
                    client.jwks = serde_json::to_string(jwks_val).unwrap_or_default();
                }
                if let Some(ref uri) = msg.registration.jwks_uri {
                    client.jwks_uri = uri.clone();
                }

                // OIDC logout metadata
                if let Some(ref uri) = msg.registration.backchannel_logout_uri {
                    client.backchannel_logout_uri = uri.clone();
                }
                if let Some(val) = msg.registration.backchannel_logout_session_required {
                    client.backchannel_logout_session_required = val;
                }
                if let Some(ref uri) = msg.registration.frontchannel_logout_uri {
                    client.frontchannel_logout_uri = uri.clone();
                }
                if let Some(val) = msg.registration.frontchannel_logout_session_required {
                    client.frontchannel_logout_session_required = val;
                }
                if let Some(ref uris) = msg.registration.post_logout_redirect_uris {
                    client.post_logout_redirect_uris =
                        serde_json::to_string(uris).unwrap_or_default();
                }
                // RFC 8705 §2.1.2: TLS client certificate subject DN
                client.tls_client_certificate_subject_dn = msg
                    .registration
                    .tls_client_certificate_subject_dn
                    .clone()
                    .unwrap_or_default();

                // Generate a registration_access_token for RFC 7591 §3.2
                client.registration_access_token = generate_secret_of_length(48);

                db.save_client(&client).await?;

                // Send back to actor for LRU cache insertion.
                let _ = self_addr.try_send(CacheClient {
                    client: client.clone(),
                });

                // Emit event
                if let Some(event_bus) = event_bus {
                    let event = AuthEvent::new(
                        EventType::ClientRegistered,
                        EventSeverity::Info,
                        None,
                        Some(client_id),
                    )
                    .with_metadata("client_name", msg.registration.client_name)
                    .with_metadata("scope", msg.registration.scope);

                    let envelope = EventEnvelope::from_current_span(event, "oauth2_server");
                    event_bus.publish_best_effort(envelope);
                }

                Ok(client)
            }
            .instrument(actor_span),
        )
    }
}

#[derive(Message)]
#[rtype(result = "Result<Client, OAuth2Error>")]
pub struct GetClient {
    pub client_id: String,
    pub span: tracing::Span,
}

impl Handler<GetClient> for ClientActor {
    type Result = ResponseFuture<Result<Client, OAuth2Error>>;

    fn handle(&mut self, msg: GetClient, ctx: &mut Self::Context) -> Self::Result {
        let db = self.db.clone();
        let requested_client_id = msg.client_id.clone();

        let parent_span = msg.span.clone();
        let actor_span = tracing::info_span!(
            parent: &parent_span,
            "actor.client.get",
            trace_id = tracing::field::Empty,
            span_id = tracing::field::Empty,
            client_id = %msg.client_id
        );
        annotate_span_with_trace_ids(&actor_span);

        // Check the LRU cache synchronously before going async.
        let cached = self.get_cached_client(&requested_client_id);
        let self_addr = ctx.address();

        #[cfg(feature = "redis-cache")]
        let redis_conn = self.redis.clone();
        #[cfg(feature = "redis-cache")]
        let cache_ttl_secs = self.cache_ttl.as_secs().max(1);

        Box::pin(
            async move {
                if let Some(client) = cached {
                    tracing::debug!(cache = "hit", layer = "L1", "Client found in cache");
                    return Ok(client);
                }

                // L2: Check Redis cache.
                #[cfg(feature = "redis-cache")]
                if let Some(ref mut conn) = redis_conn.clone() {
                    let redis_key = format!("{}{}", REDIS_CLIENT_PREFIX, requested_client_id);
                    let redis_result: Result<Option<String>, _> = conn.get(&redis_key).await;
                    if let Ok(Some(json)) = redis_result {
                        if let Ok(client) = serde_json::from_str::<Client>(&json) {
                            tracing::debug!(
                                cache = "hit",
                                layer = "L2",
                                "Client found in Redis cache"
                            );
                            let _ = self_addr.try_send(CacheClient {
                                client: client.clone(),
                            });
                            return Ok(client);
                        }
                    }
                }

                let client = db
                    .get_client(&requested_client_id)
                    .await?
                    .ok_or_else(|| OAuth2Error::invalid_client("Client not found"))?;

                // Write to Redis L2.
                #[cfg(feature = "redis-cache")]
                if let Some(ref mut conn) = redis_conn.clone() {
                    let redis_key = format!("{}{}", REDIS_CLIENT_PREFIX, requested_client_id);
                    if let Ok(json) = serde_json::to_string(&client) {
                        let _: Result<(), _> = conn.set_ex(&redis_key, json, cache_ttl_secs).await;
                    }
                }

                let _ = self_addr.try_send(CacheClient {
                    client: client.clone(),
                });

                Ok(client)
            }
            .instrument(actor_span),
        )
    }
}

#[derive(Message)]
#[rtype(result = "Result<bool, OAuth2Error>")]
pub struct ValidateClient {
    pub client_id: String,
    pub client_secret: String,
    pub span: tracing::Span,
}

impl Handler<ValidateClient> for ClientActor {
    type Result = ResponseFuture<Result<bool, OAuth2Error>>;

    fn handle(&mut self, msg: ValidateClient, ctx: &mut Self::Context) -> Self::Result {
        let db = self.db.clone();
        let event_bus = self.event_bus.clone();
        let requested_client_id = msg.client_id.clone();
        let presented_secret = msg.client_secret.clone();

        let parent_span = msg.span.clone();
        let actor_span = tracing::info_span!(
            parent: &parent_span,
            "actor.client.validate",
            trace_id = tracing::field::Empty,
            span_id = tracing::field::Empty,
            client_id = %msg.client_id
        );
        annotate_span_with_trace_ids(&actor_span);

        // Check the LRU cache synchronously.
        let cached = self.get_cached_client(&requested_client_id);
        let self_addr = ctx.address();

        #[cfg(feature = "redis-cache")]
        let redis_conn = self.redis.clone();
        #[cfg(feature = "redis-cache")]
        let cache_ttl_secs = self.cache_ttl.as_secs().max(1);

        Box::pin(
            async move {
                let client = if let Some(client) = cached {
                    tracing::debug!(
                        cache = "hit",
                        layer = "L1",
                        "Client found in validation cache"
                    );
                    client
                } else {
                    // L2: Check Redis cache.
                    #[allow(unused_mut)]
                    let mut from_redis = None;
                    #[cfg(feature = "redis-cache")]
                    if let Some(ref mut conn) = redis_conn.clone() {
                        let redis_key = format!("{}{}", REDIS_CLIENT_PREFIX, requested_client_id);
                        let redis_result: Result<Option<String>, _> = conn.get(&redis_key).await;
                        if let Ok(Some(json)) = redis_result {
                            if let Ok(client) = serde_json::from_str::<Client>(&json) {
                                tracing::debug!(
                                    cache = "hit",
                                    layer = "L2",
                                    "Client found in Redis validation cache"
                                );
                                let _ = self_addr.try_send(CacheClient {
                                    client: client.clone(),
                                });
                                from_redis = Some(client);
                            }
                        }
                    }

                    if let Some(client) = from_redis {
                        client
                    } else {
                        let fetched = db
                            .get_client(&requested_client_id)
                            .await?
                            .ok_or_else(|| OAuth2Error::invalid_client("Client not found"))?;

                        // Write to Redis L2.
                        #[cfg(feature = "redis-cache")]
                        if let Some(ref mut conn) = redis_conn.clone() {
                            let redis_key =
                                format!("{}{}", REDIS_CLIENT_PREFIX, requested_client_id);
                            if let Ok(json) = serde_json::to_string(&fetched) {
                                let _: Result<(), _> =
                                    conn.set_ex(&redis_key, json, cache_ttl_secs).await;
                            }
                        }

                        let _ = self_addr.try_send(CacheClient {
                            client: fetched.clone(),
                        });
                        fetched
                    }
                };

                // Use constant-time comparison to prevent timing attacks
                use subtle::ConstantTimeEq;
                let secret_match = client
                    .client_secret
                    .as_bytes()
                    .ct_eq(presented_secret.as_bytes())
                    .into();

                // Emit event
                if let Some(event_bus) = event_bus {
                    let event = AuthEvent::new(
                        EventType::ClientValidated,
                        EventSeverity::Info,
                        None,
                        Some(requested_client_id),
                    )
                    .with_metadata("success", if secret_match { "true" } else { "false" });

                    let envelope = EventEnvelope::from_current_span(event, "oauth2_server");
                    event_bus.publish_best_effort(envelope);
                }

                Ok(secret_match)
            }
            .instrument(actor_span),
        )
    }
}

// ---------------------------------------------------------------------------
// UpdateClient — RFC 7592 client update
// ---------------------------------------------------------------------------

#[derive(Message)]
#[rtype(result = "Result<Client, OAuth2Error>")]
pub struct UpdateClient {
    pub client: Client,
    pub span: tracing::Span,
}

impl Handler<UpdateClient> for ClientActor {
    type Result = ResponseFuture<Result<Client, OAuth2Error>>;

    fn handle(&mut self, msg: UpdateClient, ctx: &mut Self::Context) -> Self::Result {
        let db = self.db.clone();
        let self_addr = ctx.address();

        let parent_span = msg.span.clone();
        let actor_span = tracing::info_span!(
            parent: &parent_span,
            "actor.client.update",
            trace_id = tracing::field::Empty,
            span_id = tracing::field::Empty,
            client_id = %msg.client.client_id
        );
        annotate_span_with_trace_ids(&actor_span);

        Box::pin(
            async move {
                db.update_client(&msg.client).await?;

                let _ = self_addr.try_send(CacheClient {
                    client: msg.client.clone(),
                });

                Ok(msg.client)
            }
            .instrument(actor_span),
        )
    }
}

// ---------------------------------------------------------------------------
// DeleteClient — RFC 7592 client deletion
// ---------------------------------------------------------------------------

#[derive(Message)]
#[rtype(result = "Result<(), OAuth2Error>")]
pub struct DeleteClient {
    pub client_id: String,
    pub span: tracing::Span,
}

impl Handler<DeleteClient> for ClientActor {
    type Result = ResponseFuture<Result<(), OAuth2Error>>;

    fn handle(&mut self, msg: DeleteClient, _ctx: &mut Self::Context) -> Self::Result {
        let db = self.db.clone();
        let client_id = msg.client_id.clone();

        let parent_span = msg.span.clone();
        let actor_span = tracing::info_span!(
            parent: &parent_span,
            "actor.client.delete",
            trace_id = tracing::field::Empty,
            span_id = tracing::field::Empty,
            client_id = %msg.client_id
        );
        annotate_span_with_trace_ids(&actor_span);

        // Evict from LRU cache eagerly.
        self.cache.pop(&client_id);

        Box::pin(
            async move {
                db.delete_client(&client_id).await?;
                Ok(())
            }
            .instrument(actor_span),
        )
    }
}

fn generate_secret() -> String {
    generate_secret_of_length(32)
}

fn generate_secret_of_length(len: usize) -> String {
    let mut rng = rand::rngs::StdRng::from_os_rng();
    (0..len)
        .map(|_| {
            let idx = rng.random_range(0..62);
            match idx {
                0..=25 => (b'a' + idx) as char,
                26..=51 => (b'A' + (idx - 26)) as char,
                _ => (b'0' + (idx - 52)) as char,
            }
        })
        .collect()
}
