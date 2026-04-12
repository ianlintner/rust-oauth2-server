use actix::prelude::*;
use lru::LruCache;
use oauth2_events::{AuthEvent, EventBusHandle, EventEnvelope, EventSeverity, EventType};
use oauth2_observability::annotate_span_with_trace_ids;
use oauth2_ports::DynStorage;
use rand::Rng;
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
type ClientRedisConn = Option<redis::aio::ConnectionManager>;
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

    /// Attach a Redis connection manager for L2 caching.
    #[cfg(feature = "redis-cache")]
    pub fn with_redis(mut self, conn: redis::aio::ConnectionManager) -> Self {
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
                    let redis_result: Result<Option<String>, _> =
                        redis::cmd("GET").arg(&redis_key).query_async(conn).await;
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
                        let _: Result<(), _> = redis::cmd("SET")
                            .arg(&redis_key)
                            .arg(&json)
                            .arg("EX")
                            .arg(cache_ttl_secs)
                            .query_async(conn)
                            .await;
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
                        let redis_result: Result<Option<String>, _> =
                            redis::cmd("GET").arg(&redis_key).query_async(conn).await;
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
                                let _: Result<(), _> = redis::cmd("SET")
                                    .arg(&redis_key)
                                    .arg(&json)
                                    .arg("EX")
                                    .arg(cache_ttl_secs)
                                    .query_async(conn)
                                    .await;
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

fn generate_secret() -> String {
    let mut rng = rand::rng();
    let secret: String = (0..32)
        .map(|_| {
            let idx = rng.random_range(0..62);
            match idx {
                0..=25 => (b'a' + idx) as char,
                26..=51 => (b'A' + (idx - 26)) as char,
                _ => (b'0' + (idx - 52)) as char,
            }
        })
        .collect();
    secret
}
