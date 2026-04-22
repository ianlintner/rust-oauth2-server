use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::Instant;

use actix::prelude::*;
use lru::LruCache;
use oauth2_core::models::key_set::{Algorithm as KeyAlgorithm, KeySet, SigningKey};
use oauth2_events::{AuthEvent, EventBusHandle, EventEnvelope, EventSeverity, EventType};
use oauth2_observability::annotate_span_with_trace_ids;
use oauth2_ports::DynStorage;
use tokio::sync::RwLock;
use tracing::Instrument;

use oauth2_core::{Claims, OAuth2Error, Token};

/// Default token validation cache TTL (60 seconds).
const TOKEN_CACHE_TTL_SECS: u64 = 60;
/// Default max entries in the token validation cache.
const TOKEN_CACHE_MAX_ENTRIES: usize = 10_000;
/// Default access token lifetime in seconds. Overridable via config
/// (`jwt.access_token_ttl_secs`) — see RFC 9700 §2.3.
const DEFAULT_ACCESS_TOKEN_TTL_SECS: i64 = 3600;
/// Default refresh token lifetime in seconds (30 days). Overridable via
/// config (`jwt.refresh_token_ttl_secs`).
const DEFAULT_REFRESH_TOKEN_TTL_SECS: i64 = 2_592_000;
/// Redis key prefix for the L2 token cache.
#[cfg(feature = "redis-cache")]
const REDIS_TOKEN_PREFIX: &str = "oauth2:token:";

struct CachedToken {
    token: Token,
    inserted_at: Instant,
}

/// Optional Redis connection for L2 caching behind the in-process LRU.
#[cfg(feature = "redis-cache")]
type RedisConn = Option<oauth2_observability::TracedRedis>;
#[cfg(not(feature = "redis-cache"))]
type RedisConn = ();

pub struct TokenActor {
    db: DynStorage,
    jwt_secret: String,
    /// Issuer URL included in JWT `iss` claims (RFC 9068 §2.2 / RFC 7519 §4.1.1).
    issuer: String,
    access_tokens_opaque: bool,
    event_bus: Option<EventBusHandle>,
    keyset: Option<Arc<RwLock<KeySet>>>,
    /// In-process LRU cache for validated tokens, keyed by access_token string.
    /// Each entry has a TTL; expired entries are treated as cache misses.
    token_cache: LruCache<String, CachedToken>,
    token_cache_ttl: std::time::Duration,
    /// Optional Redis L2 cache behind the in-process LRU.
    #[allow(dead_code)]
    redis: RedisConn,
    /// Access token lifetime in seconds (RFC 9700 §2.3).
    access_token_ttl_secs: i64,
    /// Refresh token lifetime in seconds.
    refresh_token_ttl_secs: i64,
}

impl TokenActor {
    pub fn new(db: DynStorage, jwt_secret: String, issuer: String) -> Self {
        Self {
            db,
            jwt_secret,
            issuer,
            access_tokens_opaque: false,
            event_bus: None,
            keyset: None,
            token_cache: LruCache::new(NonZeroUsize::new(TOKEN_CACHE_MAX_ENTRIES).unwrap()),
            token_cache_ttl: std::time::Duration::from_secs(TOKEN_CACHE_TTL_SECS),
            redis: Default::default(),
            access_token_ttl_secs: DEFAULT_ACCESS_TOKEN_TTL_SECS,
            refresh_token_ttl_secs: DEFAULT_REFRESH_TOKEN_TTL_SECS,
        }
    }

    pub fn with_events(
        db: DynStorage,
        jwt_secret: String,
        issuer: String,
        event_bus: EventBusHandle,
    ) -> Self {
        Self {
            db,
            jwt_secret,
            issuer,
            access_tokens_opaque: false,
            event_bus: Some(event_bus),
            keyset: None,
            token_cache: LruCache::new(NonZeroUsize::new(TOKEN_CACHE_MAX_ENTRIES).unwrap()),
            token_cache_ttl: std::time::Duration::from_secs(TOKEN_CACHE_TTL_SECS),
            redis: Default::default(),
            access_token_ttl_secs: DEFAULT_ACCESS_TOKEN_TTL_SECS,
            refresh_token_ttl_secs: DEFAULT_REFRESH_TOKEN_TTL_SECS,
        }
    }

    /// Configure access and refresh token lifetimes. Callers that do not
    /// invoke this method retain the 1-hour access / 30-day refresh defaults.
    pub fn with_token_ttls(mut self, access_ttl_secs: i64, refresh_ttl_secs: i64) -> Self {
        self.access_token_ttl_secs = access_ttl_secs;
        self.refresh_token_ttl_secs = refresh_ttl_secs;
        self
    }

    pub fn with_keyset(mut self, keyset: Arc<RwLock<KeySet>>) -> Self {
        self.keyset = Some(keyset);
        self
    }

    /// Enable/disable opaque (reference-style) access token issuance.
    pub fn with_access_tokens_opaque(mut self, enabled: bool) -> Self {
        self.access_tokens_opaque = enabled;
        self
    }

    /// Attach a Redis connection manager for L2 caching. The connection is
    /// wrapped in [`oauth2_observability::TracedRedis`] so every Redis command
    /// issued against it emits an OTel-semconv `redis.command` child span of
    /// the surrounding HTTP/actor span.
    #[cfg(feature = "redis-cache")]
    pub fn with_redis(mut self, conn: oauth2_observability::TracedRedis) -> Self {
        self.redis = Some(conn);
        self
    }

    /// Normalize a token key the same way `ValidateToken` does so that
    /// cache lookups, insertions, and invalidations all use the same key.
    fn normalize_token_key(raw: &str) -> String {
        let trimmed = raw.trim();
        trimmed
            .strip_prefix("Bearer ")
            .unwrap_or(trimmed)
            .trim()
            .to_string()
    }

    /// Invalidate a cached token (called on revoke).
    fn invalidate_cached_token(&mut self, access_token: &str) {
        let key = Self::normalize_token_key(access_token);
        self.token_cache.pop(&key);
    }
}

impl Actor for TokenActor {
    type Context = Context<Self>;
}

#[derive(Message)]
#[rtype(result = "Result<Token, OAuth2Error>")]
pub struct CreateToken {
    pub user_id: Option<String>,
    pub client_id: String,
    pub scope: String,
    pub include_refresh: bool,
    pub token_family: Option<String>,
    /// RFC 8707: resource indicator URI. When set, overrides the JWT `aud` claim
    /// from `client_id` to the specified resource server URI.
    pub resource: Option<String>,
    /// RFC 9449 / RFC 8705: confirmation claim (`cnf`) to bind the token to a key.
    /// Set to `{"jkt": "<base64url thumbprint>"}` for DPoP or `{"x5t#S256": "..."}` for mTLS.
    pub cnf: Option<serde_json::Value>,
    /// RFC 9396: Rich Authorization Request details to embed in the JWT.
    pub authorization_details: Option<serde_json::Value>,
    pub span: tracing::Span,
}

impl Handler<CreateToken> for TokenActor {
    type Result = ResponseFuture<Result<Token, OAuth2Error>>;

    fn handle(&mut self, msg: CreateToken, _: &mut Self::Context) -> Self::Result {
        let db = self.db.clone();
        let jwt_secret = self.jwt_secret.clone();
        let issuer = self.issuer.clone();
        let event_bus = self.event_bus.clone();
        let keyset = self.keyset.clone();
        let access_tokens_opaque = self.access_tokens_opaque;
        let access_token_ttl_secs = self.access_token_ttl_secs;
        let refresh_token_ttl_secs = self.refresh_token_ttl_secs;

        let parent_span = msg.span.clone();
        let actor_span = tracing::info_span!(
            parent: &parent_span,
            "actor.token.create",
            trace_id = tracing::field::Empty,
            span_id = tracing::field::Empty,
            client_id = %msg.client_id,
            user_id = %msg.user_id.as_deref().unwrap_or(""),
            include_refresh = msg.include_refresh
        );
        annotate_span_with_trace_ids(&actor_span);

        Box::pin(
            async move {
                let subject = msg.user_id.clone().unwrap_or_else(|| msg.client_id.clone());

                // Resolve signing key once for both access and refresh tokens.
                // Prefer RS256 (asymmetric) when available, then fall back to HS256
                // from the KeySet. If neither is found, use the jwt_secret directly.
                let signing_key: Option<SigningKey> = if let Some(ref ks_lock) = keyset {
                    let ks = ks_lock.read().await;
                    let key = ks
                        .current_for_alg(KeyAlgorithm::RS256)
                        .or_else(|| ks.current_for_alg(KeyAlgorithm::HS256))
                        .cloned();
                    if key.is_none() {
                        tracing::warn!("KeySet has no current key; falling back to jwt_secret");
                    }
                    key
                } else {
                    None
                };

                // Create access token
                let access_token = if access_tokens_opaque {
                    // 256 bits of token material + human-friendly prefix.
                    // UUID v4 is RNG-backed; combining two gives high entropy.
                    format!(
                        "at_{}{}",
                        uuid::Uuid::new_v4().simple(),
                        uuid::Uuid::new_v4().simple()
                    )
                } else {
                    // RFC 8707: when a resource indicator is present, use it as `aud`.
                    let aud = msg
                        .resource
                        .clone()
                        .unwrap_or_else(|| msg.client_id.clone());
                    let mut access_claims = Claims::new(
                        subject.clone(),
                        aud.clone(),
                        msg.scope.clone(),
                        access_token_ttl_secs,
                        &issuer,
                    );
                    // Always preserve client_id claim even when aud is overridden.
                    access_claims.client_id = Some(msg.client_id.clone());
                    // RFC 9449 / RFC 8705: embed cnf (confirmation) claim if provided.
                    access_claims.cnf = msg.cnf.clone();
                    // RFC 9396: embed authorization_details if provided.
                    access_claims.authorization_details = msg.authorization_details.clone();

                    if let Some(ref key) = signing_key {
                        access_claims.encode_with_key(key)
                    } else {
                        access_claims.encode(&jwt_secret)
                    }
                    .map_err(|e| OAuth2Error::new("server_error", Some(&e.to_string())))?
                };

                // Create refresh token if requested
                let refresh_token = if msg.include_refresh {
                    let refresh_claims = Claims::new(
                        subject,
                        msg.client_id.clone(),
                        msg.scope.clone(),
                        refresh_token_ttl_secs,
                        &issuer,
                    );
                    let token = if let Some(ref key) = signing_key {
                        refresh_claims.encode_refresh_with_key(key)
                    } else {
                        refresh_claims.encode_refresh(&jwt_secret)
                    }
                    .map_err(|e| OAuth2Error::new("server_error", Some(&e.to_string())))?;
                    Some(token)
                } else {
                    None
                };

                let token = Token::new(
                    access_token,
                    refresh_token,
                    msg.client_id.clone(),
                    msg.user_id.clone(),
                    msg.scope.clone(),
                    access_token_ttl_secs as i32,
                    msg.token_family,
                );

                db.save_token(&token).await?;

                // Emit event
                if let Some(event_bus) = event_bus {
                    let event = AuthEvent::new(
                        EventType::TokenCreated,
                        EventSeverity::Info,
                        msg.user_id,
                        Some(msg.client_id),
                    )
                    .with_metadata("scope", msg.scope)
                    .with_metadata("has_refresh_token", msg.include_refresh.to_string());

                    let envelope = EventEnvelope::from_current_span(event, "oauth2_server");
                    event_bus.publish_best_effort(envelope);
                }

                Ok(token)
            }
            .instrument(actor_span),
        )
    }
}

#[derive(Message)]
#[rtype(result = "Result<Token, OAuth2Error>")]
pub struct ValidateToken {
    pub token: String,
    pub span: tracing::Span,
}

#[derive(Message)]
#[rtype(result = "Result<Option<Token>, OAuth2Error>")]
pub struct LookupToken {
    pub token: String,
    pub span: tracing::Span,
}

impl Handler<LookupToken> for TokenActor {
    type Result = ResponseFuture<Result<Option<Token>, OAuth2Error>>;

    fn handle(&mut self, msg: LookupToken, _: &mut Self::Context) -> Self::Result {
        let db = self.db.clone();
        let normalized_token = Self::normalize_token_key(&msg.token);

        let parent_span = msg.span.clone();
        let actor_span = tracing::info_span!(
            parent: &parent_span,
            "actor.token.lookup",
            trace_id = tracing::field::Empty,
            span_id = tracing::field::Empty,
            token_prefix = %normalized_token.chars().take(12).collect::<String>(),
            token_len = normalized_token.len()
        );
        annotate_span_with_trace_ids(&actor_span);

        Box::pin(
            async move { db.get_token_by_access_token(&normalized_token).await }
                .instrument(actor_span),
        )
    }
}

impl Handler<ValidateToken> for TokenActor {
    type Result = ResponseFuture<Result<Token, OAuth2Error>>;

    fn handle(&mut self, msg: ValidateToken, ctx: &mut Self::Context) -> Self::Result {
        let db = self.db.clone();
        let event_bus = self.event_bus.clone();
        let parent_span = msg.span.clone();
        let raw_token = msg.token;
        let token_prefix = raw_token.trim().chars().take(12).collect::<String>();
        let actor_span = tracing::info_span!(
            parent: &parent_span,
            "actor.token.validate",
            trace_id = tracing::field::Empty,
            span_id = tracing::field::Empty,
            token_prefix = %token_prefix,
            token_len = raw_token.len()
        );
        annotate_span_with_trace_ids(&actor_span);

        // Check the in-process LRU cache before hitting the database.
        let token_normalized = Self::normalize_token_key(&raw_token);

        let cache_ttl = self.token_cache_ttl;
        let cached = self
            .token_cache
            .get(&token_normalized)
            .filter(|ct| ct.inserted_at.elapsed() < cache_ttl)
            .map(|ct| ct.token.clone());

        // Remove expired entry eagerly.
        if cached.is_none() {
            self.token_cache.pop(&token_normalized);
        }

        // Clone Redis connection for async block.
        #[cfg(feature = "redis-cache")]
        let redis_conn = self.redis.clone();
        #[cfg(feature = "redis-cache")]
        let redis_ttl_secs = cache_ttl.as_secs().max(1);

        // Capture the actor's own address so the async block can send a
        // CacheValidatedToken message back for insertion.
        let self_addr = ctx.address();

        Box::pin(
            async move {
                if let Some(token) = cached {
                    tracing::debug!(
                        cache = "hit",
                        layer = "L1",
                        "Token found in validation cache"
                    );
                    if !token.is_valid() {
                        return Err(OAuth2Error::invalid_grant("Token is expired or revoked"));
                    }
                    return Ok(token);
                }

                // L2: Check Redis cache before DB.
                #[cfg(feature = "redis-cache")]
                if let Some(ref mut conn) = redis_conn.clone() {
                    let redis_key = format!("{}{}", REDIS_TOKEN_PREFIX, token_normalized);
                    let redis_result: Result<Option<String>, _> = conn.get(&redis_key).await;
                    if let Ok(Some(json)) = redis_result {
                        if let Ok(token) = serde_json::from_str::<Token>(&json) {
                            tracing::debug!(
                                cache = "hit",
                                layer = "L2",
                                "Token found in Redis cache"
                            );
                            // Promote to L1.
                            let _ = self_addr.try_send(CacheValidatedToken {
                                access_token: token_normalized.clone(),
                                token: token.clone(),
                            });
                            if !token.is_valid() {
                                return Err(OAuth2Error::invalid_grant(
                                    "Token is expired or revoked",
                                ));
                            }
                            return Ok(token);
                        }
                    }
                }

                let token_prefix = token_normalized.chars().take(20).collect::<String>();
                tracing::info!(
                    token_len = token_normalized.len(),
                    token_prefix = %token_prefix,
                    cache = "miss",
                    "ValidateToken called"
                );

                let token = db
                    .get_token_by_access_token(&token_normalized)
                    .await?
                    .ok_or_else(|| OAuth2Error::invalid_grant("Token not found"))?;

                if !token.is_valid() {
                    tracing::warn!(
                        revoked = token.revoked,
                        expires_at = %token.expires_at,
                        now = %chrono::Utc::now(),
                        token_len = token_normalized.len(),
                        token_prefix = %token_prefix,
                        "Token is not valid (expired or revoked)"
                    );
                    // Emit expired/invalid event
                    if let Some(event_bus) = &event_bus {
                        let event = AuthEvent::new(
                            EventType::TokenExpired,
                            EventSeverity::Warning,
                            token.user_id.clone(),
                            Some(token.client_id.clone()),
                        );
                        let envelope = EventEnvelope::from_current_span(event, "oauth2_server");
                        event_bus.publish_best_effort(envelope);
                    }

                    return Err(OAuth2Error::invalid_grant("Token is expired or revoked"));
                }

                // Write to Redis L2 cache.
                #[cfg(feature = "redis-cache")]
                if let Some(ref mut conn) = redis_conn.clone() {
                    let redis_key = format!("{}{}", REDIS_TOKEN_PREFIX, token_normalized);
                    if let Ok(json) = serde_json::to_string(&token) {
                        let _: Result<(), _> = conn.set_ex(&redis_key, json, redis_ttl_secs).await;
                    }
                }

                // Send validated token back to the actor for LRU cache insertion.
                let _ = self_addr.try_send(CacheValidatedToken {
                    access_token: token_normalized.clone(),
                    token: token.clone(),
                });

                // Emit validated event
                if let Some(event_bus) = event_bus {
                    let event = AuthEvent::new(
                        EventType::TokenValidated,
                        EventSeverity::Info,
                        token.user_id.clone(),
                        Some(token.client_id.clone()),
                    );
                    let envelope = EventEnvelope::from_current_span(event, "oauth2_server");
                    event_bus.publish_best_effort(envelope);
                }

                Ok(token)
            }
            .instrument(actor_span),
        )
    }
}

/// Internal message to insert a validated token into the LRU cache.
#[derive(Message)]
#[rtype(result = "()")]
pub struct CacheValidatedToken {
    pub access_token: String,
    pub token: Token,
}

impl Handler<CacheValidatedToken> for TokenActor {
    type Result = ();

    fn handle(&mut self, msg: CacheValidatedToken, _: &mut Self::Context) {
        self.token_cache.put(
            msg.access_token,
            CachedToken {
                token: msg.token,
                inserted_at: Instant::now(),
            },
        );
    }
}

#[derive(Message)]
#[rtype(result = "Result<(), OAuth2Error>")]
pub struct RevokeToken {
    pub token: String,
    pub span: tracing::Span,
}

impl Handler<RevokeToken> for TokenActor {
    type Result = ResponseFuture<Result<(), OAuth2Error>>;

    fn handle(&mut self, msg: RevokeToken, _: &mut Self::Context) -> Self::Result {
        let db = self.db.clone();
        let event_bus = self.event_bus.clone();
        let normalized_token = Self::normalize_token_key(&msg.token);

        let parent_span = msg.span.clone();
        let token_prefix = normalized_token.chars().take(12).collect::<String>();
        let actor_span = tracing::info_span!(
            parent: &parent_span,
            "actor.token.revoke",
            trace_id = tracing::field::Empty,
            span_id = tracing::field::Empty,
            token_prefix = %token_prefix,
            token_len = normalized_token.len()
        );
        annotate_span_with_trace_ids(&actor_span);

        // Evict from the validation cache immediately so subsequent
        // ValidateToken requests won't return a stale cached result.
        self.invalidate_cached_token(&normalized_token);

        // Clone Redis connection for async eviction.
        #[cfg(feature = "redis-cache")]
        let redis_conn = self.redis.clone();
        #[cfg(feature = "redis-cache")]
        let redis_key = format!("{}{}", REDIS_TOKEN_PREFIX, normalized_token);

        let normalized_token_for_db = normalized_token.clone();

        Box::pin(
            async move {
                // Evict from Redis L2.
                #[cfg(feature = "redis-cache")]
                if let Some(ref mut conn) = redis_conn.clone() {
                    let _: Result<(), _> = conn.del(&redis_key).await;
                }

                // Get token info before revoking for event + cascade revocation.
                let token_info = db
                    .get_token_by_access_token(&normalized_token_for_db)
                    .await?;

                // Also check if the token is a refresh token (for cascade).
                let token_by_refresh = if token_info.is_none() {
                    db.get_token_by_refresh_token(&normalized_token_for_db)
                        .await?
                } else {
                    None
                };

                let resolved = token_info.or(token_by_refresh);

                db.revoke_token(&normalized_token_for_db).await?;

                // Cascade: revoke the entire token family (linked access + refresh tokens).
                if let Some(ref token) = resolved {
                    if let Some(ref family) = token.token_family {
                        let _ = db.revoke_token_family(family).await;
                    }
                }

                // Emit revoked event
                if let Some(event_bus) = event_bus {
                    if let Some(token) = resolved {
                        let event = AuthEvent::new(
                            EventType::TokenRevoked,
                            EventSeverity::Info,
                            token.user_id,
                            Some(token.client_id),
                        );
                        let envelope = EventEnvelope::from_current_span(event, "oauth2_server");
                        event_bus.publish_best_effort(envelope);
                    }
                }

                Ok(())
            }
            .instrument(actor_span),
        )
    }
}

/// RFC 9700 §2.1.5 / §4.14.2: revoke every access + refresh token that
/// carries the supplied `family` UUID. Used on authorization-code replay
/// (cascade from the auth-code's family) and on refresh-token replay
/// (cascade from the rotated token's family).
#[derive(Message)]
#[rtype(result = "Result<u64, OAuth2Error>")]
pub struct RevokeTokenFamily {
    pub family: String,
    pub span: tracing::Span,
}

impl Handler<RevokeTokenFamily> for TokenActor {
    type Result = ResponseFuture<Result<u64, OAuth2Error>>;

    fn handle(&mut self, msg: RevokeTokenFamily, _: &mut Self::Context) -> Self::Result {
        let db = self.db.clone();
        let actor_span = tracing::info_span!(
            parent: &msg.span,
            "actor.token.revoke_family",
            trace_id = tracing::field::Empty,
            span_id = tracing::field::Empty,
            token_family = %msg.family
        );
        annotate_span_with_trace_ids(&actor_span);

        // A family revocation may invalidate many tokens whose access_token
        // strings we do not know without a query. Dropping the whole LRU
        // is the simplest correct answer — the cache is a TTL-bounded
        // performance aid, not a source of truth. Repopulation happens
        // lazily on subsequent ValidateToken calls.
        self.token_cache.clear();

        Box::pin(
            async move {
                let revoked = db.revoke_token_family(&msg.family).await?;
                tracing::info!(
                    token_family = %msg.family,
                    revoked_count = revoked,
                    "Revoked token family (RFC 9700 §2.1.5 cascade)"
                );
                Ok(revoked)
            }
            .instrument(actor_span),
        )
    }
}

// ---------------------------------------------------------------------------
// Refresh-token lookup (database round-trip, no cache)
// ---------------------------------------------------------------------------

/// Assign (or update) the token-family UUID on an existing token row.
/// Used during refresh rotation when a legacy token has no family yet so that
/// replay detection can revoke the entire grant lineage.
#[derive(Message)]
#[rtype(result = "Result<(), OAuth2Error>")]
pub struct SetTokenFamily {
    pub access_token: String,
    pub family: String,
    pub span: tracing::Span,
}

impl Handler<SetTokenFamily> for TokenActor {
    type Result = ResponseFuture<Result<(), OAuth2Error>>;

    fn handle(&mut self, msg: SetTokenFamily, _: &mut Self::Context) -> Self::Result {
        let db = self.db.clone();
        let parent_span = msg.span.clone();
        let actor_span = tracing::info_span!(
            parent: &parent_span,
            "actor.token.set_family",
            trace_id = tracing::field::Empty,
            span_id = tracing::field::Empty,
            token_family = %msg.family,
        );
        annotate_span_with_trace_ids(&actor_span);

        Box::pin(
            async move { db.set_token_family(&msg.access_token, &msg.family).await }
                .instrument(actor_span),
        )
    }
}

/// Look up a token by its refresh_token string.
/// Returns the full `Token` row if found and not revoked/expired, or an error.
#[derive(Message)]
#[rtype(result = "Result<Token, OAuth2Error>")]
pub struct ValidateRefreshToken {
    pub refresh_token: String,
    pub span: tracing::Span,
}

/// Non-validating lookup of a token by refresh_token.
/// Returns `Ok(Some(Token))` if found, `Ok(None)` if not.
/// Used by the revocation handler to verify ownership before revoking.
#[derive(Message)]
#[rtype(result = "Result<Option<Token>, OAuth2Error>")]
pub struct LookupRefreshToken {
    pub refresh_token: String,
    pub span: tracing::Span,
}

impl Handler<LookupRefreshToken> for TokenActor {
    type Result = ResponseFuture<Result<Option<Token>, OAuth2Error>>;

    fn handle(&mut self, msg: LookupRefreshToken, _: &mut Self::Context) -> Self::Result {
        let db = self.db.clone();
        let normalized_token = Self::normalize_token_key(&msg.refresh_token);

        let parent_span = msg.span.clone();
        let actor_span = tracing::info_span!(
            parent: &parent_span,
            "actor.token.lookup_refresh",
            trace_id = tracing::field::Empty,
            span_id = tracing::field::Empty,
            token_prefix = %normalized_token.chars().take(12).collect::<String>(),
            token_len = normalized_token.len()
        );
        annotate_span_with_trace_ids(&actor_span);

        Box::pin(
            async move { db.get_token_by_refresh_token(&normalized_token).await }
                .instrument(actor_span),
        )
    }
}

impl Handler<ValidateRefreshToken> for TokenActor {
    type Result = ResponseFuture<Result<Token, OAuth2Error>>;

    fn handle(&mut self, msg: ValidateRefreshToken, _: &mut Self::Context) -> Self::Result {
        let db = self.db.clone();
        let jwt_secret = self.jwt_secret.clone();
        let keyset = self.keyset.clone();

        let parent_span = msg.span.clone();
        let token_prefix = msg.refresh_token.chars().take(12).collect::<String>();
        let actor_span = tracing::info_span!(
            parent: &parent_span,
            "actor.token.validate_refresh",
            trace_id = tracing::field::Empty,
            span_id = tracing::field::Empty,
            token_prefix = %token_prefix,
            token_len = msg.refresh_token.len()
        );
        annotate_span_with_trace_ids(&actor_span);

        let refresh_token = msg.refresh_token;

        Box::pin(
            async move {
                let token = db
                    .get_token_by_refresh_token(&refresh_token)
                    .await?
                    .ok_or_else(|| {
                        OAuth2Error::invalid_grant("Refresh token not found or revoked")
                    })?;

                // Replay detection (OAuth 2.0 Security BCP §4.13.2):
                // A revoked refresh token being presented again is a replay attack.
                // Revoke the entire token family to invalidate the authorization grant.
                if token.revoked {
                    if let Some(ref family) = token.token_family {
                        let _ = db.revoke_token_family(family).await;
                    }
                    return Err(OAuth2Error::invalid_grant(
                        "Refresh token has been revoked (replay detected)",
                    ));
                }

                // Validate expiry using the refresh token JWT's own `exp` claim
                // (minted for 30 days) rather than the access-token row's
                // `expires_at` (which reflects the 1-hour access-token lifetime).
                // Build a Validation that sets the expected audience (= the client_id
                // from the DB record) so jsonwebtoken v10 accepts the aud claim.
                let refresh_expired = {
                    use jsonwebtoken::{DecodingKey, Validation};
                    let mut val = Validation::default();
                    val.set_audience(&[token.client_id.as_str()]);

                    let decoded = if let Some(ref ks_lock) = keyset {
                        let ks = ks_lock.read().await;
                        // Resolve the decoding key from the keyset, reusing the
                        // audience-aware Validation built above.
                        let header = jsonwebtoken::decode_header(&refresh_token);
                        let result = match header {
                            Ok(h) if h.kid.is_some() => {
                                let kid = h.kid.unwrap();
                                ks.find(&kid).and_then(|key| {
                                    let dk = match key.algorithm {
                                        KeyAlgorithm::HS256 => {
                                            DecodingKey::from_secret(&key.key_material)
                                        }
                                        KeyAlgorithm::RS256 => {
                                            DecodingKey::from_rsa_pem(&key.key_material).ok()?
                                        }
                                    };
                                    if key.algorithm == KeyAlgorithm::RS256 {
                                        val.algorithms = vec![jsonwebtoken::Algorithm::RS256];
                                    }
                                    jsonwebtoken::decode::<Claims>(&refresh_token, &dk, &val).ok()
                                })
                            }
                            _ => None,
                        };
                        result.is_some()
                    } else {
                        let dk = DecodingKey::from_secret(jwt_secret.as_ref());
                        jsonwebtoken::decode::<Claims>(&refresh_token, &dk, &val).is_ok()
                    };

                    !decoded
                };

                if refresh_expired {
                    return Err(OAuth2Error::invalid_grant("Refresh token is expired"));
                }

                Ok(token)
            }
            .instrument(actor_span),
        )
    }
}

// ---------------------------------------------------------------------------
// Stateless JWT-only validation (no database lookup)
// ---------------------------------------------------------------------------

/// Validate a token purely from its JWT claims — no DB round-trip.
/// Returns a minimal `Token` reconstructed from the decoded claims.
/// Revocation status is NOT checked; this trades consistency for latency.
#[derive(Message)]
#[rtype(result = "Result<Token, OAuth2Error>")]
pub struct ValidateTokenStateless {
    pub token: String,
    pub span: tracing::Span,
}

impl Handler<ValidateTokenStateless> for TokenActor {
    type Result = Result<Token, OAuth2Error>;

    fn handle(&mut self, msg: ValidateTokenStateless, _: &mut Self::Context) -> Self::Result {
        let _enter = msg.span.enter();

        if self.access_tokens_opaque {
            return Err(OAuth2Error::invalid_grant(
                "Stateless validation is unavailable for opaque access tokens",
            ));
        }

        let raw = Self::normalize_token_key(&msg.token);

        // Try keyset first, fall back to jwt_secret.
        let claims = if let Some(ref ks_lock) = self.keyset {
            // We are inside the actor (synchronous handler), so we cannot
            // await the RwLock.  Use try_read — a contended lock is
            // extremely unlikely because writers (key rotation) are rare.
            let ks = ks_lock
                .try_read()
                .map_err(|_| OAuth2Error::new("server_error", Some("keyset lock contended")))?;
            Claims::decode_with_keyset(&raw, &ks)
                .map_err(|e| OAuth2Error::invalid_grant(&format!("JWT decode failed: {e}")))?
        } else {
            Claims::decode(&raw, &self.jwt_secret)
                .map_err(|e| OAuth2Error::invalid_grant(&format!("JWT decode failed: {e}")))?
        };

        // Reconstruct a minimal Token from the claims.
        let expires_in = (claims.exp - claims.iat) as i32;

        use chrono::{TimeZone, Utc};
        let created_at = Utc
            .timestamp_opt(claims.iat, 0)
            .single()
            .unwrap_or_else(Utc::now);
        let expires_at = Utc
            .timestamp_opt(claims.exp, 0)
            .single()
            .unwrap_or_else(Utc::now);

        Ok(Token {
            id: claims.jti.clone(),
            access_token: raw,
            refresh_token: None,
            token_type: "Bearer".to_string(),
            expires_in,
            scope: claims.scope.clone(),
            client_id: claims.client_id.clone().unwrap_or_default(),
            user_id: Some(claims.sub.clone()),
            created_at,
            expires_at,
            revoked: false,
            token_family: None,
        })
    }
}
