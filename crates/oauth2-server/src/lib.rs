use actix::Actor;
use actix_cors::Cors;
use actix_files::Files;
use actix_session::{config::PersistentSession, storage::CookieSessionStore, SessionMiddleware};
use actix_web::body::MessageBody;
use actix_web::cookie::{time::Duration as CookieDuration, SameSite};
use actix_web::dev::{ServiceRequest, ServiceResponse};
use actix_web::middleware::Condition;
use actix_web::{cookie::Key, middleware as actix_middleware, web, App, HttpResponse, HttpServer};
use oauth2_core::models::key_set::{Algorithm as KeyAlgorithm, KeySet, SigningKey};
use oauth2_openapi::ApiDoc;
#[cfg(feature = "redis-cache")]
use redis::aio::ConnectionManager as CacheRedisConnectionManager;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tracing_actix_web::{DefaultRootSpanBuilder, RootSpanBuilder, TracingLogger};
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

/// The known-insecure default seed password shipped with the server.
pub const INSECURE_DEFAULT_SEED_PASSWORD: &str = "changeme";

/// Redact the `user:password@` userinfo from a database URL so it is safe
/// to emit in logs. Leaves the scheme, host, port, path, and query intact.
pub fn redact_db_url(url: &str) -> String {
    let Some(scheme_end) = url.find("://") else {
        return url.to_string();
    };
    let after_scheme = scheme_end + 3;
    let rest = &url[after_scheme..];
    let Some(at_pos) = rest.find('@') else {
        return url.to_string();
    };
    // Only treat `@` as userinfo terminator if it precedes any path/query
    // separator — otherwise it is a bare `@` inside the path/query.
    let host_terminators = ['/', '?', '#'];
    if rest[..at_pos].contains(host_terminators) {
        return url.to_string();
    }
    format!("{}://***@{}", &url[..scheme_end], &rest[at_pos + 1..])
}

#[cfg(test)]
mod redact_db_url_tests {
    use super::redact_db_url;

    #[test]
    fn redacts_mongo_password() {
        let got =
            redact_db_url("mongodb://user:s3cret@host.example.com:10255/?ssl=true&appName=foo");
        assert_eq!(
            got,
            "mongodb://***@host.example.com:10255/?ssl=true&appName=foo"
        );
    }

    #[test]
    fn redacts_postgres_password() {
        assert_eq!(
            redact_db_url("postgres://user:pw@db:5432/app"),
            "postgres://***@db:5432/app"
        );
    }

    #[test]
    fn leaves_url_without_userinfo_unchanged() {
        assert_eq!(
            redact_db_url("sqlite:///tmp/test.db"),
            "sqlite:///tmp/test.db"
        );
        assert_eq!(redact_db_url("sqlite::memory:"), "sqlite::memory:");
    }

    #[test]
    fn does_not_treat_at_in_path_as_userinfo() {
        assert_eq!(
            redact_db_url("sqlite:///tmp/foo@bar.db"),
            "sqlite:///tmp/foo@bar.db"
        );
    }
}

/// Rejects the well-known insecure default seed password unless
/// `OAUTH2_ALLOW_INSECURE_DEFAULTS=1` is set in the environment.
pub fn validate_seed_password_for_production(password: &str) -> Result<(), String> {
    if std::env::var("OAUTH2_ALLOW_INSECURE_DEFAULTS").as_deref() == Ok("1") {
        return Ok(());
    }
    if password == INSECURE_DEFAULT_SEED_PASSWORD {
        return Err(
            "OAUTH2_SEED_PASSWORD must be explicitly set for production. \
            Set it to a strong random password. \
            Set OAUTH2_ALLOW_INSECURE_DEFAULTS=1 to suppress this in test environments."
                .to_string(),
        );
    }
    Ok(())
}

#[derive(Clone, Copy)]
struct OtelRootSpanBuilder;

impl RootSpanBuilder for OtelRootSpanBuilder {
    fn on_request_start(request: &ServiceRequest) -> tracing::Span {
        // Build the default root span and declare a `span_id` field up-front.
        // We then populate both trace_id and span_id using the active OpenTelemetry context.
        let span = tracing_actix_web::root_span!(request, span_id = tracing::field::Empty);
        oauth2_observability::annotate_span_with_trace_ids(&span);
        span
    }

    fn on_request_end<B: MessageBody>(
        span: tracing::Span,
        outcome: &Result<ServiceResponse<B>, actix_web::Error>,
    ) {
        DefaultRootSpanBuilder::on_request_end(span, outcome);
    }
}

// Helper function to parse event types from configuration strings
fn parse_event_types(event_type_strings: &[String]) -> Vec<oauth2_events::EventType> {
    use oauth2_events::EventType;

    event_type_strings
        .iter()
        .filter_map(|s| match s.as_str() {
            "authorization_code_created" => Some(EventType::AuthorizationCodeCreated),
            "authorization_code_validated" => Some(EventType::AuthorizationCodeValidated),
            "authorization_code_expired" => Some(EventType::AuthorizationCodeExpired),
            "token_created" => Some(EventType::TokenCreated),
            "token_validated" => Some(EventType::TokenValidated),
            "token_revoked" => Some(EventType::TokenRevoked),
            "token_expired" => Some(EventType::TokenExpired),
            "client_registered" => Some(EventType::ClientRegistered),
            "client_validated" => Some(EventType::ClientValidated),
            "client_deleted" => Some(EventType::ClientDeleted),
            "user_authenticated" => Some(EventType::UserAuthenticated),
            "user_authentication_failed" => Some(EventType::UserAuthenticationFailed),
            "user_logout" => Some(EventType::UserLogout),
            _ => {
                tracing::warn!("Unknown event type in config: {}", s);
                None
            }
        })
        .collect()
}

#[cfg(feature = "redis-cache")]
type CacheRedisManager = Option<CacheRedisConnectionManager>;
#[cfg(not(feature = "redis-cache"))]
type CacheRedisManager = Option<()>;

#[cfg(feature = "redis-cache")]
async fn build_cache_redis_manager(config: &oauth2_config::Config) -> CacheRedisManager {
    let redis_url = config
        .cache
        .as_ref()
        .and_then(|cache| cache.redis_url.as_deref())
        .map(str::trim)
        .filter(|url| !url.is_empty());

    match redis_url {
        Some(url) => match redis::Client::open(url) {
            Ok(client) => match redis::aio::ConnectionManager::new(client).await {
                Ok(conn) => {
                    tracing::info!("Redis L2 cache enabled for client/token actors");
                    Some(conn)
                }
                Err(error) => {
                    tracing::warn!(
                        error = %error,
                        "Failed to initialize Redis L2 cache; falling back to in-process caches only"
                    );
                    None
                }
            },
            Err(error) => {
                tracing::warn!(
                    error = %error,
                    "Invalid Redis L2 cache URL; falling back to in-process caches only"
                );
                None
            }
        },
        None => None,
    }
}

#[cfg(not(feature = "redis-cache"))]
async fn build_cache_redis_manager(config: &oauth2_config::Config) -> CacheRedisManager {
    let redis_url = config
        .cache
        .as_ref()
        .and_then(|cache| cache.redis_url.as_deref())
        .map(str::trim)
        .filter(|url| !url.is_empty());

    if redis_url.is_some() {
        tracing::warn!(
            "OAUTH2_CACHE_REDIS_URL configured but feature `redis-cache` is not enabled; using in-process caches only"
        );
    }

    None
}

#[cfg(feature = "redis-cache")]
fn attach_token_cache(
    actor: oauth2_actix::actors::TokenActor,
    cache_redis: &CacheRedisManager,
) -> oauth2_actix::actors::TokenActor {
    if let Some(conn) = cache_redis.clone() {
        actor.with_redis(conn)
    } else {
        actor
    }
}

#[cfg(not(feature = "redis-cache"))]
fn attach_token_cache(
    actor: oauth2_actix::actors::TokenActor,
    _cache_redis: &CacheRedisManager,
) -> oauth2_actix::actors::TokenActor {
    actor
}

#[cfg(feature = "redis-cache")]
fn attach_client_cache(
    actor: oauth2_actix::actors::ClientActor,
    cache_redis: &CacheRedisManager,
) -> oauth2_actix::actors::ClientActor {
    if let Some(conn) = cache_redis.clone() {
        actor.with_redis(conn)
    } else {
        actor
    }
}

#[cfg(not(feature = "redis-cache"))]
fn attach_client_cache(
    actor: oauth2_actix::actors::ClientActor,
    _cache_redis: &CacheRedisManager,
) -> oauth2_actix::actors::ClientActor {
    actor
}

pub async fn run() -> std::io::Result<()> {
    // Initialize telemetry and tracing
    oauth2_observability::init_telemetry("oauth2_server").unwrap_or_else(|e| {
        eprintln!("Failed to initialize telemetry: {}", e);
        // Fall back to basic logging
        env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));
    });

    tracing::info!("Starting OAuth2 Server...");

    // Load configuration
    let config = oauth2_config::Config::default();

    if std::env::var("OAUTH2_DEBUG_CONFIG").ok().as_deref() == Some("1") {
        if let Ok(cfg_json) = serde_json::to_string_pretty(&config.sanitized()) {
            tracing::info!(config = %cfg_json, "Loaded configuration (sanitized)");
        }
    }

    // Validate configuration for production — fail startup if misconfigured.
    // Set OAUTH2_ALLOW_INSECURE_DEFAULTS=1 to skip in test/dev environments.
    if let Err(e) = config.validate_for_production() {
        tracing::error!("FATAL: insecure configuration detected: {}", e);
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("Insecure configuration: {e}"),
        ));
    }

    tracing::info!("Configuration loaded");

    // Load social login configuration from HOCON config or environment
    let social_config = if let Some(ref social) = config.social {
        Arc::new(oauth2_social_login::SocialLoginConfig::from_config_social(
            social,
        ))
    } else {
        Arc::new(oauth2_social_login::SocialLoginConfig::from_env())
    };
    tracing::info!("Social login configuration loaded");

    // Initialize metrics
    let metrics = oauth2_observability::Metrics::new().expect("Failed to initialize metrics");
    tracing::info!("Metrics initialized");

    // Initialize storage backend (SQLx by default, optional MongoDB)
    tracing::info!(
        database_url = %redact_db_url(&config.database.url),
        max_connections = config.database.max_connections,
        min_connections = config.database.min_connections,
        acquire_timeout_secs = config.database.acquire_timeout_secs,
        "Connecting to storage backend"
    );
    #[cfg(feature = "sqlx")]
    let storage = {
        let pool_config = oauth2_storage_factory::sqlx::PoolConfig {
            max_connections: config.database.max_connections,
            min_connections: config.database.min_connections,
            acquire_timeout: std::time::Duration::from_secs(config.database.acquire_timeout_secs),
            idle_timeout: std::time::Duration::from_secs(config.database.idle_timeout_secs),
        };
        oauth2_storage_factory::create_storage_with_pool_config(
            &config.database.url,
            Some(pool_config),
            config.database.read_url.as_deref(),
        )
        .await
        .expect("Failed to create storage backend")
    };
    #[cfg(not(feature = "sqlx"))]
    let storage =
        oauth2_storage_factory::create_storage_with_pool_config(&config.database.url, None, None)
            .await
            .expect("Failed to create storage backend");

    storage
        .init()
        .await
        .expect("Failed to initialize storage backend");
    tracing::info!("Storage backend initialized");

    // Seed a default admin user if none exists yet.
    // In production, change the password immediately or use OAUTH2_SEED_PASSWORD env var.
    {
        use oauth2_core::User;

        let seed_username =
            std::env::var("OAUTH2_SEED_USERNAME").unwrap_or_else(|_| "admin".to_string());
        let seed_password = std::env::var("OAUTH2_SEED_PASSWORD")
            .unwrap_or_else(|_| INSECURE_DEFAULT_SEED_PASSWORD.to_string());
        let seed_email =
            std::env::var("OAUTH2_SEED_EMAIL").unwrap_or_else(|_| "admin@example.com".to_string());

        validate_seed_password_for_production(&seed_password).map_err(|e| {
            tracing::error!("{}", e);
            std::io::Error::new(std::io::ErrorKind::InvalidInput, e)
        })?;

        match storage.get_user_by_username(&seed_username).await {
            Ok(None) => {
                let hash = oauth2_actix::handlers::login::hash_password(&seed_password)
                    .expect("Failed to hash seed password");
                let mut user = User::new(seed_username.clone(), hash, seed_email);
                user.role = "admin".to_string();
                storage
                    .save_user(&user)
                    .await
                    .expect("Failed to save seed user");
                tracing::info!(
                    username = %seed_username,
                    user_id = %user.id,
                    "Seeded default user (change password in production!)"
                );
            }
            Ok(Some(_)) => {
                tracing::debug!(username = %seed_username, "Seed user already exists, skipping");
            }
            Err(e) => {
                tracing::warn!("Could not check for seed user: {e}");
            }
        }
    }

    let jwt_secret = config.jwt.secret.clone();

    // Load session key from environment or generate a new one
    // In production, OAUTH2_SESSION_KEY should be set to a persistent value
    let session_key = if let Ok(key_str) = std::env::var("OAUTH2_SESSION_KEY") {
        if key_str.len() < 64 {
            panic!("OAUTH2_SESSION_KEY must be at least 64 characters (128 hex digits)");
        }
        let key_bytes =
            hex::decode(&key_str).expect("OAUTH2_SESSION_KEY must be valid hexadecimal");
        Key::try_from(&key_bytes[..]).expect("OAUTH2_SESSION_KEY must be exactly 64 bytes")
    } else if let Some(key_str) = config
        .session
        .as_ref()
        .and_then(|session| session.key.as_ref())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
    {
        if key_str.len() < 64 {
            panic!("OAUTH2_SESSION_KEY must be at least 64 characters (128 hex digits)");
        }
        let key_bytes =
            hex::decode(&key_str).expect("OAUTH2_SESSION_KEY must be valid hexadecimal");
        Key::try_from(&key_bytes[..]).expect("OAUTH2_SESSION_KEY must be exactly 64 bytes")
    } else {
        tracing::warn!("OAUTH2_SESSION_KEY not set. Generating random key. Sessions will not persist across restarts!");
        Key::generate()
    };

    // Optional Redis L2 cache — must be built before recent_events_store so we can attach it.
    let cache_redis_manager = build_cache_redis_manager(&config).await;

    // Ring-buffer of recent events for the admin dashboard events page.
    // Constructed here so the event bridge plugin can hold a clone.
    // When Redis is available, push/snapshot go through Redis so all replicas share the view.
    let recent_events_store = {
        let store = oauth2_actix::handlers::events::RecentEventsStore::new(500);
        #[cfg(feature = "redis-cache")]
        let store = if let Some(conn) = cache_redis_manager.clone() {
            tracing::info!("RecentEventsStore backed by Redis (cross-replica visibility)");
            store.with_redis(conn)
        } else {
            store
        };
        store
    };

    // Bridge: forwards every event published through the actor bus into RecentEventsStore
    // so the admin Events page shows OAuth flow events (token issued, revoked, etc.).
    struct RecentEventsPlugin(oauth2_actix::handlers::events::RecentEventsStore);

    #[async_trait::async_trait]
    impl oauth2_events::EventPlugin for RecentEventsPlugin {
        async fn emit(&self, envelope: &oauth2_events::EventEnvelope) -> Result<(), String> {
            if let Ok(json) = serde_json::to_value(envelope) {
                self.0.push(json).await;
            }
            Ok(())
        }

        fn name(&self) -> &str {
            "recent_events_store"
        }
    }

    // Initialize event system first
    let event_actor = if config.events.enabled {
        use oauth2_events::{ConsoleEventLogger, EventFilter, InMemoryEventLogger};

        // Parse event filter from config
        let filter = match config.events.filter_mode.as_str() {
            "include" => {
                let event_types = parse_event_types(&config.events.event_types);
                EventFilter::include_only(event_types)
            }
            "exclude" => {
                let event_types = parse_event_types(&config.events.event_types);
                EventFilter::exclude_events(event_types)
            }
            _ => EventFilter::allow_all(),
        };

        // Create plugins based on backend config
        let plugins: Vec<Arc<dyn oauth2_events::EventPlugin>> = match config.events.backend.as_str()
        {
            "console" => vec![
                Arc::new(ConsoleEventLogger::new()),
                Arc::new(RecentEventsPlugin(recent_events_store.clone())),
            ],
            "in_memory" => vec![
                Arc::new(InMemoryEventLogger::new(1000)),
                Arc::new(RecentEventsPlugin(recent_events_store.clone())),
            ],
            "both" => vec![
                Arc::new(InMemoryEventLogger::new(1000)),
                Arc::new(ConsoleEventLogger::new()),
                Arc::new(RecentEventsPlugin(recent_events_store.clone())),
            ],
            "redis" | "redis_streams" => {
                #[cfg(feature = "events-redis")]
                {
                    let url = config
                        .events
                        .redis_url
                        .clone()
                        .unwrap_or_else(|| "redis://127.0.0.1:6379".to_string());

                    let stream = config
                        .events
                        .redis_stream
                        .clone()
                        .unwrap_or_else(oauth2_events::default_stream_name);

                    let maxlen = config
                        .events
                        .redis_maxlen
                        .or_else(oauth2_events::default_maxlen);

                    match oauth2_events::RedisStreamsEventPublisher::connect(&url, stream, maxlen)
                        .await
                    {
                        Ok(p) => vec![
                            Arc::new(p),
                            Arc::new(RecentEventsPlugin(recent_events_store.clone())),
                        ],
                        Err(e) => {
                            tracing::warn!(error = %e, "Redis event backend init failed; falling back to in_memory");
                            vec![
                                Arc::new(InMemoryEventLogger::new(1000)),
                                Arc::new(RecentEventsPlugin(recent_events_store.clone())),
                            ]
                        }
                    }
                }
                #[cfg(not(feature = "events-redis"))]
                {
                    tracing::warn!(
                        "Event backend '{}' requested but feature 'events-redis' is not enabled; falling back to in_memory",
                        config.events.backend
                    );
                    vec![Arc::new(InMemoryEventLogger::new(1000))]
                }
            }
            "kafka" => {
                #[cfg(feature = "events-kafka")]
                {
                    let brokers = config
                        .events
                        .kafka_brokers
                        .clone()
                        .unwrap_or_else(|| "127.0.0.1:9092".to_string());
                    let topic = config
                        .events
                        .kafka_topic
                        .clone()
                        .unwrap_or_else(|| "oauth2_events".to_string());

                    match oauth2_events::KafkaEventPublisher::new(
                        &brokers,
                        topic,
                        config.events.kafka_client_id.clone(),
                    ) {
                        Ok(p) => vec![
                            Arc::new(p),
                            Arc::new(RecentEventsPlugin(recent_events_store.clone())),
                        ],
                        Err(e) => {
                            tracing::warn!(error = %e, "Kafka event backend init failed; falling back to in_memory");
                            vec![
                                Arc::new(InMemoryEventLogger::new(1000)),
                                Arc::new(RecentEventsPlugin(recent_events_store.clone())),
                            ]
                        }
                    }
                }
                #[cfg(not(feature = "events-kafka"))]
                {
                    tracing::warn!(
                        "Event backend '{}' requested but feature 'events-kafka' is not enabled; falling back to in_memory",
                        config.events.backend
                    );
                    vec![Arc::new(InMemoryEventLogger::new(1000))]
                }
            }
            "rabbit" | "rabbitmq" => {
                #[cfg(feature = "events-rabbit")]
                {
                    let url = config
                        .events
                        .rabbit_url
                        .clone()
                        .unwrap_or_else(|| "amqp://127.0.0.1:5672/%2f".to_string());
                    let exchange = config
                        .events
                        .rabbit_exchange
                        .clone()
                        .unwrap_or_else(|| "oauth2.events".to_string());
                    let routing_key = config
                        .events
                        .rabbit_routing_key
                        .clone()
                        .unwrap_or_else(|| "oauth2.event".to_string());

                    match oauth2_events::RabbitEventPublisher::connect(&url, exchange, routing_key)
                        .await
                    {
                        Ok(p) => vec![
                            Arc::new(p),
                            Arc::new(RecentEventsPlugin(recent_events_store.clone())),
                        ],
                        Err(e) => {
                            tracing::warn!(error = %e, "Rabbit event backend init failed; falling back to in_memory");
                            vec![
                                Arc::new(InMemoryEventLogger::new(1000)),
                                Arc::new(RecentEventsPlugin(recent_events_store.clone())),
                            ]
                        }
                    }
                }
                #[cfg(not(feature = "events-rabbit"))]
                {
                    tracing::warn!(
                        "Event backend '{}' requested but feature 'events-rabbit' is not enabled; falling back to in_memory",
                        config.events.backend
                    );
                    vec![Arc::new(InMemoryEventLogger::new(1000))]
                }
            }
            _ => {
                tracing::warn!(
                    "Unknown event backend: {}, using in_memory",
                    config.events.backend
                );
                vec![Arc::new(InMemoryEventLogger::new(1000))]
            }
        };

        let actor = oauth2_events::event_actor::EventActor::new(plugins, filter).start();
        tracing::info!("Event system initialized");
        Some(actor)
    } else {
        tracing::info!("Event system disabled");
        None
    };

    // Wrap the actor-backed event system behind the stable EventBus contract.
    let event_bus = event_actor.as_ref().map(|addr| {
        let bus = oauth2_events::ActixEventBus::new(addr.clone());
        oauth2_events::EventBusHandle::new(Arc::new(bus))
    });

    // Best-effort Phase 1 in-memory idempotency cache for ingest.
    let ingest_idempotency =
        oauth2_actix::handlers::events::IdempotencyStore::new(Duration::from_secs(5 * 60))
            // Explicitly set to default to make it configurable without changing call sites.
            .with_max_entries(100_000);

    // --- Rate limiting ---
    let rate_limiter: Option<Arc<dyn oauth2_ratelimit::RateLimiter>> = {
        let rl_config = config.rate_limit.clone().unwrap_or_default();
        if rl_config.enabled {
            tracing::info!(
                max_requests = rl_config.max_requests,
                window_secs = rl_config.window_secs,
                backend = %rl_config.backend,
                "Rate limiting enabled"
            );
            let limiter: Arc<dyn oauth2_ratelimit::RateLimiter> = match rl_config.backend.as_str() {
                "in_memory" => Arc::new(oauth2_ratelimit::in_memory::InMemoryRateLimiter::new(
                    rl_config.max_requests,
                    rl_config.window_secs,
                )),
                "redis" => {
                    #[cfg(feature = "redis-rate-limit")]
                    {
                        let redis_url = rl_config
                            .redis_url
                            .as_deref()
                            .map(str::trim)
                            .filter(|url| !url.is_empty());

                        if let Some(redis_url) = redis_url {
                            match oauth2_ratelimit::redis::RedisRateLimiter::new(
                                redis_url,
                                rl_config.max_requests,
                                rl_config.window_secs,
                            )
                            .await
                            {
                                Ok(limiter) => {
                                    tracing::info!("Redis rate limiting backend enabled");
                                    Arc::new(limiter)
                                }
                                Err(error) => {
                                    tracing::warn!(
                                        error = %error,
                                        "Failed to initialize Redis rate limiter; falling back to in_memory"
                                    );
                                    Arc::new(oauth2_ratelimit::in_memory::InMemoryRateLimiter::new(
                                        rl_config.max_requests,
                                        rl_config.window_secs,
                                    ))
                                }
                            }
                        } else {
                            tracing::warn!(
                                "Redis rate limiting backend requested but OAUTH2_RATE_LIMIT_REDIS_URL is not set; falling back to in_memory"
                            );
                            Arc::new(oauth2_ratelimit::in_memory::InMemoryRateLimiter::new(
                                rl_config.max_requests,
                                rl_config.window_secs,
                            ))
                        }
                    }
                    #[cfg(not(feature = "redis-rate-limit"))]
                    {
                        tracing::warn!(
                            "Redis rate limiting backend requested but feature `redis-rate-limit` is not enabled; falling back to in_memory"
                        );
                        Arc::new(oauth2_ratelimit::in_memory::InMemoryRateLimiter::new(
                            rl_config.max_requests,
                            rl_config.window_secs,
                        ))
                    }
                }
                other => {
                    tracing::warn!(
                        backend = %other,
                        "Unknown rate limiting backend; falling back to in_memory"
                    );
                    Arc::new(oauth2_ratelimit::in_memory::InMemoryRateLimiter::new(
                        rl_config.max_requests,
                        rl_config.window_secs,
                    ))
                }
            };
            Some(limiter)
        } else {
            tracing::info!("Rate limiting disabled");
            None
        }
    };

    // --- Invalid-client penalty bucket (RFC 9700 §2.5) ---
    //
    // Keyed by `client_id` (not IP) so it works correctly behind any proxy
    // topology (Istio, ALB, NGINX). Counts only `invalid_client` failures on
    // the token endpoint; when exhausted the handler returns 429 instead of
    // leaking that credentials are wrong (blocks credential stuffing).
    //
    // Independent of `rate_limit.enabled` — active whenever
    // `invalid_client_max_requests > 0`, regardless of IP rate limit config.
    let invalid_client_limiter: Option<Arc<dyn oauth2_ratelimit::RateLimiter>> = {
        let rl_config = config.rate_limit.clone().unwrap_or_default();
        if rl_config.invalid_client_max_requests > 0 {
            let limiter: Arc<dyn oauth2_ratelimit::RateLimiter> = match rl_config.backend.as_str() {
                "redis" if rl_config.enabled => {
                    #[cfg(feature = "redis-rate-limit")]
                    {
                        let redis_url = rl_config
                            .redis_url
                            .as_deref()
                            .map(str::trim)
                            .filter(|url| !url.is_empty());
                        if let Some(redis_url) = redis_url {
                            match oauth2_ratelimit::redis::RedisRateLimiter::new(
                                redis_url,
                                rl_config.invalid_client_max_requests,
                                rl_config.window_secs,
                            )
                            .await
                            {
                                Ok(l) => Arc::new(l),
                                Err(_) => {
                                    Arc::new(oauth2_ratelimit::in_memory::InMemoryRateLimiter::new(
                                        rl_config.invalid_client_max_requests,
                                        rl_config.window_secs,
                                    ))
                                }
                            }
                        } else {
                            Arc::new(oauth2_ratelimit::in_memory::InMemoryRateLimiter::new(
                                rl_config.invalid_client_max_requests,
                                rl_config.window_secs,
                            ))
                        }
                    }
                    #[cfg(not(feature = "redis-rate-limit"))]
                    Arc::new(oauth2_ratelimit::in_memory::InMemoryRateLimiter::new(
                        rl_config.invalid_client_max_requests,
                        rl_config.window_secs,
                    ))
                }
                _ => Arc::new(oauth2_ratelimit::in_memory::InMemoryRateLimiter::new(
                    rl_config.invalid_client_max_requests,
                    rl_config.window_secs,
                )),
            };
            tracing::info!(
                invalid_client_max_requests = rl_config.invalid_client_max_requests,
                window_secs = rl_config.window_secs,
                "Invalid-client rate limit bucket enabled (keyed by client_id)"
            );
            Some(limiter)
        } else {
            None
        }
    };

    // --- Resilience (back-pressure, bulkheads, circuit breaker) ---
    let resilience_concurrency: Option<Arc<oauth2_resilience::ConcurrencyLimiter>>;
    let resilience_bulkheads: Option<Arc<oauth2_resilience::BulkheadRegistry>>;
    let resilience_circuit_breaker: Option<Arc<oauth2_resilience::CircuitBreaker>>;

    if let Some(ref res_cfg) = config.resilience {
        if res_cfg.enabled {
            // Back-pressure
            resilience_concurrency = res_cfg.back_pressure.as_ref().map(|bp| {
                tracing::info!(
                    max_concurrent = bp.max_concurrent,
                    "Resilience: back-pressure enabled"
                );
                Arc::new(oauth2_resilience::ConcurrencyLimiter::new(
                    bp.max_concurrent,
                ))
            });

            // Bulkheads
            if !res_cfg.bulkheads.is_empty() {
                let bulkhead_cfgs: Vec<oauth2_resilience::BulkheadConfig> = res_cfg
                    .bulkheads
                    .iter()
                    .map(|e| {
                        tracing::info!(
                            name = %e.name,
                            path_prefix = %e.path_prefix,
                            max_concurrent = e.max_concurrent,
                            "Resilience: bulkhead configured"
                        );
                        oauth2_resilience::BulkheadConfig {
                            name: e.name.clone(),
                            path_prefix: e.path_prefix.clone(),
                            max_concurrent: e.max_concurrent,
                        }
                    })
                    .collect();
                resilience_bulkheads = Some(Arc::new(
                    oauth2_resilience::BulkheadRegistry::from_configs(bulkhead_cfgs),
                ));
            } else {
                resilience_bulkheads = None;
            }

            // Circuit breaker
            let cb_cfg = res_cfg.circuit_breaker.clone().unwrap_or_default();
            tracing::info!(
                failure_threshold = cb_cfg.failure_threshold,
                success_threshold = cb_cfg.success_threshold,
                open_secs = cb_cfg.open_secs,
                "Resilience: circuit breaker enabled"
            );
            resilience_circuit_breaker = Some(Arc::new(oauth2_resilience::CircuitBreaker::new(
                "global",
                oauth2_resilience::CircuitBreakerConfig {
                    failure_threshold: cb_cfg.failure_threshold,
                    success_threshold: cb_cfg.success_threshold,
                    open_duration: std::time::Duration::from_secs(cb_cfg.open_secs),
                    half_open_max_probes: cb_cfg.half_open_max_probes,
                },
            )));
        } else {
            tracing::info!("Resilience middleware disabled");
            resilience_concurrency = None;
            resilience_bulkheads = None;
            resilience_circuit_breaker = None;
        }
    } else {
        resilience_concurrency = None;
        resilience_bulkheads = None;
        resilience_circuit_breaker = None;
    }

    // Build OIDC configuration for discovery + id_token generation.
    // Normalize: strip trailing slashes so `iss` is consistent everywhere
    // (authorization response, JWT claims, discovery metadata).
    let issuer = config
        .server
        .public_url
        .clone()
        .or_else(|| config.server.public_base_url.clone())
        .unwrap_or_else(|| format!("http://{}:{}", config.server.host, config.server.port))
        .trim_end_matches('/')
        .to_string();

    // Optional: RS256 id_token signing (recommended for OIDC clients like oauth2-proxy).
    // We accept the PEM either as a literal with newlines, or with \n escapes.
    let id_token_private_key_pem = std::env::var("OAUTH2_ID_TOKEN_PRIVATE_KEY_PEM")
        .ok()
        .map(|s| s.replace("\\n", "\n"))
        .filter(|s| !s.trim().is_empty());
    let id_token_kid = std::env::var("OAUTH2_ID_TOKEN_KID")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let id_token_alg = std::env::var("OAUTH2_ID_TOKEN_ALG")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| {
            if id_token_private_key_pem.is_some() {
                "RS256".to_string()
            } else {
                "HS256".to_string()
            }
        });
    let oidc_config = oauth2_actix::handlers::wellknown::OidcConfig {
        issuer: issuer.clone(),
        jwt_secret: jwt_secret.clone(),
        id_token_alg,
        id_token_kid: id_token_kid.clone(),
        id_token_private_key_pem: id_token_private_key_pem.clone(),
    };
    tracing::info!(issuer = %issuer, "OIDC issuer configured");

    // --- JWT KeySet ---
    let keyset = {
        let mut ks = KeySet::new();

        // Seed HS256 key from JWT secret
        ks.add(SigningKey {
            kid: "hs256-initial".to_string(),
            algorithm: KeyAlgorithm::HS256,
            key_material: config.jwt.secret.as_bytes().to_vec(),
            is_current: true,
            created_at: chrono::Utc::now(),
            expires_at: None,
        });

        // Seed RS256 key if configured (reuse already-parsed PEM with \n handling)
        if let Some(ref pem) = id_token_private_key_pem {
            let kid = id_token_kid
                .clone()
                .unwrap_or_else(|| "rs256-initial".to_string());
            ks.add(SigningKey {
                kid,
                algorithm: KeyAlgorithm::RS256,
                key_material: pem.as_bytes().to_vec(),
                is_current: true,
                created_at: chrono::Utc::now(),
                expires_at: None,
            });
        }

        Arc::new(RwLock::new(ks))
    };

    // Start actors with event system and enlarged mailboxes (default is 16,
    // which becomes a bottleneck above ~1 000 req/s per instance).
    const ACTOR_MAILBOX_CAPACITY: usize = 256;

    // Build a pool of TokenActor shards for parallelism.
    // When `token_actor_shards == 1` (default), this behaves identically
    // to a single actor.
    let shard_count = config
        .cache
        .as_ref()
        .map(|c| c.token_actor_shards.max(1))
        .unwrap_or(1);
    let token_pool = {
        let mut shards = Vec::with_capacity(shard_count);
        let access_ttl = config.jwt.access_token_ttl_secs as i64;
        let refresh_ttl = config.jwt.refresh_token_ttl_secs as i64;
        for _ in 0..shard_count {
            let shard = if let Some(ref event_bus) = event_bus {
                let eb = event_bus.clone();
                let cache_redis = cache_redis_manager.clone();
                actix::Actor::create(|ctx| {
                    ctx.set_mailbox_capacity(ACTOR_MAILBOX_CAPACITY);
                    let actor = oauth2_actix::actors::TokenActor::with_events(
                        storage.clone(),
                        jwt_secret.clone(),
                        issuer.clone(),
                        eb,
                    )
                    .with_keyset(keyset.clone())
                    .with_access_tokens_opaque(config.jwt.access_tokens_opaque)
                    .with_token_ttls(access_ttl, refresh_ttl);
                    attach_token_cache(actor, &cache_redis)
                })
            } else {
                let cache_redis = cache_redis_manager.clone();
                actix::Actor::create(|ctx| {
                    ctx.set_mailbox_capacity(ACTOR_MAILBOX_CAPACITY);
                    let actor = oauth2_actix::actors::TokenActor::new(
                        storage.clone(),
                        jwt_secret.clone(),
                        issuer.clone(),
                    )
                    .with_keyset(keyset.clone())
                    .with_access_tokens_opaque(config.jwt.access_tokens_opaque)
                    .with_token_ttls(access_ttl, refresh_ttl);
                    attach_token_cache(actor, &cache_redis)
                })
            };
            shards.push(shard);
        }
        oauth2_actix::actors::TokenActorPool::new(shards)
    };
    tracing::info!(shards = shard_count, "TokenActorPool started");

    let client_actor = if let Some(ref event_bus) = event_bus {
        let cache_redis = cache_redis_manager.clone();
        actix::Actor::create(|ctx| {
            ctx.set_mailbox_capacity(ACTOR_MAILBOX_CAPACITY);
            let actor =
                oauth2_actix::actors::ClientActor::with_events(storage.clone(), event_bus.clone());
            attach_client_cache(actor, &cache_redis)
        })
    } else {
        let cache_redis = cache_redis_manager.clone();
        actix::Actor::create(|ctx| {
            ctx.set_mailbox_capacity(ACTOR_MAILBOX_CAPACITY);
            let actor = oauth2_actix::actors::ClientActor::new(storage.clone());
            attach_client_cache(actor, &cache_redis)
        })
    };

    let auth_code_ttl = config.jwt.authorization_code_ttl_secs as i64;
    let auth_actor = if let Some(ref event_bus) = event_bus {
        actix::Actor::create(|ctx| {
            ctx.set_mailbox_capacity(ACTOR_MAILBOX_CAPACITY);
            oauth2_actix::actors::AuthActor::with_events(storage.clone(), event_bus.clone())
                .with_auth_code_ttl(auth_code_ttl)
        })
    } else {
        actix::Actor::create(|ctx| {
            ctx.set_mailbox_capacity(ACTOR_MAILBOX_CAPACITY);
            oauth2_actix::actors::AuthActor::new(storage.clone()).with_auth_code_ttl(auth_code_ttl)
        })
    };

    tracing::info!("Actors started");

    // OpenAPI documentation
    let openapi = ApiDoc::openapi();

    let bind_addr = format!("{}:{}", config.server.host, config.server.port);
    tracing::info!("Starting server at http://{}", bind_addr);
    tracing::info!("Login page available at http://{}/auth/login", bind_addr);
    tracing::info!("Swagger UI available at http://{}/swagger-ui", bind_addr);
    tracing::info!("Admin dashboard at http://{}/admin", bind_addr);
    tracing::info!("Metrics endpoint at http://{}/metrics", bind_addr);

    let server_config = config.server.clone();
    let app_config = config.clone();
    let key_rotation_grace_hours = oauth2_actix::handlers::admin_keys::KeyRotationGraceHours(
        config.jwt.key_rotation_grace_hours,
    );

    // Start HTTP server
    let mut server = HttpServer::new(move || {
        let cors = {
            let origins = server_config.allowed_origins.clone();
            let mut cors_builder = Cors::default()
                .allow_any_method()
                .allow_any_header()
                .max_age(3600);
            if origins.is_empty() {
                cors_builder
            } else if origins.iter().any(|o| o == "*") {
                cors_builder.allow_any_origin().send_wildcard()
            } else {
                for origin in &origins {
                    cors_builder = cors_builder.allowed_origin(origin);
                }
                cors_builder
            }
        };

        // Rate limiting middleware. When disabled, rate_limiter is None and
        // Condition::new(false, ...) ensures the middleware is never invoked.
        // The dummy InMemoryRateLimiter below is only constructed in the
        // disabled path for type unification and does NOT get called.
        let rl_middleware = {
            let (enabled, limiter) = match rate_limiter.clone() {
                Some(l) => (true, l),
                None => (
                    false,
                    Arc::new(oauth2_ratelimit::in_memory::InMemoryRateLimiter::new(1, 1))
                        as Arc<dyn oauth2_ratelimit::RateLimiter>,
                ),
            };
            Condition::new(
                enabled,
                oauth2_actix::middleware::rate_limit::RateLimitMiddleware::new(
                    limiter,
                    vec!["/health".into(), "/ready".into(), "/metrics".into()],
                    server_config.trust_proxy_headers,
                ),
            )
        };

        // Resilience middleware (back-pressure + bulkheads + circuit breaker).
        // When all three are None the middleware still registers but is a no-op
        // for every request (exempt paths skip even the no-op checks).
        let resilience_mw = oauth2_actix::middleware::resilience::ResilienceMiddleware::new(
            resilience_concurrency.clone(),
            resilience_bulkheads.clone(),
            resilience_circuit_breaker.clone(),
            Arc::new(metrics.clone()),
            vec!["/health".into(), "/ready".into(), "/metrics".into()],
        );

        // Actix middleware execution order: the **last** `.wrap()` is the
        // outermost layer (runs first on incoming requests).  We want:
        //   resilience (outermost) → rate-limiting → session → logging → …
        // so resilience_mw is registered last.
        let mut app = App::new()
            .wrap(
                actix_middleware::DefaultHeaders::new()
                    .add(("X-Frame-Options", "DENY"))
                    .add(("X-Content-Type-Options", "nosniff"))
                    .add(("Referrer-Policy", "no-referrer"))
                    // HSTS (RFC 6797): forces browsers to upgrade HTTP to HTTPS
                    // for this host for 1 year. `includeSubDomains` protects
                    // sibling hosts. `preload` is opt-in — operators submit
                    // their host to hstspreload.org separately; we advertise
                    // readiness by default.
                    .add((
                        "Strict-Transport-Security",
                        "max-age=31536000; includeSubDomains",
                    ))
                    // CSP: existing templates still include inline
                    // `<script>` blocks, so `script-src` must retain
                    // 'unsafe-inline' until those scripts are moved to
                    // external files or converted to nonce/hash-based CSP.
                    // `style-src` also retains 'unsafe-inline' for
                    // Tailwind utility classes.
                    .add(("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.tailwindcss.com https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data:; frame-ancestors 'none'; base-uri 'self'; form-action 'self'")),
            )
            .wrap(cors)
            .wrap(oauth2_observability::actix::MetricsMiddleware::new(
                metrics.clone(),
            ))
            .wrap(actix_middleware::Compress::default())
            .wrap(actix_middleware::Logger::default())
            .wrap(TracingLogger::<OtelRootSpanBuilder>::new())
            // Session cookie hardening (W2-H5):
            //   - `Secure` is enabled unless `OAUTH2_ALLOW_INSECURE_DEFAULTS=1`
            //     (matches the same env convention used by `validate_for_production()`
            //     and the seed-password check). Production deployments MUST leave
            //     the variable unset so the cookie is never sent over plaintext HTTP.
            //   - `HttpOnly` blocks `document.cookie` access from JavaScript.
            //   - `SameSite=Lax` is required because the OAuth authorize redirect
            //     returns via a top-level navigation; `Strict` would drop the
            //     session on return and break the login flow.
            //   - Persistent session TTL = 12h; browsers expire the cookie even
            //     when the tab stays open.
            .wrap(
                SessionMiddleware::builder(
                    CookieSessionStore::default(),
                    session_key.clone(),
                )
                .cookie_secure(
                    std::env::var("OAUTH2_ALLOW_INSECURE_DEFAULTS").as_deref() != Ok("1"),
                )
                .cookie_http_only(true)
                .cookie_same_site(SameSite::Lax)
                .session_lifecycle(
                    PersistentSession::default().session_ttl(CookieDuration::hours(12)),
                )
                .build(),
            )
            .wrap(rl_middleware)
            // IP denylist check runs before rate limiting so that
            // denylisted IPs don't consume rate-limit quota.
            .wrap(oauth2_actix::middleware::denylist::DenylistGuard)
            // Resilience is next-outermost. Tripped circuit / full concurrency
            // pool → 503 on the cheapest path, before rate-limiting, session,
            // or logging run.
            .wrap(resilience_mw)
            // RFC 9700 §2.6: outermost layer — reject plain HTTP before any
            // other processing when `server.enforce_https = true`. No-op
            // when disabled (the dev default).
            .wrap(oauth2_actix::middleware::https_redirect::HttpsRedirect::new(
                config.server.enforce_https,
                config.server.trust_proxy_headers,
            ))
            // Shared state
            .app_data(web::Data::new(token_pool.clone()))
            .app_data(web::Data::new(client_actor.clone()))
            .app_data(web::Data::new(auth_actor.clone()))
            .app_data(web::Data::new(jwt_secret.clone()))
            .app_data(web::Data::new(storage.clone()))
            .app_data(web::Data::new(metrics.clone()))
            .app_data(web::Data::new(social_config.clone()))
            .app_data(web::Data::new(oauth2_social_login::SocialLoginService::new()))
            // Server/public URL settings (used by well-known discovery and other URL builders)
            .app_data(web::Data::new(server_config.clone()))
            .app_data(web::Data::new(app_config.clone()))
            .app_data(web::Data::new(oidc_config.clone()))
            .app_data(web::Data::new(keyset.clone()))
            .app_data(web::Data::new(key_rotation_grace_hours))
            // Stateless JWT validation flag (skips DB lookup during introspection)
            .app_data(web::Data::new(app_config.jwt.stateless_validation));

        // Login rate-limiter (W2-H1): per-IP and per-username credential-stuffing
        // protection.  Registered as optional app_data so tests that don't supply
        // it can still compile without needing a real limiter instance.
        app = app.app_data(web::Data::new(
            oauth2_actix::handlers::login::LoginRateLimiter::default(),
        ));

        // Trust proxy headers flag — shared with rate limit middleware and login handler.
        app = app.app_data(web::Data::new(server_config.trust_proxy_headers));

        // Shared, best-effort in-memory idempotency cache for event ingest.
        app = app.app_data(web::Data::new(ingest_idempotency.clone()));

        // Recent events ring-buffer for admin dashboard.
        app = app.app_data(web::Data::new(recent_events_store.clone()));

        // Add event actor if enabled
        if let Some(ref event_actor) = event_actor {
            app = app.app_data(web::Data::new(event_actor.clone()));
        }

        // Add event bus handle if enabled
        if let Some(ref event_bus) = event_bus {
            app = app.app_data(web::Data::new(event_bus.clone()));
        }

        // Invalid-client penalty bucket (RFC 9700 §2.5)
        if let Some(ref ic_limiter) = invalid_client_limiter {
            app = app.app_data(web::Data::new(
                oauth2_actix::middleware::rate_limit::InvalidClientRateLimiter(ic_limiter.clone()),
            ));
        }

        app
            // Root route
            .route(
                "/",
                web::get().to(|| async {
                    HttpResponse::Found()
                        .append_header(("Location", "/profile"))
                        .finish()
                }),
            )
            // Authentication routes
            .service(
                web::scope("/auth")
                    .route(
                        "/login",
                        web::get().to(oauth2_actix::handlers::login::login_page),
                    )
                    .route(
                        "/login",
                        web::post().to(oauth2_actix::handlers::login::login_submit),
                    )
                    .route(
                        "/logout",
                        web::post().to(oauth2_social_login::handlers::auth::logout),
                    )
                    .route(
                        "/success",
                        web::get().to(oauth2_social_login::handlers::auth::auth_success),
                    )
                    .service(
                        web::scope("/login")
                            .route(
                                "/google",
                                web::get().to(oauth2_social_login::handlers::auth::google_login),
                            )
                            .route(
                                "/microsoft",
                                web::get().to(oauth2_social_login::handlers::auth::microsoft_login),
                            )
                            .route(
                                "/github",
                                web::get().to(oauth2_social_login::handlers::auth::github_login),
                            )
                            .route(
                                "/azure",
                                web::get().to(oauth2_social_login::handlers::auth::azure_login),
                            )
                            // NOTE: Okta and Auth0 handlers not yet implemented - buttons should be hidden in UI
                            // or implement proper handlers in handlers::auth module
                            .route(
                                "/okta",
                                web::get().to(|| async {
                                    actix_web::HttpResponse::ServiceUnavailable()
                                        .body("Okta login not yet implemented")
                                }),
                            )
                            .route(
                                "/auth0",
                                web::get().to(|| async {
                                    actix_web::HttpResponse::ServiceUnavailable()
                                        .body("Auth0 login not yet implemented")
                                }),
                            ),
                    )
                    .route(
                        "/callback/{provider}",
                        web::get().to(oauth2_social_login::handlers::auth::auth_callback),
                    ),
            )
            // OAuth2 endpoints
            .service(
                web::scope("/oauth")
                    .route(
                        "/authorize",
                        web::get().to(oauth2_actix::handlers::oauth::authorize),
                    )
                    .route(
                        "/par",
                        web::post().to(oauth2_actix::handlers::oauth::par),
                    )
                    .route(
                        "/token",
                        web::post().to(oauth2_actix::handlers::oauth::token),
                    )
                    .route(
                        "/logout",
                        web::get().to(oauth2_actix::handlers::oidc_logout::logout),
                    )
                    .route(
                        "/device_authorization",
                        web::post().to(oauth2_actix::handlers::device::device_authorization),
                    )
                    .route(
                        "/device/verify",
                        web::get().to(oauth2_actix::handlers::device::verify_page),
                    )
                    .route(
                        "/device/verify",
                        web::post().to(oauth2_actix::handlers::device::verify_submit),
                    )
                    .route(
                        "/introspect",
                        web::post().to(oauth2_actix::handlers::token::introspect),
                    )
                    .route(
                        "/revoke",
                        web::post().to(oauth2_actix::handlers::token::revoke),
                    )
                    .route(
                        "/userinfo",
                        web::get().to(oauth2_actix::handlers::wellknown::userinfo),
                    )
                    .route(
                        "/userinfo",
                        web::post().to(oauth2_actix::handlers::wellknown::userinfo),
                    )
                    // OIDC Session Management 1.0: check_session_iframe
                    .route(
                        "/check_session",
                        web::get().to(oauth2_actix::handlers::session::check_session_iframe),
                    ),
            )
            // Well-known endpoints
            .service(
                web::scope("/.well-known")
                    .route(
                        "/openid-configuration",
                        web::get().to(oauth2_actix::handlers::wellknown::openid_configuration),
                    )
                    // RFC 8414 §3: authorization server metadata MUST also be served at this path.
                    .route(
                        "/oauth-authorization-server",
                        web::get().to(oauth2_actix::handlers::wellknown::openid_configuration),
                    )
                    .route(
                        "/jwks.json",
                        web::get().to(oauth2_actix::handlers::wellknown::jwks),
                    )
                    // RFC 9728: Protected Resource Metadata
                    .route(
                        "/oauth-protected-resource",
                        web::get().to(oauth2_actix::handlers::wellknown::protected_resource_metadata),
                    )
                    // Token Status List (draft-ietf-oauth-status-list)
                    .route(
                        "/oauth-authorization-server/status",
                        web::get().to(oauth2_actix::handlers::wellknown::token_status_list),
                    ),
            )
            // RFC 7591 / RFC 7592: Dynamic Client Registration & Management
            .service(
                web::scope("/connect")
                    .route(
                        "/register",
                        web::post().to(oauth2_actix::handlers::client::dynamic_register),
                    )
                    .route(
                        "/register/{client_id}",
                        web::get().to(oauth2_actix::handlers::client::read_client_configuration),
                    )
                    .route(
                        "/register/{client_id}",
                        web::put().to(oauth2_actix::handlers::client::update_client_configuration),
                    )
                    .route(
                        "/register/{client_id}",
                        web::delete().to(oauth2_actix::handlers::client::delete_client_configuration),
                    ),
            )
            // Admin endpoints (protected by AdminGuard middleware)
            .service(
                web::scope("/admin")
                    .wrap(oauth2_actix::middleware::admin_guard::AdminGuard)
                    // SPA page routes — all return the same dashboard HTML
                    .route("", web::get().to(admin_dashboard))
                    .route("/clients", web::get().to(admin_dashboard))
                    .route("/tokens", web::get().to(admin_dashboard))
                    .route("/users", web::get().to(admin_dashboard))
                    .route("/device", web::get().to(admin_dashboard))
                    .route("/keys", web::get().to(admin_dashboard))
                    .route("/metrics", web::get().to(admin_dashboard))
                    .route("/events", web::get().to(admin_dashboard))
                    .route("/denylist", web::get().to(admin_dashboard))
                    .route("/audit", web::get().to(admin_dashboard))
                    .route(
                        "/clients/register",
                        web::post().to(oauth2_actix::handlers::client::register_client),
                    )
                    .service(
                        web::scope("/api")
                            .route(
                                "/dashboard",
                                web::get().to(oauth2_actix::handlers::admin::dashboard),
                            )
                            .route(
                                "/capabilities",
                                web::get().to(oauth2_actix::handlers::admin::capabilities),
                            )
                            // Clients
                            .route(
                                "/clients",
                                web::get().to(oauth2_actix::handlers::admin::list_clients),
                            )
                            .route(
                                "/clients",
                                web::post().to(oauth2_actix::handlers::admin_extra::create_client),
                            )
                            .route(
                                "/clients/{id}",
                                web::get().to(oauth2_actix::handlers::admin::get_client),
                            )
                            .route(
                                "/clients/{id}",
                                web::put().to(oauth2_actix::handlers::admin_extra::update_client),
                            )
                            .route(
                                "/clients/{id}",
                                web::delete().to(oauth2_actix::handlers::admin::delete_client),
                            )
                            .route(
                                "/clients/{id}/enabled",
                                web::post()
                                    .to(oauth2_actix::handlers::admin_extra::set_client_enabled),
                            )
                            .route(
                                "/clients/{id}/regenerate-secret",
                                web::post()
                                    .to(oauth2_actix::handlers::admin_extra::regenerate_client_secret),
                            )
                            // Tokens
                            .route(
                                "/tokens",
                                web::get().to(oauth2_actix::handlers::admin::list_tokens),
                            )
                            .route(
                                "/tokens/{id}",
                                web::get().to(oauth2_actix::handlers::admin::get_token),
                            )
                            .route(
                                "/tokens/{id}/revoke",
                                web::post().to(oauth2_actix::handlers::admin::admin_revoke_token),
                            )
                            .route(
                                "/tokens/revoke-by-user",
                                web::post()
                                    .to(oauth2_actix::handlers::admin_extra::bulk_revoke_by_user),
                            )
                            .route(
                                "/tokens/revoke-by-client",
                                web::post()
                                    .to(oauth2_actix::handlers::admin_extra::bulk_revoke_by_client),
                            )
                            // Users
                            .route(
                                "/users",
                                web::get().to(oauth2_actix::handlers::admin::list_users),
                            )
                            .route(
                                "/users",
                                web::post().to(oauth2_actix::handlers::admin_extra::create_user),
                            )
                            .route(
                                "/users/{id}",
                                web::get().to(oauth2_actix::handlers::admin::get_user),
                            )
                            .route(
                                "/users/{id}",
                                web::put().to(oauth2_actix::handlers::admin_extra::update_user),
                            )
                            .route(
                                "/users/{id}",
                                web::delete().to(oauth2_actix::handlers::admin_extra::delete_user),
                            )
                            .route(
                                "/users/{id}/enabled",
                                web::post()
                                    .to(oauth2_actix::handlers::admin_extra::set_user_enabled),
                            )
                            .route(
                                "/users/{id}/role",
                                web::post()
                                    .to(oauth2_actix::handlers::admin_extra::set_user_role),
                            )
                            .route(
                                "/users/{id}/password",
                                web::post()
                                    .to(oauth2_actix::handlers::admin_extra::reset_user_password),
                            )
                            // Denylist
                            .route(
                                "/denylist",
                                web::get().to(oauth2_actix::handlers::admin_extra::list_denylist),
                            )
                            .route(
                                "/denylist",
                                web::post().to(oauth2_actix::handlers::admin_extra::add_denylist),
                            )
                            .route(
                                "/denylist/{id}",
                                web::delete()
                                    .to(oauth2_actix::handlers::admin_extra::remove_denylist),
                            )
                            // Audit log
                            .route(
                                "/audit",
                                web::get().to(oauth2_actix::handlers::admin_extra::list_audit_log),
                            )
                            // Device authorizations
                            .route(
                                "/device",
                                web::get().to(oauth2_actix::handlers::admin::list_device_authorizations),
                            )
                            .route(
                                "/device/{code}/expire",
                                web::post().to(oauth2_actix::handlers::admin::expire_device_code),
                            )
                            // JWT keys
                            .service(
                                web::scope("/keys")
                                    .route("/rotate", web::post().to(oauth2_actix::handlers::admin_keys::rotate_key))
                                    .route("", web::get().to(oauth2_actix::handlers::admin_keys::list_keys))
                            )
                            // Recent events (admin)
                            .route(
                                "/events/recent",
                                web::get().to(oauth2_actix::handlers::events::recent_events),
                            ),
                    ),
            )
            // User profile page (landing page for non-admin users)
            .route(
                "/profile",
                web::get().to(oauth2_actix::handlers::profile::profile_page),
            )
            // Error page
            .route("/error", web::get().to(error_page))
            // Observability endpoints
            .route(
                "/health",
                web::get().to(oauth2_actix::handlers::admin::health),
            )
            .route(
                "/ready",
                web::get().to(oauth2_actix::handlers::admin::readiness),
            )
            .route(
                "/metrics",
                web::get().to(oauth2_actix::handlers::admin::system_metrics),
            )
            // Eventing endpoints
            .service(
                web::scope("/events")
                    .route(
                        "/ingest",
                        web::post().to(oauth2_actix::handlers::events::ingest),
                    )
                    .route(
                        "/health",
                        web::get().to(oauth2_actix::handlers::events::health),
                    ),
            )
            // Swagger UI
            .service(
                SwaggerUi::new("/swagger-ui/{_:.*}").url("/api-docs/openapi.json", openapi.clone()),
            )
            // Static files
            .service(Files::new("/static", "./static"))
    })
    // Prevent idle connections from consuming file descriptors indefinitely.
    .keep_alive(std::time::Duration::from_secs(75))
    // Cap how long we wait for request headers after accepting a connection.
    .client_request_timeout(std::time::Duration::from_secs(30))
    // Cap how long we wait for the client to disconnect after sending a response.
    .client_disconnect_timeout(std::time::Duration::from_secs(5))
    // Increase the listen backlog in high-traffic deployments so that the OS
    // can queue more incoming TCP connections while the server is busy.
    .backlog(2048);

    if let Some(workers) = config.server.workers {
        tracing::info!(workers, "HTTP worker override configured");
        server = server.workers(workers);
    }

    let server = server.bind(&bind_addr)?.run();

    server.await?;

    // Shutdown telemetry
    oauth2_observability::shutdown_telemetry();

    Ok(())
}

// Admin dashboard HTML page
async fn admin_dashboard() -> HttpResponse {
    let html = std::fs::read_to_string("templates/admin_dashboard.html")
        .unwrap_or_else(|_| r#"
            <!DOCTYPE html>
            <html>
            <head><title>Admin Dashboard</title></head>
            <body>
                <h1>OAuth2 Server Admin Dashboard</h1>
                <p>Dashboard template not found. Please ensure templates/admin_dashboard.html exists.</p>
                <ul>
                    <li><a href=\"/swagger-ui\">API Documentation</a></li>
                    <li><a href=\"/metrics\">Prometheus Metrics</a></li>
                    <li><a href=\"/health\">Health Check</a></li>
                </ul>
            </body>
            </html>
        "#
        .to_string());

    HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(html)
}

// Error page
async fn error_page() -> HttpResponse {
    let html = std::fs::read_to_string("templates/error.html").unwrap_or_else(|_| {
        r#"
            <!DOCTYPE html>
            <html>
            <head><title>Error</title></head>
            <body>
                <h1>Error</h1>
                <p>An error occurred.</p>
                <a href=\"/\">Go back</a>
            </body>
            </html>
        "#
        .to_string()
    });

    HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(html)
}
