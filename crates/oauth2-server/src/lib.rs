use actix::Actor;
use actix_cors::Cors;
use actix_files::Files;
use actix_session::{storage::CookieSessionStore, SessionMiddleware};
use actix_web::body::MessageBody;
use actix_web::dev::{ServiceRequest, ServiceResponse};
use actix_web::middleware::Condition;
use actix_web::{cookie::Key, middleware as actix_middleware, web, App, HttpResponse, HttpServer};
use oauth2_core::models::key_set::{Algorithm as KeyAlgorithm, KeySet, SigningKey};
use oauth2_openapi::ApiDoc;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tracing_actix_web::{DefaultRootSpanBuilder, RootSpanBuilder, TracingLogger};
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

/// The known-insecure default seed password shipped with the server.
pub const INSECURE_DEFAULT_SEED_PASSWORD: &str = "changeme";

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
        database_url = %config.database.url,
        max_connections = config.database.max_connections,
        min_connections = config.database.min_connections,
        acquire_timeout_secs = config.database.acquire_timeout_secs,
        "Connecting to storage backend"
    );
    let pool_config = oauth2_storage_factory::sqlx::PoolConfig {
        max_connections: config.database.max_connections,
        min_connections: config.database.min_connections,
        acquire_timeout: std::time::Duration::from_secs(config.database.acquire_timeout_secs),
        idle_timeout: std::time::Duration::from_secs(config.database.idle_timeout_secs),
    };
    let storage = oauth2_storage_factory::create_storage_with_pool_config(
        &config.database.url,
        Some(pool_config),
        config.database.read_url.as_deref(),
    )
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
            "console" => vec![Arc::new(ConsoleEventLogger::new())],
            "in_memory" => vec![Arc::new(InMemoryEventLogger::new(1000))],
            "both" => vec![
                Arc::new(InMemoryEventLogger::new(1000)),
                Arc::new(ConsoleEventLogger::new()),
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
                        Ok(p) => vec![Arc::new(p)],
                        Err(e) => {
                            tracing::warn!(error = %e, "Redis event backend init failed; falling back to in_memory");
                            vec![Arc::new(InMemoryEventLogger::new(1000))]
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
                        Ok(p) => vec![Arc::new(p)],
                        Err(e) => {
                            tracing::warn!(error = %e, "Kafka event backend init failed; falling back to in_memory");
                            vec![Arc::new(InMemoryEventLogger::new(1000))]
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
                        Ok(p) => vec![Arc::new(p)],
                        Err(e) => {
                            tracing::warn!(error = %e, "Rabbit event backend init failed; falling back to in_memory");
                            vec![Arc::new(InMemoryEventLogger::new(1000))]
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
                    tracing::warn!(
                        "Redis rate limiting backend requested but not yet available \
                             in this build; falling back to in_memory"
                    );
                    Arc::new(oauth2_ratelimit::in_memory::InMemoryRateLimiter::new(
                        rl_config.max_requests,
                        rl_config.window_secs,
                    ))
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
    let issuer = config
        .server
        .public_url
        .clone()
        .unwrap_or_else(|| format!("http://{}:{}", config.server.host, config.server.port));

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
        for _ in 0..shard_count {
            let shard = if let Some(ref event_bus) = event_bus {
                let eb = event_bus.clone();
                actix::Actor::create(|ctx| {
                    ctx.set_mailbox_capacity(ACTOR_MAILBOX_CAPACITY);
                    oauth2_actix::actors::TokenActor::with_events(
                        storage.clone(),
                        jwt_secret.clone(),
                        eb,
                    )
                    .with_keyset(keyset.clone())
                })
            } else {
                actix::Actor::create(|ctx| {
                    ctx.set_mailbox_capacity(ACTOR_MAILBOX_CAPACITY);
                    oauth2_actix::actors::TokenActor::new(storage.clone(), jwt_secret.clone())
                        .with_keyset(keyset.clone())
                })
            };
            shards.push(shard);
        }
        oauth2_actix::actors::TokenActorPool::new(shards)
    };
    tracing::info!(shards = shard_count, "TokenActorPool started");

    let client_actor = if let Some(ref event_bus) = event_bus {
        actix::Actor::create(|ctx| {
            ctx.set_mailbox_capacity(ACTOR_MAILBOX_CAPACITY);
            oauth2_actix::actors::ClientActor::with_events(storage.clone(), event_bus.clone())
        })
    } else {
        actix::Actor::create(|ctx| {
            ctx.set_mailbox_capacity(ACTOR_MAILBOX_CAPACITY);
            oauth2_actix::actors::ClientActor::new(storage.clone())
        })
    };

    let auth_actor = if let Some(ref event_bus) = event_bus {
        actix::Actor::create(|ctx| {
            ctx.set_mailbox_capacity(ACTOR_MAILBOX_CAPACITY);
            oauth2_actix::actors::AuthActor::with_events(storage.clone(), event_bus.clone())
        })
    } else {
        actix::Actor::create(|ctx| {
            ctx.set_mailbox_capacity(ACTOR_MAILBOX_CAPACITY);
            oauth2_actix::actors::AuthActor::new(storage.clone())
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
    let key_rotation_grace_hours = oauth2_actix::handlers::admin_keys::KeyRotationGraceHours(
        config.jwt.key_rotation_grace_hours,
    );

    // Start HTTP server
    let server = HttpServer::new(move || {
        let cors = {
            let origins = server_config.allowed_origins.clone();
            let mut cors_builder = Cors::default()
                .allow_any_method()
                .allow_any_header()
                .max_age(3600);
            if origins.is_empty() {
                cors_builder
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
                    .add(("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data:")),
            )
            .wrap(cors)
            .wrap(oauth2_observability::actix::MetricsMiddleware::new(
                metrics.clone(),
            ))
            .wrap(actix_middleware::Compress::default())
            .wrap(actix_middleware::Logger::default())
            .wrap(TracingLogger::<OtelRootSpanBuilder>::new())
            .wrap(SessionMiddleware::new(
                CookieSessionStore::default(),
                session_key.clone(),
            ))
            .wrap(rl_middleware)
            // Resilience is the outermost layer (last .wrap() call).
            // Tripped circuit / full concurrency pool → 503 on the cheapest
            // path, before rate-limiting, session, or logging run.
            .wrap(resilience_mw)
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
            .app_data(web::Data::new(oidc_config.clone()))
            .app_data(web::Data::new(keyset.clone()))
            .app_data(web::Data::new(key_rotation_grace_hours))
            // Stateless JWT validation flag (skips DB lookup during introspection)
            .app_data(web::Data::new(config.jwt.stateless_validation));

        // Shared, best-effort in-memory idempotency cache for event ingest.
        app = app.app_data(web::Data::new(ingest_idempotency.clone()));

        // Add event actor if enabled
        if let Some(ref event_actor) = event_actor {
            app = app.app_data(web::Data::new(event_actor.clone()));
        }

        // Add event bus handle if enabled
        if let Some(ref event_bus) = event_bus {
            app = app.app_data(web::Data::new(event_bus.clone()));
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
                                web::get().to(oauth2_social_login::handlers::auth::microsoft_login),
                            ) // Azure uses Microsoft endpoint
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
                        "/token",
                        web::post().to(oauth2_actix::handlers::oauth::token),
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
                    ),
            )
            // Well-known endpoints
            .service(
                web::scope("/.well-known")
                    .route(
                        "/openid-configuration",
                        web::get().to(oauth2_actix::handlers::wellknown::openid_configuration),
                    )
                    .route(
                        "/jwks.json",
                        web::get().to(oauth2_actix::handlers::wellknown::jwks),
                    ),
            )
            // Admin endpoints (protected by AdminGuard middleware)
            .service(
                web::scope("/admin")
                    .wrap(oauth2_actix::middleware::admin_guard::AdminGuard)
                    .route("", web::get().to(admin_dashboard))
                    .route("/clients", web::get().to(admin_dashboard))
                    .route("/tokens", web::get().to(admin_dashboard))
                    .route("/users", web::get().to(admin_dashboard))
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
                                "/clients",
                                web::get().to(oauth2_actix::handlers::admin::list_clients),
                            )
                            .route(
                                "/tokens",
                                web::get().to(oauth2_actix::handlers::admin::list_tokens),
                            )
                            .route(
                                "/users",
                                web::get().to(oauth2_actix::handlers::admin::list_users),
                            )
                            .route(
                                "/tokens/{id}/revoke",
                                web::post().to(oauth2_actix::handlers::admin::admin_revoke_token),
                            )
                            .route(
                                "/clients/{id}",
                                web::delete().to(oauth2_actix::handlers::admin::delete_client),
                            )
                            .service(
                                web::scope("/keys")
                                    .route("/rotate", web::post().to(oauth2_actix::handlers::admin_keys::rotate_key))
                                    .route("", web::get().to(oauth2_actix::handlers::admin_keys::list_keys))
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
    .backlog(2048)
    .bind(&bind_addr)?
    .run();

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
