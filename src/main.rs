mod actors;
mod config;
mod db;
mod events;
mod handlers;
mod metrics;
mod middleware;
mod models;
mod services;
mod storage;
mod telemetry;

use actix::Actor;
use actix_cors::Cors;
use actix_files::Files;
use actix_session::{storage::CookieSessionStore, SessionMiddleware};
use actix_web::body::MessageBody;
use actix_web::dev::{ServiceRequest, ServiceResponse};
use actix_web::{cookie::Key, middleware as actix_middleware, web, App, HttpResponse, HttpServer};
use std::sync::Arc;
use std::time::Duration;
use tracing_actix_web::{DefaultRootSpanBuilder, RootSpanBuilder, TracingLogger};
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

#[derive(Clone, Copy)]
struct OtelRootSpanBuilder;

impl RootSpanBuilder for OtelRootSpanBuilder {
    fn on_request_start(request: &ServiceRequest) -> tracing::Span {
        // Build the default root span and declare a `span_id` field up-front.
        // We then populate both trace_id and span_id using the active OpenTelemetry context.
        let span = tracing_actix_web::root_span!(request, span_id = tracing::field::Empty);
        telemetry::annotate_span_with_trace_ids(&span);
        span
    }

    fn on_request_end<B: MessageBody>(
        span: tracing::Span,
        outcome: &Result<ServiceResponse<B>, actix_web::Error>,
    ) {
        DefaultRootSpanBuilder::on_request_end(span, outcome);
    }
}

#[derive(OpenApi)]
#[openapi(
    components(
        schemas(
            models::TokenResponse,
            models::IntrospectionResponse,
            models::ClientRegistration,
            models::ClientCredentials,
            models::OAuth2Error,
        )
    ),
    tags(
        (name = "OAuth2", description = "OAuth2 authentication and authorization endpoints"),
        (name = "Client Management", description = "Client registration and management"),
        (name = "Token Management", description = "Token introspection and revocation"),
        (name = "Admin", description = "Administrative and monitoring endpoints"),
        (name = "Observability", description = "Health checks and metrics"),
    ),
    info(
        title = "OAuth2 Server API",
        version = "0.1.0",
        description = "A complete OAuth2 server implementation with Actix-web, featuring social logins and OIDC support",
        contact(
            name = "API Support",
            email = "support@example.com"
        ),
        license(
            name = "MIT OR Apache-2.0"
        )
    )
)]
struct ApiDoc;

// Helper function to parse event types from configuration strings
fn parse_event_types(event_type_strings: &[String]) -> Vec<events::EventType> {
    use events::EventType;

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

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Initialize telemetry and tracing
    telemetry::init_telemetry("oauth2_server").unwrap_or_else(|e| {
        eprintln!("Failed to initialize telemetry: {}", e);
        // Fall back to basic logging
        env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));
    });

    tracing::info!("Starting OAuth2 Server...");

    // Load configuration
    let config = config::Config::default();

    if std::env::var("OAUTH2_DEBUG_CONFIG").ok().as_deref() == Some("1") {
        if let Ok(cfg_json) = serde_json::to_string_pretty(&config.sanitized()) {
            tracing::info!(config = %cfg_json, "Loaded configuration (sanitized)");
        }
    }

    // Validate configuration for production
    if let Err(e) = config.validate_for_production() {
        tracing::warn!("Configuration validation warning: {}", e);
        tracing::warn!("This configuration should only be used for testing!");
    }

    tracing::info!("Configuration loaded");

    // Load social login configuration
    let social_config = Arc::new(models::SocialLoginConfig::from_env());
    tracing::info!("Social login configuration loaded");

    // Initialize metrics
    let metrics = metrics::Metrics::new().expect("Failed to initialize metrics");
    tracing::info!("Metrics initialized");

    // Initialize storage backend (SQLx by default, optional MongoDB)
    tracing::info!(database_url = %config.database.url, "Connecting to storage backend");
    let storage = storage::create_storage(&config.database.url)
        .await
        .expect("Failed to create storage backend");

    storage
        .init()
        .await
        .expect("Failed to initialize storage backend");
    tracing::info!("Storage backend initialized");
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
    } else {
        tracing::warn!("OAUTH2_SESSION_KEY not set. Generating random key. Sessions will not persist across restarts!");
        Key::generate()
    };

    // Initialize event system first
    let event_actor = if config.events.enabled {
        use events::{ConsoleEventLogger, EventFilter, InMemoryEventLogger};
        use std::sync::Arc;

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
        let plugins: Vec<Arc<dyn events::EventPlugin>> = match config.events.backend.as_str() {
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
                        .unwrap_or_else(events::default_stream_name);

                    let maxlen = config.events.redis_maxlen.or_else(events::default_maxlen);

                    match events::RedisStreamsEventPublisher::connect(&url, stream, maxlen).await {
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

                    match events::KafkaEventPublisher::new(
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

                    match events::RabbitEventPublisher::connect(&url, exchange, routing_key).await {
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

        let actor = events::event_actor::EventActor::new(plugins, filter).start();
        tracing::info!("Event system initialized");
        Some(actor)
    } else {
        tracing::info!("Event system disabled");
        None
    };

    // Wrap the actor-backed event system behind the stable EventBus contract.
    let event_bus = event_actor.as_ref().map(|addr| {
        let bus = events::ActixEventBus::new(addr.clone());
        events::EventBusHandle::new(Arc::new(bus))
    });

    // Best-effort Phase 1 in-memory idempotency cache for ingest.
    let ingest_idempotency = handlers::events::IdempotencyStore::new(Duration::from_secs(5 * 60))
        // Explicitly set to default to make it configurable without changing call sites.
        .with_max_entries(100_000);

    // Start actors with event system
    let token_actor = if let Some(ref event_bus) = event_bus {
        actors::TokenActor::with_events(storage.clone(), jwt_secret.clone(), event_bus.clone())
            .start()
    } else {
        actors::TokenActor::new(storage.clone(), jwt_secret.clone()).start()
    };

    let client_actor = if let Some(ref event_bus) = event_bus {
        actors::ClientActor::with_events(storage.clone(), event_bus.clone()).start()
    } else {
        actors::ClientActor::new(storage.clone()).start()
    };

    let auth_actor = if let Some(ref event_bus) = event_bus {
        actors::AuthActor::with_events(storage.clone(), event_bus.clone()).start()
    } else {
        actors::AuthActor::new(storage.clone()).start()
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

    // Start HTTP server
    let server = HttpServer::new(move || {
        let cors = Cors::default()
            .allow_any_origin()
            .allow_any_method()
            .allow_any_header()
            .max_age(3600);

        let mut app = App::new()
            // Middleware
            .wrap(SessionMiddleware::new(
                CookieSessionStore::default(),
                session_key.clone(),
            ))
            .wrap(TracingLogger::<OtelRootSpanBuilder>::new())
            .wrap(actix_middleware::Logger::default())
            .wrap(actix_middleware::Compress::default())
            .wrap(middleware::MetricsMiddleware::new(metrics.clone()))
            .wrap(cors)
            // Shared state
            .app_data(web::Data::new(token_actor.clone()))
            .app_data(web::Data::new(client_actor.clone()))
            .app_data(web::Data::new(auth_actor.clone()))
            .app_data(web::Data::new(jwt_secret.clone()))
            .app_data(web::Data::new(storage.clone()))
            .app_data(web::Data::new(metrics.clone()))
            .app_data(web::Data::new(social_config.clone()));

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
                        .append_header(("Location", "/auth/login"))
                        .finish()
                }),
            )
            // Authentication routes
            .service(
                web::scope("/auth")
                    .route("/login", web::get().to(handlers::auth::login_page))
                    .route("/logout", web::post().to(handlers::auth::logout))
                    .route("/success", web::get().to(handlers::auth::auth_success))
                    .service(
                        web::scope("/login")
                            .route("/google", web::get().to(handlers::auth::google_login))
                            .route("/microsoft", web::get().to(handlers::auth::microsoft_login))
                            .route("/github", web::get().to(handlers::auth::github_login))
                            .route("/azure", web::get().to(handlers::auth::microsoft_login)) // Azure uses Microsoft endpoint
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
                        web::get().to(handlers::auth::auth_callback),
                    ),
            )
            // OAuth2 endpoints
            .service(
                web::scope("/oauth")
                    .route("/authorize", web::get().to(handlers::oauth::authorize))
                    .route("/token", web::post().to(handlers::oauth::token))
                    .route("/introspect", web::post().to(handlers::token::introspect))
                    .route("/revoke", web::post().to(handlers::token::revoke)),
            )
            // Client management endpoints
            .service(web::scope("/clients").route(
                "/register",
                web::post().to(handlers::client::register_client),
            ))
            // Well-known endpoints
            .service(web::scope("/.well-known").route(
                "/openid-configuration",
                web::get().to(handlers::wellknown::openid_configuration),
            ))
            // Admin endpoints
            .service(
                web::scope("/admin")
                    .route("", web::get().to(admin_dashboard))
                    .service(
                        web::scope("/api")
                            .route("/dashboard", web::get().to(handlers::admin::dashboard))
                            .route("/clients", web::get().to(handlers::admin::list_clients))
                            .route("/tokens", web::get().to(handlers::admin::list_tokens))
                            .route(
                                "/tokens/{id}/revoke",
                                web::post().to(handlers::admin::admin_revoke_token),
                            )
                            .route(
                                "/clients/{id}",
                                web::delete().to(handlers::admin::delete_client),
                            ),
                    ),
            )
            // Error page
            .route("/error", web::get().to(error_page))
            // Observability endpoints
            .route("/health", web::get().to(handlers::admin::health))
            .route("/ready", web::get().to(handlers::admin::readiness))
            .route("/metrics", web::get().to(handlers::admin::system_metrics))
            // Eventing endpoints
            .service(
                web::scope("/events")
                    .route("/ingest", web::post().to(handlers::events::ingest))
                    .route("/health", web::get().to(handlers::events::health)),
            )
            // Swagger UI
            .service(
                SwaggerUi::new("/swagger-ui/{_:.*}").url("/api-docs/openapi.json", openapi.clone()),
            )
            // Static files
            .service(Files::new("/static", "./static"))
    })
    .bind(&bind_addr)?
    .run();

    server.await?;

    // Shutdown telemetry
    telemetry::shutdown_telemetry();

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
                    <li><a href="/swagger-ui">API Documentation</a></li>
                    <li><a href="/metrics">Prometheus Metrics</a></li>
                    <li><a href="/health">Health Check</a></li>
                </ul>
            </body>
            </html>
        "#.to_string());

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
                <a href="/">Go back</a>
            </body>
            </html>
        "#
        .to_string()
    });

    HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(html)
}
