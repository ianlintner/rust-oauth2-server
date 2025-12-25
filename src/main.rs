mod actors;
mod config;
mod db;
mod handlers;
mod metrics;
mod middleware;
mod models;
mod services;
mod telemetry;

use actix::Actor;
use actix_cors::Cors;
use actix_files::Files;
use actix_session::{storage::CookieSessionStore, SessionMiddleware};
use actix_web::{cookie::Key, middleware as actix_middleware, web, App, HttpResponse, HttpServer};
use std::sync::Arc;
use tracing_actix_web::TracingLogger;
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

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

    // Initialize database
    let db = db::Database::new(&config.database.url)
        .await
        .expect("Failed to connect to database");

    db.init().await.expect("Failed to initialize database");
    tracing::info!("Database initialized");

    let db = Arc::new(db);
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

    // Start actors
    let token_actor = actors::TokenActor::new(db.clone(), jwt_secret.clone()).start();
    let client_actor = actors::ClientActor::new(db.clone()).start();
    let auth_actor = actors::AuthActor::new(db.clone()).start();

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

        App::new()
            // Middleware
            .wrap(SessionMiddleware::new(
                CookieSessionStore::default(),
                session_key.clone(),
            ))
            .wrap(TracingLogger::default())
            .wrap(actix_middleware::Logger::default())
            .wrap(actix_middleware::Compress::default())
            .wrap(middleware::MetricsMiddleware::new(metrics.clone()))
            .wrap(cors)
            // Shared state
            .app_data(web::Data::new(token_actor.clone()))
            .app_data(web::Data::new(client_actor.clone()))
            .app_data(web::Data::new(auth_actor.clone()))
            .app_data(web::Data::new(jwt_secret.clone()))
            .app_data(web::Data::new(db.clone()))
            .app_data(web::Data::new(metrics.clone()))
            .app_data(web::Data::new(social_config.clone()))
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
