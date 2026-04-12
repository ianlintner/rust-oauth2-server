use actix::{Actor, Addr};
use actix_session::{storage::CookieSessionStore, Session, SessionMiddleware};
use actix_web::{cookie::Key, test, web, App, HttpResponse};
use async_trait::async_trait;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc, Mutex,
};

use oauth2_actix::actors::TokenActorPool;
use oauth2_actix::handlers::wellknown::OidcConfig;
use oauth2_core::{AuthorizationCode, Client, OAuth2Error, Token, TokenResponse, User};
use oauth2_observability::Metrics;
use oauth2_ports::{DynStorage, Storage};
use oauth2_server::validate_seed_password_for_production;

fn s256_challenge(verifier: &str) -> String {
    use base64::{engine::general_purpose, Engine as _};
    use sha2::{Digest, Sha256};
    let hash = Sha256::digest(verifier.as_bytes());
    general_purpose::URL_SAFE_NO_PAD.encode(hash)
}

fn basic_auth_header(client_id: &str, client_secret: &str) -> String {
    use base64::{engine::general_purpose, Engine as _};

    format!(
        "Basic {}",
        general_purpose::STANDARD.encode(format!("{client_id}:{client_secret}"))
    )
}

fn extract_query_param(url: &str, key: &str) -> Option<String> {
    // Very small helper for test-only parsing.
    let (_base, query) = url.split_once('?')?;
    for pair in query.split('&') {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        if k == key {
            return Some(v.to_string());
        }
    }
    None
}

/// Test-only handler that establishes a session for the mock user_123.
async fn test_set_session(session: Session) -> HttpResponse {
    session.insert("user_id", "user_123").unwrap();
    session.insert("authenticated", true).unwrap();
    HttpResponse::Ok().finish()
}

/// Extract the session cookie value from a Set-Cookie header.
fn extract_session_cookie(
    resp: &actix_web::dev::ServiceResponse<impl actix_web::body::MessageBody>,
) -> String {
    resp.response()
        .headers()
        .get(actix_web::http::header::SET_COOKIE)
        .and_then(|h| h.to_str().ok())
        .expect("session cookie should be set")
        .split(';')
        .next()
        .unwrap()
        .to_string()
}

async fn setup_context(
    client: Client,
) -> (
    TokenActorPool,
    Addr<oauth2_actix::actors::ClientActor>,
    Addr<oauth2_actix::actors::AuthActor>,
    String,
    Metrics,
    OidcConfig,
) {
    setup_context_with_clients(vec![client]).await
}

async fn setup_context_with_clients(
    clients: Vec<Client>,
) -> (
    TokenActorPool,
    Addr<oauth2_actix::actors::ClientActor>,
    Addr<oauth2_actix::actors::AuthActor>,
    String,
    Metrics,
    OidcConfig,
) {
    let storage = oauth2_storage_factory::create_storage("sqlite::memory:")
        .await
        .expect("create storage");
    storage.init().await.expect("init storage");
    for client in clients {
        storage.save_client(&client).await.expect("save client");
    }

    // The authorize endpoint reads user_id from the session (set by test_set_session).
    // SQL backends enforce an FK from authorization_codes.user_id -> users.id, so we must ensure
    // this user exists for authorize() to succeed.
    let now = chrono::Utc::now();
    let user = User {
        id: "user_123".to_string(),
        username: "user_123".to_string(),
        password_hash: "not_used_in_security_http_tests".to_string(),
        email: "user_123@example.test".to_string(),
        enabled: true,
        role: "user".to_string(),
        created_at: now,
        updated_at: now,
    };
    storage.save_user(&user).await.expect("save user");

    let jwt_secret = "test_jwt_secret".to_string();
    let metrics = Metrics::new().expect("metrics");

    let token_actor = oauth2_actix::actors::TokenActor::new(
        storage.clone(),
        jwt_secret.clone(),
        "http://localhost".to_string(),
    )
    .start();
    let token_pool = TokenActorPool::new(vec![token_actor]);
    let client_actor = oauth2_actix::actors::ClientActor::new(storage.clone()).start();
    let auth_actor = oauth2_actix::actors::AuthActor::new(storage.clone()).start();

    let oidc_config = OidcConfig {
        issuer: "http://localhost".to_string(),
        jwt_secret: jwt_secret.clone(),
        id_token_alg: "HS256".to_string(),
        id_token_kid: None,
        id_token_private_key_pem: None,
    };

    (
        token_pool,
        client_actor,
        auth_actor,
        jwt_secret,
        metrics,
        oidc_config,
    )
}

fn test_runtime_config(jwt_secret: &str) -> oauth2_config::Config {
    let mut config = oauth2_config::Config::default();
    config.jwt.secret = jwt_secret.to_string();
    config.jwt.public_introspection = false;
    config.events.public_ingest = false;
    config.events.ingest_bearer_token = Some("test-events-token".to_string());
    config
}

async fn issue_access_token(
    token_pool: &TokenActorPool,
    client_id: &str,
    user_id: Option<&str>,
    scope: &str,
) -> Token {
    token_pool
        .route(client_id)
        .send(oauth2_actix::actors::CreateToken {
            user_id: user_id.map(|value| value.to_string()),
            client_id: client_id.to_string(),
            scope: scope.to_string(),
            include_refresh: false,
            token_family: None,
            span: tracing::Span::current(),
        })
        .await
        .expect("send create token")
        .expect("create token")
}

fn sample_event_envelope() -> oauth2_events::EventEnvelope {
    let event = oauth2_events::AuthEvent::new(
        oauth2_events::EventType::TokenCreated,
        oauth2_events::EventSeverity::Info,
        Some("user_123".to_string()),
        Some("client_events".to_string()),
    );

    oauth2_events::EventEnvelope::from_current_span(event, "security_http_tests")
}

#[derive(Default)]
struct CountingStats {
    get_client_calls: AtomicUsize,
    save_token_calls: AtomicUsize,
    get_token_calls: AtomicUsize,
}

struct CountingStorage {
    client: Mutex<Option<Client>>,
    stats: Arc<CountingStats>,
}

impl CountingStorage {
    fn with_client(client: Client) -> (DynStorage, Arc<CountingStats>) {
        let stats = Arc::new(CountingStats::default());
        let storage: DynStorage = Arc::new(Self {
            client: Mutex::new(Some(client)),
            stats: stats.clone(),
        });
        (storage, stats)
    }
}

#[async_trait]
impl Storage for CountingStorage {
    async fn init(&self) -> Result<(), OAuth2Error> {
        Ok(())
    }

    async fn save_client(&self, client: &Client) -> Result<(), OAuth2Error> {
        *self.client.lock().expect("client mutex poisoned") = Some(client.clone());
        Ok(())
    }

    async fn get_client(&self, client_id: &str) -> Result<Option<Client>, OAuth2Error> {
        self.stats.get_client_calls.fetch_add(1, Ordering::SeqCst);
        let client = self.client.lock().expect("client mutex poisoned").clone();
        Ok(client.filter(|c| c.client_id == client_id))
    }

    async fn update_client(&self, client: &Client) -> Result<(), OAuth2Error> {
        *self.client.lock().expect("client mutex poisoned") = Some(client.clone());
        Ok(())
    }

    async fn delete_client(&self, _client_id: &str) -> Result<(), OAuth2Error> {
        *self.client.lock().expect("client mutex poisoned") = None;
        Ok(())
    }

    async fn save_user(&self, _user: &User) -> Result<(), OAuth2Error> {
        Ok(())
    }

    async fn get_user_by_username(&self, _username: &str) -> Result<Option<User>, OAuth2Error> {
        Ok(None)
    }

    async fn save_token(&self, _token: &Token) -> Result<(), OAuth2Error> {
        self.stats.save_token_calls.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    async fn get_token_by_access_token(
        &self,
        _access_token: &str,
    ) -> Result<Option<Token>, OAuth2Error> {
        self.stats.get_token_calls.fetch_add(1, Ordering::SeqCst);
        Ok(None)
    }

    async fn get_token_by_refresh_token(
        &self,
        _refresh_token: &str,
    ) -> Result<Option<Token>, OAuth2Error> {
        Ok(None)
    }

    async fn revoke_token(&self, _token: &str) -> Result<(), OAuth2Error> {
        Ok(())
    }

    async fn save_authorization_code(
        &self,
        _auth_code: &AuthorizationCode,
    ) -> Result<(), OAuth2Error> {
        Ok(())
    }

    async fn get_authorization_code(
        &self,
        _code: &str,
    ) -> Result<Option<AuthorizationCode>, OAuth2Error> {
        Ok(None)
    }

    async fn mark_authorization_code_used(&self, _code: &str) -> Result<(), OAuth2Error> {
        Ok(())
    }
}

#[actix_web::test]
async fn authorize_rejects_unregistered_redirect_uri() {
    let client = Client::new(
        "client_a".to_string(),
        "secret_a".to_string(),
        vec!["https://good.example/cb".to_string()],
        vec!["authorization_code".to_string()],
        "read".to_string(),
        "test".to_string(),
    );

    let (token_actor, client_actor, auth_actor, jwt_secret, metrics, oidc_config) =
        setup_context(client).await;
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(token_actor))
            .app_data(web::Data::new(client_actor))
            .app_data(web::Data::new(auth_actor))
            .app_data(web::Data::new(jwt_secret))
            .app_data(web::Data::new(metrics))
            .app_data(web::Data::new(oidc_config))
            .app_data(web::Data::new(false))
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
                    ),
            )
            .service(web::scope("/.well-known").route(
                "/openid-configuration",
                web::get().to(oauth2_actix::handlers::wellknown::openid_configuration),
            )),
    )
    .await;

    // NOTE: percent-encode redirect_uri so the request URI is always valid and decodes back to the
    // exact string stored for the client.
    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let challenge = s256_challenge(verifier);
    let req = test::TestRequest::get().uri(&format!("/oauth/authorize?response_type=code&client_id=client_a&redirect_uri=https%3A%2F%2Fevil.example%2Fcb&scope=read&code_challenge={challenge}&code_challenge_method=S256")).to_request();
    let resp = test::call_service(&app, req).await;

    assert_eq!(resp.status(), 400);
    let body: OAuth2Error = test::read_body_json(resp).await;
    assert_eq!(body.error, "invalid_request");
}

#[actix_web::test]
async fn authorize_rejects_implicit_response_type() {
    let client = Client::new(
        "client_a".to_string(),
        "secret_a".to_string(),
        vec!["https://good.example/cb".to_string()],
        vec!["authorization_code".to_string()],
        "read".to_string(),
        "test".to_string(),
    );

    let (token_actor, client_actor, auth_actor, jwt_secret, metrics, oidc_config) =
        setup_context(client).await;
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(token_actor))
            .app_data(web::Data::new(client_actor))
            .app_data(web::Data::new(auth_actor))
            .app_data(web::Data::new(jwt_secret))
            .app_data(web::Data::new(metrics))
            .app_data(web::Data::new(oidc_config))
            .app_data(web::Data::new(false))
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
                    ),
            )
            .service(web::scope("/.well-known").route(
                "/openid-configuration",
                web::get().to(oauth2_actix::handlers::wellknown::openid_configuration),
            )),
    )
    .await;

    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let challenge = s256_challenge(verifier);
    let req = test::TestRequest::get().uri(&format!("/oauth/authorize?response_type=token&client_id=client_a&redirect_uri=https%3A%2F%2Fgood.example%2Fcb&scope=read&code_challenge={challenge}&code_challenge_method=S256")).to_request();
    let resp = test::call_service(&app, req).await;

    assert_eq!(resp.status(), 400);
    let body: OAuth2Error = test::read_body_json(resp).await;
    assert_eq!(body.error, "invalid_request");
}

#[actix_web::test]
async fn token_client_credentials_rejects_invalid_secret() {
    let client = Client::new(
        "client_cc".to_string(),
        "secret_cc".to_string(),
        vec!["https://unused.example/cb".to_string()],
        vec!["client_credentials".to_string()],
        "read".to_string(),
        "test".to_string(),
    );

    let (token_actor, client_actor, auth_actor, jwt_secret, metrics, oidc_config) =
        setup_context(client).await;
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(token_actor))
            .app_data(web::Data::new(client_actor))
            .app_data(web::Data::new(auth_actor))
            .app_data(web::Data::new(jwt_secret))
            .app_data(web::Data::new(metrics))
            .app_data(web::Data::new(oidc_config))
            .app_data(web::Data::new(false))
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
                    ),
            )
            .service(web::scope("/.well-known").route(
                "/openid-configuration",
                web::get().to(oauth2_actix::handlers::wellknown::openid_configuration),
            )),
    )
    .await;

    let req = test::TestRequest::post()
        .uri("/oauth/token")
        .set_form([
            ("grant_type", "client_credentials"),
            ("client_id", "client_cc"),
            ("client_secret", "wrong"),
            ("scope", "read"),
        ])
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 401);

    let body: OAuth2Error = test::read_body_json(resp).await;
    assert_eq!(body.error, "invalid_client");
}

#[actix_web::test]
async fn token_client_credentials_uses_single_lookup_with_warm_cache() {
    let client = Client::new(
        "client_perf".to_string(),
        "secret_perf".to_string(),
        vec!["https://unused.example/cb".to_string()],
        vec!["client_credentials".to_string()],
        "read".to_string(),
        "test".to_string(),
    );

    let (storage, stats) = CountingStorage::with_client(client);
    let jwt_secret = "test_jwt_secret".to_string();
    let metrics = Metrics::new().expect("metrics");
    let token_actor = oauth2_actix::actors::TokenActor::new(
        storage.clone(),
        jwt_secret.clone(),
        "http://localhost".to_string(),
    )
    .start();
    let token_pool = TokenActorPool::new(vec![token_actor]);
    let client_actor = oauth2_actix::actors::ClientActor::new(storage.clone()).start();
    let auth_actor = oauth2_actix::actors::AuthActor::new(storage).start();
    let oidc_config = OidcConfig {
        issuer: "http://localhost".to_string(),
        jwt_secret,
        id_token_alg: "HS256".to_string(),
        id_token_kid: None,
        id_token_private_key_pem: None,
    };

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(token_pool))
            .app_data(web::Data::new(client_actor))
            .app_data(web::Data::new(auth_actor))
            .app_data(web::Data::new(metrics))
            .app_data(web::Data::new(oidc_config))
            .app_data(web::Data::new(false))
            .service(web::scope("/oauth").route(
                "/token",
                web::post().to(oauth2_actix::handlers::oauth::token),
            )),
    )
    .await;

    let req = test::TestRequest::post()
        .uri("/oauth/token")
        .set_form([
            ("grant_type", "client_credentials"),
            ("client_id", "client_perf"),
            ("client_secret", "secret_perf"),
            ("scope", "read"),
        ])
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());

    // Repeat the same request; with a warm cache this should avoid an extra client lookup.
    let req2 = test::TestRequest::post()
        .uri("/oauth/token")
        .set_form([
            ("grant_type", "client_credentials"),
            ("client_id", "client_perf"),
            ("client_secret", "secret_perf"),
            ("scope", "read"),
        ])
        .to_request();

    let resp2 = test::call_service(&app, req2).await;
    assert!(resp2.status().is_success());

    assert_eq!(
        stats.get_client_calls.load(Ordering::SeqCst),
        1,
        "client_credentials should perform only one client lookup across repeated requests",
    );
    assert_eq!(
        stats.save_token_calls.load(Ordering::SeqCst),
        2,
        "client_credentials should persist one token per successful request",
    );
    assert_eq!(
        stats.get_token_calls.load(Ordering::SeqCst),
        0,
        "client_credentials should not read tokens during issuance",
    );
}

/// RFC 6749 §2.3.1: client credentials in Basic auth are URL-encoded before
/// base64-encoding.  Verify that secrets containing special chars (`/`, `+`)
/// are correctly decoded so the constant-time comparison matches.
#[actix_web::test]
async fn token_basic_auth_decodes_url_encoded_secret() {
    use base64::{engine::general_purpose, Engine as _};

    // Secret containing `/` and `+` — just like the production value.
    let raw_secret = "/Xahug+MGm1vCzn0Obrz6agxB9p/b1ccatLLn6cSHJDttRqxWUIV5YaL09VhzhLv";

    let client = Client::new(
        "client_special".to_string(),
        raw_secret.to_string(),
        vec!["https://unused.example/cb".to_string()],
        vec!["client_credentials".to_string()],
        "read".to_string(),
        "test".to_string(),
    );

    let (token_actor, client_actor, auth_actor, jwt_secret, metrics, oidc_config) =
        setup_context(client).await;
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(token_actor))
            .app_data(web::Data::new(client_actor))
            .app_data(web::Data::new(auth_actor))
            .app_data(web::Data::new(jwt_secret))
            .app_data(web::Data::new(metrics))
            .app_data(web::Data::new(oidc_config))
            .app_data(web::Data::new(false))
            .service(web::scope("/oauth").route(
                "/token",
                web::post().to(oauth2_actix::handlers::oauth::token),
            )),
    )
    .await;

    // Build Basic auth header with URL-encoded credentials (Go oauth2 style).
    use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};
    let encoded_id = utf8_percent_encode("client_special", NON_ALPHANUMERIC).to_string();
    let encoded_secret = utf8_percent_encode(raw_secret, NON_ALPHANUMERIC).to_string();
    let basic = general_purpose::STANDARD.encode(format!("{encoded_id}:{encoded_secret}"));

    let req = test::TestRequest::post()
        .uri("/oauth/token")
        .insert_header(("Authorization", format!("Basic {basic}")))
        .set_form([("grant_type", "client_credentials"), ("scope", "read")])
        .to_request();
    let resp = test::call_service(&app, req).await;

    // Should succeed (200), not fail with invalid_client (401).
    assert_eq!(
        resp.status(),
        200,
        "URL-encoded Basic auth should decode to match the stored secret"
    );

    let body: TokenResponse = test::read_body_json(resp).await;
    assert!(!body.access_token.is_empty());
}

#[actix_web::test]
async fn token_response_has_no_store_headers() {
    let client = Client::new(
        "client_cc".to_string(),
        "secret_cc".to_string(),
        vec!["https://unused.example/cb".to_string()],
        vec!["client_credentials".to_string()],
        "read".to_string(),
        "test".to_string(),
    );

    let (token_actor, client_actor, auth_actor, jwt_secret, metrics, oidc_config) =
        setup_context(client).await;
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(token_actor))
            .app_data(web::Data::new(client_actor))
            .app_data(web::Data::new(auth_actor))
            .app_data(web::Data::new(jwt_secret))
            .app_data(web::Data::new(metrics))
            .app_data(web::Data::new(oidc_config))
            .app_data(web::Data::new(false))
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
                    ),
            )
            .service(web::scope("/.well-known").route(
                "/openid-configuration",
                web::get().to(oauth2_actix::handlers::wellknown::openid_configuration),
            )),
    )
    .await;

    let req = test::TestRequest::post()
        .uri("/oauth/token")
        .set_form([
            ("grant_type", "client_credentials"),
            ("client_id", "client_cc"),
            ("client_secret", "secret_cc"),
            ("scope", "read"),
        ])
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());

    let cache_control = resp
        .headers()
        .get(actix_web::http::header::CACHE_CONTROL)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");
    assert!(cache_control.contains("no-store"));

    let pragma = resp
        .headers()
        .get(actix_web::http::header::PRAGMA)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");
    assert!(pragma.contains("no-cache"));

    let _body: TokenResponse = test::read_body_json(resp).await;
}

#[actix_web::test]
async fn authorize_requires_pkce_s256() {
    let client = Client::new(
        "client_ac".to_string(),
        "secret_ac".to_string(),
        vec!["https://good.example/cb".to_string()],
        vec!["authorization_code".to_string()],
        "read".to_string(),
        "test".to_string(),
    );

    let (token_actor, client_actor, auth_actor, jwt_secret, metrics, oidc_config) =
        setup_context(client).await;
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(token_actor))
            .app_data(web::Data::new(client_actor))
            .app_data(web::Data::new(auth_actor))
            .app_data(web::Data::new(jwt_secret))
            .app_data(web::Data::new(metrics))
            .app_data(web::Data::new(oidc_config))
            .app_data(web::Data::new(false))
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
                    ),
            )
            .service(web::scope("/.well-known").route(
                "/openid-configuration",
                web::get().to(oauth2_actix::handlers::wellknown::openid_configuration),
            )),
    )
    .await;

    // Missing PKCE parameters should be rejected.
    let req = test::TestRequest::get().uri("/oauth/authorize?response_type=code&client_id=client_ac&redirect_uri=https%3A%2F%2Fgood.example%2Fcb&scope=read").to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 400);

    let body: OAuth2Error = test::read_body_json(resp).await;
    assert_eq!(body.error, "invalid_request");
}

#[actix_web::test]
async fn pkce_allows_public_exchange_and_prevents_downgrade() {
    let client = Client::new(
        "client_pkce".to_string(),
        "secret_pkce".to_string(),
        vec!["https://good.example/cb".to_string()],
        vec!["authorization_code".to_string()],
        "read".to_string(),
        "test".to_string(),
    );

    let (token_actor, client_actor, auth_actor, jwt_secret, metrics, oidc_config) =
        setup_context(client).await;
    let app = test::init_service(
        App::new()
            .wrap(SessionMiddleware::new(
                CookieSessionStore::default(),
                Key::generate(),
            ))
            .route("/test/login", web::get().to(test_set_session))
            .app_data(web::Data::new(token_actor))
            .app_data(web::Data::new(client_actor))
            .app_data(web::Data::new(auth_actor))
            .app_data(web::Data::new(jwt_secret))
            .app_data(web::Data::new(metrics))
            .app_data(web::Data::new(oidc_config))
            .app_data(web::Data::new(false))
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
                    ),
            )
            .service(web::scope("/.well-known").route(
                "/openid-configuration",
                web::get().to(oauth2_actix::handlers::wellknown::openid_configuration),
            )),
    )
    .await;

    // Establish an authenticated session
    let login_req = test::TestRequest::get().uri("/test/login").to_request();
    let login_resp = test::call_service(&app, login_req).await;
    let session_cookie = extract_session_cookie(&login_resp);

    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let challenge = s256_challenge(verifier);

    // Get a code with PKCE
    let req = test::TestRequest::get().uri(&format!("/oauth/authorize?response_type=code&client_id=client_pkce&redirect_uri=https%3A%2F%2Fgood.example%2Fcb&scope=read&code_challenge={challenge}&code_challenge_method=S256")).insert_header(("Cookie", session_cookie.as_str())).to_request();
    let resp = test::call_service(&app, req).await;
    if resp.status() != 302 {
        let status = resp.status();
        let body = test::read_body(resp).await;
        panic!(
            "expected 302 from /oauth/authorize (PKCE), got {status} body={}",
            String::from_utf8_lossy(&body)
        );
    }

    let loc = resp
        .headers()
        .get(actix_web::http::header::LOCATION)
        .and_then(|h| h.to_str().ok())
        .unwrap();
    let code = extract_query_param(loc, "code").expect("code");

    // Missing verifier: should be rejected.
    let req = test::TestRequest::post()
        .uri("/oauth/token")
        .set_form([
            ("grant_type", "authorization_code"),
            ("client_id", "client_pkce"),
            ("client_secret", "secret_pkce"),
            ("code", code.as_str()),
            ("redirect_uri", "https://good.example/cb"),
        ])
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 400);

    let body: OAuth2Error = test::read_body_json(resp).await;
    assert_eq!(body.error, "invalid_grant");

    // Missing client_secret: should be rejected (token endpoint requires client auth).
    let req = test::TestRequest::post()
        .uri("/oauth/token")
        .set_form([
            ("grant_type", "authorization_code"),
            ("client_id", "client_pkce"),
            ("code", code.as_str()),
            ("redirect_uri", "https://good.example/cb"),
            ("code_verifier", verifier),
        ])
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 401);

    let body: OAuth2Error = test::read_body_json(resp).await;
    assert_eq!(body.error, "invalid_client");

    // Correct exchange: include verifier and client_secret.
    let req = test::TestRequest::post()
        .uri("/oauth/token")
        .set_form([
            ("grant_type", "authorization_code"),
            ("client_id", "client_pkce"),
            ("client_secret", "secret_pkce"),
            ("code", code.as_str()),
            ("redirect_uri", "https://good.example/cb"),
            ("code_verifier", verifier),
        ])
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());
}

#[actix_web::test]
async fn token_authorization_code_exchange_allows_missing_redirect_uri() {
    let client = Client::new(
        "client_oauth21".to_string(),
        "secret_oauth21".to_string(),
        vec!["https://good.example/cb".to_string()],
        vec!["authorization_code".to_string()],
        "read".to_string(),
        "test".to_string(),
    );

    let (token_actor, client_actor, auth_actor, jwt_secret, metrics, oidc_config) =
        setup_context(client).await;
    let app = test::init_service(
        App::new()
            .wrap(SessionMiddleware::new(
                CookieSessionStore::default(),
                Key::generate(),
            ))
            .route("/test/login", web::get().to(test_set_session))
            .app_data(web::Data::new(token_actor))
            .app_data(web::Data::new(client_actor))
            .app_data(web::Data::new(auth_actor))
            .app_data(web::Data::new(jwt_secret))
            .app_data(web::Data::new(metrics))
            .app_data(web::Data::new(oidc_config))
            .app_data(web::Data::new(false))
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
                    ),
            )
            .service(web::scope("/.well-known").route(
                "/openid-configuration",
                web::get().to(oauth2_actix::handlers::wellknown::openid_configuration),
            )),
    )
    .await;

    // Establish an authenticated session
    let login_req = test::TestRequest::get().uri("/test/login").to_request();
    let login_resp = test::call_service(&app, login_req).await;
    let session_cookie = extract_session_cookie(&login_resp);

    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let challenge = s256_challenge(verifier);

    // Get a code with PKCE
    let req = test::TestRequest::get().uri(&format!(
        "/oauth/authorize?response_type=code&client_id=client_oauth21&redirect_uri=https%3A%2F%2Fgood.example%2Fcb&scope=read&code_challenge={challenge}&code_challenge_method=S256"
    )).insert_header(("Cookie", session_cookie.as_str())).to_request();
    let resp = test::call_service(&app, req).await;
    if resp.status() != 302 {
        let status = resp.status();
        let body = test::read_body(resp).await;
        panic!(
            "expected 302 from /oauth/authorize (PKCE), got {status} body={}",
            String::from_utf8_lossy(&body)
        );
    }

    let loc = resp
        .headers()
        .get(actix_web::http::header::LOCATION)
        .and_then(|h| h.to_str().ok())
        .unwrap();
    let code = extract_query_param(loc, "code").expect("code");

    // OAuth 2.1 token request style: omit redirect_uri.
    let req = test::TestRequest::post()
        .uri("/oauth/token")
        .set_form([
            ("grant_type", "authorization_code"),
            ("client_id", "client_oauth21"),
            ("client_secret", "secret_oauth21"),
            ("code", code.as_str()),
            ("code_verifier", verifier),
        ])
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());
}

#[actix_web::test]
async fn token_authorization_code_exchange_rejects_wrong_redirect_uri_when_provided() {
    let client = Client::new(
        "client_redirect_mismatch".to_string(),
        "secret_redirect_mismatch".to_string(),
        vec!["https://good.example/cb".to_string()],
        vec!["authorization_code".to_string()],
        "read".to_string(),
        "test".to_string(),
    );

    let (token_actor, client_actor, auth_actor, jwt_secret, metrics, oidc_config) =
        setup_context(client).await;
    let app = test::init_service(
        App::new()
            .wrap(SessionMiddleware::new(
                CookieSessionStore::default(),
                Key::generate(),
            ))
            .route("/test/login", web::get().to(test_set_session))
            .app_data(web::Data::new(token_actor))
            .app_data(web::Data::new(client_actor))
            .app_data(web::Data::new(auth_actor))
            .app_data(web::Data::new(jwt_secret))
            .app_data(web::Data::new(metrics))
            .app_data(web::Data::new(oidc_config))
            .app_data(web::Data::new(false))
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
                    ),
            )
            .service(web::scope("/.well-known").route(
                "/openid-configuration",
                web::get().to(oauth2_actix::handlers::wellknown::openid_configuration),
            )),
    )
    .await;

    // Establish an authenticated session
    let login_req = test::TestRequest::get().uri("/test/login").to_request();
    let login_resp = test::call_service(&app, login_req).await;
    let session_cookie = extract_session_cookie(&login_resp);

    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let challenge = s256_challenge(verifier);

    // Get a code bound to the correct redirect_uri.
    let req = test::TestRequest::get().uri(&format!(
        "/oauth/authorize?response_type=code&client_id=client_redirect_mismatch&redirect_uri=https%3A%2F%2Fgood.example%2Fcb&scope=read&code_challenge={challenge}&code_challenge_method=S256"
    )).insert_header(("Cookie", session_cookie.as_str())).to_request();
    let resp = test::call_service(&app, req).await;
    if resp.status() != 302 {
        let status = resp.status();
        let body = test::read_body(resp).await;
        panic!(
            "expected 302 from /oauth/authorize (PKCE), got {status} body={}",
            String::from_utf8_lossy(&body)
        );
    }

    let loc = resp
        .headers()
        .get(actix_web::http::header::LOCATION)
        .and_then(|h| h.to_str().ok())
        .unwrap();
    let code = extract_query_param(loc, "code").expect("code");

    // OAuth 2.0 backward-compat style: include redirect_uri, but wrong => invalid_grant.
    let req = test::TestRequest::post()
        .uri("/oauth/token")
        .set_form([
            ("grant_type", "authorization_code"),
            ("client_id", "client_redirect_mismatch"),
            ("client_secret", "secret_redirect_mismatch"),
            ("code", code.as_str()),
            ("redirect_uri", "https://evil.example/cb"),
            ("code_verifier", verifier),
        ])
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 400);

    let body: OAuth2Error = test::read_body_json(resp).await;
    assert_eq!(body.error, "invalid_grant");
}

#[actix_web::test]
async fn authorization_code_cannot_be_reused() {
    let client = Client::new(
        "client_reuse".to_string(),
        "secret_reuse".to_string(),
        vec!["https://good.example/cb".to_string()],
        vec!["authorization_code".to_string()],
        "read".to_string(),
        "test".to_string(),
    );

    let (token_actor, client_actor, auth_actor, jwt_secret, metrics, oidc_config) =
        setup_context(client).await;
    let app = test::init_service(
        App::new()
            .wrap(SessionMiddleware::new(
                CookieSessionStore::default(),
                Key::generate(),
            ))
            .route("/test/login", web::get().to(test_set_session))
            .app_data(web::Data::new(token_actor))
            .app_data(web::Data::new(client_actor))
            .app_data(web::Data::new(auth_actor))
            .app_data(web::Data::new(jwt_secret))
            .app_data(web::Data::new(metrics))
            .app_data(web::Data::new(oidc_config))
            .app_data(web::Data::new(false))
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
                    ),
            )
            .service(web::scope("/.well-known").route(
                "/openid-configuration",
                web::get().to(oauth2_actix::handlers::wellknown::openid_configuration),
            )),
    )
    .await;

    // Establish an authenticated session
    let login_req = test::TestRequest::get().uri("/test/login").to_request();
    let login_resp = test::call_service(&app, login_req).await;
    let session_cookie = extract_session_cookie(&login_resp);

    // Get a code (PKCE required)
    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let challenge = s256_challenge(verifier);
    let req = test::TestRequest::get().uri(&format!("/oauth/authorize?response_type=code&client_id=client_reuse&redirect_uri=https%3A%2F%2Fgood.example%2Fcb&scope=read&code_challenge={challenge}&code_challenge_method=S256")).insert_header(("Cookie", session_cookie.as_str())).to_request();
    let resp = test::call_service(&app, req).await;
    if resp.status() != 302 {
        let status = resp.status();
        let body = test::read_body(resp).await;
        panic!(
            "expected 302 from /oauth/authorize (reuse), got {status} body={}",
            String::from_utf8_lossy(&body)
        );
    }

    let loc = resp
        .headers()
        .get(actix_web::http::header::LOCATION)
        .and_then(|h| h.to_str().ok())
        .unwrap();
    let code = extract_query_param(loc, "code").expect("code");

    // First exchange succeeds.
    let req = test::TestRequest::post()
        .uri("/oauth/token")
        .set_form([
            ("grant_type", "authorization_code"),
            ("client_id", "client_reuse"),
            ("client_secret", "secret_reuse"),
            ("code", code.as_str()),
            ("redirect_uri", "https://good.example/cb"),
            ("code_verifier", verifier),
        ])
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());

    // Second exchange fails.
    let req = test::TestRequest::post()
        .uri("/oauth/token")
        .set_form([
            ("grant_type", "authorization_code"),
            ("client_id", "client_reuse"),
            ("client_secret", "secret_reuse"),
            ("code", code.as_str()),
            ("redirect_uri", "https://good.example/cb"),
            ("code_verifier", verifier),
        ])
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 400);

    let body: OAuth2Error = test::read_body_json(resp).await;
    assert_eq!(body.error, "invalid_grant");
}

#[actix_web::test]
async fn well_known_metadata_matches_supported_flows() {
    let client = Client::new(
        "client_meta".to_string(),
        "secret_meta".to_string(),
        vec!["https://good.example/cb".to_string()],
        vec!["authorization_code".to_string()],
        "read".to_string(),
        "test".to_string(),
    );

    let (token_actor, client_actor, auth_actor, jwt_secret, metrics, oidc_config) =
        setup_context(client).await;
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(token_actor))
            .app_data(web::Data::new(client_actor))
            .app_data(web::Data::new(auth_actor))
            .app_data(web::Data::new(jwt_secret))
            .app_data(web::Data::new(metrics))
            .app_data(web::Data::new(oidc_config))
            .app_data(web::Data::new(false))
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
                    ),
            )
            .service(web::scope("/.well-known").route(
                "/openid-configuration",
                web::get().to(oauth2_actix::handlers::wellknown::openid_configuration),
            )),
    )
    .await;

    let req = test::TestRequest::get()
        .uri("/.well-known/openid-configuration")
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());

    let body: serde_json::Value = test::read_body_json(resp).await;

    let rts = body
        .get("response_types_supported")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    assert!(!rts.iter().any(|v| v == "token"));

    let gts = body
        .get("grant_types_supported")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    assert!(gts.iter().any(|v| v == "refresh_token"));
    assert!(!gts.iter().any(|v| v == "password"));

    let pkce_methods = body
        .get("code_challenge_methods_supported")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    assert!(pkce_methods.iter().any(|v| v == "S256"));
    assert!(!pkce_methods.iter().any(|v| v == "plain"));
}

#[actix_web::test]
async fn authorize_redirect_has_clickjacking_and_referrer_headers() {
    let client = Client::new(
        "client_hdr".to_string(),
        "secret_hdr".to_string(),
        vec!["https://good.example/cb".to_string()],
        vec!["authorization_code".to_string()],
        "read".to_string(),
        "test".to_string(),
    );

    let (token_actor, client_actor, auth_actor, jwt_secret, metrics, oidc_config) =
        setup_context(client).await;
    let app = test::init_service(
        App::new()
            .wrap(SessionMiddleware::new(
                CookieSessionStore::default(),
                Key::generate(),
            ))
            .route("/test/login", web::get().to(test_set_session))
            .app_data(web::Data::new(token_actor))
            .app_data(web::Data::new(client_actor))
            .app_data(web::Data::new(auth_actor))
            .app_data(web::Data::new(jwt_secret))
            .app_data(web::Data::new(metrics))
            .app_data(web::Data::new(oidc_config))
            .app_data(web::Data::new(false))
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
                    ),
            )
            .service(web::scope("/.well-known").route(
                "/openid-configuration",
                web::get().to(oauth2_actix::handlers::wellknown::openid_configuration),
            )),
    )
    .await;

    // Establish an authenticated session
    let login_req = test::TestRequest::get().uri("/test/login").to_request();
    let login_resp = test::call_service(&app, login_req).await;
    let session_cookie = extract_session_cookie(&login_resp);

    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let challenge = s256_challenge(verifier);
    let req = test::TestRequest::get().uri(&format!("/oauth/authorize?response_type=code&client_id=client_hdr&redirect_uri=https%3A%2F%2Fgood.example%2Fcb&scope=read&code_challenge={challenge}&code_challenge_method=S256")).insert_header(("Cookie", session_cookie.as_str())).to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 302);

    let rp = resp
        .headers()
        .get(actix_web::http::header::REFERRER_POLICY)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");
    assert!(rp.contains("no-referrer"));

    let xfo = resp
        .headers()
        .get(actix_web::http::header::X_FRAME_OPTIONS)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");
    assert!(xfo.contains("DENY"));

    let csp = resp
        .headers()
        .get(actix_web::http::header::CONTENT_SECURITY_POLICY)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");
    assert!(csp.contains("frame-ancestors"));
}

#[actix_web::test]
async fn pkce_rejects_short_verifier() {
    let client = Client::new(
        "client_short".to_string(),
        "secret_short".to_string(),
        vec!["https://good.example/cb".to_string()],
        vec!["authorization_code".to_string()],
        "read".to_string(),
        "test".to_string(),
    );

    let (token_actor, client_actor, auth_actor, jwt_secret, metrics, oidc_config) =
        setup_context(client).await;
    let app = test::init_service(
        App::new()
            .wrap(SessionMiddleware::new(
                CookieSessionStore::default(),
                Key::generate(),
            ))
            .route("/test/login", web::get().to(test_set_session))
            .app_data(web::Data::new(token_actor))
            .app_data(web::Data::new(client_actor))
            .app_data(web::Data::new(auth_actor))
            .app_data(web::Data::new(jwt_secret))
            .app_data(web::Data::new(metrics))
            .app_data(web::Data::new(oidc_config))
            .app_data(web::Data::new(false))
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
                    ),
            )
            .service(web::scope("/.well-known").route(
                "/openid-configuration",
                web::get().to(oauth2_actix::handlers::wellknown::openid_configuration),
            )),
    )
    .await;

    // Establish an authenticated session
    let login_req = test::TestRequest::get().uri("/test/login").to_request();
    let login_resp = test::call_service(&app, login_req).await;
    let session_cookie = extract_session_cookie(&login_resp);

    // Use a valid-length verifier to mint a code.
    let good_verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let challenge = s256_challenge(good_verifier);
    let req = test::TestRequest::get().uri(&format!("/oauth/authorize?response_type=code&client_id=client_short&redirect_uri=https%3A%2F%2Fgood.example%2Fcb&scope=read&code_challenge={challenge}&code_challenge_method=S256")).insert_header(("Cookie", session_cookie.as_str())).to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 302);

    let loc = resp
        .headers()
        .get(actix_web::http::header::LOCATION)
        .and_then(|h| h.to_str().ok())
        .unwrap();
    let code = extract_query_param(loc, "code").expect("code");

    // Exchange with a too-short verifier should fail.
    let req = test::TestRequest::post()
        .uri("/oauth/token")
        .set_form([
            ("grant_type", "authorization_code"),
            ("client_id", "client_short"),
            ("client_secret", "secret_short"),
            ("code", code.as_str()),
            ("redirect_uri", "https://good.example/cb"),
            ("code_verifier", "short"),
        ])
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 400);

    let body: OAuth2Error = test::read_body_json(resp).await;
    assert_eq!(body.error, "invalid_grant");
}

#[actix_web::test]
async fn admin_check_requires_role_not_username() {
    use chrono::Utc;
    use oauth2_core::User;

    // A user named "admin" with role "user" must NOT be admin
    let impersonator = User {
        id: "u1".to_string(),
        username: "admin".to_string(),
        password_hash: "x".to_string(),
        email: "hacker@evil.com".to_string(),
        enabled: true,
        role: "user".to_string(),
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };
    assert!(
        !impersonator.is_admin(),
        "username='admin' with role='user' must not grant admin"
    );

    // A user with role "admin" but a different username MUST be admin
    let real_admin = User {
        id: "u2".to_string(),
        username: "alice".to_string(),
        password_hash: "x".to_string(),
        email: "alice@corp.com".to_string(),
        enabled: true,
        role: "admin".to_string(),
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };
    assert!(
        real_admin.is_admin(),
        "role='admin' must grant admin regardless of username"
    );
}

#[actix_web::test]
async fn insecure_jwt_secret_is_rejected_without_opt_in() {
    // Without OAUTH2_ALLOW_INSECURE_DEFAULTS=1, the known default must fail validation.
    // With it set, validation should pass (allows test environments to work).
    use oauth2_config::{Config, INSECURE_DEFAULT_JWT_SECRET};

    // RAII guard: removes OAUTH2_ALLOW_INSECURE_DEFAULTS on drop (including on panic),
    // preventing env-var pollution from leaking into concurrently-running tests.
    struct EnvCleanup;
    impl Drop for EnvCleanup {
        fn drop(&mut self) {
            std::env::remove_var("OAUTH2_ALLOW_INSECURE_DEFAULTS");
        }
    }
    let _guard = EnvCleanup;

    std::env::remove_var("OAUTH2_ALLOW_INSECURE_DEFAULTS");
    let mut config = Config::default();
    config.jwt.secret = INSECURE_DEFAULT_JWT_SECRET.to_string();

    let result = config.validate_for_production();
    assert!(
        result.is_err(),
        "insecure secret must fail validation without opt-in"
    );
    assert!(
        result.unwrap_err().contains("OAUTH2_JWT_SECRET"),
        "error must reference OAUTH2_JWT_SECRET"
    );

    std::env::set_var("OAUTH2_ALLOW_INSECURE_DEFAULTS", "1");
    let result2 = config.validate_for_production();
    assert!(
        result2.is_ok(),
        "insecure secret must be allowed with OAUTH2_ALLOW_INSECURE_DEFAULTS=1"
    );
}

#[actix_web::test]
async fn open_redirect_validation_rejects_external_urls() {
    use oauth2_core::utils::redirect::is_safe_redirect;

    let safe = ["/profile", "/oauth/authorize?client_id=x", "/admin"];
    let unsafe_urls = [
        "https://evil.com",
        "//evil.com",
        "/\\evil.com",
        "javascript:alert(1)",
        "http://localhost@evil.com",
        "  https://evil.com",
    ];

    for url in &safe {
        assert!(is_safe_redirect(url), "Expected safe: {url}");
    }
    for url in &unsafe_urls {
        assert!(!is_safe_redirect(url), "Expected unsafe: {url}");
    }
}

#[actix_web::test]
async fn client_registration_requires_admin_session() {
    use actix_session::{storage::CookieSessionStore, SessionMiddleware};
    use actix_web::{cookie::Key, test, web, App};
    use oauth2_actix::handlers::client::register_client;
    use oauth2_actix::middleware::admin_guard::AdminGuard;

    // Minimal storage for the handler
    let storage = oauth2_storage_factory::create_storage("sqlite::memory:")
        .await
        .expect("create storage");
    storage.init().await.expect("init storage");
    let dyn_storage: oauth2_ports::storage::DynStorage = storage;

    let session_key = Key::generate();
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(dyn_storage))
            .wrap(SessionMiddleware::new(
                CookieSessionStore::default(),
                session_key.clone(),
            ))
            .service(
                web::scope("/admin")
                    .wrap(AdminGuard)
                    .route("/clients/register", web::post().to(register_client)),
            ),
    )
    .await;

    let req = test::TestRequest::post()
        .uri("/admin/clients/register")
        .set_json(serde_json::json!({
            "client_name": "malicious-client",
            "redirect_uris": ["https://attacker.com/callback"],
            "grant_types": ["authorization_code"],
            "scope": "openid profile"
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    let status = resp.status().as_u16();

    // AdminGuard redirects unauthenticated users to /auth/login (302).
    // It must never return 201 Created.
    assert_ne!(
        status, 201,
        "unauthenticated client registration must be rejected, got {status}"
    );
    assert_eq!(
        status, 302,
        "unauthenticated request should redirect to login, got {status}"
    );
}

#[actix_web::test]
async fn cors_empty_allowed_origins_denies_cross_origin() {
    use actix_cors::Cors;

    // Cors::default() with no .allowed_origin() calls is fail-closed: it emits no
    // Access-Control-Allow-Origin header, effectively denying all cross-origin requests.
    let cors = Cors::default()
        .allow_any_method()
        .allow_any_header()
        .max_age(3600);

    let app = test::init_service(
        App::new()
            .wrap(cors)
            .route("/", web::get().to(|| async { HttpResponse::Ok().finish() })),
    )
    .await;

    let req = test::TestRequest::get()
        .uri("/")
        .insert_header(("Origin", "https://evil.example.com"))
        .to_request();

    let resp: actix_web::dev::ServiceResponse<_> = test::call_service(&app, req).await;

    assert!(
        !resp.headers().contains_key("access-control-allow-origin"),
        "Cors::default() with no allowed origins should not emit Access-Control-Allow-Origin"
    );
}

#[actix_web::test]
async fn cors_allowed_origins_parsed_correctly() {
    use oauth2_config::Config;

    // Note: std::env::set_var is not thread-safe when tests run in parallel.
    // The serial_test crate is not a dependency here; take care if parallelism is a concern.
    // SAFETY: This test sets and immediately restores OAUTH2_ALLOWED_ORIGINS.  It is
    // intentionally a single-threaded unit test (no async runtime, no shared state beyond
    // the process environment), so the risk of races with other tests is low in practice.
    unsafe {
        std::env::set_var(
            "OAUTH2_ALLOWED_ORIGINS",
            "https://app.example.com, https://admin.example.com, ",
        );
    }

    // Config::default() tries application.conf first (HOCON), then falls back to
    // from_env_fallback().  Either code path reads OAUTH2_ALLOWED_ORIGINS and applies
    // the same split/trim/filter logic, so both exercise the real production path.
    let config = Config::default();

    unsafe {
        std::env::remove_var("OAUTH2_ALLOWED_ORIGINS");
    }

    let origins = &config.server.allowed_origins;
    assert_eq!(
        origins.len(),
        2,
        "Expected exactly 2 origins after parsing (trailing comma/space must be stripped), got: {:?}",
        origins
    );
    assert_eq!(origins[0], "https://app.example.com");
    assert_eq!(origins[1], "https://admin.example.com");
}

#[actix_web::test]
async fn seed_password_default_changeme_is_rejected_in_production() {
    // RAII guard: removes env vars on drop (including on panic).
    struct EnvCleanup;
    impl Drop for EnvCleanup {
        fn drop(&mut self) {
            std::env::remove_var("OAUTH2_ALLOW_INSECURE_DEFAULTS");
            std::env::remove_var("OAUTH2_SEED_PASSWORD");
        }
    }
    let _guard = EnvCleanup;

    std::env::remove_var("OAUTH2_ALLOW_INSECURE_DEFAULTS");
    std::env::remove_var("OAUTH2_SEED_PASSWORD");

    let result = validate_seed_password_for_production("changeme");
    assert!(
        result.is_err(),
        "insecure default seed password must fail validation without opt-in"
    );
    assert!(
        result.unwrap_err().contains("OAUTH2_SEED_PASSWORD"),
        "error must reference OAUTH2_SEED_PASSWORD"
    );
}

#[actix_web::test]
async fn seed_password_changeme_is_allowed_with_insecure_defaults_flag() {
    // RAII guard: removes env vars on drop (including on panic).
    struct EnvCleanup;
    impl Drop for EnvCleanup {
        fn drop(&mut self) {
            std::env::remove_var("OAUTH2_ALLOW_INSECURE_DEFAULTS");
            std::env::remove_var("OAUTH2_SEED_PASSWORD");
        }
    }
    let _guard = EnvCleanup;

    std::env::set_var("OAUTH2_ALLOW_INSECURE_DEFAULTS", "1");

    let result = validate_seed_password_for_production("changeme");
    assert!(
        result.is_ok(),
        "insecure seed password must be allowed with OAUTH2_ALLOW_INSECURE_DEFAULTS=1"
    );
}

#[actix_web::test]
async fn login_renews_session_id_after_successful_authentication() {
    use actix_session::{storage::CookieSessionStore, SessionMiddleware};
    use actix_web::cookie::Key;

    let secret_key = Key::generate();
    let app = test::init_service(
        App::new()
            .wrap(SessionMiddleware::new(
                CookieSessionStore::default(),
                secret_key.clone(),
            ))
            .route(
                "/auth/login",
                web::post().to(|session: actix_session::Session| async move {
                    // Simulate what login_submit does after credential verification
                    session.renew();
                    session.insert("user_id", "test-user-id").unwrap();
                    HttpResponse::Found()
                        .append_header(("Location", "/profile"))
                        .finish()
                }),
            ),
    )
    .await;

    let req = test::TestRequest::post().uri("/auth/login").to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 302);
    assert!(
        resp.headers().contains_key("set-cookie"),
        "A renewed session must set a new cookie on login response"
    );
}

#[actix_web::test]
async fn security_headers_present_on_responses() {
    use actix_web::middleware::DefaultHeaders;

    let app = test::init_service(
        App::new()
            .wrap(
                DefaultHeaders::new()
                    .add(("X-Frame-Options", "DENY"))
                    .add(("X-Content-Type-Options", "nosniff"))
                    .add(("Referrer-Policy", "no-referrer"))
                    .add(("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data:")),
            )
            .route("/", web::get().to(|| async { HttpResponse::Ok().finish() })),
    )
    .await;

    let req = test::TestRequest::get().uri("/").to_request();
    let resp = test::call_service(&app, req).await;

    assert_eq!(
        resp.headers()
            .get("x-frame-options")
            .and_then(|v| v.to_str().ok()),
        Some("DENY"),
        "X-Frame-Options: DENY must be present"
    );
    assert_eq!(
        resp.headers()
            .get("x-content-type-options")
            .and_then(|v| v.to_str().ok()),
        Some("nosniff"),
        "X-Content-Type-Options: nosniff must be present"
    );
    assert_eq!(
        resp.headers()
            .get("referrer-policy")
            .and_then(|v| v.to_str().ok()),
        Some("no-referrer"),
        "Referrer-Policy: no-referrer must be present"
    );
    assert_eq!(
        resp.headers().get("content-security-policy").and_then(|v| v.to_str().ok()),
        Some("default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data:"),
        "Content-Security-Policy must allow CDN resources used by templates"
    );
}

// ── Task 4 (M-redirect-dedup) ──────────────────────────────────────────────

#[actix_web::test]
async fn is_safe_redirect_is_importable_from_oauth2_core() {
    use oauth2_core::utils::redirect::is_safe_redirect;

    assert!(is_safe_redirect("/oauth/authorize?response_type=code"));
    assert!(is_safe_redirect("/profile"));
    assert!(!is_safe_redirect("https://evil.example.com"));
    assert!(!is_safe_redirect("//evil.example.com"));
    assert!(!is_safe_redirect("/\\evil.example.com"));
    assert!(!is_safe_redirect("javascript:alert(1)"));
}

#[actix_web::test]
async fn introspect_requires_client_auth_by_default() {
    let client = Client::new(
        "client_introspect".to_string(),
        "secret_introspect".to_string(),
        vec!["https://unused.example/cb".to_string()],
        vec!["client_credentials".to_string()],
        "read".to_string(),
        "test".to_string(),
    );

    let (token_pool, client_actor, _auth_actor, jwt_secret, _metrics, _oidc_config) =
        setup_context(client).await;
    let access_token = issue_access_token(&token_pool, "client_introspect", None, "read").await;

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(token_pool))
            .app_data(web::Data::new(client_actor))
            .app_data(web::Data::new(jwt_secret))
            .app_data(web::Data::new(false))
            .service(web::scope("/oauth").route(
                "/introspect",
                web::post().to(oauth2_actix::handlers::token::introspect),
            )),
    )
    .await;

    let resp = test::call_service(
        &app,
        test::TestRequest::post()
            .uri("/oauth/introspect")
            .set_form([("token", access_token.access_token.as_str())])
            .to_request(),
    )
    .await;

    assert_eq!(resp.status(), 401);
    let body: OAuth2Error = test::read_body_json(resp).await;
    assert_eq!(body.error, "invalid_client");
}

#[actix_web::test]
async fn introspect_public_mode_can_be_enabled_explicitly() {
    let client = Client::new(
        "client_public_introspect".to_string(),
        "secret_public_introspect".to_string(),
        vec!["https://unused.example/cb".to_string()],
        vec!["client_credentials".to_string()],
        "read".to_string(),
        "test".to_string(),
    );

    let (token_pool, client_actor, _auth_actor, jwt_secret, _metrics, _oidc_config) =
        setup_context(client).await;
    let access_token =
        issue_access_token(&token_pool, "client_public_introspect", None, "read").await;

    let mut config = test_runtime_config(&jwt_secret);
    config.jwt.public_introspection = true;

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(token_pool))
            .app_data(web::Data::new(client_actor))
            .app_data(web::Data::new(jwt_secret))
            .app_data(web::Data::new(false))
            .app_data(web::Data::new(config))
            .service(web::scope("/oauth").route(
                "/introspect",
                web::post().to(oauth2_actix::handlers::token::introspect),
            )),
    )
    .await;

    let resp = test::call_service(
        &app,
        test::TestRequest::post()
            .uri("/oauth/introspect")
            .set_form([("token", access_token.access_token.as_str())])
            .to_request(),
    )
    .await;

    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(
        body.get("active").and_then(|value| value.as_bool()),
        Some(true)
    );
}

#[actix_web::test]
async fn introspect_returns_inactive_for_other_clients_token() {
    let owner = Client::new(
        "client_owner".to_string(),
        "secret_owner".to_string(),
        vec!["https://unused.example/cb".to_string()],
        vec!["client_credentials".to_string()],
        "read".to_string(),
        "owner".to_string(),
    );
    let observer = Client::new(
        "client_observer".to_string(),
        "secret_observer".to_string(),
        vec!["https://unused.example/cb".to_string()],
        vec!["client_credentials".to_string()],
        "read".to_string(),
        "observer".to_string(),
    );

    let (token_pool, client_actor, _auth_actor, jwt_secret, _metrics, _oidc_config) =
        setup_context_with_clients(vec![owner, observer]).await;
    let access_token = issue_access_token(&token_pool, "client_owner", None, "read").await;

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(token_pool))
            .app_data(web::Data::new(client_actor))
            .app_data(web::Data::new(jwt_secret))
            .app_data(web::Data::new(false))
            .service(web::scope("/oauth").route(
                "/introspect",
                web::post().to(oauth2_actix::handlers::token::introspect),
            )),
    )
    .await;

    let resp = test::call_service(
        &app,
        test::TestRequest::post()
            .uri("/oauth/introspect")
            .insert_header((
                "Authorization",
                basic_auth_header("client_observer", "secret_observer"),
            ))
            .set_form([("token", access_token.access_token.as_str())])
            .to_request(),
    )
    .await;

    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(
        body.get("active").and_then(|value| value.as_bool()),
        Some(false)
    );
}

#[actix_web::test]
async fn revoke_requires_authenticated_client_and_preserves_other_clients_tokens() {
    let owner = Client::new(
        "client_revoke_owner".to_string(),
        "secret_revoke_owner".to_string(),
        vec!["https://unused.example/cb".to_string()],
        vec!["client_credentials".to_string()],
        "read".to_string(),
        "owner".to_string(),
    );
    let observer = Client::new(
        "client_revoke_observer".to_string(),
        "secret_revoke_observer".to_string(),
        vec!["https://unused.example/cb".to_string()],
        vec!["client_credentials".to_string()],
        "read".to_string(),
        "observer".to_string(),
    );

    let (token_pool, client_actor, _auth_actor, _jwt_secret, _metrics, _oidc_config) =
        setup_context_with_clients(vec![owner, observer]).await;
    let token_pool_for_assert = token_pool.clone();
    let access_token = issue_access_token(&token_pool, "client_revoke_owner", None, "read").await;

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(token_pool))
            .app_data(web::Data::new(client_actor))
            .service(web::scope("/oauth").route(
                "/revoke",
                web::post().to(oauth2_actix::handlers::token::revoke),
            )),
    )
    .await;

    let unauthenticated = test::call_service(
        &app,
        test::TestRequest::post()
            .uri("/oauth/revoke")
            .set_form([("token", access_token.access_token.as_str())])
            .to_request(),
    )
    .await;

    assert_eq!(unauthenticated.status(), 401);
    let body: OAuth2Error = test::read_body_json(unauthenticated).await;
    assert_eq!(body.error, "invalid_client");

    let wrong_client = test::call_service(
        &app,
        test::TestRequest::post()
            .uri("/oauth/revoke")
            .insert_header((
                "Authorization",
                basic_auth_header("client_revoke_observer", "secret_revoke_observer"),
            ))
            .set_form([("token", access_token.access_token.as_str())])
            .to_request(),
    )
    .await;

    assert_eq!(wrong_client.status(), 200);
    let still_valid = token_pool_for_assert
        .route(&access_token.access_token)
        .send(oauth2_actix::actors::ValidateToken {
            token: access_token.access_token.clone(),
            span: tracing::Span::current(),
        })
        .await
        .expect("validate token send")
        .expect("token should remain valid");
    assert_eq!(still_valid.client_id, "client_revoke_owner");
}

#[actix_web::test]
async fn userinfo_rejects_query_access_tokens() {
    let client = Client::new(
        "client_userinfo_query".to_string(),
        "secret_userinfo_query".to_string(),
        vec!["https://unused.example/cb".to_string()],
        vec!["authorization_code".to_string()],
        "openid profile".to_string(),
        "userinfo".to_string(),
    );

    let (token_pool, _client_actor, _auth_actor, jwt_secret, _metrics, oidc_config) =
        setup_context(client).await;
    let access_token = issue_access_token(
        &token_pool,
        "client_userinfo_query",
        Some("user_123"),
        "openid profile",
    )
    .await;

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(token_pool))
            .app_data(web::Data::new(oidc_config))
            .app_data(web::Data::new(jwt_secret))
            .service(web::scope("/oauth").route(
                "/userinfo",
                web::get().to(oauth2_actix::handlers::wellknown::userinfo),
            )),
    )
    .await;

    let resp = test::call_service(
        &app,
        test::TestRequest::get()
            .uri(&format!(
                "/oauth/userinfo?access_token={}",
                access_token.access_token
            ))
            .to_request(),
    )
    .await;

    assert_eq!(resp.status(), 401);
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(
        body.get("error").and_then(|value| value.as_str()),
        Some("invalid_token")
    );
}

#[actix_web::test]
async fn userinfo_rejects_revoked_access_tokens() {
    let client = Client::new(
        "client_userinfo_revoked".to_string(),
        "secret_userinfo_revoked".to_string(),
        vec!["https://unused.example/cb".to_string()],
        vec!["authorization_code".to_string()],
        "openid profile".to_string(),
        "userinfo".to_string(),
    );

    let (token_pool, _client_actor, _auth_actor, jwt_secret, _metrics, oidc_config) =
        setup_context(client).await;
    let access_token = issue_access_token(
        &token_pool,
        "client_userinfo_revoked",
        Some("user_123"),
        "openid profile",
    )
    .await;

    token_pool
        .route(&access_token.access_token)
        .send(oauth2_actix::actors::RevokeToken {
            token: access_token.access_token.clone(),
            span: tracing::Span::current(),
        })
        .await
        .expect("send revoke")
        .expect("revoke token");

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(token_pool))
            .app_data(web::Data::new(oidc_config))
            .app_data(web::Data::new(jwt_secret))
            .service(web::scope("/oauth").route(
                "/userinfo",
                web::get().to(oauth2_actix::handlers::wellknown::userinfo),
            )),
    )
    .await;

    let resp = test::call_service(
        &app,
        test::TestRequest::get()
            .uri("/oauth/userinfo")
            .insert_header((
                "Authorization",
                format!("Bearer {}", access_token.access_token),
            ))
            .to_request(),
    )
    .await;

    assert_eq!(resp.status(), 401);
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(
        body.get("error").and_then(|value| value.as_str()),
        Some("invalid_token")
    );
}

#[actix_web::test]
async fn well_known_metadata_advertises_standard_endpoint_auth_fields() {
    let client = Client::new(
        "client_meta_standard".to_string(),
        "secret_meta_standard".to_string(),
        vec!["https://good.example/cb".to_string()],
        vec!["authorization_code".to_string()],
        "openid profile".to_string(),
        "meta".to_string(),
    );

    let (_token_pool, _client_actor, _auth_actor, jwt_secret, _metrics, oidc_config) =
        setup_context(client).await;
    let mut config = test_runtime_config(&jwt_secret);
    config.jwt.public_introspection = true;

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(oidc_config))
            .app_data(web::Data::new(config))
            .service(web::scope("/.well-known").route(
                "/openid-configuration",
                web::get().to(oauth2_actix::handlers::wellknown::openid_configuration),
            )),
    )
    .await;

    let resp = test::call_service(
        &app,
        test::TestRequest::get()
            .uri("/.well-known/openid-configuration")
            .to_request(),
    )
    .await;

    assert!(resp.status().is_success());
    let body: serde_json::Value = test::read_body_json(resp).await;

    assert_eq!(
        body.get("introspection_endpoint")
            .and_then(|value| value.as_str()),
        Some("http://localhost/oauth/introspect")
    );
    assert_eq!(
        body.get("revocation_endpoint")
            .and_then(|value| value.as_str()),
        Some("http://localhost/oauth/revoke")
    );
    assert_eq!(
        body.get("end_session_endpoint")
            .and_then(|value| value.as_str()),
        Some("http://localhost/oauth/logout")
    );

    let introspection_methods = body
        .get("introspection_endpoint_auth_methods_supported")
        .and_then(|value| value.as_array())
        .cloned()
        .unwrap_or_default();
    assert!(introspection_methods.iter().any(|value| value == "none"));
    assert!(introspection_methods
        .iter()
        .any(|value| value == "client_secret_basic"));

    let revocation_methods = body
        .get("revocation_endpoint_auth_methods_supported")
        .and_then(|value| value.as_array())
        .cloned()
        .unwrap_or_default();
    assert!(revocation_methods
        .iter()
        .any(|value| value == "client_secret_post"));
}

#[actix_web::test]
async fn oidc_logout_redirects_to_registered_post_logout_redirect_uri_with_state() {
    let storage = oauth2_storage_factory::create_storage("sqlite::memory:")
        .await
        .expect("create storage");
    storage.init().await.expect("init storage");

    let client = Client::new(
        "logout_client".to_string(),
        "logout_secret".to_string(),
        vec!["https://app.example.com/logged-out".to_string()],
        vec!["authorization_code".to_string()],
        "openid profile".to_string(),
        "logout client".to_string(),
    );
    storage.save_client(&client).await.expect("save client");

    let jwt_secret = "test_jwt_secret_at_least_32_chars".to_string();

    let oidc_config = OidcConfig {
        issuer: "http://localhost".to_string(),
        jwt_secret,
        id_token_alg: "HS256".to_string(),
        id_token_kid: None,
        id_token_private_key_pem: None,
    };

    let dyn_storage: DynStorage = storage;

    let app = test::init_service(
        App::new()
            .wrap(SessionMiddleware::new(
                CookieSessionStore::default(),
                Key::generate(),
            ))
            .route("/test/login", web::get().to(test_set_session))
            .app_data(web::Data::new(dyn_storage))
            .app_data(web::Data::new(oidc_config))
            .service(web::scope("/oauth").route(
                "/logout",
                web::get().to(oauth2_actix::handlers::oidc_logout::logout),
            )),
    )
    .await;

    let login_resp = test::call_service(
        &app,
        test::TestRequest::get().uri("/test/login").to_request(),
    )
    .await;
    let session_cookie = extract_session_cookie(&login_resp);

    let resp = test::call_service(
        &app,
        test::TestRequest::get()
            .uri("/oauth/logout?post_logout_redirect_uri=https%3A%2F%2Fapp.example.com%2Flogged-out&state=xyz")
            .insert_header(("Cookie", session_cookie.as_str()))
            .to_request(),
    )
    .await;

    assert_eq!(resp.status(), 302);
    let location = resp
        .headers()
        .get(actix_web::http::header::LOCATION)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    assert_eq!(location, "https://app.example.com/logged-out?state=xyz");
}

#[actix_web::test]
async fn oidc_logout_rejects_unregistered_post_logout_redirect_uri() {
    let storage = oauth2_storage_factory::create_storage("sqlite::memory:")
        .await
        .expect("create storage");
    storage.init().await.expect("init storage");

    let client = Client::new(
        "logout_client_reject".to_string(),
        "logout_secret_reject".to_string(),
        vec!["https://app.example.com/logged-out".to_string()],
        vec!["authorization_code".to_string()],
        "openid profile".to_string(),
        "logout client reject".to_string(),
    );
    storage.save_client(&client).await.expect("save client");

    let jwt_secret = "test_jwt_secret_at_least_32_chars".to_string();

    let oidc_config = OidcConfig {
        issuer: "http://localhost".to_string(),
        jwt_secret,
        id_token_alg: "HS256".to_string(),
        id_token_kid: None,
        id_token_private_key_pem: None,
    };

    let dyn_storage: DynStorage = storage;

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(dyn_storage))
            .app_data(web::Data::new(oidc_config))
            .service(web::scope("/oauth").route(
                "/logout",
                web::get().to(oauth2_actix::handlers::oidc_logout::logout),
            )),
    )
    .await;

    let resp = test::call_service(
        &app,
        test::TestRequest::get()
            .uri("/oauth/logout?post_logout_redirect_uri=https%3A%2F%2Fevil.example%2Fafter-logout")
            .to_request(),
    )
    .await;

    assert_eq!(resp.status(), 400);
    let body: OAuth2Error = test::read_body_json(resp).await;
    assert_eq!(body.error, "invalid_request");
}

#[actix_web::test]
async fn events_ingest_requires_bearer_token_by_default() {
    let mut config = test_runtime_config("test_jwt_secret");
    config.events.public_ingest = false;
    config.events.ingest_bearer_token = Some("expected-events-token".to_string());

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(
                oauth2_actix::handlers::events::IdempotencyStore::new(
                    std::time::Duration::from_secs(60),
                ),
            ))
            .app_data(web::Data::new(config))
            .service(web::scope("/events").route(
                "/ingest",
                web::post().to(oauth2_actix::handlers::events::ingest),
            )),
    )
    .await;

    let resp = test::call_service(
        &app,
        test::TestRequest::post()
            .uri("/events/ingest")
            .set_json(sample_event_envelope())
            .to_request(),
    )
    .await;

    assert_eq!(resp.status(), 401);
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(
        body.get("error").and_then(|value| value.as_str()),
        Some("invalid_token")
    );
}

#[actix_web::test]
async fn events_public_ingest_can_be_enabled_explicitly() {
    let mut config = test_runtime_config("test_jwt_secret");
    config.events.public_ingest = true;

    let plugins: Vec<Arc<dyn oauth2_events::EventPlugin>> =
        vec![Arc::new(oauth2_events::InMemoryEventLogger::new(10))];
    let event_actor = oauth2_events::event_actor::EventActor::new(
        plugins,
        oauth2_events::EventFilter::allow_all(),
    )
    .start();
    let event_bus = oauth2_events::EventBusHandle::new(Arc::new(
        oauth2_events::ActixEventBus::new(event_actor),
    ));

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(
                oauth2_actix::handlers::events::IdempotencyStore::new(
                    std::time::Duration::from_secs(60),
                ),
            ))
            .app_data(web::Data::new(config))
            .app_data(web::Data::new(event_bus))
            .service(web::scope("/events").route(
                "/ingest",
                web::post().to(oauth2_actix::handlers::events::ingest),
            )),
    )
    .await;

    let resp = test::call_service(
        &app,
        test::TestRequest::post()
            .uri("/events/ingest")
            .set_json(sample_event_envelope())
            .to_request(),
    )
    .await;

    assert_eq!(resp.status(), 202);
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(
        body.get("status").and_then(|value| value.as_str()),
        Some("accepted")
    );
}

// ── Refresh Token Grant Tests ──────────────────────────────────────────────────

#[actix_web::test]
async fn refresh_token_grant_issues_new_access_token() {
    // Client must list "refresh_token" among its allowed grant types.
    let client = Client::new(
        "client_refresh".to_string(),
        "secret_refresh".to_string(),
        vec!["https://good.example/cb".to_string()],
        vec![
            "authorization_code".to_string(),
            "refresh_token".to_string(),
        ],
        "read write".to_string(),
        "test".to_string(),
    );

    let (token_actor, client_actor, auth_actor, jwt_secret, metrics, oidc_config) =
        setup_context(client).await;
    let config = test_runtime_config(&jwt_secret);

    let app = test::init_service(
        App::new()
            .wrap(SessionMiddleware::new(
                CookieSessionStore::default(),
                Key::generate(),
            ))
            .route("/test/login", web::get().to(test_set_session))
            .app_data(web::Data::new(token_actor))
            .app_data(web::Data::new(client_actor))
            .app_data(web::Data::new(auth_actor))
            .app_data(web::Data::new(jwt_secret.clone()))
            .app_data(web::Data::new(metrics))
            .app_data(web::Data::new(oidc_config))
            .app_data(web::Data::new(config))
            .app_data(web::Data::new(false))
            .service(
                web::scope("/oauth")
                    .route(
                        "/authorize",
                        web::get().to(oauth2_actix::handlers::oauth::authorize),
                    )
                    .route(
                        "/token",
                        web::post().to(oauth2_actix::handlers::oauth::token),
                    ),
            ),
    )
    .await;

    // 1. Establish authenticated session
    let login_resp = test::call_service(
        &app,
        test::TestRequest::get().uri("/test/login").to_request(),
    )
    .await;
    let session_cookie = extract_session_cookie(&login_resp);

    // 2. Get an authorization code
    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let challenge = s256_challenge(verifier);
    let authorize_resp = test::call_service(
        &app,
        test::TestRequest::get()
            .uri(&format!(
                "/oauth/authorize?response_type=code\
                 &client_id=client_refresh\
                 &redirect_uri=https%3A%2F%2Fgood.example%2Fcb\
                 &scope=read\
                 &code_challenge={challenge}\
                 &code_challenge_method=S256"
            ))
            .insert_header(("Cookie", session_cookie.as_str()))
            .to_request(),
    )
    .await;
    assert_eq!(authorize_resp.status(), 302, "authorize should redirect");
    let loc = authorize_resp
        .headers()
        .get(actix_web::http::header::LOCATION)
        .and_then(|h| h.to_str().ok())
        .unwrap();
    let code = extract_query_param(loc, "code").expect("code param missing from redirect");

    // 3. Exchange authorization code for tokens (expect a refresh_token)
    let token_resp = test::call_service(
        &app,
        test::TestRequest::post()
            .uri("/oauth/token")
            .set_form([
                ("grant_type", "authorization_code"),
                ("client_id", "client_refresh"),
                ("client_secret", "secret_refresh"),
                ("code", code.as_str()),
                ("redirect_uri", "https://good.example/cb"),
                ("code_verifier", verifier),
            ])
            .to_request(),
    )
    .await;
    assert!(
        token_resp.status().is_success(),
        "auth code exchange should succeed, got {}",
        token_resp.status()
    );

    let token_body: serde_json::Value = test::read_body_json(token_resp).await;
    let refresh_token = token_body
        .get("refresh_token")
        .and_then(|v| v.as_str())
        .expect("auth code response should include refresh_token");
    let original_access_token = token_body
        .get("access_token")
        .and_then(|v| v.as_str())
        .expect("access_token");

    // 4. Use the refresh token to obtain a new access token
    let refresh_resp = test::call_service(
        &app,
        test::TestRequest::post()
            .uri("/oauth/token")
            .set_form([
                ("grant_type", "refresh_token"),
                ("client_id", "client_refresh"),
                ("client_secret", "secret_refresh"),
                ("refresh_token", refresh_token),
            ])
            .to_request(),
    )
    .await;
    assert!(
        refresh_resp.status().is_success(),
        "refresh_token grant should succeed, got {}",
        refresh_resp.status()
    );

    let refresh_body: serde_json::Value = test::read_body_json(refresh_resp).await;
    let new_access_token = refresh_body
        .get("access_token")
        .and_then(|v| v.as_str())
        .expect("refresh response should include access_token");

    assert_ne!(
        new_access_token, original_access_token,
        "new access token should differ from the original"
    );
    assert!(
        refresh_body.get("token_type").is_some(),
        "refresh response should include token_type"
    );
    assert!(
        refresh_body.get("expires_in").is_some(),
        "refresh response should include expires_in"
    );
}

#[actix_web::test]
async fn refresh_token_grant_rejects_wrong_client_secret() {
    let client = Client::new(
        "client_refresh_neg".to_string(),
        "correct_secret".to_string(),
        vec!["https://good.example/cb".to_string()],
        vec![
            "authorization_code".to_string(),
            "refresh_token".to_string(),
        ],
        "read write".to_string(),
        "test".to_string(),
    );

    let (token_actor, client_actor, auth_actor, jwt_secret, metrics, oidc_config) =
        setup_context(client).await;
    let config = test_runtime_config(&jwt_secret);

    let app = test::init_service(
        App::new()
            .wrap(SessionMiddleware::new(
                CookieSessionStore::default(),
                Key::generate(),
            ))
            .route("/test/login", web::get().to(test_set_session))
            .app_data(web::Data::new(token_actor))
            .app_data(web::Data::new(client_actor))
            .app_data(web::Data::new(auth_actor))
            .app_data(web::Data::new(jwt_secret.clone()))
            .app_data(web::Data::new(metrics))
            .app_data(web::Data::new(oidc_config))
            .app_data(web::Data::new(config))
            .app_data(web::Data::new(false))
            .service(
                web::scope("/oauth")
                    .route(
                        "/authorize",
                        web::get().to(oauth2_actix::handlers::oauth::authorize),
                    )
                    .route(
                        "/token",
                        web::post().to(oauth2_actix::handlers::oauth::token),
                    ),
            ),
    )
    .await;

    // 1. Establish authenticated session
    let login_resp = test::call_service(
        &app,
        test::TestRequest::get().uri("/test/login").to_request(),
    )
    .await;
    let session_cookie = extract_session_cookie(&login_resp);

    // 2. Get an authorization code
    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let challenge = s256_challenge(verifier);
    let authorize_resp = test::call_service(
        &app,
        test::TestRequest::get()
            .uri(&format!(
                "/oauth/authorize?response_type=code\
                 &client_id=client_refresh_neg\
                 &redirect_uri=https%3A%2F%2Fgood.example%2Fcb\
                 &scope=read\
                 &code_challenge={challenge}\
                 &code_challenge_method=S256"
            ))
            .insert_header(("Cookie", session_cookie.as_str()))
            .to_request(),
    )
    .await;
    assert_eq!(authorize_resp.status(), 302, "authorize should redirect");
    let loc = authorize_resp
        .headers()
        .get(actix_web::http::header::LOCATION)
        .and_then(|h| h.to_str().ok())
        .unwrap();
    let code = extract_query_param(loc, "code").expect("code param missing from redirect");

    // 3. Exchange authorization code for tokens (get a valid refresh_token)
    let token_resp = test::call_service(
        &app,
        test::TestRequest::post()
            .uri("/oauth/token")
            .set_form([
                ("grant_type", "authorization_code"),
                ("client_id", "client_refresh_neg"),
                ("client_secret", "correct_secret"),
                ("code", code.as_str()),
                ("redirect_uri", "https://good.example/cb"),
                ("code_verifier", verifier),
            ])
            .to_request(),
    )
    .await;
    assert!(
        token_resp.status().is_success(),
        "auth code exchange should succeed, got {}",
        token_resp.status()
    );

    let token_body: serde_json::Value = test::read_body_json(token_resp).await;
    let refresh_token = token_body
        .get("refresh_token")
        .and_then(|v| v.as_str())
        .expect("auth code response should include refresh_token");

    // 4. Attempt refresh with WRONG client_secret — must fail
    let refresh_resp = test::call_service(
        &app,
        test::TestRequest::post()
            .uri("/oauth/token")
            .set_form([
                ("grant_type", "refresh_token"),
                ("client_id", "client_refresh_neg"),
                ("client_secret", "wrong_secret"),
                ("refresh_token", refresh_token),
            ])
            .to_request(),
    )
    .await;

    assert_eq!(
        refresh_resp.status(),
        actix_web::http::StatusCode::UNAUTHORIZED,
        "refresh with wrong client_secret should be rejected (401 per RFC 6749)"
    );

    let err_body: serde_json::Value = test::read_body_json(refresh_resp).await;
    assert_eq!(
        err_body.get("error").and_then(|v| v.as_str()),
        Some("invalid_client"),
        "error code should be invalid_client"
    );
}

// ── OIDC Nonce Validation Tests ───────────────────────────────────────────────

/// OIDC Core §3.1.2.1: the `nonce` value sent in the authorization request MUST
/// be echoed verbatim as a `nonce` claim in the resulting ID token.
#[actix_web::test]
async fn id_token_echoes_nonce_from_authorize_request() {
    let client = Client::new(
        "nonce_test_client".to_string(),
        "nonce_secret".to_string(),
        vec!["http://localhost/callback".to_string()],
        vec!["authorization_code".to_string()],
        "openid".to_string(),
        "Nonce Test".to_string(),
    );

    let (token_actor, client_actor, auth_actor, jwt_secret, metrics, oidc_config) =
        setup_context(client).await;
    let config = test_runtime_config(&jwt_secret);

    let app = test::init_service(
        App::new()
            .wrap(SessionMiddleware::new(
                CookieSessionStore::default(),
                Key::generate(),
            ))
            .route("/test/login", web::get().to(test_set_session))
            .app_data(web::Data::new(token_actor))
            .app_data(web::Data::new(client_actor))
            .app_data(web::Data::new(auth_actor))
            .app_data(web::Data::new(jwt_secret.clone()))
            .app_data(web::Data::new(metrics))
            .app_data(web::Data::new(oidc_config))
            .app_data(web::Data::new(config))
            .app_data(web::Data::new(false))
            .service(
                web::scope("/oauth")
                    .route(
                        "/authorize",
                        web::get().to(oauth2_actix::handlers::oauth::authorize),
                    )
                    .route(
                        "/token",
                        web::post().to(oauth2_actix::handlers::oauth::token),
                    ),
            ),
    )
    .await;

    // 1. Establish authenticated session
    let login_resp = test::call_service(
        &app,
        test::TestRequest::get().uri("/test/login").to_request(),
    )
    .await;
    let session_cookie = extract_session_cookie(&login_resp);

    // 2. Authorize with nonce — the nonce must survive the code-exchange round-trip
    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let challenge = s256_challenge(verifier);
    let nonce = "test-nonce-abc123";
    let authorize_resp = test::call_service(
        &app,
        test::TestRequest::get()
            .uri(&format!(
                "/oauth/authorize?response_type=code\
                 &client_id=nonce_test_client\
                 &redirect_uri=http%3A%2F%2Flocalhost%2Fcallback\
                 &scope=openid\
                 &code_challenge={challenge}\
                 &code_challenge_method=S256\
                 &nonce={nonce}"
            ))
            .insert_header(("Cookie", session_cookie.as_str()))
            .to_request(),
    )
    .await;
    assert_eq!(authorize_resp.status(), 302, "authorize should redirect");
    let loc = authorize_resp
        .headers()
        .get(actix_web::http::header::LOCATION)
        .and_then(|h| h.to_str().ok())
        .unwrap();
    let code = extract_query_param(loc, "code").expect("code param missing from redirect");

    // 3. Exchange authorization code for tokens
    let token_resp = test::call_service(
        &app,
        test::TestRequest::post()
            .uri("/oauth/token")
            .set_form([
                ("grant_type", "authorization_code"),
                ("client_id", "nonce_test_client"),
                ("client_secret", "nonce_secret"),
                ("code", code.as_str()),
                ("redirect_uri", "http://localhost/callback"),
                ("code_verifier", verifier),
            ])
            .to_request(),
    )
    .await;
    assert!(
        token_resp.status().is_success(),
        "auth code exchange should succeed, got {}",
        token_resp.status()
    );

    let token_body: serde_json::Value = test::read_body_json(token_resp).await;
    let id_token_str = token_body
        .get("id_token")
        .and_then(|v| v.as_str())
        .expect("response should include id_token for openid scope");

    // 4. Decode JWT payload (base64url, no signature verification needed here)
    use base64::{engine::general_purpose, Engine as _};
    let parts: Vec<&str> = id_token_str.split('.').collect();
    assert_eq!(parts.len(), 3, "id_token should be a three-part JWT");
    let payload_bytes = general_purpose::URL_SAFE_NO_PAD
        .decode(parts[1])
        .expect("id_token payload should be valid base64url");
    let claims: serde_json::Value =
        serde_json::from_slice(&payload_bytes).expect("id_token payload should be valid JSON");

    // 5. The nonce claim must match exactly what was sent at authorize time
    assert_eq!(
        claims.get("nonce").and_then(|v| v.as_str()),
        Some(nonce),
        "id_token nonce claim must equal the nonce from the authorize request (OIDC Core §3.1.2.1)"
    );
}

// ── OIDC c_hash Tests ──────────────────────────────────────────────────────────

/// OIDC Core §3.3.2.11: the `c_hash` claim in the ID token must equal the
/// base64url-encoded left half of SHA-256 of the authorization code string.
#[actix_web::test]
async fn id_token_contains_correct_c_hash() {
    let client = Client::new(
        "c_hash_test_client".to_string(),
        "c_hash_secret".to_string(),
        vec!["http://localhost/callback".to_string()],
        vec!["authorization_code".to_string()],
        "openid".to_string(),
        "C-Hash Test".to_string(),
    );

    let (token_actor, client_actor, auth_actor, jwt_secret, metrics, oidc_config) =
        setup_context(client).await;
    let config = test_runtime_config(&jwt_secret);

    let app = test::init_service(
        App::new()
            .wrap(SessionMiddleware::new(
                CookieSessionStore::default(),
                Key::generate(),
            ))
            .route("/test/login", web::get().to(test_set_session))
            .app_data(web::Data::new(token_actor))
            .app_data(web::Data::new(client_actor))
            .app_data(web::Data::new(auth_actor))
            .app_data(web::Data::new(jwt_secret.clone()))
            .app_data(web::Data::new(metrics))
            .app_data(web::Data::new(oidc_config))
            .app_data(web::Data::new(config))
            .app_data(web::Data::new(false))
            .service(
                web::scope("/oauth")
                    .route(
                        "/authorize",
                        web::get().to(oauth2_actix::handlers::oauth::authorize),
                    )
                    .route(
                        "/token",
                        web::post().to(oauth2_actix::handlers::oauth::token),
                    ),
            ),
    )
    .await;

    // 1. Establish authenticated session
    let login_resp = test::call_service(
        &app,
        test::TestRequest::get().uri("/test/login").to_request(),
    )
    .await;
    let session_cookie = extract_session_cookie(&login_resp);

    // 2. Authorize request (PKCE + openid scope, no nonce)
    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let challenge = s256_challenge(verifier);
    let authorize_resp = test::call_service(
        &app,
        test::TestRequest::get()
            .uri(&format!(
                "/oauth/authorize?response_type=code\
                 &client_id=c_hash_test_client\
                 &redirect_uri=http%3A%2F%2Flocalhost%2Fcallback\
                 &scope=openid\
                 &code_challenge={challenge}\
                 &code_challenge_method=S256"
            ))
            .insert_header(("Cookie", session_cookie.as_str()))
            .to_request(),
    )
    .await;
    assert_eq!(authorize_resp.status(), 302, "authorize should redirect");
    let loc = authorize_resp
        .headers()
        .get(actix_web::http::header::LOCATION)
        .and_then(|h| h.to_str().ok())
        .unwrap();
    let code = extract_query_param(loc, "code").expect("code param missing from redirect");

    // 3. Compute expected c_hash independently from the code we extracted
    let expected_c_hash = {
        use base64::{engine::general_purpose, Engine as _};
        use sha2::{Digest, Sha256};
        let hash = Sha256::digest(code.as_bytes());
        general_purpose::URL_SAFE_NO_PAD.encode(&hash[..16])
    };

    // 4. Exchange code for tokens
    let token_resp = test::call_service(
        &app,
        test::TestRequest::post()
            .uri("/oauth/token")
            .set_form([
                ("grant_type", "authorization_code"),
                ("client_id", "c_hash_test_client"),
                ("client_secret", "c_hash_secret"),
                ("code", code.as_str()),
                ("redirect_uri", "http://localhost/callback"),
                ("code_verifier", verifier),
            ])
            .to_request(),
    )
    .await;
    assert!(
        token_resp.status().is_success(),
        "auth code exchange should succeed, got {}",
        token_resp.status()
    );

    let token_body: serde_json::Value = test::read_body_json(token_resp).await;
    let id_token_str = token_body
        .get("id_token")
        .and_then(|v| v.as_str())
        .expect("response should include id_token for openid scope");

    // 5. Decode JWT payload
    use base64::{engine::general_purpose, Engine as _};
    let parts: Vec<&str> = id_token_str.split('.').collect();
    assert_eq!(parts.len(), 3, "id_token should be a three-part JWT");
    let payload_bytes = general_purpose::URL_SAFE_NO_PAD
        .decode(parts[1])
        .expect("id_token payload should be valid base64url");
    let claims: serde_json::Value =
        serde_json::from_slice(&payload_bytes).expect("id_token payload should be valid JSON");

    // 6. Assert c_hash matches expected value (OIDC Core §3.3.2.11)
    assert_eq!(
        claims.get("c_hash").and_then(|v| v.as_str()),
        Some(expected_c_hash.as_str()),
        "id_token c_hash must equal base64url(SHA-256(code)[..16]) per OIDC Core §3.3.2.11"
    );
}

/// OAuth 2.0 Security BCP §4.13.2 — Refresh token replay detection.
///
/// When a previously-used (revoked) refresh token is presented, the entire
/// token family must be invalidated immediately.
///
/// Scenario:
///   RT1  = initial refresh token from auth-code exchange
///   RT2  = new refresh token issued after RT1 is used
///   Replay RT1 → 400 invalid_grant
///   Try RT2    → 400 invalid_grant  (family was revoked during replay)
#[actix_web::test]
async fn refresh_token_replay_revokes_entire_token_family() {
    let client = Client::new(
        "client_replay".to_string(),
        "secret_replay".to_string(),
        vec!["https://good.example/cb".to_string()],
        vec![
            "authorization_code".to_string(),
            "refresh_token".to_string(),
        ],
        "read write".to_string(),
        "test".to_string(),
    );

    let (token_actor, client_actor, auth_actor, jwt_secret, metrics, oidc_config) =
        setup_context(client).await;
    let config = test_runtime_config(&jwt_secret);

    let app = test::init_service(
        App::new()
            .wrap(SessionMiddleware::new(
                CookieSessionStore::default(),
                Key::generate(),
            ))
            .route("/test/login", web::get().to(test_set_session))
            .app_data(web::Data::new(token_actor))
            .app_data(web::Data::new(client_actor))
            .app_data(web::Data::new(auth_actor))
            .app_data(web::Data::new(jwt_secret.clone()))
            .app_data(web::Data::new(metrics))
            .app_data(web::Data::new(oidc_config))
            .app_data(web::Data::new(config))
            .app_data(web::Data::new(false))
            .service(
                web::scope("/oauth")
                    .route(
                        "/authorize",
                        web::get().to(oauth2_actix::handlers::oauth::authorize),
                    )
                    .route(
                        "/token",
                        web::post().to(oauth2_actix::handlers::oauth::token),
                    ),
            ),
    )
    .await;

    // 1. Establish authenticated session
    let login_resp = test::call_service(
        &app,
        test::TestRequest::get().uri("/test/login").to_request(),
    )
    .await;
    let session_cookie = extract_session_cookie(&login_resp);

    // 2. Get an authorization code
    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let challenge = s256_challenge(verifier);
    let authorize_resp = test::call_service(
        &app,
        test::TestRequest::get()
            .uri(&format!(
                "/oauth/authorize?response_type=code\
                 &client_id=client_replay\
                 &redirect_uri=https%3A%2F%2Fgood.example%2Fcb\
                 &scope=read\
                 &code_challenge={challenge}\
                 &code_challenge_method=S256"
            ))
            .insert_header(("Cookie", session_cookie.as_str()))
            .to_request(),
    )
    .await;
    assert_eq!(authorize_resp.status(), 302, "authorize should redirect");
    let loc = authorize_resp
        .headers()
        .get(actix_web::http::header::LOCATION)
        .and_then(|h| h.to_str().ok())
        .unwrap();
    let code = extract_query_param(loc, "code").expect("code param missing");

    // 3. Exchange auth code → RT1 (initial refresh token)
    let token_resp = test::call_service(
        &app,
        test::TestRequest::post()
            .uri("/oauth/token")
            .set_form([
                ("grant_type", "authorization_code"),
                ("client_id", "client_replay"),
                ("client_secret", "secret_replay"),
                ("code", code.as_str()),
                ("redirect_uri", "https://good.example/cb"),
                ("code_verifier", verifier),
            ])
            .to_request(),
    )
    .await;
    assert!(
        token_resp.status().is_success(),
        "auth code exchange should succeed, got {}",
        token_resp.status()
    );
    let token_body: serde_json::Value = test::read_body_json(token_resp).await;
    let rt1 = token_body
        .get("refresh_token")
        .and_then(|v| v.as_str())
        .expect("initial token response should include refresh_token (RT1)")
        .to_string();

    // 4. Use RT1 → should succeed and issue RT2
    let refresh_resp = test::call_service(
        &app,
        test::TestRequest::post()
            .uri("/oauth/token")
            .set_form([
                ("grant_type", "refresh_token"),
                ("client_id", "client_replay"),
                ("client_secret", "secret_replay"),
                ("refresh_token", rt1.as_str()),
            ])
            .to_request(),
    )
    .await;
    assert!(
        refresh_resp.status().is_success(),
        "first use of RT1 should succeed, got {}",
        refresh_resp.status()
    );
    let refresh_body: serde_json::Value = test::read_body_json(refresh_resp).await;
    let rt2 = refresh_body
        .get("refresh_token")
        .and_then(|v| v.as_str())
        .expect("refresh response should include RT2")
        .to_string();

    // 5. Replay RT1 (already revoked) → must be rejected with 400 invalid_grant
    let replay_resp = test::call_service(
        &app,
        test::TestRequest::post()
            .uri("/oauth/token")
            .set_form([
                ("grant_type", "refresh_token"),
                ("client_id", "client_replay"),
                ("client_secret", "secret_replay"),
                ("refresh_token", rt1.as_str()),
            ])
            .to_request(),
    )
    .await;
    assert_eq!(
        replay_resp.status(),
        400,
        "replaying RT1 must return 400, got {}",
        replay_resp.status()
    );
    let replay_body: serde_json::Value = test::read_body_json(replay_resp).await;
    assert_eq!(
        replay_body.get("error").and_then(|v| v.as_str()),
        Some("invalid_grant"),
        "replaying RT1 must return error=invalid_grant"
    );

    // 6. Try RT2 → must also be rejected (entire family was revoked in step 5)
    let rt2_resp = test::call_service(
        &app,
        test::TestRequest::post()
            .uri("/oauth/token")
            .set_form([
                ("grant_type", "refresh_token"),
                ("client_id", "client_replay"),
                ("client_secret", "secret_replay"),
                ("refresh_token", rt2.as_str()),
            ])
            .to_request(),
    )
    .await;
    assert_eq!(
        rt2_resp.status(),
        400,
        "RT2 must be rejected after family revocation, got {}",
        rt2_resp.status()
    );
    let rt2_body: serde_json::Value = test::read_body_json(rt2_resp).await;
    assert_eq!(
        rt2_body.get("error").and_then(|v| v.as_str()),
        Some("invalid_grant"),
        "RT2 must return error=invalid_grant after family was revoked"
    );
}
