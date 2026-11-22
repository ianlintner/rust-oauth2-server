//! RFC 8707 §2 / §2.2 resource-indicator validation on the refresh and
//! client-credentials grant paths (SEC-rust-oauth2-server-20261115-G4).
//!
//! These tests exercise the real token endpoint over HTTP: authorization-code
//! issuance with a resource indicator, refresh rotation, and client
//! credentials with malformed/unregistered resources.

use actix::Actor;
use actix_session::{storage::CookieSessionStore, Session, SessionMiddleware};
use actix_web::{cookie::Key, http::header::ACCEPT, test, web, App, HttpResponse};
use base64::{engine::general_purpose, Engine as _};
use oauth2_actix::actors::{ClientActor, TokenActor, TokenActorPool};
use oauth2_actix::handlers::wellknown::OidcConfig;
use oauth2_core::{Client, ProtectedResource};
use oauth2_observability::Metrics;
use oauth2_ports::DynStorage;
use percent_encoding::{percent_encode, AsciiSet, CONTROLS};

const ISSUER: &str = "https://auth.example.test";
const JWT_SECRET: &str = "resource_validation_test_secret_at_least_32";
const FORM_SET: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'/')
    .add(b':')
    .add(b'#')
    .add(b'?')
    .add(b'&')
    .add(b'=');

struct Context {
    token_pool: TokenActorPool,
    client_actor: actix::Addr<ClientActor>,
    auth_actor: actix::Addr<oauth2_actix::actors::AuthActor>,
    metrics: Metrics,
    oidc_config: OidcConfig,
    storage: DynStorage,
}

/// Builds an inline `App` per test — see CLAUDE.md: never return an
/// `impl Service<Request>` from a helper.
macro_rules! app {
    ($ctx:expr) => {
        test::init_service(
            App::new()
                .wrap(SessionMiddleware::new(
                    CookieSessionStore::default(),
                    Key::generate(),
                ))
                .route("/test/login", web::get().to(test_set_session))
                .app_data(web::Data::new($ctx.token_pool.clone()))
                .app_data(web::Data::new($ctx.client_actor.clone()))
                .app_data(web::Data::new($ctx.auth_actor.clone()))
                .app_data(web::Data::new($ctx.storage.clone()))
                .app_data(web::Data::new(JWT_SECRET.to_string()))
                .app_data(web::Data::new($ctx.metrics.clone()))
                .app_data(web::Data::new($ctx.oidc_config.clone()))
                .app_data(web::Data::new(oauth2_config::Config::default()))
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
        .await
    };
}

/// Runs the authorization-code flow with an optional `resource`, returning
/// the token response body. Expanded inline in each test to avoid a helper
/// that names the opaque `init_service` type.
macro_rules! issue_code_tokens {
    ($app:expr, $client_id:expr, $secret:expr, $resource:expr) => {{
        let login = test::call_service(
            &$app,
            test::TestRequest::get().uri("/test/login").to_request(),
        )
        .await;
        let cookie = login
            .headers()
            .get(actix_web::http::header::SET_COOKIE)
            .and_then(|h| h.to_str().ok())
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_string();

        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let challenge = s256_challenge(verifier);
        let mut uri = format!(
            "/oauth/authorize?response_type=code&client_id={}\
             &redirect_uri=https%3A%2F%2Fclient.example%2Fcb&scope=read\
             &code_challenge={challenge}&code_challenge_method=S256",
            $client_id
        );
        if let Some(resource) = $resource {
            uri.push_str(&format!("&resource={}", form_encode(resource)));
        }
        let authorize = test::call_service(
            &$app,
            test::TestRequest::get()
                .uri(&uri)
                .insert_header(("Cookie", cookie.as_str()))
                .to_request(),
        )
        .await;
        assert_eq!(authorize.status(), 302, "authorize must redirect");
        let location = authorize
            .headers()
            .get(actix_web::http::header::LOCATION)
            .and_then(|h| h.to_str().ok())
            .unwrap()
            .to_string();
        let code = query_param(&location, "code").expect("code in redirect");

        let mut form: Vec<(String, String)> = vec![
            ("grant_type".into(), "authorization_code".into()),
            ("client_id".into(), $client_id.to_string()),
            ("client_secret".into(), $secret.to_string()),
            ("code".into(), code),
            ("redirect_uri".into(), "https://client.example/cb".into()),
            ("code_verifier".into(), verifier.to_string()),
        ];
        if let Some(resource) = $resource {
            form.push(("resource".into(), resource.to_string()));
        }
        let resp = test::call_service(
            &$app,
            test::TestRequest::post()
                .uri("/oauth/token")
                .set_form(form)
                .to_request(),
        )
        .await;
        assert_eq!(resp.status(), 200, "code exchange must succeed");
        test::read_body_json(resp).await
    }};
}

/// Returns (status, body). Expanded inline for the same reason as above.
macro_rules! refresh {
    ($app:expr, $client_id:expr, $secret:expr, $token:expr, $resource:expr) => {{
        let mut form: Vec<(String, String)> = vec![
            ("grant_type".into(), "refresh_token".into()),
            ("client_id".into(), $client_id.to_string()),
            ("client_secret".into(), $secret.to_string()),
            ("refresh_token".into(), $token.to_string()),
        ];
        if let Some(resource) = $resource {
            form.push(("resource".into(), resource.to_string()));
        }
        let resp = test::call_service(
            &$app,
            test::TestRequest::post()
                .uri("/oauth/token")
                .set_form(form)
                .to_request(),
        )
        .await;
        let status = resp.status().as_u16();
        let body: serde_json::Value = test::read_body_json(resp).await;
        (status, body)
    }};
}

/// Returns (status, body) for a client-credentials request.
macro_rules! client_credentials {
    ($app:expr, $client_id:expr, $secret:expr, $scope:expr, $resources:expr) => {{
        let mut form: Vec<(String, String)> = vec![
            ("grant_type".into(), "client_credentials".into()),
            ("client_id".into(), $client_id.to_string()),
            ("client_secret".into(), $secret.to_string()),
            ("scope".into(), $scope.to_string()),
        ];
        for value in $resources {
            form.push(("resource".into(), value.to_string()));
        }
        let resp = test::call_service(
            &$app,
            test::TestRequest::post()
                .uri("/oauth/token")
                .insert_header((ACCEPT, "application/json"))
                .set_form(form)
                .to_request(),
        )
        .await;
        let status = resp.status().as_u16();
        let body: serde_json::Value = test::read_body_json(resp).await;
        (status, body)
    }};
}

async fn setup(clients: Vec<Client>) -> Context {
    let storage = oauth2_storage_factory::create_storage("sqlite::memory:")
        .await
        .expect("create storage");
    storage.init().await.expect("init storage");
    for client in clients {
        storage.save_client(&client).await.expect("save client");
    }
    let now = chrono::Utc::now();
    let user = oauth2_core::User {
        id: "user_resource".to_string(),
        username: "user_resource".to_string(),
        password_hash: "not_used".to_string(),
        email: "user_resource@example.test".to_string(),
        enabled: true,
        role: "user".to_string(),
        created_at: now,
        updated_at: now,
    };
    storage.save_user(&user).await.expect("save user");

    let token_pool = TokenActorPool::new(vec![TokenActor::new(
        storage.clone(),
        JWT_SECRET.to_string(),
        ISSUER.to_string(),
    )
    .start()]);
    let client_actor = ClientActor::new(storage.clone()).start();
    let auth_actor = oauth2_actix::actors::AuthActor::new(storage.clone()).start();
    let oidc_config = OidcConfig {
        issuer: ISSUER.to_string(),
        jwt_secret: JWT_SECRET.to_string(),
        id_token_alg: "HS256".to_string(),
        id_token_kid: None,
        id_token_private_key_pem: None,
    };
    Context {
        token_pool,
        client_actor,
        auth_actor,
        metrics: Metrics::new().expect("metrics"),
        oidc_config,
        storage,
    }
}

async fn test_set_session(session: Session) -> HttpResponse {
    let _ = session.insert("user_id", "user_resource".to_string());
    let _ = session.insert("email", "user_resource@example.test".to_string());
    HttpResponse::Ok().finish()
}

fn confidential_client(id: &str, secret: &str) -> Client {
    Client::new(
        id.to_string(),
        secret.to_string(),
        vec!["https://client.example/cb".to_string()],
        vec![
            "authorization_code".to_string(),
            "refresh_token".to_string(),
            "client_credentials".to_string(),
        ],
        "read write".to_string(),
        "resource validation test client".to_string(),
    )
}

fn s256_challenge(verifier: &str) -> String {
    use sha2::{Digest, Sha256};
    general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

fn query_param(url: &str, name: &str) -> Option<String> {
    let (_, query) = url.split_once('?')?;
    query.split('&').find_map(|pair| {
        let (key, value) = pair.split_once('=')?;
        if key == name {
            Some(value.to_string())
        } else {
            None
        }
    })
}

fn form_encode(value: &str) -> String {
    percent_encode(value.as_bytes(), FORM_SET).to_string()
}

fn aud_of(token: &str) -> Vec<String> {
    let bytes = general_purpose::URL_SAFE_NO_PAD
        .decode(token.split('.').nth(1).expect("JWT payload"))
        .expect("base64url payload");
    let claims: serde_json::Value = serde_json::from_slice(&bytes).expect("JSON claims");
    match &claims["aud"] {
        serde_json::Value::String(s) => vec![s.clone()],
        serde_json::Value::Array(values) => values
            .iter()
            .filter_map(|v| v.as_str().map(str::to_string))
            .collect(),
        _ => Vec::new(),
    }
}

fn access_token(body: &serde_json::Value) -> &str {
    body["access_token"]
        .as_str()
        .expect("access_token in success response")
}

fn refresh_token(body: &serde_json::Value) -> &str {
    body["refresh_token"]
        .as_str()
        .expect("refresh_token in code response")
}

#[actix_web::test]
async fn refresh_cannot_widen_resource() {
    let ctx = setup(vec![confidential_client("widening", "widening_secret")]).await;
    let app = app!(ctx);
    let issued = issue_code_tokens!(
        app,
        "widening",
        "widening_secret",
        Some("https://a.example/")
    );
    let (status, body) = refresh!(
        app,
        "widening",
        "widening_secret",
        refresh_token(&issued),
        Some("https://b.example/")
    );
    assert_eq!(status, 400, "wider audience must be refused");
    assert_eq!(body["error"], "invalid_target");
    assert!(body.get("access_token").is_none(), "no token on refusal");
}

#[actix_web::test]
async fn refresh_cannot_add_resource_when_original_had_none() {
    let ctx = setup(vec![confidential_client("adding", "adding_secret")]).await;
    let app = app!(ctx);
    let issued = issue_code_tokens!(app, "adding", "adding_secret", None::<&str>);
    let (status, body) = refresh!(
        app,
        "adding",
        "adding_secret",
        refresh_token(&issued),
        Some("https://b.example/")
    );
    assert_eq!(status, 400, "new audience must be refused");
    assert_eq!(body["error"], "invalid_target");
}

#[actix_web::test]
async fn refresh_inherits_original_resource_when_omitted() {
    let ctx = setup(vec![confidential_client("inheriting", "inheriting_secret")]).await;
    let app = app!(ctx);
    let issued = issue_code_tokens!(
        app,
        "inheriting",
        "inheriting_secret",
        Some("https://a.example/")
    );
    let (status, body) = refresh!(
        app,
        "inheriting",
        "inheriting_secret",
        refresh_token(&issued),
        None::<&str>
    );
    assert_eq!(status, 200, "omitted resource must inherit: {body}");
    assert_eq!(aud_of(access_token(&body)), vec!["https://a.example/"]);
}

#[actix_web::test]
async fn refresh_accepts_same_resource() {
    let ctx = setup(vec![confidential_client("same", "same_secret")]).await;
    let app = app!(ctx);
    let issued = issue_code_tokens!(app, "same", "same_secret", Some("https://a.example/"));
    let (status, body) = refresh!(
        app,
        "same",
        "same_secret",
        refresh_token(&issued),
        Some("https://a.example/")
    );
    assert_eq!(status, 200, "same audience must be accepted: {body}");
    assert_eq!(aud_of(access_token(&body)), vec!["https://a.example/"]);
}

#[actix_web::test]
async fn client_credentials_rejects_malformed_resource() {
    let ctx = setup(vec![confidential_client("malformed", "malformed_secret")]).await;
    let app = app!(ctx);
    for resource in ["not a uri", "https://a.example/#frag"] {
        let (status, body) =
            client_credentials!(app, "malformed", "malformed_secret", "read", &[resource]);
        assert_eq!(
            status, 400,
            "malformed resource {resource:?} must be refused"
        );
        assert_eq!(body["error"], "invalid_target");
    }
}

#[actix_web::test]
async fn client_credentials_rejects_unregistered_resource_when_registry_populated() {
    let ctx = setup(vec![confidential_client("registry", "registry_secret")]).await;
    let registered = ProtectedResource::new(
        "https://a.example/".to_string(),
        "A".to_string(),
        vec!["read".to_string()],
    );
    ctx.storage
        .save_resource(&registered)
        .await
        .expect("seed resource registry");
    let app = app!(ctx);

    let (status, body) = client_credentials!(
        app,
        "registry",
        "registry_secret",
        "read",
        &["https://b.example/"]
    );
    assert_eq!(status, 400, "unregistered resource must be refused");
    assert_eq!(body["error"], "invalid_target");

    let (status, body) = client_credentials!(
        app,
        "registry",
        "registry_secret",
        "read",
        &["https://a.example/"]
    );
    assert_eq!(status, 200, "registered resource must be accepted: {body}");
    assert_eq!(aud_of(access_token(&body)), vec!["https://a.example/"]);
}
