//! Phase 7 (agent / A2A OAuth) Task 17: named-agent consent.
//!
//! `draft-oauth-ai-agents-on-behalf-of-user`: the authorization request names
//! the agent that will act for the user (`requested_actor`), the login page
//! tells the user who is being named, the authorization code carries the
//! request, and the code exchange must present an `actor_token` proving the
//! named agent is really the one collecting the token. The issued access
//! token then carries `act = {sub: <agent>, iss: <issuer>, sub_profile:
//! "ai_agent"}`, which the refresh grant preserves.

use actix::Actor;
use actix_session::{storage::CookieSessionStore, Session, SessionMiddleware};
use actix_web::{cookie::Key, test, web, App, HttpResponse};
use serde_json::Value;
use std::sync::Arc;
use tokio::sync::RwLock;

use oauth2_actix::actors::{CreateToken, TokenActor, TokenActorPool};
use oauth2_actix::handlers::wellknown::OidcConfig;
use oauth2_config::AgentConfig;
use oauth2_core::{Client, Token, User};
use oauth2_observability::Metrics;
use oauth2_ports::DynStorage;

const ISSUER: &str = "https://auth.example.com";
const JWT_SECRET: &str = "obo_consent_test_secret_at_least_32_chars";
const REDIRECT_URI: &str = "https://app.example.test/cb";
const VERIFIER: &str = "verifier-obo-abcdefghijklmnopqrstuvwxyz1234567890";
const ACCESS_TOKEN_TYPE: &str = "urn:ietf:params:oauth:token-type:access_token";
const USER_ID: &str = "user_obo";
const USER_PASSWORD: &str = "correct horse battery staple";

fn s256(verifier: &str) -> String {
    use base64::{engine::general_purpose, Engine as _};
    use sha2::{Digest, Sha256};
    general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

fn client(client_id: &str, name: &str, grants: &[&str]) -> Client {
    Client::new(
        client_id.to_string(),
        format!("{client_id}_secret"),
        vec![REDIRECT_URI.to_string()],
        grants.iter().map(|g| g.to_string()).collect(),
        "read".to_string(),
        name.to_string(),
    )
}

async fn storage() -> DynStorage {
    let storage = oauth2_storage_factory::create_storage("sqlite::memory:")
        .await
        .expect("create storage");
    storage.init().await.expect("init storage");

    storage
        .save_client(&client(
            "user_client",
            "Acme Mail",
            &["authorization_code", "refresh_token"],
        ))
        .await
        .expect("save user_client");
    storage
        .save_client(&client(
            "agent_client",
            "Scheduler Agent",
            &["client_credentials"],
        ))
        .await
        .expect("save agent_client");
    storage
        .save_client(&client(
            "other_client",
            "Unrelated Agent",
            &["client_credentials"],
        ))
        .await
        .expect("save other_client");

    let now = chrono::Utc::now();
    storage
        .save_user(&User {
            id: USER_ID.to_string(),
            username: USER_ID.to_string(),
            password_hash: oauth2_actix::handlers::login::hash_password(USER_PASSWORD)
                .expect("hash password"),
            email: "obo@example.test".to_string(),
            enabled: true,
            role: "user".to_string(),
            created_at: now,
            updated_at: now,
        })
        .await
        .expect("save user");

    storage
}

/// Mint an access token for `client_id` through the real `CreateToken` path so
/// it is persisted and resolvable as an `actor_token`.
async fn mint_agent_token(storage: &DynStorage, client_id: &str) -> Token {
    TokenActor::new(storage.clone(), JWT_SECRET.to_string(), ISSUER.to_string())
        .start()
        .send(CreateToken {
            user_id: None,
            client_id: client_id.to_string(),
            scope: "read".to_string(),
            include_refresh: false,
            token_family: None,
            resources: vec![],
            cnf: None,
            authorization_details: None,
            act: None,
            ttl_override_secs: None,
            sub_profile: None,
            txn: None,
            span: tracing::Span::current(),
        })
        .await
        .expect("send CreateToken")
        .expect("create token")
}

async fn set_session(session: Session) -> HttpResponse {
    session.insert("user_id", USER_ID).unwrap();
    session.insert("authenticated", true).unwrap();
    HttpResponse::Ok().finish()
}

fn session_cookie(
    resp: &actix_web::dev::ServiceResponse<impl actix_web::body::MessageBody>,
) -> Option<String> {
    resp.response()
        .headers()
        .get(actix_web::http::header::SET_COOKIE)
        .and_then(|h| h.to_str().ok())
        .map(|h| h.split(';').next().unwrap().to_string())
}

fn location(resp: &actix_web::dev::ServiceResponse<impl actix_web::body::MessageBody>) -> String {
    resp.headers()
        .get("Location")
        .expect("Location header")
        .to_str()
        .expect("utf-8 Location")
        .to_string()
}

/// Build an inline App exposing authorize / token / introspect plus the login
/// page, all behind a cookie session.
macro_rules! obo_app {
    ($storage:expr, $agent_config:expr) => {{
        let storage: DynStorage = $storage.clone();
        let jwt_secret = JWT_SECRET.to_string();
        let metrics = Metrics::new().expect("metrics");
        let token_pool = TokenActorPool::new(vec![TokenActor::new(
            storage.clone(),
            jwt_secret.clone(),
            ISSUER.to_string(),
        )
        .start()]);
        let client_actor = oauth2_actix::actors::ClientActor::new(storage.clone()).start();
        let auth_actor = oauth2_actix::actors::AuthActor::new(storage.clone()).start();
        let oidc_config = OidcConfig {
            issuer: ISSUER.to_string(),
            jwt_secret: jwt_secret.clone(),
            id_token_alg: "HS256".to_string(),
            id_token_kid: None,
            id_token_private_key_pem: None,
        };
        let keyset = Arc::new(RwLock::new(oauth2_core::models::key_set::KeySet::default()));
        let mut config = oauth2_config::Config::default();
        config.jwt.secret = jwt_secret.clone();

        test::init_service(
            App::new()
                .wrap(SessionMiddleware::new(
                    CookieSessionStore::default(),
                    Key::generate(),
                ))
                .app_data(web::Data::new(token_pool))
                .app_data(web::Data::new(client_actor))
                .app_data(web::Data::new(auth_actor))
                .app_data(web::Data::new(storage))
                .app_data(web::Data::new(jwt_secret))
                .app_data(web::Data::new(metrics))
                .app_data(web::Data::new(oidc_config))
                .app_data(web::Data::new(keyset))
                .app_data(web::Data::new(false))
                .app_data(web::Data::new(config))
                .app_data(web::Data::new($agent_config))
                .route("/_set_session", web::get().to(set_session))
                .service(
                    web::scope("/auth")
                        .route(
                            "/login",
                            web::get().to(oauth2_actix::handlers::login::login_page),
                        )
                        .route(
                            "/login",
                            web::post().to(oauth2_actix::handlers::login::login_submit),
                        ),
                )
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
                        ),
                ),
        )
        .await
    }};
}

fn authorize_uri(requested_actor: Option<&str>) -> String {
    let mut uri = format!(
        "/oauth/authorize?response_type=code&client_id=user_client&redirect_uri=https%3A%2F%2Fapp.example.test%2Fcb&scope=read&state=xyz&code_challenge={}&code_challenge_method=S256",
        s256(VERIFIER)
    );
    if let Some(actor) = requested_actor {
        uri.push_str(&format!("&requested_actor={actor}"));
    }
    uri
}

macro_rules! authorize {
    ($app:expr, $cookie:expr, $requested_actor:expr) => {{
        let mut req = test::TestRequest::get().uri(&authorize_uri($requested_actor));
        if let Some(cookie) = $cookie {
            req = req.insert_header(("Cookie", cookie));
        }
        test::call_service(&$app, req.to_request()).await
    }};
}

/// Drive `/_set_session` + `/oauth/authorize` and return the issued code.
macro_rules! code_for {
    ($app:expr, $requested_actor:expr) => {{
        let session_resp = test::call_service(
            &$app,
            test::TestRequest::get().uri("/_set_session").to_request(),
        )
        .await;
        let cookie = session_cookie(&session_resp).expect("session cookie");
        let resp = authorize!($app, Some(cookie.as_str()), $requested_actor);
        assert_eq!(resp.status(), 302, "authorize must redirect with a code");
        let loc = location(&resp);
        loc.split_once("code=")
            .map(|(_, rest)| rest.split('&').next().unwrap().to_string())
            .unwrap_or_else(|| panic!("no code in redirect: {loc}"))
    }};
}

macro_rules! exchange_code {
    ($app:expr, $code:expr, $extra:expr) => {{
        let mut pairs: Vec<(&str, &str)> = vec![
            ("grant_type", "authorization_code"),
            ("code", $code),
            ("client_id", "user_client"),
            ("client_secret", "user_client_secret"),
            ("redirect_uri", REDIRECT_URI),
            ("code_verifier", VERIFIER),
        ];
        pairs.extend_from_slice($extra);
        test::call_service(
            &$app,
            test::TestRequest::post()
                .uri("/oauth/token")
                .set_form(pairs)
                .to_request(),
        )
        .await
    }};
}

macro_rules! introspect {
    ($app:expr, $token:expr) => {{
        let resp = test::call_service(
            &$app,
            test::TestRequest::post()
                .uri("/oauth/introspect")
                .set_form([
                    ("token", $token),
                    ("client_id", "user_client"),
                    ("client_secret", "user_client_secret"),
                ])
                .to_request(),
        )
        .await;
        assert_eq!(resp.status(), 200, "introspection must return 200");
        let body: Value = test::read_body_json(resp).await;
        body
    }};
}

fn obo_on() -> AgentConfig {
    AgentConfig {
        obo_enabled: true,
        ..AgentConfig::default()
    }
}

fn obo_off() -> AgentConfig {
    AgentConfig {
        obo_enabled: false,
        ..AgentConfig::default()
    }
}

// ---------------------------------------------------------------------------
// 1. Feature flag off — `requested_actor` is an unknown parameter (RFC 6749 §3.1)
// ---------------------------------------------------------------------------

#[actix_web::test]
async fn flag_off_ignores_requested_actor() {
    let storage = storage().await;
    let app = obo_app!(storage, obo_off());

    let code = code_for!(app, Some("agent_client"));
    // No actor_token supplied: with the flag off the code carries no actor
    // requirement, so the exchange must succeed.
    let resp = exchange_code!(app, code.as_str(), &[]);
    assert_eq!(
        resp.status(),
        200,
        "exchange must succeed with the flag off"
    );
    let body: Value = test::read_body_json(resp).await;
    let access_token = body["access_token"].as_str().expect("access_token");

    let intro = introspect!(app, access_token);
    assert!(
        intro.get("act").map(Value::is_null).unwrap_or(true),
        "no delegation was authorized, so `act` must be absent: {intro}"
    );
}

// ---------------------------------------------------------------------------
// 2. Unknown actor → error redirect
// ---------------------------------------------------------------------------

#[actix_web::test]
async fn unknown_requested_actor_is_error_redirect() {
    let storage = storage().await;
    let app = obo_app!(storage, obo_on());

    let session_resp = test::call_service(
        &app,
        test::TestRequest::get().uri("/_set_session").to_request(),
    )
    .await;
    let cookie = session_cookie(&session_resp).expect("session cookie");

    let resp = authorize!(app, Some(cookie.as_str()), Some("not_a_client"));
    assert_eq!(resp.status(), 302, "unknown actor must redirect, not 400");
    let loc = location(&resp);
    assert!(
        loc.starts_with(REDIRECT_URI),
        "error must go through the redirect channel: {loc}"
    );
    assert!(
        loc.contains("error=invalid_request"),
        "expected invalid_request: {loc}"
    );
    assert!(!loc.contains("code="), "no code may be issued: {loc}");
}

// ---------------------------------------------------------------------------
// 3. Happy path
// ---------------------------------------------------------------------------

#[actix_web::test]
async fn named_agent_consent_happy_path() {
    let storage = storage().await;
    let agent_token = mint_agent_token(&storage, "agent_client").await;
    let app = obo_app!(storage, obo_on());

    let code = code_for!(app, Some("agent_client"));
    let resp = exchange_code!(
        app,
        code.as_str(),
        &[
            ("actor_token", agent_token.access_token.as_str()),
            ("actor_token_type", ACCESS_TOKEN_TYPE),
        ]
    );
    assert_eq!(resp.status(), 200, "named-agent exchange must succeed");
    let body: Value = test::read_body_json(resp).await;
    let access_token = body["access_token"].as_str().expect("access_token");

    let intro = introspect!(app, access_token);
    assert_eq!(intro["act"]["sub"], "agent_client", "body: {intro}");
    assert_eq!(intro["act"]["iss"], ISSUER, "body: {intro}");
    assert_eq!(intro["act"]["sub_profile"], "ai_agent", "body: {intro}");
}

// ---------------------------------------------------------------------------
// 4. Missing actor_token at the code exchange
// ---------------------------------------------------------------------------

#[actix_web::test]
async fn missing_actor_token_is_invalid_request() {
    let storage = storage().await;
    let app = obo_app!(storage, obo_on());

    let code = code_for!(app, Some("agent_client"));
    let resp = exchange_code!(app, code.as_str(), &[]);
    assert_eq!(resp.status(), 400);
    let body: Value = test::read_body_json(resp).await;
    assert_eq!(body["error"], "invalid_request", "body: {body}");
}

#[actix_web::test]
async fn actor_token_without_type_is_invalid_request() {
    let storage = storage().await;
    let agent_token = mint_agent_token(&storage, "agent_client").await;
    let app = obo_app!(storage, obo_on());

    let code = code_for!(app, Some("agent_client"));
    let resp = exchange_code!(
        app,
        code.as_str(),
        &[("actor_token", agent_token.access_token.as_str())]
    );
    assert_eq!(resp.status(), 400);
    let body: Value = test::read_body_json(resp).await;
    assert_eq!(body["error"], "invalid_request", "body: {body}");
}

// ---------------------------------------------------------------------------
// 5. actor_token issued to a different client
// ---------------------------------------------------------------------------

#[actix_web::test]
async fn actor_token_from_another_client_is_invalid_grant() {
    let storage = storage().await;
    let other_token = mint_agent_token(&storage, "other_client").await;
    let app = obo_app!(storage, obo_on());

    let code = code_for!(app, Some("agent_client"));
    let resp = exchange_code!(
        app,
        code.as_str(),
        &[
            ("actor_token", other_token.access_token.as_str()),
            ("actor_token_type", ACCESS_TOKEN_TYPE),
        ]
    );
    assert_eq!(resp.status(), 400);
    let body: Value = test::read_body_json(resp).await;
    assert_eq!(body["error"], "invalid_grant", "body: {body}");
}

// ---------------------------------------------------------------------------
// 6. Refresh preserves `act` (7.C.4)
// ---------------------------------------------------------------------------

#[actix_web::test]
async fn refresh_grant_preserves_act() {
    let storage = storage().await;
    let agent_token = mint_agent_token(&storage, "agent_client").await;
    let app = obo_app!(storage, obo_on());

    let code = code_for!(app, Some("agent_client"));
    let resp = exchange_code!(
        app,
        code.as_str(),
        &[
            ("actor_token", agent_token.access_token.as_str()),
            ("actor_token_type", ACCESS_TOKEN_TYPE),
        ]
    );
    assert_eq!(resp.status(), 200);
    let body: Value = test::read_body_json(resp).await;
    let refresh_token = body["refresh_token"]
        .as_str()
        .expect("refresh_token")
        .to_string();

    let resp = test::call_service(
        &app,
        test::TestRequest::post()
            .uri("/oauth/token")
            .set_form([
                ("grant_type", "refresh_token"),
                ("refresh_token", refresh_token.as_str()),
                ("client_id", "user_client"),
                ("client_secret", "user_client_secret"),
            ])
            .to_request(),
    )
    .await;
    assert_eq!(resp.status(), 200, "refresh must succeed");
    let body: Value = test::read_body_json(resp).await;
    let refreshed = body["access_token"].as_str().expect("access_token");

    let intro = introspect!(app, refreshed);
    assert_eq!(intro["act"]["sub"], "agent_client", "body: {intro}");
    assert_eq!(intro["act"]["sub_profile"], "ai_agent", "body: {intro}");
}

// ---------------------------------------------------------------------------
// 7. Consent prompt on the login page
// ---------------------------------------------------------------------------

#[actix_web::test]
async fn login_page_names_the_requested_actor() {
    let storage = storage().await;
    let app = obo_app!(storage, obo_on());

    // No session → authorize stores the pending request and bounces to login.
    let resp = authorize!(app, None::<&str>, Some("agent_client"));
    assert_eq!(resp.status(), 302);
    assert_eq!(location(&resp), "/auth/login");
    let cookie = session_cookie(&resp).expect("session cookie");

    let resp = test::call_service(
        &app,
        test::TestRequest::get()
            .uri("/auth/login")
            .insert_header(("Cookie", cookie.as_str()))
            .to_request(),
    )
    .await;
    assert_eq!(resp.status(), 200);
    let body = String::from_utf8(test::read_body(resp).await.to_vec()).expect("utf-8 body");
    assert!(
        body.contains("Scheduler Agent"),
        "login page must name the agent"
    );
    assert!(
        body.contains("Acme Mail"),
        "login page must name the requesting client"
    );

    // The prompt is one-shot: it must not survive the login submission.
    let resp = test::call_service(
        &app,
        test::TestRequest::post()
            .uri("/auth/login")
            .insert_header(("Cookie", cookie.as_str()))
            .set_form([("username", USER_ID), ("password", USER_PASSWORD)])
            .to_request(),
    )
    .await;
    assert_eq!(resp.status(), 303, "login must redirect on success");
    let cookie = session_cookie(&resp).unwrap_or(cookie);

    let resp = test::call_service(
        &app,
        test::TestRequest::get()
            .uri("/auth/login")
            .insert_header(("Cookie", cookie.as_str()))
            .to_request(),
    )
    .await;
    let body = String::from_utf8(test::read_body(resp).await.to_vec()).expect("utf-8 body");
    assert!(
        !body.contains("Scheduler Agent"),
        "the actor prompt must be cleared once the user has logged in"
    );
}

#[actix_web::test]
async fn login_page_has_no_actor_prompt_without_requested_actor() {
    let storage = storage().await;
    let app = obo_app!(storage, obo_on());

    let resp = authorize!(app, None::<&str>, None);
    assert_eq!(resp.status(), 302);
    let cookie = session_cookie(&resp).expect("session cookie");

    let resp = test::call_service(
        &app,
        test::TestRequest::get()
            .uri("/auth/login")
            .insert_header(("Cookie", cookie.as_str()))
            .to_request(),
    )
    .await;
    let body = String::from_utf8(test::read_body(resp).await.to_vec()).expect("utf-8 body");
    assert!(
        !body.contains("Scheduler Agent"),
        "no agent was requested, so no prompt may be rendered"
    );
}
