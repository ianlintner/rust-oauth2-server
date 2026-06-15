//! Phase 6 OAuth2/OIDC compliance tests.
//!
//! Covers:
//! - OIDC Back-Channel Logout 1.0: logout_token generation and claims.
//! - OIDC Front-Channel Logout 1.0: iframe-based logout rendering.
//! - OIDC Session Management 1.0: check_session_iframe endpoint.
//! - OIDC Core §3.1.2.1: prompt=consent and prompt=select_account.
//! - Discovery document: new fields for session/logout support.
//! - Client registration: back-channel/front-channel logout fields.

use actix::{Actor, Addr};
use actix_session::{storage::CookieSessionStore, Session, SessionMiddleware};
use actix_web::{cookie::Key, test, web, App, HttpResponse};
use serde_json::Value;

use oauth2_actix::actors::TokenActorPool;
use oauth2_actix::handlers::wellknown::OidcConfig;
use oauth2_core::{Client, User};
use oauth2_observability::Metrics;
use oauth2_ports::DynStorage;

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

fn oidc_config() -> OidcConfig {
    OidcConfig {
        issuer: "http://localhost".to_string(),
        jwt_secret: "test_jwt_secret".to_string(),
        id_token_alg: "HS256".to_string(),
        id_token_kid: None,
        id_token_private_key_pem: None,
    }
}

async fn test_set_session(session: Session) -> HttpResponse {
    session.insert("user_id", "user_123").unwrap();
    session.insert("authenticated", true).unwrap();
    session
        .insert("auth_time", chrono::Utc::now().timestamp())
        .unwrap();
    HttpResponse::Ok().finish()
}

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

fn s256_challenge(verifier: &str) -> String {
    use base64::{engine::general_purpose, Engine as _};
    use sha2::{Digest, Sha256};
    let hash = Sha256::digest(verifier.as_bytes());
    general_purpose::URL_SAFE_NO_PAD.encode(hash)
}

async fn setup_context(
    client: Client,
) -> (
    TokenActorPool,
    Addr<oauth2_actix::actors::ClientActor>,
    Addr<oauth2_actix::actors::AuthActor>,
    DynStorage,
    String,
    Metrics,
    OidcConfig,
) {
    let storage = oauth2_storage_factory::create_storage("sqlite::memory:")
        .await
        .expect("create storage");
    storage.init().await.expect("init storage");
    storage.save_client(&client).await.expect("save client");

    let now = chrono::Utc::now();
    let user = User {
        id: "user_123".to_string(),
        username: "user_123".to_string(),
        password_hash: "not_used".to_string(),
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

    let oidc_config = oidc_config();

    (
        token_pool,
        client_actor,
        auth_actor,
        storage,
        jwt_secret,
        metrics,
        oidc_config,
    )
}

/// Build a test client with back-channel logout configured.
fn backchannel_client() -> Client {
    let mut client = Client::new(
        "bc_client".to_string(),
        "bc_secret".to_string(),
        vec!["https://example.com/callback".to_string()],
        vec!["authorization_code".to_string()],
        "openid".to_string(),
        "test".to_string(),
    );
    client.backchannel_logout_uri = "https://example.com/backchannel-logout".to_string();
    client.backchannel_logout_session_required = true;
    client.post_logout_redirect_uris =
        serde_json::to_string(&vec!["https://example.com/logged-out"]).unwrap();
    client
}

/// Build a test client with front-channel logout configured.
fn frontchannel_client() -> Client {
    let mut client = Client::new(
        "fc_client".to_string(),
        "fc_secret".to_string(),
        vec!["https://example.com/callback".to_string()],
        vec!["authorization_code".to_string()],
        "openid".to_string(),
        "test".to_string(),
    );
    client.frontchannel_logout_uri = "https://example.com/frontchannel-logout".to_string();
    client.frontchannel_logout_session_required = true;
    client.post_logout_redirect_uris =
        serde_json::to_string(&vec!["https://example.com/logged-out"]).unwrap();
    client
}

/// Build a test app with session middleware and logout/session endpoints.
macro_rules! logout_app {
    ($token_actor:expr, $client_actor:expr, $auth_actor:expr,
     $storage:expr, $jwt_secret:expr, $metrics:expr, $oidc_config:expr) => {
        test::init_service(
            App::new()
                .wrap(SessionMiddleware::new(
                    CookieSessionStore::default(),
                    Key::generate(),
                ))
                .route("/test/login", web::get().to(test_set_session))
                .app_data(web::Data::new($token_actor))
                .app_data(web::Data::new($client_actor))
                .app_data(web::Data::new($auth_actor))
                .app_data(web::Data::new($storage))
                .app_data(web::Data::new($jwt_secret))
                .app_data(web::Data::new($metrics))
                .app_data(web::Data::new($oidc_config))
                .app_data(web::Data::new(false))
                .service(
                    web::scope("/oauth")
                        .route(
                            "/authorize",
                            web::get().to(oauth2_actix::handlers::oauth::authorize),
                        )
                        .route(
                            "/logout",
                            web::get().to(oauth2_actix::handlers::oidc_logout::logout),
                        )
                        .route(
                            "/check_session",
                            web::get().to(oauth2_actix::handlers::session::check_session_iframe),
                        ),
                )
                .service(web::scope("/.well-known").route(
                    "/openid-configuration",
                    web::get().to(oauth2_actix::handlers::wellknown::openid_configuration),
                )),
        )
        .await
    };
}

// ---------------------------------------------------------------------------
// Discovery document tests
// ---------------------------------------------------------------------------

/// OIDC Session Management 1.0: check_session_iframe must be advertised.
///
/// @rfc oidc-session-1.0
/// @section 4
/// @requirement Discovery must advertise `check_session_iframe` for OIDC Session Management.
/// @level MUST
/// @url https://openid.net/specs/openid-connect-session-1_0.html#OPMetadata
#[actix_web::test]
async fn wave6_discovery_includes_session_management_fields() {
    let oidc = oidc_config();
    let app = test::init_service(App::new().app_data(web::Data::new(oidc)).service(
        web::scope("/.well-known").route(
            "/openid-configuration",
            web::get().to(oauth2_actix::handlers::wellknown::openid_configuration),
        ),
    ))
    .await;

    let req = test::TestRequest::get()
        .uri("/.well-known/openid-configuration")
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 200);

    let body: Value = test::read_body_json(resp).await;

    // OIDC Session Management 1.0
    assert_eq!(
        body["check_session_iframe"],
        "http://localhost/oauth/check_session"
    );

    // OIDC Back-Channel Logout 1.0
    assert_eq!(body["backchannel_logout_supported"], true);
    assert_eq!(body["backchannel_logout_session_supported"], true);

    // OIDC Front-Channel Logout 1.0
    assert_eq!(body["frontchannel_logout_supported"], true);
    assert_eq!(body["frontchannel_logout_session_supported"], true);

    // prompt values
    let prompt_values = body["prompt_values_supported"].as_array().expect("array");
    let prompts: Vec<&str> = prompt_values.iter().map(|v| v.as_str().unwrap()).collect();
    assert!(prompts.contains(&"consent"), "missing prompt=consent");
    assert!(
        prompts.contains(&"select_account"),
        "missing prompt=select_account"
    );
}

// ---------------------------------------------------------------------------
// OIDC Session Management: check_session_iframe
// ---------------------------------------------------------------------------

/// OIDC Session Management 1.0 §3: check_session_iframe must return HTML
/// with a postMessage handler.
///
/// @rfc oidc-session-1.0
/// @section 3
/// @requirement check_session_iframe must return HTML with a postMessage handler.
/// @level MUST
/// @url https://openid.net/specs/openid-connect-session-1_0.html#OPiframe
#[actix_web::test]
async fn wave6_check_session_iframe_returns_html() {
    let oidc = oidc_config();
    let app = test::init_service(App::new().app_data(web::Data::new(oidc)).service(
        web::scope("/oauth").route(
            "/check_session",
            web::get().to(oauth2_actix::handlers::session::check_session_iframe),
        ),
    ))
    .await;

    let req = test::TestRequest::get()
        .uri("/oauth/check_session")
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 200);

    let content_type = resp
        .headers()
        .get("Content-Type")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(
        content_type.contains("text/html"),
        "check_session must return HTML"
    );

    let body = String::from_utf8(test::read_body(resp).await.to_vec()).unwrap();
    assert!(
        body.contains("postMessage"),
        "check_session must use postMessage API"
    );
    assert!(
        body.contains("SHA-256"),
        "check_session must compute SHA-256 for session state"
    );
}

// ---------------------------------------------------------------------------
// OIDC RP-Initiated Logout + Front-Channel
// ---------------------------------------------------------------------------

/// OIDC Front-Channel Logout 1.0 §3: When a client has frontchannel_logout_uri
/// registered, the logout endpoint must render an HTML page with iframes.
///
/// @rfc oidc-frontchannel-1.0
/// @section 3
/// @requirement Logout endpoint must render front-channel logout iframes for clients with `frontchannel_logout_uri`.
/// @level MUST
/// @url https://openid.net/specs/openid-connect-frontchannel-1_0.html#RPLogout
#[actix_web::test]
async fn wave6_logout_renders_frontchannel_iframes() {
    let client = frontchannel_client();
    let (token_actor, client_actor, auth_actor, storage, jwt_secret, metrics, oidc_config) =
        setup_context(client).await;
    let app = logout_app!(
        token_actor,
        client_actor,
        auth_actor,
        storage,
        jwt_secret,
        metrics,
        oidc_config
    );

    // Establish session.
    let login_req = test::TestRequest::get().uri("/test/login").to_request();
    let login_resp = test::call_service(&app, login_req).await;
    let cookie = extract_session_cookie(&login_resp);

    // Hit logout.
    let req = test::TestRequest::get()
        .uri("/oauth/logout")
        .insert_header(("Cookie", cookie))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 200);

    let body = String::from_utf8(test::read_body(resp).await.to_vec()).unwrap();
    assert!(
        body.contains("<iframe"),
        "front-channel logout must render iframes"
    );
    assert!(
        body.contains("https://example.com/frontchannel-logout"),
        "iframe must point to the client's frontchannel_logout_uri"
    );
    assert!(
        body.contains("iss="),
        "iframe URI must include iss parameter"
    );
}

/// OIDC RP-Initiated Logout: post_logout_redirect_uri must be checked against
/// post_logout_redirect_uris (not just redirect_uris).
///
/// @rfc oidc-rpinit-1.0
/// @section 3
/// @requirement Logout must accept post_logout_redirect_uri only when registered in post_logout_redirect_uris.
/// @level MUST
/// @url https://openid.net/specs/openid-connect-rpinitiated-1_0.html#RPLogout
#[actix_web::test]
async fn wave6_logout_accepts_registered_post_logout_redirect_uri() {
    let client = backchannel_client();
    let (token_actor, client_actor, auth_actor, storage, jwt_secret, metrics, oidc_config) =
        setup_context(client).await;
    let app = logout_app!(
        token_actor,
        client_actor,
        auth_actor,
        storage,
        jwt_secret,
        metrics,
        oidc_config
    );

    // Establish session.
    let login_req = test::TestRequest::get().uri("/test/login").to_request();
    let login_resp = test::call_service(&app, login_req).await;
    let cookie = extract_session_cookie(&login_resp);

    // Logout with registered post_logout_redirect_uri.
    let req = test::TestRequest::get()
        .uri("/oauth/logout?post_logout_redirect_uri=https%3A%2F%2Fexample.com%2Flogged-out")
        .insert_header(("Cookie", cookie))
        .to_request();
    let resp = test::call_service(&app, req).await;

    // Should redirect (302) to the registered URI.
    assert_eq!(resp.status(), 302);
    let location = resp.headers().get("Location").unwrap().to_str().unwrap();
    assert!(location.starts_with("https://example.com/logged-out"));
}

/// OIDC RP-Initiated Logout: unregistered post_logout_redirect_uri must be rejected.
///
/// @rfc oidc-rpinit-1.0
/// @section 3
/// @requirement Logout must reject unregistered post_logout_redirect_uri values.
/// @level MUST
/// @url https://openid.net/specs/openid-connect-rpinitiated-1_0.html#RPLogout
#[actix_web::test]
async fn wave6_logout_rejects_unregistered_post_logout_redirect_uri() {
    let client = backchannel_client();
    let (token_actor, client_actor, auth_actor, storage, jwt_secret, metrics, oidc_config) =
        setup_context(client).await;
    let app = logout_app!(
        token_actor,
        client_actor,
        auth_actor,
        storage,
        jwt_secret,
        metrics,
        oidc_config
    );

    // Establish session.
    let login_req = test::TestRequest::get().uri("/test/login").to_request();
    let login_resp = test::call_service(&app, login_req).await;
    let cookie = extract_session_cookie(&login_resp);

    // Logout with unregistered post_logout_redirect_uri.
    let req = test::TestRequest::get()
        .uri("/oauth/logout?post_logout_redirect_uri=https%3A%2F%2Fevil.com%2Fredirect")
        .insert_header(("Cookie", cookie))
        .to_request();
    let resp = test::call_service(&app, req).await;

    // Must be rejected (4xx).
    assert!(
        resp.status().is_client_error(),
        "must reject unregistered post_logout_redirect_uri, got {}",
        resp.status()
    );
}

// ---------------------------------------------------------------------------
// prompt=consent
// ---------------------------------------------------------------------------

/// OIDC Core §3.1.2.1: prompt=consent should proceed normally (auto-approve).
///
/// @rfc oidc-core-1.0
/// @section 3.1.2.1
/// @requirement `prompt=consent` must proceed to authorization (auto-approve in test harness).
/// @level MUST
/// @url https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
#[actix_web::test]
async fn wave6_prompt_consent_proceeds_after_auto_approve() {
    let mut client = Client::new(
        "consent_client".to_string(),
        "consent_secret".to_string(),
        vec!["https://example.com/callback".to_string()],
        vec!["authorization_code".to_string()],
        "openid read".to_string(),
        "test".to_string(),
    );
    client.token_endpoint_auth_method = "client_secret_basic".to_string();

    let (token_actor, client_actor, auth_actor, storage, jwt_secret, metrics, oidc_config) =
        setup_context(client).await;

    let app = logout_app!(
        token_actor,
        client_actor,
        auth_actor,
        storage,
        jwt_secret,
        metrics,
        oidc_config
    );

    // Establish session.
    let login_req = test::TestRequest::get().uri("/test/login").to_request();
    let login_resp = test::call_service(&app, login_req).await;
    let cookie = extract_session_cookie(&login_resp);

    let verifier = "test_verifier_abcdef_1234567890_consent";
    let challenge = s256_challenge(verifier);

    // Authorization request with prompt=consent.
    let req = test::TestRequest::get()
        .uri(&format!(
            "/oauth/authorize?response_type=code&client_id=consent_client\
             &redirect_uri=https%3A%2F%2Fexample.com%2Fcallback\
             &scope=openid+read&state=abc&prompt=consent\
             &code_challenge={}&code_challenge_method=S256",
            challenge
        ))
        .insert_header(("Cookie", cookie))
        .to_request();
    let resp = test::call_service(&app, req).await;

    // Should redirect with an authorization code (auto-approved consent).
    assert_eq!(
        resp.status(),
        302,
        "prompt=consent should succeed with auto-approve"
    );
    let location = resp.headers().get("Location").unwrap().to_str().unwrap();
    assert!(
        location.contains("code="),
        "redirect must contain authorization code"
    );
}

/// OIDC Core §3.1.2.1: prompt=select_account forces re-authentication
/// (single-account server treats it as prompt=login).
///
/// @rfc oidc-core-1.0
/// @section 3.1.2.1
/// @requirement `prompt=select_account` must force account selection / re-authentication.
/// @level MUST
/// @url https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
#[actix_web::test]
async fn wave6_prompt_select_account_forces_reauth() {
    let client = Client::new(
        "sa_client".to_string(),
        "sa_secret".to_string(),
        vec!["https://example.com/callback".to_string()],
        vec!["authorization_code".to_string()],
        "read".to_string(),
        "test".to_string(),
    );

    let (token_actor, client_actor, auth_actor, storage, jwt_secret, metrics, oidc_config) =
        setup_context(client).await;
    let app = logout_app!(
        token_actor,
        client_actor,
        auth_actor,
        storage,
        jwt_secret,
        metrics,
        oidc_config
    );

    // Establish session.
    let login_req = test::TestRequest::get().uri("/test/login").to_request();
    let login_resp = test::call_service(&app, login_req).await;
    let cookie = extract_session_cookie(&login_resp);

    let verifier = "test_verifier_select_account_123456789";
    let challenge = s256_challenge(verifier);

    // Authorization request with prompt=select_account.
    let req = test::TestRequest::get()
        .uri(&format!(
            "/oauth/authorize?response_type=code&client_id=sa_client\
             &redirect_uri=https%3A%2F%2Fexample.com%2Fcallback\
             &scope=read&state=xyz&prompt=select_account\
             &code_challenge={}&code_challenge_method=S256",
            challenge
        ))
        .insert_header(("Cookie", cookie))
        .to_request();
    let resp = test::call_service(&app, req).await;

    // prompt=select_account forces login, should redirect to login page.
    assert_eq!(resp.status(), 302);
    let location = resp.headers().get("Location").unwrap().to_str().unwrap();
    assert!(
        location.contains("/auth/login"),
        "prompt=select_account must redirect to login"
    );
}

/// OIDC Back-Channel Logout 1.0 §2.4/§2.5: The logout endpoint must POST a
/// correctly structured logout_token JWT to every client with a registered
/// backchannel_logout_uri.  The token must carry typ=logout+JWT, exp, iss,
/// aud, iat, jti, events, and at least one of sub or sid.
///
/// @rfc oidc-backchannel-1.0
/// @section 2.4
/// @requirement logout_token must have typ=logout+JWT, exp, and required claims.
/// @level MUST
/// @url https://openid.net/specs/openid-connect-backchannel-1_0.html#LogoutToken
#[actix_web::test]
async fn wave6_backchannel_logout_posts_valid_token() {
    use httpmock::prelude::*;
    use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
    use std::sync::{Arc, Mutex};

    // Shared capture of the raw request body.
    let captured: Arc<Mutex<String>> = Arc::new(Mutex::new(String::new()));
    let captured_clone = Arc::clone(&captured);

    let mock_server = MockServer::start();
    let bc_mock = mock_server.mock(|when, then| {
        when.method(POST)
            .path("/bc-logout")
            .header("Content-Type", "application/x-www-form-urlencoded")
            .is_true(move |req| {
                let body = req.body_string();
                *captured_clone.lock().unwrap() = body.clone();
                body.starts_with("logout_token=")
            });
        then.status(200);
    });

    let mut client = Client::new(
        "bc_deliver_client".to_string(),
        "bc_secret_deliver".to_string(),
        vec!["https://example.com/callback".to_string()],
        vec!["authorization_code".to_string()],
        "openid".to_string(),
        "test".to_string(),
    );
    client.backchannel_logout_uri = format!("{}/bc-logout", mock_server.base_url());
    client.backchannel_logout_session_required = false;

    let (token_actor, client_actor, auth_actor, storage, jwt_secret, metrics, oidc_config) =
        setup_context(client).await;
    let app = logout_app!(
        token_actor,
        client_actor,
        auth_actor,
        storage,
        jwt_secret,
        metrics,
        oidc_config
    );

    // Establish a session so the handler can derive sub.
    let login_req = test::TestRequest::get().uri("/test/login").to_request();
    let login_resp = test::call_service(&app, login_req).await;
    let cookie = extract_session_cookie(&login_resp);

    // Build an id_token_hint signed with the test secret so the handler can extract sub.
    let now = chrono::Utc::now().timestamp();
    let id_token_claims = serde_json::json!({
        "iss": "http://localhost",
        "sub": "user_123",
        "aud": "bc_deliver_client",
        "exp": now + 3600,
        "iat": now,
    });
    let id_token = jsonwebtoken::encode(
        &jsonwebtoken::Header::default(),
        &id_token_claims,
        &jsonwebtoken::EncodingKey::from_secret(b"test_jwt_secret"),
    )
    .unwrap();

    let req = test::TestRequest::get()
        .uri(&format!("/oauth/logout?id_token_hint={}", id_token))
        .insert_header(("Cookie", cookie))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert!(
        resp.status().is_success() || resp.status().is_redirection(),
        "logout should succeed, got {}",
        resp.status()
    );

    // Verify exactly one POST was made with the correct body prefix.
    bc_mock.assert_calls(1);

    // Extract the JWT from the captured body (form-encoded: logout_token=<jwt>).
    let raw = captured.lock().unwrap().clone();
    let token_str = raw
        .strip_prefix("logout_token=")
        .expect("body must start with logout_token=");
    // The value is URL-percent-encoded in form bodies; dots and base64url chars
    // survive unencoded, but we decode defensively.
    let token_str = percent_encoding::percent_decode_str(token_str)
        .decode_utf8()
        .expect("valid UTF-8")
        .into_owned();

    // §2.4: JOSE header must have typ=logout+JWT.
    let header = jsonwebtoken::decode_header(&token_str).expect("valid JWT header");
    assert_eq!(
        header.typ.as_deref(),
        Some("logout+JWT"),
        "logout token header must have typ=logout+JWT"
    );

    // Decode claims without signature verification (we trust the test secret).
    let mut validation = Validation::new(Algorithm::HS256);
    validation.validate_exp = false;
    validation.validate_aud = false;
    let claims: serde_json::Value = decode(
        &token_str,
        &DecodingKey::from_secret(b"test_jwt_secret"),
        &validation,
    )
    .expect("token must be decodable")
    .claims;

    assert_eq!(claims["iss"], "http://localhost", "iss must match issuer");
    assert_eq!(claims["aud"], "bc_deliver_client", "aud must be client_id");
    assert!(claims["iat"].is_number(), "iat must be present");
    assert!(claims["exp"].is_number(), "exp must be present");
    assert!(claims["jti"].is_string(), "jti must be present");
    assert!(
        claims["events"]["http://schemas.openid.net/event/backchannel-logout"].is_object(),
        "events claim must contain the backchannel-logout URI"
    );
    assert_eq!(
        claims["sub"], "user_123",
        "sub must match the authenticated user"
    );
}

// ---------------------------------------------------------------------------
// Client registration: logout fields
// ---------------------------------------------------------------------------

/// OIDC Back-Channel Logout 1.0 §2.1: Dynamic client registration must
/// accept backchannel_logout_uri and backchannel_logout_session_required.
///
/// @rfc oidc-backchannel-1.0
/// @section 2.1
/// @requirement Dynamic client registration must accept `backchannel_logout_uri` and `backchannel_logout_session_required`.
/// @level MUST
/// @url https://openid.net/specs/openid-connect-backchannel-1_0.html#ClientMetadata
#[actix_web::test]
async fn wave6_client_registration_includes_logout_fields() {
    // Enable the public RFC 7591 registration endpoint for this test (process-local
    // to this test binary).
    std::env::set_var("OAUTH2_DYNAMIC_REGISTRATION_ENABLED", "true");

    let storage = oauth2_storage_factory::create_storage("sqlite::memory:")
        .await
        .expect("storage");
    storage.init().await.expect("init");

    let client_actor = oauth2_actix::actors::ClientActor::new(storage.clone()).start();

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(client_actor))
            .app_data(web::Data::new(oidc_config()))
            .service(web::scope("/connect").route(
                "/register",
                web::post().to(oauth2_actix::handlers::client::dynamic_register),
            )),
    )
    .await;

    let reg_body = serde_json::json!({
        "redirect_uris": ["https://example.com/callback"],
        "grant_types": ["authorization_code"],
        "scope": "openid",
        "client_name": "test_logout_client",
        "backchannel_logout_uri": "https://example.com/bc-logout",
        "backchannel_logout_session_required": true,
        "frontchannel_logout_uri": "https://example.com/fc-logout",
        "frontchannel_logout_session_required": true,
        "post_logout_redirect_uris": ["https://example.com/logged-out"]
    });

    let req = test::TestRequest::post()
        .uri("/connect/register")
        .set_json(&reg_body)
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 201, "dynamic registration should succeed");

    let body: Value = test::read_body_json(resp).await;
    assert_eq!(
        body["backchannel_logout_uri"], "https://example.com/bc-logout",
        "response must echo backchannel_logout_uri"
    );
    assert_eq!(
        body["backchannel_logout_session_required"], true,
        "response must echo backchannel_logout_session_required"
    );
    assert_eq!(
        body["frontchannel_logout_uri"], "https://example.com/fc-logout",
        "response must echo frontchannel_logout_uri"
    );
    assert_eq!(
        body["frontchannel_logout_session_required"], true,
        "response must echo frontchannel_logout_session_required"
    );
}

/// OIDC RP-Initiated Logout: simple logout without id_token_hint or redirect returns 200.
///
/// @rfc oidc-rpinit-1.0
/// @section 3
/// @requirement Logout endpoint must accept a simple GET (no id_token_hint, no redirect) and return 200.
/// @level SHOULD
/// @url https://openid.net/specs/openid-connect-rpinitiated-1_0.html#RPLogout
#[actix_web::test]
async fn wave6_simple_logout_returns_ok() {
    let client = Client::new(
        "simple_client".to_string(),
        "simple_secret".to_string(),
        vec!["https://example.com/callback".to_string()],
        vec!["authorization_code".to_string()],
        "openid".to_string(),
        "test".to_string(),
    );

    let (token_actor, client_actor, auth_actor, storage, jwt_secret, metrics, oidc_config) =
        setup_context(client).await;
    let app = logout_app!(
        token_actor,
        client_actor,
        auth_actor,
        storage,
        jwt_secret,
        metrics,
        oidc_config
    );

    // Establish session.
    let login_req = test::TestRequest::get().uri("/test/login").to_request();
    let login_resp = test::call_service(&app, login_req).await;
    let cookie = extract_session_cookie(&login_resp);

    // Simple logout.
    let req = test::TestRequest::get()
        .uri("/oauth/logout")
        .insert_header(("Cookie", cookie))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 200);

    let body: Value = test::read_body_json(resp).await;
    assert_eq!(body["status"], "logged_out");
}
