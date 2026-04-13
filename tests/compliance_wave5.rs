//! Phase 5 OAuth2/OIDC compliance tests.
//!
//! Covers:
//! - §5.1 JAR (RFC 9101): inline `request` JWT parameter — unsigned (public client)
//!   and HS256 (confidential client).
//! - §5.2 OIDC Hybrid Flow: `response_type=code id_token` with `c_hash` in the
//!   id_token (OIDC Core §3.3).
//! - §5.3 `response_mode=fragment` (OAuth 2.0 Multiple Response Type Encoding Practices).
//! - Discovery document: updated `response_types_supported`,
//!   `response_modes_supported`, and `request_parameter_supported`.

use actix::{Actor, Addr};
use actix_session::{storage::CookieSessionStore, Session, SessionMiddleware};
use actix_web::{cookie::Key, test, web, App, HttpResponse};
use base64::{engine::general_purpose, Engine as _};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use serde_json::{json, Value};

use oauth2_actix::actors::TokenActorPool;
use oauth2_actix::handlers::wellknown::OidcConfig;
use oauth2_core::{Client, OAuth2Error, User};
use oauth2_observability::Metrics;

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

fn s256_challenge(verifier: &str) -> String {
    use sha2::{Digest, Sha256};
    let hash = Sha256::digest(verifier.as_bytes());
    general_purpose::URL_SAFE_NO_PAD.encode(hash)
}

/// Build an unsigned (alg=none) JAR.
/// Used only with public clients (token_endpoint_auth_method = "none").
fn make_unsigned_jar(claims: Value) -> String {
    let header_json = r#"{"alg":"none","typ":"JWT"}"#;
    let header_b64 = general_purpose::URL_SAFE_NO_PAD.encode(header_json.as_bytes());
    let payload_b64 =
        general_purpose::URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap().as_slice());
    // alg=none → empty signature part
    format!("{header_b64}.{payload_b64}.")
}

/// Build an HS256-signed JAR.
/// Claims must include `iss` (= client_id), `exp`, and `aud` (= authorization endpoint URL).
fn make_hs256_jar(claims: Value, secret: &str) -> String {
    let header = Header::new(Algorithm::HS256);
    let key = EncodingKey::from_secret(secret.as_bytes());
    encode(&header, &claims, &key).unwrap()
}

/// Extract a named key from the URL fragment (`#key=value&…`).
/// Values may be percent-encoded; this function returns the raw encoded string since
/// we only need to confirm presence in most tests.
fn extract_fragment_param(location: &str, key: &str) -> Option<String> {
    let frag = location.split('#').nth(1)?;
    for pair in frag.split('&') {
        if let Some((k, v)) = pair.split_once('=') {
            if k == key {
                return Some(v.to_string());
            }
        }
    }
    None
}

/// Extract a named key from the URL query string (`?key=value&…`).
fn extract_query_param(url: &str, key: &str) -> Option<String> {
    let (_base, query) = url.split_once('?')?;
    for pair in query.split('&') {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        if k == key {
            return Some(v.to_string());
        }
    }
    None
}

async fn test_set_session(session: Session) -> HttpResponse {
    session.insert("user_id", "user_123").unwrap();
    session.insert("authenticated", true).unwrap();
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

fn oidc_config() -> OidcConfig {
    OidcConfig {
        issuer: "http://localhost".to_string(),
        jwt_secret: "test_jwt_secret".to_string(),
        id_token_alg: "HS256".to_string(),
        id_token_kid: None,
        id_token_private_key_pem: None,
    }
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
        jwt_secret,
        metrics,
        oidc_config,
    )
}

/// Build a test app with session middleware (needed for the authorization_code flow).
macro_rules! session_app {
    ($token_actor:expr, $client_actor:expr, $auth_actor:expr,
     $jwt_secret:expr, $metrics:expr, $oidc_config:expr) => {
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
                .app_data(web::Data::new($jwt_secret))
                .app_data(web::Data::new($metrics))
                .app_data(web::Data::new($oidc_config))
                .app_data(web::Data::new(false))
                .service(web::scope("/oauth").route(
                    "/authorize",
                    web::get().to(oauth2_actix::handlers::oauth::authorize),
                ))
                .service(web::scope("/.well-known").route(
                    "/openid-configuration",
                    web::get().to(oauth2_actix::handlers::wellknown::openid_configuration),
                )),
        )
        .await
    };
}

/// Build a test app without session (for tests that fail before auth gate).
macro_rules! plain_app {
    ($token_actor:expr, $client_actor:expr, $auth_actor:expr,
     $jwt_secret:expr, $metrics:expr, $oidc_config:expr) => {
        test::init_service(
            App::new()
                .app_data(web::Data::new($token_actor))
                .app_data(web::Data::new($client_actor))
                .app_data(web::Data::new($auth_actor))
                .app_data(web::Data::new($jwt_secret))
                .app_data(web::Data::new($metrics))
                .app_data(web::Data::new($oidc_config))
                .app_data(web::Data::new(false))
                .service(web::scope("/oauth").route(
                    "/authorize",
                    web::get().to(oauth2_actix::handlers::oauth::authorize),
                ))
                .service(web::scope("/.well-known").route(
                    "/openid-configuration",
                    web::get().to(oauth2_actix::handlers::wellknown::openid_configuration),
                )),
        )
        .await
    };
}

/// Discovery-only app (no session, no actor pool — just OidcConfig).
macro_rules! discovery_app {
    ($oidc_config:expr) => {
        test::init_service(App::new().app_data(web::Data::new($oidc_config)).service(
            web::scope("/.well-known").route(
                "/openid-configuration",
                web::get().to(oauth2_actix::handlers::wellknown::openid_configuration),
            ),
        ))
        .await
    };
}

// ---------------------------------------------------------------------------
// §5.3 response_mode=fragment
// ---------------------------------------------------------------------------

/// OIDC Multiple Response Types §2: `response_mode=fragment` must deliver the
/// authorization code in the URL fragment rather than the query string.
#[actix_web::test]
async fn wave5_response_mode_fragment_delivers_code_in_fragment() {
    let client = Client::new(
        "client_frag".to_string(),
        "secret_frag".to_string(),
        vec!["https://cb.example/cb".to_string()],
        vec!["authorization_code".to_string()],
        "read".to_string(),
        "test".to_string(),
    );
    let (token_actor, client_actor, auth_actor, jwt_secret, metrics, oidc_config) =
        setup_context(client).await;
    let app = session_app!(
        token_actor,
        client_actor,
        auth_actor,
        jwt_secret,
        metrics,
        oidc_config
    );

    let login_resp = test::call_service(
        &app,
        test::TestRequest::get().uri("/test/login").to_request(),
    )
    .await;
    let session_cookie = extract_session_cookie(&login_resp);

    let challenge = s256_challenge("verifier_frag_mode");
    let req = test::TestRequest::get()
        .uri(&format!(
            "/oauth/authorize?response_type=code&client_id=client_frag\
             &redirect_uri=https%3A%2F%2Fcb.example%2Fcb\
             &scope=read&response_mode=fragment\
             &code_challenge={challenge}&code_challenge_method=S256"
        ))
        .insert_header(("Cookie", session_cookie.as_str()))
        .to_request();
    let resp = test::call_service(&app, req).await;

    assert_eq!(resp.status(), 302, "fragment mode must still 302-redirect");
    let loc = resp
        .headers()
        .get(actix_web::http::header::LOCATION)
        .and_then(|h| h.to_str().ok())
        .expect("Location header must be set");

    assert!(
        loc.contains('#'),
        "Location must contain a fragment separator '#'"
    );
    assert!(
        extract_fragment_param(loc, "code").is_some(),
        "fragment must contain a 'code' parameter; Location: {loc}"
    );
    // Confirm the code is NOT in the query string.
    assert!(
        extract_query_param(loc, "code").is_none(),
        "code must not appear in the query string when response_mode=fragment; Location: {loc}"
    );
    // iss must be present in the fragment (RFC 9207 mix-up mitigation).
    assert!(
        extract_fragment_param(loc, "iss").is_some(),
        "fragment must include 'iss'; Location: {loc}"
    );
}

/// An unsupported response_mode must be rejected with an invalid_request error.
#[actix_web::test]
async fn wave5_unsupported_response_mode_is_rejected() {
    let client = Client::new(
        "client_bad_mode".to_string(),
        "secret_bad_mode".to_string(),
        vec!["https://cb.example/cb".to_string()],
        vec!["authorization_code".to_string()],
        "read".to_string(),
        "test".to_string(),
    );
    let (token_actor, client_actor, auth_actor, jwt_secret, metrics, oidc_config) =
        setup_context(client).await;
    let app = plain_app!(
        token_actor,
        client_actor,
        auth_actor,
        jwt_secret,
        metrics,
        oidc_config
    );

    let challenge = s256_challenge("verifier_bad_mode");
    let req = test::TestRequest::get()
        .uri(&format!(
            "/oauth/authorize?response_type=code&client_id=client_bad_mode\
             &redirect_uri=https%3A%2F%2Fcb.example%2Fcb\
             &scope=read&response_mode=token\
             &code_challenge={challenge}&code_challenge_method=S256"
        ))
        .to_request();
    let resp = test::call_service(&app, req).await;

    assert_eq!(resp.status(), 400, "unsupported response_mode must be 400");
    let body: OAuth2Error = test::read_body_json(resp).await;
    assert_eq!(body.error, "invalid_request");
}

// ---------------------------------------------------------------------------
// §5.2 OIDC Hybrid Flow: response_type=code id_token
// ---------------------------------------------------------------------------

/// OIDC Core §3.3: A `code id_token` hybrid request must return both an
/// authorization code and an id_token in the fragment.
#[actix_web::test]
async fn wave5_hybrid_code_id_token_delivers_both_in_fragment() {
    let client = Client::new(
        "client_hybrid".to_string(),
        "secret_hybrid".to_string(),
        vec!["https://cb.example/cb".to_string()],
        vec!["authorization_code".to_string()],
        "openid read".to_string(),
        "test".to_string(),
    );
    let (token_actor, client_actor, auth_actor, jwt_secret, metrics, oidc_config) =
        setup_context(client).await;
    let app = session_app!(
        token_actor,
        client_actor,
        auth_actor,
        jwt_secret,
        metrics,
        oidc_config
    );

    let login_resp = test::call_service(
        &app,
        test::TestRequest::get().uri("/test/login").to_request(),
    )
    .await;
    let session_cookie = extract_session_cookie(&login_resp);

    let challenge = s256_challenge("verifier_hybrid_flow");
    // response_type "code id_token" must be percent-encoded in the URL.
    let req = test::TestRequest::get()
        .uri(&format!(
            "/oauth/authorize?response_type=code%20id_token&client_id=client_hybrid\
             &redirect_uri=https%3A%2F%2Fcb.example%2Fcb\
             &scope=openid%20read&nonce=abc123\
             &code_challenge={challenge}&code_challenge_method=S256"
        ))
        .insert_header(("Cookie", session_cookie.as_str()))
        .to_request();
    let resp = test::call_service(&app, req).await;

    assert_eq!(resp.status(), 302, "hybrid flow must 302-redirect");
    let loc = resp
        .headers()
        .get(actix_web::http::header::LOCATION)
        .and_then(|h| h.to_str().ok())
        .expect("Location header must be set");

    // Default response_mode for hybrid is "fragment" (OIDC Core §3.3.2.3).
    assert!(
        loc.contains('#'),
        "hybrid flow must use fragment delivery; Location: {loc}"
    );
    assert!(
        extract_fragment_param(loc, "code").is_some(),
        "fragment must contain 'code'; Location: {loc}"
    );
    assert!(
        extract_fragment_param(loc, "id_token").is_some(),
        "fragment must contain 'id_token' for code id_token hybrid flow; Location: {loc}"
    );
}

/// OIDC Core §3.3: When scope does NOT include "openid", a `code id_token`
/// request must NOT include an id_token in the response (no openid scope → no id_token).
#[actix_web::test]
async fn wave5_hybrid_no_openid_scope_omits_id_token() {
    let client = Client::new(
        "client_hybrid_noidc".to_string(),
        "secret_hybrid_noidc".to_string(),
        vec!["https://cb.example/cb".to_string()],
        vec!["authorization_code".to_string()],
        "read".to_string(),
        "test".to_string(),
    );
    let (token_actor, client_actor, auth_actor, jwt_secret, metrics, oidc_config) =
        setup_context(client).await;
    let app = session_app!(
        token_actor,
        client_actor,
        auth_actor,
        jwt_secret,
        metrics,
        oidc_config
    );

    let login_resp = test::call_service(
        &app,
        test::TestRequest::get().uri("/test/login").to_request(),
    )
    .await;
    let session_cookie = extract_session_cookie(&login_resp);

    let challenge = s256_challenge("verifier_hybrid_noidc");
    let req = test::TestRequest::get()
        .uri(&format!(
            "/oauth/authorize?response_type=code%20id_token&client_id=client_hybrid_noidc\
             &redirect_uri=https%3A%2F%2Fcb.example%2Fcb\
             &scope=read&nonce=xyz\
             &code_challenge={challenge}&code_challenge_method=S256"
        ))
        .insert_header(("Cookie", session_cookie.as_str()))
        .to_request();
    let resp = test::call_service(&app, req).await;

    assert_eq!(resp.status(), 302, "should still redirect successfully");
    let loc = resp
        .headers()
        .get(actix_web::http::header::LOCATION)
        .and_then(|h| h.to_str().ok())
        .expect("Location header");

    // code must still be delivered in the fragment.
    assert!(
        extract_fragment_param(loc, "code").is_some(),
        "code must be in fragment; Location: {loc}"
    );
    // id_token must be absent since openid scope was not requested.
    assert!(
        extract_fragment_param(loc, "id_token").is_none(),
        "id_token must not appear without openid scope; Location: {loc}"
    );
}

// ---------------------------------------------------------------------------
// §5.1 JAR (RFC 9101): inline request parameter
// ---------------------------------------------------------------------------

/// RFC 9101 §4: A public client (token_endpoint_auth_method=none) may send an
/// unsigned (alg=none) JAR.  The JWT payload claims override the query parameters.
#[actix_web::test]
async fn wave5_jar_public_client_unsigned_succeeds() {
    let mut client = Client::new(
        "client_jar_pub".to_string(),
        "".to_string(), // public — no secret
        vec!["https://cb.example/cb".to_string()],
        vec!["authorization_code".to_string()],
        "openid read".to_string(),
        "test".to_string(),
    );
    client.token_endpoint_auth_method = "none".to_string();

    let (token_actor, client_actor, auth_actor, jwt_secret, metrics, oidc_config) =
        setup_context(client).await;
    let app = session_app!(
        token_actor,
        client_actor,
        auth_actor,
        jwt_secret,
        metrics,
        oidc_config
    );

    let login_resp = test::call_service(
        &app,
        test::TestRequest::get().uri("/test/login").to_request(),
    )
    .await;
    let session_cookie = extract_session_cookie(&login_resp);

    let challenge = s256_challenge("verifier_jar_pub");
    // Build an unsigned JAR whose payload overrides scope and nonce.
    let jar_claims = json!({
        "redirect_uri": "https://cb.example/cb",
        "scope": "openid read",
        "nonce": "jar_nonce_pub",
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    });
    let jar = make_unsigned_jar(jar_claims);

    let req = test::TestRequest::get()
        .uri(&format!(
            "/oauth/authorize?response_type=code&client_id=client_jar_pub\
             &redirect_uri=https%3A%2F%2Fcb.example%2Fcb\
             &scope=read&code_challenge={challenge}&code_challenge_method=S256\
             &request={jar}"
        ))
        .insert_header(("Cookie", session_cookie.as_str()))
        .to_request();
    let resp = test::call_service(&app, req).await;

    assert_eq!(resp.status(), 302, "JAR public client must 302-redirect");
    let loc = resp
        .headers()
        .get(actix_web::http::header::LOCATION)
        .and_then(|h| h.to_str().ok())
        .expect("Location header");
    assert!(
        extract_query_param(loc, "code").is_some(),
        "response must contain a code; Location: {loc}"
    );
}

/// RFC 9101 §4: A confidential client may sign the JAR with HS256 using its
/// client_secret.  The payload claims must include `iss` (= client_id), `exp`,
/// and `aud` (= authorization endpoint URL).
#[actix_web::test]
async fn wave5_jar_confidential_client_hs256_succeeds() {
    let client_secret = "secret_jar_hs256";
    let client = Client::new(
        "client_jar_hs".to_string(),
        client_secret.to_string(),
        vec!["https://cb.example/cb".to_string()],
        vec!["authorization_code".to_string()],
        "openid read".to_string(),
        "test".to_string(),
    );
    // Default token_endpoint_auth_method = "client_secret_basic".
    let (token_actor, client_actor, auth_actor, jwt_secret, metrics, oidc_config) =
        setup_context(client).await;
    let app = session_app!(
        token_actor,
        client_actor,
        auth_actor,
        jwt_secret,
        metrics,
        oidc_config
    );

    let login_resp = test::call_service(
        &app,
        test::TestRequest::get().uri("/test/login").to_request(),
    )
    .await;
    let session_cookie = extract_session_cookie(&login_resp);

    let challenge = s256_challenge("verifier_jar_hs");
    // The authorization endpoint URL used for `aud` must match what process_jar() builds:
    // format!("{}/oauth/authorize", oidc_config.issuer) = "http://localhost/oauth/authorize"
    let exp = chrono::Utc::now().timestamp() + 300;
    let jar_claims = json!({
        "iss": "client_jar_hs",
        "aud": "http://localhost/oauth/authorize",
        "exp": exp,
        "redirect_uri": "https://cb.example/cb",
        "scope": "openid read",
        "nonce": "jar_nonce_hs",
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    });
    let jar = make_hs256_jar(jar_claims, client_secret);

    let req = test::TestRequest::get()
        .uri(&format!(
            "/oauth/authorize?response_type=code&client_id=client_jar_hs\
             &redirect_uri=https%3A%2F%2Fcb.example%2Fcb\
             &scope=read&code_challenge={challenge}&code_challenge_method=S256\
             &request={jar}"
        ))
        .insert_header(("Cookie", session_cookie.as_str()))
        .to_request();
    let resp = test::call_service(&app, req).await;

    assert_eq!(resp.status(), 302, "JAR HS256 must 302-redirect");
    let loc = resp
        .headers()
        .get(actix_web::http::header::LOCATION)
        .and_then(|h| h.to_str().ok())
        .expect("Location header");
    assert!(
        extract_query_param(loc, "code").is_some(),
        "response must contain a code; Location: {loc}"
    );
}

/// RFC 9101 §4: A JAR with a tampered / wrong signature must be rejected.
#[actix_web::test]
async fn wave5_jar_tampered_hs256_is_rejected() {
    let client = Client::new(
        "client_jar_bad".to_string(),
        "correct_secret".to_string(),
        vec!["https://cb.example/cb".to_string()],
        vec!["authorization_code".to_string()],
        "read".to_string(),
        "test".to_string(),
    );
    let (token_actor, client_actor, auth_actor, jwt_secret, metrics, oidc_config) =
        setup_context(client).await;
    let app = plain_app!(
        token_actor,
        client_actor,
        auth_actor,
        jwt_secret,
        metrics,
        oidc_config
    );

    let challenge = s256_challenge("verifier_jar_bad");
    let exp = chrono::Utc::now().timestamp() + 300;
    let jar_claims = json!({
        "iss": "client_jar_bad",
        "aud": "http://localhost/oauth/authorize",
        "exp": exp,
        "redirect_uri": "https://cb.example/cb",
        "scope": "read",
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    });
    // Sign with the WRONG secret.
    let jar = make_hs256_jar(jar_claims, "wrong_secret");

    let req = test::TestRequest::get()
        .uri(&format!(
            "/oauth/authorize?response_type=code&client_id=client_jar_bad\
             &redirect_uri=https%3A%2F%2Fcb.example%2Fcb\
             &scope=read&code_challenge={challenge}&code_challenge_method=S256\
             &request={jar}"
        ))
        .to_request();
    let resp = test::call_service(&app, req).await;

    assert_eq!(resp.status(), 400, "tampered JAR must be rejected with 400");
    let body: OAuth2Error = test::read_body_json(resp).await;
    assert_eq!(body.error, "invalid_request");
}

// ---------------------------------------------------------------------------
// Discovery document — Phase 5 fields
// ---------------------------------------------------------------------------

/// Discovery must advertise `code id_token` as a supported response type.
#[actix_web::test]
async fn wave5_discovery_response_types_includes_code_id_token() {
    let app = discovery_app!(oidc_config());
    let req = test::TestRequest::get()
        .uri("/.well-known/openid-configuration")
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 200);
    let body: Value = test::read_body_json(resp).await;

    let types = body["response_types_supported"]
        .as_array()
        .expect("response_types_supported must be an array");
    assert!(
        types.iter().any(|v| v.as_str() == Some("code id_token")),
        "response_types_supported must include 'code id_token'; got: {types:?}"
    );
    // Plain "code" must still be present.
    assert!(
        types.iter().any(|v| v.as_str() == Some("code")),
        "response_types_supported must include 'code'; got: {types:?}"
    );
}

/// Discovery must advertise `fragment` as a supported response mode.
#[actix_web::test]
async fn wave5_discovery_response_modes_includes_fragment() {
    let app = discovery_app!(oidc_config());
    let req = test::TestRequest::get()
        .uri("/.well-known/openid-configuration")
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 200);
    let body: Value = test::read_body_json(resp).await;

    let modes = body["response_modes_supported"]
        .as_array()
        .expect("response_modes_supported must be an array");
    assert!(
        modes.iter().any(|v| v.as_str() == Some("fragment")),
        "response_modes_supported must include 'fragment'; got: {modes:?}"
    );
    assert!(
        modes.iter().any(|v| v.as_str() == Some("query")),
        "response_modes_supported must include 'query'; got: {modes:?}"
    );
    assert!(
        modes.iter().any(|v| v.as_str() == Some("form_post")),
        "response_modes_supported must include 'form_post'; got: {modes:?}"
    );
}

/// Discovery must advertise `request_parameter_supported: true` (RFC 9101).
#[actix_web::test]
async fn wave5_discovery_request_parameter_supported_is_true() {
    let app = discovery_app!(oidc_config());
    let req = test::TestRequest::get()
        .uri("/.well-known/openid-configuration")
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 200);
    let body: Value = test::read_body_json(resp).await;

    assert_eq!(
        body["request_parameter_supported"].as_bool(),
        Some(true),
        "request_parameter_supported must be true; got: {}",
        body["request_parameter_supported"]
    );
}
