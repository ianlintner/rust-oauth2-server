//! RFC 6749 — The OAuth 2.0 Authorization Framework
//!
//! Compliance tests that map directly to RFC 6749 sections.
//! See docs/compliance/RFC_COMPLIANCE.md for the full matrix.
//!
//! # Compliance metadata format
//!
//! Each `#[actix_web::test]` in this file is annotated with a structured
//! block of doc-comment tags consumed by `cargo run --bin compliance_report`
//! to produce the published compliance matrix. Format:
//!
//! ```text
//! /// RFC 6749 §3.1.2: <human-readable prose explaining what is checked>
//! ///
//! /// @rfc 6749
//! /// @section 3.1.2
//! /// @requirement <one-line normative requirement under test>
//! /// @level MUST              # RFC 2119 keyword: MUST | SHOULD | MAY
//! /// @url https://datatracker.ietf.org/doc/html/rfc6749#section-3.1.2
//! ```
//!
//! Tags must appear on contiguous `///` lines immediately preceding the
//! `#[actix_web::test]` (or `#[test]`) attribute. The extractor pairs them
//! with the test's runtime status (passed / failed / ignored) from
//! `cargo test --message-format=json` to produce Markdown, JSON, and JUnit
//! XML reports.

use actix::{Actor, Addr};
use actix_session::{storage::CookieSessionStore, Session, SessionMiddleware};
use actix_web::{cookie::Key, test, web, App, HttpResponse};

use oauth2_actix::actors::TokenActorPool;
use oauth2_actix::handlers::wellknown::OidcConfig;
use oauth2_core::{Client, OAuth2Error, TokenResponse, User};
use oauth2_observability::Metrics;

// ---------------------------------------------------------------------------
// Test helpers (mirror of security_http.rs helpers, local to this file)
// ---------------------------------------------------------------------------

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

/// Build a test app with session support (needed for authorization_code flow).
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
        .await
    };
}

/// Build a test app without session (for client_credentials, introspect, revoke).
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
        .await
    };
}

// ---------------------------------------------------------------------------
// §3.1.2 — Redirect URI
// ---------------------------------------------------------------------------

/// RFC 6749 §3.1.2: The redirect URI provided at the authorization endpoint
/// must exactly match the one registered for the client.
///
/// @rfc 6749
/// @section 3.1.2
/// @requirement Redirect URI in the authorization request must exactly match a registered redirect URI.
/// @level MUST
/// @url https://datatracker.ietf.org/doc/html/rfc6749#section-3.1.2
#[actix_web::test]
async fn rfc6749_s3_1_2_redirect_uri_must_match() {
    let client = Client::new(
        "client_redirect".to_string(),
        "secret_redirect".to_string(),
        vec!["https://good.example/cb".to_string()],
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

    let challenge = s256_challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk");
    let req = test::TestRequest::get()
        .uri(&format!(
            "/oauth/authorize?response_type=code&client_id=client_redirect\
             &redirect_uri=https%3A%2F%2Fevil.example%2Fcb\
             &scope=read&code_challenge={challenge}&code_challenge_method=S256"
        ))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 400);
    let body: OAuth2Error = test::read_body_json(resp).await;
    assert_eq!(body.error, "invalid_request");
}

// ---------------------------------------------------------------------------
// §4.1.1 — Authorization Request
// ---------------------------------------------------------------------------

/// RFC 6749 §4.1.1: `response_type` is a required parameter.
///
/// @rfc 6749
/// @section 4.1.1
/// @requirement The authorization request MUST include the `response_type` parameter.
/// @level MUST
/// @url https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.1
#[actix_web::test]
async fn rfc6749_s4_1_1_authorize_requires_response_type() {
    let client = Client::new(
        "client_rt".to_string(),
        "secret_rt".to_string(),
        vec!["https://good.example/cb".to_string()],
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

    let req = test::TestRequest::get()
        .uri("/oauth/authorize?client_id=client_rt&redirect_uri=https%3A%2F%2Fgood.example%2Fcb&scope=read")
        .to_request();
    let resp = test::call_service(&app, req).await;
    // actix-web query extractor rejects missing required fields with 400 before
    // the handler runs; the body is not OAuth2Error JSON in that path.
    assert_eq!(resp.status(), 400);
}

/// RFC 6749 §4.1.1: Unsupported `response_type` values must be rejected.
///
/// @rfc 6749
/// @section 4.1.1
/// @requirement Authorization requests with an unsupported `response_type` MUST be rejected with `unsupported_response_type` (or equivalent error).
/// @level MUST
/// @url https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.1
#[actix_web::test]
async fn rfc6749_s4_1_1_authorize_rejects_unknown_response_type() {
    let client = Client::new(
        "client_unk_rt".to_string(),
        "secret_unk_rt".to_string(),
        vec!["https://good.example/cb".to_string()],
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

    let challenge = s256_challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk");
    let req = test::TestRequest::get()
        .uri(&format!(
            "/oauth/authorize?response_type=id_token&client_id=client_unk_rt\
             &redirect_uri=https%3A%2F%2Fgood.example%2Fcb\
             &scope=read&code_challenge={challenge}&code_challenge_method=S256"
        ))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 400);
    let body: OAuth2Error = test::read_body_json(resp).await;
    assert_eq!(body.error, "invalid_request");
}

/// RFC 6749 §4.1.1: `client_id` is a required parameter.
///
/// @rfc 6749
/// @section 4.1.1
/// @requirement The authorization request MUST include the `client_id` parameter.
/// @level MUST
/// @url https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.1
#[actix_web::test]
async fn rfc6749_s4_1_1_authorize_requires_client_id() {
    let client = Client::new(
        "client_cid".to_string(),
        "secret_cid".to_string(),
        vec!["https://good.example/cb".to_string()],
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

    let challenge = s256_challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk");
    let req = test::TestRequest::get()
        .uri(&format!(
            "/oauth/authorize?response_type=code\
             &redirect_uri=https%3A%2F%2Fgood.example%2Fcb\
             &scope=read&code_challenge={challenge}&code_challenge_method=S256"
        ))
        .to_request();
    let resp = test::call_service(&app, req).await;
    // actix-web query extractor rejects missing required fields with 400 before
    // the handler runs; the body is not OAuth2Error JSON in that path.
    assert_eq!(resp.status(), 400);
}

/// RFC 6749 §4.1.1: An unknown `client_id` must be rejected.
///
/// @rfc 6749
/// @section 4.1.1
/// @requirement Authorization requests bearing an unknown `client_id` MUST be rejected.
/// @level MUST
/// @url https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.1
#[actix_web::test]
async fn rfc6749_s4_1_1_authorize_rejects_unknown_client() {
    let client = Client::new(
        "client_known".to_string(),
        "secret_known".to_string(),
        vec!["https://good.example/cb".to_string()],
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

    let challenge = s256_challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk");
    let req = test::TestRequest::get()
        .uri(&format!(
            "/oauth/authorize?response_type=code&client_id=does_not_exist\
             &redirect_uri=https%3A%2F%2Fgood.example%2Fcb\
             &scope=read&code_challenge={challenge}&code_challenge_method=S256"
        ))
        .to_request();
    let resp = test::call_service(&app, req).await;
    // Unknown client_id returns 401 invalid_client (RFC 6749 §4.1.2.1 does not
    // require 400 here; the server uses invalid_client → HTTP 401).
    assert_eq!(resp.status(), 401);
    let body: OAuth2Error = test::read_body_json(resp).await;
    assert_eq!(body.error, "invalid_client");
}

// ---------------------------------------------------------------------------
// §4.1.2 — Authorization Response
// ---------------------------------------------------------------------------

/// RFC 6749 §4.1.2: Successful authorization returns a 302 redirect containing
/// the `code` query parameter.
///
/// @rfc 6749
/// @section 4.1.2
/// @requirement A successful authorization response MUST be delivered as a redirect to the client's redirect URI with a `code` query parameter.
/// @level MUST
/// @url https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2
#[actix_web::test]
async fn rfc6749_s4_1_2_authorize_redirects_with_code() {
    let client = Client::new(
        "client_auth_code".to_string(),
        "secret_auth_code".to_string(),
        vec!["https://good.example/cb".to_string()],
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

    let challenge = s256_challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk");
    let req = test::TestRequest::get()
        .uri(&format!(
            "/oauth/authorize?response_type=code&client_id=client_auth_code\
             &redirect_uri=https%3A%2F%2Fgood.example%2Fcb\
             &scope=read&code_challenge={challenge}&code_challenge_method=S256"
        ))
        .insert_header(("Cookie", session_cookie.as_str()))
        .to_request();
    let resp = test::call_service(&app, req).await;

    assert_eq!(resp.status(), 302, "authorize must redirect on success");
    let loc = resp
        .headers()
        .get(actix_web::http::header::LOCATION)
        .and_then(|h| h.to_str().ok())
        .expect("Location header");
    assert!(
        extract_query_param(loc, "code").is_some(),
        "redirect must contain a `code` parameter"
    );
}

/// RFC 6749 §4.1.2: The `state` parameter, when present, must be included
/// verbatim in the redirect response.
///
/// @rfc 6749
/// @section 4.1.2
/// @requirement If the client includes a `state` parameter, the authorization server MUST include the exact value received in the response.
/// @level MUST
/// @url https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2
#[actix_web::test]
async fn rfc6749_s4_1_2_state_is_echoed_in_redirect() {
    let client = Client::new(
        "client_state".to_string(),
        "secret_state".to_string(),
        vec!["https://good.example/cb".to_string()],
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

    let challenge = s256_challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk");
    let state_value = "my_opaque_state_xyz";
    let req = test::TestRequest::get()
        .uri(&format!(
            "/oauth/authorize?response_type=code&client_id=client_state\
             &redirect_uri=https%3A%2F%2Fgood.example%2Fcb\
             &scope=read&state={state_value}\
             &code_challenge={challenge}&code_challenge_method=S256"
        ))
        .insert_header(("Cookie", session_cookie.as_str()))
        .to_request();
    let resp = test::call_service(&app, req).await;

    assert_eq!(resp.status(), 302);
    let loc = resp
        .headers()
        .get(actix_web::http::header::LOCATION)
        .and_then(|h| h.to_str().ok())
        .expect("Location header");
    let echoed_state = extract_query_param(loc, "state").expect("state echoed in redirect");
    assert_eq!(echoed_state, state_value);
}

// ---------------------------------------------------------------------------
// §4.1.3 — Token Request
// ---------------------------------------------------------------------------

/// RFC 6749 §4.1.3: `grant_type` is a required parameter.
///
/// @rfc 6749
/// @section 4.1.3
/// @requirement Token requests MUST include the `grant_type` parameter.
/// @level MUST
/// @url https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.3
#[actix_web::test]
async fn rfc6749_s4_1_3_token_requires_grant_type() {
    let client = Client::new(
        "client_gt".to_string(),
        "secret_gt".to_string(),
        vec!["https://good.example/cb".to_string()],
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

    let req = test::TestRequest::post()
        .uri("/oauth/token")
        .set_form([
            ("client_id", "client_gt"),
            ("client_secret", "secret_gt"),
            ("code", "some_code"),
        ])
        .to_request();
    let resp = test::call_service(&app, req).await;
    // Missing grant_type → 400 or 401
    assert!(
        resp.status().is_client_error(),
        "missing grant_type must return 4xx, got {}",
        resp.status()
    );
}

/// RFC 6749 §4.1.3: Unsupported `grant_type` values must be rejected.
///
/// @rfc 6749
/// @section 4.1.3
/// @requirement Token requests with an unsupported `grant_type` MUST be rejected with `unsupported_grant_type`.
/// @level MUST
/// @url https://datatracker.ietf.org/doc/html/rfc6749#section-5.2
#[actix_web::test]
async fn rfc6749_s4_1_3_token_rejects_unsupported_grant_type() {
    let client = Client::new(
        "client_supp_gt".to_string(),
        "secret_supp_gt".to_string(),
        vec!["https://good.example/cb".to_string()],
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

    let req = test::TestRequest::post()
        .uri("/oauth/token")
        .set_form([
            ("grant_type", "password"),
            ("client_id", "client_supp_gt"),
            ("client_secret", "secret_supp_gt"),
            ("username", "user"),
            ("password", "pass"),
        ])
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert!(
        resp.status().is_client_error(),
        "unsupported grant_type must return 4xx, got {}",
        resp.status()
    );
    let body: OAuth2Error = test::read_body_json(resp).await;
    assert_eq!(body.error, "unsupported_grant_type");
}

/// RFC 6749 §4.1.3: A client must not be able to exchange a code that was
/// issued to a different client.
///
/// @rfc 6749
/// @section 4.1.3
/// @requirement The authorization server MUST ensure that an authorization code is bound to the client identifier it was issued to.
/// @level MUST
/// @url https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.3
#[actix_web::test]
async fn rfc6749_s4_1_3_token_rejects_wrong_client_for_code() {
    let client_a = Client::new(
        "client_code_a".to_string(),
        "secret_code_a".to_string(),
        vec!["https://good.example/cb".to_string()],
        vec!["authorization_code".to_string()],
        "read".to_string(),
        "test".to_string(),
    );
    let client_b = Client::new(
        "client_code_b".to_string(),
        "secret_code_b".to_string(),
        vec!["https://good.example/cb".to_string()],
        vec!["authorization_code".to_string()],
        "read".to_string(),
        "test".to_string(),
    );

    // Build app with both clients registered.
    let storage = oauth2_storage_factory::create_storage("sqlite::memory:")
        .await
        .expect("create storage");
    storage.init().await.expect("init storage");
    storage.save_client(&client_a).await.expect("save client_a");
    storage.save_client(&client_b).await.expect("save client_b");
    let now = chrono::Utc::now();
    let user = User {
        id: "user_123".to_string(),
        username: "user_123".to_string(),
        password_hash: "x".to_string(),
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

    let app = session_app!(
        token_pool,
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

    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let challenge = s256_challenge(verifier);

    // Issue a code for client_a.
    let req = test::TestRequest::get()
        .uri(&format!(
            "/oauth/authorize?response_type=code&client_id=client_code_a\
             &redirect_uri=https%3A%2F%2Fgood.example%2Fcb\
             &scope=read&code_challenge={challenge}&code_challenge_method=S256"
        ))
        .insert_header(("Cookie", session_cookie.as_str()))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 302);
    let loc = resp
        .headers()
        .get(actix_web::http::header::LOCATION)
        .and_then(|h| h.to_str().ok())
        .unwrap();
    let code = extract_query_param(loc, "code").expect("code");

    // client_b tries to exchange client_a's code — must fail.
    let req = test::TestRequest::post()
        .uri("/oauth/token")
        .set_form([
            ("grant_type", "authorization_code"),
            ("client_id", "client_code_b"),
            ("client_secret", "secret_code_b"),
            ("code", code.as_str()),
            ("redirect_uri", "https://good.example/cb"),
            ("code_verifier", verifier),
        ])
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert!(
        resp.status().is_client_error(),
        "wrong client must be rejected, got {}",
        resp.status()
    );
    let body: OAuth2Error = test::read_body_json(resp).await;
    assert_eq!(body.error, "invalid_grant");
}

// ---------------------------------------------------------------------------
// §4.4.2 — Client Credentials Grant
// ---------------------------------------------------------------------------

/// RFC 6749 §4.4.2: Successful client credentials grant returns an access token.
///
/// @rfc 6749
/// @section 4.4.2
/// @requirement A successful client credentials grant MUST return an access token in the token response body.
/// @level MUST
/// @url https://datatracker.ietf.org/doc/html/rfc6749#section-4.4.2
#[actix_web::test]
async fn rfc6749_s4_4_2_client_credentials_returns_access_token() {
    let client = Client::new(
        "client_cc_ok".to_string(),
        "secret_cc_ok".to_string(),
        vec!["https://unused.example/cb".to_string()],
        vec!["client_credentials".to_string()],
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

    let req = test::TestRequest::post()
        .uri("/oauth/token")
        .set_form([
            ("grant_type", "client_credentials"),
            ("client_id", "client_cc_ok"),
            ("client_secret", "secret_cc_ok"),
            ("scope", "read"),
        ])
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 200);
    let body: TokenResponse = test::read_body_json(resp).await;
    assert!(
        !body.access_token.is_empty(),
        "access_token must be present"
    );
}

/// RFC 6749 §4.4.3: Invalid client credentials → `invalid_client` (401).
///
/// @rfc 6749
/// @section 4.4.3
/// @requirement Invalid client authentication on the token endpoint MUST be rejected with `invalid_client`.
/// @level MUST
/// @url https://datatracker.ietf.org/doc/html/rfc6749#section-5.2
#[actix_web::test]
async fn rfc6749_s4_4_3_client_credentials_rejects_invalid_client() {
    let client = Client::new(
        "client_cc_bad".to_string(),
        "secret_cc_bad".to_string(),
        vec!["https://unused.example/cb".to_string()],
        vec!["client_credentials".to_string()],
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

    let req = test::TestRequest::post()
        .uri("/oauth/token")
        .set_form([
            ("grant_type", "client_credentials"),
            ("client_id", "client_cc_bad"),
            ("client_secret", "wrong_secret"),
            ("scope", "read"),
        ])
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 401);
    let body: OAuth2Error = test::read_body_json(resp).await;
    assert_eq!(body.error, "invalid_client");
}

// ---------------------------------------------------------------------------
// §2.3 — Client Authentication
// ---------------------------------------------------------------------------

/// RFC 6749 §2.3.1: Client credentials may be sent in an HTTP Basic
/// Authorization header.
///
/// @rfc 6749
/// @section 2.3.1
/// @requirement The authorization server MUST support HTTP Basic authentication for clients with a client password.
/// @level MUST
/// @url https://datatracker.ietf.org/doc/html/rfc6749#section-2.3.1
#[actix_web::test]
async fn rfc6749_s2_3_client_auth_via_basic_header() {
    let client = Client::new(
        "client_basic".to_string(),
        "secret_basic".to_string(),
        vec!["https://unused.example/cb".to_string()],
        vec!["client_credentials".to_string()],
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

    let req = test::TestRequest::post()
        .uri("/oauth/token")
        .insert_header((
            "Authorization",
            basic_auth_header("client_basic", "secret_basic"),
        ))
        .set_form([("grant_type", "client_credentials"), ("scope", "read")])
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 200);
    let body: TokenResponse = test::read_body_json(resp).await;
    assert!(!body.access_token.is_empty());
}

/// RFC 6749 §2.3.1: Client credentials may also be sent as request body
/// parameters (`client_id` + `client_secret`).
///
/// @rfc 6749
/// @section 2.3.1
/// @requirement Client credentials MAY be included in the request body using `client_id` and `client_secret` parameters.
/// @level MAY
/// @url https://datatracker.ietf.org/doc/html/rfc6749#section-2.3.1
#[actix_web::test]
async fn rfc6749_s2_3_client_auth_via_post_params() {
    let client = Client::new(
        "client_post_auth".to_string(),
        "secret_post_auth".to_string(),
        vec!["https://unused.example/cb".to_string()],
        vec!["client_credentials".to_string()],
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

    let req = test::TestRequest::post()
        .uri("/oauth/token")
        .set_form([
            ("grant_type", "client_credentials"),
            ("client_id", "client_post_auth"),
            ("client_secret", "secret_post_auth"),
            ("scope", "read"),
        ])
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 200);
    let body: TokenResponse = test::read_body_json(resp).await;
    assert!(!body.access_token.is_empty());
}

// ---------------------------------------------------------------------------
// §5 — Token Response
// ---------------------------------------------------------------------------

/// RFC 6749 §5.1: Successful token response must include `token_type` (bearer)
/// and a non-empty `access_token`.
///
/// @rfc 6749
/// @section 5.1
/// @requirement Successful token responses MUST include the `access_token` and `token_type` fields.
/// @level MUST
/// @url https://datatracker.ietf.org/doc/html/rfc6749#section-5.1
#[actix_web::test]
async fn rfc6749_s5_1_token_response_has_required_fields() {
    let client = Client::new(
        "client_resp_fields".to_string(),
        "secret_resp_fields".to_string(),
        vec!["https://unused.example/cb".to_string()],
        vec!["client_credentials".to_string()],
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

    let req = test::TestRequest::post()
        .uri("/oauth/token")
        .set_form([
            ("grant_type", "client_credentials"),
            ("client_id", "client_resp_fields"),
            ("client_secret", "secret_resp_fields"),
            ("scope", "read"),
        ])
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 200);

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert!(
        body.get("access_token").and_then(|v| v.as_str()).is_some(),
        "access_token must be present"
    );
    let token_type = body
        .get("token_type")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    assert!(
        token_type.eq_ignore_ascii_case("bearer"),
        "token_type must be 'bearer', got '{token_type}'"
    );
}

/// RFC 6749 §5.2: Token response must include `Cache-Control: no-store` and
/// `Pragma: no-cache` to prevent caching of sensitive tokens.
///
/// @rfc 6749
/// @section 5.1
/// @requirement Token endpoint responses MUST include `Cache-Control: no-store` and `Pragma: no-cache` to prevent caching of sensitive credentials.
/// @level MUST
/// @url https://datatracker.ietf.org/doc/html/rfc6749#section-5.1
#[actix_web::test]
async fn rfc6749_s5_2_token_response_no_cache_headers() {
    let client = Client::new(
        "client_cache_hdr".to_string(),
        "secret_cache_hdr".to_string(),
        vec!["https://unused.example/cb".to_string()],
        vec!["client_credentials".to_string()],
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

    let req = test::TestRequest::post()
        .uri("/oauth/token")
        .set_form([
            ("grant_type", "client_credentials"),
            ("client_id", "client_cache_hdr"),
            ("client_secret", "secret_cache_hdr"),
            ("scope", "read"),
        ])
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 200);

    let cache_control = resp
        .headers()
        .get(actix_web::http::header::CACHE_CONTROL)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");
    assert!(
        cache_control.contains("no-store"),
        "Cache-Control must include no-store, got '{cache_control}'"
    );

    let pragma = resp
        .headers()
        .get(actix_web::http::header::PRAGMA)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");
    assert!(
        pragma.contains("no-cache"),
        "Pragma must include no-cache, got '{pragma}'"
    );
}

/// RFC 6749 §5.2: Error responses must be JSON objects with at minimum
/// an `error` string field.
///
/// @rfc 6749
/// @section 5.2
/// @requirement Error responses from the token endpoint MUST be JSON objects containing an `error` field.
/// @level MUST
/// @url https://datatracker.ietf.org/doc/html/rfc6749#section-5.2
#[actix_web::test]
async fn rfc6749_s5_2_error_response_format() {
    let client = Client::new(
        "client_err_fmt".to_string(),
        "secret_err_fmt".to_string(),
        vec!["https://unused.example/cb".to_string()],
        vec!["client_credentials".to_string()],
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

    let req = test::TestRequest::post()
        .uri("/oauth/token")
        .set_form([
            ("grant_type", "client_credentials"),
            ("client_id", "client_err_fmt"),
            ("client_secret", "wrong_secret"),
            ("scope", "read"),
        ])
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_client_error());

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert!(
        body.get("error").and_then(|v| v.as_str()).is_some(),
        "error response must have an 'error' field, got: {body}"
    );
}

// ---------------------------------------------------------------------------
// §10.3 — One-time use of authorization codes
// ---------------------------------------------------------------------------

/// RFC 6749 §10.3: An authorization code must only be usable once.
/// A second exchange with the same code must fail.
///
/// @rfc 6749
/// @section 10.5
/// @requirement Authorization codes MUST be single-use; a second redemption of the same code MUST be rejected.
/// @level MUST
/// @url https://datatracker.ietf.org/doc/html/rfc6749#section-10.5
#[actix_web::test]
async fn rfc6749_s10_3_authorization_code_single_use() {
    let client = Client::new(
        "client_single_use".to_string(),
        "secret_single_use".to_string(),
        vec!["https://good.example/cb".to_string()],
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

    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let challenge = s256_challenge(verifier);

    let req = test::TestRequest::get()
        .uri(&format!(
            "/oauth/authorize?response_type=code&client_id=client_single_use\
             &redirect_uri=https%3A%2F%2Fgood.example%2Fcb\
             &scope=read&code_challenge={challenge}&code_challenge_method=S256"
        ))
        .insert_header(("Cookie", session_cookie.as_str()))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 302);
    let loc = resp
        .headers()
        .get(actix_web::http::header::LOCATION)
        .and_then(|h| h.to_str().ok())
        .unwrap();
    let code = extract_query_param(loc, "code").expect("code");

    // First exchange — must succeed.
    let req = test::TestRequest::post()
        .uri("/oauth/token")
        .set_form([
            ("grant_type", "authorization_code"),
            ("client_id", "client_single_use"),
            ("client_secret", "secret_single_use"),
            ("code", code.as_str()),
            ("redirect_uri", "https://good.example/cb"),
            ("code_verifier", verifier),
        ])
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success(), "first exchange must succeed");

    // Second exchange — must fail.
    let req = test::TestRequest::post()
        .uri("/oauth/token")
        .set_form([
            ("grant_type", "authorization_code"),
            ("client_id", "client_single_use"),
            ("client_secret", "secret_single_use"),
            ("code", code.as_str()),
            ("redirect_uri", "https://good.example/cb"),
            ("code_verifier", verifier),
        ])
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(
        resp.status(),
        400,
        "second use of same code must return 400"
    );
    let body: OAuth2Error = test::read_body_json(resp).await;
    assert_eq!(body.error, "invalid_grant");
}
