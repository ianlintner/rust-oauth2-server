//! RFC 7636 — Proof Key for Code Exchange (PKCE)
//!
//! Compliance tests that map directly to RFC 7636 sections.
//! See docs/compliance/RFC_COMPLIANCE.md for the full matrix.

use actix::Actor;
use actix_session::{storage::CookieSessionStore, Session, SessionMiddleware};
use actix_web::{cookie::Key, test, web, App, HttpResponse};

use oauth2_actix::actors::TokenActorPool;
use oauth2_actix::handlers::wellknown::OidcConfig;
use oauth2_core::{Client, OAuth2Error, TokenResponse, User};
use oauth2_observability::Metrics;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn s256_challenge(verifier: &str) -> String {
    use base64::{engine::general_purpose, Engine as _};
    use sha2::{Digest, Sha256};
    let hash = Sha256::digest(verifier.as_bytes());
    general_purpose::URL_SAFE_NO_PAD.encode(hash)
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

async fn setup_context(
    client: Client,
) -> (
    TokenActorPool,
    actix::Addr<oauth2_actix::actors::ClientActor>,
    actix::Addr<oauth2_actix::actors::AuthActor>,
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

macro_rules! get_code_with_pkce {
    ($app:expr, $client_id:expr, $challenge:expr, $method:expr) => {{
        let login_resp = test::call_service(
            &$app,
            test::TestRequest::get().uri("/test/login").to_request(),
        )
        .await;
        let session_cookie = extract_session_cookie(&login_resp);
        let req = test::TestRequest::get()
            .uri(&format!(
                "/oauth/authorize?response_type=code&client_id={}\
                 &redirect_uri=https%3A%2F%2Fgood.example%2Fcb\
                 &scope=read&code_challenge={}&code_challenge_method={}",
                $client_id, $challenge, $method
            ))
            .insert_header(("Cookie", session_cookie.as_str()))
            .to_request();
        let resp = test::call_service(&$app, req).await;
        assert_eq!(resp.status(), 302, "authorize should succeed");
        let loc = resp
            .headers()
            .get(actix_web::http::header::LOCATION)
            .and_then(|h: &actix_web::http::header::HeaderValue| h.to_str().ok())
            .unwrap()
            .to_string();
        let code = extract_query_param(&loc, "code").expect("code in redirect");
        (code, session_cookie)
    }};
}

macro_rules! app {
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
                        ),
                ),
        )
        .await
    };
}

// ---------------------------------------------------------------------------
// §4.1 — Client Creates a Code Verifier
// ---------------------------------------------------------------------------

/// RFC 7636 §4.1 + §4.3: PKCE is required for public authorization-code
/// clients; an authorize request without a code_challenge must be rejected.
///
/// @rfc 7636
/// @section 4.1
/// @requirement Public clients using authorization_code must include code_challenge in the authorize request.
/// @level MUST
/// @url https://datatracker.ietf.org/doc/html/rfc7636#section-4.1
#[actix_web::test]
async fn rfc7636_s4_1_pkce_required_for_authorization_code() {
    let client = Client::new(
        "client_pkce_req".to_string(),
        "secret_pkce_req".to_string(),
        vec!["https://good.example/cb".to_string()],
        vec!["authorization_code".to_string()],
        "read".to_string(),
        "test".to_string(),
    );
    let (token_actor, client_actor, auth_actor, jwt_secret, metrics, oidc_config) =
        setup_context(client).await;
    let app = app!(
        token_actor,
        client_actor,
        auth_actor,
        jwt_secret,
        metrics,
        oidc_config
    );

    // No session needed: expect a rejection (4xx) even before the user logs in.
    let req = test::TestRequest::get()
        .uri(
            "/oauth/authorize?response_type=code&client_id=client_pkce_req\
             &redirect_uri=https%3A%2F%2Fgood.example%2Fcb&scope=read",
        )
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 400, "missing PKCE challenge must return 400");
    let body: OAuth2Error = test::read_body_json(resp).await;
    assert!(
        body.error == "invalid_request" || body.error == "pkce_required",
        "expected invalid_request or pkce_required, got '{}'",
        body.error
    );
}

/// RFC 7636 §4.1: `code_verifier` minimum length is 43 characters (ASCII
/// unreserved characters).  Shorter verifiers must be rejected at token exchange.
///
/// @rfc 7636
/// @section 4.1
/// @requirement code_verifier shorter than 43 characters must be rejected.
/// @level MUST
/// @url https://datatracker.ietf.org/doc/html/rfc7636#section-4.1
#[actix_web::test]
async fn rfc7636_s4_1_verifier_min_length_43() {
    let client = Client::new(
        "client_verifier_min".to_string(),
        "secret_verifier_min".to_string(),
        vec!["https://good.example/cb".to_string()],
        vec!["authorization_code".to_string()],
        "read".to_string(),
        "test".to_string(),
    );
    let (token_actor, client_actor, auth_actor, jwt_secret, metrics, oidc_config) =
        setup_context(client).await;
    let app = app!(
        token_actor,
        client_actor,
        auth_actor,
        jwt_secret,
        metrics,
        oidc_config
    );

    // Use a valid 43-char verifier to get a code, then exchange with a short one.
    let good_verifier = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"; // exactly 43 chars
    let short_verifier = "AAAAAAA"; // 7 chars — too short
    let challenge = s256_challenge(good_verifier);

    let (code, _) = get_code_with_pkce!(app, "client_verifier_min", &challenge, "S256");

    let req = test::TestRequest::post()
        .uri("/oauth/token")
        .set_form([
            ("grant_type", "authorization_code"),
            ("client_id", "client_verifier_min"),
            ("client_secret", "secret_verifier_min"),
            ("code", code.as_str()),
            ("redirect_uri", "https://good.example/cb"),
            ("code_verifier", short_verifier),
        ])
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert!(
        resp.status().is_client_error(),
        "short verifier must be rejected, got {}",
        resp.status()
    );
}

/// RFC 7636 §4.1: `code_verifier` maximum length is 128 characters.
/// Verifiers exceeding this limit must be rejected.
///
/// @rfc 7636
/// @section 4.1
/// @requirement code_verifier longer than 128 characters must be rejected.
/// @level MUST
/// @url https://datatracker.ietf.org/doc/html/rfc7636#section-4.1
#[actix_web::test]
async fn rfc7636_s4_1_verifier_max_length_128() {
    let client = Client::new(
        "client_verifier_max".to_string(),
        "secret_verifier_max".to_string(),
        vec!["https://good.example/cb".to_string()],
        vec!["authorization_code".to_string()],
        "read".to_string(),
        "test".to_string(),
    );
    let (token_actor, client_actor, auth_actor, jwt_secret, metrics, oidc_config) =
        setup_context(client).await;
    let app = app!(
        token_actor,
        client_actor,
        auth_actor,
        jwt_secret,
        metrics,
        oidc_config
    );

    let good_verifier = "A".repeat(43);
    let long_verifier = "A".repeat(129); // 129 chars — too long
    let challenge = s256_challenge(&good_verifier);

    let (code, _) = get_code_with_pkce!(app, "client_verifier_max", &challenge, "S256");

    let req = test::TestRequest::post()
        .uri("/oauth/token")
        .set_form([
            ("grant_type", "authorization_code"),
            ("client_id", "client_verifier_max"),
            ("client_secret", "secret_verifier_max"),
            ("code", code.as_str()),
            ("redirect_uri", "https://good.example/cb"),
            ("code_verifier", long_verifier.as_str()),
        ])
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert!(
        resp.status().is_client_error(),
        "verifier >128 chars must be rejected, got {}",
        resp.status()
    );
}

// ---------------------------------------------------------------------------
// §4.2 — Client Creates the Code Challenge
// ---------------------------------------------------------------------------

/// RFC 7636 §4.2: The `S256` code challenge method must be accepted.
///
/// @rfc 7636
/// @section 4.2
/// @requirement Servers must support the S256 code_challenge_method.
/// @level MUST
/// @url https://datatracker.ietf.org/doc/html/rfc7636#section-4.2
#[actix_web::test]
async fn rfc7636_s4_2_s256_challenge_method_is_accepted() {
    let client = Client::new(
        "client_s256_ok".to_string(),
        "secret_s256_ok".to_string(),
        vec!["https://good.example/cb".to_string()],
        vec!["authorization_code".to_string()],
        "read".to_string(),
        "test".to_string(),
    );
    let (token_actor, client_actor, auth_actor, jwt_secret, metrics, oidc_config) =
        setup_context(client).await;
    let app = app!(
        token_actor,
        client_actor,
        auth_actor,
        jwt_secret,
        metrics,
        oidc_config
    );

    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let challenge = s256_challenge(verifier);
    let (code, _) = get_code_with_pkce!(app, "client_s256_ok", &challenge, "S256");

    let req = test::TestRequest::post()
        .uri("/oauth/token")
        .set_form([
            ("grant_type", "authorization_code"),
            ("client_id", "client_s256_ok"),
            ("client_secret", "secret_s256_ok"),
            ("code", code.as_str()),
            ("redirect_uri", "https://good.example/cb"),
            ("code_verifier", verifier),
        ])
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 200, "S256 PKCE exchange must succeed");
    let body: TokenResponse = test::read_body_json(resp).await;
    assert!(!body.access_token.is_empty());
}

/// RFC 7636 §4.2: The `plain` code challenge method must NOT be accepted
/// (this server enforces S256-only per best practice).
///
/// @rfc 7636
/// @section 4.2
/// @requirement The plain code_challenge_method must be rejected (S256-only enforcement).
/// @level MUST
/// @url https://datatracker.ietf.org/doc/html/rfc7636#section-4.2
#[actix_web::test]
async fn rfc7636_s4_2_plain_method_is_rejected() {
    let client = Client::new(
        "client_plain_rej".to_string(),
        "secret_plain_rej".to_string(),
        vec!["https://good.example/cb".to_string()],
        vec!["authorization_code".to_string()],
        "read".to_string(),
        "test".to_string(),
    );
    let (token_actor, client_actor, auth_actor, jwt_secret, metrics, oidc_config) =
        setup_context(client).await;
    let app = app!(
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
    let req = test::TestRequest::get()
        .uri(&format!(
            "/oauth/authorize?response_type=code&client_id=client_plain_rej\
             &redirect_uri=https%3A%2F%2Fgood.example%2Fcb\
             &scope=read&code_challenge={verifier}&code_challenge_method=plain"
        ))
        .insert_header(("Cookie", session_cookie.as_str()))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(
        resp.status(),
        400,
        "`plain` method must be rejected with 400"
    );
    let body: OAuth2Error = test::read_body_json(resp).await;
    assert!(
        body.error == "invalid_request" || body.error == "invalid_code_challenge_method",
        "expected invalid_request or invalid_code_challenge_method, got '{}'",
        body.error
    );
}

/// RFC 7636 §4.2: Providing a `code_challenge_method` without a
/// `code_challenge` must be rejected.
///
/// @rfc 7636
/// @section 4.2
/// @requirement code_challenge_method without code_challenge must be rejected.
/// @level MUST
/// @url https://datatracker.ietf.org/doc/html/rfc7636#section-4.2
#[actix_web::test]
async fn rfc7636_s4_2_method_without_challenge_rejected() {
    let client = Client::new(
        "client_meth_no_chal".to_string(),
        "secret_meth_no_chal".to_string(),
        vec!["https://good.example/cb".to_string()],
        vec!["authorization_code".to_string()],
        "read".to_string(),
        "test".to_string(),
    );
    let (token_actor, client_actor, auth_actor, jwt_secret, metrics, oidc_config) =
        setup_context(client).await;
    let app = app!(
        token_actor,
        client_actor,
        auth_actor,
        jwt_secret,
        metrics,
        oidc_config
    );

    let req = test::TestRequest::get()
        .uri(
            "/oauth/authorize?response_type=code&client_id=client_meth_no_chal\
             &redirect_uri=https%3A%2F%2Fgood.example%2Fcb\
             &scope=read&code_challenge_method=S256",
        )
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 400);
    let body: OAuth2Error = test::read_body_json(resp).await;
    assert_eq!(body.error, "invalid_request");
}

// ---------------------------------------------------------------------------
// §4.3 — Token Endpoint
// ---------------------------------------------------------------------------

/// RFC 7636 §4.3: Exchanging a code with the correct verifier must succeed.
///
/// @rfc 7636
/// @section 4.3
/// @requirement A correct PKCE code_verifier must be accepted at the token endpoint.
/// @level MUST
/// @url https://datatracker.ietf.org/doc/html/rfc7636#section-4.3
#[actix_web::test]
async fn rfc7636_s4_3_valid_verifier_exchanges_code() {
    let client = Client::new(
        "client_good_ver".to_string(),
        "secret_good_ver".to_string(),
        vec!["https://good.example/cb".to_string()],
        vec!["authorization_code".to_string()],
        "read".to_string(),
        "test".to_string(),
    );
    let (token_actor, client_actor, auth_actor, jwt_secret, metrics, oidc_config) =
        setup_context(client).await;
    let app = app!(
        token_actor,
        client_actor,
        auth_actor,
        jwt_secret,
        metrics,
        oidc_config
    );

    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let challenge = s256_challenge(verifier);
    let (code, _) = get_code_with_pkce!(app, "client_good_ver", &challenge, "S256");

    let req = test::TestRequest::post()
        .uri("/oauth/token")
        .set_form([
            ("grant_type", "authorization_code"),
            ("client_id", "client_good_ver"),
            ("client_secret", "secret_good_ver"),
            ("code", code.as_str()),
            ("redirect_uri", "https://good.example/cb"),
            ("code_verifier", verifier),
        ])
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 200);
    let body: TokenResponse = test::read_body_json(resp).await;
    assert!(!body.access_token.is_empty());
}

/// RFC 7636 §4.3: Exchanging a code with a wrong verifier must return
/// `invalid_grant`.
///
/// @rfc 7636
/// @section 4.3
/// @requirement An incorrect PKCE code_verifier must yield invalid_grant at the token endpoint.
/// @level MUST
/// @url https://datatracker.ietf.org/doc/html/rfc7636#section-4.3
#[actix_web::test]
async fn rfc7636_s4_3_wrong_verifier_is_rejected() {
    let client = Client::new(
        "client_bad_ver".to_string(),
        "secret_bad_ver".to_string(),
        vec!["https://good.example/cb".to_string()],
        vec!["authorization_code".to_string()],
        "read".to_string(),
        "test".to_string(),
    );
    let (token_actor, client_actor, auth_actor, jwt_secret, metrics, oidc_config) =
        setup_context(client).await;
    let app = app!(
        token_actor,
        client_actor,
        auth_actor,
        jwt_secret,
        metrics,
        oidc_config
    );

    let good_verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let wrong_verifier = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"; // 43 chars, wrong
    let challenge = s256_challenge(good_verifier);
    let (code, _) = get_code_with_pkce!(app, "client_bad_ver", &challenge, "S256");

    let req = test::TestRequest::post()
        .uri("/oauth/token")
        .set_form([
            ("grant_type", "authorization_code"),
            ("client_id", "client_bad_ver"),
            ("client_secret", "secret_bad_ver"),
            ("code", code.as_str()),
            ("redirect_uri", "https://good.example/cb"),
            ("code_verifier", wrong_verifier),
        ])
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 400);
    let body: OAuth2Error = test::read_body_json(resp).await;
    assert_eq!(body.error, "invalid_grant");
}

/// RFC 7636 §4.3: Missing verifier when a challenge was registered must
/// return `invalid_grant`.
///
/// @rfc 7636
/// @section 4.3
/// @requirement Missing code_verifier when challenge was registered must yield invalid_grant.
/// @level MUST
/// @url https://datatracker.ietf.org/doc/html/rfc7636#section-4.3
#[actix_web::test]
async fn rfc7636_s4_3_missing_verifier_rejects_pkce_code() {
    let client = Client::new(
        "client_no_ver".to_string(),
        "secret_no_ver".to_string(),
        vec!["https://good.example/cb".to_string()],
        vec!["authorization_code".to_string()],
        "read".to_string(),
        "test".to_string(),
    );
    let (token_actor, client_actor, auth_actor, jwt_secret, metrics, oidc_config) =
        setup_context(client).await;
    let app = app!(
        token_actor,
        client_actor,
        auth_actor,
        jwt_secret,
        metrics,
        oidc_config
    );

    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let challenge = s256_challenge(verifier);
    let (code, _) = get_code_with_pkce!(app, "client_no_ver", &challenge, "S256");

    let req = test::TestRequest::post()
        .uri("/oauth/token")
        .set_form([
            ("grant_type", "authorization_code"),
            ("client_id", "client_no_ver"),
            ("client_secret", "secret_no_ver"),
            ("code", code.as_str()),
            ("redirect_uri", "https://good.example/cb"),
            // no code_verifier
        ])
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert!(
        resp.status().is_client_error(),
        "missing verifier must return 4xx, got {}",
        resp.status()
    );
    let body: OAuth2Error = test::read_body_json(resp).await;
    assert_eq!(body.error, "invalid_grant");
}

/// RFC 7636 §4.3: Sending the verifier *value* as the challenge (i.e.,
/// `challenge == verifier` instead of `challenge == S256(verifier)`) must fail.
///
/// @rfc 7636
/// @section 4.3
/// @requirement Verifier-as-challenge (plain-style) misuse must be rejected when S256 is required.
/// @level MUST
/// @url https://datatracker.ietf.org/doc/html/rfc7636#section-4.3
#[actix_web::test]
async fn rfc7636_s4_3_sending_verifier_as_challenge_rejected() {
    let client = Client::new(
        "client_ver_as_chal".to_string(),
        "secret_ver_as_chal".to_string(),
        vec!["https://good.example/cb".to_string()],
        vec!["authorization_code".to_string()],
        "read".to_string(),
        "test".to_string(),
    );
    let (token_actor, client_actor, auth_actor, jwt_secret, metrics, oidc_config) =
        setup_context(client).await;
    let app = app!(
        token_actor,
        client_actor,
        auth_actor,
        jwt_secret,
        metrics,
        oidc_config
    );

    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    // Deliberately use the raw verifier as the challenge (not S256 of it).
    let (code, _) = get_code_with_pkce!(app, "client_ver_as_chal", verifier, "S256");

    // Exchange with the correct verifier — but the stored challenge is unparseable
    // as a valid S256 hash of that verifier, so validation must fail.
    let req = test::TestRequest::post()
        .uri("/oauth/token")
        .set_form([
            ("grant_type", "authorization_code"),
            ("client_id", "client_ver_as_chal"),
            ("client_secret", "secret_ver_as_chal"),
            ("code", code.as_str()),
            ("redirect_uri", "https://good.example/cb"),
            ("code_verifier", verifier),
        ])
        .to_request();
    let resp = test::call_service(&app, req).await;
    // The S256(verifier) ≠ verifier, so the comparison fails → invalid_grant.
    assert!(
        resp.status().is_client_error(),
        "verifier-as-challenge must fail, got {}",
        resp.status()
    );
}
