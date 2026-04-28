//! OpenID Connect Core 1.0 — Compliance tests
//!
//! Tests map to OpenID Connect Core 1.0, primarily §3.1 (Authorization Code
//! Flow) and §5.3 (UserInfo Endpoint).
//! See docs/compliance/RFC_COMPLIANCE.md for the full matrix.

use actix::{Actor, Addr};
use actix_session::{storage::CookieSessionStore, Session, SessionMiddleware};
use actix_web::{cookie::Key, test, web, App, HttpResponse};

use oauth2_actix::actors::TokenActorPool;
use oauth2_actix::handlers::wellknown::OidcConfig;
use oauth2_core::{Client, User};
use oauth2_observability::Metrics;

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

fn s256_challenge(verifier: &str) -> String {
    use base64::{engine::general_purpose, Engine as _};
    use sha2::{Digest, Sha256};
    let hash = Sha256::digest(verifier.as_bytes());
    general_purpose::URL_SAFE_NO_PAD.encode(hash)
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

/// Decode the payload of a compact-serialised JWT into a JSON `Value`.
fn decode_jwt_payload(token: &str) -> serde_json::Value {
    use base64::{engine::general_purpose, Engine as _};
    let parts: Vec<&str> = token.split('.').collect();
    assert_eq!(parts.len(), 3, "JWT must have header.payload.signature");
    let bytes = general_purpose::URL_SAFE_NO_PAD
        .decode(parts[1])
        .expect("base64url-decode JWT payload");
    serde_json::from_slice(&bytes).expect("parse JWT payload as JSON")
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

/// Build a test app with session, OIDC authorize/token, and userinfo endpoints.
macro_rules! oidc_app {
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
                            "/userinfo",
                            web::get().to(oauth2_actix::handlers::wellknown::userinfo),
                        ),
                ),
        )
        .await
    };
}

/// Perform the full OIDC authorization code flow (login → authorize → token).
/// Expands inline to produce `(access_token: String, id_token: Option<String>)`.
macro_rules! do_oidc_flow {
    // Without nonce
    ($app:expr, $client_id:expr, $client_secret:expr, $scope:expr) => {
        do_oidc_flow!($app, $client_id, $client_secret, $scope, "")
    };
    // With optional nonce (pass "" to omit)
    ($app:expr, $client_id:expr, $client_secret:expr, $scope:expr, $nonce:expr) => {{
        let login_resp = test::call_service(
            &$app,
            test::TestRequest::get().uri("/test/login").to_request(),
        )
        .await;
        let session_cookie = extract_session_cookie(&login_resp);

        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let challenge = s256_challenge(verifier);
        let nonce_segment: String = if $nonce.is_empty() {
            String::new()
        } else {
            format!("&nonce={}", $nonce)
        };

        let auth_resp = test::call_service(
            &$app,
            test::TestRequest::get()
                .uri(&format!(
                    "/oauth/authorize?response_type=code&client_id={}\
                     &redirect_uri=https%3A%2F%2Fgood.example%2Fcb\
                     &scope={}&code_challenge={}&code_challenge_method=S256{}",
                    $client_id, $scope, challenge, nonce_segment
                ))
                .insert_header(("Cookie", session_cookie.as_str()))
                .to_request(),
        )
        .await;
        assert_eq!(auth_resp.status(), 302, "authorize must redirect with 302");
        let loc = auth_resp
            .headers()
            .get(actix_web::http::header::LOCATION)
            .and_then(|h| h.to_str().ok())
            .expect("Location header present");
        let code = extract_query_param(loc, "code").expect("code in redirect Location");

        let token_resp = test::call_service(
            &$app,
            test::TestRequest::post()
                .uri("/oauth/token")
                .set_form([
                    ("grant_type", "authorization_code"),
                    ("client_id", $client_id),
                    ("client_secret", $client_secret),
                    ("code", code.as_str()),
                    ("redirect_uri", "https://good.example/cb"),
                    ("code_verifier", verifier),
                ])
                .to_request(),
        )
        .await;
        assert_eq!(token_resp.status(), 200, "token exchange must succeed");
        let body: serde_json::Value = test::read_body_json(token_resp).await;
        let access_token = body["access_token"]
            .as_str()
            .expect("access_token in token response")
            .to_string();
        let id_token = body["id_token"].as_str().map(|s| s.to_string());
        (access_token, id_token)
    }};
}

// ===========================================================================
// OIDC Core §3.1 — Authorization Code Flow
// ===========================================================================

/// OIDC Core §3.1: Including `openid` in the scope of an authorization code
/// grant MUST result in an `id_token` field in the token response.
///
/// @rfc oidc-core-1.0
/// @section 3.1
/// @requirement Authorization-code flow with `openid` scope must include an id_token in the token response.
/// @level MUST
/// @url https://openid.net/specs/openid-connect-core-1_0.html#TokenResponse
#[actix_web::test]
async fn oidc_core_s3_1_openid_scope_triggers_id_token() {
    let client = Client::new(
        "client_oidc_trigger".to_string(),
        "secret_oidc_trigger".to_string(),
        vec!["https://good.example/cb".to_string()],
        vec!["authorization_code".to_string()],
        "openid read".to_string(),
        "test".to_string(),
    );
    let (token_actor, client_actor, auth_actor, jwt_secret, metrics, oidc_config) =
        setup_context(client).await;
    let app = oidc_app!(
        token_actor,
        client_actor,
        auth_actor,
        jwt_secret,
        metrics,
        oidc_config
    );

    let (_access_token, id_token) =
        do_oidc_flow!(app, "client_oidc_trigger", "secret_oidc_trigger", "openid");

    assert!(
        id_token.is_some(),
        "id_token must be present when scope includes `openid`"
    );
}

/// OIDC Core §3.1: The `id_token` MUST be a compact-serialised JWT with
/// exactly three dot-separated components (header.payload.signature).
///
/// @rfc oidc-core-1.0
/// @section 3.1
/// @requirement id_token must be a compact-serialised JWT (header.payload.signature).
/// @level MUST
/// @url https://openid.net/specs/openid-connect-core-1_0.html#IDToken
#[actix_web::test]
async fn oidc_core_s3_1_id_token_is_valid_jwt() {
    let client = Client::new(
        "client_oidc_jwt".to_string(),
        "secret_oidc_jwt".to_string(),
        vec!["https://good.example/cb".to_string()],
        vec!["authorization_code".to_string()],
        "openid".to_string(),
        "test".to_string(),
    );
    let (token_actor, client_actor, auth_actor, jwt_secret, metrics, oidc_config) =
        setup_context(client).await;
    let app = oidc_app!(
        token_actor,
        client_actor,
        auth_actor,
        jwt_secret,
        metrics,
        oidc_config
    );

    let (_access_token, id_token) =
        do_oidc_flow!(app, "client_oidc_jwt", "secret_oidc_jwt", "openid");
    let id_token = id_token.expect("id_token must be present");

    let part_count = id_token.split('.').count();
    assert_eq!(
        part_count, 3,
        "id_token must be a 3-part compact JWT (header.payload.signature)"
    );
}

/// OIDC Core §2: The `sub` (subject) claim MUST be present in the id_token
/// and MUST identify the authenticated end-user.
///
/// @rfc oidc-core-1.0
/// @section 2
/// @requirement id_token must contain a `sub` claim identifying the end-user.
/// @level MUST
/// @url https://openid.net/specs/openid-connect-core-1_0.html#IDToken
#[actix_web::test]
async fn oidc_core_s3_1_id_token_sub_claim_present() {
    let client = Client::new(
        "client_oidc_sub".to_string(),
        "secret_oidc_sub".to_string(),
        vec!["https://good.example/cb".to_string()],
        vec!["authorization_code".to_string()],
        "openid".to_string(),
        "test".to_string(),
    );
    let (token_actor, client_actor, auth_actor, jwt_secret, metrics, oidc_config) =
        setup_context(client).await;
    let app = oidc_app!(
        token_actor,
        client_actor,
        auth_actor,
        jwt_secret,
        metrics,
        oidc_config
    );

    let (_access_token, id_token) =
        do_oidc_flow!(app, "client_oidc_sub", "secret_oidc_sub", "openid");
    let id_token = id_token.expect("id_token must be present");
    let claims = decode_jwt_payload(&id_token);

    let sub = claims["sub"].as_str().expect("sub must be a string claim");
    assert!(!sub.is_empty(), "sub must not be empty");
    assert_eq!(sub, "user_123", "sub must equal the authenticated user_id");
}

/// OIDC Core §2: The `iss` (issuer) claim MUST be present and MUST exactly
/// match the issuer value from the server configuration.
///
/// @rfc oidc-core-1.0
/// @section 2
/// @requirement id_token `iss` claim must match the configured issuer value exactly.
/// @level MUST
/// @url https://openid.net/specs/openid-connect-core-1_0.html#IDToken
#[actix_web::test]
async fn oidc_core_s3_1_id_token_iss_matches_config() {
    let client = Client::new(
        "client_oidc_iss".to_string(),
        "secret_oidc_iss".to_string(),
        vec!["https://good.example/cb".to_string()],
        vec!["authorization_code".to_string()],
        "openid".to_string(),
        "test".to_string(),
    );
    let (token_actor, client_actor, auth_actor, jwt_secret, metrics, oidc_config) =
        setup_context(client).await;
    let app = oidc_app!(
        token_actor,
        client_actor,
        auth_actor,
        jwt_secret,
        metrics,
        oidc_config
    );

    let (_access_token, id_token) =
        do_oidc_flow!(app, "client_oidc_iss", "secret_oidc_iss", "openid");
    let id_token = id_token.expect("id_token must be present");
    let claims = decode_jwt_payload(&id_token);

    let iss = claims["iss"].as_str().expect("iss must be a string claim");
    assert_eq!(
        iss, "http://localhost",
        "iss must match the configured issuer"
    );
}

/// OIDC Core §2: The `aud` (audience) claim MUST contain the `client_id` of
/// the relying party that requested the id_token.
///
/// @rfc oidc-core-1.0
/// @section 2
/// @requirement id_token `aud` claim must contain the requesting RP's client_id.
/// @level MUST
/// @url https://openid.net/specs/openid-connect-core-1_0.html#IDToken
#[actix_web::test]
async fn oidc_core_s3_1_id_token_aud_matches_client() {
    let client = Client::new(
        "client_oidc_aud".to_string(),
        "secret_oidc_aud".to_string(),
        vec!["https://good.example/cb".to_string()],
        vec!["authorization_code".to_string()],
        "openid".to_string(),
        "test".to_string(),
    );
    let (token_actor, client_actor, auth_actor, jwt_secret, metrics, oidc_config) =
        setup_context(client).await;
    let app = oidc_app!(
        token_actor,
        client_actor,
        auth_actor,
        jwt_secret,
        metrics,
        oidc_config
    );

    let (_access_token, id_token) =
        do_oidc_flow!(app, "client_oidc_aud", "secret_oidc_aud", "openid");
    let id_token = id_token.expect("id_token must be present");
    let claims = decode_jwt_payload(&id_token);

    // `aud` may be a JSON string or a JSON array per OIDC Core §2.
    let aud_contains_client = match &claims["aud"] {
        serde_json::Value::String(s) => s == "client_oidc_aud",
        serde_json::Value::Array(arr) => arr.iter().any(|v| v.as_str() == Some("client_oidc_aud")),
        _ => false,
    };
    assert!(
        aud_contains_client,
        "aud must contain the requesting client_id"
    );
}

/// OIDC Core §2: The `iat` (issued-at) and `exp` (expiration) claims MUST be
/// present as integer NumericDate values, with `exp` strictly after `iat`.
///
/// @rfc oidc-core-1.0
/// @section 2
/// @requirement id_token must have `iat` and `exp` NumericDate claims with `exp` > `iat`.
/// @level MUST
/// @url https://openid.net/specs/openid-connect-core-1_0.html#IDToken
#[actix_web::test]
async fn oidc_core_s3_1_id_token_has_iat_and_exp() {
    let client = Client::new(
        "client_oidc_times".to_string(),
        "secret_oidc_times".to_string(),
        vec!["https://good.example/cb".to_string()],
        vec!["authorization_code".to_string()],
        "openid".to_string(),
        "test".to_string(),
    );
    let (token_actor, client_actor, auth_actor, jwt_secret, metrics, oidc_config) =
        setup_context(client).await;
    let app = oidc_app!(
        token_actor,
        client_actor,
        auth_actor,
        jwt_secret,
        metrics,
        oidc_config
    );

    let (_access_token, id_token) =
        do_oidc_flow!(app, "client_oidc_times", "secret_oidc_times", "openid");
    let id_token = id_token.expect("id_token must be present");
    let claims = decode_jwt_payload(&id_token);

    assert!(claims["iat"].is_number(), "iat must be a numeric date");
    assert!(claims["exp"].is_number(), "exp must be a numeric date");

    let iat = claims["iat"].as_i64().unwrap();
    let exp = claims["exp"].as_i64().unwrap();
    assert!(exp > iat, "exp must be strictly after iat");
}

/// OIDC Core §3.1.2.1: When a `nonce` is provided in the authorization
/// request, it MUST be present verbatim in the id_token claims.
///
/// @rfc oidc-core-1.0
/// @section 3.1.2.1
/// @requirement A nonce in the authorization request must be echoed verbatim in the id_token.
/// @level MUST
/// @url https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
#[actix_web::test]
async fn oidc_core_s3_1_2_1_nonce_echoed_in_id_token() {
    let client = Client::new(
        "client_oidc_nonce".to_string(),
        "secret_oidc_nonce".to_string(),
        vec!["https://good.example/cb".to_string()],
        vec!["authorization_code".to_string()],
        "openid".to_string(),
        "test".to_string(),
    );
    let (token_actor, client_actor, auth_actor, jwt_secret, metrics, oidc_config) =
        setup_context(client).await;
    let app = oidc_app!(
        token_actor,
        client_actor,
        auth_actor,
        jwt_secret,
        metrics,
        oidc_config
    );

    let expected_nonce = "my_unique_nonce_abc123";
    let (_access_token, id_token) = do_oidc_flow!(
        app,
        "client_oidc_nonce",
        "secret_oidc_nonce",
        "openid",
        expected_nonce
    );
    let id_token = id_token.expect("id_token must be present");
    let claims = decode_jwt_payload(&id_token);

    let nonce = claims["nonce"]
        .as_str()
        .expect("nonce must be a string claim in the id_token");
    assert_eq!(nonce, expected_nonce, "nonce must be echoed verbatim");
}

/// OIDC Core §3.1: When `openid` is absent from the scope, the token
/// response MUST NOT include an `id_token` field.
///
/// @rfc oidc-core-1.0
/// @section 3.1
/// @requirement Token response without `openid` scope must not include an id_token.
/// @level MUST
/// @url https://openid.net/specs/openid-connect-core-1_0.html#TokenResponse
#[actix_web::test]
async fn oidc_core_s3_1_no_id_token_without_openid_scope() {
    let client = Client::new(
        "client_oidc_noscope".to_string(),
        "secret_oidc_noscope".to_string(),
        vec!["https://good.example/cb".to_string()],
        vec!["authorization_code".to_string()],
        "read".to_string(),
        "test".to_string(),
    );
    let (token_actor, client_actor, auth_actor, jwt_secret, metrics, oidc_config) =
        setup_context(client).await;
    let app = oidc_app!(
        token_actor,
        client_actor,
        auth_actor,
        jwt_secret,
        metrics,
        oidc_config
    );

    let (_access_token, id_token) =
        do_oidc_flow!(app, "client_oidc_noscope", "secret_oidc_noscope", "read");

    assert!(
        id_token.is_none(),
        "id_token must NOT be present when `openid` is absent from scope"
    );
}

// ===========================================================================
// OIDC Core §5.3 — UserInfo Endpoint
// ===========================================================================

/// OIDC Core §5.3: A valid Bearer access token MUST return a JSON body
/// containing the `sub` claim that identifies the authenticated end-user.
///
/// @rfc oidc-core-1.0
/// @section 5.3
/// @requirement UserInfo response with a valid token must include the `sub` claim.
/// @level MUST
/// @url https://openid.net/specs/openid-connect-core-1_0.html#UserInfo
#[actix_web::test]
async fn oidc_core_userinfo_s5_3_sub_claim_present() {
    let client = Client::new(
        "client_userinfo_sub".to_string(),
        "secret_userinfo_sub".to_string(),
        vec!["https://good.example/cb".to_string()],
        vec!["authorization_code".to_string()],
        "openid".to_string(),
        "test".to_string(),
    );
    let (token_actor, client_actor, auth_actor, jwt_secret, metrics, oidc_config) =
        setup_context(client).await;
    let app = oidc_app!(
        token_actor,
        client_actor,
        auth_actor,
        jwt_secret,
        metrics,
        oidc_config
    );

    let (access_token, _id_token) =
        do_oidc_flow!(app, "client_userinfo_sub", "secret_userinfo_sub", "openid");

    let resp = test::call_service(
        &app,
        test::TestRequest::get()
            .uri("/oauth/userinfo")
            .insert_header(("Authorization", format!("Bearer {access_token}")))
            .to_request(),
    )
    .await;
    assert_eq!(resp.status(), 200);

    let body: serde_json::Value = test::read_body_json(resp).await;
    let sub = body["sub"].as_str().expect("sub claim must be present");
    assert_eq!(sub, "user_123", "sub must identify the authenticated user");
}

/// OIDC Core §5.3: The UserInfo endpoint MUST return HTTP 401 with a
/// `WWW-Authenticate: Bearer` header when no access token is provided.
///
/// @rfc oidc-core-1.0
/// @section 5.3
/// @requirement UserInfo endpoint must return 401 with WWW-Authenticate: Bearer when token is missing.
/// @level MUST
/// @url https://openid.net/specs/openid-connect-core-1_0.html#UserInfo
#[actix_web::test]
async fn oidc_core_userinfo_s5_3_missing_token_returns_401() {
    let client = Client::new(
        "client_userinfo_noauth".to_string(),
        "secret_userinfo_noauth".to_string(),
        vec!["https://good.example/cb".to_string()],
        vec!["authorization_code".to_string()],
        "openid".to_string(),
        "test".to_string(),
    );
    let (token_actor, client_actor, auth_actor, jwt_secret, metrics, oidc_config) =
        setup_context(client).await;
    let app = oidc_app!(
        token_actor,
        client_actor,
        auth_actor,
        jwt_secret,
        metrics,
        oidc_config
    );

    let resp = test::call_service(
        &app,
        test::TestRequest::get().uri("/oauth/userinfo").to_request(),
    )
    .await;
    assert_eq!(resp.status(), 401);

    let www_auth = resp
        .headers()
        .get("www-authenticate")
        .and_then(|h| h.to_str().ok())
        .expect("WWW-Authenticate header must be present on 401");
    assert!(
        www_auth.starts_with("Bearer"),
        "WWW-Authenticate must indicate Bearer scheme, got: {www_auth}"
    );
}
