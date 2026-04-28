/// RFC 9700 (OAuth 2.0 Security Best Current Practice) conformance test suite.
///
/// This harness covers the 13 test vectors from §9.3 of `docs/oauth2-spec-audit.md`.
///
/// ## Test Vector Map
///
/// | Vector | Test Function | Status |
/// |--------|---------------|--------|
/// | (a) `code_challenge_method=plain` → 400 | `test_vector_a_plain_pkce_rejected` | Active |
/// | (b) Public client missing `code_challenge` → 400 | `test_vector_b_public_client_missing_pkce` | Active |
/// | (c) Code replay → 400 + family revoked | `test_vector_c_authorization_code_replay` | Ignored (bead 6.1) |
/// | (d) Refresh replay → 400 + family revoked | `test_vector_d_refresh_token_replay` | Ignored (bead 6.1) |
/// | (e) Authorization response includes `iss` | `test_vector_e_iss_in_authorization_response` | Active |
/// | (f) `redirect_uri` trailing-slash mismatch | `test_vector_f_redirect_uri_trailing_slash` | Active |
/// | (g) `redirect_uri` extra query param | `test_vector_g_redirect_uri_extra_query_param` | Active |
/// | (h) Login redirect → 303 See Other | `test_vector_h_login_redirect_303` | Ignored (bead 6.7) |
/// | (i) Token response `Cache-Control: no-store` | `test_vector_i_token_cache_control_no_store` | Active |
/// | (j) `/authorize` + `/consent` security headers | `test_vector_j_authorize_security_headers` | Active |
/// | (k) Discovery JSON constraints | `test_vector_k_discovery_json_constraints` | Active |
/// | (l) Client assertion `jti` replay → 400 | `test_vector_l_client_assertion_jti_replay` | Ignored (bead 6.5) |
/// | (m) `resource` → `aud` claim | `test_vector_m_resource_to_aud_claim` | Ignored (bead 6.3) |
use actix::{Actor, Addr};
use actix_session::{storage::CookieSessionStore, Session, SessionMiddleware};
use actix_web::{cookie::Key, test, web, App, HttpResponse};
use std::sync::Arc;
use tokio::sync::RwLock;

use oauth2_actix::actors::TokenActorPool;
use oauth2_actix::handlers::wellknown::OidcConfig;
use oauth2_core::{Client, OAuth2Error, User};
use oauth2_observability::Metrics;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn s256(verifier: &str) -> String {
    use base64::{engine::general_purpose, Engine as _};
    use sha2::{Digest, Sha256};
    general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

fn extract_query_param(url: &str, key: &str) -> Option<String> {
    let (_, query) = url.split_once('?')?;
    for pair in query.split('&') {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        if k == key {
            return Some(
                percent_encoding::percent_decode_str(v)
                    .decode_utf8_lossy()
                    .into_owned(),
            );
        }
    }
    None
}

async fn test_set_session(session: Session) -> HttpResponse {
    session.insert("user_id", "user_rfc").unwrap();
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
        .expect("session cookie")
        .split(';')
        .next()
        .unwrap()
        .to_string()
}

/// Setup helper for RFC 9700 tests.
///
/// Returns raw components for inline `App` construction in each test.
/// Uses `sqlite::memory:` and creates a `user_rfc` / `user_rfc@example.test` user.
async fn setup_rfc9700_context(
    clients: Vec<Client>,
    issuer: &str,
) -> (
    TokenActorPool,
    Addr<oauth2_actix::actors::ClientActor>,
    Addr<oauth2_actix::actors::AuthActor>,
    String, // jwt_secret
    Metrics,
    OidcConfig,
) {
    let storage = oauth2_storage_factory::create_storage("sqlite::memory:")
        .await
        .expect("create storage");
    storage.init().await.expect("init");

    for client in clients {
        storage.save_client(&client).await.expect("save client");
    }

    let now = chrono::Utc::now();
    let user = User {
        id: "user_rfc".to_string(),
        username: "user_rfc".to_string(),
        password_hash: "$argon2id$v=19$m=19456,t=2,p=1$VE0rWbJBKKaUUC4g7kAChQ$ut8jRoii8yfgSu9IGptwMKxcbH3T1Ra+OAOuXhts0xE".to_string(), // password: "test"
        email: "user_rfc@example.test".to_string(),
        enabled: true,
        role: "user".to_string(),
        created_at: now,
        updated_at: now,
    };
    storage.save_user(&user).await.expect("save user");

    let jwt_secret = "rfc9700_test_jwt_secret_at_least_32_chars".to_string();
    let metrics = Metrics::new().expect("metrics");

    let token_actor = oauth2_actix::actors::TokenActor::new(
        storage.clone(),
        jwt_secret.clone(),
        issuer.to_string(),
    )
    .start();
    let token_pool = TokenActorPool::new(vec![token_actor]);
    let client_actor = oauth2_actix::actors::ClientActor::new(storage.clone()).start();
    let auth_actor = oauth2_actix::actors::AuthActor::new(storage).start();

    let oidc_config = OidcConfig {
        issuer: issuer.to_string(),
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

// ---------------------------------------------------------------------------
// Vector (a): code_challenge_method=plain → 400 invalid_request
// ---------------------------------------------------------------------------

/// RFC 9700 §2.1.1: PKCE `plain` method MUST be rejected.
///
/// @rfc 9700
/// @section 2.1.1
/// @requirement PKCE `plain` method must be rejected; only S256 is acceptable.
/// @level MUST
/// @url https://datatracker.ietf.org/doc/html/rfc9700#section-2.1.1
#[actix_web::test]
async fn test_vector_a_plain_pkce_rejected() {
    let client = Client::new(
        "client_a".to_string(),
        "secret_a".to_string(),
        vec!["https://app.example/cb".to_string()],
        vec!["authorization_code".to_string()],
        "read".to_string(),
        "test".to_string(),
    );

    let (token_actor, client_actor, auth_actor, jwt_secret, metrics, oidc_config) =
        setup_rfc9700_context(vec![client], "https://auth.example.com").await;
    let keyset = Arc::new(RwLock::new(oauth2_core::models::key_set::KeySet::default()));

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
            .app_data(web::Data::new(keyset))
            .app_data(web::Data::new(false))
            .service(web::scope("/oauth").route(
                "/authorize",
                web::get().to(oauth2_actix::handlers::oauth::authorize),
            )),
    )
    .await;

    // Establish session
    let login_resp = test::call_service(
        &app,
        test::TestRequest::get().uri("/test/login").to_request(),
    )
    .await;
    let cookie = extract_session_cookie(&login_resp);

    let req = test::TestRequest::get()
        .uri(
            "/oauth/authorize?response_type=code&client_id=client_a\
             &redirect_uri=https%3A%2F%2Fapp.example%2Fcb&scope=read\
             &code_challenge=plaintext_challenge&code_challenge_method=plain&state=xyz",
        )
        .insert_header(("Cookie", cookie.as_str()))
        .to_request();
    let resp = test::call_service(&app, req).await;

    assert_eq!(resp.status(), 400, "plain PKCE must be rejected");
    let body: OAuth2Error = test::read_body_json(resp).await;
    assert_eq!(body.error, "invalid_request");
}

// ---------------------------------------------------------------------------
// Vector (b): Public client missing code_challenge → 400
// ---------------------------------------------------------------------------

/// RFC 9700 §2.1.1: Public clients MUST supply PKCE.
///
/// @rfc 9700
/// @section 2.1.1
/// @requirement Public clients must supply PKCE on the authorization-code flow.
/// @level MUST
/// @url https://datatracker.ietf.org/doc/html/rfc9700#section-2.1.1
#[actix_web::test]
async fn test_vector_b_public_client_missing_pkce() {
    let mut client = Client::new(
        "client_b".to_string(),
        "".to_string(),
        vec!["https://app.example/cb".to_string()],
        vec!["authorization_code".to_string()],
        "read".to_string(),
        "test".to_string(),
    );
    client.token_endpoint_auth_method = "none".to_string();

    let (token_actor, client_actor, auth_actor, jwt_secret, metrics, oidc_config) =
        setup_rfc9700_context(vec![client], "https://auth.example.com").await;
    let keyset = Arc::new(RwLock::new(oauth2_core::models::key_set::KeySet::default()));

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
            .app_data(web::Data::new(keyset))
            .app_data(web::Data::new(false))
            .service(web::scope("/oauth").route(
                "/authorize",
                web::get().to(oauth2_actix::handlers::oauth::authorize),
            )),
    )
    .await;

    // Establish session
    let login_resp = test::call_service(
        &app,
        test::TestRequest::get().uri("/test/login").to_request(),
    )
    .await;
    let cookie = extract_session_cookie(&login_resp);

    // Public client without PKCE
    let req = test::TestRequest::get()
        .uri(
            "/oauth/authorize?response_type=code&client_id=client_b\
             &redirect_uri=https%3A%2F%2Fapp.example%2Fcb&scope=read&state=xyz",
        )
        .insert_header(("Cookie", cookie.as_str()))
        .to_request();
    let resp = test::call_service(&app, req).await;

    assert_eq!(
        resp.status(),
        400,
        "public client without PKCE must be rejected"
    );
    let body: OAuth2Error = test::read_body_json(resp).await;
    assert_eq!(body.error, "invalid_request");
}

// ---------------------------------------------------------------------------
// Vector (c): Code replay → 400 + family revoked (IGNORED — bead 6.1)
// ---------------------------------------------------------------------------

/// RFC 9700 §2.1.5: replaying an authorization code MUST revoke the entire token family.
///
/// @rfc 9700
/// @section 2.1.5
/// @requirement Authorization-code replay must revoke the entire issued token family.
/// @level MUST
/// @url https://datatracker.ietf.org/doc/html/rfc9700#section-2.1.5
#[actix_web::test]
#[ignore = "Awaits bead 6.1: token family revocation on code replay"]
async fn test_vector_c_authorization_code_replay() {
    // TODO(6.1): implement token family tracking + cascade revocation on code replay
    todo!("Bead 6.1: revoke token family on authorization-code replay");
}

// ---------------------------------------------------------------------------
// Vector (d): Refresh token replay → 400 + family revoked (IGNORED — bead 6.1)
// ---------------------------------------------------------------------------

/// RFC 9700 §2.1.5: replaying a rotated refresh token MUST revoke the entire family.
///
/// @rfc 9700
/// @section 2.1.5
/// @requirement Replaying a rotated refresh token must revoke the entire token family.
/// @level MUST
/// @url https://datatracker.ietf.org/doc/html/rfc9700#section-2.1.5
#[actix_web::test]
#[ignore = "Awaits bead 6.1: token family revocation on refresh replay"]
async fn test_vector_d_refresh_token_replay() {
    // TODO(6.1): implement refresh token rotation + family revocation on replay
    todo!("Bead 6.1: revoke token family on refresh-token replay");
}

// ---------------------------------------------------------------------------
// Vector (e): Authorization response includes `iss`
// ---------------------------------------------------------------------------

/// RFC 9207 + RFC 9700 §4.8: every authorization response (success and error) MUST include `iss`.
///
/// @rfc 9207
/// @section 2
/// @requirement Authorization response (success or error) must include the `iss` parameter.
/// @level MUST
/// @url https://datatracker.ietf.org/doc/html/rfc9207#section-2
#[actix_web::test]
async fn test_vector_e_iss_in_authorization_response() {
    const ISSUER: &str = "https://auth.example.com";

    let client = Client::new(
        "client_e".to_string(),
        "secret_e".to_string(),
        vec!["https://app.example/cb".to_string()],
        vec!["authorization_code".to_string()],
        "read".to_string(),
        "test".to_string(),
    );

    let (token_actor, client_actor, auth_actor, jwt_secret, metrics, oidc_config) =
        setup_rfc9700_context(vec![client], ISSUER).await;
    let keyset = Arc::new(RwLock::new(oauth2_core::models::key_set::KeySet::default()));

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
            .app_data(web::Data::new(keyset))
            .app_data(web::Data::new(false))
            .service(web::scope("/oauth").route(
                "/authorize",
                web::get().to(oauth2_actix::handlers::oauth::authorize),
            )),
    )
    .await;

    // Establish session
    let login_resp = test::call_service(
        &app,
        test::TestRequest::get().uri("/test/login").to_request(),
    )
    .await;
    let cookie = extract_session_cookie(&login_resp);

    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let challenge = s256(verifier);

    // Success response
    let req = test::TestRequest::get()
        .uri(&format!(
            "/oauth/authorize?response_type=code&client_id=client_e\
             &redirect_uri=https%3A%2F%2Fapp.example%2Fcb&scope=read\
             &code_challenge={challenge}&code_challenge_method=S256&state=abc"
        ))
        .insert_header(("Cookie", cookie.as_str()))
        .to_request();
    let resp = test::call_service(&app, req).await;

    assert_eq!(resp.status(), 302);
    let location = resp
        .headers()
        .get(actix_web::http::header::LOCATION)
        .and_then(|h| h.to_str().ok())
        .expect("Location header");

    let iss = extract_query_param(location, "iss").expect("iss in success redirect");
    assert_eq!(iss, ISSUER);

    // Error response (invalid scope)
    let req_err = test::TestRequest::get()
        .uri(&format!(
            "/oauth/authorize?response_type=code&client_id=client_e\
             &redirect_uri=https%3A%2F%2Fapp.example%2Fcb&scope=invalid_scope\
             &code_challenge={challenge}&code_challenge_method=S256&state=def"
        ))
        .insert_header(("Cookie", cookie))
        .to_request();
    let resp_err = test::call_service(&app, req_err).await;

    assert_eq!(resp_err.status(), 302);
    let location_err = resp_err
        .headers()
        .get(actix_web::http::header::LOCATION)
        .and_then(|h| h.to_str().ok())
        .expect("Location header");

    let iss_err = extract_query_param(location_err, "iss").expect("iss in error redirect");
    assert_eq!(iss_err, ISSUER);
}

// ---------------------------------------------------------------------------
// Vector (f): redirect_uri trailing-slash mismatch → rejected
// ---------------------------------------------------------------------------

/// RFC 9700 §4.1: `redirect_uri` must match registered URI exactly (no normalization).
///
/// @rfc 9700
/// @section 4.1
/// @requirement redirect_uri must be matched byte-for-byte; trailing-slash differences must be rejected.
/// @level MUST
/// @url https://datatracker.ietf.org/doc/html/rfc9700#section-4.1
#[actix_web::test]
async fn test_vector_f_redirect_uri_trailing_slash() {
    let client = Client::new(
        "client_f".to_string(),
        "secret_f".to_string(),
        vec!["https://app.example/callback".to_string()], // no trailing slash
        vec!["authorization_code".to_string()],
        "read".to_string(),
        "test".to_string(),
    );

    let (token_actor, client_actor, auth_actor, jwt_secret, metrics, oidc_config) =
        setup_rfc9700_context(vec![client], "https://auth.example.com").await;
    let keyset = Arc::new(RwLock::new(oauth2_core::models::key_set::KeySet::default()));

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
            .app_data(web::Data::new(keyset))
            .app_data(web::Data::new(false))
            .service(web::scope("/oauth").route(
                "/authorize",
                web::get().to(oauth2_actix::handlers::oauth::authorize),
            )),
    )
    .await;

    // Establish session
    let login_resp = test::call_service(
        &app,
        test::TestRequest::get().uri("/test/login").to_request(),
    )
    .await;
    let cookie = extract_session_cookie(&login_resp);

    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let challenge = s256(verifier);

    // Request with trailing slash (different from registration)
    let req = test::TestRequest::get()
        .uri(&format!(
            "/oauth/authorize?response_type=code&client_id=client_f\
             &redirect_uri=https%3A%2F%2Fapp.example%2Fcallback%2F&scope=read\
             &code_challenge={challenge}&code_challenge_method=S256&state=xyz"
        ))
        .insert_header(("Cookie", cookie.as_str()))
        .to_request();
    let resp = test::call_service(&app, req).await;

    assert_eq!(
        resp.status(),
        400,
        "trailing-slash mismatch must be rejected"
    );
    let body: OAuth2Error = test::read_body_json(resp).await;
    assert_eq!(body.error, "invalid_request");
}

// ---------------------------------------------------------------------------
// Vector (g): redirect_uri with extra query param → rejected
// ---------------------------------------------------------------------------

/// RFC 9700 §4.1: `redirect_uri` with extra query parameters must be rejected.
///
/// @rfc 9700
/// @section 4.1
/// @requirement redirect_uri carrying additional query parameters must be rejected.
/// @level MUST
/// @url https://datatracker.ietf.org/doc/html/rfc9700#section-4.1
#[actix_web::test]
async fn test_vector_g_redirect_uri_extra_query_param() {
    let client = Client::new(
        "client_g".to_string(),
        "secret_g".to_string(),
        vec!["https://app.example/callback".to_string()],
        vec!["authorization_code".to_string()],
        "read".to_string(),
        "test".to_string(),
    );

    let (token_actor, client_actor, auth_actor, jwt_secret, metrics, oidc_config) =
        setup_rfc9700_context(vec![client], "https://auth.example.com").await;
    let keyset = Arc::new(RwLock::new(oauth2_core::models::key_set::KeySet::default()));

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
            .app_data(web::Data::new(keyset))
            .app_data(web::Data::new(false))
            .service(web::scope("/oauth").route(
                "/authorize",
                web::get().to(oauth2_actix::handlers::oauth::authorize),
            )),
    )
    .await;

    // Establish session
    let login_resp = test::call_service(
        &app,
        test::TestRequest::get().uri("/test/login").to_request(),
    )
    .await;
    let cookie = extract_session_cookie(&login_resp);

    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let challenge = s256(verifier);

    // Request with extra query param
    let req = test::TestRequest::get()
        .uri(&format!(
            "/oauth/authorize?response_type=code&client_id=client_g\
             &redirect_uri=https%3A%2F%2Fapp.example%2Fcallback%3Fextra%3Dparam&scope=read\
             &code_challenge={challenge}&code_challenge_method=S256&state=xyz"
        ))
        .insert_header(("Cookie", cookie.as_str()))
        .to_request();
    let resp = test::call_service(&app, req).await;

    assert_eq!(
        resp.status(),
        400,
        "redirect_uri with extra query param must be rejected"
    );
    let body: OAuth2Error = test::read_body_json(resp).await;
    assert_eq!(body.error, "invalid_request");
}

// ---------------------------------------------------------------------------
// Vector (h): Login redirect → 303 See Other (IGNORED — bead 6.7)
// ---------------------------------------------------------------------------

/// RFC 9700 §4.11: login form POST should redirect with 303 See Other, not 302.
///
/// @rfc 9700
/// @section 4.11
/// @requirement Login form POST handler should redirect with 303 See Other (not 302).
/// @level SHOULD
/// @url https://datatracker.ietf.org/doc/html/rfc9700#section-4.11
#[actix_web::test]
#[ignore = "Awaits bead 6.7: 302 → 303 See Other for login redirects"]
async fn test_vector_h_login_redirect_303() {
    // TODO(6.7): change login form POST redirect from 302 to 303
    todo!("Bead 6.7: login redirect must use 303 See Other");
}

// ---------------------------------------------------------------------------
// Vector (i): Token endpoint response `Cache-Control: no-store`
// ---------------------------------------------------------------------------

/// RFC 9700 §2.3: token responses MUST include `Cache-Control: no-store`.
///
/// @rfc 9700
/// @section 2.3
/// @requirement Token endpoint responses must include `Cache-Control: no-store`.
/// @level MUST
/// @url https://datatracker.ietf.org/doc/html/rfc9700#section-2.3
#[actix_web::test]
async fn test_vector_i_token_cache_control_no_store() {
    let client = Client::new(
        "client_i".to_string(),
        "secret_i".to_string(),
        vec!["https://unused/cb".to_string()],
        vec!["client_credentials".to_string()],
        "read".to_string(),
        "test".to_string(),
    );

    let (token_actor, client_actor, auth_actor, jwt_secret, metrics, oidc_config) =
        setup_rfc9700_context(vec![client], "https://auth.example.com").await;
    let keyset = Arc::new(RwLock::new(oauth2_core::models::key_set::KeySet::default()));

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(token_actor))
            .app_data(web::Data::new(client_actor))
            .app_data(web::Data::new(auth_actor))
            .app_data(web::Data::new(jwt_secret))
            .app_data(web::Data::new(metrics))
            .app_data(web::Data::new(oidc_config))
            .app_data(web::Data::new(keyset))
            .app_data(web::Data::new(false))
            .service(web::scope("/oauth").route(
                "/token",
                web::post().to(oauth2_actix::handlers::oauth::token),
            )),
    )
    .await;

    let resp = test::call_service(
        &app,
        test::TestRequest::post()
            .uri("/oauth/token")
            .set_form([
                ("grant_type", "client_credentials"),
                ("client_id", "client_i"),
                ("client_secret", "secret_i"),
                ("scope", "read"),
            ])
            .to_request(),
    )
    .await;

    assert_eq!(resp.status(), 200);

    let cache_control = resp
        .headers()
        .get(actix_web::http::header::CACHE_CONTROL)
        .and_then(|h| h.to_str().ok())
        .expect("Cache-Control header");

    assert_eq!(cache_control, "no-store");
}

// ---------------------------------------------------------------------------
// Vector (j): /authorize and /consent security headers (X-Frame-Options: DENY)
// ---------------------------------------------------------------------------

/// RFC 9700 §4.12: `/authorize` and `/consent` MUST include X-Frame-Options: DENY or CSP frame-ancestors 'none'.
///
/// @rfc 9700
/// @section 4.12
/// @requirement /authorize and /consent must set X-Frame-Options: DENY or CSP frame-ancestors 'none'.
/// @level MUST
/// @url https://datatracker.ietf.org/doc/html/rfc9700#section-4.12
#[actix_web::test]
async fn test_vector_j_authorize_security_headers() {
    let client = Client::new(
        "client_j".to_string(),
        "secret_j".to_string(),
        vec!["https://app.example/cb".to_string()],
        vec!["authorization_code".to_string()],
        "read".to_string(),
        "test".to_string(),
    );

    let (token_actor, client_actor, auth_actor, jwt_secret, metrics, oidc_config) =
        setup_rfc9700_context(vec![client], "https://auth.example.com").await;
    let keyset = Arc::new(RwLock::new(oauth2_core::models::key_set::KeySet::default()));

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
            .app_data(web::Data::new(keyset))
            .app_data(web::Data::new(false))
            .service(web::scope("/oauth").route(
                "/authorize",
                web::get().to(oauth2_actix::handlers::oauth::authorize),
            )),
    )
    .await;

    // Establish session
    let login_resp = test::call_service(
        &app,
        test::TestRequest::get().uri("/test/login").to_request(),
    )
    .await;
    let cookie = extract_session_cookie(&login_resp);

    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let challenge = s256(verifier);

    let req = test::TestRequest::get()
        .uri(&format!(
            "/oauth/authorize?response_type=code&client_id=client_j\
             &redirect_uri=https%3A%2F%2Fapp.example%2Fcb&scope=read\
             &code_challenge={challenge}&code_challenge_method=S256&state=xyz"
        ))
        .insert_header(("Cookie", cookie.as_str()))
        .to_request();
    let resp = test::call_service(&app, req).await;

    assert_eq!(resp.status(), 302);

    // Check X-Frame-Options
    let x_frame = resp
        .headers()
        .get(actix_web::http::header::X_FRAME_OPTIONS)
        .and_then(|h| h.to_str().ok())
        .expect("X-Frame-Options header");
    assert_eq!(x_frame, "DENY");

    // Check CSP frame-ancestors
    let csp = resp
        .headers()
        .get(actix_web::http::header::CONTENT_SECURITY_POLICY)
        .and_then(|h| h.to_str().ok())
        .expect("CSP header");
    assert!(csp.contains("frame-ancestors 'none'"));
}

// ---------------------------------------------------------------------------
// Vector (k): Discovery JSON constraints
// ---------------------------------------------------------------------------

/// RFC 9700 §4: discovery document MUST advertise:
/// - `code_challenge_methods_supported=["S256"]`
/// - `grant_types_supported` excludes `password`
/// - `response_types_supported` excludes `token`
/// - `authorization_response_iss_parameter_supported=true`
///
/// @rfc 9700
/// @section 4
/// @requirement Discovery doc must satisfy RFC 9700 BCP constraints (S256-only, no password, no implicit, iss param).
/// @level MUST
/// @url https://datatracker.ietf.org/doc/html/rfc9700#section-4
#[actix_web::test]
async fn test_vector_k_discovery_json_constraints() {
    let (_, _, _, _, _, oidc_config) =
        setup_rfc9700_context(vec![], "https://auth.example.com").await;

    let app = test::init_service(App::new().app_data(web::Data::new(oidc_config)).service(
        web::scope("/.well-known").route(
            "/openid-configuration",
            web::get().to(oauth2_actix::handlers::wellknown::openid_configuration),
        ),
    ))
    .await;

    let resp = test::call_service(
        &app,
        test::TestRequest::get()
            .uri("/.well-known/openid-configuration")
            .to_request(),
    )
    .await;

    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = test::read_body_json(resp).await;

    // Check code_challenge_methods_supported
    let pkce_methods = body["code_challenge_methods_supported"]
        .as_array()
        .expect("code_challenge_methods_supported");
    assert_eq!(pkce_methods.len(), 1);
    assert_eq!(pkce_methods[0], "S256");

    // Check grant_types_supported excludes "password"
    let grant_types = body["grant_types_supported"]
        .as_array()
        .expect("grant_types_supported");
    assert!(!grant_types.iter().any(|v| v == "password"));

    // Check response_types_supported excludes "token"
    let response_types = body["response_types_supported"]
        .as_array()
        .expect("response_types_supported");
    assert!(!response_types.iter().any(|v| v == "token"));

    // Check authorization_response_iss_parameter_supported
    let iss_supported = body["authorization_response_iss_parameter_supported"]
        .as_bool()
        .expect("authorization_response_iss_parameter_supported");
    assert!(iss_supported);
}

// ---------------------------------------------------------------------------
// Vector (l): Client assertion jti replay → 400 (IGNORED — bead 6.5)
// ---------------------------------------------------------------------------

/// RFC 9700 §2.5: replaying a client assertion with the same `jti` within its exp window MUST be rejected.
///
/// @rfc 9700
/// @section 2.5
/// @requirement A replayed client assertion (same `jti` within exp window) must be rejected.
/// @level MUST
/// @url https://datatracker.ietf.org/doc/html/rfc9700#section-2.5
#[actix_web::test]
#[ignore = "Awaits bead 6.5: JWT client-assertion jti replay store"]
async fn test_vector_l_client_assertion_jti_replay() {
    // TODO(6.5): implement jti replay cache for client assertions
    todo!("Bead 6.5: reject replayed client assertion jti");
}

// ---------------------------------------------------------------------------
// Vector (m): resource → aud claim (IGNORED — bead 6.3)
// ---------------------------------------------------------------------------

/// RFC 9700 §2.3 + RFC 8707: token request with `resource` parameter MUST populate `aud` claim.
///
/// @rfc 8707
/// @section 2
/// @requirement Token request `resource` parameter must populate the issued token's `aud` claim.
/// @level MUST
/// @url https://datatracker.ietf.org/doc/html/rfc8707#section-2
#[actix_web::test]
async fn test_vector_m_resource_to_aud_claim() {
    let client = Client::new(
        "client_m".to_string(),
        "secret_m".to_string(),
        vec!["https://app.example/cb".to_string()],
        vec![
            "authorization_code".to_string(),
            "client_credentials".to_string(),
        ],
        "read".to_string(),
        "test".to_string(),
    );

    let (token_actor, client_actor, auth_actor, jwt_secret, metrics, oidc_config) =
        setup_rfc9700_context(vec![client], "https://auth.example.com").await;
    let keyset = Arc::new(RwLock::new(oauth2_core::models::key_set::KeySet::default()));

    // Test 1: client_credentials grant with resource parameter
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(token_actor.clone()))
            .app_data(web::Data::new(client_actor.clone()))
            .app_data(web::Data::new(auth_actor.clone()))
            .app_data(web::Data::new(jwt_secret.clone()))
            .app_data(web::Data::new(metrics.clone()))
            .app_data(web::Data::new(oidc_config.clone()))
            .app_data(web::Data::new(keyset.clone()))
            .app_data(web::Data::new(false))
            .service(web::scope("/oauth").route(
                "/token",
                web::post().to(oauth2_actix::handlers::oauth::token),
            )),
    )
    .await;

    let resp = test::call_service(
        &app,
        test::TestRequest::post()
            .uri("/oauth/token")
            .set_form([
                ("grant_type", "client_credentials"),
                ("client_id", "client_m"),
                ("client_secret", "secret_m"),
                ("scope", "read"),
                ("resource", "https://api.resource.test"),
            ])
            .to_request(),
    )
    .await;

    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = test::read_body_json(resp).await;
    let access_token = body["access_token"]
        .as_str()
        .expect("access_token in response");

    // Decode the JWT to verify aud claim
    use jsonwebtoken::decode_header;
    let header = decode_header(access_token).expect("valid JWT header");
    assert_eq!(header.typ, Some("at+JWT".to_string()));

    // Decode without verification (we trust our own token)
    let claims = oauth2_core::models::token::Claims::decode_unverified(access_token)
        .expect("decode JWT claims");

    // RFC 8707 §2: aud MUST reflect the resource parameter
    assert_eq!(claims.aud, vec!["https://api.resource.test".to_string()]);
    // client_id should still be present as a separate claim
    assert_eq!(claims.client_id, Some("client_m".to_string()));
    assert_eq!(claims.iss, "https://auth.example.com");
}

// ---------------------------------------------------------------------------
// Vector (n): DPoP proof validation (RFC 9449) — Phase 6.2
// ---------------------------------------------------------------------------

/// RFC 9449 §4: DPoP proof with invalid typ header → 400 invalid_dpop_proof
///
/// @rfc 9449
/// @section 4
/// @requirement DPoP proof with invalid `typ` JOSE header must be rejected with `invalid_dpop_proof`.
/// @level MUST
/// @url https://datatracker.ietf.org/doc/html/rfc9449#section-4
#[actix_web::test]
async fn test_vector_n_dpop_invalid_typ() {
    use oauth2_actix::handlers::dpop::{validate_dpop_proof, DpopReplayStore};

    // A JWT with typ="JWT" instead of "dpop+jwt" (crafted for this test)
    let bad_proof = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.e30.signature";
    let store = DpopReplayStore::new();

    let result = validate_dpop_proof(
        bad_proof,
        "POST",
        "https://auth.example.com/oauth/token",
        &store,
    );

    assert!(result.is_err());
    let err = result.unwrap_err();
    assert_eq!(err.error, "invalid_dpop_proof");
    assert!(err.error_description.as_ref().unwrap().contains("typ"));
}

/// RFC 9449 §4: DPoP proof jti replay → 400 invalid_dpop_proof
///
/// @rfc 9449
/// @section 4
/// @requirement Replayed DPoP proof (same `jti`) must be rejected with `invalid_dpop_proof`.
/// @level MUST
/// @url https://datatracker.ietf.org/doc/html/rfc9449#section-4
#[actix_web::test]
async fn test_vector_o_dpop_jti_replay() {
    use oauth2_actix::handlers::dpop::DpopReplayStore;
    use std::time::{Duration, Instant};

    let store = DpopReplayStore::new();
    let jti = "test-jti-12345";
    let expiry = Instant::now() + Duration::from_secs(60);

    // First use: should succeed
    assert!(store.check_and_insert(jti, expiry).is_ok());

    // Replay: should fail
    let result = store.check_and_insert(jti, expiry);
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert_eq!(err.error, "invalid_dpop_proof");
    assert!(err.error_description.as_ref().unwrap().contains("replay"));
}

// ---------------------------------------------------------------------------
// Vector (p): mTLS client authentication (RFC 8705) — Phase 6.10
// ---------------------------------------------------------------------------

/// RFC 8705 §2.1: tls_client_auth requires certificate Subject DN match
///
/// @rfc 8705
/// @section 2.1
/// @requirement `tls_client_auth` must validate the client certificate Subject DN against the registered value.
/// @level MUST
/// @url https://datatracker.ietf.org/doc/html/rfc8705#section-2.1
#[actix_web::test]
async fn test_vector_p_mtls_subject_dn_validation() {
    use oauth2_actix::handlers::oauth;

    // Build a client with tls_client_auth and a specific Subject DN requirement.
    let mut client = Client::new(
        "mtls-client".to_string(),
        "test-secret".to_string(),
        vec!["https://example.com/callback".to_string()],
        vec!["client_credentials".to_string()],
        "read".to_string(),
        "mTLS Test Client".to_string(),
    );
    client.token_endpoint_auth_method = "tls_client_auth".to_string();
    client.tls_client_certificate_subject_dn = "CN=test-client".to_string();

    let (token_actor, client_actor, auth_actor, jwt_secret, metrics, oidc_config) =
        setup_rfc9700_context(vec![client], "https://auth.example.com").await;

    let keyset = Arc::new(RwLock::new(oauth2_core::models::key_set::KeySet::default()));
    let jwks_cache = Arc::new(RwLock::new(
        oauth2_actix::handlers::jwks_cache::JwksCache::default(),
    ));

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(token_actor))
            .app_data(web::Data::new(client_actor))
            .app_data(web::Data::new(auth_actor))
            .app_data(web::Data::new(jwt_secret))
            .app_data(web::Data::new(metrics))
            .app_data(web::Data::new(oidc_config))
            .app_data(web::Data::new(keyset))
            .app_data(web::Data::new(jwks_cache))
            .app_data(web::Data::new(false)) // stateless_validation
            .service(web::scope("/oauth").route("/token", web::post().to(oauth::token))),
    )
    .await;

    // Positive case: client_credentials grant with matching Subject DN
    let form_data =
        "grant_type=client_credentials&client_id=mtls-client&client_secret=test-secret&scope=read";
    let req = test::TestRequest::post()
        .uri("/oauth/token")
        .insert_header(("content-type", "application/x-www-form-urlencoded"))
        .insert_header(("X-Client-Cert-Thumbprint", "abc123")) // mTLS cert present
        .insert_header(("X-SSL-Client-S-DN", "CN=test-client")) // Matching DN
        .set_payload(form_data)
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(
        resp.status(),
        200,
        "Expected 200 for valid mTLS with matching Subject DN"
    );

    // Negative case: mismatched Subject DN (attacker cert)
    let req = test::TestRequest::post()
        .uri("/oauth/token")
        .insert_header(("content-type", "application/x-www-form-urlencoded"))
        .insert_header(("X-Client-Cert-Thumbprint", "abc123")) // mTLS cert present
        .insert_header(("X-SSL-Client-S-DN", "CN=attacker")) // Wrong DN
        .set_payload(form_data)
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(
        resp.status(),
        401,
        "Expected 401 for mTLS with mismatched Subject DN"
    );
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["error"], "invalid_client");
}

// ---------------------------------------------------------------------------
// Vector (q): JAR request parameter (RFC 9101) — Phase 6.12
// ---------------------------------------------------------------------------

/// RFC 9101 §4: JAR implementation verified via oauth.rs lines 713-778
///
/// @rfc 9101
/// @section 4
/// @requirement Authorization endpoint must accept and process the JAR `request` parameter.
/// @level MUST
/// @url https://datatracker.ietf.org/doc/html/rfc9101#section-4
#[actix_web::test]
async fn test_vector_q_jar_request_parameter_integration() {
    use jsonwebtoken::{encode, Algorithm, EncodingKey, Header as JwtHeader};
    use oauth2_actix::handlers::jwks_cache::JwksCache;
    use oauth2_actix::handlers::oauth;
    use oauth2_core::models::key_set::KeySet;
    use serde_json::json;

    // Build a client that uses HS256 for JAR (shared secret).
    let client = Client::new(
        "jar-client".to_string(),
        "jar-secret".to_string(),
        vec!["https://app.example/cb".to_string()],
        vec!["authorization_code".to_string()],
        "read".to_string(),
        "JAR Test Client".to_string(),
    );

    let (token_actor, client_actor, auth_actor, jwt_secret, metrics, oidc_config) =
        setup_rfc9700_context(vec![client], "https://auth.example.com").await;

    let keyset = Arc::new(RwLock::new(KeySet::default()));
    // JwksCache is Clone + Send + Sync (internally Arc<Mutex<...>>); register the bare
    // type so the handler's `Option<web::Data<JwksCache>>` extractor matches.
    let jwks_cache = JwksCache::default();
    let session_key = Key::generate();

    let app = test::init_service(
        App::new()
            .wrap(SessionMiddleware::new(
                CookieSessionStore::default(),
                session_key.clone(),
            ))
            .app_data(web::Data::new(token_actor))
            .app_data(web::Data::new(client_actor))
            .app_data(web::Data::new(auth_actor))
            .app_data(web::Data::new(jwt_secret))
            .app_data(web::Data::new(metrics))
            .app_data(web::Data::new(oidc_config))
            .app_data(web::Data::new(keyset))
            .app_data(web::Data::new(jwks_cache))
            .app_data(web::Data::new(false)) // stateless_validation
            .route("/test/set-session", web::get().to(test_set_session))
            .service(
                web::scope("/oauth")
                    .route("/authorize", web::get().to(oauth::authorize))
                    .route("/authorize", web::post().to(oauth::authorize)),
            ),
    )
    .await;

    // Set up session.
    let resp = test::call_service(
        &app,
        test::TestRequest::get()
            .uri("/test/set-session")
            .to_request(),
    )
    .await;
    let session_cookie = extract_session_cookie(&resp);

    // Positive case: Build a JAR JWT with state="jar-state-123" in the payload.
    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let challenge = s256(verifier);
    let jar_claims = json!({
        "iss": "jar-client",
        "aud": "https://auth.example.com/oauth/authorize",
        "response_type": "code",
        "client_id": "jar-client",
        "redirect_uri": "https://app.example/cb",
        "state": "jar-state-123",
        "scope": "read",
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "exp": (chrono::Utc::now().timestamp() + 300),
        "iat": chrono::Utc::now().timestamp(),
    });
    let jar_jwt = encode(
        &JwtHeader::new(Algorithm::HS256),
        &jar_claims,
        &EncodingKey::from_secret("jar-secret".as_bytes()),
    )
    .unwrap();

    // Send /authorize with the JAR request parameter and a DIFFERENT state in query string.
    // Per RFC 9101 §6.3, callers MAY duplicate JAR-bound params in the query; we duplicate
    // redirect_uri here because the AS extracts it before JAR overlay (defensive parsing
    // for early validation) but JAR claims still take precedence per RFC 9101 §5.
    let req = test::TestRequest::get()
        .uri(&format!(
            "/oauth/authorize?client_id=jar-client&redirect_uri=https://app.example/cb&response_type=code&request={}&state=query-state-different",
            jar_jwt
        ))
        .insert_header(("Cookie", session_cookie.as_str()))
        .to_request();

    let resp = test::call_service(&app, req).await;
    let status = resp.status();
    if status != 302 && status != 303 {
        let body = test::read_body(resp).await;
        panic!(
            "Expected 302/303 redirect for valid JAR request, got {}: {}",
            status,
            String::from_utf8_lossy(&body)
        );
    }
    let location = resp
        .headers()
        .get("location")
        .and_then(|h| h.to_str().ok())
        .unwrap()
        .to_string();
    eprintln!("vector_q location: {}", location);
    // The redirect should contain the state from the JAR JWT, NOT the query string.
    let state_from_redirect = extract_query_param(&location, "state")
        .unwrap_or_else(|| panic!("location had no state param: {}", location));
    assert_eq!(
        state_from_redirect, "jar-state-123",
        "State should come from JAR JWT payload, not query string"
    );
    assert!(
        !location.contains("query-state-different"),
        "Query string state should be ignored when JAR is present"
    );

    // Negative case: tampered signature.
    let tampered_jwt = format!("{}.tampered", &jar_jwt[..jar_jwt.rfind('.').unwrap()]);
    let req = test::TestRequest::get()
        .uri(&format!(
            "/oauth/authorize?client_id=jar-client&redirect_uri=https://app.example/cb&response_type=code&request={}",
            tampered_jwt
        ))
        .insert_header(("Cookie", session_cookie.as_str()))
        .to_request();

    let resp = test::call_service(&app, req).await;
    let status = resp.status();
    if status == 302 || status == 303 {
        let location = resp
            .headers()
            .get("location")
            .and_then(|h| h.to_str().ok())
            .unwrap();
        assert!(
            location.contains("error=invalid_request_object"),
            "Expected invalid_request_object error for tampered JAR signature, got location: {}",
            location
        );
    } else if status == 400 {
        // JAR processing errors before redirect-eligible state may surface as 400.
        let body = test::read_body(resp).await;
        let body_str = String::from_utf8_lossy(&body);
        assert!(
            body_str.contains("invalid_request_object") || body_str.contains("invalid_request"),
            "Expected invalid_request_object/invalid_request error for tampered JAR, got: {}",
            body_str
        );
    } else {
        panic!(
            "Expected 302/303 redirect or 400 for tampered JAR, got {}",
            status
        );
    }
}

/// RFC 9101 §4: JAR with private_key_jwt requires JWKS resolution
///
/// @rfc 9101
/// @section 4
/// @requirement JAR signed via `private_key_jwt` must be verified using the client's resolved JWKS.
/// @level MUST
/// @url https://datatracker.ietf.org/doc/html/rfc9101#section-4
#[actix_web::test]
async fn test_vector_r_jar_private_key_jwt_jwks_cache() {
    use base64::{engine::general_purpose, Engine as _};
    use httpmock::prelude::*;
    use jsonwebtoken::{encode, Algorithm, EncodingKey, Header as JwtHeader};
    use oauth2_actix::handlers::jwks_cache::JwksCache;
    use oauth2_actix::handlers::oauth;
    use oauth2_core::models::key_set::KeySet;
    use rsa::pkcs1::EncodeRsaPrivateKey;
    use rsa::traits::PublicKeyParts;
    use rsa::{RsaPrivateKey, RsaPublicKey};
    use serde_json::json;

    // Generate an RSA key pair for signing the JAR.
    let mut rng = rand_core::OsRng;
    let private_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
    let public_key = RsaPublicKey::from(&private_key);

    // Build a JWKS document with the public key.
    let n_bytes = public_key.n().to_bytes_be();
    let e_bytes = public_key.e().to_bytes_be();
    let n_b64 = general_purpose::URL_SAFE_NO_PAD.encode(&n_bytes);
    let e_b64 = general_purpose::URL_SAFE_NO_PAD.encode(&e_bytes);
    let jwks = json!({
        "keys": [
            {
                "kty": "RSA",
                "kid": "jar-key-1",
                "use": "sig",
                "alg": "RS256",
                "n": n_b64,
                "e": e_b64,
            }
        ]
    });

    // Start a mock HTTP server serving the JWKS with Cache-Control: max-age=300.
    let server = MockServer::start();
    let jwks_mock = server.mock(|when, then| {
        when.method(GET).path("/jwks");
        then.status(200)
            .header("Content-Type", "application/json")
            .header("Cache-Control", "max-age=300")
            .json_body(jwks);
    });

    // Build a client with jwks_uri pointing to the mock server.
    let mut client = Client::new(
        "jar-rs256-client".to_string(),
        "".to_string(), // No client_secret for private_key_jwt
        vec!["https://app.example/cb".to_string()],
        vec!["authorization_code".to_string()],
        "read".to_string(),
        "JAR RS256 Test Client".to_string(),
    );
    client.token_endpoint_auth_method = "private_key_jwt".to_string();
    client.jwks_uri = format!("{}/jwks", server.base_url());

    let (token_actor, client_actor, auth_actor, jwt_secret, metrics, oidc_config) =
        setup_rfc9700_context(vec![client], "https://auth.example.com").await;

    let keyset = Arc::new(RwLock::new(KeySet::default()));
    // JwksCache is Clone + Send + Sync (internally Arc<Mutex<...>>); register the bare
    // type as Actix data so the handler's `Option<web::Data<JwksCache>>` extractor matches.
    let jwks_cache = JwksCache::default();
    let session_key = Key::generate();

    let app = test::init_service(
        App::new()
            .wrap(SessionMiddleware::new(
                CookieSessionStore::default(),
                session_key.clone(),
            ))
            .app_data(web::Data::new(token_actor))
            .app_data(web::Data::new(client_actor))
            .app_data(web::Data::new(auth_actor))
            .app_data(web::Data::new(jwt_secret))
            .app_data(web::Data::new(metrics))
            .app_data(web::Data::new(oidc_config))
            .app_data(web::Data::new(keyset))
            .app_data(web::Data::new(jwks_cache))
            .app_data(web::Data::new(false)) // stateless_validation
            .route("/test/set-session", web::get().to(test_set_session))
            .service(
                web::scope("/oauth")
                    .route("/authorize", web::get().to(oauth::authorize))
                    .route("/authorize", web::post().to(oauth::authorize)),
            ),
    )
    .await;

    // Set up session.
    let resp = test::call_service(
        &app,
        test::TestRequest::get()
            .uri("/test/set-session")
            .to_request(),
    )
    .await;
    let session_cookie = extract_session_cookie(&resp);

    // First JAR request with state="jar-state-1".
    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let challenge = s256(verifier);
    let jar_claims_1 = json!({
        "iss": "jar-rs256-client",
        "aud": "https://auth.example.com/oauth/authorize",
        "response_type": "code",
        "client_id": "jar-rs256-client",
        "redirect_uri": "https://app.example/cb",
        "state": "jar-state-1",
        "scope": "read",
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "exp": (chrono::Utc::now().timestamp() + 300),
        "iat": chrono::Utc::now().timestamp(),
    });
    let private_key_pem = private_key
        .to_pkcs1_pem(rsa::pkcs8::LineEnding::LF)
        .unwrap();
    let mut jar_header_1 = JwtHeader::new(Algorithm::RS256);
    jar_header_1.kid = Some("jar-key-1".to_string());
    let jar_jwt_1 = encode(
        &jar_header_1,
        &jar_claims_1,
        &EncodingKey::from_rsa_pem(private_key_pem.as_bytes()).unwrap(),
    )
    .unwrap();

    let req1 = test::TestRequest::get()
        .uri(&format!(
            "/oauth/authorize?client_id=jar-rs256-client&redirect_uri=https://app.example/cb&response_type=code&request={}",
            jar_jwt_1
        ))
        .insert_header(("Cookie", session_cookie.as_str()))
        .to_request();

    let resp1 = test::call_service(&app, req1).await;
    let status1 = resp1.status();
    if status1 != 302 && status1 != 303 {
        let body = test::read_body(resp1).await;
        panic!(
            "Expected 302/303 redirect for first JAR request, got {}: {}",
            status1,
            String::from_utf8_lossy(&body)
        );
    }
    // JWKS endpoint should have been called once.
    jwks_mock.assert_calls(1);

    // Second JAR request with state="jar-state-2" (different state to distinguish).
    let jar_claims_2 = json!({
        "iss": "jar-rs256-client",
        "aud": "https://auth.example.com/oauth/authorize",
        "response_type": "code",
        "client_id": "jar-rs256-client",
        "redirect_uri": "https://app.example/cb",
        "state": "jar-state-2",
        "scope": "read",
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "exp": (chrono::Utc::now().timestamp() + 300),
        "iat": chrono::Utc::now().timestamp(),
    });
    let jar_jwt_2 = encode(
        &jar_header_1,
        &jar_claims_2,
        &EncodingKey::from_rsa_pem(private_key_pem.as_bytes()).unwrap(),
    )
    .unwrap();

    let req2 = test::TestRequest::get()
        .uri(&format!(
            "/oauth/authorize?client_id=jar-rs256-client&redirect_uri=https://app.example/cb&response_type=code&request={}",
            jar_jwt_2
        ))
        .insert_header(("Cookie", session_cookie.as_str()))
        .to_request();

    let resp2 = test::call_service(&app, req2).await;
    let status2 = resp2.status();
    assert!(
        status2 == 302 || status2 == 303,
        "Expected 302/303 redirect for second JAR request, got {}",
        status2
    );
    // JWKS endpoint should still have been called only once (cache hit).
    jwks_mock.assert_calls(1);
}
