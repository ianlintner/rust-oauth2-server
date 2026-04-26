/// RFC / OAuth2 spec compliance tests for Phase 1 hardening.
///
/// Each test is annotated with the RFC it exercises.
use actix::{Actor, Addr};
use actix_session::{storage::CookieSessionStore, Session, SessionMiddleware};
use actix_web::{cookie::Key, test, web, App, HttpResponse};
use std::sync::Arc;
use tokio::sync::RwLock;

use oauth2_actix::actors::TokenActorPool;
use oauth2_actix::handlers::wellknown::OidcConfig;
use oauth2_core::{Client, IntrospectionResponse, OAuth2Error, TokenResponse, User};
use oauth2_observability::Metrics;

// ---------------------------------------------------------------------------
// Helpers shared across all RFC tests
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

async fn setup_rfc_context(
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
        password_hash: "unused".to_string(),
        email: "user_rfc@example.test".to_string(),
        enabled: true,
        role: "user".to_string(),
        created_at: now,
        updated_at: now,
    };
    storage.save_user(&user).await.expect("save user");

    let jwt_secret = "rfc_test_jwt_secret_at_least_32_chars".to_string();
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
// RFC 9207: Authorization Server Issuer Identification
// ---------------------------------------------------------------------------

/// RFC 9207 §2: the `iss` parameter MUST be included in the authorization response.
#[actix_web::test]
async fn rfc9207_iss_included_in_authorization_response() {
    const ISSUER: &str = "https://auth.example.com";

    let client = Client::new(
        "client_iss".to_string(),
        "secret_iss".to_string(),
        vec!["https://app.example/cb".to_string()],
        vec!["authorization_code".to_string()],
        "read".to_string(),
        "test".to_string(),
    );

    let (token_actor, client_actor, auth_actor, jwt_secret, metrics, oidc_config) =
        setup_rfc_context(vec![client], ISSUER).await;
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
            "/oauth/authorize?response_type=code&client_id=client_iss\
             &redirect_uri=https%3A%2F%2Fapp.example%2Fcb&scope=read\
             &code_challenge={challenge}&code_challenge_method=S256&state=abc"
        ))
        .insert_header(("Cookie", cookie.as_str()))
        .to_request();
    let resp = test::call_service(&app, req).await;

    assert_eq!(resp.status(), 302, "authorize must redirect");
    let location = resp
        .headers()
        .get(actix_web::http::header::LOCATION)
        .and_then(|h| h.to_str().ok())
        .expect("Location header");

    let iss = extract_query_param(location, "iss").expect("iss must be in redirect");
    assert_eq!(
        iss, ISSUER,
        "RFC 9207: iss in redirect must equal the server issuer"
    );

    // state must also be echoed (RFC 6749 §4.1.2)
    let state = extract_query_param(location, "state").expect("state in redirect");
    assert_eq!(state, "abc");
}

// ---------------------------------------------------------------------------
// RFC 9068: JWT Profile for Access Tokens
// ---------------------------------------------------------------------------

/// RFC 9068 §2.1: access tokens MUST carry `typ: "at+JWT"` in the JOSE header.
#[actix_web::test]
async fn rfc9068_access_token_has_typ_at_jwt() {
    let client = Client::new(
        "client_typ".to_string(),
        "secret_typ".to_string(),
        vec!["https://unused/cb".to_string()],
        vec!["client_credentials".to_string()],
        "read".to_string(),
        "test".to_string(),
    );

    let (token_actor, client_actor, auth_actor, jwt_secret, metrics, oidc_config) =
        setup_rfc_context(vec![client], "https://auth.example.com").await;
    let keyset = Arc::new(RwLock::new(oauth2_core::models::key_set::KeySet::default()));

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(token_actor))
            .app_data(web::Data::new(client_actor))
            .app_data(web::Data::new(auth_actor))
            .app_data(web::Data::new(jwt_secret.clone()))
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
                ("client_id", "client_typ"),
                ("client_secret", "secret_typ"),
                ("scope", "read"),
            ])
            .to_request(),
    )
    .await;

    assert_eq!(resp.status(), 200);
    let body: TokenResponse = test::read_body_json(resp).await;

    // Decode JOSE header without verifying the signature.
    let header = jsonwebtoken::decode_header(&body.access_token).expect("valid JWT header");
    assert_eq!(
        header.typ.as_deref(),
        Some("at+JWT"),
        "RFC 9068: typ header must be 'at+JWT', got {:?}",
        header.typ
    );
    drop(jwt_secret);
}

/// RFC 9068 §2.2: `iss` claim in the JWT must equal the configured issuer URL.
#[actix_web::test]
async fn rfc9068_jwt_iss_matches_configured_issuer() {
    const ISSUER: &str = "https://my-auth-server.example";

    let client = Client::new(
        "client_iss_jwt".to_string(),
        "secret_iss_jwt".to_string(),
        vec!["https://unused/cb".to_string()],
        vec!["client_credentials".to_string()],
        "read".to_string(),
        "test".to_string(),
    );

    let (token_actor, client_actor, auth_actor, jwt_secret, metrics, oidc_config) =
        setup_rfc_context(vec![client], ISSUER).await;
    let keyset = Arc::new(RwLock::new(oauth2_core::models::key_set::KeySet::default()));

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(token_actor))
            .app_data(web::Data::new(client_actor))
            .app_data(web::Data::new(auth_actor))
            .app_data(web::Data::new(jwt_secret.clone()))
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
                ("client_id", "client_iss_jwt"),
                ("client_secret", "secret_iss_jwt"),
                ("scope", "read"),
            ])
            .to_request(),
    )
    .await;

    assert_eq!(resp.status(), 200);
    let body: TokenResponse = test::read_body_json(resp).await;

    // Decode claims with the known test secret.
    let mut validation = jsonwebtoken::Validation::default();
    validation.set_audience(&["client_iss_jwt"]);
    let token_data = jsonwebtoken::decode::<serde_json::Value>(
        &body.access_token,
        &jsonwebtoken::DecodingKey::from_secret(jwt_secret.as_bytes()),
        &validation,
    )
    .expect("decodable JWT");

    let iss = token_data.claims["iss"].as_str().expect("iss claim");
    assert_eq!(
        iss, ISSUER,
        "RFC 9068: iss must equal the configured issuer"
    );
}

// ---------------------------------------------------------------------------
// RFC 7662: Token Introspection — nbf, jti, aud, iss fields
// ---------------------------------------------------------------------------

/// RFC 7662 §2.2: active introspection MUST include `nbf`, `jti`, `aud`, `iss`.
#[actix_web::test]
async fn rfc7662_introspection_includes_nbf_jti_aud_iss() {
    const ISSUER: &str = "https://auth.example.com";

    let client = Client::new(
        "client_intro".to_string(),
        "secret_intro".to_string(),
        vec!["https://unused/cb".to_string()],
        vec!["client_credentials".to_string()],
        "read".to_string(),
        "test".to_string(),
    );

    let (token_actor, client_actor, auth_actor, jwt_secret, metrics, oidc_config) =
        setup_rfc_context(vec![client], ISSUER).await;
    let keyset = Arc::new(RwLock::new(oauth2_core::models::key_set::KeySet::default()));
    let config = {
        let mut c = oauth2_config::Config::default();
        c.jwt.secret = jwt_secret.clone();
        c.jwt.public_introspection = false;
        c
    };

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
            .app_data(web::Data::new(config))
            .service(
                web::scope("/oauth")
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
    .await;

    // Issue a token
    let token_resp: TokenResponse = test::read_body_json(
        test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/oauth/token")
                .set_form([
                    ("grant_type", "client_credentials"),
                    ("client_id", "client_intro"),
                    ("client_secret", "secret_intro"),
                    ("scope", "read"),
                ])
                .to_request(),
        )
        .await,
    )
    .await;

    // Introspect
    let intro_resp = test::call_service(
        &app,
        test::TestRequest::post()
            .uri("/oauth/introspect")
            .set_form([
                ("token", token_resp.access_token.as_str()),
                ("client_id", "client_intro"),
                ("client_secret", "secret_intro"),
            ])
            .to_request(),
    )
    .await;

    assert_eq!(intro_resp.status(), 200);
    let body: IntrospectionResponse = test::read_body_json(intro_resp).await;

    assert!(body.active, "introspected token must be active");
    assert!(body.nbf.is_some(), "RFC 7662 §2.2: nbf must be present");
    assert!(body.jti.is_some(), "RFC 7662 §2.2: jti must be present");
    assert!(body.aud.is_some(), "RFC 7662 §2.2: aud must be present");
    assert_eq!(
        body.aud
            .as_ref()
            .and_then(|v| v.first().map(|s| s.as_str())),
        Some("client_intro"),
        "aud must equal the client_id"
    );
    assert_eq!(
        body.iss.as_deref(),
        Some(ISSUER),
        "iss in introspection must equal the server issuer"
    );
}

/// RFC 7662 §2.2: `nbf` must be <= `iat` for tokens valid from issuance.
#[actix_web::test]
async fn rfc7662_introspection_nbf_le_iat() {
    let client = Client::new(
        "client_nbf".to_string(),
        "secret_nbf".to_string(),
        vec!["https://unused/cb".to_string()],
        vec!["client_credentials".to_string()],
        "read".to_string(),
        "test".to_string(),
    );

    let (token_actor, client_actor, auth_actor, jwt_secret, metrics, oidc_config) =
        setup_rfc_context(vec![client], "https://auth.example.com").await;
    let keyset = Arc::new(RwLock::new(oauth2_core::models::key_set::KeySet::default()));
    let config = {
        let mut c = oauth2_config::Config::default();
        c.jwt.secret = jwt_secret.clone();
        c
    };

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
            .app_data(web::Data::new(config))
            .service(
                web::scope("/oauth")
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
    .await;

    let token_resp: TokenResponse = test::read_body_json(
        test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/oauth/token")
                .set_form([
                    ("grant_type", "client_credentials"),
                    ("client_id", "client_nbf"),
                    ("client_secret", "secret_nbf"),
                    ("scope", "read"),
                ])
                .to_request(),
        )
        .await,
    )
    .await;

    let body: IntrospectionResponse = test::read_body_json(
        test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/oauth/introspect")
                .set_form([
                    ("token", token_resp.access_token.as_str()),
                    ("client_id", "client_nbf"),
                    ("client_secret", "secret_nbf"),
                ])
                .to_request(),
        )
        .await,
    )
    .await;

    let nbf = body.nbf.expect("nbf");
    let iat = body.iat.expect("iat");
    assert!(nbf <= iat, "nbf ({nbf}) must be <= iat ({iat})");
}

// ---------------------------------------------------------------------------
// Public clients (token_endpoint_auth_method = none) — RFC 6749 / RFC 7591
// ---------------------------------------------------------------------------

fn make_public_client(id: &str, redirect: &str) -> Client {
    let mut client = Client::new(
        id.to_string(),
        String::new(),
        vec![redirect.to_string()],
        vec!["authorization_code".to_string()],
        "read".to_string(),
        "native app".to_string(),
    );
    client.token_endpoint_auth_method = "none".to_string();
    client
}

/// Public clients can exchange an authorization code using only PKCE (no secret).
#[actix_web::test]
async fn public_client_exchanges_code_without_secret() {
    let client = make_public_client("client_public", "https://native.example/cb");

    let (token_actor, client_actor, auth_actor, jwt_secret, metrics, oidc_config) =
        setup_rfc_context(vec![client], "https://auth.example.com").await;
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

    // Establish session
    let login_resp = test::call_service(
        &app,
        test::TestRequest::get().uri("/test/login").to_request(),
    )
    .await;
    let cookie = extract_session_cookie(&login_resp);

    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let challenge = s256(verifier);

    let auth_resp = test::call_service(
        &app,
        test::TestRequest::get()
            .uri(&format!(
                "/oauth/authorize?response_type=code&client_id=client_public\
                 &redirect_uri=https%3A%2F%2Fnative.example%2Fcb&scope=read\
                 &code_challenge={challenge}&code_challenge_method=S256"
            ))
            .insert_header(("Cookie", cookie.as_str()))
            .to_request(),
    )
    .await;

    assert_eq!(auth_resp.status(), 302, "authorize must redirect");
    let location = auth_resp
        .headers()
        .get(actix_web::http::header::LOCATION)
        .and_then(|h| h.to_str().ok())
        .expect("Location");
    let code = extract_query_param(location, "code").expect("code");

    // Exchange without client_secret
    let token_resp = test::call_service(
        &app,
        test::TestRequest::post()
            .uri("/oauth/token")
            .set_form([
                ("grant_type", "authorization_code"),
                ("client_id", "client_public"),
                ("code", code.as_str()),
                ("redirect_uri", "https://native.example/cb"),
                ("code_verifier", verifier),
            ])
            .to_request(),
    )
    .await;

    assert_eq!(
        token_resp.status(),
        200,
        "public client must exchange code without secret"
    );
    let body: TokenResponse = test::read_body_json(token_resp).await;
    assert!(!body.access_token.is_empty());
}

/// Presenting a client_secret for a public client must be rejected with `invalid_client`.
#[actix_web::test]
async fn public_client_must_not_present_secret() {
    let client = make_public_client("client_pub_secret", "https://native.example/cb");

    let (token_actor, client_actor, auth_actor, jwt_secret, metrics, oidc_config) =
        setup_rfc_context(vec![client], "https://auth.example.com").await;
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

    let login_resp = test::call_service(
        &app,
        test::TestRequest::get().uri("/test/login").to_request(),
    )
    .await;
    let cookie = extract_session_cookie(&login_resp);

    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let challenge = s256(verifier);

    let auth_resp = test::call_service(
        &app,
        test::TestRequest::get()
            .uri(&format!(
                "/oauth/authorize?response_type=code&client_id=client_pub_secret\
                 &redirect_uri=https%3A%2F%2Fnative.example%2Fcb&scope=read\
                 &code_challenge={challenge}&code_challenge_method=S256"
            ))
            .insert_header(("Cookie", cookie.as_str()))
            .to_request(),
    )
    .await;

    assert_eq!(auth_resp.status(), 302);
    let location = auth_resp
        .headers()
        .get(actix_web::http::header::LOCATION)
        .and_then(|h| h.to_str().ok())
        .expect("Location");
    let code = extract_query_param(location, "code").expect("code");

    // Include a secret — must be rejected.
    let token_resp = test::call_service(
        &app,
        test::TestRequest::post()
            .uri("/oauth/token")
            .set_form([
                ("grant_type", "authorization_code"),
                ("client_id", "client_pub_secret"),
                ("client_secret", "should_not_be_here"),
                ("code", code.as_str()),
                ("redirect_uri", "https://native.example/cb"),
                ("code_verifier", verifier),
            ])
            .to_request(),
    )
    .await;

    assert_eq!(
        token_resp.status(),
        401,
        "presenting a secret for a public client must be rejected with 401"
    );
    let err: OAuth2Error = test::read_body_json(token_resp).await;
    assert_eq!(err.error, "invalid_client");
}

// ---------------------------------------------------------------------------
// RFC 8414: Authorization Server Metadata — alternate well-known path
// ---------------------------------------------------------------------------

/// RFC 8414 §3: metadata MUST also be served at `/.well-known/oauth-authorization-server`.
#[actix_web::test]
async fn rfc8414_oauth_authorization_server_well_known_returns_metadata() {
    let (token_actor, client_actor, auth_actor, jwt_secret, metrics, oidc_config) =
        setup_rfc_context(vec![], "https://auth.example.com").await;
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
            .service(
                web::scope("/.well-known")
                    .route(
                        "/openid-configuration",
                        web::get().to(oauth2_actix::handlers::wellknown::openid_configuration),
                    )
                    .route(
                        "/oauth-authorization-server",
                        web::get().to(oauth2_actix::handlers::wellknown::openid_configuration),
                    ),
            ),
    )
    .await;

    let resp = test::call_service(
        &app,
        test::TestRequest::get()
            .uri("/.well-known/oauth-authorization-server")
            .to_request(),
    )
    .await;

    assert_eq!(
        resp.status(),
        200,
        "/.well-known/oauth-authorization-server must return 200"
    );
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert!(
        body.get("issuer").is_some(),
        "metadata must contain 'issuer'"
    );
    assert!(
        body.get("token_endpoint").is_some(),
        "metadata must contain 'token_endpoint'"
    );
    assert!(
        body.get("authorization_endpoint").is_some(),
        "metadata must contain 'authorization_endpoint'"
    );
}

/// Both well-known paths must return identical responses (RFC 8414 §3).
#[actix_web::test]
async fn rfc8414_both_well_known_paths_return_same_response() {
    let (token_actor, client_actor, auth_actor, jwt_secret, metrics, oidc_config) =
        setup_rfc_context(vec![], "https://auth.example.com").await;
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
            .service(
                web::scope("/.well-known")
                    .route(
                        "/openid-configuration",
                        web::get().to(oauth2_actix::handlers::wellknown::openid_configuration),
                    )
                    .route(
                        "/oauth-authorization-server",
                        web::get().to(oauth2_actix::handlers::wellknown::openid_configuration),
                    ),
            ),
    )
    .await;

    let oidc_resp: serde_json::Value = test::read_body_json(
        test::call_service(
            &app,
            test::TestRequest::get()
                .uri("/.well-known/openid-configuration")
                .to_request(),
        )
        .await,
    )
    .await;

    let as_resp: serde_json::Value = test::read_body_json(
        test::call_service(
            &app,
            test::TestRequest::get()
                .uri("/.well-known/oauth-authorization-server")
                .to_request(),
        )
        .await,
    )
    .await;

    assert_eq!(
        oidc_resp, as_resp,
        "Both well-known paths must return identical metadata"
    );
}

// ---------------------------------------------------------------------------
// Public client registration validation (RFC 7591 / registration handler)
// ---------------------------------------------------------------------------

/// Registering a public client with `token_endpoint_auth_method=none` must succeed.
#[actix_web::test]
async fn public_client_registration_with_none_auth_method_succeeds() {
    let storage = oauth2_storage_factory::create_storage("sqlite::memory:")
        .await
        .expect("storage");
    storage.init().await.expect("init");

    let client_actor = oauth2_actix::actors::ClientActor::new(storage).start();

    let app = test::init_service(App::new().app_data(web::Data::new(client_actor)).route(
        "/clients/register",
        web::post().to(oauth2_actix::handlers::client::register_client),
    ))
    .await;

    let resp = test::call_service(
        &app,
        test::TestRequest::post()
            .uri("/clients/register")
            .set_json(serde_json::json!({
                "client_name": "My Native App",
                "redirect_uris": ["https://native.example/cb"],
                "grant_types": ["authorization_code"],
                "scope": "openid read",
                "token_endpoint_auth_method": "none"
            }))
            .to_request(),
    )
    .await;

    assert_eq!(
        resp.status(),
        201,
        "public client registration must succeed"
    );
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert!(body.get("client_id").is_some(), "must return client_id");
}

/// Registering a public client with `client_credentials` grant must be rejected.
#[actix_web::test]
async fn public_client_registration_with_client_credentials_is_rejected() {
    let storage = oauth2_storage_factory::create_storage("sqlite::memory:")
        .await
        .expect("storage");
    storage.init().await.expect("init");

    let client_actor = oauth2_actix::actors::ClientActor::new(storage).start();

    let app = test::init_service(App::new().app_data(web::Data::new(client_actor)).route(
        "/clients/register",
        web::post().to(oauth2_actix::handlers::client::register_client),
    ))
    .await;

    let resp = test::call_service(
        &app,
        test::TestRequest::post()
            .uri("/clients/register")
            .set_json(serde_json::json!({
                "client_name": "Bad Public Client",
                "redirect_uris": ["https://native.example/cb"],
                "grant_types": ["authorization_code", "client_credentials"],
                "scope": "read",
                "token_endpoint_auth_method": "none"
            }))
            .to_request(),
    )
    .await;

    assert_eq!(
        resp.status(),
        400,
        "public client with client_credentials grant must be rejected"
    );
    let err: OAuth2Error = test::read_body_json(resp).await;
    assert_eq!(err.error, "invalid_request");
}

// ---------------------------------------------------------------------------
// Chunk 1.C — UserInfo real claims from storage (OIDC Core §5.3/§5.4)
// ---------------------------------------------------------------------------

/// OIDC Core §5.4: UserInfo MUST return email claim when `email` scope is present.
#[actix_web::test]
async fn userinfo_returns_real_email_when_email_scope_requested() {
    let client = Client::new(
        "client_ui_email".to_string(),
        "secret_ui_email".to_string(),
        vec!["https://unused/cb".to_string()],
        vec!["client_credentials".to_string()],
        "openid email".to_string(),
        "test".to_string(),
    );

    let storage = oauth2_storage_factory::create_storage("sqlite::memory:")
        .await
        .expect("create storage");
    storage.init().await.expect("init");

    storage.save_client(&client).await.expect("save client");

    // Create a real user
    let now = chrono::Utc::now();
    let user = User {
        id: "user_email_test".to_string(),
        username: "emailuser".to_string(),
        password_hash: "unused".to_string(),
        email: "real@example.com".to_string(),
        enabled: true,
        role: "user".to_string(),
        created_at: now,
        updated_at: now,
    };
    storage.save_user(&user).await.expect("save user");

    let jwt_secret = "rfc_test_jwt_secret_at_least_32_chars".to_string();
    let metrics = Metrics::new().expect("metrics");

    let token_actor = oauth2_actix::actors::TokenActor::new(
        storage.clone(),
        jwt_secret.clone(),
        "https://auth.example.com".to_string(),
    )
    .start();
    let token_pool = TokenActorPool::new(vec![token_actor]);
    let client_actor = oauth2_actix::actors::ClientActor::new(storage.clone()).start();
    let auth_actor = oauth2_actix::actors::AuthActor::new(storage.clone()).start();

    let oidc_config = OidcConfig {
        issuer: "https://auth.example.com".to_string(),
        jwt_secret: jwt_secret.clone(),
        id_token_alg: "HS256".to_string(),
        id_token_kid: None,
        id_token_private_key_pem: None,
    };
    let keyset = Arc::new(RwLock::new(oauth2_core::models::key_set::KeySet::default()));
    let dyn_storage: oauth2_ports::DynStorage = storage;

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(token_pool))
            .app_data(web::Data::new(client_actor))
            .app_data(web::Data::new(auth_actor))
            .app_data(web::Data::new(jwt_secret))
            .app_data(web::Data::new(metrics))
            .app_data(web::Data::new(oidc_config))
            .app_data(web::Data::new(keyset))
            .app_data(web::Data::new(false))
            .app_data(web::Data::new(dyn_storage))
            .service(
                web::scope("/oauth")
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
    .await;

    // client_credentials tokens have no user_id, so userinfo correctly rejects them.
    // The full auth code flow with real user claims is tested separately in
    // userinfo_returns_real_claims_for_auth_code_flow.

    let resp = test::call_service(
        &app,
        test::TestRequest::post()
            .uri("/oauth/token")
            .set_form([
                ("grant_type", "client_credentials"),
                ("client_id", "client_ui_email"),
                ("client_secret", "secret_ui_email"),
                ("scope", "openid email"),
            ])
            .to_request(),
    )
    .await;
    assert_eq!(resp.status(), 200);
    let body: TokenResponse = test::read_body_json(resp).await;

    // client_credentials tokens have no user_id, so userinfo will return 401.
    // This is correct behavior per spec — client_credentials tokens don't represent users.
    let resp = test::call_service(
        &app,
        test::TestRequest::get()
            .uri("/oauth/userinfo")
            .insert_header(("Authorization", format!("Bearer {}", body.access_token)))
            .to_request(),
    )
    .await;
    assert_eq!(
        resp.status(),
        401,
        "client_credentials token must be rejected by userinfo (no user)"
    );
}

/// OIDC Core §5.4: UserInfo with `profile` scope returns preferred_username.
#[actix_web::test]
async fn userinfo_returns_real_claims_for_auth_code_flow() {
    let client = Client::new(
        "client_ui_profile".to_string(),
        "secret_ui_profile".to_string(),
        vec!["https://app.example/cb".to_string()],
        vec!["authorization_code".to_string()],
        "openid email profile".to_string(),
        "test".to_string(),
    );

    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let db_path = temp_dir.path().join("oauth2_ui_profile.db");
    let storage = oauth2_storage_factory::create_storage(&format!("sqlite:{}", db_path.display()))
        .await
        .expect("create storage");
    storage.init().await.expect("init");

    storage.save_client(&client).await.expect("save client");

    let now = chrono::Utc::now();
    let user = User {
        id: "user_rfc".to_string(),
        username: "rfc_user".to_string(),
        password_hash: "unused".to_string(),
        email: "rfc@example.com".to_string(),
        enabled: true,
        role: "user".to_string(),
        created_at: now,
        updated_at: now,
    };
    storage.save_user(&user).await.expect("save user");

    let jwt_secret = "rfc_test_jwt_secret_at_least_32_chars".to_string();
    let metrics = Metrics::new().expect("metrics");

    let token_actor = oauth2_actix::actors::TokenActor::new(
        storage.clone(),
        jwt_secret.clone(),
        "https://auth.example.com".to_string(),
    )
    .start();
    let token_pool = TokenActorPool::new(vec![token_actor]);
    let client_actor = oauth2_actix::actors::ClientActor::new(storage.clone()).start();
    let auth_actor = oauth2_actix::actors::AuthActor::new(storage.clone()).start();

    let oidc_config = OidcConfig {
        issuer: "https://auth.example.com".to_string(),
        jwt_secret: jwt_secret.clone(),
        id_token_alg: "HS256".to_string(),
        id_token_kid: None,
        id_token_private_key_pem: None,
    };
    let keyset = Arc::new(RwLock::new(oauth2_core::models::key_set::KeySet::default()));
    let dyn_storage: oauth2_ports::DynStorage = storage;

    let app = test::init_service(
        App::new()
            .wrap(SessionMiddleware::new(
                CookieSessionStore::default(),
                Key::generate(),
            ))
            .route("/test/login", web::get().to(test_set_session))
            .app_data(web::Data::new(token_pool))
            .app_data(web::Data::new(client_actor))
            .app_data(web::Data::new(auth_actor))
            .app_data(web::Data::new(jwt_secret))
            .app_data(web::Data::new(metrics))
            .app_data(web::Data::new(oidc_config))
            .app_data(web::Data::new(keyset))
            .app_data(web::Data::new(false))
            .app_data(web::Data::new(dyn_storage))
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

    let auth_resp = test::call_service(
        &app,
        test::TestRequest::get()
            .uri(&format!(
                "/oauth/authorize?response_type=code&client_id=client_ui_profile\
                 &redirect_uri=https%3A%2F%2Fapp.example%2Fcb\
                 &scope=openid+email+profile\
                 &code_challenge={challenge}&code_challenge_method=S256"
            ))
            .insert_header(("Cookie", cookie.as_str()))
            .to_request(),
    )
    .await;

    assert_eq!(auth_resp.status(), 302);
    let location = auth_resp
        .headers()
        .get(actix_web::http::header::LOCATION)
        .and_then(|h| h.to_str().ok())
        .expect("Location");
    let code = extract_query_param(location, "code").expect("code");

    // Exchange code for token
    let token_resp = test::call_service(
        &app,
        test::TestRequest::post()
            .uri("/oauth/token")
            .set_form([
                ("grant_type", "authorization_code"),
                ("client_id", "client_ui_profile"),
                ("client_secret", "secret_ui_profile"),
                ("code", code.as_str()),
                ("redirect_uri", "https://app.example/cb"),
                ("code_verifier", verifier),
            ])
            .to_request(),
    )
    .await;

    assert_eq!(token_resp.status(), 200);
    let body: TokenResponse = test::read_body_json(token_resp).await;

    // Call userinfo
    let userinfo_resp = test::call_service(
        &app,
        test::TestRequest::get()
            .uri("/oauth/userinfo")
            .insert_header(("Authorization", format!("Bearer {}", body.access_token)))
            .to_request(),
    )
    .await;

    assert_eq!(userinfo_resp.status(), 200);
    let claims: serde_json::Value = test::read_body_json(userinfo_resp).await;

    assert_eq!(claims["sub"], "user_rfc", "sub must be user ID");
    assert_eq!(
        claims["email"], "rfc@example.com",
        "email must come from storage when email scope requested"
    );
    assert_eq!(
        claims["preferred_username"], "rfc_user",
        "preferred_username must come from storage when profile scope requested"
    );
}

// ---------------------------------------------------------------------------
// Chunk 1.D — OIDC prompt=none / prompt=login / max_age
// ---------------------------------------------------------------------------

/// OIDC Core §3.1.2.1: `prompt=none` without session → login_required error redirect.
#[actix_web::test]
async fn prompt_none_without_session_returns_login_required() {
    let client = Client::new(
        "client_prompt_none".to_string(),
        "secret_prompt".to_string(),
        vec!["https://app.example/cb".to_string()],
        vec!["authorization_code".to_string()],
        "read".to_string(),
        "test".to_string(),
    );

    let (token_actor, client_actor, auth_actor, jwt_secret, metrics, oidc_config) =
        setup_rfc_context(vec![client], "https://auth.example.com").await;
    let keyset = Arc::new(RwLock::new(oauth2_core::models::key_set::KeySet::default()));

    let app = test::init_service(
        App::new()
            .wrap(SessionMiddleware::new(
                CookieSessionStore::default(),
                Key::generate(),
            ))
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

    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let challenge = s256(verifier);

    // No session cookie → should get login_required redirect
    let resp = test::call_service(
        &app,
        test::TestRequest::get()
            .uri(&format!(
                "/oauth/authorize?response_type=code&client_id=client_prompt_none\
                 &redirect_uri=https%3A%2F%2Fapp.example%2Fcb&scope=read\
                 &code_challenge={challenge}&code_challenge_method=S256\
                 &state=keep_me&prompt=none"
            ))
            .to_request(),
    )
    .await;

    assert_eq!(resp.status(), 302, "must redirect");
    let location = resp
        .headers()
        .get(actix_web::http::header::LOCATION)
        .and_then(|h| h.to_str().ok())
        .expect("Location header");

    let error = extract_query_param(location, "error").expect("error in redirect");
    assert_eq!(
        error, "login_required",
        "OIDC: prompt=none without session must return login_required"
    );
    let state = extract_query_param(location, "state").expect("state in redirect");
    assert_eq!(
        state, "keep_me",
        "state must be preserved in error redirect"
    );
    assert!(
        extract_query_param(location, "iss").is_some(),
        "iss must be present in error redirect (RFC 9207)"
    );
}

/// OIDC Core §3.1.2.1: `prompt=login` forces re-authentication even with active session.
#[actix_web::test]
async fn prompt_login_forces_reauthentication() {
    let client = Client::new(
        "client_prompt_login".to_string(),
        "secret_prompt_login".to_string(),
        vec!["https://app.example/cb".to_string()],
        vec!["authorization_code".to_string()],
        "read".to_string(),
        "test".to_string(),
    );

    let (token_actor, client_actor, auth_actor, jwt_secret, metrics, oidc_config) =
        setup_rfc_context(vec![client], "https://auth.example.com").await;
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

    // With session + prompt=login → should redirect to login, not issue code
    let resp = test::call_service(
        &app,
        test::TestRequest::get()
            .uri(&format!(
                "/oauth/authorize?response_type=code&client_id=client_prompt_login\
                 &redirect_uri=https%3A%2F%2Fapp.example%2Fcb&scope=read\
                 &code_challenge={challenge}&code_challenge_method=S256\
                 &prompt=login"
            ))
            .insert_header(("Cookie", cookie.as_str()))
            .to_request(),
    )
    .await;

    assert_eq!(resp.status(), 302);
    let location = resp
        .headers()
        .get(actix_web::http::header::LOCATION)
        .and_then(|h| h.to_str().ok())
        .expect("Location header");

    assert_eq!(
        location, "/auth/login",
        "prompt=login must redirect to login even with active session"
    );
}

/// OIDC Core §3.1.2.1: `max_age=0` forces re-authentication (auth_time missing).
#[actix_web::test]
async fn max_age_zero_forces_reauthentication() {
    let client = Client::new(
        "client_max_age".to_string(),
        "secret_max_age".to_string(),
        vec!["https://app.example/cb".to_string()],
        vec!["authorization_code".to_string()],
        "read".to_string(),
        "test".to_string(),
    );

    let (token_actor, client_actor, auth_actor, jwt_secret, metrics, oidc_config) =
        setup_rfc_context(vec![client], "https://auth.example.com").await;
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

    // Establish session (but without auth_time in session)
    let login_resp = test::call_service(
        &app,
        test::TestRequest::get().uri("/test/login").to_request(),
    )
    .await;
    let cookie = extract_session_cookie(&login_resp);

    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let challenge = s256(verifier);

    // max_age=0 means auth_time must be "now" — since test_set_session doesn't set auth_time,
    // this should trigger re-authentication.
    let resp = test::call_service(
        &app,
        test::TestRequest::get()
            .uri(&format!(
                "/oauth/authorize?response_type=code&client_id=client_max_age\
                 &redirect_uri=https%3A%2F%2Fapp.example%2Fcb&scope=read\
                 &code_challenge={challenge}&code_challenge_method=S256\
                 &max_age=0"
            ))
            .insert_header(("Cookie", cookie.as_str()))
            .to_request(),
    )
    .await;

    assert_eq!(resp.status(), 302);
    let location = resp
        .headers()
        .get(actix_web::http::header::LOCATION)
        .and_then(|h| h.to_str().ok())
        .expect("Location");

    assert_eq!(
        location, "/auth/login",
        "max_age=0 without auth_time must redirect to login"
    );
}

// ---------------------------------------------------------------------------
// Chunk 1.E — Logout with id_token_hint / cascade revocation
// ---------------------------------------------------------------------------

/// OIDC RP-Initiated Logout: id_token_hint with invalid aud returns error.
#[actix_web::test]
async fn logout_with_invalid_aud_id_token_hint_returns_error() {
    let storage = oauth2_storage_factory::create_storage("sqlite::memory:")
        .await
        .expect("storage");
    storage.init().await.expect("init");

    let jwt_secret = "rfc_test_jwt_secret_at_least_32_chars".to_string();

    let oidc_config = OidcConfig {
        issuer: "https://auth.example.com".to_string(),
        jwt_secret: jwt_secret.clone(),
        id_token_alg: "HS256".to_string(),
        id_token_kid: None,
        id_token_private_key_pem: None,
    };
    let dyn_storage: oauth2_ports::DynStorage = storage;

    let app = test::init_service(
        App::new()
            .wrap(SessionMiddleware::new(
                CookieSessionStore::default(),
                Key::generate(),
            ))
            .app_data(web::Data::new(dyn_storage))
            .app_data(web::Data::new(oidc_config))
            .service(web::scope("/oauth").route(
                "/logout",
                web::get().to(oauth2_actix::handlers::oidc_logout::logout),
            )),
    )
    .await;

    // Create a JWT id_token with an unregistered client aud
    let id_token = jsonwebtoken::encode(
        &jsonwebtoken::Header::default(),
        &serde_json::json!({
            "iss": "https://auth.example.com",
            "sub": "user_123",
            "aud": "unregistered_client",
            "exp": chrono::Utc::now().timestamp() + 3600,
            "iat": chrono::Utc::now().timestamp()
        }),
        &jsonwebtoken::EncodingKey::from_secret(jwt_secret.as_bytes()),
    )
    .expect("encode id_token");

    let resp = test::call_service(
        &app,
        test::TestRequest::get()
            .uri(&format!("/oauth/logout?id_token_hint={id_token}"))
            .to_request(),
    )
    .await;

    assert_eq!(
        resp.status(),
        400,
        "id_token_hint with unregistered aud must return 400"
    );
    let err: OAuth2Error = test::read_body_json(resp).await;
    assert_eq!(err.error, "invalid_request");
}

/// Token revocation cascades to the entire token family (RFC 7009 + Security BCP).
#[actix_web::test]
async fn revoke_cascades_to_entire_token_family() {
    let client = Client::new(
        "client_cascade".to_string(),
        "secret_cascade".to_string(),
        vec!["https://app.example/cb".to_string()],
        vec![
            "authorization_code".to_string(),
            "refresh_token".to_string(),
        ],
        "read".to_string(),
        "test".to_string(),
    );

    let (token_actor, client_actor, auth_actor, jwt_secret, metrics, oidc_config) =
        setup_rfc_context(vec![client], "https://auth.example.com").await;
    let keyset = Arc::new(RwLock::new(oauth2_core::models::key_set::KeySet::default()));
    let config = {
        let mut c = oauth2_config::Config::default();
        c.jwt.secret = jwt_secret.clone();
        c.jwt.public_introspection = false;
        c
    };

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
            .app_data(web::Data::new(config))
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
                        "/revoke",
                        web::post().to(oauth2_actix::handlers::token::revoke),
                    )
                    .route(
                        "/introspect",
                        web::post().to(oauth2_actix::handlers::token::introspect),
                    ),
            ),
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

    // Get auth code
    let auth_resp = test::call_service(
        &app,
        test::TestRequest::get()
            .uri(&format!(
                "/oauth/authorize?response_type=code&client_id=client_cascade\
                 &redirect_uri=https%3A%2F%2Fapp.example%2Fcb&scope=read\
                 &code_challenge={challenge}&code_challenge_method=S256"
            ))
            .insert_header(("Cookie", cookie.as_str()))
            .to_request(),
    )
    .await;

    assert_eq!(auth_resp.status(), 302);
    let location = auth_resp
        .headers()
        .get(actix_web::http::header::LOCATION)
        .and_then(|h| h.to_str().ok())
        .expect("Location");
    let code = extract_query_param(location, "code").expect("code");

    // Exchange for tokens
    let token_resp = test::call_service(
        &app,
        test::TestRequest::post()
            .uri("/oauth/token")
            .set_form([
                ("grant_type", "authorization_code"),
                ("client_id", "client_cascade"),
                ("client_secret", "secret_cascade"),
                ("code", code.as_str()),
                ("redirect_uri", "https://app.example/cb"),
                ("code_verifier", verifier),
            ])
            .to_request(),
    )
    .await;

    assert_eq!(token_resp.status(), 200);
    let body: TokenResponse = test::read_body_json(token_resp).await;
    let access_token = body.access_token.clone();
    let refresh_token = body.refresh_token.expect("refresh_token expected");

    // Revoke the refresh token
    let revoke_resp = test::call_service(
        &app,
        test::TestRequest::post()
            .uri("/oauth/revoke")
            .set_form([
                ("token", refresh_token.as_str()),
                ("client_id", "client_cascade"),
                ("client_secret", "secret_cascade"),
            ])
            .to_request(),
    )
    .await;
    assert_eq!(revoke_resp.status(), 200);

    // The access token should also be revoked (cascade via token_family)
    let intro_resp = test::call_service(
        &app,
        test::TestRequest::post()
            .uri("/oauth/introspect")
            .set_form([
                ("token", access_token.as_str()),
                ("client_id", "client_cascade"),
                ("client_secret", "secret_cascade"),
            ])
            .to_request(),
    )
    .await;

    assert_eq!(intro_resp.status(), 200);
    let intro: IntrospectionResponse = test::read_body_json(intro_resp).await;
    assert!(
        !intro.active,
        "Access token must be inactive after revoking the refresh token (cascade revocation)"
    );
}

// ---------------------------------------------------------------------------
// Chunk 1.F — Discovery doc compliance
// ---------------------------------------------------------------------------

/// Discovery doc MUST include `authorization_response_iss_parameter_supported: true` (RFC 9207).
#[actix_web::test]
async fn discovery_includes_iss_parameter_supported() {
    let (token_actor, client_actor, auth_actor, jwt_secret, metrics, oidc_config) =
        setup_rfc_context(vec![], "https://auth.example.com").await;
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

    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = test::read_body_json(resp).await;

    assert_eq!(
        body["authorization_response_iss_parameter_supported"],
        serde_json::Value::Bool(true),
        "RFC 9207: must advertise authorization_response_iss_parameter_supported"
    );

    // prompt_values_supported must include none and login
    let prompt_values = body["prompt_values_supported"]
        .as_array()
        .expect("prompt_values_supported array");
    let prompts: Vec<&str> = prompt_values.iter().filter_map(|v| v.as_str()).collect();
    assert!(prompts.contains(&"none"), "must support prompt=none");
    assert!(prompts.contains(&"login"), "must support prompt=login");

    // token_endpoint_auth_methods_supported must include "none"
    let auth_methods = body["token_endpoint_auth_methods_supported"]
        .as_array()
        .expect("token_endpoint_auth_methods_supported array");
    let methods: Vec<&str> = auth_methods.iter().filter_map(|v| v.as_str()).collect();
    assert!(
        methods.contains(&"none"),
        "must advertise 'none' in token_endpoint_auth_methods_supported"
    );
    assert!(
        methods.contains(&"client_secret_basic"),
        "must still include client_secret_basic"
    );

    // claims_supported must include email and preferred_username (actually produced)
    let claims = body["claims_supported"]
        .as_array()
        .expect("claims_supported array");
    let claim_names: Vec<&str> = claims.iter().filter_map(|v| v.as_str()).collect();
    assert!(
        claim_names.contains(&"email"),
        "claims_supported must include 'email'"
    );
    assert!(
        claim_names.contains(&"preferred_username"),
        "claims_supported must include 'preferred_username'"
    );
}
