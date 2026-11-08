//! Regression tests mirroring oauth2-conformance scenarios (contract main
//! dccd338, `scenarios/token-lifecycle/**`) that were flagged as
//! `reference-deviation` against this Rust reference SUT.
//!
//! See docs/token-lifecycle-coverage.md in the oauth2-conformance repo for
//! the authoritative scenario text. These tests reproduce the same HTTP
//! sequences directly against the actix handlers.

use actix::{Actor, Addr};
use actix_session::{storage::CookieSessionStore, Session, SessionMiddleware};
use actix_web::{cookie::Key, test, web, App, HttpResponse};
use std::sync::Arc;
use tokio::sync::RwLock;

use oauth2_actix::actors::TokenActorPool;
use oauth2_actix::handlers::wellknown::OidcConfig;
use oauth2_core::{Client, IntrospectionResponse, OAuth2Error, TokenResponse, User};
use oauth2_observability::Metrics;

fn s256(verifier: &str) -> String {
    use base64::{engine::general_purpose, Engine as _};
    use sha2::{Digest, Sha256};
    general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

fn basic_auth_header(client_id: &str, client_secret: &str) -> String {
    use base64::{engine::general_purpose, Engine as _};
    format!(
        "Basic {}",
        general_purpose::STANDARD.encode(format!("{client_id}:{client_secret}"))
    )
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

async fn setup_context(
    clients: Vec<Client>,
    issuer: &str,
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

/// token-lifecycle.client-credentials.no-client-auth
///
/// RFC 6749 §5.2: a request with no client authentication is `invalid_client`
/// (401), not `invalid_request` (400).
#[actix_web::test]
async fn client_credentials_no_client_auth_is_401_invalid_client() {
    let client = Client::new(
        "client-cc".to_string(),
        "test-only-cc-secret".to_string(),
        vec![],
        vec!["client_credentials".to_string()],
        "read".to_string(),
        "test".to_string(),
    );

    let (token_actor, client_actor, auth_actor, jwt_secret, metrics, oidc_config) =
        setup_context(vec![client], "http://localhost").await;
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
            .set_form([("grant_type", "client_credentials")])
            .to_request(),
    )
    .await;

    assert_eq!(
        resp.status(),
        401,
        "client_credentials with no client auth must be 401"
    );
    let body: OAuth2Error = test::read_body_json(resp).await;
    assert_eq!(body.error, "invalid_client");
}

/// token-lifecycle.refresh.no-client-authentication
///
/// RFC 6749 §6: a confidential client MUST authenticate on refresh. Rotating
/// the token with no authentication would be a real defect.
#[actix_web::test]
async fn refresh_with_no_client_authentication_is_401_invalid_client() {
    let client = Client::new(
        "client-a".to_string(),
        "test-only-secret".to_string(),
        vec!["https://client.example/callback".to_string()],
        vec![
            "authorization_code".to_string(),
            "refresh_token".to_string(),
        ],
        "read".to_string(),
        "test".to_string(),
    );

    let (token_actor, client_actor, auth_actor, jwt_secret, metrics, oidc_config) =
        setup_context(vec![client], "http://localhost").await;
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
                "/oauth/authorize?response_type=code&client_id=client-a\
                 &redirect_uri=https%3A%2F%2Fclient.example%2Fcallback&scope=read\
                 &state=s-gen&code_challenge={challenge}&code_challenge_method=S256"
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

    let token_resp = test::call_service(
        &app,
        test::TestRequest::post()
            .uri("/oauth/token")
            .insert_header((
                "authorization",
                basic_auth_header("client-a", "test-only-secret"),
            ))
            .set_form([
                ("grant_type", "authorization_code"),
                ("code", code.as_str()),
                ("redirect_uri", "https://client.example/callback"),
                ("code_verifier", verifier),
            ])
            .to_request(),
    )
    .await;
    assert_eq!(token_resp.status(), 200);
    let body: TokenResponse = test::read_body_json(token_resp).await;
    let refresh_token = body.refresh_token.expect("refresh_token");

    // No client authentication at all on the refresh request.
    let no_auth_resp = test::call_service(
        &app,
        test::TestRequest::post()
            .uri("/oauth/token")
            .set_form([
                ("grant_type", "refresh_token"),
                ("refresh_token", refresh_token.as_str()),
            ])
            .to_request(),
    )
    .await;

    assert_eq!(
        no_auth_resp.status(),
        401,
        "refresh_token grant with no client authentication must be 401"
    );
    let err: OAuth2Error = test::read_body_json(no_auth_resp).await;
    assert_eq!(err.error, "invalid_client");
}

/// token-lifecycle.revocation.cross-client
///
/// RFC 7009 §2.1: a client revoking another client's token is refused and
/// the token stays active.
#[actix_web::test]
async fn revoke_refuses_to_revoke_another_clients_token() {
    let client_a = Client::new(
        "client-a".to_string(),
        "test-only-secret".to_string(),
        vec!["https://client.example/callback".to_string()],
        vec![
            "authorization_code".to_string(),
            "refresh_token".to_string(),
        ],
        "read".to_string(),
        "test".to_string(),
    );
    let client_cc = Client::new(
        "client-cc".to_string(),
        "test-only-cc-secret".to_string(),
        vec![],
        vec!["client_credentials".to_string()],
        "read".to_string(),
        "test".to_string(),
    );

    let (token_actor, client_actor, auth_actor, jwt_secret, metrics, oidc_config) =
        setup_context(vec![client_a, client_cc], "http://localhost").await;
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
                "/oauth/authorize?response_type=code&client_id=client-a\
                 &redirect_uri=https%3A%2F%2Fclient.example%2Fcallback&scope=read\
                 &state=s-gen&code_challenge={challenge}&code_challenge_method=S256"
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

    let token_resp = test::call_service(
        &app,
        test::TestRequest::post()
            .uri("/oauth/token")
            .insert_header((
                "authorization",
                basic_auth_header("client-a", "test-only-secret"),
            ))
            .set_form([
                ("grant_type", "authorization_code"),
                ("code", code.as_str()),
                ("redirect_uri", "https://client.example/callback"),
                ("code_verifier", verifier),
            ])
            .to_request(),
    )
    .await;
    assert_eq!(token_resp.status(), 200);
    let body: TokenResponse = test::read_body_json(token_resp).await;
    let access_token = body.access_token;

    // client-cc (a different client) tries to revoke client-a's access token.
    let revoke_resp = test::call_service(
        &app,
        test::TestRequest::post()
            .uri("/oauth/revoke")
            .insert_header((
                "authorization",
                basic_auth_header("client-cc", "test-only-cc-secret"),
            ))
            .set_form([("token", access_token.as_str())])
            .to_request(),
    )
    .await;
    assert_eq!(
        revoke_resp.status(),
        400,
        "revoking another client's token must be refused"
    );

    // The token must still be active.
    let intro_resp = test::call_service(
        &app,
        test::TestRequest::post()
            .uri("/oauth/introspect")
            .insert_header((
                "authorization",
                basic_auth_header("client-a", "test-only-secret"),
            ))
            .set_form([("token", access_token.as_str())])
            .to_request(),
    )
    .await;
    assert_eq!(intro_resp.status(), 200);
    let intro: IntrospectionResponse = test::read_body_json(intro_resp).await;
    assert!(
        intro.active,
        "token must stay active after a refused cross-client revocation"
    );
}

/// token-lifecycle.revocation.refresh-cascades-to-access
///
/// RFC 7009 §2.1 (SHOULD): revoking a refresh token also invalidates the
/// access token of the same grant.
#[actix_web::test]
async fn revoke_refresh_token_cascades_to_access_token() {
    let client = Client::new(
        "client-a".to_string(),
        "test-only-secret".to_string(),
        vec!["https://client.example/callback".to_string()],
        vec![
            "authorization_code".to_string(),
            "refresh_token".to_string(),
        ],
        "read".to_string(),
        "test".to_string(),
    );

    let (token_actor, client_actor, auth_actor, jwt_secret, metrics, oidc_config) =
        setup_context(vec![client], "http://localhost").await;
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
                "/oauth/authorize?response_type=code&client_id=client-a\
                 &redirect_uri=https%3A%2F%2Fclient.example%2Fcallback&scope=read\
                 &state=s-gen&code_challenge={challenge}&code_challenge_method=S256"
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

    let token_resp = test::call_service(
        &app,
        test::TestRequest::post()
            .uri("/oauth/token")
            .insert_header((
                "authorization",
                basic_auth_header("client-a", "test-only-secret"),
            ))
            .set_form([
                ("grant_type", "authorization_code"),
                ("code", code.as_str()),
                ("redirect_uri", "https://client.example/callback"),
                ("code_verifier", verifier),
            ])
            .to_request(),
    )
    .await;
    assert_eq!(token_resp.status(), 200);
    let body: TokenResponse = test::read_body_json(token_resp).await;
    let access_token = body.access_token;
    let refresh_token = body.refresh_token.expect("refresh_token");

    let revoke_resp = test::call_service(
        &app,
        test::TestRequest::post()
            .uri("/oauth/revoke")
            .insert_header((
                "authorization",
                basic_auth_header("client-a", "test-only-secret"),
            ))
            .set_form([
                ("token", refresh_token.as_str()),
                ("token_type_hint", "refresh_token"),
            ])
            .to_request(),
    )
    .await;
    assert_eq!(revoke_resp.status(), 200);

    let intro_resp = test::call_service(
        &app,
        test::TestRequest::post()
            .uri("/oauth/introspect")
            .insert_header((
                "authorization",
                basic_auth_header("client-a", "test-only-secret"),
            ))
            .set_form([("token", access_token.as_str())])
            .to_request(),
    )
    .await;
    assert_eq!(intro_resp.status(), 200);
    let intro: IntrospectionResponse = test::read_body_json(intro_resp).await;
    assert!(
        !intro.active,
        "access token must be inactive after revoking its refresh token"
    );
}
