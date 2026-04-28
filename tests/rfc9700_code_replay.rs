//! RFC 9700 §2.1.5 — authorization-code replay cascade revocation.
//!
//! Goal: when an authorization code is exchanged a second time, the AS MUST
//! invalidate every access / refresh token that was issued from the original
//! (legitimate) exchange. This test drives the full grant through
//! `/oauth/authorize` → `/oauth/token`, then replays the code and verifies
//! that the previously-issued access token introspects as `active: false`.

use actix::Actor;
use actix_session::{storage::CookieSessionStore, Session, SessionMiddleware};
use actix_web::{cookie::Key, test, web, App, HttpResponse};
use std::sync::Arc;
use tokio::sync::RwLock;

use oauth2_actix::actors::TokenActorPool;
use oauth2_actix::handlers::wellknown::OidcConfig;
use oauth2_core::{Client, IntrospectionResponse, TokenResponse, User};
use oauth2_observability::Metrics;

fn s256(verifier: &str) -> String {
    use base64::{engine::general_purpose, Engine as _};
    use sha2::{Digest, Sha256};
    general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

async fn set_session(session: Session) -> HttpResponse {
    session.insert("user_id", "user_replay").unwrap();
    session.insert("authenticated", true).unwrap();
    HttpResponse::Ok().finish()
}

fn session_cookie(
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

/// RFC 9700 §2.1.1: Replaying an authorization code must revoke all tokens previously issued from it.
///
/// @rfc 9700
/// @section 2.1.1
/// @requirement Authorization-code replay must cascade-revoke every access/refresh token issued from the original exchange.
/// @level MUST
/// @url https://datatracker.ietf.org/doc/html/rfc9700#section-2.1.1
#[actix_web::test]
async fn rfc9700_authorization_code_replay_revokes_issued_tokens() {
    const ISSUER: &str = "https://auth.example.com";
    const VERIFIER: &str = "verifier-replay-abcdefghijklmnopqrstuvwxyz1234567890";

    let client = Client::new(
        "client_replay".to_string(),
        "secret_replay".to_string(),
        vec!["https://client.example.test/cb".to_string()],
        vec![
            "authorization_code".to_string(),
            "refresh_token".to_string(),
        ],
        "read".to_string(),
        "Replay Test Client".to_string(),
    );

    let storage = oauth2_storage_factory::create_storage("sqlite::memory:")
        .await
        .expect("storage");
    storage.init().await.expect("init");
    storage.save_client(&client).await.expect("save_client");

    let now = chrono::Utc::now();
    let user = User {
        id: "user_replay".to_string(),
        username: "user_replay".to_string(),
        password_hash: "unused".to_string(),
        email: "replay@example.test".to_string(),
        enabled: true,
        role: "user".to_string(),
        created_at: now,
        updated_at: now,
    };
    storage.save_user(&user).await.expect("save_user");

    let jwt_secret = "replay_test_secret_at_least_32_chars_long".to_string();
    let metrics = Metrics::new().expect("metrics");

    let token_actor = oauth2_actix::actors::TokenActor::new(
        storage.clone(),
        jwt_secret.clone(),
        ISSUER.to_string(),
    )
    .start();
    let token_pool = TokenActorPool::new(vec![token_actor]);
    let client_actor = oauth2_actix::actors::ClientActor::new(storage.clone()).start();
    let auth_actor = oauth2_actix::actors::AuthActor::new(storage).start();
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

    let app = test::init_service(
        App::new()
            .wrap(SessionMiddleware::new(
                CookieSessionStore::default(),
                Key::generate(),
            ))
            .app_data(web::Data::new(token_pool))
            .app_data(web::Data::new(client_actor))
            .app_data(web::Data::new(auth_actor))
            .app_data(web::Data::new(jwt_secret))
            .app_data(web::Data::new(metrics))
            .app_data(web::Data::new(oidc_config))
            .app_data(web::Data::new(keyset))
            .app_data(web::Data::new(false))
            .app_data(web::Data::new(config))
            .route("/_set_session", web::get().to(set_session))
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
    .await;

    // Establish a session so /oauth/authorize does not bounce to /auth/login.
    let session_resp = test::call_service(
        &app,
        test::TestRequest::get().uri("/_set_session").to_request(),
    )
    .await;
    let cookie = session_cookie(&session_resp);

    // Drive a PKCE authorization_code grant.
    let authorize_uri = format!(
        "/oauth/authorize?response_type=code&client_id=client_replay&redirect_uri=https%3A%2F%2Fclient.example.test%2Fcb&scope=read&state=xyz&code_challenge={}&code_challenge_method=S256",
        s256(VERIFIER)
    );
    let authz_resp = test::call_service(
        &app,
        test::TestRequest::get()
            .uri(&authorize_uri)
            .insert_header(("Cookie", cookie.as_str()))
            .to_request(),
    )
    .await;
    if authz_resp.status() != 302 {
        let status = authz_resp.status();
        let body_bytes = test::read_body(authz_resp).await;
        panic!(
            "authorize returned {status}: {:?}",
            std::str::from_utf8(&body_bytes).unwrap_or("<non-utf8>")
        );
    }
    let location = authz_resp
        .headers()
        .get("Location")
        .expect("Location")
        .to_str()
        .unwrap();
    let code = location
        .split_once("code=")
        .map(|(_, rest)| rest.split('&').next().unwrap().to_string())
        .expect("auth code in redirect");

    // First (legitimate) exchange.
    let token_resp = test::call_service(
        &app,
        test::TestRequest::post()
            .uri("/oauth/token")
            .set_form([
                ("grant_type", "authorization_code"),
                ("code", code.as_str()),
                ("client_id", "client_replay"),
                ("client_secret", "secret_replay"),
                ("redirect_uri", "https://client.example.test/cb"),
                ("code_verifier", VERIFIER),
            ])
            .to_request(),
    )
    .await;
    assert_eq!(token_resp.status(), 200, "first code exchange must succeed");
    let token_body: TokenResponse = test::read_body_json(token_resp).await;
    let access_token = token_body.access_token.clone();

    // Confirm the token is active before the replay.
    let intro_before: IntrospectionResponse = test::read_body_json(
        test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/oauth/introspect")
                .set_form([
                    ("token", access_token.as_str()),
                    ("client_id", "client_replay"),
                    ("client_secret", "secret_replay"),
                ])
                .to_request(),
        )
        .await,
    )
    .await;
    assert!(
        intro_before.active,
        "token from first exchange must be active before replay"
    );

    // Replay the same code. MUST fail AND MUST cascade-revoke the family.
    let replay_resp = test::call_service(
        &app,
        test::TestRequest::post()
            .uri("/oauth/token")
            .set_form([
                ("grant_type", "authorization_code"),
                ("code", code.as_str()),
                ("client_id", "client_replay"),
                ("client_secret", "secret_replay"),
                ("redirect_uri", "https://client.example.test/cb"),
                ("code_verifier", VERIFIER),
            ])
            .to_request(),
    )
    .await;
    assert_eq!(
        replay_resp.status(),
        400,
        "code replay must be rejected with invalid_grant"
    );

    // RFC 9700 §2.1.5: the originally-issued access token MUST now be
    // inactive because the family was revoked.
    let intro_after: IntrospectionResponse = test::read_body_json(
        test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/oauth/introspect")
                .set_form([
                    ("token", access_token.as_str()),
                    ("client_id", "client_replay"),
                    ("client_secret", "secret_replay"),
                ])
                .to_request(),
        )
        .await,
    )
    .await;
    assert!(
        !intro_after.active,
        "RFC 9700 §2.1.5: prior token from replayed auth code MUST be revoked — got active=true"
    );
}
