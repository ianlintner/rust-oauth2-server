//! RFC 9700 §4.7 — per-client `require_state` policy flag conformance.

use actix::Actor;
use actix_session::{storage::CookieSessionStore, Session, SessionMiddleware};
use actix_web::{cookie::Key, test, web, App, HttpResponse};
use std::sync::Arc;
use tokio::sync::RwLock;

use oauth2_actix::actors::TokenActorPool;
use oauth2_actix::handlers::wellknown::OidcConfig;
use oauth2_core::{Client, User};
use oauth2_observability::Metrics;

fn s256(verifier: &str) -> String {
    use base64::{engine::general_purpose, Engine as _};
    use sha2::{Digest, Sha256};
    general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

async fn set_session(session: Session) -> HttpResponse {
    session.insert("user_id", "user_rs").unwrap();
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

async fn run_authorize(require_state: bool, send_state: bool) -> u16 {
    const ISSUER: &str = "https://auth.example.com";
    const VERIFIER: &str = "verifier-require-state-abcdefghijklmnopqrstuvwxyz12";

    let mut client = Client::new(
        "client_rs".to_string(),
        "secret_rs".to_string(),
        vec!["https://client.example.test/cb".to_string()],
        vec!["authorization_code".to_string()],
        "read".to_string(),
        "RS Client".to_string(),
    );
    client.require_state = require_state;

    let storage = oauth2_storage_factory::create_storage("sqlite::memory:")
        .await
        .expect("storage");
    storage.init().await.expect("init");
    storage.save_client(&client).await.expect("save_client");

    let now = chrono::Utc::now();
    let user = User {
        id: "user_rs".to_string(),
        username: "user_rs".to_string(),
        password_hash: "unused".to_string(),
        email: "rs@example.test".to_string(),
        enabled: true,
        role: "user".to_string(),
        created_at: now,
        updated_at: now,
    };
    storage.save_user(&user).await.expect("save_user");

    let jwt_secret = "require_state_test_secret_at_least_32_chars".to_string();
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
            .route("/_set_session", web::get().to(set_session))
            .service(web::scope("/oauth").route(
                "/authorize",
                web::get().to(oauth2_actix::handlers::oauth::authorize),
            )),
    )
    .await;

    let session_resp = test::call_service(
        &app,
        test::TestRequest::get().uri("/_set_session").to_request(),
    )
    .await;
    let cookie = session_cookie(&session_resp);

    let mut uri = format!(
        "/oauth/authorize?response_type=code&client_id=client_rs\
         &redirect_uri=https%3A%2F%2Fclient.example.test%2Fcb&scope=read\
         &code_challenge={}&code_challenge_method=S256",
        s256(VERIFIER)
    );
    if send_state {
        uri.push_str("&state=xyz");
    }

    let resp = test::call_service(
        &app,
        test::TestRequest::get()
            .uri(&uri)
            .insert_header(("Cookie", cookie.as_str()))
            .to_request(),
    )
    .await;
    resp.status().as_u16()
}

#[actix_web::test]
async fn require_state_off_accepts_missing_state() {
    let status = run_authorize(false, false).await;
    assert_eq!(
        status, 302,
        "default client (require_state=false) must accept authorize without state"
    );
}

#[actix_web::test]
async fn require_state_on_rejects_missing_state() {
    let status = run_authorize(true, false).await;
    assert_eq!(
        status, 400,
        "RFC 9700 §4.7: require_state=true must reject authorize requests missing state"
    );
}

#[actix_web::test]
async fn require_state_on_accepts_present_state() {
    let status = run_authorize(true, true).await;
    assert_eq!(
        status, 302,
        "require_state=true must accept authorize when state is present"
    );
}
