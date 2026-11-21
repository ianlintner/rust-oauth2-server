//! A disabled client or user must stop working on the next request, on every
//! grant path, even though the session cookie / client cache still hold the
//! old state.

use actix::Actor;
use actix_session::{storage::CookieSessionStore, Session, SessionMiddleware};
use actix_web::{cookie::Key, http::header, test, web, App, HttpResponse};
use serde_json::{json, Value};

use oauth2_actix::actors::{AuthActor, ClientActor, TokenActor, TokenActorPool};
use oauth2_actix::handlers::events::RecentEventsStore;
use oauth2_actix::handlers::wellknown::OidcConfig;
use oauth2_actix::handlers::{admin_extra, oauth, token};
use oauth2_actix::middleware::admin_guard::AdminGuard;
use oauth2_core::{Client, User};
use oauth2_observability::Metrics;
use oauth2_ports::DynStorage;

const CLIENT_ID: &str = "status_client";
/// Runtime-generated secret (no hard-coded credential material).
fn client_secret() -> &'static str {
    static SECRET: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    SECRET.get_or_init(|| uuid::Uuid::new_v4().simple().to_string())
}
const REDIRECT: &str = "https://good.example/cb";

async fn setup_storage() -> DynStorage {
    let tmp = tempfile::NamedTempFile::new().expect("tempfile");
    let url = format!("sqlite://{}", tmp.path().display());
    std::mem::forget(tmp);
    let storage = oauth2_storage_factory::create_storage(&url)
        .await
        .expect("create storage");
    storage.init().await.expect("init");
    storage
}

fn make_client() -> Client {
    Client::new(
        CLIENT_ID.to_string(),
        client_secret().to_string(),
        vec![REDIRECT.to_string()],
        vec![
            "authorization_code".to_string(),
            "client_credentials".to_string(),
            "refresh_token".to_string(),
        ],
        "read write".to_string(),
        "status".to_string(),
    )
}

fn make_user(name: &str, role: &str) -> User {
    let mut user = User::new(
        name.to_string(),
        "$argon2id$unused".to_string(),
        format!("{name}@test.example"),
    );
    user.role = role.to_string();
    user
}

/// Establish a session for the user whose id is in the path.
async fn login(session: Session, path: web::Path<String>) -> HttpResponse {
    session.insert("user_id", path.into_inner()).unwrap();
    session.insert("authenticated", true).unwrap();
    session.insert("role", "admin").unwrap();
    HttpResponse::Ok().finish()
}

macro_rules! build_app {
    ($storage:expr) => {{
        let storage: DynStorage = $storage.clone();
        let jwt_secret = uuid::Uuid::new_v4().simple().to_string();
        let token_actor = TokenActor::new(
            storage.clone(),
            jwt_secret.clone(),
            "http://localhost".into(),
        )
        .start();
        let mut config = oauth2_config::Config::default();
        config.jwt.secret = jwt_secret.clone();
        config.jwt.public_introspection = false;
        test::init_service(
            App::new()
                .wrap(SessionMiddleware::new(
                    CookieSessionStore::default(),
                    Key::generate(),
                ))
                .app_data(web::Data::new(TokenActorPool::new(vec![token_actor])))
                .app_data(web::Data::new(ClientActor::new(storage.clone()).start()))
                .app_data(web::Data::new(AuthActor::new(storage.clone()).start()))
                .app_data(web::Data::new(storage.clone()))
                .app_data(web::Data::new(jwt_secret.clone()))
                .app_data(web::Data::new(Metrics::new().expect("metrics")))
                .app_data(web::Data::new(OidcConfig {
                    issuer: "http://localhost".to_string(),
                    jwt_secret,
                    id_token_alg: "HS256".to_string(),
                    id_token_kid: None,
                    id_token_private_key_pem: None,
                }))
                .app_data(web::Data::new(config))
                .app_data(web::Data::new(false))
                .app_data(web::Data::new(RecentEventsStore::new(16)))
                .route("/test/login/{id}", web::get().to(login))
                .route("/oauth/authorize", web::get().to(oauth::authorize))
                .route("/oauth/token", web::post().to(oauth::token))
                .route("/oauth/introspect", web::post().to(token::introspect))
                .route("/oauth/revoke", web::post().to(token::revoke))
                .route(
                    "/test/clients/{id}/enabled",
                    web::put().to(admin_extra::set_client_enabled),
                )
                .service(web::scope("/admin").wrap(AdminGuard).route(
                    "/api/ping",
                    web::get().to(|| async { HttpResponse::Ok().finish() }),
                )),
        )
        .await
    }};
}

macro_rules! cookie_for {
    ($app:expr, $user_id:expr) => {{
        let resp = test::call_service(
            &$app,
            test::TestRequest::get()
                .uri(&format!("/test/login/{}", $user_id))
                .to_request(),
        )
        .await;
        resp.headers()
            .get(header::SET_COOKIE)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.split(';').next().unwrap_or("").to_string())
            .expect("session cookie")
    }};
}

macro_rules! disable_client {
    ($app:expr, $storage:expr) => {{
        let row = $storage
            .get_client(CLIENT_ID)
            .await
            .unwrap()
            .expect("client row");
        let resp = test::call_service(
            &$app,
            test::TestRequest::put()
                .uri(&format!("/test/clients/{}/enabled", row.id))
                .set_json(json!({ "enabled": false }))
                .to_request(),
        )
        .await;
        assert_eq!(resp.status(), 200, "admin disable must succeed");
    }};
}

macro_rules! post_form {
    ($app:expr, $uri:expr, $form:expr) => {{
        test::call_service(
            &$app,
            test::TestRequest::post()
                .uri($uri)
                .set_form($form)
                .to_request(),
        )
        .await
    }};
}

async fn assert_invalid_client(
    resp: actix_web::dev::ServiceResponse<impl actix_web::body::MessageBody>,
) {
    assert_eq!(resp.status(), 401);
    let body: Value = test::read_body_json(resp).await;
    assert_eq!(body["error"], "invalid_client");
}

fn cc_form() -> [(&'static str, &'static str); 4] {
    [
        ("grant_type", "client_credentials"),
        ("client_id", CLIENT_ID),
        ("client_secret", client_secret()),
        ("scope", "read"),
    ]
}

#[actix_web::test]
async fn disabled_client_cannot_use_client_credentials() {
    let storage = setup_storage().await;
    storage.save_client(&make_client()).await.unwrap();
    let app = build_app!(storage);

    disable_client!(app, storage);

    assert_invalid_client(post_form!(app, "/oauth/token", cc_form())).await;
}

#[actix_web::test]
async fn disable_takes_effect_despite_client_cache() {
    let storage = setup_storage().await;
    storage.save_client(&make_client()).await.unwrap();
    let app = build_app!(storage);

    // Warms the ClientActor cache.
    let ok = post_form!(app, "/oauth/token", cc_form());
    assert_eq!(ok.status(), 200);

    disable_client!(app, storage);

    assert_invalid_client(post_form!(app, "/oauth/token", cc_form())).await;
}

#[actix_web::test]
async fn disabled_client_cannot_introspect_or_revoke() {
    let storage = setup_storage().await;
    storage.save_client(&make_client()).await.unwrap();
    let app = build_app!(storage);

    let issued = post_form!(app, "/oauth/token", cc_form());
    let body: Value = test::read_body_json(issued).await;
    let access = body["access_token"].as_str().unwrap().to_string();

    disable_client!(app, storage);

    let form = [
        ("token", access.as_str()),
        ("client_id", CLIENT_ID),
        ("client_secret", client_secret()),
    ];
    assert_invalid_client(post_form!(app, "/oauth/introspect", form)).await;
    assert_invalid_client(post_form!(app, "/oauth/revoke", form)).await;
}

#[actix_web::test]
async fn disabled_client_cannot_start_authorization() {
    let storage = setup_storage().await;
    storage.save_client(&make_client()).await.unwrap();
    let user = make_user("authz_user", "user");
    storage.save_user(&user).await.unwrap();
    let app = build_app!(storage);
    let cookie = cookie_for!(app, user.id);

    disable_client!(app, storage);

    let resp = test::call_service(
        &app,
        test::TestRequest::get()
            .uri(&format!(
                "/oauth/authorize?response_type=code&client_id={CLIENT_ID}\
                 &redirect_uri=https%3A%2F%2Fgood.example%2Fcb&scope=read\
                 &code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM\
                 &code_challenge_method=S256"
            ))
            .insert_header(("Cookie", cookie))
            .to_request(),
    )
    .await;
    assert!(
        resp.headers()
            .get(header::LOCATION)
            .and_then(|v| v.to_str().ok())
            .map(|l| !l.contains("code="))
            .unwrap_or(true),
        "no code may be issued to a disabled client"
    );
    assert_eq!(resp.status(), 401);
}

#[actix_web::test]
async fn disabled_client_cannot_refresh() {
    let storage = setup_storage().await;
    storage.save_client(&make_client()).await.unwrap();
    let user = make_user("refresh_user", "user");
    storage.save_user(&user).await.unwrap();
    let app = build_app!(storage);
    let cookie = cookie_for!(app, user.id);

    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let authorize = test::call_service(
        &app,
        test::TestRequest::get()
            .uri(&format!(
                "/oauth/authorize?response_type=code&client_id={CLIENT_ID}\
                 &redirect_uri=https%3A%2F%2Fgood.example%2Fcb&scope=read\
                 &code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM\
                 &code_challenge_method=S256"
            ))
            .insert_header(("Cookie", cookie))
            .to_request(),
    )
    .await;
    assert_eq!(authorize.status(), 302);
    let location = authorize
        .headers()
        .get(header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .unwrap()
        .to_string();
    let code = location
        .split_once('?')
        .unwrap()
        .1
        .split('&')
        .find_map(|p| p.strip_prefix("code="))
        .expect("code in redirect")
        .to_string();

    let exchanged = post_form!(
        app,
        "/oauth/token",
        [
            ("grant_type", "authorization_code"),
            ("client_id", CLIENT_ID),
            ("client_secret", client_secret()),
            ("code", code.as_str()),
            ("redirect_uri", REDIRECT),
            ("code_verifier", verifier),
        ]
    );
    assert!(exchanged.status().is_success());
    let body: Value = test::read_body_json(exchanged).await;
    let refresh = body["refresh_token"].as_str().expect("refresh token");

    disable_client!(app, storage);

    assert_invalid_client(post_form!(
        app,
        "/oauth/token",
        [
            ("grant_type", "refresh_token"),
            ("client_id", CLIENT_ID),
            ("client_secret", client_secret()),
            ("refresh_token", refresh),
        ]
    ))
    .await;
}

#[actix_web::test]
async fn disabled_user_session_cannot_authorize() {
    let storage = setup_storage().await;
    storage.save_client(&make_client()).await.unwrap();
    let user = make_user("disabled_user", "user");
    storage.save_user(&user).await.unwrap();
    let app = build_app!(storage);
    let cookie = cookie_for!(app, user.id);

    storage.set_user_enabled(&user.id, false).await.unwrap();

    let resp = test::call_service(
        &app,
        test::TestRequest::get()
            .uri(&format!(
                "/oauth/authorize?response_type=code&client_id={CLIENT_ID}\
                 &redirect_uri=https%3A%2F%2Fgood.example%2Fcb&scope=read\
                 &code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM\
                 &code_challenge_method=S256"
            ))
            .insert_header(("Cookie", cookie))
            .to_request(),
    )
    .await;
    let location = resp
        .headers()
        .get(header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    assert!(!location.contains("code="), "no code for a disabled user");
    assert!(location.starts_with("/auth/login"), "got {location}");
}

#[actix_web::test]
async fn demoted_admin_session_loses_admin_access() {
    let storage = setup_storage().await;
    let admin = make_user("demoted_admin", "admin");
    storage.save_user(&admin).await.unwrap();
    let app = build_app!(storage);
    let cookie = cookie_for!(app, admin.id);

    let before = test::call_service(
        &app,
        test::TestRequest::get()
            .uri("/admin/api/ping")
            .insert_header(("Cookie", cookie.clone()))
            .to_request(),
    )
    .await;
    assert_eq!(before.status(), 200, "admin session passes the guard");

    storage.set_user_role(&admin.id, "user").await.unwrap();

    let after = test::call_service(
        &app,
        test::TestRequest::get()
            .uri("/admin/api/ping")
            .insert_header(("Cookie", cookie))
            .to_request(),
    )
    .await;
    assert_eq!(after.status(), 403);
}
