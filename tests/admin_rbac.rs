//! Role-based access control for admin_extra endpoints.
//!
//! Verifies the `AdminGuard` middleware correctly gates:
//! - Unauthenticated requests → 302 redirect (or 403 JSON on `/admin/api/*`)
//! - Authenticated non-admin session → 403 JSON on API paths
//! - Bearer tokens without `admin` scope → 403 `insufficient_scope`
//! - Valid admin session → 2xx passthrough

use actix_session::{storage::CookieSessionStore, Session, SessionMiddleware};
use actix_web::{cookie::Key, test, web, App, HttpResponse};
use serde_json::json;

use oauth2_actix::handlers::admin_extra;
use oauth2_actix::handlers::events::RecentEventsStore;
use oauth2_actix::middleware::admin_guard::AdminGuard;
use oauth2_core::{Client, Token};
use oauth2_ports::DynStorage;

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

fn session_key() -> Key {
    Key::from(&[13u8; 64])
}

async fn as_admin(session: Session) -> HttpResponse {
    let _ = session.insert("user_id", "admin-uid".to_string());
    let _ = session.insert("email", "admin@example.test".to_string());
    let _ = session.insert("role", "admin".to_string());
    HttpResponse::Ok().finish()
}

async fn as_plain_user(session: Session) -> HttpResponse {
    let _ = session.insert("user_id", "user-uid".to_string());
    let _ = session.insert("email", "user@example.test".to_string());
    let _ = session.insert("role", "user".to_string());
    HttpResponse::Ok().finish()
}

macro_rules! session_cookie {
    ($app:expr, $path:expr) => {{
        let req = test::TestRequest::get().uri($path).to_request();
        let resp = test::call_service(&$app, req).await;
        assert_eq!(resp.status(), 200);
        resp.headers()
            .get("set-cookie")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.split(';').next().unwrap_or("").to_string())
            .expect("set-cookie header")
    }};
}

// ---------------------------------------------------------------------------
// No session → redirect / 403
// ---------------------------------------------------------------------------

#[actix_web::test]
async fn admin_api_without_session_returns_redirect_for_html_paths() {
    let storage = setup_storage().await;
    let app = test::init_service(
        App::new()
            .wrap(SessionMiddleware::new(
                CookieSessionStore::default(),
                session_key(),
            ))
            .app_data(web::Data::new(storage))
            .app_data(web::Data::new(RecentEventsStore::new(16)))
            .service(
                web::scope("/admin")
                    .wrap(AdminGuard)
                    .route("/users/{id}", web::put().to(admin_extra::update_user)),
            ),
    )
    .await;

    // PUT /admin/users/{id} is not under /admin/api/ — triggers the HTML
    // branch (302 redirect to /auth/login). We still exercise the 401-ish
    // path because the guard must not fall through to the handler.
    let req = test::TestRequest::put()
        .uri("/admin/users/someone")
        .set_json(json!({ "email": "x@y.z" }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 302);
    let location = resp
        .headers()
        .get("Location")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(location.contains("/auth/login"));
}

#[actix_web::test]
async fn admin_api_without_session_returns_302_on_api_paths() {
    // Under current AdminGuard impl, unauthenticated requests redirect
    // regardless of `/admin/api/` prefix. This test pins that behavior so
    // future relaxations are intentional.
    let storage = setup_storage().await;
    let app = test::init_service(
        App::new()
            .wrap(SessionMiddleware::new(
                CookieSessionStore::default(),
                session_key(),
            ))
            .app_data(web::Data::new(storage))
            .app_data(web::Data::new(RecentEventsStore::new(16)))
            .service(web::scope("/admin").wrap(AdminGuard).service(
                web::scope("/api").route("/users", web::post().to(admin_extra::create_user)),
            )),
    )
    .await;

    let req = test::TestRequest::post()
        .uri("/admin/api/users")
        .set_json(json!({
            "username": "x",
            "email": "x@x",
            "password": "password123"
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 302);
}

// ---------------------------------------------------------------------------
// Plain user session → 403 on API paths
// ---------------------------------------------------------------------------

#[actix_web::test]
async fn plain_user_session_gets_403_on_admin_api() {
    let storage = setup_storage().await;
    let app = test::init_service(
        App::new()
            .wrap(SessionMiddleware::new(
                CookieSessionStore::default(),
                session_key(),
            ))
            .app_data(web::Data::new(storage))
            .app_data(web::Data::new(RecentEventsStore::new(16)))
            .route("/test/user-login", web::get().to(as_plain_user))
            .service(
                web::scope("/admin").wrap(AdminGuard).service(
                    web::scope("/api")
                        .route("/users", web::post().to(admin_extra::create_user))
                        .route("/denylist", web::post().to(admin_extra::add_denylist)),
                ),
            ),
    )
    .await;
    let cookie = session_cookie!(app, "/test/user-login");

    for (uri, body) in [
        (
            "/admin/api/users",
            json!({ "username": "x", "email": "x@x", "password": "password123" }),
        ),
        (
            "/admin/api/denylist",
            json!({ "kind": "ip", "value": "203.0.113.2" }),
        ),
    ] {
        let req = test::TestRequest::post()
            .uri(uri)
            .insert_header(("Cookie", cookie.clone()))
            .set_json(body)
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 403, "plain user must be 403 on {uri}");
        let body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(body["error"], "insufficient_permissions");
    }
}

// ---------------------------------------------------------------------------
// Admin session → passes through
// ---------------------------------------------------------------------------

#[actix_web::test]
async fn admin_session_can_invoke_admin_api() {
    let storage = setup_storage().await;
    let app = test::init_service(
        App::new()
            .wrap(SessionMiddleware::new(
                CookieSessionStore::default(),
                session_key(),
            ))
            .app_data(web::Data::new(storage.clone()))
            .app_data(web::Data::new(RecentEventsStore::new(16)))
            .route("/test/admin-login", web::get().to(as_admin))
            .service(web::scope("/admin").wrap(AdminGuard).service(
                web::scope("/api").route("/users", web::post().to(admin_extra::create_user)),
            )),
    )
    .await;
    let cookie = session_cookie!(app, "/test/admin-login");

    let req = test::TestRequest::post()
        .uri("/admin/api/users")
        .insert_header(("Cookie", cookie))
        .set_json(json!({
            "username": "fresh",
            "email": "fresh@example.test",
            "password": "passphrase-secure"
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 201);
}

// ---------------------------------------------------------------------------
// Bearer token RBAC
// ---------------------------------------------------------------------------

#[actix_web::test]
async fn bearer_token_without_admin_scope_is_403() {
    let storage = setup_storage().await;
    let client = Client::new(
        "machine-client".to_string(),
        "secret".to_string(),
        vec![],
        vec!["client_credentials".to_string()],
        "read".to_string(),
        "Machine".to_string(),
    );
    storage.save_client(&client).await.unwrap();

    let token = Token::new(
        "no-admin-scope-token".to_string(),
        None,
        client.client_id.clone(),
        None,
        "read".to_string(),
        3600,
        None,
    );
    storage.save_token(&token).await.unwrap();

    let app = test::init_service(
        App::new()
            .wrap(SessionMiddleware::new(
                CookieSessionStore::default(),
                session_key(),
            ))
            .app_data(web::Data::new(storage))
            .app_data(web::Data::new(RecentEventsStore::new(16)))
            .service(web::scope("/admin").wrap(AdminGuard).service(
                web::scope("/api").route("/users", web::post().to(admin_extra::create_user)),
            )),
    )
    .await;

    let req = test::TestRequest::post()
        .uri("/admin/api/users")
        .insert_header(("Authorization", "Bearer no-admin-scope-token"))
        .set_json(json!({
            "username": "x",
            "email": "x@x",
            "password": "password123"
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 403);
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["error"], "insufficient_scope");
}

#[actix_web::test]
async fn bearer_token_with_admin_scope_passes() {
    let storage = setup_storage().await;
    let client = Client::new(
        "machine-admin".to_string(),
        "secret".to_string(),
        vec![],
        vec!["client_credentials".to_string()],
        "admin".to_string(),
        "Machine".to_string(),
    );
    storage.save_client(&client).await.unwrap();

    let token = Token::new(
        "admin-scope-token".to_string(),
        None,
        client.client_id.clone(),
        None,
        "admin read".to_string(),
        3600,
        None,
    );
    storage.save_token(&token).await.unwrap();

    let app = test::init_service(
        App::new()
            .wrap(SessionMiddleware::new(
                CookieSessionStore::default(),
                session_key(),
            ))
            .app_data(web::Data::new(storage))
            .app_data(web::Data::new(RecentEventsStore::new(16)))
            .service(web::scope("/admin").wrap(AdminGuard).service(
                web::scope("/api").route("/denylist", web::post().to(admin_extra::add_denylist)),
            )),
    )
    .await;

    let req = test::TestRequest::post()
        .uri("/admin/api/denylist")
        .insert_header(("Authorization", "Bearer admin-scope-token"))
        .set_json(json!({
            "kind": "ip",
            "value": "198.51.100.200",
            "reason": "test"
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 201);
}

#[actix_web::test]
async fn invalid_bearer_token_is_401() {
    let storage = setup_storage().await;
    let app = test::init_service(
        App::new()
            .wrap(SessionMiddleware::new(
                CookieSessionStore::default(),
                session_key(),
            ))
            .app_data(web::Data::new(storage))
            .app_data(web::Data::new(RecentEventsStore::new(16)))
            .service(web::scope("/admin").wrap(AdminGuard).service(
                web::scope("/api").route("/users", web::post().to(admin_extra::create_user)),
            )),
    )
    .await;

    let req = test::TestRequest::post()
        .uri("/admin/api/users")
        .insert_header(("Authorization", "Bearer garbage-token"))
        .set_json(json!({
            "username": "x",
            "email": "x@x",
            "password": "password123"
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 401);
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["error"], "invalid_token");
}
