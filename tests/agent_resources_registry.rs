//! Protected resources registry (RFC 8707 / RFC 9728) — storage round-trip
//! and admin CRUD HTTP tests. Part of Phase 7 (agent / A2A OAuth).

use actix_session::{storage::CookieSessionStore, Session, SessionMiddleware};
use actix_web::{cookie::Key, test, web, App, HttpResponse};
use serde_json::{json, Value};

use oauth2_actix::handlers::admin_resources;
use oauth2_actix::middleware::admin_guard::AdminGuard;
use oauth2_core::ProtectedResource;

// ---------------------------------------------------------------------------
// `ProtectedResource::validate_uri`
// ---------------------------------------------------------------------------

#[actix_web::test]
async fn validate_uri_rejects_uri_without_scheme() {
    let err = ProtectedResource::validate_uri("mcp.example.com").expect_err("must reject");
    assert_eq!(err.error, "invalid_target");
}

#[actix_web::test]
async fn validate_uri_rejects_fragment() {
    let err = ProtectedResource::validate_uri("https://x#frag").expect_err("must reject");
    assert_eq!(err.error, "invalid_target");
}

#[actix_web::test]
async fn validate_uri_accepts_https_without_fragment() {
    ProtectedResource::validate_uri("https://mcp.example.com/api").expect("must accept");
}

#[actix_web::test]
async fn validate_uri_accepts_http_without_fragment() {
    ProtectedResource::validate_uri("http://localhost:8080/api").expect("must accept");
}

// ---------------------------------------------------------------------------
// Storage round-trip (sqlite::memory:)
// ---------------------------------------------------------------------------

#[actix_web::test]
async fn storage_save_get_list_delete_round_trip() {
    let storage = oauth2_storage_factory::create_storage("sqlite::memory:")
        .await
        .expect("create storage");
    storage.init().await.expect("init storage");

    let resource = ProtectedResource::new(
        "https://mcp.example.com/api".to_string(),
        "Example MCP server".to_string(),
        vec!["read".to_string(), "write".to_string()],
    );

    storage
        .save_resource(&resource)
        .await
        .expect("save_resource");

    // get_resource_by_uri
    let fetched = storage
        .get_resource_by_uri("https://mcp.example.com/api")
        .await
        .expect("get_resource_by_uri")
        .expect("resource must exist");
    assert_eq!(fetched.id, resource.id);
    assert_eq!(fetched.name, "Example MCP server");
    assert_eq!(
        fetched.scopes_vec(),
        vec!["read".to_string(), "write".to_string()]
    );

    // Unknown URI returns None.
    let missing = storage
        .get_resource_by_uri("https://unknown.example.com")
        .await
        .expect("get_resource_by_uri");
    assert!(missing.is_none());

    // list_resources
    let all = storage.list_resources().await.expect("list_resources");
    assert_eq!(all.len(), 1);
    assert_eq!(all[0].id, resource.id);

    // delete_resource
    storage
        .delete_resource(&resource.id)
        .await
        .expect("delete_resource");
    let all_after_delete = storage.list_resources().await.expect("list_resources");
    assert!(all_after_delete.is_empty());
}

// ---------------------------------------------------------------------------
// Admin HTTP round-trip
// ---------------------------------------------------------------------------

fn session_key() -> Key {
    Key::from(&[7u8; 64])
}

async fn as_admin(session: Session) -> HttpResponse {
    let _ = session.insert("user_id", "admin-uid".to_string());
    let _ = session.insert("email", "admin@example.test".to_string());
    let _ = session.insert("role", "admin".to_string());
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

#[actix_web::test]
async fn admin_resources_post_then_get_round_trip() {
    let storage = oauth2_storage_factory::create_storage("sqlite::memory:")
        .await
        .expect("create storage");
    storage.init().await.expect("init storage");

    let app = test::init_service(
        App::new()
            .wrap(SessionMiddleware::new(
                CookieSessionStore::default(),
                session_key(),
            ))
            .app_data(web::Data::new(storage))
            .route("/test/admin-login", web::get().to(as_admin))
            .service(
                web::scope("/admin").wrap(AdminGuard).service(
                    web::scope("/resources")
                        .route("", web::get().to(admin_resources::list_resources))
                        .route("", web::post().to(admin_resources::create_resource))
                        .route("/{id}", web::delete().to(admin_resources::delete_resource)),
                ),
            ),
    )
    .await;

    let cookie = session_cookie!(app, "/test/admin-login");

    // POST /admin/resources
    let req = test::TestRequest::post()
        .uri("/admin/resources")
        .insert_header(("Cookie", cookie.clone()))
        .set_json(json!({
            "resource_uri": "https://mcp.example.com/api",
            "name": "Example MCP server",
            "scopes": ["read", "write"],
            "authorization_details_types": ["payment_initiation"],
            "txn_challenge_jwks_uri": "https://mcp.example.com/.well-known/jwks.json"
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 201);
    let created: Value = test::read_body_json(resp).await;
    assert_eq!(created["resource_uri"], "https://mcp.example.com/api");
    assert_eq!(created["name"], "Example MCP server");
    assert_eq!(created["scopes"], json!(["read", "write"]));
    let id = created["id"].as_str().expect("id").to_string();

    // GET /admin/resources — must include what we just created.
    let req = test::TestRequest::get()
        .uri("/admin/resources")
        .insert_header(("Cookie", cookie.clone()))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 200);
    let listed: Value = test::read_body_json(resp).await;
    let resources = listed["resources"].as_array().expect("resources array");
    assert_eq!(resources.len(), 1);
    assert_eq!(resources[0]["id"], id);

    // DELETE /admin/resources/{id}
    let req = test::TestRequest::delete()
        .uri(&format!("/admin/resources/{id}"))
        .insert_header(("Cookie", cookie.clone()))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 204);

    // GET again — now empty.
    let req = test::TestRequest::get()
        .uri("/admin/resources")
        .insert_header(("Cookie", cookie))
        .to_request();
    let resp = test::call_service(&app, req).await;
    let listed: Value = test::read_body_json(resp).await;
    assert!(listed["resources"].as_array().expect("array").is_empty());
}

#[actix_web::test]
async fn admin_resources_rejects_invalid_target_uri() {
    let storage = oauth2_storage_factory::create_storage("sqlite::memory:")
        .await
        .expect("create storage");
    storage.init().await.expect("init storage");

    let app = test::init_service(
        App::new()
            .wrap(SessionMiddleware::new(
                CookieSessionStore::default(),
                session_key(),
            ))
            .app_data(web::Data::new(storage))
            .route("/test/admin-login", web::get().to(as_admin))
            .service(
                web::scope("/admin").wrap(AdminGuard).service(
                    web::scope("/resources")
                        .route("", web::post().to(admin_resources::create_resource)),
                ),
            ),
    )
    .await;

    let cookie = session_cookie!(app, "/test/admin-login");

    let req = test::TestRequest::post()
        .uri("/admin/resources")
        .insert_header(("Cookie", cookie))
        .set_json(json!({
            "resource_uri": "mcp.example.com",
            "name": "No scheme"
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 400);
    let body: Value = test::read_body_json(resp).await;
    assert_eq!(body["error"], "invalid_target");
}

#[actix_web::test]
async fn admin_resources_without_session_redirects_to_login() {
    let storage = oauth2_storage_factory::create_storage("sqlite::memory:")
        .await
        .expect("create storage");
    storage.init().await.expect("init storage");

    let app = test::init_service(
        App::new()
            .wrap(SessionMiddleware::new(
                CookieSessionStore::default(),
                session_key(),
            ))
            .app_data(web::Data::new(storage))
            .service(web::scope("/admin").wrap(AdminGuard).service(
                web::scope("/resources").route("", web::get().to(admin_resources::list_resources)),
            )),
    )
    .await;

    let req = test::TestRequest::get()
        .uri("/admin/resources")
        .to_request();
    let resp = test::call_service(&app, req).await;
    // AdminGuard redirects unauthenticated requests to /auth/login (302); it
    // must never return the resource list.
    assert_eq!(resp.status(), 302);
    let location = resp
        .headers()
        .get("Location")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(location.contains("/auth/login"));
}
