//! Integration tests for admin-maintainer endpoints added in V17:
//! user CRUD, client CRUD extensions, denylist, audit log, bulk revoke.
//!
//! Every test stands up an isolated `sqlite::memory:` backend and mounts just
//! the handler(s) under test behind a minimal SessionMiddleware so
//! `build_audit` can read the session.

use actix_session::{storage::CookieSessionStore, Session, SessionMiddleware};
use actix_web::{cookie::Key, test, web, App, HttpResponse};
use serde_json::{json, Value};

use oauth2_actix::handlers::{admin, admin_extra};
use oauth2_core::{Client, DenylistEntry, ListQuery, Token, User};
use oauth2_ports::DynStorage;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async fn setup_storage() -> DynStorage {
    // Use a unique file-backed SQLite per test. `sqlite::memory:` creates a
    // fresh database per connection, so a pool with >1 connection loses
    // writes when reads hit a different connection. We also can't use a
    // shared in-process memory DB because tests run concurrently.
    let tmp = tempfile::NamedTempFile::new().expect("tempfile");
    let url = format!("sqlite://{}", tmp.path().display());
    // Leak the guard so the file outlives the test — Drop removes it.
    std::mem::forget(tmp);
    let storage = oauth2_storage_factory::create_storage(&url)
        .await
        .expect("create storage");
    storage.init().await.expect("init");
    storage
}

/// Seed a persistent admin session so `build_audit` can record the actor.
async fn seed_session(session: Session) -> HttpResponse {
    let _ = session.insert("user_id", "admin-uid".to_string());
    let _ = session.insert("email", "admin@test.example".to_string());
    let _ = session.insert("role", "admin".to_string());
    HttpResponse::Ok().finish()
}

/// Cookie-store key for session middleware. Stable so session cookies
/// produced by `/test/login` can be reused across subsequent requests.
fn session_key() -> Key {
    Key::from(&[42u8; 64])
}

/// Produce a signed session cookie header value for the seeded admin
/// session by invoking `/test/login`. Done as a macro so the caller's
/// concrete service type stays opaque.
macro_rules! admin_cookie {
    ($app:expr) => {{
        let req = test::TestRequest::get().uri("/test/login").to_request();
        let resp = test::call_service(&$app, req).await;
        assert_eq!(resp.status(), 200);
        resp.headers()
            .get("set-cookie")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.split(';').next().unwrap_or("").to_string())
            .expect("set-cookie header")
    }};
}

fn make_user(username: &str) -> User {
    User::new(
        username.to_string(),
        "$argon2id$unused".to_string(),
        format!("{username}@test.example"),
    )
}

fn make_client_row(suffix: &str) -> Client {
    Client::new(
        format!("client-{suffix}"),
        "secret".to_string(),
        vec!["https://example.com/cb".to_string()],
        vec!["authorization_code".to_string()],
        "read".to_string(),
        format!("Client {suffix}"),
    )
}

// ---------------------------------------------------------------------------
// User CRUD
// ---------------------------------------------------------------------------

#[actix_web::test]
async fn create_user_succeeds_and_hashes_password() {
    let storage = setup_storage().await;

    let app = test::init_service(
        App::new()
            .wrap(SessionMiddleware::new(
                CookieSessionStore::default(),
                session_key(),
            ))
            .app_data(web::Data::new(storage.clone()))
            .route("/test/login", web::get().to(seed_session))
            .route("/admin/api/users", web::post().to(admin_extra::create_user)),
    )
    .await;

    let cookie = admin_cookie!(app);

    let req = test::TestRequest::post()
        .uri("/admin/api/users")
        .insert_header(("Cookie", cookie))
        .set_json(json!({
            "username": "alice",
            "email": "alice@test.example",
            "password": "correcthorsebatterystaple",
            "role": "user"
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 201);

    let body: Value = test::read_body_json(resp).await;
    assert_eq!(body["username"], "alice");
    assert_eq!(body["role"], "user");
    assert_eq!(body["enabled"], true);

    // Verify storage round-trip + password hashed (not plain).
    let stored = storage
        .get_user_by_username("alice")
        .await
        .unwrap()
        .expect("user persisted");
    assert!(stored.password_hash.starts_with("$argon2"));
    assert_ne!(stored.password_hash, "correcthorsebatterystaple");
}

#[actix_web::test]
async fn create_user_rejects_missing_fields() {
    let storage = setup_storage().await;
    let app = test::init_service(
        App::new()
            .wrap(SessionMiddleware::new(
                CookieSessionStore::default(),
                session_key(),
            ))
            .app_data(web::Data::new(storage))
            .route("/test/login", web::get().to(seed_session))
            .route("/admin/api/users", web::post().to(admin_extra::create_user)),
    )
    .await;
    let cookie = admin_cookie!(app);

    let req = test::TestRequest::post()
        .uri("/admin/api/users")
        .insert_header(("Cookie", cookie))
        .set_json(json!({ "username": "", "email": "", "password": "" }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 400);
}

#[actix_web::test]
async fn create_user_rejects_duplicate_username() {
    let storage = setup_storage().await;
    storage.save_user(&make_user("dup")).await.unwrap();

    let app = test::init_service(
        App::new()
            .wrap(SessionMiddleware::new(
                CookieSessionStore::default(),
                session_key(),
            ))
            .app_data(web::Data::new(storage))
            .route("/test/login", web::get().to(seed_session))
            .route("/admin/api/users", web::post().to(admin_extra::create_user)),
    )
    .await;
    let cookie = admin_cookie!(app);

    let req = test::TestRequest::post()
        .uri("/admin/api/users")
        .insert_header(("Cookie", cookie))
        .set_json(json!({
            "username": "dup",
            "email": "dup2@test.example",
            "password": "whatever123"
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 409);
}

#[actix_web::test]
async fn update_user_patches_email_and_role() {
    let storage = setup_storage().await;
    let user = make_user("patchme");
    storage.save_user(&user).await.unwrap();

    let app = test::init_service(
        App::new()
            .wrap(SessionMiddleware::new(
                CookieSessionStore::default(),
                session_key(),
            ))
            .app_data(web::Data::new(storage.clone()))
            .route("/test/login", web::get().to(seed_session))
            .route(
                "/admin/api/users/{id}",
                web::put().to(admin_extra::update_user),
            ),
    )
    .await;
    let cookie = admin_cookie!(app);

    let req = test::TestRequest::put()
        .uri(&format!("/admin/api/users/{}", user.id))
        .insert_header(("Cookie", cookie))
        .set_json(json!({ "email": "new@test.example", "role": "admin" }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 200);

    let reloaded = storage.get_user_by_id(&user.id).await.unwrap().unwrap();
    assert_eq!(reloaded.email, "new@test.example");
    assert_eq!(reloaded.role, "admin");
}

#[actix_web::test]
async fn update_user_ignores_invalid_role() {
    let storage = setup_storage().await;
    let user = make_user("rolechk");
    storage.save_user(&user).await.unwrap();

    let app = test::init_service(
        App::new()
            .wrap(SessionMiddleware::new(
                CookieSessionStore::default(),
                session_key(),
            ))
            .app_data(web::Data::new(storage.clone()))
            .route("/test/login", web::get().to(seed_session))
            .route(
                "/admin/api/users/{id}",
                web::put().to(admin_extra::update_user),
            ),
    )
    .await;
    let cookie = admin_cookie!(app);

    let req = test::TestRequest::put()
        .uri(&format!("/admin/api/users/{}", user.id))
        .insert_header(("Cookie", cookie))
        .set_json(json!({ "role": "superhacker" }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 200);

    let reloaded = storage.get_user_by_id(&user.id).await.unwrap().unwrap();
    assert_eq!(reloaded.role, "user", "invalid role kept as 'user'");
}

#[actix_web::test]
async fn update_user_404_for_missing() {
    let storage = setup_storage().await;
    let app = test::init_service(
        App::new()
            .wrap(SessionMiddleware::new(
                CookieSessionStore::default(),
                session_key(),
            ))
            .app_data(web::Data::new(storage))
            .route("/test/login", web::get().to(seed_session))
            .route(
                "/admin/api/users/{id}",
                web::put().to(admin_extra::update_user),
            ),
    )
    .await;
    let cookie = admin_cookie!(app);

    let req = test::TestRequest::put()
        .uri("/admin/api/users/ghost-id")
        .insert_header(("Cookie", cookie))
        .set_json(json!({ "email": "x@y.z" }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 404);
}

#[actix_web::test]
async fn delete_user_removes_row_and_revokes_tokens() {
    let storage = setup_storage().await;
    let user = make_user("bye");
    storage.save_user(&user).await.unwrap();
    let client = make_client_row("del");
    storage.save_client(&client).await.unwrap();

    // Seed a live token for the user.
    let token = Token::new(
        "access-delete".to_string(),
        Some("refresh-delete".to_string()),
        client.client_id.clone(),
        Some(user.id.clone()),
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
            .app_data(web::Data::new(storage.clone()))
            .route("/test/login", web::get().to(seed_session))
            .route(
                "/admin/api/users/{id}",
                web::delete().to(admin_extra::delete_user),
            ),
    )
    .await;
    let cookie = admin_cookie!(app);

    let req = test::TestRequest::delete()
        .uri(&format!("/admin/api/users/{}", user.id))
        .insert_header(("Cookie", cookie))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 200);

    assert!(storage.get_user_by_id(&user.id).await.unwrap().is_none());
    let revoked = storage
        .get_token_by_access_token("access-delete")
        .await
        .unwrap()
        .unwrap();
    assert!(revoked.revoked, "user deletion cascades token revocation");
}

#[actix_web::test]
async fn set_user_enabled_toggles_flag_and_revokes_on_disable() {
    let storage = setup_storage().await;
    let user = make_user("onoff");
    storage.save_user(&user).await.unwrap();
    let client = make_client_row("enabled");
    storage.save_client(&client).await.unwrap();

    let token = Token::new(
        "access-disable".to_string(),
        None,
        client.client_id.clone(),
        Some(user.id.clone()),
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
            .app_data(web::Data::new(storage.clone()))
            .route("/test/login", web::get().to(seed_session))
            .route(
                "/admin/api/users/{id}/enabled",
                web::post().to(admin_extra::set_user_enabled),
            ),
    )
    .await;
    let cookie = admin_cookie!(app);

    // Disable
    let req = test::TestRequest::post()
        .uri(&format!("/admin/api/users/{}/enabled", user.id))
        .insert_header(("Cookie", cookie.clone()))
        .set_json(json!({ "enabled": false }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 200);

    let reloaded = storage.get_user_by_id(&user.id).await.unwrap().unwrap();
    assert!(!reloaded.enabled);
    let revoked = storage
        .get_token_by_access_token("access-disable")
        .await
        .unwrap()
        .unwrap();
    assert!(revoked.revoked, "disable revokes active tokens");

    // Re-enable
    let req = test::TestRequest::post()
        .uri(&format!("/admin/api/users/{}/enabled", user.id))
        .insert_header(("Cookie", cookie))
        .set_json(json!({ "enabled": true }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 200);

    let reloaded = storage.get_user_by_id(&user.id).await.unwrap().unwrap();
    assert!(reloaded.enabled);
}

#[actix_web::test]
async fn set_user_role_rejects_invalid_role() {
    let storage = setup_storage().await;
    let user = make_user("rolerej");
    storage.save_user(&user).await.unwrap();

    let app = test::init_service(
        App::new()
            .wrap(SessionMiddleware::new(
                CookieSessionStore::default(),
                session_key(),
            ))
            .app_data(web::Data::new(storage))
            .route("/test/login", web::get().to(seed_session))
            .route(
                "/admin/api/users/{id}/role",
                web::post().to(admin_extra::set_user_role),
            ),
    )
    .await;
    let cookie = admin_cookie!(app);

    let req = test::TestRequest::post()
        .uri(&format!("/admin/api/users/{}/role", user.id))
        .insert_header(("Cookie", cookie))
        .set_json(json!({ "role": "root" }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 400);
}

#[actix_web::test]
async fn reset_user_password_rejects_weak_password() {
    let storage = setup_storage().await;
    let user = make_user("pwrej");
    storage.save_user(&user).await.unwrap();

    let app = test::init_service(
        App::new()
            .wrap(SessionMiddleware::new(
                CookieSessionStore::default(),
                session_key(),
            ))
            .app_data(web::Data::new(storage))
            .route("/test/login", web::get().to(seed_session))
            .route(
                "/admin/api/users/{id}/password",
                web::post().to(admin_extra::reset_user_password),
            ),
    )
    .await;
    let cookie = admin_cookie!(app);

    let req = test::TestRequest::post()
        .uri(&format!("/admin/api/users/{}/password", user.id))
        .insert_header(("Cookie", cookie))
        .set_json(json!({ "password": "short" }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 400);
}

#[actix_web::test]
async fn reset_user_password_updates_hash_and_revokes_tokens() {
    let storage = setup_storage().await;
    let user = make_user("pwok");
    storage.save_user(&user).await.unwrap();
    let client = make_client_row("pw");
    storage.save_client(&client).await.unwrap();
    let token = Token::new(
        "access-pwreset".to_string(),
        None,
        client.client_id.clone(),
        Some(user.id.clone()),
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
            .app_data(web::Data::new(storage.clone()))
            .route("/test/login", web::get().to(seed_session))
            .route(
                "/admin/api/users/{id}/password",
                web::post().to(admin_extra::reset_user_password),
            ),
    )
    .await;
    let cookie = admin_cookie!(app);

    let req = test::TestRequest::post()
        .uri(&format!("/admin/api/users/{}/password", user.id))
        .insert_header(("Cookie", cookie))
        .set_json(json!({ "password": "a-very-solid-password" }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 200);

    let reloaded = storage.get_user_by_id(&user.id).await.unwrap().unwrap();
    assert_ne!(reloaded.password_hash, user.password_hash);
    assert!(reloaded.password_hash.starts_with("$argon2"));

    let revoked = storage
        .get_token_by_access_token("access-pwreset")
        .await
        .unwrap()
        .unwrap();
    assert!(revoked.revoked, "password reset revokes all active tokens");
}

// ---------------------------------------------------------------------------
// Client CRUD extensions
// ---------------------------------------------------------------------------

#[actix_web::test]
async fn create_client_confidential_returns_secret_once() {
    let storage = setup_storage().await;
    let app = test::init_service(
        App::new()
            .wrap(SessionMiddleware::new(
                CookieSessionStore::default(),
                session_key(),
            ))
            .app_data(web::Data::new(storage.clone()))
            .route("/test/login", web::get().to(seed_session))
            .route(
                "/admin/api/clients",
                web::post().to(admin_extra::create_client),
            ),
    )
    .await;
    let cookie = admin_cookie!(app);

    let req = test::TestRequest::post()
        .uri("/admin/api/clients")
        .insert_header(("Cookie", cookie))
        .set_json(json!({
            "name": "Acme",
            "redirect_uris": ["https://acme.test/cb"],
            "grant_types": ["authorization_code", "refresh_token"],
            "scope": "openid profile"
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 201);

    let body: Value = test::read_body_json(resp).await;
    assert_eq!(body["name"], "Acme");
    assert!(body["client_id"].as_str().unwrap().starts_with("client-"));
    let secret = body["client_secret"]
        .as_str()
        .expect("confidential client gets a secret");
    assert!(secret.len() > 16);
}

#[actix_web::test]
async fn create_public_client_has_no_secret() {
    let storage = setup_storage().await;
    let app = test::init_service(
        App::new()
            .wrap(SessionMiddleware::new(
                CookieSessionStore::default(),
                session_key(),
            ))
            .app_data(web::Data::new(storage))
            .route("/test/login", web::get().to(seed_session))
            .route(
                "/admin/api/clients",
                web::post().to(admin_extra::create_client),
            ),
    )
    .await;
    let cookie = admin_cookie!(app);

    let req = test::TestRequest::post()
        .uri("/admin/api/clients")
        .insert_header(("Cookie", cookie))
        .set_json(json!({
            "name": "Public",
            "redirect_uris": ["https://public.test/cb"],
            "token_endpoint_auth_method": "none"
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 201);

    let body: Value = test::read_body_json(resp).await;
    assert!(body["client_secret"].is_null());
    assert_eq!(body["token_endpoint_auth_method"], "none");
}

#[actix_web::test]
async fn create_client_rejects_empty_name() {
    let storage = setup_storage().await;
    let app = test::init_service(
        App::new()
            .wrap(SessionMiddleware::new(
                CookieSessionStore::default(),
                session_key(),
            ))
            .app_data(web::Data::new(storage))
            .route("/test/login", web::get().to(seed_session))
            .route(
                "/admin/api/clients",
                web::post().to(admin_extra::create_client),
            ),
    )
    .await;
    let cookie = admin_cookie!(app);

    let req = test::TestRequest::post()
        .uri("/admin/api/clients")
        .insert_header(("Cookie", cookie))
        .set_json(json!({ "name": "" }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 400);
}

#[actix_web::test]
async fn update_client_mutates_metadata() {
    let storage = setup_storage().await;
    let client = make_client_row("upd");
    storage.save_client(&client).await.unwrap();

    let app = test::init_service(
        App::new()
            .wrap(SessionMiddleware::new(
                CookieSessionStore::default(),
                session_key(),
            ))
            .app_data(web::Data::new(storage.clone()))
            .route("/test/login", web::get().to(seed_session))
            .route(
                "/admin/api/clients/{id}",
                web::put().to(admin_extra::update_client),
            ),
    )
    .await;
    let cookie = admin_cookie!(app);

    let req = test::TestRequest::put()
        .uri(&format!("/admin/api/clients/{}", client.id))
        .insert_header(("Cookie", cookie))
        .set_json(json!({
            "name": "Updated Acme",
            "scope": "openid profile email",
            "enabled": false
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 200);

    let reloaded = storage
        .get_client(&client.client_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(reloaded.name, "Updated Acme");
    assert_eq!(reloaded.scope, "openid profile email");
    assert!(!reloaded.enabled);
}

#[actix_web::test]
async fn set_client_enabled_toggles_and_revokes_tokens_on_disable() {
    let storage = setup_storage().await;
    let client = make_client_row("togl");
    storage.save_client(&client).await.unwrap();
    let token = Token::new(
        "access-client-disable".to_string(),
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
            .app_data(web::Data::new(storage.clone()))
            .route("/test/login", web::get().to(seed_session))
            .route(
                "/admin/api/clients/{id}/enabled",
                web::post().to(admin_extra::set_client_enabled),
            ),
    )
    .await;
    let cookie = admin_cookie!(app);

    let req = test::TestRequest::post()
        .uri(&format!("/admin/api/clients/{}/enabled", client.id))
        .insert_header(("Cookie", cookie))
        .set_json(json!({ "enabled": false }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 200);

    let reloaded = storage
        .get_client(&client.client_id)
        .await
        .unwrap()
        .unwrap();
    assert!(!reloaded.enabled);
    let rev = storage
        .get_token_by_access_token("access-client-disable")
        .await
        .unwrap()
        .unwrap();
    assert!(rev.revoked);
}

#[actix_web::test]
async fn regenerate_client_secret_rejects_public_clients() {
    let storage = setup_storage().await;
    let mut client = make_client_row("pub");
    client.token_endpoint_auth_method = "none".to_string();
    client.client_secret = String::new();
    storage.save_client(&client).await.unwrap();

    let app = test::init_service(
        App::new()
            .wrap(SessionMiddleware::new(
                CookieSessionStore::default(),
                session_key(),
            ))
            .app_data(web::Data::new(storage))
            .route("/test/login", web::get().to(seed_session))
            .route(
                "/admin/api/clients/{id}/regenerate-secret",
                web::post().to(admin_extra::regenerate_client_secret),
            ),
    )
    .await;
    let cookie = admin_cookie!(app);

    let req = test::TestRequest::post()
        .uri(&format!(
            "/admin/api/clients/{}/regenerate-secret",
            client.id
        ))
        .insert_header(("Cookie", cookie))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 400);
}

#[actix_web::test]
async fn regenerate_client_secret_replaces_secret() {
    let storage = setup_storage().await;
    let client = make_client_row("regen");
    let original_secret = client.client_secret.clone();
    storage.save_client(&client).await.unwrap();

    let app = test::init_service(
        App::new()
            .wrap(SessionMiddleware::new(
                CookieSessionStore::default(),
                session_key(),
            ))
            .app_data(web::Data::new(storage.clone()))
            .route("/test/login", web::get().to(seed_session))
            .route(
                "/admin/api/clients/{id}/regenerate-secret",
                web::post().to(admin_extra::regenerate_client_secret),
            ),
    )
    .await;
    let cookie = admin_cookie!(app);

    let req = test::TestRequest::post()
        .uri(&format!(
            "/admin/api/clients/{}/regenerate-secret",
            client.id
        ))
        .insert_header(("Cookie", cookie))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 200);

    let body: Value = test::read_body_json(resp).await;
    let new_secret = body["client_secret"].as_str().unwrap();
    assert_ne!(new_secret, original_secret);

    let reloaded = storage
        .get_client(&client.client_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(reloaded.client_secret, new_secret);
}

// ---------------------------------------------------------------------------
// Denylist
// ---------------------------------------------------------------------------

#[actix_web::test]
async fn add_denylist_entry_round_trips() {
    let storage = setup_storage().await;
    let app = test::init_service(
        App::new()
            .wrap(SessionMiddleware::new(
                CookieSessionStore::default(),
                session_key(),
            ))
            .app_data(web::Data::new(storage.clone()))
            .route("/test/login", web::get().to(seed_session))
            .route(
                "/admin/api/denylist",
                web::post().to(admin_extra::add_denylist),
            )
            .route(
                "/admin/api/denylist",
                web::get().to(admin_extra::list_denylist),
            ),
    )
    .await;
    let cookie = admin_cookie!(app);

    let req = test::TestRequest::post()
        .uri("/admin/api/denylist")
        .insert_header(("Cookie", cookie.clone()))
        .set_json(json!({
            "kind": "ip",
            "value": "198.51.100.10",
            "reason": "brute force"
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 201);

    let req = test::TestRequest::get()
        .uri("/admin/api/denylist")
        .insert_header(("Cookie", cookie))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 200);

    let body: Value = test::read_body_json(resp).await;
    assert_eq!(body["total"].as_u64().unwrap(), 1);
    assert_eq!(body["items"][0]["kind"], "ip");
    assert_eq!(body["items"][0]["value"], "198.51.100.10");
    assert_eq!(body["items"][0]["active"], true);
}

#[actix_web::test]
async fn add_denylist_rejects_unknown_kind() {
    let storage = setup_storage().await;
    let app = test::init_service(
        App::new()
            .wrap(SessionMiddleware::new(
                CookieSessionStore::default(),
                session_key(),
            ))
            .app_data(web::Data::new(storage))
            .route("/test/login", web::get().to(seed_session))
            .route(
                "/admin/api/denylist",
                web::post().to(admin_extra::add_denylist),
            ),
    )
    .await;
    let cookie = admin_cookie!(app);

    let req = test::TestRequest::post()
        .uri("/admin/api/denylist")
        .insert_header(("Cookie", cookie))
        .set_json(json!({ "kind": "country", "value": "ZZ" }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 400);
}

#[actix_web::test]
async fn add_denylist_upserts_on_duplicate() {
    let storage = setup_storage().await;
    let app = test::init_service(
        App::new()
            .wrap(SessionMiddleware::new(
                CookieSessionStore::default(),
                session_key(),
            ))
            .app_data(web::Data::new(storage.clone()))
            .route("/test/login", web::get().to(seed_session))
            .route(
                "/admin/api/denylist",
                web::post().to(admin_extra::add_denylist),
            ),
    )
    .await;
    let cookie = admin_cookie!(app);

    for reason in ["initial", "updated"] {
        let req = test::TestRequest::post()
            .uri("/admin/api/denylist")
            .insert_header(("Cookie", cookie.clone()))
            .set_json(json!({
                "kind": "username",
                "value": "mallory",
                "reason": reason
            }))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert!(resp.status().is_success(), "status: {}", resp.status());
    }

    let entry = storage
        .find_denylist_entry("username", "mallory")
        .await
        .unwrap()
        .expect("entry present");
    assert_eq!(entry.reason, "updated", "latest reason overrides");
}

#[actix_web::test]
async fn remove_denylist_clears_entry() {
    let storage = setup_storage().await;
    let entry = DenylistEntry::new("ip", "203.0.113.5", "noisy", "admin@test.example");
    storage.add_denylist_entry(&entry).await.unwrap();

    let app = test::init_service(
        App::new()
            .wrap(SessionMiddleware::new(
                CookieSessionStore::default(),
                session_key(),
            ))
            .app_data(web::Data::new(storage.clone()))
            .route("/test/login", web::get().to(seed_session))
            .route(
                "/admin/api/denylist/{id}",
                web::delete().to(admin_extra::remove_denylist),
            ),
    )
    .await;
    let cookie = admin_cookie!(app);

    let req = test::TestRequest::delete()
        .uri(&format!("/admin/api/denylist/{}", entry.id))
        .insert_header(("Cookie", cookie))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 200);

    let page = storage.list_denylist(&ListQuery::default()).await.unwrap();
    assert_eq!(page.total, 0);
}

#[actix_web::test]
async fn denylist_expired_entries_not_returned_by_find() {
    let storage = setup_storage().await;
    let mut entry = DenylistEntry::new("ip", "192.0.2.99", "tmp", "admin@test.example");
    entry.expires_at = Some(chrono::Utc::now() - chrono::Duration::minutes(5));
    storage.add_denylist_entry(&entry).await.unwrap();

    let hit = storage
        .find_denylist_entry("ip", "192.0.2.99")
        .await
        .unwrap();
    assert!(hit.is_none(), "expired entries are not returned");
}

// ---------------------------------------------------------------------------
// Audit log
// ---------------------------------------------------------------------------

#[actix_web::test]
async fn admin_mutation_writes_audit_entry() {
    let storage = setup_storage().await;
    let app = test::init_service(
        App::new()
            .wrap(SessionMiddleware::new(
                CookieSessionStore::default(),
                session_key(),
            ))
            .app_data(web::Data::new(storage.clone()))
            .route("/test/login", web::get().to(seed_session))
            .route("/admin/api/users", web::post().to(admin_extra::create_user)),
    )
    .await;
    let cookie = admin_cookie!(app);

    let req = test::TestRequest::post()
        .uri("/admin/api/users")
        .insert_header(("Cookie", cookie))
        .set_json(json!({
            "username": "audit-target",
            "email": "audit@test.example",
            "password": "passphrase-12345"
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 201);

    let entries = storage.list_audit_log(&ListQuery::default()).await.unwrap();
    assert!(entries.total >= 1);
    let entry = entries
        .items
        .iter()
        .find(|e| e.action == "user.create")
        .expect("user.create audit entry");
    assert_eq!(entry.actor_email, "admin@test.example");
    assert_eq!(entry.target_kind, "user");
    assert!(entry.metadata.contains("audit-target"));
}

#[actix_web::test]
async fn list_audit_log_is_paginated_newest_first() {
    let storage = setup_storage().await;

    for i in 0..5 {
        let mut entry = oauth2_core::AuditLogEntry::new(
            "actor",
            "actor@test.example",
            &format!("test.action.{i}"),
        );
        entry.created_at = chrono::Utc::now() + chrono::Duration::seconds(i as i64);
        storage.write_audit_log(&entry).await.unwrap();
    }

    let app = test::init_service(App::new().app_data(web::Data::new(storage)).route(
        "/admin/api/audit",
        web::get().to(admin_extra::list_audit_log),
    ))
    .await;

    let req = test::TestRequest::get()
        .uri("/admin/api/audit?limit=3")
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 200);

    let body: Value = test::read_body_json(resp).await;
    assert_eq!(body["items"].as_array().unwrap().len(), 3);
    assert_eq!(body["total"].as_u64().unwrap(), 5);
    assert_eq!(body["items"][0]["action"], "test.action.4");
}

// ---------------------------------------------------------------------------
// Bulk revoke
// ---------------------------------------------------------------------------

#[actix_web::test]
async fn bulk_revoke_by_user_revokes_all_their_tokens() {
    let storage = setup_storage().await;
    let user = make_user("bulk");
    storage.save_user(&user).await.unwrap();
    let client = make_client_row("bulk");
    storage.save_client(&client).await.unwrap();

    for i in 0..3 {
        let t = Token::new(
            format!("access-bulk-{i}"),
            None,
            client.client_id.clone(),
            Some(user.id.clone()),
            "read".to_string(),
            3600,
            None,
        );
        storage.save_token(&t).await.unwrap();
    }

    let app = test::init_service(
        App::new()
            .wrap(SessionMiddleware::new(
                CookieSessionStore::default(),
                session_key(),
            ))
            .app_data(web::Data::new(storage.clone()))
            .route("/test/login", web::get().to(seed_session))
            .route(
                "/admin/api/tokens/revoke-by-user",
                web::post().to(admin_extra::bulk_revoke_by_user),
            ),
    )
    .await;
    let cookie = admin_cookie!(app);

    let req = test::TestRequest::post()
        .uri("/admin/api/tokens/revoke-by-user")
        .insert_header(("Cookie", cookie))
        .set_json(json!({ "user_id": user.id }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 200);

    let body: Value = test::read_body_json(resp).await;
    assert_eq!(body["revoked"].as_u64().unwrap(), 3);

    for i in 0..3 {
        let t = storage
            .get_token_by_access_token(&format!("access-bulk-{i}"))
            .await
            .unwrap()
            .unwrap();
        assert!(t.revoked);
    }
}

#[actix_web::test]
async fn bulk_revoke_by_client_revokes_only_that_client() {
    let storage = setup_storage().await;
    let c1 = make_client_row("one");
    let c2 = make_client_row("two");
    storage.save_client(&c1).await.unwrap();
    storage.save_client(&c2).await.unwrap();

    storage
        .save_token(&Token::new(
            "t1".to_string(),
            None,
            c1.client_id.clone(),
            None,
            "read".to_string(),
            3600,
            None,
        ))
        .await
        .unwrap();
    storage
        .save_token(&Token::new(
            "t2".to_string(),
            None,
            c2.client_id.clone(),
            None,
            "read".to_string(),
            3600,
            None,
        ))
        .await
        .unwrap();

    let app = test::init_service(
        App::new()
            .wrap(SessionMiddleware::new(
                CookieSessionStore::default(),
                session_key(),
            ))
            .app_data(web::Data::new(storage.clone()))
            .route("/test/login", web::get().to(seed_session))
            .route(
                "/admin/api/tokens/revoke-by-client",
                web::post().to(admin_extra::bulk_revoke_by_client),
            ),
    )
    .await;
    let cookie = admin_cookie!(app);

    let req = test::TestRequest::post()
        .uri("/admin/api/tokens/revoke-by-client")
        .insert_header(("Cookie", cookie))
        .set_json(json!({ "client_id": c1.client_id }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 200);

    let t1 = storage
        .get_token_by_access_token("t1")
        .await
        .unwrap()
        .unwrap();
    let t2 = storage
        .get_token_by_access_token("t2")
        .await
        .unwrap()
        .unwrap();
    assert!(t1.revoked);
    assert!(!t2.revoked, "tokens for other clients are untouched");
}

// ---------------------------------------------------------------------------
// Capabilities
// ---------------------------------------------------------------------------

#[actix_web::test]
async fn capabilities_exposes_new_feature_flags() {
    let storage = setup_storage().await;
    let app = test::init_service(App::new().app_data(web::Data::new(storage.clone())).route(
        "/admin/api/capabilities",
        web::get().to(admin::capabilities),
    ))
    .await;

    let req = test::TestRequest::get()
        .uri("/admin/api/capabilities")
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 200);

    let body: Value = test::read_body_json(resp).await;
    for flag in [
        "events",
        "device_flow",
        "key_rotation",
        "user_crud",
        "client_crud",
        "denylist",
        "audit_log",
        "bulk_revoke",
    ] {
        assert_eq!(body[flag], true, "cap flag {flag} should be true");
    }
}

// NOTE: No Mongo-backed capabilities test is included here.
// `MongoStorage::new()` opens a real client and requires a running Mongo
// server, which is out of scope for unit tests. Mongo inherits the
// trait defaults (`false` for both `supports_denylist` /
// `supports_audit_log` on `oauth2_ports::Storage`) until real impls ship
// in v0.7.0.
