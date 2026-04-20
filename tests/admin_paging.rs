/// Integration tests for admin API paging, filtering, and detail endpoints.
use actix_web::{test, web, App};
use serde_json::Value;

use oauth2_core::{Client, User};
use oauth2_ports::DynStorage;

async fn setup_storage() -> DynStorage {
    let storage = oauth2_storage_factory::create_storage("sqlite::memory:")
        .await
        .expect("create storage");
    storage.init().await.expect("init");
    storage
}

fn make_client(suffix: &str) -> Client {
    Client::new(
        format!("client-{suffix}"),
        "secret".to_string(),
        vec!["https://example.com/cb".to_string()],
        vec!["authorization_code".to_string()],
        "read".to_string(),
        format!("Test Client {suffix}"),
    )
}

fn make_user(suffix: &str) -> User {
    let now = chrono::Utc::now();
    User {
        id: format!("uid-{suffix}"),
        username: format!("user_{suffix}"),
        password_hash: "unused".to_string(),
        email: format!("user_{suffix}@test.example"),
        enabled: true,
        role: "user".to_string(),
        created_at: now,
        updated_at: now,
    }
}

// ---------------------------------------------------------------------------
// Paging tests
// ---------------------------------------------------------------------------

#[actix_web::test]
async fn list_clients_returns_paged_envelope() {
    let storage = setup_storage().await;

    for i in 0..15u32 {
        storage
            .save_client(&make_client(&i.to_string()))
            .await
            .expect("save client");
    }

    let app = test::init_service(App::new().app_data(web::Data::new(storage)).route(
        "/admin/api/clients",
        web::get().to(oauth2_actix::handlers::admin::list_clients),
    ))
    .await;

    let req = test::TestRequest::get()
        .uri("/admin/api/clients?limit=5&offset=0")
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 200);

    let body: Value = test::read_body_json(resp).await;
    assert_eq!(body["items"].as_array().unwrap().len(), 5);
    assert_eq!(body["total"].as_u64().unwrap(), 15);
    assert_eq!(body["limit"].as_u64().unwrap(), 5);
    assert_eq!(body["offset"].as_u64().unwrap(), 0);
}

#[actix_web::test]
async fn list_clients_last_page_has_remainder() {
    let storage = setup_storage().await;

    for i in 0..10u32 {
        storage
            .save_client(&make_client(&i.to_string()))
            .await
            .expect("save client");
    }

    let app = test::init_service(App::new().app_data(web::Data::new(storage)).route(
        "/admin/api/clients",
        web::get().to(oauth2_actix::handlers::admin::list_clients),
    ))
    .await;

    let req = test::TestRequest::get()
        .uri("/admin/api/clients?limit=4&offset=8")
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 200);

    let body: Value = test::read_body_json(resp).await;
    assert_eq!(
        body["items"].as_array().unwrap().len(),
        2,
        "last page has 2 items"
    );
    assert_eq!(body["total"].as_u64().unwrap(), 10);
    assert_eq!(body["offset"].as_u64().unwrap(), 8);
}

#[actix_web::test]
async fn list_clients_search_filters_by_name() {
    let storage = setup_storage().await;

    storage
        .save_client(&make_client("alpha"))
        .await
        .expect("save");
    storage
        .save_client(&make_client("beta"))
        .await
        .expect("save");
    storage
        .save_client(&make_client("gamma"))
        .await
        .expect("save");

    let app = test::init_service(App::new().app_data(web::Data::new(storage)).route(
        "/admin/api/clients",
        web::get().to(oauth2_actix::handlers::admin::list_clients),
    ))
    .await;

    let req = test::TestRequest::get()
        .uri("/admin/api/clients?search=alpha")
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 200);

    let body: Value = test::read_body_json(resp).await;
    let items = body["items"].as_array().unwrap();
    assert!(
        items.iter().any(|c| c["name"]
            .as_str()
            .unwrap_or("")
            .to_lowercase()
            .contains("alpha")),
        "alpha client should appear"
    );
    assert!(
        !items.iter().any(|c| c["name"]
            .as_str()
            .unwrap_or("")
            .to_lowercase()
            .contains("beta")),
        "beta should be filtered out"
    );
}

#[actix_web::test]
async fn list_clients_empty_when_none_exist() {
    let storage = setup_storage().await;

    let app = test::init_service(App::new().app_data(web::Data::new(storage)).route(
        "/admin/api/clients",
        web::get().to(oauth2_actix::handlers::admin::list_clients),
    ))
    .await;

    let req = test::TestRequest::get()
        .uri("/admin/api/clients")
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 200);

    let body: Value = test::read_body_json(resp).await;
    assert_eq!(body["items"].as_array().unwrap().len(), 0);
    assert_eq!(body["total"].as_u64().unwrap(), 0);
}

// ---------------------------------------------------------------------------
// Detail endpoint tests
// ---------------------------------------------------------------------------

#[actix_web::test]
async fn get_client_returns_detail() {
    let storage = setup_storage().await;
    let client = make_client("detail");
    storage.save_client(&client).await.expect("save");

    let app = test::init_service(App::new().app_data(web::Data::new(storage)).route(
        "/admin/api/clients/{id}",
        web::get().to(oauth2_actix::handlers::admin::get_client),
    ))
    .await;

    let uri = format!("/admin/api/clients/{}", client.id);
    let req = test::TestRequest::get().uri(&uri).to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 200);

    let body: Value = test::read_body_json(resp).await;
    assert_eq!(body["client_id"].as_str().unwrap(), client.client_id);
    assert_eq!(body["name"].as_str().unwrap(), client.name);
}

#[actix_web::test]
async fn get_client_404_for_missing() {
    let storage = setup_storage().await;

    let app = test::init_service(App::new().app_data(web::Data::new(storage)).route(
        "/admin/api/clients/{id}",
        web::get().to(oauth2_actix::handlers::admin::get_client),
    ))
    .await;

    let req = test::TestRequest::get()
        .uri("/admin/api/clients/does-not-exist")
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 404);
}

#[actix_web::test]
async fn get_user_returns_detail() {
    let storage = setup_storage().await;
    let user = make_user("alice");
    storage.save_user(&user).await.expect("save");

    let app = test::init_service(App::new().app_data(web::Data::new(storage)).route(
        "/admin/api/users/{id}",
        web::get().to(oauth2_actix::handlers::admin::get_user),
    ))
    .await;

    let uri = format!("/admin/api/users/{}", user.id);
    let req = test::TestRequest::get().uri(&uri).to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 200);

    let body: Value = test::read_body_json(resp).await;
    assert_eq!(body["username"].as_str().unwrap(), user.username);
}

#[actix_web::test]
async fn get_user_404_for_missing() {
    let storage = setup_storage().await;

    let app = test::init_service(App::new().app_data(web::Data::new(storage)).route(
        "/admin/api/users/{id}",
        web::get().to(oauth2_actix::handlers::admin::get_user),
    ))
    .await;

    let req = test::TestRequest::get()
        .uri("/admin/api/users/no-such-user")
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 404);
}

// ---------------------------------------------------------------------------
// Dashboard
// ---------------------------------------------------------------------------

#[actix_web::test]
async fn dashboard_returns_expected_shape() {
    let storage = setup_storage().await;
    storage
        .save_client(&make_client("dash1"))
        .await
        .expect("save");
    storage
        .save_client(&make_client("dash2"))
        .await
        .expect("save");
    storage.save_user(&make_user("dash")).await.expect("save");

    let app = test::init_service(App::new().app_data(web::Data::new(storage)).route(
        "/admin/api/dashboard",
        web::get().to(oauth2_actix::handlers::admin::dashboard),
    ))
    .await;

    let req = test::TestRequest::get()
        .uri("/admin/api/dashboard")
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 200);

    let body: Value = test::read_body_json(resp).await;
    assert_eq!(body["total_clients"].as_i64().unwrap(), 2);
    assert_eq!(body["total_users"].as_i64().unwrap(), 1);
    assert!(body.get("active_tokens").is_some());
    assert!(body.get("pending_device_codes").is_some());
}

// ---------------------------------------------------------------------------
// Users paging
// ---------------------------------------------------------------------------

#[actix_web::test]
async fn list_users_paged() {
    let storage = setup_storage().await;

    for i in 0..8u32 {
        storage
            .save_user(&make_user(&i.to_string()))
            .await
            .expect("save user");
    }

    let app = test::init_service(App::new().app_data(web::Data::new(storage)).route(
        "/admin/api/users",
        web::get().to(oauth2_actix::handlers::admin::list_users),
    ))
    .await;

    let req = test::TestRequest::get()
        .uri("/admin/api/users?limit=3&offset=6")
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 200);

    let body: Value = test::read_body_json(resp).await;
    assert_eq!(body["total"].as_u64().unwrap(), 8);
    assert_eq!(body["items"].as_array().unwrap().len(), 2);
}
