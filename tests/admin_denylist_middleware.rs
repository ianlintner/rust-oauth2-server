//! Integration test for the DenylistGuard middleware — requests from
//! denylisted IPs must be rejected with 403 before reaching the handler.

use actix_web::{test, web, App, HttpResponse};
use oauth2_core::{DenylistEntry, DENYLIST_KIND_IP};
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

async fn echo_ok() -> HttpResponse {
    HttpResponse::Ok().body("ok")
}

#[actix_web::test]
async fn middleware_allows_requests_from_non_denylisted_ip() {
    let storage = setup_storage().await;

    let app = test::init_service(
        App::new()
            .wrap(oauth2_actix::middleware::denylist::DenylistGuard)
            .app_data(web::Data::new(storage))
            .route("/echo", web::get().to(echo_ok)),
    )
    .await;

    let req = test::TestRequest::get()
        .uri("/echo")
        .peer_addr("203.0.113.99:40000".parse().unwrap())
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 200);
}

#[actix_web::test]
async fn middleware_blocks_denylisted_ip() {
    let storage = setup_storage().await;
    let entry = DenylistEntry::new(
        DENYLIST_KIND_IP,
        "198.51.100.5",
        "brute force",
        "admin@test.example",
    );
    storage.add_denylist_entry(&entry).await.unwrap();

    let app = test::init_service(
        App::new()
            .wrap(oauth2_actix::middleware::denylist::DenylistGuard)
            .app_data(web::Data::new(storage))
            .route("/echo", web::get().to(echo_ok)),
    )
    .await;

    let req = test::TestRequest::get()
        .uri("/echo")
        .peer_addr("198.51.100.5:40000".parse().unwrap())
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 403);

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["error"], "access_denied");
}

#[actix_web::test]
async fn middleware_honors_expired_denylist_entries() {
    let storage = setup_storage().await;
    let mut entry = DenylistEntry::new(
        DENYLIST_KIND_IP,
        "192.0.2.77",
        "temporary",
        "admin@test.example",
    );
    entry.expires_at = Some(chrono::Utc::now() - chrono::Duration::minutes(10));
    storage.add_denylist_entry(&entry).await.unwrap();

    let app = test::init_service(
        App::new()
            .wrap(oauth2_actix::middleware::denylist::DenylistGuard)
            .app_data(web::Data::new(storage))
            .route("/echo", web::get().to(echo_ok)),
    )
    .await;

    let req = test::TestRequest::get()
        .uri("/echo")
        .peer_addr("192.0.2.77:40000".parse().unwrap())
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(
        resp.status(),
        200,
        "expired denylist entries no longer block"
    );
}

#[actix_web::test]
async fn check_subject_denylisted_returns_reason() {
    let storage = setup_storage().await;
    let entry = DenylistEntry::new("username", "mallory", "abuse", "admin@test.example");
    storage.add_denylist_entry(&entry).await.unwrap();

    let hit = oauth2_actix::middleware::denylist::check_subject_denylisted(
        &storage, "username", "mallory",
    )
    .await;
    assert_eq!(hit.as_deref(), Some("abuse"));

    let miss =
        oauth2_actix::middleware::denylist::check_subject_denylisted(&storage, "username", "alice")
            .await;
    assert!(miss.is_none());
}

#[actix_web::test]
async fn check_subject_denylisted_ignores_empty_value() {
    let storage = setup_storage().await;
    let hit =
        oauth2_actix::middleware::denylist::check_subject_denylisted(&storage, "email", "").await;
    assert!(hit.is_none());
}
