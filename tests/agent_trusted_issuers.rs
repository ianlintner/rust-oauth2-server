//! Task 6 (Phase 7 agent / A2A OAuth): trusted issuers registry storage
//! round-trip, `Storage::get_user_by_email`, and the admin HTTP endpoints.

use actix_session::{storage::CookieSessionStore, Session, SessionMiddleware};
use actix_web::{cookie::Key, test, web, App, HttpResponse};

use oauth2_core::{TrustedIssuer, User};
use oauth2_ports::DynStorage;

/// Use a unique file-backed SQLite per test, following the pattern documented
/// in `tests/admin_extra.rs`: `sqlite::memory:` creates a fresh database per
/// pooled connection, so a pool with >1 connection can lose writes when a
/// later read acquires a different connection. A tempfile-backed DB gives
/// the reliable write-then-read consistency these tests need.
async fn setup_storage() -> DynStorage {
    let tmp = tempfile::NamedTempFile::new().expect("tempfile");
    let url = format!("sqlite://{}", tmp.path().display());
    // Leak the guard so the file outlives the test — Drop removes it.
    std::mem::forget(tmp);
    let storage = oauth2_storage_factory::create_storage(&url)
        .await
        .expect("create storage");
    storage.init().await.expect("init storage");
    storage
}

// --- Storage: trusted issuers round-trip -----------------------------------

#[actix_web::test]
async fn trusted_issuer_storage_round_trip() {
    let storage = setup_storage().await;

    // Unknown issuer returns None.
    assert!(storage
        .get_trusted_issuer("https://unknown.example")
        .await
        .expect("get_trusted_issuer should not error")
        .is_none());

    let mut trusted_issuer = TrustedIssuer::new(
        "https://issuer.example".to_string(),
        "https://issuer.example/.well-known/jwks.json".to_string(),
    );
    trusted_issuer.subject_mapping = "email".to_string();
    trusted_issuer.jit_provision = true;
    trusted_issuer.allowed_audiences =
        serde_json::to_string(&vec!["http://localhost/oauth/token"]).unwrap();
    trusted_issuer.allowed_client_ids = serde_json::to_string(&vec!["agent-1"]).unwrap();

    storage
        .save_trusted_issuer(&trusted_issuer)
        .await
        .expect("save_trusted_issuer");

    let fetched = storage
        .get_trusted_issuer("https://issuer.example")
        .await
        .expect("get_trusted_issuer")
        .expect("trusted issuer should exist after save");
    assert_eq!(fetched.id, trusted_issuer.id);
    assert_eq!(fetched.issuer, "https://issuer.example");
    assert_eq!(
        fetched.jwks_uri,
        "https://issuer.example/.well-known/jwks.json"
    );
    assert_eq!(fetched.subject_mapping, "email");
    assert!(fetched.jit_provision);
    assert_eq!(fetched.allowed_client_ids_vec(), vec!["agent-1"]);
    assert!(fetched.allows_client("agent-1"));
    assert!(!fetched.allows_client("agent-2"));

    let all = storage
        .list_trusted_issuers()
        .await
        .expect("list_trusted_issuers");
    assert_eq!(all.len(), 1);
    assert_eq!(all[0].issuer, "https://issuer.example");

    storage
        .delete_trusted_issuer(&trusted_issuer.id)
        .await
        .expect("delete_trusted_issuer");

    assert!(storage
        .get_trusted_issuer("https://issuer.example")
        .await
        .expect("get_trusted_issuer after delete")
        .is_none());
    let all_after_delete = storage
        .list_trusted_issuers()
        .await
        .expect("list_trusted_issuers after delete");
    assert!(all_after_delete.is_empty());
}

// --- Storage: get_user_by_email --------------------------------------------

#[actix_web::test]
async fn get_user_by_email_finds_saved_user_and_none_for_unknown() {
    let storage = setup_storage().await;

    let now = chrono::Utc::now();
    let user = User {
        id: "user_email_1".to_string(),
        username: "email_user".to_string(),
        password_hash: "not_used".to_string(),
        email: "agent-user@example.test".to_string(),
        enabled: true,
        role: "user".to_string(),
        created_at: now,
        updated_at: now,
    };
    storage.save_user(&user).await.expect("save user");

    let found = storage
        .get_user_by_email("agent-user@example.test")
        .await
        .expect("get_user_by_email should not error")
        .expect("user should be found by email");
    assert_eq!(found.id, "user_email_1");
    assert_eq!(found.username, "email_user");

    let missing = storage
        .get_user_by_email("nobody@example.test")
        .await
        .expect("get_user_by_email should not error for unknown email");
    assert!(missing.is_none());
}

// --- Admin HTTP endpoints ----------------------------------------------------

/// Test-only login route that establishes an admin session, mirroring the
/// pattern used in `tests/security_http.rs` (`login_renews_session_id_after_successful_authentication`).
async fn admin_login(session: Session) -> HttpResponse {
    session.insert("user_id", "admin_1").unwrap();
    session.insert("role", "admin").unwrap();
    HttpResponse::Ok().finish()
}

fn extract_session_cookie(
    resp: &actix_web::dev::ServiceResponse<impl actix_web::body::MessageBody>,
) -> String {
    resp.response()
        .headers()
        .get(actix_web::http::header::SET_COOKIE)
        .and_then(|h| h.to_str().ok())
        .expect("session cookie should be set")
        .split(';')
        .next()
        .unwrap()
        .to_string()
}

#[actix_web::test]
async fn admin_trusted_issuers_post_get_delete_round_trip() {
    use oauth2_actix::handlers::admin_trusted_issuers::{
        create_trusted_issuer, delete_trusted_issuer, list_trusted_issuers,
    };
    use oauth2_actix::middleware::admin_guard::AdminGuard;

    let dyn_storage = setup_storage().await;

    let session_key = Key::generate();
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(dyn_storage))
            .wrap(SessionMiddleware::new(
                CookieSessionStore::default(),
                session_key.clone(),
            ))
            .route("/test-login", web::post().to(admin_login))
            .service(
                web::scope("/admin")
                    .wrap(AdminGuard)
                    .route("/trusted-issuers", web::get().to(list_trusted_issuers))
                    .route("/trusted-issuers", web::post().to(create_trusted_issuer))
                    .route(
                        "/trusted-issuers/{id}",
                        web::delete().to(delete_trusted_issuer),
                    ),
            ),
    )
    .await;

    let login_req = test::TestRequest::post().uri("/test-login").to_request();
    let login_resp = test::call_service(&app, login_req).await;
    let session_cookie = extract_session_cookie(&login_resp);

    // GET starts empty.
    let list_req = test::TestRequest::get()
        .uri("/admin/trusted-issuers")
        .insert_header(("Cookie", session_cookie.clone()))
        .to_request();
    let list_resp = test::call_service(&app, list_req).await;
    assert_eq!(list_resp.status(), 200);
    let body: serde_json::Value = test::read_body_json(list_resp).await;
    assert_eq!(body["trusted_issuers"].as_array().unwrap().len(), 0);

    // POST creates a trusted issuer.
    let post_req = test::TestRequest::post()
        .uri("/admin/trusted-issuers")
        .insert_header(("Cookie", session_cookie.clone()))
        .set_json(serde_json::json!({
            "issuer": "https://agent-issuer.example",
            "jwks_uri": "https://agent-issuer.example/.well-known/jwks.json",
            "subject_mapping": "email",
            "jit_provision": true,
            "allowed_client_ids": ["agent-1"]
        }))
        .to_request();
    let post_resp = test::call_service(&app, post_req).await;
    assert_eq!(post_resp.status(), 201);
    let created: serde_json::Value = test::read_body_json(post_resp).await;
    assert_eq!(created["issuer"], "https://agent-issuer.example");
    assert_eq!(created["subject_mapping"], "email");
    assert_eq!(created["jit_provision"], true);
    let created_id = created["id"].as_str().unwrap().to_string();

    // GET now shows the created issuer.
    let list_req2 = test::TestRequest::get()
        .uri("/admin/trusted-issuers")
        .insert_header(("Cookie", session_cookie.clone()))
        .to_request();
    let list_resp2 = test::call_service(&app, list_req2).await;
    assert_eq!(list_resp2.status(), 200);
    let body2: serde_json::Value = test::read_body_json(list_resp2).await;
    assert_eq!(body2["trusted_issuers"].as_array().unwrap().len(), 1);

    // Invalid subject_mapping is rejected.
    let bad_req = test::TestRequest::post()
        .uri("/admin/trusted-issuers")
        .insert_header(("Cookie", session_cookie.clone()))
        .set_json(serde_json::json!({
            "issuer": "https://bad-issuer.example",
            "jwks_uri": "https://bad-issuer.example/jwks.json",
            "subject_mapping": "not_a_real_mapping"
        }))
        .to_request();
    let bad_resp = test::call_service(&app, bad_req).await;
    assert_eq!(bad_resp.status(), 400);
    let bad_body: serde_json::Value = test::read_body_json(bad_resp).await;
    assert_eq!(bad_body["error"], "invalid_request");

    // A plain-http jwks_uri is rejected (SSRF / MITM signature-verification gap).
    let http_jwks_req = test::TestRequest::post()
        .uri("/admin/trusted-issuers")
        .insert_header(("Cookie", session_cookie.clone()))
        .set_json(serde_json::json!({
            "issuer": "https://insecure-issuer.example",
            "jwks_uri": "http://insecure-issuer.example/jwks.json"
        }))
        .to_request();
    let http_jwks_resp = test::call_service(&app, http_jwks_req).await;
    assert_eq!(http_jwks_resp.status(), 400);
    let http_jwks_body: serde_json::Value = test::read_body_json(http_jwks_resp).await;
    assert_eq!(http_jwks_body["error"], "invalid_request");

    // A malformed jwks_uri is rejected.
    let malformed_jwks_req = test::TestRequest::post()
        .uri("/admin/trusted-issuers")
        .insert_header(("Cookie", session_cookie.clone()))
        .set_json(serde_json::json!({
            "issuer": "https://malformed-issuer.example",
            "jwks_uri": "not a url"
        }))
        .to_request();
    let malformed_jwks_resp = test::call_service(&app, malformed_jwks_req).await;
    assert_eq!(malformed_jwks_resp.status(), 400);
    let malformed_jwks_body: serde_json::Value = test::read_body_json(malformed_jwks_resp).await;
    assert_eq!(malformed_jwks_body["error"], "invalid_request");

    // Neither of the rejected attempts was persisted.
    let list_req_after_rejections = test::TestRequest::get()
        .uri("/admin/trusted-issuers")
        .insert_header(("Cookie", session_cookie.clone()))
        .to_request();
    let list_resp_after_rejections = test::call_service(&app, list_req_after_rejections).await;
    let body_after_rejections: serde_json::Value =
        test::read_body_json(list_resp_after_rejections).await;
    assert_eq!(
        body_after_rejections["trusted_issuers"]
            .as_array()
            .unwrap()
            .len(),
        1
    );

    // DELETE removes it.
    let del_req = test::TestRequest::delete()
        .uri(&format!("/admin/trusted-issuers/{created_id}"))
        .insert_header(("Cookie", session_cookie.clone()))
        .to_request();
    let del_resp = test::call_service(&app, del_req).await;
    assert_eq!(del_resp.status(), 200);

    let list_req3 = test::TestRequest::get()
        .uri("/admin/trusted-issuers")
        .insert_header(("Cookie", session_cookie))
        .to_request();
    let list_resp3 = test::call_service(&app, list_req3).await;
    let body3: serde_json::Value = test::read_body_json(list_resp3).await;
    assert_eq!(body3["trusted_issuers"].as_array().unwrap().len(), 0);
}

#[actix_web::test]
async fn admin_trusted_issuers_requires_admin_session() {
    use oauth2_actix::handlers::admin_trusted_issuers::list_trusted_issuers;
    use oauth2_actix::middleware::admin_guard::AdminGuard;

    let dyn_storage = setup_storage().await;

    let session_key = Key::generate();
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(dyn_storage))
            .wrap(SessionMiddleware::new(
                CookieSessionStore::default(),
                session_key.clone(),
            ))
            .service(
                web::scope("/admin")
                    .wrap(AdminGuard)
                    .route("/trusted-issuers", web::get().to(list_trusted_issuers)),
            ),
    )
    .await;

    let req = test::TestRequest::get()
        .uri("/admin/trusted-issuers")
        .to_request();
    let resp = test::call_service(&app, req).await;

    assert_eq!(
        resp.status(),
        302,
        "unauthenticated request should redirect to login"
    );
}
