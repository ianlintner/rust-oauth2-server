//! Integration tests asserting the Prometheus metrics are actually wired:
//! - `MetricsMiddleware` emits the `status_class`-labelled request counter and
//!   observes the request-duration histogram.
//! - Admin handlers increment the counters they own (token revoke, authz code).
//!
//! Admin dashboard charts depend on all of the above being populated.

use std::sync::Arc;

use actix::Actor;
use actix_session::{storage::CookieSessionStore, Session, SessionMiddleware};
use actix_web::{cookie::Key, test, web, App, HttpResponse};
use tokio::sync::RwLock;

use oauth2_actix::actors::TokenActorPool;
use oauth2_actix::handlers::admin;
use oauth2_actix::handlers::wellknown::OidcConfig;
use oauth2_core::{Client, Token, User};
use oauth2_observability::{actix::MetricsMiddleware, encode_prometheus_text, Metrics};
use oauth2_ports::DynStorage;

async fn setup_storage() -> DynStorage {
    // Unique file-backed SQLite per test. `sqlite::memory:` creates a fresh
    // database per connection, which breaks the pool's multi-connection model.
    let tmp = tempfile::NamedTempFile::new().expect("tempfile");
    let url = format!("sqlite://{}", tmp.path().display());
    std::mem::forget(tmp);
    let storage = oauth2_storage_factory::create_storage(&url)
        .await
        .expect("create storage");
    storage.init().await.expect("init");
    storage
}

async fn ok_handler() -> HttpResponse {
    HttpResponse::Ok().body("ok")
}

async fn not_found_handler() -> HttpResponse {
    HttpResponse::NotFound().body("not found")
}

async fn metrics_dump(metrics: web::Data<Metrics>) -> HttpResponse {
    let body = encode_prometheus_text(&metrics.registry).expect("encode");
    HttpResponse::Ok().body(body)
}

/// Parse the trailing numeric value from a Prometheus text-format line like
/// `name{labels} 3` or `name 3`.
fn parse_value(line: &str) -> f64 {
    line.rsplit_once(' ')
        .and_then(|(_, v)| v.trim().parse::<f64>().ok())
        .unwrap_or(0.0)
}

fn s256(verifier: &str) -> String {
    use base64::{engine::general_purpose, Engine as _};
    use sha2::{Digest, Sha256};
    general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

async fn test_set_session(session: Session) -> HttpResponse {
    session.insert("user_id", "user_metrics").unwrap();
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

#[actix_web::test]
async fn metrics_middleware_emits_status_class_counter_and_duration_histogram() {
    let metrics = Metrics::new().expect("metrics");

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(metrics.clone()))
            .wrap(MetricsMiddleware::new(metrics.clone()))
            .route("/ok", web::get().to(ok_handler))
            .route("/missing", web::get().to(not_found_handler))
            .route("/metrics", web::get().to(metrics_dump)),
    )
    .await;

    for _ in 0..3 {
        let req = test::TestRequest::get().uri("/ok").to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);
    }

    for _ in 0..2 {
        let req = test::TestRequest::get().uri("/missing").to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 404);
    }

    let req = test::TestRequest::get().uri("/metrics").to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 200);
    let body = test::read_body(resp).await;
    let body = std::str::from_utf8(&body).expect("utf8 metrics body");

    assert!(
        body.lines().any(|l| l
            .starts_with("oauth2_server_http_requests_by_class_total{status_class=\"2xx\"}")
            && parse_value(l) > 0.0),
        "expected 2xx status_class counter > 0\n{body}"
    );
    assert!(
        body.lines().any(|l| l
            .starts_with("oauth2_server_http_requests_by_class_total{status_class=\"4xx\"}")
            && parse_value(l) > 0.0),
        "expected 4xx status_class counter > 0\n{body}"
    );

    let inf_line = body
        .lines()
        .find(|l| l.starts_with("oauth2_server_http_request_duration_seconds_bucket{le=\"+Inf\"}"))
        .unwrap_or_else(|| panic!("expected +Inf bucket line\n{body}"));
    assert!(
        parse_value(inf_line) > 0.0,
        "expected +Inf bucket > 0, got: {inf_line}"
    );
}

#[actix_web::test]
async fn admin_revoke_token_increments_prometheus_counter() {
    let storage = setup_storage().await;
    let metrics = Metrics::new().expect("metrics");

    // Token FKs require an existing client + user row.
    let user = User::new(
        "metrics-user".to_string(),
        "$argon2id$unused".to_string(),
        "metrics-user@test.example".to_string(),
    );
    storage.save_user(&user).await.expect("save user");
    let client = Client::new(
        "client-metrics".to_string(),
        "secret".to_string(),
        vec!["https://example.com/cb".to_string()],
        vec!["authorization_code".to_string()],
        "read".to_string(),
        "Metrics Client".to_string(),
    );
    storage.save_client(&client).await.expect("save client");

    let token = Token::new(
        "access-metrics-wire".to_string(),
        None,
        client.client_id.clone(),
        Some(user.id.clone()),
        "read".to_string(),
        3600,
        None,
    );
    storage.save_token(&token).await.expect("save token");

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(storage))
            .app_data(web::Data::new(metrics))
            .route(
                "/admin/api/tokens/{id}/revoke",
                web::post().to(admin::admin_revoke_token),
            )
            .route("/metrics", web::get().to(admin::system_metrics)),
    )
    .await;

    let baseline = test::TestRequest::get().uri("/metrics").to_request();
    let baseline_body = test::call_and_read_body(&app, baseline).await;
    let baseline_text = std::str::from_utf8(&baseline_body).unwrap();
    assert!(
        baseline_text.contains("oauth2_server_oauth_token_revoked_total 0"),
        "baseline metrics missing revoked counter line: {baseline_text}"
    );

    let req = test::TestRequest::post()
        .uri("/admin/api/tokens/access-metrics-wire/revoke")
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 200);

    let after = test::TestRequest::get().uri("/metrics").to_request();
    let after_body = test::call_and_read_body(&app, after).await;
    let after_text = std::str::from_utf8(&after_body).unwrap();

    let line = after_text
        .lines()
        .find(|l| l.starts_with("oauth2_server_oauth_token_revoked_total "))
        .expect("revoked_total line present");
    let value: u64 = line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .expect("numeric counter value");
    assert!(
        value >= 1,
        "oauth2_server_oauth_token_revoked_total should be >= 1 after revoke, got {value}"
    );
}

/// A successful authorization_code flow must increment
/// `oauth2_server_oauth_authorization_codes_issued`. This metric backs the
/// "Auth Codes" bar on the admin dashboard's Metrics page.
#[actix_web::test]
async fn authorize_increments_authorization_codes_issued_counter() {
    const ISSUER: &str = "https://auth.example.com";

    let client = Client::new(
        "client_metrics".to_string(),
        "secret_metrics".to_string(),
        vec!["https://app.example/cb".to_string()],
        vec!["authorization_code".to_string()],
        "read".to_string(),
        "test".to_string(),
    );

    let storage = oauth2_storage_factory::create_storage("sqlite::memory:")
        .await
        .expect("create storage");
    storage.init().await.expect("init");
    storage.save_client(&client).await.expect("save client");

    let now = chrono::Utc::now();
    let user = User {
        id: "user_metrics".to_string(),
        username: "user_metrics".to_string(),
        password_hash: "unused".to_string(),
        email: "user_metrics@example.test".to_string(),
        enabled: true,
        role: "user".to_string(),
        created_at: now,
        updated_at: now,
    };
    storage.save_user(&user).await.expect("save user");

    let jwt_secret = "metrics_test_jwt_secret_at_least_32_chars".to_string();
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
            .route("/test/login", web::get().to(test_set_session))
            .app_data(web::Data::new(token_pool))
            .app_data(web::Data::new(client_actor))
            .app_data(web::Data::new(auth_actor))
            .app_data(web::Data::new(jwt_secret))
            .app_data(web::Data::new(metrics))
            .app_data(web::Data::new(oidc_config))
            .app_data(web::Data::new(keyset))
            .app_data(web::Data::new(false))
            .service(web::scope("/oauth").route(
                "/authorize",
                web::get().to(oauth2_actix::handlers::oauth::authorize),
            ))
            .route(
                "/metrics",
                web::get().to(oauth2_actix::handlers::admin::system_metrics),
            ),
    )
    .await;

    // Establish session so /oauth/authorize sees an authenticated user.
    let login_resp = test::call_service(
        &app,
        test::TestRequest::get().uri("/test/login").to_request(),
    )
    .await;
    let cookie = extract_session_cookie(&login_resp);

    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let challenge = s256(verifier);

    let req = test::TestRequest::get()
        .uri(&format!(
            "/oauth/authorize?response_type=code&client_id=client_metrics\
             &redirect_uri=https%3A%2F%2Fapp.example%2Fcb&scope=read\
             &code_challenge={challenge}&code_challenge_method=S256&state=abc"
        ))
        .insert_header(("Cookie", cookie.as_str()))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 302, "authorize must redirect on success");

    let metrics_resp =
        test::call_service(&app, test::TestRequest::get().uri("/metrics").to_request()).await;
    assert_eq!(metrics_resp.status(), 200);
    let body_bytes = test::read_body(metrics_resp).await;
    let body = std::str::from_utf8(&body_bytes).expect("utf8 metrics body");

    let line = body
        .lines()
        .find(|l| {
            !l.starts_with('#') && l.starts_with("oauth2_server_oauth_authorization_codes_issued ")
        })
        .unwrap_or_else(|| {
            panic!(
                "metric `oauth2_server_oauth_authorization_codes_issued` missing in /metrics output:\n{body}"
            )
        });
    let value: f64 = line
        .split_whitespace()
        .nth(1)
        .and_then(|v| v.parse().ok())
        .unwrap_or_else(|| panic!("could not parse metric value from line: {line}"));
    assert!(
        value >= 1.0,
        "expected oauth_authorization_codes_issued >= 1 after successful authorize, got {value}"
    );
}
