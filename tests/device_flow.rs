use actix::{Actor, Addr};
use actix_session::{storage::CookieSessionStore, Session, SessionMiddleware};
use actix_web::{cookie::Key, test, web, App, HttpResponse};

use oauth2_actix::actors::TokenActorPool;
use oauth2_actix::handlers::wellknown::OidcConfig;
use oauth2_core::{Client, OAuth2Error, TokenResponse, User};
use oauth2_observability::Metrics;
use oauth2_ports::DynStorage;

async fn test_set_session(session: Session) -> HttpResponse {
    session.insert("user_id", "user_123").unwrap();
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
        .expect("session cookie should be set")
        .split(';')
        .next()
        .unwrap()
        .to_string()
}

async fn setup_context(
    client: Client,
) -> (
    TokenActorPool,
    Addr<oauth2_actix::actors::ClientActor>,
    Addr<oauth2_actix::actors::AuthActor>,
    DynStorage,
    String,
    Metrics,
    OidcConfig,
) {
    let db_path = format!("/tmp/oauth2_device_flow_{}.db", uuid::Uuid::new_v4());
    let storage = oauth2_storage_factory::create_storage(&format!("sqlite:{db_path}"))
        .await
        .expect("create storage");
    storage.init().await.expect("init storage");
    storage.save_client(&client).await.expect("save client");

    let now = chrono::Utc::now();
    let user = User {
        id: "user_123".to_string(),
        username: "user_123".to_string(),
        password_hash: "not_used".to_string(),
        email: "user_123@example.test".to_string(),
        enabled: true,
        role: "user".to_string(),
        created_at: now,
        updated_at: now,
    };
    storage.save_user(&user).await.expect("save user");

    let jwt_secret = "test_jwt_secret".to_string();
    let metrics = Metrics::new().expect("metrics");

    let token_actor = oauth2_actix::actors::TokenActor::new(
        storage.clone(),
        jwt_secret.clone(),
        "http://localhost".to_string(),
    )
    .start();
    let token_pool = TokenActorPool::new(vec![token_actor]);
    let client_actor = oauth2_actix::actors::ClientActor::new(storage.clone()).start();
    let auth_actor = oauth2_actix::actors::AuthActor::new(storage.clone()).start();

    let oidc_config = OidcConfig {
        issuer: "http://localhost".to_string(),
        jwt_secret: jwt_secret.clone(),
        id_token_alg: "HS256".to_string(),
        id_token_kid: None,
        id_token_private_key_pem: None,
    };

    (
        token_pool,
        client_actor,
        auth_actor,
        storage,
        jwt_secret,
        metrics,
        oidc_config,
    )
}

#[actix_web::test]
async fn device_flow_pending_then_approved_returns_token() {
    let client = Client::new(
        "device_client".to_string(),
        "device_secret".to_string(),
        vec!["https://unused.example/cb".to_string()],
        vec![
            "urn:ietf:params:oauth:grant-type:device_code".to_string(),
            "refresh_token".to_string(),
        ],
        "openid read".to_string(),
        "device client".to_string(),
    );

    let (token_actor, client_actor, auth_actor, storage, jwt_secret, metrics, oidc_config) =
        setup_context(client).await;

    let app = test::init_service(
        App::new()
            .wrap(SessionMiddleware::new(
                CookieSessionStore::default(),
                Key::generate(),
            ))
            .route("/test/login", web::get().to(test_set_session))
            .app_data(web::Data::new(token_actor))
            .app_data(web::Data::new(client_actor))
            .app_data(web::Data::new(auth_actor))
            .app_data(web::Data::new(storage))
            .app_data(web::Data::new(jwt_secret))
            .app_data(web::Data::new(metrics))
            .app_data(web::Data::new(oidc_config))
            .app_data(web::Data::new(false))
            .service(
                web::scope("/oauth")
                    .route(
                        "/device_authorization",
                        web::post().to(oauth2_actix::handlers::device::device_authorization),
                    )
                    .route(
                        "/device/verify",
                        web::post().to(oauth2_actix::handlers::device::verify_submit),
                    )
                    .route(
                        "/token",
                        web::post().to(oauth2_actix::handlers::oauth::token),
                    ),
            ),
    )
    .await;

    let device_init = test::call_service(
        &app,
        test::TestRequest::post()
            .uri("/oauth/device_authorization")
            .set_form([
                ("client_id", "device_client"),
                ("client_secret", "device_secret"),
                ("scope", "openid read"),
            ])
            .to_request(),
    )
    .await;

    assert_eq!(device_init.status(), 200);
    let init_body: serde_json::Value = test::read_body_json(device_init).await;
    let device_code = init_body
        .get("device_code")
        .and_then(|v| v.as_str())
        .expect("device_code")
        .to_string();
    let user_code = init_body
        .get("user_code")
        .and_then(|v| v.as_str())
        .expect("user_code")
        .to_string();

    let pending = test::call_service(
        &app,
        test::TestRequest::post()
            .uri("/oauth/token")
            .set_form([
                ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
                ("client_id", "device_client"),
                ("client_secret", "device_secret"),
                ("device_code", device_code.as_str()),
            ])
            .to_request(),
    )
    .await;

    assert_eq!(pending.status(), 400);
    let pending_body: OAuth2Error = test::read_body_json(pending).await;
    assert_eq!(pending_body.error, "authorization_pending");

    let login_resp = test::call_service(
        &app,
        test::TestRequest::get().uri("/test/login").to_request(),
    )
    .await;
    let session_cookie = extract_session_cookie(&login_resp);

    let approve = test::call_service(
        &app,
        test::TestRequest::post()
            .uri("/oauth/device/verify")
            .insert_header(("Cookie", session_cookie.as_str()))
            .set_form([("user_code", user_code.as_str()), ("action", "approve")])
            .to_request(),
    )
    .await;
    assert_eq!(approve.status(), 200);

    let success = test::call_service(
        &app,
        test::TestRequest::post()
            .uri("/oauth/token")
            .set_form([
                ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
                ("client_id", "device_client"),
                ("client_secret", "device_secret"),
                ("device_code", device_code.as_str()),
            ])
            .to_request(),
    )
    .await;

    assert_eq!(success.status(), 200);
    let token: TokenResponse = test::read_body_json(success).await;
    assert!(!token.access_token.is_empty());
    assert!(
        token.id_token.is_some(),
        "openid scope via device flow should issue id_token"
    );
}

#[actix_web::test]
async fn discovery_advertises_device_authorization_endpoint() {
    let client = Client::new(
        "client_meta".to_string(),
        "secret_meta".to_string(),
        vec!["https://unused.example/cb".to_string()],
        vec!["authorization_code".to_string()],
        "read".to_string(),
        "meta client".to_string(),
    );

    let (token_actor, client_actor, auth_actor, _storage, jwt_secret, metrics, oidc_config) =
        setup_context(client).await;

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(token_actor))
            .app_data(web::Data::new(client_actor))
            .app_data(web::Data::new(auth_actor))
            .app_data(web::Data::new(jwt_secret))
            .app_data(web::Data::new(metrics))
            .app_data(web::Data::new(oidc_config))
            .app_data(web::Data::new(false))
            .service(web::scope("/.well-known").route(
                "/openid-configuration",
                web::get().to(oauth2_actix::handlers::wellknown::openid_configuration),
            )),
    )
    .await;

    let resp = test::call_service(
        &app,
        test::TestRequest::get()
            .uri("/.well-known/openid-configuration")
            .to_request(),
    )
    .await;

    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = test::read_body_json(resp).await;

    let endpoint = body
        .get("device_authorization_endpoint")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    assert!(endpoint.ends_with("/oauth/device_authorization"));

    let grants = body
        .get("grant_types_supported")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();

    assert!(grants
        .iter()
        .any(|v| v == "urn:ietf:params:oauth:grant-type:device_code"));
}
