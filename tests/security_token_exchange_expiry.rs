//! Security regression: RFC 8693 token exchange must reject an expired
//! subject_token. Previously only `revoked` was checked, so an expired (but
//! still-persisted) access token could be exchanged for a fresh token.

use actix::Actor;
use actix_web::{test, web, App};

use oauth2_actix::actors::TokenActorPool;
use oauth2_actix::handlers::wellknown::OidcConfig;
use oauth2_core::{Client, Token, User};
use oauth2_observability::Metrics;

const TOKEN_EXCHANGE: &str = "urn:ietf:params:oauth:grant-type:token-exchange";

#[actix_web::test]
async fn expired_subject_token_is_rejected() {
    let storage = oauth2_storage_factory::create_storage("sqlite::memory:")
        .await
        .expect("create storage");
    storage.init().await.expect("init storage");

    // Confidential client allowed to use token-exchange.
    let client = Client::new(
        "tx_client".to_string(),
        "tx_secret".to_string(),
        vec!["https://unused.example/cb".to_string()],
        vec![TOKEN_EXCHANGE.to_string()],
        "read".to_string(),
        "test".to_string(),
    );
    storage.save_client(&client).await.expect("save client");

    // The token's user_id FK references users(id), so the user must exist.
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

    // An already-expired access token (negative expires_in => expires_at in the past).
    let expired = Token::new(
        "expired_access_token_value".to_string(),
        None,
        "tx_client".to_string(),
        Some("user_123".to_string()),
        "read".to_string(),
        -3600,
        None,
    );
    assert!(expired.is_expired(), "fixture token must be expired");
    storage.save_token(&expired).await.expect("save token");

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

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(token_pool))
            .app_data(web::Data::new(client_actor))
            .app_data(web::Data::new(auth_actor))
            .app_data(web::Data::new(storage.clone()))
            .app_data(web::Data::new(metrics))
            .app_data(web::Data::new(oidc_config))
            .service(web::scope("/oauth").route(
                "/token",
                web::post().to(oauth2_actix::handlers::oauth::token),
            )),
    )
    .await;

    let basic = format!("Basic {}", base64_encode(b"tx_client:tx_secret"));
    let body = format!(
        "grant_type={}&subject_token=expired_access_token_value&subject_token_type=urn:ietf:params:oauth:token-type:access_token",
        urlencode(TOKEN_EXCHANGE)
    );

    let req = test::TestRequest::post()
        .uri("/oauth/token")
        .insert_header(("Authorization", basic))
        .insert_header(("Content-Type", "application/x-www-form-urlencoded"))
        .set_payload(body)
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(
        resp.status(),
        400,
        "expired subject_token must be rejected with invalid_grant (400), got {}",
        resp.status()
    );
}

#[actix_web::test]
async fn valid_subject_token_is_exchanged() {
    let storage = oauth2_storage_factory::create_storage("sqlite::memory:")
        .await
        .expect("create storage");
    storage.init().await.expect("init storage");

    // Confidential client allowed to use token-exchange.
    let client = Client::new(
        "tx_client".to_string(),
        "tx_secret".to_string(),
        vec!["https://unused.example/cb".to_string()],
        vec![TOKEN_EXCHANGE.to_string()],
        "read".to_string(),
        "test".to_string(),
    );
    storage.save_client(&client).await.expect("save client");

    // The token's user_id FK references users(id), so the user must exist.
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

    // A still-valid access token (positive expires_in => expires_at in the future).
    let valid = Token::new(
        "valid_access_token_value".to_string(),
        None,
        "tx_client".to_string(),
        Some("user_123".to_string()),
        "read".to_string(),
        3600,
        None,
    );
    assert!(!valid.is_expired(), "fixture token must not be expired");
    storage.save_token(&valid).await.expect("save token");

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

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(token_pool))
            .app_data(web::Data::new(client_actor))
            .app_data(web::Data::new(auth_actor))
            .app_data(web::Data::new(storage.clone()))
            .app_data(web::Data::new(metrics))
            .app_data(web::Data::new(oidc_config))
            .service(web::scope("/oauth").route(
                "/token",
                web::post().to(oauth2_actix::handlers::oauth::token),
            )),
    )
    .await;

    let basic = format!("Basic {}", base64_encode(b"tx_client:tx_secret"));
    let body = format!(
        "grant_type={}&subject_token=valid_access_token_value&subject_token_type=urn:ietf:params:oauth:token-type:access_token",
        urlencode(TOKEN_EXCHANGE)
    );

    let req = test::TestRequest::post()
        .uri("/oauth/token")
        .insert_header(("Authorization", basic))
        .insert_header(("Content-Type", "application/x-www-form-urlencoded"))
        .set_payload(body)
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(
        resp.status(),
        200,
        "valid subject_token must be exchanged successfully (200), got {}",
        resp.status()
    );
}

fn base64_encode(input: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(input)
}

// Only safe for the colon-only token-exchange grant-type constant.
fn urlencode(s: &str) -> String {
    s.replace(':', "%3A")
}
