//! RFC 7523 §3 / RFC 9700 §2.5 — JWT client-assertion `jti` replay guard.
//!
//! A client using `client_secret_jwt` (HMAC) submits a signed assertion to
//! the token endpoint. The first submission succeeds. Replaying the same
//! assertion (same `jti`) within its validity window MUST be rejected with
//! `invalid_client`.

use actix::Actor;
use actix_web::{test, web, App};
use jsonwebtoken::{encode, EncodingKey, Header};
use std::sync::Arc;
use tokio::sync::RwLock;

use oauth2_actix::actors::TokenActorPool;
use oauth2_actix::handlers::wellknown::OidcConfig;
use oauth2_core::{Client, TokenResponse};
use oauth2_observability::Metrics;

#[actix_web::test]
async fn rfc9700_client_secret_jwt_replay_is_rejected() {
    const ISSUER: &str = "https://auth.example.com";
    const TOKEN_ENDPOINT: &str = "https://auth.example.com/oauth/token";

    // Client registered for client_secret_jwt — its client_secret doubles as
    // the HMAC key for the assertion.
    let mut client = Client::new(
        "client_jti".to_string(),
        "shared-jti-test-secret-minimum-32-chars".to_string(),
        vec!["https://unused/cb".to_string()],
        vec!["client_credentials".to_string()],
        "read".to_string(),
        "JTI Replay Client".to_string(),
    );
    client.token_endpoint_auth_method = "client_secret_jwt".to_string();

    let storage = oauth2_storage_factory::create_storage("sqlite::memory:")
        .await
        .expect("storage");
    storage.init().await.expect("init");
    storage.save_client(&client).await.expect("save_client");

    let jwt_secret = "server_side_jwt_secret_at_least_32_chars_long".to_string();
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
            .app_data(web::Data::new(token_pool))
            .app_data(web::Data::new(client_actor))
            .app_data(web::Data::new(auth_actor))
            .app_data(web::Data::new(jwt_secret))
            .app_data(web::Data::new(metrics))
            .app_data(web::Data::new(oidc_config))
            .app_data(web::Data::new(keyset))
            .app_data(web::Data::new(false))
            .service(web::scope("/oauth").route(
                "/token",
                web::post().to(oauth2_actix::handlers::oauth::token),
            )),
    )
    .await;

    // Build a compliant RFC 7523 assertion: iss=sub=client_id, aud=token
    // endpoint, exp 60s in the future, jti = unique-per-test string.
    let now = chrono::Utc::now().timestamp();
    let jti = "jti-replay-test-001".to_string();
    let claims = serde_json::json!({
        "iss": "client_jti",
        "sub": "client_jti",
        "aud": TOKEN_ENDPOINT,
        "exp": now + 60,
        "iat": now,
        "jti": jti,
    });
    let assertion = encode(
        &Header::new(jsonwebtoken::Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(client.client_secret.as_bytes()),
    )
    .expect("encode HS256 assertion");

    // First exchange — must succeed.
    let resp_first = test::call_service(
        &app,
        test::TestRequest::post()
            .uri("/oauth/token")
            .set_form([
                ("grant_type", "client_credentials"),
                ("client_id", "client_jti"),
                ("scope", "read"),
                (
                    "client_assertion_type",
                    "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                ),
                ("client_assertion", assertion.as_str()),
            ])
            .to_request(),
    )
    .await;
    assert_eq!(
        resp_first.status(),
        200,
        "first client_assertion exchange must succeed"
    );
    let _: TokenResponse = test::read_body_json(resp_first).await;

    // Replay — same assertion, same jti, within validity window.
    let resp_replay = test::call_service(
        &app,
        test::TestRequest::post()
            .uri("/oauth/token")
            .set_form([
                ("grant_type", "client_credentials"),
                ("client_id", "client_jti"),
                ("scope", "read"),
                (
                    "client_assertion_type",
                    "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                ),
                ("client_assertion", assertion.as_str()),
            ])
            .to_request(),
    )
    .await;
    assert_eq!(
        resp_replay.status(),
        401,
        "RFC 7523 §3: replayed jti MUST be rejected with invalid_client (401)"
    );
    let body = test::read_body(resp_replay).await;
    let body_str = std::str::from_utf8(&body).unwrap();
    assert!(
        body_str.contains("invalid_client"),
        "error code must be invalid_client — got: {body_str}"
    );
    assert!(
        body_str.contains("jti"),
        "error message should reference jti — got: {body_str}"
    );
}

/// A fresh `jti` (even from the same client) must succeed — the guard
/// only rejects exact `(client_id, jti)` replays, not all subsequent
/// assertions from a client.
#[actix_web::test]
async fn rfc9700_fresh_jti_from_same_client_is_accepted() {
    const ISSUER: &str = "https://auth.example.com";
    const TOKEN_ENDPOINT: &str = "https://auth.example.com/oauth/token";

    let mut client = Client::new(
        "client_jti2".to_string(),
        "shared-jti-test2-secret-minimum-32-chars".to_string(),
        vec!["https://unused/cb".to_string()],
        vec!["client_credentials".to_string()],
        "read".to_string(),
        "JTI Fresh Client".to_string(),
    );
    client.token_endpoint_auth_method = "client_secret_jwt".to_string();

    let storage = oauth2_storage_factory::create_storage("sqlite::memory:")
        .await
        .expect("storage");
    storage.init().await.expect("init");
    storage.save_client(&client).await.expect("save_client");

    let jwt_secret = "fresh_jti_server_secret_at_least_32_chars_long".to_string();
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
            .app_data(web::Data::new(token_pool))
            .app_data(web::Data::new(client_actor))
            .app_data(web::Data::new(auth_actor))
            .app_data(web::Data::new(jwt_secret))
            .app_data(web::Data::new(metrics))
            .app_data(web::Data::new(oidc_config))
            .app_data(web::Data::new(keyset))
            .app_data(web::Data::new(false))
            .service(web::scope("/oauth").route(
                "/token",
                web::post().to(oauth2_actix::handlers::oauth::token),
            )),
    )
    .await;

    for jti in ["jti-fresh-a", "jti-fresh-b"] {
        let now = chrono::Utc::now().timestamp();
        let claims = serde_json::json!({
            "iss": "client_jti2",
            "sub": "client_jti2",
            "aud": TOKEN_ENDPOINT,
            "exp": now + 60,
            "iat": now,
            "jti": jti,
        });
        let assertion = encode(
            &Header::new(jsonwebtoken::Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(client.client_secret.as_bytes()),
        )
        .expect("encode HS256 assertion");

        let resp = test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/oauth/token")
                .set_form([
                    ("grant_type", "client_credentials"),
                    ("client_id", "client_jti2"),
                    ("scope", "read"),
                    (
                        "client_assertion_type",
                        "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                    ),
                    ("client_assertion", assertion.as_str()),
                ])
                .to_request(),
        )
        .await;
        assert_eq!(
            resp.status(),
            200,
            "fresh jti '{jti}' from the same client must succeed"
        );
    }
}
