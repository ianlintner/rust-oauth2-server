//! RFC 7662 §5 / RFC 9700 §2.5 — introspection PII scoping.
//!
//! When the introspection endpoint is opened to anonymous callers via
//! `public_introspection = true`, the response MUST NOT leak the token
//! subject's identity (username, sub). Resource servers validating a
//! bearer token still need the lifecycle fields (active, scope, exp, iss,
//! aud, iat, nbf, client_id, token_type, jti).

use actix::Actor;
use actix_web::{test, web, App};
use std::sync::Arc;
use tokio::sync::RwLock;

use oauth2_actix::actors::TokenActorPool;
use oauth2_actix::handlers::wellknown::OidcConfig;
use oauth2_core::{Client, IntrospectionResponse, TokenResponse, User};
use oauth2_observability::Metrics;

/// Anonymous caller (public_introspection=true) gets lifecycle claims but
/// NOT the token subject's identity fields.
#[actix_web::test]
async fn rfc9700_anonymous_introspection_strips_username_and_sub() {
    const ISSUER: &str = "https://auth.example.com";

    let client = Client::new(
        "client_pii".to_string(),
        "secret_pii".to_string(),
        vec!["https://unused/cb".to_string()],
        vec!["client_credentials".to_string()],
        "read".to_string(),
        "test".to_string(),
    );

    let storage = oauth2_storage_factory::create_storage("sqlite::memory:")
        .await
        .expect("storage");
    storage.init().await.expect("init");
    storage.save_client(&client).await.expect("save_client");

    let now = chrono::Utc::now();
    let user = User {
        id: "user_pii".to_string(),
        username: "alice".to_string(),
        password_hash: "unused".to_string(),
        email: "alice@example.test".to_string(),
        enabled: true,
        role: "user".to_string(),
        created_at: now,
        updated_at: now,
    };
    storage.save_user(&user).await.expect("save_user");

    let jwt_secret = "pii_test_secret_at_least_32_chars_long".to_string();
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
    // Enable public_introspection so the anonymous caller path is exercised.
    let mut config = oauth2_config::Config::default();
    config.jwt.secret = jwt_secret.clone();
    config.jwt.public_introspection = true;

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
            .app_data(web::Data::new(config))
            .service(
                web::scope("/oauth")
                    .route(
                        "/token",
                        web::post().to(oauth2_actix::handlers::oauth::token),
                    )
                    .route(
                        "/introspect",
                        web::post().to(oauth2_actix::handlers::token::introspect),
                    ),
            ),
    )
    .await;

    // Issue a token authenticated as the client.
    let token_resp: TokenResponse = test::read_body_json(
        test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/oauth/token")
                .set_form([
                    ("grant_type", "client_credentials"),
                    ("client_id", "client_pii"),
                    ("client_secret", "secret_pii"),
                    ("scope", "read"),
                ])
                .to_request(),
        )
        .await,
    )
    .await;

    // Introspect WITHOUT client credentials (public_introspection path).
    let intro_resp = test::call_service(
        &app,
        test::TestRequest::post()
            .uri("/oauth/introspect")
            .set_form([("token", token_resp.access_token.as_str())])
            .to_request(),
    )
    .await;
    assert_eq!(intro_resp.status(), 200);
    let body: IntrospectionResponse = test::read_body_json(intro_resp).await;

    assert!(body.active, "token must still be reported active");
    // PII stripped
    assert!(
        body.username.is_none(),
        "RFC 7662 §5: anonymous introspection MUST NOT return username — got {:?}",
        body.username
    );
    assert!(
        body.sub.is_none(),
        "RFC 7662 §5: anonymous introspection MUST NOT return sub — got {:?}",
        body.sub
    );
    // Lifecycle fields still present
    assert!(body.scope.is_some(), "scope must be returned to RS");
    assert!(body.exp.is_some(), "exp must be returned to RS");
    assert!(body.iat.is_some(), "iat must be returned to RS");
    assert!(body.client_id.is_some(), "client_id may be returned");
    assert!(body.iss.is_some(), "iss must be returned");
}

/// Owner (authenticated as the token-issuing client) gets the full
/// response including PII. Token_client_credentials grant has no user, so
/// we exercise this via authorization_code elsewhere; here we assert the
/// owner simply gets `username` populated when it exists on the token.
#[actix_web::test]
async fn rfc9700_owner_introspection_still_returns_pii() {
    const ISSUER: &str = "https://auth.example.com";

    let client = Client::new(
        "client_owner".to_string(),
        "secret_owner".to_string(),
        vec!["https://unused/cb".to_string()],
        vec!["client_credentials".to_string()],
        "read".to_string(),
        "test".to_string(),
    );

    let storage = oauth2_storage_factory::create_storage("sqlite::memory:")
        .await
        .expect("storage");
    storage.init().await.expect("init");
    storage.save_client(&client).await.expect("save_client");

    let jwt_secret = "pii_test_secret_at_least_32_chars_long".to_string();
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
    let mut config = oauth2_config::Config::default();
    config.jwt.secret = jwt_secret.clone();
    // Require client auth — owner path.
    config.jwt.public_introspection = false;

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
            .app_data(web::Data::new(config))
            .service(
                web::scope("/oauth")
                    .route(
                        "/token",
                        web::post().to(oauth2_actix::handlers::oauth::token),
                    )
                    .route(
                        "/introspect",
                        web::post().to(oauth2_actix::handlers::token::introspect),
                    ),
            ),
    )
    .await;

    let token_resp: TokenResponse = test::read_body_json(
        test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/oauth/token")
                .set_form([
                    ("grant_type", "client_credentials"),
                    ("client_id", "client_owner"),
                    ("client_secret", "secret_owner"),
                    ("scope", "read"),
                ])
                .to_request(),
        )
        .await,
    )
    .await;

    let intro_resp = test::call_service(
        &app,
        test::TestRequest::post()
            .uri("/oauth/introspect")
            .set_form([
                ("token", token_resp.access_token.as_str()),
                ("client_id", "client_owner"),
                ("client_secret", "secret_owner"),
            ])
            .to_request(),
    )
    .await;
    assert_eq!(intro_resp.status(), 200);
    let body: IntrospectionResponse = test::read_body_json(intro_resp).await;

    assert!(body.active);
    // sub is present; for client_credentials it equals the client_id (no user)
    // but the field is NOT stripped as it would be for an anonymous caller.
    assert!(
        body.sub.is_some(),
        "owner introspection must include sub (even for client_credentials tokens)"
    );
    assert_eq!(body.client_id.as_deref(), Some("client_owner"));
}
