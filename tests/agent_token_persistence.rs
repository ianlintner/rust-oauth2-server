//! Phase 7 (agent / A2A OAuth) Task 3: delegation metadata persisted on the
//! `tokens` row (V23 migration) must be exposed at introspection time for
//! *both* JWT and opaque access tokens.
//!
//! For JWT access tokens the `act`/`cnf` claims are embedded directly in the
//! token and introspection decodes them from there. For opaque access
//! tokens there is no JWT payload to decode, so `act`/`cnf` must be read
//! back from the `tokens.act` / `tokens.cnf` columns persisted by
//! `Token::with_delegation` (see `crates/oauth2-core/src/models/token.rs`
//! and `TokenActor`'s `CreateToken` handler in
//! `crates/oauth2-actix/src/actors/token_actor.rs`).
//!
//! The `Actor` typed shape (from a separate, concurrently-developed task)
//! does not exist yet in this worktree, so `act` is exercised here as a raw
//! `serde_json::Value` shaped like `{"sub": ..., "iss": ...}` per
//! `oauth2_core::Actor`'s documented shape in the global constraints.

use actix::Actor;
use actix_web::{test, web, App};

use oauth2_actix::actors::{CreateToken, TokenActorPool};
use oauth2_actix::handlers::wellknown::OidcConfig;
use oauth2_config::Config;
use oauth2_core::{Client, User};
use oauth2_observability::Metrics;

/// Shared fixture: storage + client + user, ready for `CreateToken`.
async fn setup(client_id: &str) -> (oauth2_ports::DynStorage, String) {
    let db_path = format!(
        "/tmp/oauth2_agent_token_persistence_{}.db",
        uuid::Uuid::new_v4()
    );
    let storage = oauth2_storage_factory::create_storage(&format!("sqlite:{db_path}"))
        .await
        .expect("create storage");
    storage.init().await.expect("init storage");

    let client = Client::new(
        client_id.to_string(),
        "secret".to_string(),
        vec!["https://unused.example/cb".to_string()],
        vec!["client_credentials".to_string()],
        "read".to_string(),
        "agent test client".to_string(),
    );
    storage.save_client(&client).await.expect("save client");

    let now = chrono::Utc::now();
    let user = User {
        id: "agent_test_user".to_string(),
        username: "agent_test_user".to_string(),
        password_hash: "not_used".to_string(),
        email: "agent_test_user@example.test".to_string(),
        enabled: true,
        role: "user".to_string(),
        created_at: now,
        updated_at: now,
    };
    storage.save_user(&user).await.expect("save user");

    (storage, client_id.to_string())
}

fn delegated_actor() -> serde_json::Value {
    serde_json::json!({ "sub": "agent-1", "iss": "http://localhost" })
}

// Shaped as an mTLS confirmation (`x5t#S256`) rather than DPoP (`jkt`):
// the introspection endpoint treats a `cnf.jkt` claim as "this token is
// DPoP-bound" and requires a DPoP proof header to be present (RFC 9449
// §7.1), which is orthogonal to what this test is exercising (persistence
// and surfacing of `act`/`cnf`, not DPoP-proof validation).
fn test_cnf() -> serde_json::Value {
    serde_json::json!({ "x5t#S256": "test-thumbprint" })
}

#[actix_web::test]
async fn jwt_mode_persists_and_introspects_delegation() {
    let (storage, client_id) = setup("jwt_delegation_client").await;

    let jwt_secret = "test_jwt_secret".to_string();
    let metrics = Metrics::new().expect("metrics");

    let token_actor = oauth2_actix::actors::TokenActor::new(
        storage.clone(),
        jwt_secret.clone(),
        "http://localhost".to_string(),
    )
    .start();
    let token_pool = TokenActorPool::new(vec![token_actor.clone()]);

    let created = token_actor
        .send(CreateToken {
            user_id: Some("agent_test_user".to_string()),
            client_id: client_id.clone(),
            scope: "read".to_string(),
            include_refresh: false,
            token_family: None,
            resources: vec!["https://api.example.test".to_string()],
            cnf: Some(test_cnf()),
            authorization_details: None,
            act: Some(delegated_actor()),
            span: tracing::Span::current(),
        })
        .await
        .expect("send create token")
        .expect("create token");

    // The access token is a JWT: it should carry a `.` and be decodable.
    assert!(
        created.access_token.contains('.'),
        "JWT-mode access token should look like a JWT"
    );

    // The row itself should also carry the persisted delegation metadata,
    // independent of what introspection later reconstructs.
    assert_eq!(
        created.actor(),
        Some(delegated_actor()),
        "Token::actor() should round-trip the persisted act column"
    );
    assert_eq!(
        created.resources(),
        vec!["https://api.example.test".to_string()]
    );

    let client_actor = oauth2_actix::actors::ClientActor::new(storage.clone()).start();
    let auth_actor = oauth2_actix::actors::AuthActor::new(storage.clone()).start();
    let oidc_config = OidcConfig {
        issuer: "http://localhost".to_string(),
        jwt_secret: jwt_secret.clone(),
        id_token_alg: "HS256".to_string(),
        id_token_kid: None,
        id_token_private_key_pem: None,
    };
    let mut config = Config::default();
    config.jwt.public_introspection = true;

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(token_pool))
            .app_data(web::Data::new(client_actor))
            .app_data(web::Data::new(auth_actor))
            .app_data(web::Data::new(storage))
            .app_data(web::Data::new(jwt_secret))
            .app_data(web::Data::new(metrics))
            .app_data(web::Data::new(oidc_config))
            .app_data(web::Data::new(false)) // stateless_validation
            .app_data(web::Data::new(config))
            .service(web::scope("/oauth").route(
                "/introspect",
                web::post().to(oauth2_actix::handlers::token::introspect),
            )),
    )
    .await;

    let resp = test::call_service(
        &app,
        test::TestRequest::post()
            .uri("/oauth/introspect")
            .set_form([("token", created.access_token.as_str())])
            .to_request(),
    )
    .await;

    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = test::read_body_json(resp).await;

    assert_eq!(body["active"], serde_json::json!(true));
    assert_eq!(
        body["act"]["sub"], "agent-1",
        "introspection response body: {body}"
    );
    assert_eq!(body["cnf"]["x5t#S256"], "test-thumbprint");
}

#[actix_web::test]
async fn opaque_mode_persists_and_introspects_delegation() {
    let (storage, client_id) = setup("opaque_delegation_client").await;

    let jwt_secret = "test_jwt_secret".to_string();
    let metrics = Metrics::new().expect("metrics");

    let token_actor = oauth2_actix::actors::TokenActor::new(
        storage.clone(),
        jwt_secret.clone(),
        "http://localhost".to_string(),
    )
    .with_access_tokens_opaque(true)
    .start();
    let token_pool = TokenActorPool::new(vec![token_actor.clone()]);

    let created = token_actor
        .send(CreateToken {
            user_id: Some("agent_test_user".to_string()),
            client_id: client_id.clone(),
            scope: "read".to_string(),
            include_refresh: false,
            token_family: None,
            resources: Vec::new(),
            cnf: Some(test_cnf()),
            authorization_details: None,
            act: Some(delegated_actor()),
            span: tracing::Span::current(),
        })
        .await
        .expect("send create token")
        .expect("create token");

    assert!(
        !created.access_token.contains('.'),
        "opaque access token should not look like a JWT"
    );
    assert_eq!(created.actor(), Some(delegated_actor()));
    assert_eq!(created.cnf_value(), Some(test_cnf()));

    let client_actor = oauth2_actix::actors::ClientActor::new(storage.clone()).start();
    let auth_actor = oauth2_actix::actors::AuthActor::new(storage.clone()).start();
    let oidc_config = OidcConfig {
        issuer: "http://localhost".to_string(),
        jwt_secret: jwt_secret.clone(),
        id_token_alg: "HS256".to_string(),
        id_token_kid: None,
        id_token_private_key_pem: None,
    };
    let mut config = Config::default();
    config.jwt.public_introspection = true;
    config.jwt.access_tokens_opaque = true;

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(token_pool))
            .app_data(web::Data::new(client_actor))
            .app_data(web::Data::new(auth_actor))
            .app_data(web::Data::new(storage))
            .app_data(web::Data::new(jwt_secret))
            .app_data(web::Data::new(metrics))
            .app_data(web::Data::new(oidc_config))
            // Even if enabled, stateless validation should be bypassed for opaque tokens.
            .app_data(web::Data::new(true))
            .app_data(web::Data::new(config))
            .service(web::scope("/oauth").route(
                "/introspect",
                web::post().to(oauth2_actix::handlers::token::introspect),
            )),
    )
    .await;

    let resp = test::call_service(
        &app,
        test::TestRequest::post()
            .uri("/oauth/introspect")
            .set_form([("token", created.access_token.as_str())])
            .to_request(),
    )
    .await;

    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = test::read_body_json(resp).await;

    assert_eq!(body["active"], serde_json::json!(true));
    assert_eq!(
        body["act"]["sub"], "agent-1",
        "introspection response body: {body}"
    );
    assert_eq!(body["cnf"]["x5t#S256"], "test-thumbprint");
}
