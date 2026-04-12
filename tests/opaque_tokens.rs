use actix::Actor;
use actix_web::{test, web, App};

use oauth2_actix::actors::TokenActorPool;
use oauth2_actix::handlers::wellknown::OidcConfig;
use oauth2_config::Config;
use oauth2_core::Client;
use oauth2_observability::Metrics;

async fn setup_context(
    client: Client,
    opaque_access_tokens: bool,
) -> (
    TokenActorPool,
    actix::Addr<oauth2_actix::actors::ClientActor>,
    actix::Addr<oauth2_actix::actors::AuthActor>,
    oauth2_ports::DynStorage,
    String,
    Metrics,
    OidcConfig,
) {
    let db_path = format!("/tmp/oauth2_opaque_tokens_{}.db", uuid::Uuid::new_v4());
    let storage = oauth2_storage_factory::create_storage(&format!("sqlite:{db_path}"))
        .await
        .expect("create storage");
    storage.init().await.expect("init storage");
    storage.save_client(&client).await.expect("save client");

    let jwt_secret = "test_jwt_secret".to_string();
    let metrics = Metrics::new().expect("metrics");

    let token_actor = oauth2_actix::actors::TokenActor::new(
        storage.clone(),
        jwt_secret.clone(),
        "http://localhost".to_string(),
    )
    .with_access_tokens_opaque(opaque_access_tokens)
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
async fn opaque_access_tokens_issue_and_introspect_successfully() {
    let client = Client::new(
        "opaque_client".to_string(),
        "opaque_secret".to_string(),
        vec!["https://unused.example/cb".to_string()],
        vec!["client_credentials".to_string()],
        "read".to_string(),
        "opaque client".to_string(),
    );

    let (token_actor, client_actor, auth_actor, storage, jwt_secret, metrics, oidc_config) =
        setup_context(client, true).await;

    let mut config = Config::default();
    config.jwt.public_introspection = true;
    config.jwt.access_tokens_opaque = true;

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(token_actor))
            .app_data(web::Data::new(client_actor))
            .app_data(web::Data::new(auth_actor))
            .app_data(web::Data::new(storage))
            .app_data(web::Data::new(jwt_secret))
            .app_data(web::Data::new(metrics))
            .app_data(web::Data::new(oidc_config))
            // Even if enabled, stateless validation should be bypassed for opaque tokens.
            .app_data(web::Data::new(true))
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

    let token_resp = test::call_service(
        &app,
        test::TestRequest::post()
            .uri("/oauth/token")
            .set_form([
                ("grant_type", "client_credentials"),
                ("client_id", "opaque_client"),
                ("client_secret", "opaque_secret"),
                ("scope", "read"),
            ])
            .to_request(),
    )
    .await;

    assert_eq!(token_resp.status(), 200);
    let token_json: serde_json::Value = test::read_body_json(token_resp).await;
    let access_token = token_json
        .get("access_token")
        .and_then(|v| v.as_str())
        .expect("access_token should exist");

    assert!(
        !access_token.contains('.'),
        "opaque access token should not look like a JWT"
    );

    let introspect_resp = test::call_service(
        &app,
        test::TestRequest::post()
            .uri("/oauth/introspect")
            .set_form([("token", access_token)])
            .to_request(),
    )
    .await;

    assert_eq!(introspect_resp.status(), 200);
    let introspect_json: serde_json::Value = test::read_body_json(introspect_resp).await;

    assert!(introspect_json
        .get("active")
        .and_then(|v| v.as_bool())
        .unwrap_or(false));
    assert!(
        introspect_json
            .get("exp")
            .and_then(|v| v.as_i64())
            .is_some(),
        "introspection should include exp for opaque tokens"
    );
    assert!(
        introspect_json
            .get("iat")
            .and_then(|v| v.as_i64())
            .is_some(),
        "introspection should include iat for opaque tokens"
    );
}
