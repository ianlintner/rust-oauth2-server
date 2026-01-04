use actix::{Actor, Addr};
use actix_web::{test, web, App};

use oauth2_core::{Client, OAuth2Error, TokenResponse};
use oauth2_observability::Metrics;

fn extract_query_param(url: &str, key: &str) -> Option<String> {
    // Very small helper for test-only parsing.
    let query = url.splitn(2, '?').nth(1)?;
    for pair in query.split('&') {
        let mut it = pair.splitn(2, '=');
        let k = it.next()?;
        let v = it.next().unwrap_or("");
        if k == key {
            return Some(v.to_string());
        }
    }
    None
}

async fn setup_context(
    client: Client,
) -> (
    Addr<oauth2_actix::actors::TokenActor>,
    Addr<oauth2_actix::actors::ClientActor>,
    Addr<oauth2_actix::actors::AuthActor>,
    String,
    Metrics,
) {
    let storage = oauth2_storage_factory::create_storage("sqlite::memory:")
        .await
        .expect("create storage");
    storage.init().await.expect("init storage");
    storage.save_client(&client).await.expect("save client");

    let jwt_secret = "test_jwt_secret".to_string();
    let metrics = Metrics::new().expect("metrics");

    let token_actor = oauth2_actix::actors::TokenActor::new(storage.clone(), jwt_secret.clone())
        .start();
    let client_actor = oauth2_actix::actors::ClientActor::new(storage.clone()).start();
    let auth_actor = oauth2_actix::actors::AuthActor::new(storage.clone()).start();

    (token_actor, client_actor, auth_actor, jwt_secret, metrics)
}

#[actix_web::test]
async fn authorize_rejects_unregistered_redirect_uri() {
    let client = Client::new(
        "client_a".to_string(),
        "secret_a".to_string(),
        vec!["https://good.example/cb".to_string()],
        vec!["authorization_code".to_string()],
        "read".to_string(),
        "test".to_string(),
    );

    let (token_actor, client_actor, auth_actor, jwt_secret, metrics) = setup_context(client).await;
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(token_actor))
            .app_data(web::Data::new(client_actor))
            .app_data(web::Data::new(auth_actor))
            .app_data(web::Data::new(jwt_secret))
            .app_data(web::Data::new(metrics))
            .service(
                web::scope("/oauth")
                    .route(
                        "/authorize",
                        web::get().to(oauth2_actix::handlers::oauth::authorize),
                    )
                    .route(
                        "/token",
                        web::post().to(oauth2_actix::handlers::oauth::token),
                    )
                    .route(
                        "/introspect",
                        web::post().to(oauth2_actix::handlers::token::introspect),
                    )
                    .route(
                        "/revoke",
                        web::post().to(oauth2_actix::handlers::token::revoke),
                    ),
            )
            .service(
                web::scope("/.well-known").route(
                    "/openid-configuration",
                    web::get().to(oauth2_actix::handlers::wellknown::openid_configuration),
                ),
            ),
    )
    .await;

    // NOTE: percent-encode redirect_uri so the request URI is always valid and decodes back to the
    // exact string stored for the client.
    let req = test::TestRequest::get()
        .uri("/oauth/authorize?response_type=code&client_id=client_a&redirect_uri=https%3A%2F%2Fevil.example%2Fcb&scope=read")
        .to_request();
    let resp = test::call_service(&app, req).await;

    assert_eq!(resp.status(), 400);
    let body: OAuth2Error = test::read_body_json(resp).await;
    assert_eq!(body.error, "invalid_request");
}

#[actix_web::test]
async fn authorize_rejects_implicit_response_type() {
    let client = Client::new(
        "client_a".to_string(),
        "secret_a".to_string(),
        vec!["https://good.example/cb".to_string()],
        vec!["authorization_code".to_string()],
        "read".to_string(),
        "test".to_string(),
    );

    let (token_actor, client_actor, auth_actor, jwt_secret, metrics) = setup_context(client).await;
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(token_actor))
            .app_data(web::Data::new(client_actor))
            .app_data(web::Data::new(auth_actor))
            .app_data(web::Data::new(jwt_secret))
            .app_data(web::Data::new(metrics))
            .service(
                web::scope("/oauth")
                    .route(
                        "/authorize",
                        web::get().to(oauth2_actix::handlers::oauth::authorize),
                    )
                    .route(
                        "/token",
                        web::post().to(oauth2_actix::handlers::oauth::token),
                    )
                    .route(
                        "/introspect",
                        web::post().to(oauth2_actix::handlers::token::introspect),
                    )
                    .route(
                        "/revoke",
                        web::post().to(oauth2_actix::handlers::token::revoke),
                    ),
            )
            .service(
                web::scope("/.well-known").route(
                    "/openid-configuration",
                    web::get().to(oauth2_actix::handlers::wellknown::openid_configuration),
                ),
            ),
    )
    .await;

    let req = test::TestRequest::get()
        .uri("/oauth/authorize?response_type=token&client_id=client_a&redirect_uri=https%3A%2F%2Fgood.example%2Fcb&scope=read")
        .to_request();
    let resp = test::call_service(&app, req).await;

    assert_eq!(resp.status(), 400);
    let body: OAuth2Error = test::read_body_json(resp).await;
    assert_eq!(body.error, "invalid_request");
}

#[actix_web::test]
async fn token_client_credentials_rejects_invalid_secret() {
    let client = Client::new(
        "client_cc".to_string(),
        "secret_cc".to_string(),
        vec!["https://unused.example/cb".to_string()],
        vec!["client_credentials".to_string()],
        "read".to_string(),
        "test".to_string(),
    );

    let (token_actor, client_actor, auth_actor, jwt_secret, metrics) = setup_context(client).await;
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(token_actor))
            .app_data(web::Data::new(client_actor))
            .app_data(web::Data::new(auth_actor))
            .app_data(web::Data::new(jwt_secret))
            .app_data(web::Data::new(metrics))
            .service(
                web::scope("/oauth")
                    .route(
                        "/authorize",
                        web::get().to(oauth2_actix::handlers::oauth::authorize),
                    )
                    .route(
                        "/token",
                        web::post().to(oauth2_actix::handlers::oauth::token),
                    )
                    .route(
                        "/introspect",
                        web::post().to(oauth2_actix::handlers::token::introspect),
                    )
                    .route(
                        "/revoke",
                        web::post().to(oauth2_actix::handlers::token::revoke),
                    ),
            )
            .service(
                web::scope("/.well-known").route(
                    "/openid-configuration",
                    web::get().to(oauth2_actix::handlers::wellknown::openid_configuration),
                ),
            ),
    )
    .await;

    let req = test::TestRequest::post()
        .uri("/oauth/token")
        .set_form([
            ("grant_type", "client_credentials"),
            ("client_id", "client_cc"),
            ("client_secret", "wrong"),
            ("scope", "read"),
        ])
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 401);

    let body: OAuth2Error = test::read_body_json(resp).await;
    assert_eq!(body.error, "invalid_client");
}

#[actix_web::test]
async fn token_response_has_no_store_headers() {
    let client = Client::new(
        "client_cc".to_string(),
        "secret_cc".to_string(),
        vec!["https://unused.example/cb".to_string()],
        vec!["client_credentials".to_string()],
        "read".to_string(),
        "test".to_string(),
    );

    let (token_actor, client_actor, auth_actor, jwt_secret, metrics) = setup_context(client).await;
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(token_actor))
            .app_data(web::Data::new(client_actor))
            .app_data(web::Data::new(auth_actor))
            .app_data(web::Data::new(jwt_secret))
            .app_data(web::Data::new(metrics))
            .service(
                web::scope("/oauth")
                    .route(
                        "/authorize",
                        web::get().to(oauth2_actix::handlers::oauth::authorize),
                    )
                    .route(
                        "/token",
                        web::post().to(oauth2_actix::handlers::oauth::token),
                    )
                    .route(
                        "/introspect",
                        web::post().to(oauth2_actix::handlers::token::introspect),
                    )
                    .route(
                        "/revoke",
                        web::post().to(oauth2_actix::handlers::token::revoke),
                    ),
            )
            .service(
                web::scope("/.well-known").route(
                    "/openid-configuration",
                    web::get().to(oauth2_actix::handlers::wellknown::openid_configuration),
                ),
            ),
    )
    .await;

    let req = test::TestRequest::post()
        .uri("/oauth/token")
        .set_form([
            ("grant_type", "client_credentials"),
            ("client_id", "client_cc"),
            ("client_secret", "secret_cc"),
            ("scope", "read"),
        ])
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());

    let cache_control = resp
        .headers()
        .get(actix_web::http::header::CACHE_CONTROL)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");
    assert!(cache_control.contains("no-store"));

    let pragma = resp
        .headers()
        .get(actix_web::http::header::PRAGMA)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");
    assert!(pragma.contains("no-cache"));

    let _body: TokenResponse = test::read_body_json(resp).await;
}

#[actix_web::test]
async fn authorization_code_requires_secret_unless_pkce_used() {
    let client = Client::new(
        "client_ac".to_string(),
        "secret_ac".to_string(),
        vec!["https://good.example/cb".to_string()],
        vec!["authorization_code".to_string()],
        "read".to_string(),
        "test".to_string(),
    );

    let (token_actor, client_actor, auth_actor, jwt_secret, metrics) = setup_context(client).await;
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(token_actor))
            .app_data(web::Data::new(client_actor))
            .app_data(web::Data::new(auth_actor))
            .app_data(web::Data::new(jwt_secret))
            .app_data(web::Data::new(metrics))
            .service(
                web::scope("/oauth")
                    .route(
                        "/authorize",
                        web::get().to(oauth2_actix::handlers::oauth::authorize),
                    )
                    .route(
                        "/token",
                        web::post().to(oauth2_actix::handlers::oauth::token),
                    )
                    .route(
                        "/introspect",
                        web::post().to(oauth2_actix::handlers::token::introspect),
                    )
                    .route(
                        "/revoke",
                        web::post().to(oauth2_actix::handlers::token::revoke),
                    ),
            )
            .service(
                web::scope("/.well-known").route(
                    "/openid-configuration",
                    web::get().to(oauth2_actix::handlers::wellknown::openid_configuration),
                ),
            ),
    )
    .await;

    // Get a code without PKCE
    let req = test::TestRequest::get().uri("/oauth/authorize?response_type=code&client_id=client_ac&redirect_uri=https%3A%2F%2Fgood.example%2Fcb&scope=read").to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 302);

    let loc = resp
        .headers()
        .get(actix_web::http::header::LOCATION)
        .and_then(|h| h.to_str().ok())
        .unwrap();
    let code = extract_query_param(loc, "code").expect("code");

    // Exchange without a client_secret: should be rejected.
    let req = test::TestRequest::post()
        .uri("/oauth/token")
        .set_form([
            ("grant_type", "authorization_code"),
            ("client_id", "client_ac"),
            ("code", code.as_str()),
            ("redirect_uri", "https://good.example/cb"),
        ])
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 401);

    // Exchange with the correct secret: should succeed.
    let req = test::TestRequest::post()
        .uri("/oauth/token")
        .set_form([
            ("grant_type", "authorization_code"),
            ("client_id", "client_ac"),
            ("client_secret", "secret_ac"),
            ("code", code.as_str()),
            ("redirect_uri", "https://good.example/cb"),
        ])
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());
}

#[actix_web::test]
async fn pkce_allows_public_exchange_and_prevents_downgrade() {
    let client = Client::new(
        "client_pkce".to_string(),
        "secret_pkce".to_string(),
        vec!["https://good.example/cb".to_string()],
        vec!["authorization_code".to_string()],
        "read".to_string(),
        "test".to_string(),
    );

    let (token_actor, client_actor, auth_actor, jwt_secret, metrics) = setup_context(client).await;
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(token_actor))
            .app_data(web::Data::new(client_actor))
            .app_data(web::Data::new(auth_actor))
            .app_data(web::Data::new(jwt_secret))
            .app_data(web::Data::new(metrics))
            .service(
                web::scope("/oauth")
                    .route(
                        "/authorize",
                        web::get().to(oauth2_actix::handlers::oauth::authorize),
                    )
                    .route(
                        "/token",
                        web::post().to(oauth2_actix::handlers::oauth::token),
                    )
                    .route(
                        "/introspect",
                        web::post().to(oauth2_actix::handlers::token::introspect),
                    )
                    .route(
                        "/revoke",
                        web::post().to(oauth2_actix::handlers::token::revoke),
                    ),
            )
            .service(
                web::scope("/.well-known").route(
                    "/openid-configuration",
                    web::get().to(oauth2_actix::handlers::wellknown::openid_configuration),
                ),
            ),
    )
    .await;

    // For S256, the server expects challenge = BASE64URL(SHA256(verifier))
    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let challenge = {
        use base64::{engine::general_purpose, Engine as _};
        use sha2::{Digest, Sha256};
        let hash = Sha256::digest(verifier.as_bytes());
        general_purpose::URL_SAFE_NO_PAD.encode(hash)
    };

    // Get a code with PKCE
    let req = test::TestRequest::get().uri(&format!("/oauth/authorize?response_type=code&client_id=client_pkce&redirect_uri=https%3A%2F%2Fgood.example%2Fcb&scope=read&code_challenge={challenge}&code_challenge_method=S256")).to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 302);

    let loc = resp
        .headers()
        .get(actix_web::http::header::LOCATION)
        .and_then(|h| h.to_str().ok())
        .unwrap();
    let code = extract_query_param(loc, "code").expect("code");

    // Downgrade attempt: omit verifier.
    let req = test::TestRequest::post()
        .uri("/oauth/token")
        .set_form([
            ("grant_type", "authorization_code"),
            ("client_id", "client_pkce"),
            ("code", code.as_str()),
            ("redirect_uri", "https://good.example/cb"),
        ])
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 400);

    let body: OAuth2Error = test::read_body_json(resp).await;
    assert_eq!(body.error, "invalid_grant");

    // Correct exchange: include verifier, omit client_secret.
    let req = test::TestRequest::post()
        .uri("/oauth/token")
        .set_form([
            ("grant_type", "authorization_code"),
            ("client_id", "client_pkce"),
            ("code", code.as_str()),
            ("redirect_uri", "https://good.example/cb"),
            ("code_verifier", verifier),
        ])
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());
}

#[actix_web::test]
async fn authorization_code_cannot_be_reused() {
    let client = Client::new(
        "client_reuse".to_string(),
        "secret_reuse".to_string(),
        vec!["https://good.example/cb".to_string()],
        vec!["authorization_code".to_string()],
        "read".to_string(),
        "test".to_string(),
    );

    let (token_actor, client_actor, auth_actor, jwt_secret, metrics) = setup_context(client).await;
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(token_actor))
            .app_data(web::Data::new(client_actor))
            .app_data(web::Data::new(auth_actor))
            .app_data(web::Data::new(jwt_secret))
            .app_data(web::Data::new(metrics))
            .service(
                web::scope("/oauth")
                    .route(
                        "/authorize",
                        web::get().to(oauth2_actix::handlers::oauth::authorize),
                    )
                    .route(
                        "/token",
                        web::post().to(oauth2_actix::handlers::oauth::token),
                    )
                    .route(
                        "/introspect",
                        web::post().to(oauth2_actix::handlers::token::introspect),
                    )
                    .route(
                        "/revoke",
                        web::post().to(oauth2_actix::handlers::token::revoke),
                    ),
            )
            .service(
                web::scope("/.well-known").route(
                    "/openid-configuration",
                    web::get().to(oauth2_actix::handlers::wellknown::openid_configuration),
                ),
            ),
    )
    .await;

    // Get a code
    let req = test::TestRequest::get().uri("/oauth/authorize?response_type=code&client_id=client_reuse&redirect_uri=https%3A%2F%2Fgood.example%2Fcb&scope=read").to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 302);

    let loc = resp
        .headers()
        .get(actix_web::http::header::LOCATION)
        .and_then(|h| h.to_str().ok())
        .unwrap();
    let code = extract_query_param(loc, "code").expect("code");

    // First exchange succeeds.
    let req = test::TestRequest::post()
        .uri("/oauth/token")
        .set_form([
            ("grant_type", "authorization_code"),
            ("client_id", "client_reuse"),
            ("client_secret", "secret_reuse"),
            ("code", code.as_str()),
            ("redirect_uri", "https://good.example/cb"),
        ])
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());

    // Second exchange fails.
    let req = test::TestRequest::post()
        .uri("/oauth/token")
        .set_form([
            ("grant_type", "authorization_code"),
            ("client_id", "client_reuse"),
            ("client_secret", "secret_reuse"),
            ("code", code.as_str()),
            ("redirect_uri", "https://good.example/cb"),
        ])
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 400);

    let body: OAuth2Error = test::read_body_json(resp).await;
    assert_eq!(body.error, "invalid_grant");
}

#[actix_web::test]
async fn well_known_metadata_matches_supported_flows() {
    let client = Client::new(
        "client_meta".to_string(),
        "secret_meta".to_string(),
        vec!["https://good.example/cb".to_string()],
        vec!["authorization_code".to_string()],
        "read".to_string(),
        "test".to_string(),
    );

    let (token_actor, client_actor, auth_actor, jwt_secret, metrics) = setup_context(client).await;
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(token_actor))
            .app_data(web::Data::new(client_actor))
            .app_data(web::Data::new(auth_actor))
            .app_data(web::Data::new(jwt_secret))
            .app_data(web::Data::new(metrics))
            .service(
                web::scope("/oauth")
                    .route(
                        "/authorize",
                        web::get().to(oauth2_actix::handlers::oauth::authorize),
                    )
                    .route(
                        "/token",
                        web::post().to(oauth2_actix::handlers::oauth::token),
                    )
                    .route(
                        "/introspect",
                        web::post().to(oauth2_actix::handlers::token::introspect),
                    )
                    .route(
                        "/revoke",
                        web::post().to(oauth2_actix::handlers::token::revoke),
                    ),
            )
            .service(
                web::scope("/.well-known").route(
                    "/openid-configuration",
                    web::get().to(oauth2_actix::handlers::wellknown::openid_configuration),
                ),
            ),
    )
    .await;

    let req = test::TestRequest::get()
        .uri("/.well-known/openid-configuration")
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());

    let body: serde_json::Value = test::read_body_json(resp).await;

    let rts = body
        .get("response_types_supported")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    assert!(!rts.iter().any(|v| v == "token"));

    let gts = body
        .get("grant_types_supported")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    assert!(!gts.iter().any(|v| v == "refresh_token"));
}
