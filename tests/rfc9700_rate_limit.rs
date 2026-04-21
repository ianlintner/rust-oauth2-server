//! RFC 9700 §2.5 Phase 6.9 — token-endpoint rate limiting + invalid_client penalty bucket.

use actix::Actor;
use actix_web::{test, web, App};
use std::sync::Arc;

use oauth2_actix::actors::TokenActorPool;
use oauth2_actix::handlers::wellknown::OidcConfig;
use oauth2_actix::middleware::rate_limit::InvalidClientRateLimiter;
use oauth2_core::{Client, OAuth2Error};
use oauth2_observability::Metrics;

async fn build_context() -> (
    TokenActorPool,
    actix::Addr<oauth2_actix::actors::ClientActor>,
    actix::Addr<oauth2_actix::actors::AuthActor>,
    String,
    Metrics,
    OidcConfig,
) {
    let storage = oauth2_storage_factory::create_storage("sqlite::memory:")
        .await
        .expect("storage");
    storage.init().await.expect("init");

    let client = Client::new(
        "client_rl".to_string(),
        "secret_rl".to_string(),
        vec!["https://client.example.test/cb".to_string()],
        vec!["client_credentials".to_string()],
        "read".to_string(),
        "RL Test Client".to_string(),
    );
    storage.save_client(&client).await.expect("save_client");

    let jwt_secret = "rate_limit_test_secret_at_least_32_chars!".to_string();
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
        jwt_secret,
        metrics,
        oidc_config,
    )
}

fn bad_credentials_body() -> &'static str {
    "grant_type=client_credentials&client_id=client_rl&client_secret=WRONG"
}

/// After exhausting the invalid_client bucket the token endpoint returns 429.
#[actix_web::test]
async fn invalid_client_rate_limit_returns_429_after_budget_exhausted() {
    let (token_pool, client_actor, auth_actor, jwt_secret, metrics, oidc_config) =
        build_context().await;

    // Bucket allows 3 invalid_client failures before returning 429.
    let ic_limiter = Arc::new(oauth2_ratelimit::in_memory::InMemoryRateLimiter::new(3, 60))
        as Arc<dyn oauth2_ratelimit::RateLimiter>;
    let ic_limiter_data = web::Data::new(InvalidClientRateLimiter(ic_limiter));

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(token_pool))
            .app_data(web::Data::new(client_actor))
            .app_data(web::Data::new(auth_actor))
            .app_data(web::Data::new(jwt_secret))
            .app_data(web::Data::new(metrics))
            .app_data(web::Data::new(oidc_config))
            .app_data(web::Data::new(false)) // stateless_validation
            .app_data(ic_limiter_data)
            .service(web::scope("/oauth").route(
                "/token",
                web::post().to(oauth2_actix::handlers::oauth::token),
            )),
    )
    .await;

    // First 3 attempts: bucket allows, returns 401 invalid_client.
    for attempt in 1..=3 {
        let req = test::TestRequest::post()
            .uri("/oauth/token")
            .set_payload(bad_credentials_body())
            .insert_header(("Content-Type", "application/x-www-form-urlencoded"))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(
            resp.status(),
            401,
            "attempt {attempt}: expected 401 invalid_client"
        );
        let body: OAuth2Error = test::read_body_json(resp).await;
        assert_eq!(body.error, "invalid_client", "attempt {attempt}");
    }

    // 4th attempt: bucket exhausted → 429.
    let req = test::TestRequest::post()
        .uri("/oauth/token")
        .set_payload(bad_credentials_body())
        .insert_header(("Content-Type", "application/x-www-form-urlencoded"))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 429, "4th attempt should be 429");
    let body: OAuth2Error = test::read_body_json(resp).await;
    assert_eq!(body.error, "too_many_requests");
}

/// Without an invalid_client limiter in app_data the handler still returns
/// 401 invalid_client (Option is None → no rate limiting applied).
#[actix_web::test]
async fn invalid_client_no_limiter_returns_401() {
    let (token_pool, client_actor, auth_actor, jwt_secret, metrics, oidc_config) =
        build_context().await;

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(token_pool))
            .app_data(web::Data::new(client_actor))
            .app_data(web::Data::new(auth_actor))
            .app_data(web::Data::new(jwt_secret))
            .app_data(web::Data::new(metrics))
            .app_data(web::Data::new(oidc_config))
            .app_data(web::Data::new(false))
            .service(web::scope("/oauth").route(
                "/token",
                web::post().to(oauth2_actix::handlers::oauth::token),
            )),
    )
    .await;

    let req = test::TestRequest::post()
        .uri("/oauth/token")
        .set_payload(bad_credentials_body())
        .insert_header(("Content-Type", "application/x-www-form-urlencoded"))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 401);
    let body: OAuth2Error = test::read_body_json(resp).await;
    assert_eq!(body.error, "invalid_client");
}

/// Different client_ids have independent buckets — exhausting one does not
/// affect another. Verifies the key is client_id, not a shared IP.
#[actix_web::test]
async fn invalid_client_buckets_are_isolated_per_client_id() {
    let storage = oauth2_storage_factory::create_storage("sqlite::memory:")
        .await
        .expect("storage");
    storage.init().await.expect("init");

    // Register two clients with the same secret so "WRONG" fails for both.
    for id in ["client_iso_a", "client_iso_b"] {
        let c = Client::new(
            id.to_string(),
            "real_secret".to_string(),
            vec!["https://client.example.test/cb".to_string()],
            vec!["client_credentials".to_string()],
            "read".to_string(),
            "Iso Client".to_string(),
        );
        storage.save_client(&c).await.expect("save_client");
    }

    let jwt_secret = "isolation_test_secret_at_least_32_chars!!".to_string();
    let metrics = Metrics::new().expect("metrics");
    let token_actor = oauth2_actix::actors::TokenActor::new(
        storage.clone(),
        jwt_secret.clone(),
        "http://localhost".to_string(),
    )
    .start();
    let token_pool = TokenActorPool::new(vec![token_actor]);
    let client_actor = oauth2_actix::actors::ClientActor::new(storage.clone()).start();
    let auth_actor = oauth2_actix::actors::AuthActor::new(storage).start();
    let oidc_config = OidcConfig {
        issuer: "http://localhost".to_string(),
        jwt_secret: jwt_secret.clone(),
        id_token_alg: "HS256".to_string(),
        id_token_kid: None,
        id_token_private_key_pem: None,
    };

    // Bucket: 2 failures max per client_id.
    let ic_limiter = Arc::new(oauth2_ratelimit::in_memory::InMemoryRateLimiter::new(2, 60))
        as Arc<dyn oauth2_ratelimit::RateLimiter>;

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(token_pool))
            .app_data(web::Data::new(client_actor))
            .app_data(web::Data::new(auth_actor))
            .app_data(web::Data::new(jwt_secret))
            .app_data(web::Data::new(metrics))
            .app_data(web::Data::new(oidc_config))
            .app_data(web::Data::new(false))
            .app_data(web::Data::new(InvalidClientRateLimiter(ic_limiter)))
            .service(web::scope("/oauth").route(
                "/token",
                web::post().to(oauth2_actix::handlers::oauth::token),
            )),
    )
    .await;

    let bad_req = |client_id: &str| {
        let body =
            format!("grant_type=client_credentials&client_id={client_id}&client_secret=WRONG");
        test::TestRequest::post()
            .uri("/oauth/token")
            .set_payload(body)
            .insert_header(("Content-Type", "application/x-www-form-urlencoded"))
            .to_request()
    };

    // Exhaust client_iso_a's bucket (2 failures → 3rd is 429).
    assert_eq!(
        test::call_service(&app, bad_req("client_iso_a"))
            .await
            .status(),
        401
    );
    assert_eq!(
        test::call_service(&app, bad_req("client_iso_a"))
            .await
            .status(),
        401
    );
    assert_eq!(
        test::call_service(&app, bad_req("client_iso_a"))
            .await
            .status(),
        429,
        "client_iso_a bucket exhausted"
    );

    // client_iso_b still has a full bucket — first failure returns 401, not 429.
    assert_eq!(
        test::call_service(&app, bad_req("client_iso_b"))
            .await
            .status(),
        401,
        "client_iso_b bucket is independent"
    );
}

/// Successful token requests do NOT consume the invalid_client bucket.
#[actix_web::test]
async fn valid_requests_do_not_deplete_invalid_client_bucket() {
    let storage = oauth2_storage_factory::create_storage("sqlite::memory:")
        .await
        .expect("storage");
    storage.init().await.expect("init");

    let client = Client::new(
        "client_rl2".to_string(),
        "secret_rl2".to_string(),
        vec!["https://client.example.test/cb".to_string()],
        vec!["client_credentials".to_string()],
        "read".to_string(),
        "RL Test Client 2".to_string(),
    );
    storage.save_client(&client).await.expect("save_client");

    let jwt_secret = "rate_limit_test_secret_2_at_least_32_chars".to_string();
    let metrics = Metrics::new().expect("metrics");
    let token_actor = oauth2_actix::actors::TokenActor::new(
        storage.clone(),
        jwt_secret.clone(),
        "http://localhost".to_string(),
    )
    .start();
    let token_pool = TokenActorPool::new(vec![token_actor]);
    let client_actor = oauth2_actix::actors::ClientActor::new(storage).start();
    let auth_actor = oauth2_actix::actors::AuthActor::new(
        oauth2_storage_factory::create_storage("sqlite::memory:")
            .await
            .expect("auth storage"),
    )
    .start();
    let oidc_config = OidcConfig {
        issuer: "http://localhost".to_string(),
        jwt_secret: jwt_secret.clone(),
        id_token_alg: "HS256".to_string(),
        id_token_kid: None,
        id_token_private_key_pem: None,
    };

    // Bucket allows only 1 failure before 429.
    let ic_limiter = Arc::new(oauth2_ratelimit::in_memory::InMemoryRateLimiter::new(1, 60))
        as Arc<dyn oauth2_ratelimit::RateLimiter>;

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(token_pool))
            .app_data(web::Data::new(client_actor))
            .app_data(web::Data::new(auth_actor))
            .app_data(web::Data::new(jwt_secret))
            .app_data(web::Data::new(metrics))
            .app_data(web::Data::new(oidc_config))
            .app_data(web::Data::new(false))
            .app_data(web::Data::new(InvalidClientRateLimiter(ic_limiter)))
            .service(web::scope("/oauth").route(
                "/token",
                web::post().to(oauth2_actix::handlers::oauth::token),
            )),
    )
    .await;

    // Multiple successful client_credentials requests — should not deplete bucket.
    for _ in 0..5 {
        let req = test::TestRequest::post()
            .uri("/oauth/token")
            .set_payload(
                "grant_type=client_credentials&client_id=client_rl2&client_secret=secret_rl2",
            )
            .insert_header(("Content-Type", "application/x-www-form-urlencoded"))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200, "successful request should be 200");
    }

    // One bad attempt: bucket has 1 token, so this should still return 401 (not 429).
    let req = test::TestRequest::post()
        .uri("/oauth/token")
        .set_payload("grant_type=client_credentials&client_id=client_rl2&client_secret=WRONG")
        .insert_header(("Content-Type", "application/x-www-form-urlencoded"))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 401, "first bad attempt should be 401");
}
