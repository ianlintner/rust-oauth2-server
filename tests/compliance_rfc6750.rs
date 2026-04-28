//! RFC 6750 — The OAuth 2.0 Authorization Framework: Bearer Token Usage
//!
//! Compliance tests that map directly to RFC 6750 sections.
//! See docs/compliance/RFC_COMPLIANCE.md for the full matrix.

use actix::Actor;
use actix_web::{test, web, App};

use oauth2_actix::actors::{CreateToken, TokenActorPool};
use oauth2_actix::handlers::wellknown::OidcConfig;
use oauth2_core::{Client, User};
use oauth2_observability::Metrics;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async fn setup_context(client: Client) -> (TokenActorPool, String, Metrics, OidcConfig) {
    let storage = oauth2_storage_factory::create_storage("sqlite::memory:")
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
    let oidc_config = OidcConfig {
        issuer: "http://localhost".to_string(),
        jwt_secret: jwt_secret.clone(),
        id_token_alg: "HS256".to_string(),
        id_token_kid: None,
        id_token_private_key_pem: None,
    };

    (token_pool, jwt_secret, metrics, oidc_config)
}

async fn issue_user_token(
    token_pool: &TokenActorPool,
    client_id: &str,
    scope: &str,
) -> oauth2_core::Token {
    token_pool
        .route(client_id)
        .send(CreateToken {
            user_id: Some("user_123".to_string()),
            client_id: client_id.to_string(),
            scope: scope.to_string(),
            include_refresh: false,
            token_family: None,
            resource: None,
            cnf: None,
            authorization_details: None,
            span: tracing::Span::current(),
        })
        .await
        .expect("send create token")
        .expect("create token")
}

async fn issue_client_token(
    token_pool: &TokenActorPool,
    client_id: &str,
    scope: &str,
) -> oauth2_core::Token {
    token_pool
        .route(client_id)
        .send(CreateToken {
            user_id: None,
            client_id: client_id.to_string(),
            scope: scope.to_string(),
            include_refresh: false,
            token_family: None,
            resource: None,
            cnf: None,
            authorization_details: None,
            span: tracing::Span::current(),
        })
        .await
        .expect("send create token")
        .expect("create token")
}

macro_rules! app {
    ($token_pool:expr, $oidc_config:expr) => {
        test::init_service(
            App::new()
                .app_data(web::Data::new($token_pool))
                .app_data(web::Data::new($oidc_config))
                .service(web::scope("/oauth").route(
                    "/userinfo",
                    web::get().to(oauth2_actix::handlers::wellknown::userinfo),
                )),
        )
        .await
    };
}

// ---------------------------------------------------------------------------
// RFC 6750 §2.1 — Authorization Request Header Field
// ---------------------------------------------------------------------------

/// RFC 6750 §2.1: Bearer token in the `Authorization` header must be accepted
/// and return the resource owner's claims.
///
/// @rfc 6750
/// @section 2.1
/// @requirement Bearer token in the Authorization header must be accepted by protected resources.
/// @level MUST
/// @url https://datatracker.ietf.org/doc/html/rfc6750#section-2.1
#[actix_web::test]
async fn rfc6750_s2_1_bearer_in_authorization_header_returns_200() {
    let client = Client::new(
        "client_bearer_ok".to_string(),
        "secret_bearer_ok".to_string(),
        vec!["https://unused.example/cb".to_string()],
        vec!["authorization_code".to_string()],
        "openid profile".to_string(),
        "test".to_string(),
    );
    let (token_pool, _jwt_secret, _metrics, oidc_config) = setup_context(client).await;
    let token = issue_user_token(&token_pool, "client_bearer_ok", "openid").await;
    let app = app!(token_pool, oidc_config);

    let req = test::TestRequest::get()
        .uri("/oauth/userinfo")
        .insert_header(("Authorization", format!("Bearer {}", token.access_token)))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(
        resp.status(),
        200,
        "valid Bearer token must yield 200 from userinfo"
    );
}

/// RFC 6750 §2.1: The userinfo response must include the `sub` claim.
///
/// @rfc 6750
/// @section 2.1
/// @requirement A valid Bearer token must enable retrieval of the resource owner's `sub` claim.
/// @level MUST
/// @url https://datatracker.ietf.org/doc/html/rfc6750#section-2.1
#[actix_web::test]
async fn rfc6750_s2_1_userinfo_response_contains_sub() {
    let client = Client::new(
        "client_bearer_sub".to_string(),
        "secret_bearer_sub".to_string(),
        vec!["https://unused.example/cb".to_string()],
        vec!["authorization_code".to_string()],
        "openid profile".to_string(),
        "test".to_string(),
    );
    let (token_pool, _jwt_secret, _metrics, oidc_config) = setup_context(client).await;
    let token = issue_user_token(&token_pool, "client_bearer_sub", "openid").await;
    let app = app!(token_pool, oidc_config);

    let req = test::TestRequest::get()
        .uri("/oauth/userinfo")
        .insert_header(("Authorization", format!("Bearer {}", token.access_token)))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert!(
        body.get("sub").is_some(),
        "userinfo response must include `sub` claim"
    );
}

// ---------------------------------------------------------------------------
// RFC 6750 §3.1 — WWW-Authenticate response on errors
// ---------------------------------------------------------------------------

/// RFC 6750 §3.1: A request without an `Authorization` header must return
/// 401 Unauthorized with a `WWW-Authenticate: Bearer` header.
///
/// @rfc 6750
/// @section 3.1
/// @requirement Missing Bearer credentials must return 401 with WWW-Authenticate: Bearer.
/// @level MUST
/// @url https://datatracker.ietf.org/doc/html/rfc6750#section-3.1
#[actix_web::test]
async fn rfc6750_s3_1_missing_token_returns_401() {
    let client = Client::new(
        "client_bearer_miss".to_string(),
        "secret_bearer_miss".to_string(),
        vec!["https://unused.example/cb".to_string()],
        vec!["authorization_code".to_string()],
        "openid".to_string(),
        "test".to_string(),
    );
    let (token_pool, _jwt_secret, _metrics, oidc_config) = setup_context(client).await;
    let app = app!(token_pool, oidc_config);

    let req = test::TestRequest::get().uri("/oauth/userinfo").to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 401, "missing Bearer token must return 401");
    let www_auth = resp
        .response()
        .headers()
        .get("WWW-Authenticate")
        .expect("WWW-Authenticate header must be present on 401");
    let value = www_auth.to_str().unwrap();
    assert!(
        value.contains("Bearer"),
        "WWW-Authenticate must use the Bearer scheme, got: {value}"
    );
}

/// RFC 6750 §3.1: A request presenting an invalid / garbage Bearer token must
/// return 401 with a `WWW-Authenticate: Bearer error="invalid_token"` header.
///
/// @rfc 6750
/// @section 3.1
/// @requirement Invalid Bearer token must return 401 with WWW-Authenticate including error=invalid_token.
/// @level MUST
/// @url https://datatracker.ietf.org/doc/html/rfc6750#section-3.1
#[actix_web::test]
async fn rfc6750_s3_1_invalid_token_returns_401_with_www_authenticate() {
    let client = Client::new(
        "client_bearer_bad".to_string(),
        "secret_bearer_bad".to_string(),
        vec!["https://unused.example/cb".to_string()],
        vec!["authorization_code".to_string()],
        "openid".to_string(),
        "test".to_string(),
    );
    let (token_pool, _jwt_secret, _metrics, oidc_config) = setup_context(client).await;
    let app = app!(token_pool, oidc_config);

    let req = test::TestRequest::get()
        .uri("/oauth/userinfo")
        .insert_header(("Authorization", "Bearer this_is_not_a_real_token"))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 401, "invalid Bearer token must return 401");
    let www_auth = resp
        .response()
        .headers()
        .get("WWW-Authenticate")
        .expect("WWW-Authenticate header must be present on 401");
    let value = www_auth.to_str().unwrap();
    assert!(
        value.contains("invalid_token"),
        "WWW-Authenticate must include error=invalid_token, got: {value}"
    );
}

/// RFC 6750 §3.1: The error body for an invalid token must include an `error`
/// field set to `invalid_token`.
///
/// @rfc 6750
/// @section 3.1
/// @requirement Invalid token error body must contain `error: invalid_token`.
/// @level MUST
/// @url https://datatracker.ietf.org/doc/html/rfc6750#section-3.1
#[actix_web::test]
async fn rfc6750_s3_1_error_body_has_invalid_token_code() {
    let client = Client::new(
        "client_bearer_err".to_string(),
        "secret_bearer_err".to_string(),
        vec!["https://unused.example/cb".to_string()],
        vec!["authorization_code".to_string()],
        "openid".to_string(),
        "test".to_string(),
    );
    let (token_pool, _jwt_secret, _metrics, oidc_config) = setup_context(client).await;
    let app = app!(token_pool, oidc_config);

    let req = test::TestRequest::get()
        .uri("/oauth/userinfo")
        .insert_header(("Authorization", "Bearer not_valid_at_all"))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 401);
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(
        body.get("error").and_then(|v| v.as_str()),
        Some("invalid_token"),
        "error body must have error=invalid_token"
    );
}

/// RFC 6750 §2.3: A client credentials token (no user context) must not grant
/// access to the userinfo endpoint — the resource server returns 401 because
/// the token represents a client, not a resource owner.
///
/// @rfc 6750
/// @section 2
/// @requirement A token without a resource-owner subject must not be accepted by the userinfo endpoint.
/// @level MUST
/// @url https://datatracker.ietf.org/doc/html/rfc6750#section-2
#[actix_web::test]
async fn rfc6750_s2_client_credentials_token_cannot_access_userinfo() {
    let client = Client::new(
        "client_bearer_cc".to_string(),
        "secret_bearer_cc".to_string(),
        vec!["https://unused.example/cb".to_string()],
        vec!["client_credentials".to_string()],
        "read".to_string(),
        "test".to_string(),
    );
    let (token_pool, _jwt_secret, _metrics, oidc_config) = setup_context(client).await;
    let token = issue_client_token(&token_pool, "client_bearer_cc", "read").await;
    let app = app!(token_pool, oidc_config);

    let req = test::TestRequest::get()
        .uri("/oauth/userinfo")
        .insert_header(("Authorization", format!("Bearer {}", token.access_token)))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert!(
        resp.status().is_client_error(),
        "client credentials token (no user context) must not access userinfo — got {}",
        resp.status()
    );
}
