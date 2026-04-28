//! RFC 7662 — OAuth 2.0 Token Introspection
//! RFC 7009 — OAuth 2.0 Token Revocation
//!
//! Compliance tests that map directly to RFC 7662 and RFC 7009 sections.
//! See docs/compliance/RFC_COMPLIANCE.md for the full matrix.

use actix::Actor;
use actix_web::{test, web, App};

use oauth2_actix::actors::{CreateToken, TokenActorPool};
use oauth2_actix::handlers::wellknown::OidcConfig;
use oauth2_core::{Client, IntrospectionResponse, Token, User};
use oauth2_observability::Metrics;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn basic_auth_header(client_id: &str, client_secret: &str) -> String {
    use base64::{engine::general_purpose, Engine as _};
    format!(
        "Basic {}",
        general_purpose::STANDARD.encode(format!("{client_id}:{client_secret}"))
    )
}

async fn setup_context(
    client: Client,
) -> (
    TokenActorPool,
    actix::Addr<oauth2_actix::actors::ClientActor>,
    actix::Addr<oauth2_actix::actors::AuthActor>,
    String,
    Metrics,
    OidcConfig,
) {
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

async fn setup_two_clients(
    client_a: Client,
    client_b: Client,
) -> (
    TokenActorPool,
    actix::Addr<oauth2_actix::actors::ClientActor>,
    actix::Addr<oauth2_actix::actors::AuthActor>,
    String,
    Metrics,
    OidcConfig,
) {
    let storage = oauth2_storage_factory::create_storage("sqlite::memory:")
        .await
        .expect("create storage");
    storage.init().await.expect("init storage");
    storage.save_client(&client_a).await.expect("save client_a");
    storage.save_client(&client_b).await.expect("save client_b");

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
        jwt_secret,
        metrics,
        oidc_config,
    )
}

async fn issue_access_token(
    token_pool: &TokenActorPool,
    client_id: &str,
    user_id: Option<&str>,
    scope: &str,
) -> Token {
    token_pool
        .route(client_id)
        .send(CreateToken {
            user_id: user_id.map(|v| v.to_string()),
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
    ($token_actor:expr, $client_actor:expr, $auth_actor:expr,
     $jwt_secret:expr, $metrics:expr, $oidc_config:expr) => {
        test::init_service(
            App::new()
                .app_data(web::Data::new($token_actor))
                .app_data(web::Data::new($client_actor))
                .app_data(web::Data::new($auth_actor))
                .app_data(web::Data::new($jwt_secret))
                .app_data(web::Data::new($metrics))
                .app_data(web::Data::new($oidc_config))
                .app_data(web::Data::new(false))
                .service(
                    web::scope("/oauth")
                        .route(
                            "/introspect",
                            web::post().to(oauth2_actix::handlers::token::introspect),
                        )
                        .route(
                            "/revoke",
                            web::post().to(oauth2_actix::handlers::token::revoke),
                        ),
                ),
        )
        .await
    };
}

// ---------------------------------------------------------------------------
// RFC 7662 — Token Introspection
// ---------------------------------------------------------------------------

/// RFC 7662 §2.2: Introspection of an active token must return `active: true`.
///
/// @rfc 7662
/// @section 2.2
/// @requirement Introspection of an active token must yield `active: true`.
/// @level MUST
/// @url https://datatracker.ietf.org/doc/html/rfc7662#section-2.2
#[actix_web::test]
async fn rfc7662_s2_2_introspect_active_token_returns_true() {
    let client = Client::new(
        "client_intros_act".to_string(),
        "secret_intros_act".to_string(),
        vec!["https://unused.example/cb".to_string()],
        vec!["client_credentials".to_string()],
        "read".to_string(),
        "test".to_string(),
    );
    let (token_pool, client_actor, auth_actor, jwt_secret, metrics, oidc_config) =
        setup_context(client).await;
    let token = issue_access_token(&token_pool, "client_intros_act", None, "read").await;
    let app = app!(
        token_pool,
        client_actor,
        auth_actor,
        jwt_secret,
        metrics,
        oidc_config
    );

    let req = test::TestRequest::post()
        .uri("/oauth/introspect")
        .set_form([
            ("token", token.access_token.as_str()),
            ("client_id", "client_intros_act"),
            ("client_secret", "secret_intros_act"),
        ])
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 200);
    let body: IntrospectionResponse = test::read_body_json(resp).await;
    assert!(body.active, "active token must report active=true");
}

/// RFC 7662 §2.2: Introspection must return `active: false` for an unknown or
/// garbage token string.
///
/// @rfc 7662
/// @section 2.2
/// @requirement Introspection must return `active: false` for an invalid or unknown token.
/// @level MUST
/// @url https://datatracker.ietf.org/doc/html/rfc7662#section-2.2
#[actix_web::test]
async fn rfc7662_s2_2_introspect_invalid_token_returns_false() {
    let client = Client::new(
        "client_intros_inv".to_string(),
        "secret_intros_inv".to_string(),
        vec!["https://unused.example/cb".to_string()],
        vec!["client_credentials".to_string()],
        "read".to_string(),
        "test".to_string(),
    );
    let (token_pool, client_actor, auth_actor, jwt_secret, metrics, oidc_config) =
        setup_context(client).await;
    let app = app!(
        token_pool,
        client_actor,
        auth_actor,
        jwt_secret,
        metrics,
        oidc_config
    );

    let req = test::TestRequest::post()
        .uri("/oauth/introspect")
        .set_form([
            ("token", "not_a_real_token_at_all"),
            ("client_id", "client_intros_inv"),
            ("client_secret", "secret_intros_inv"),
        ])
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 200);
    let body: IntrospectionResponse = test::read_body_json(resp).await;
    assert!(!body.active, "invalid token must report active=false");
}

/// RFC 7662 §2.1: The introspect endpoint must require client authentication
/// (when public introspection is disabled).
///
/// @rfc 7662
/// @section 2.1
/// @requirement Introspection endpoint must require client authentication.
/// @level MUST
/// @url https://datatracker.ietf.org/doc/html/rfc7662#section-2.1
#[actix_web::test]
async fn rfc7662_s2_1_introspect_requires_client_auth() {
    let client = Client::new(
        "client_intros_auth".to_string(),
        "secret_intros_auth".to_string(),
        vec!["https://unused.example/cb".to_string()],
        vec!["client_credentials".to_string()],
        "read".to_string(),
        "test".to_string(),
    );
    let (token_pool, client_actor, auth_actor, jwt_secret, metrics, oidc_config) =
        setup_context(client).await;
    let token = issue_access_token(&token_pool, "client_intros_auth", None, "read").await;
    let app = app!(
        token_pool,
        client_actor,
        auth_actor,
        jwt_secret,
        metrics,
        oidc_config
    );

    // Submit token without any client credentials.
    let req = test::TestRequest::post()
        .uri("/oauth/introspect")
        .set_form([("token", token.access_token.as_str())])
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert!(
        resp.status().is_client_error(),
        "introspect without client auth must return 4xx, got {}",
        resp.status()
    );
}

/// RFC 7662 §2.2: Introspection response must include `scope`, `client_id`,
/// and `token_type` fields for an active token.
///
/// @rfc 7662
/// @section 2.2
/// @requirement Introspection response for an active token must include scope, client_id, and token_type.
/// @level MUST
/// @url https://datatracker.ietf.org/doc/html/rfc7662#section-2.2
#[actix_web::test]
async fn rfc7662_s2_2_introspect_response_includes_required_fields() {
    let client = Client::new(
        "client_intros_fld".to_string(),
        "secret_intros_fld".to_string(),
        vec!["https://unused.example/cb".to_string()],
        vec!["client_credentials".to_string()],
        "read write".to_string(),
        "test".to_string(),
    );
    let (token_pool, client_actor, auth_actor, jwt_secret, metrics, oidc_config) =
        setup_context(client).await;
    let token = issue_access_token(&token_pool, "client_intros_fld", None, "read").await;
    let app = app!(
        token_pool,
        client_actor,
        auth_actor,
        jwt_secret,
        metrics,
        oidc_config
    );

    let req = test::TestRequest::post()
        .uri("/oauth/introspect")
        .set_form([
            ("token", token.access_token.as_str()),
            ("client_id", "client_intros_fld"),
            ("client_secret", "secret_intros_fld"),
        ])
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 200);
    let body: IntrospectionResponse = test::read_body_json(resp).await;
    assert!(body.active);
    assert!(body.scope.is_some(), "scope field must be present");
    assert_eq!(
        body.client_id.as_deref(),
        Some("client_intros_fld"),
        "client_id must match the token owner"
    );
    assert!(
        body.token_type.is_some(),
        "token_type field must be present"
    );
}

/// RFC 7662 §2.2: Introspection must return `active: false` for a token that
/// belongs to a different client (cross-client isolation).
///
/// @rfc 7662
/// @section 2.2
/// @requirement Introspection must report a token belonging to a different client as inactive.
/// @level MUST
/// @url https://datatracker.ietf.org/doc/html/rfc7662#section-2.2
#[actix_web::test]
async fn rfc7662_s2_2_introspect_cross_client_returns_inactive() {
    let client_a = Client::new(
        "client_intros_a".to_string(),
        "secret_intros_a".to_string(),
        vec!["https://unused.example/cb".to_string()],
        vec!["client_credentials".to_string()],
        "read".to_string(),
        "test".to_string(),
    );
    let client_b = Client::new(
        "client_intros_b".to_string(),
        "secret_intros_b".to_string(),
        vec!["https://unused.example/cb".to_string()],
        vec!["client_credentials".to_string()],
        "read".to_string(),
        "test".to_string(),
    );
    let (token_pool, client_actor, auth_actor, jwt_secret, metrics, oidc_config) =
        setup_two_clients(client_a, client_b).await;

    // Issue a token for client_a.
    let token = issue_access_token(&token_pool, "client_intros_a", None, "read").await;

    let app = app!(
        token_pool,
        client_actor,
        auth_actor,
        jwt_secret,
        metrics,
        oidc_config
    );

    // client_b attempts to introspect client_a's token.
    let req = test::TestRequest::post()
        .uri("/oauth/introspect")
        .set_form([
            ("token", token.access_token.as_str()),
            ("client_id", "client_intros_b"),
            ("client_secret", "secret_intros_b"),
        ])
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 200);
    let body: IntrospectionResponse = test::read_body_json(resp).await;
    assert!(
        !body.active,
        "cross-client introspection must return active=false"
    );
}

/// RFC 7662 §2.1: Introspect endpoint must accept client auth via Basic header.
///
/// @rfc 7662
/// @section 2.1
/// @requirement Introspection endpoint must accept HTTP Basic client authentication.
/// @level MUST
/// @url https://datatracker.ietf.org/doc/html/rfc7662#section-2.1
#[actix_web::test]
async fn rfc7662_s2_1_introspect_accepts_basic_auth() {
    let client = Client::new(
        "client_intros_basic".to_string(),
        "secret_intros_basic".to_string(),
        vec!["https://unused.example/cb".to_string()],
        vec!["client_credentials".to_string()],
        "read".to_string(),
        "test".to_string(),
    );
    let (token_pool, client_actor, auth_actor, jwt_secret, metrics, oidc_config) =
        setup_context(client).await;
    let token = issue_access_token(&token_pool, "client_intros_basic", None, "read").await;
    let app = app!(
        token_pool,
        client_actor,
        auth_actor,
        jwt_secret,
        metrics,
        oidc_config
    );

    let req = test::TestRequest::post()
        .uri("/oauth/introspect")
        .insert_header((
            "Authorization",
            basic_auth_header("client_intros_basic", "secret_intros_basic"),
        ))
        .set_form([("token", token.access_token.as_str())])
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 200);
    let body: IntrospectionResponse = test::read_body_json(resp).await;
    assert!(body.active, "Basic-auth introspect must return active=true");
}

// ---------------------------------------------------------------------------
// RFC 7009 — Token Revocation
// ---------------------------------------------------------------------------

/// RFC 7009 §2.2: Successful revocation must return 200 OK.
///
/// @rfc 7009
/// @section 2.2
/// @requirement Successful token revocation must return HTTP 200.
/// @level MUST
/// @url https://datatracker.ietf.org/doc/html/rfc7009#section-2.2
#[actix_web::test]
async fn rfc7009_s2_2_revoke_valid_token_returns_200() {
    let client = Client::new(
        "client_revoke_ok".to_string(),
        "secret_revoke_ok".to_string(),
        vec!["https://unused.example/cb".to_string()],
        vec!["client_credentials".to_string()],
        "read".to_string(),
        "test".to_string(),
    );
    let (token_pool, client_actor, auth_actor, jwt_secret, metrics, oidc_config) =
        setup_context(client).await;
    let token = issue_access_token(&token_pool, "client_revoke_ok", None, "read").await;
    let app = app!(
        token_pool,
        client_actor,
        auth_actor,
        jwt_secret,
        metrics,
        oidc_config
    );

    let req = test::TestRequest::post()
        .uri("/oauth/revoke")
        .set_form([
            ("token", token.access_token.as_str()),
            ("client_id", "client_revoke_ok"),
            ("client_secret", "secret_revoke_ok"),
        ])
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 200);
}

/// RFC 7009 §2.2: Revocation of an unknown (never-issued) token must also
/// return 200 OK per the spec ("error-free" behavior for unknown tokens).
///
/// @rfc 7009
/// @section 2.2
/// @requirement Revocation of an unknown token must still return HTTP 200.
/// @level MUST
/// @url https://datatracker.ietf.org/doc/html/rfc7009#section-2.2
#[actix_web::test]
async fn rfc7009_s2_2_revoke_unknown_token_returns_200() {
    let client = Client::new(
        "client_revoke_unk".to_string(),
        "secret_revoke_unk".to_string(),
        vec!["https://unused.example/cb".to_string()],
        vec!["client_credentials".to_string()],
        "read".to_string(),
        "test".to_string(),
    );
    let (token_pool, client_actor, auth_actor, jwt_secret, metrics, oidc_config) =
        setup_context(client).await;
    let app = app!(
        token_pool,
        client_actor,
        auth_actor,
        jwt_secret,
        metrics,
        oidc_config
    );

    let req = test::TestRequest::post()
        .uri("/oauth/revoke")
        .set_form([
            ("token", "totally_unknown_token_xyz"),
            ("client_id", "client_revoke_unk"),
            ("client_secret", "secret_revoke_unk"),
        ])
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(
        resp.status(),
        200,
        "unknown token revocation must return 200"
    );
}

/// RFC 7009 §2.1: Token revocation must require client authentication.
///
/// @rfc 7009
/// @section 2.1
/// @requirement Token revocation endpoint must require client authentication.
/// @level MUST
/// @url https://datatracker.ietf.org/doc/html/rfc7009#section-2.1
#[actix_web::test]
async fn rfc7009_s2_1_revoke_requires_client_auth() {
    let client = Client::new(
        "client_revoke_auth".to_string(),
        "secret_revoke_auth".to_string(),
        vec!["https://unused.example/cb".to_string()],
        vec!["client_credentials".to_string()],
        "read".to_string(),
        "test".to_string(),
    );
    let (token_pool, client_actor, auth_actor, jwt_secret, metrics, oidc_config) =
        setup_context(client).await;
    let token = issue_access_token(&token_pool, "client_revoke_auth", None, "read").await;
    let app = app!(
        token_pool,
        client_actor,
        auth_actor,
        jwt_secret,
        metrics,
        oidc_config
    );

    let req = test::TestRequest::post()
        .uri("/oauth/revoke")
        .set_form([("token", token.access_token.as_str())])
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert!(
        resp.status().is_client_error(),
        "revoke without client auth must return 4xx, got {}",
        resp.status()
    );
}

/// RFC 7009 §2 + RFC 7662 §2.2: After revocation, introspecting the token
/// must return `active: false`.
///
/// @rfc 7009
/// @section 2
/// @requirement A revoked token must subsequently be reported as inactive by introspection.
/// @level MUST
/// @url https://datatracker.ietf.org/doc/html/rfc7009#section-2
#[actix_web::test]
async fn rfc7009_s2_token_inactive_after_revoke() {
    let client = Client::new(
        "client_revoke_check".to_string(),
        "secret_revoke_check".to_string(),
        vec!["https://unused.example/cb".to_string()],
        vec!["client_credentials".to_string()],
        "read".to_string(),
        "test".to_string(),
    );
    let (token_pool, client_actor, auth_actor, jwt_secret, metrics, oidc_config) =
        setup_context(client).await;
    let token = issue_access_token(&token_pool, "client_revoke_check", None, "read").await;
    let app = app!(
        token_pool,
        client_actor,
        auth_actor,
        jwt_secret,
        metrics,
        oidc_config
    );

    // Confirm active before revocation.
    let req = test::TestRequest::post()
        .uri("/oauth/introspect")
        .set_form([
            ("token", token.access_token.as_str()),
            ("client_id", "client_revoke_check"),
            ("client_secret", "secret_revoke_check"),
        ])
        .to_request();
    let resp = test::call_service(&app, req).await;
    let before: IntrospectionResponse = test::read_body_json(resp).await;
    assert!(before.active, "token must be active before revocation");

    // Revoke it.
    let req = test::TestRequest::post()
        .uri("/oauth/revoke")
        .set_form([
            ("token", token.access_token.as_str()),
            ("client_id", "client_revoke_check"),
            ("client_secret", "secret_revoke_check"),
        ])
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 200);

    // Confirm inactive after revocation.
    let req = test::TestRequest::post()
        .uri("/oauth/introspect")
        .set_form([
            ("token", token.access_token.as_str()),
            ("client_id", "client_revoke_check"),
            ("client_secret", "secret_revoke_check"),
        ])
        .to_request();
    let resp = test::call_service(&app, req).await;
    let after: IntrospectionResponse = test::read_body_json(resp).await;
    assert!(!after.active, "token must be inactive after revocation");
}
