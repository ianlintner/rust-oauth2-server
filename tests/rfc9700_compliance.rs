//! RFC 9700 (OAuth 2.0 Security Best Current Practice) conformance tests.
//!
//! These tests assert the section-by-section guarantees listed in
//! `docs/oauth2-spec-audit.md` §9.1. They are kept separate from
//! `rfc_compliance.rs` so that Phase 6 hardening claims can be verified
//! independently and cited by RFC section number.

use actix::Actor;
use actix_session::{storage::CookieSessionStore, SessionMiddleware};
use actix_web::{cookie::Key, test, web, App};
use std::sync::Arc;
use tokio::sync::RwLock;

use oauth2_actix::actors::TokenActorPool;
use oauth2_actix::handlers::wellknown::OidcConfig;
use oauth2_core::{Client, TokenResponse, User};
use oauth2_observability::Metrics;

// ---------------------------------------------------------------------------
// Shared setup (same pattern as tests/rfc_compliance.rs).
// ---------------------------------------------------------------------------

async fn setup(
    clients: Vec<Client>,
    issuer: &str,
    access_ttl_secs: Option<i64>,
    refresh_ttl_secs: Option<i64>,
) -> (
    TokenActorPool,
    actix::Addr<oauth2_actix::actors::ClientActor>,
    actix::Addr<oauth2_actix::actors::AuthActor>,
    String,
    Metrics,
    OidcConfig,
    oauth2_ports::DynStorage,
) {
    let storage = oauth2_storage_factory::create_storage("sqlite::memory:")
        .await
        .expect("storage");
    storage.init().await.expect("init");

    for client in clients {
        storage.save_client(&client).await.expect("save_client");
    }

    let now = chrono::Utc::now();
    let user = User {
        id: "user_rfc9700".to_string(),
        username: "alice".to_string(),
        // Argon2 hash of "correct-horse-battery-staple" generated offline; any
        // password verification in this suite uses this exact value.
        password_hash: oauth2_actix::handlers::login::hash_password("correct-horse-battery-staple")
            .expect("hash"),
        email: "alice@example.test".to_string(),
        enabled: true,
        role: "user".to_string(),
        created_at: now,
        updated_at: now,
    };
    storage.save_user(&user).await.expect("save_user");

    let jwt_secret = "rfc9700_test_secret_at_least_32_chars_long".to_string();
    let metrics = Metrics::new().expect("metrics");

    let mut token_actor = oauth2_actix::actors::TokenActor::new(
        storage.clone(),
        jwt_secret.clone(),
        issuer.to_string(),
    );
    if let (Some(a), Some(r)) = (access_ttl_secs, refresh_ttl_secs) {
        token_actor = token_actor.with_token_ttls(a, r);
    }
    let token_pool = TokenActorPool::new(vec![token_actor.start()]);
    let client_actor = oauth2_actix::actors::ClientActor::new(storage.clone()).start();
    let auth_actor = oauth2_actix::actors::AuthActor::new(storage.clone()).start();

    let oidc_config = OidcConfig {
        issuer: issuer.to_string(),
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
        storage,
    )
}

// ---------------------------------------------------------------------------
// §2.3 — Access token audience restriction via RFC 8707 `resource` parameter.
// ---------------------------------------------------------------------------

/// When the token request carries a `resource` parameter, the issued access
/// token's `aud` claim MUST equal that resource URI (not the client_id).
#[actix_web::test]
async fn rfc9700_aud_reflects_resource_parameter_on_client_credentials() {
    const ISSUER: &str = "https://auth.example.com";
    const RESOURCE: &str = "https://api.example.com/widgets";

    let client = Client::new(
        "client_res".to_string(),
        "secret_res".to_string(),
        vec!["https://unused/cb".to_string()],
        vec!["client_credentials".to_string()],
        "read".to_string(),
        "test".to_string(),
    );

    let (token_actor, client_actor, auth_actor, jwt_secret, metrics, oidc_config, _storage) =
        setup(vec![client], ISSUER, None, None).await;
    let keyset = Arc::new(RwLock::new(oauth2_core::models::key_set::KeySet::default()));

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(token_actor))
            .app_data(web::Data::new(client_actor))
            .app_data(web::Data::new(auth_actor))
            .app_data(web::Data::new(jwt_secret.clone()))
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

    let resp = test::call_service(
        &app,
        test::TestRequest::post()
            .uri("/oauth/token")
            .set_form([
                ("grant_type", "client_credentials"),
                ("client_id", "client_res"),
                ("client_secret", "secret_res"),
                ("scope", "read"),
                ("resource", RESOURCE),
            ])
            .to_request(),
    )
    .await;

    assert_eq!(
        resp.status(),
        200,
        "token endpoint should accept resource param"
    );
    let body: TokenResponse = test::read_body_json(resp).await;

    let mut validation = jsonwebtoken::Validation::default();
    validation.set_audience(&[RESOURCE]);
    let decoded = jsonwebtoken::decode::<serde_json::Value>(
        &body.access_token,
        &jsonwebtoken::DecodingKey::from_secret(jwt_secret.as_bytes()),
        &validation,
    )
    .expect("JWT must decode with resource as audience");

    assert_eq!(
        decoded.claims["aud"].as_str(),
        Some(RESOURCE),
        "RFC 9700 §2.3 / RFC 8707: aud MUST equal the resource parameter"
    );
    assert_eq!(
        decoded.claims["client_id"].as_str(),
        Some("client_res"),
        "client_id claim must still identify the issuing client"
    );
}

// ---------------------------------------------------------------------------
// §4.11 — 303 See Other after credential POST.
// ---------------------------------------------------------------------------

/// RFC 9700 §4.11: the AS MUST use HTTP 303 (or a GET-based redirect) after
/// a credential POST so that user-agents do not replay the POST body to the
/// redirect target.
#[actix_web::test]
async fn rfc9700_login_returns_303_after_credentials_post() {
    let (_token_actor, _client_actor, _auth_actor, _jwt_secret, metrics, _oidc, storage) =
        setup(vec![], "https://auth.example.com", None, None).await;

    let app = test::init_service(
        App::new()
            .wrap(SessionMiddleware::new(
                CookieSessionStore::default(),
                Key::generate(),
            ))
            .app_data(web::Data::new(storage))
            .app_data(web::Data::new(metrics))
            .route(
                "/auth/login",
                web::post().to(oauth2_actix::handlers::login::login_submit),
            ),
    )
    .await;

    // Wrong password path — still a credential POST, still MUST be 303.
    let resp = test::call_service(
        &app,
        test::TestRequest::post()
            .uri("/auth/login")
            .set_form([("username", "alice"), ("password", "not-the-password")])
            .to_request(),
    )
    .await;
    assert_eq!(
        resp.status(),
        303,
        "RFC 9700 §4.11: login endpoint must return 303 See Other after credential POST"
    );

    // Correct-credentials path — also 303.
    let resp = test::call_service(
        &app,
        test::TestRequest::post()
            .uri("/auth/login")
            .set_form([
                ("username", "alice"),
                ("password", "correct-horse-battery-staple"),
            ])
            .to_request(),
    )
    .await;
    assert_eq!(
        resp.status(),
        303,
        "RFC 9700 §4.11: successful login must return 303 See Other"
    );
}

// ---------------------------------------------------------------------------
// §2.1.1.2 / §2.1.2 / §2.4 — discovery document excludes deprecated flows.
// ---------------------------------------------------------------------------

/// The discovery document MUST NOT advertise insecure flows or PKCE methods
/// prohibited by RFC 9700 (implicit grant, ROPC, `plain` PKCE).
#[actix_web::test]
async fn rfc9700_discovery_excludes_deprecated_flows() {
    let (token_actor, client_actor, auth_actor, jwt_secret, metrics, oidc_config, _storage) =
        setup(vec![], "https://auth.example.com", None, None).await;
    let keyset = Arc::new(RwLock::new(oauth2_core::models::key_set::KeySet::default()));

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(token_actor))
            .app_data(web::Data::new(client_actor))
            .app_data(web::Data::new(auth_actor))
            .app_data(web::Data::new(jwt_secret))
            .app_data(web::Data::new(metrics))
            .app_data(web::Data::new(oidc_config))
            .app_data(web::Data::new(keyset))
            .app_data(web::Data::new(false))
            .route(
                "/.well-known/openid-configuration",
                web::get().to(oauth2_actix::handlers::wellknown::openid_configuration),
            ),
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

    let grants = body["grant_types_supported"]
        .as_array()
        .expect("grant_types_supported array")
        .iter()
        .filter_map(|v| v.as_str())
        .collect::<Vec<_>>();
    assert!(
        !grants.contains(&"password"),
        "RFC 9700 §2.4: ROPC (`password`) grant MUST NOT be advertised — got {grants:?}"
    );

    let response_types = body["response_types_supported"]
        .as_array()
        .expect("response_types_supported array")
        .iter()
        .filter_map(|v| v.as_str())
        .collect::<Vec<_>>();
    assert!(
        !response_types.contains(&"token"),
        "RFC 9700 §2.1.2: implicit grant (`response_type=token`) MUST NOT be advertised — got {response_types:?}"
    );

    let pkce_methods = body["code_challenge_methods_supported"]
        .as_array()
        .expect("code_challenge_methods_supported array")
        .iter()
        .filter_map(|v| v.as_str())
        .collect::<Vec<_>>();
    assert!(
        !pkce_methods.contains(&"plain"),
        "RFC 9700 §4.8: `plain` PKCE MUST NOT be advertised — got {pkce_methods:?}"
    );
    assert!(
        pkce_methods.contains(&"S256"),
        "RFC 9700 §2.1.1.2: S256 PKCE method MUST be advertised — got {pkce_methods:?}"
    );

    assert_eq!(
        body["authorization_response_iss_parameter_supported"].as_bool(),
        Some(true),
        "RFC 9207 / RFC 9700 §2.1.3: issuer parameter support MUST be advertised"
    );
}

// ---------------------------------------------------------------------------
// §2.3 / §4.14 — configurable token TTLs (Phase 6.4).
// ---------------------------------------------------------------------------

/// Access tokens honor the `jwt.access_token_ttl_secs` config knob. Operators
/// tuning for RFC 9700 §2.3 ("short-lived access tokens") need this surface.
#[actix_web::test]
async fn rfc9700_access_token_ttl_is_configurable() {
    const ISSUER: &str = "https://auth.example.com";
    const CUSTOM_ACCESS_TTL: i64 = 90;
    const CUSTOM_REFRESH_TTL: i64 = 1800;

    let client = Client::new(
        "client_ttl".to_string(),
        "secret_ttl".to_string(),
        vec!["https://unused/cb".to_string()],
        vec!["client_credentials".to_string()],
        "read".to_string(),
        "test".to_string(),
    );

    let (token_actor, client_actor, auth_actor, jwt_secret, metrics, oidc_config, _storage) =
        setup(
            vec![client],
            ISSUER,
            Some(CUSTOM_ACCESS_TTL),
            Some(CUSTOM_REFRESH_TTL),
        )
        .await;
    let keyset = Arc::new(RwLock::new(oauth2_core::models::key_set::KeySet::default()));

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(token_actor))
            .app_data(web::Data::new(client_actor))
            .app_data(web::Data::new(auth_actor))
            .app_data(web::Data::new(jwt_secret.clone()))
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

    let resp = test::call_service(
        &app,
        test::TestRequest::post()
            .uri("/oauth/token")
            .set_form([
                ("grant_type", "client_credentials"),
                ("client_id", "client_ttl"),
                ("client_secret", "secret_ttl"),
                ("scope", "read"),
            ])
            .to_request(),
    )
    .await;
    assert_eq!(resp.status(), 200);
    let body: TokenResponse = test::read_body_json(resp).await;

    assert_eq!(
        body.expires_in, CUSTOM_ACCESS_TTL as i32,
        "expires_in must reflect configured access_token_ttl_secs"
    );

    // Access token JWT exp - iat must equal the configured access TTL.
    let mut validation = jsonwebtoken::Validation::default();
    validation.set_audience(&["client_ttl"]);
    let decoded = jsonwebtoken::decode::<serde_json::Value>(
        &body.access_token,
        &jsonwebtoken::DecodingKey::from_secret(jwt_secret.as_bytes()),
        &validation,
    )
    .expect("decodable JWT");
    let exp = decoded.claims["exp"].as_i64().expect("exp claim");
    let iat = decoded.claims["iat"].as_i64().expect("iat claim");
    assert_eq!(
        exp - iat,
        CUSTOM_ACCESS_TTL,
        "JWT exp - iat must equal configured access TTL"
    );
}
