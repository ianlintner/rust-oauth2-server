/// RFC Phase 2 compliance tests — Dynamic Client Registration & JWT Auth.
///
/// Tests cover:
///   - RFC 7591 Dynamic Client Registration
///   - RFC 7591 §3.2 registration_access_token
///   - RFC 7592 Client Configuration Endpoint (read / update / delete)
///   - RFC 7523 client_secret_jwt authentication
///   - RFC 7523 private_key_jwt authentication
///   - RFC 8414 discovery doc updates
///   - OIDC metadata fields in client registration
use actix::{Actor, Addr};
use actix_web::{test, web, App};
use std::sync::Arc;
use tokio::sync::RwLock;

use oauth2_actix::actors::TokenActorPool;
use oauth2_actix::handlers::wellknown::OidcConfig;
use oauth2_core::{Client, ClientRegistrationResponse, OAuth2Error, User};
use oauth2_observability::Metrics; // ---------------------------------------------------------------------------
                                   // Helpers shared across all Phase 2 tests
                                   // ---------------------------------------------------------------------------

async fn setup_phase2_context(
    clients: Vec<Client>,
    issuer: &str,
) -> (
    TokenActorPool,
    Addr<oauth2_actix::actors::ClientActor>,
    Addr<oauth2_actix::actors::AuthActor>,
    String, // jwt_secret
    Metrics,
    OidcConfig,
) {
    let storage = oauth2_storage_factory::create_storage("sqlite::memory:")
        .await
        .expect("create storage");
    storage.init().await.expect("init");

    for client in clients {
        storage.save_client(&client).await.expect("save client");
    }

    let now = chrono::Utc::now();
    let user = User {
        id: "user_phase2".to_string(),
        username: "user_phase2".to_string(),
        password_hash: "unused".to_string(),
        email: "user_phase2@example.test".to_string(),
        enabled: true,
        role: "user".to_string(),
        created_at: now,
        updated_at: now,
    };
    storage.save_user(&user).await.expect("save user");

    let jwt_secret = "phase2_test_jwt_secret_at_least_32_chars".to_string();
    let metrics = Metrics::new().expect("metrics");

    let token_actor = oauth2_actix::actors::TokenActor::new(
        storage.clone(),
        jwt_secret.clone(),
        issuer.to_string(),
    )
    .start();
    let token_pool = TokenActorPool::new(vec![token_actor]);
    let client_actor = oauth2_actix::actors::ClientActor::new(storage.clone()).start();
    let auth_actor = oauth2_actix::actors::AuthActor::new(storage).start();

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
    )
}

// ===================================================================
// RFC 7591: Dynamic Client Registration
// ===================================================================

/// RFC 7591 §3.1: successful dynamic registration returns a 201 with full
/// client information response including registration_access_token.
///
/// @rfc 7591
/// @section 3.1
/// @requirement Successful dynamic client registration must return 201 with full client info plus registration_access_token.
/// @level MUST
/// @url https://datatracker.ietf.org/doc/html/rfc7591#section-3.1
#[actix_web::test]
async fn rfc7591_dynamic_registration_success() {
    const ISSUER: &str = "https://auth.example.com";

    let (token_pool, client_actor, auth_actor, jwt_secret, metrics, oidc_config) =
        setup_phase2_context(vec![], ISSUER).await;
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
            .service(web::scope("/connect").route(
                "/register",
                web::post().to(oauth2_actix::handlers::client::dynamic_register),
            )),
    )
    .await;

    let body = serde_json::json!({
        "client_name": "Test App",
        "redirect_uris": ["https://app.example/callback"],
        "grant_types": ["authorization_code", "refresh_token"],
        "scope": "openid profile email",
        "token_endpoint_auth_method": "client_secret_basic",
        "contacts": ["admin@example.com"],
        "logo_uri": "https://app.example/logo.png",
        "client_uri": "https://app.example",
        "policy_uri": "https://app.example/privacy",
        "tos_uri": "https://app.example/tos"
    });

    let req = test::TestRequest::post()
        .uri("/connect/register")
        .set_json(&body)
        .to_request();
    let resp = test::call_service(&app, req).await;

    assert_eq!(resp.status(), 201, "RFC 7591 §3.2.1 — MUST return 201");

    let body: ClientRegistrationResponse = test::read_body_json(resp).await;
    assert!(!body.client_id.is_empty(), "client_id must be assigned");
    assert!(
        body.client_secret.is_some(),
        "confidential client must get a secret"
    );
    assert!(
        !body.registration_access_token.is_empty(),
        "registration_access_token must be returned"
    );
    assert!(
        body.registration_client_uri.contains("/connect/register/"),
        "registration_client_uri must point to config endpoint"
    );
    assert_eq!(body.client_name, "Test App");
    assert_eq!(body.redirect_uris, vec!["https://app.example/callback"]);
    assert_eq!(body.token_endpoint_auth_method, "client_secret_basic");
    assert_eq!(body.contacts, vec!["admin@example.com"]);
    assert_eq!(
        body.logo_uri,
        Some("https://app.example/logo.png".to_string())
    );
    assert_eq!(body.client_uri, Some("https://app.example".to_string()));
    assert_eq!(
        body.policy_uri,
        Some("https://app.example/privacy".to_string())
    );
    assert_eq!(body.tos_uri, Some("https://app.example/tos".to_string()));
    assert_eq!(body.client_secret_expires_at, Some(0));
    assert!(body.client_id_issued_at > 0);
}

/// RFC 7591 §3.1: defaults — when `grant_types` and `response_types` are
/// omitted, the server MUST default to `authorization_code` / `code`.
///
/// @rfc 7591
/// @section 3.1
/// @requirement Registration must default `grant_types`/`response_types` to `authorization_code`/`code` when omitted.
/// @level MUST
/// @url https://datatracker.ietf.org/doc/html/rfc7591#section-3.1
#[actix_web::test]
async fn rfc7591_defaults_grant_and_response_types() {
    const ISSUER: &str = "https://auth.example.com";

    let (token_pool, client_actor, auth_actor, jwt_secret, metrics, oidc_config) =
        setup_phase2_context(vec![], ISSUER).await;
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
            .service(web::scope("/connect").route(
                "/register",
                web::post().to(oauth2_actix::handlers::client::dynamic_register),
            )),
    )
    .await;

    // Omit grant_types and response_types — server must fill in defaults.
    let body = serde_json::json!({
        "client_name": "Defaulting App",
        "redirect_uris": ["https://app.example/cb"]
    });

    let req = test::TestRequest::post()
        .uri("/connect/register")
        .set_json(&body)
        .to_request();
    let resp = test::call_service(&app, req).await;

    assert_eq!(resp.status(), 201);
    let body: ClientRegistrationResponse = test::read_body_json(resp).await;
    assert_eq!(body.grant_types, vec!["authorization_code"]);
    assert_eq!(body.response_types, vec!["code"]);
    assert_eq!(body.scope, "openid");
}

/// RFC 7591 §3.1: public client registration (token_endpoint_auth_method=none)
/// must NOT return a client_secret.
///
/// @rfc 7591
/// @section 3.1
/// @requirement Public-client registration must omit `client_secret` from the registration response.
/// @level MUST
/// @url https://datatracker.ietf.org/doc/html/rfc7591#section-3.1
#[actix_web::test]
async fn rfc7591_public_client_no_secret() {
    const ISSUER: &str = "https://auth.example.com";

    let (token_pool, client_actor, auth_actor, jwt_secret, metrics, oidc_config) =
        setup_phase2_context(vec![], ISSUER).await;
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
            .service(web::scope("/connect").route(
                "/register",
                web::post().to(oauth2_actix::handlers::client::dynamic_register),
            )),
    )
    .await;

    let body = serde_json::json!({
        "client_name": "Public SPA",
        "redirect_uris": ["https://spa.example/cb"],
        "grant_types": ["authorization_code"],
        "token_endpoint_auth_method": "none"
    });

    let req = test::TestRequest::post()
        .uri("/connect/register")
        .set_json(&body)
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 201);

    let body: ClientRegistrationResponse = test::read_body_json(resp).await;
    assert!(
        body.client_secret.is_none(),
        "public clients MUST NOT get a secret"
    );
    assert!(
        body.client_secret_expires_at.is_none(),
        "public clients MUST NOT get client_secret_expires_at"
    );
    assert_eq!(body.token_endpoint_auth_method, "none");
}

/// RFC 7591: registration rejects invalid redirect_uris.
///
/// @rfc 7591
/// @section 2
/// @requirement Registration must reject invalid `redirect_uris` (malformed/non-absolute/etc).
/// @level MUST
/// @url https://datatracker.ietf.org/doc/html/rfc7591#section-2
#[actix_web::test]
async fn rfc7591_rejects_invalid_redirect_uris() {
    const ISSUER: &str = "https://auth.example.com";

    let (token_pool, client_actor, auth_actor, jwt_secret, metrics, oidc_config) =
        setup_phase2_context(vec![], ISSUER).await;
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
            .service(web::scope("/connect").route(
                "/register",
                web::post().to(oauth2_actix::handlers::client::dynamic_register),
            )),
    )
    .await;

    // No redirect_uris at all
    let body = serde_json::json!({
        "client_name": "Bad App",
        "redirect_uris": []
    });
    let req = test::TestRequest::post()
        .uri("/connect/register")
        .set_json(&body)
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 400);

    // Fragment in redirect_uri
    let body = serde_json::json!({
        "client_name": "Fragment App",
        "redirect_uris": ["https://app.example/cb#frag"]
    });
    let req = test::TestRequest::post()
        .uri("/connect/register")
        .set_json(&body)
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 400);
}

// ===================================================================
// RFC 7591 §3.2 / RFC 7592: Client Configuration Endpoint
// ===================================================================

/// Helper macro: register a client via POST /connect/register and return
/// the parsed `ClientRegistrationResponse`.
macro_rules! register_test_client {
    ($app:expr) => {{
        let body = serde_json::json!({
            "client_name": "Config Test Client",
            "redirect_uris": ["https://app.example/callback"],
            "grant_types": ["authorization_code", "refresh_token"],
            "scope": "openid profile"
        });
        let req = test::TestRequest::post()
            .uri("/connect/register")
            .set_json(&body)
            .to_request();
        let resp = test::call_service(&$app, req).await;
        assert_eq!(resp.status(), 201);
        let reg: ClientRegistrationResponse = test::read_body_json(resp).await;
        reg
    }};
}

/// RFC 7592 §2.1: GET /connect/register/{client_id} with a valid
/// registration_access_token returns the client configuration.
///
/// @rfc 7592
/// @section 2.1
/// @requirement GET on the client configuration endpoint must return the client config when authenticated with the registration access token.
/// @level MUST
/// @url https://datatracker.ietf.org/doc/html/rfc7592#section-2.1
#[actix_web::test]
async fn rfc7592_read_client_configuration() {
    const ISSUER: &str = "https://auth.example.com";

    let (token_pool, client_actor, auth_actor, jwt_secret, metrics, oidc_config) =
        setup_phase2_context(vec![], ISSUER).await;
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
            .service(
                web::scope("/connect")
                    .route(
                        "/register",
                        web::post().to(oauth2_actix::handlers::client::dynamic_register),
                    )
                    .route(
                        "/register/{client_id}",
                        web::get().to(oauth2_actix::handlers::client::read_client_configuration),
                    ),
            ),
    )
    .await;

    let registered = register_test_client!(app);

    // GET with valid token → 200
    let req = test::TestRequest::get()
        .uri(&format!("/connect/register/{}", registered.client_id))
        .insert_header((
            "Authorization",
            format!("Bearer {}", registered.registration_access_token),
        ))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 200);

    let config: ClientRegistrationResponse = test::read_body_json(resp).await;
    assert_eq!(config.client_id, registered.client_id);
    assert_eq!(config.client_name, "Config Test Client");

    // GET with invalid token → 401
    let req = test::TestRequest::get()
        .uri(&format!("/connect/register/{}", registered.client_id))
        .insert_header(("Authorization", "Bearer wrong_token"))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 401);

    // GET without token → 401
    let req = test::TestRequest::get()
        .uri(&format!("/connect/register/{}", registered.client_id))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 401);
}

/// RFC 7592 §2.2: PUT /connect/register/{client_id} updates the client.
///
/// @rfc 7592
/// @section 2.2
/// @requirement PUT on the client configuration endpoint must update the client metadata.
/// @level MUST
/// @url https://datatracker.ietf.org/doc/html/rfc7592#section-2.2
#[actix_web::test]
async fn rfc7592_update_client_configuration() {
    const ISSUER: &str = "https://auth.example.com";

    let (token_pool, client_actor, auth_actor, jwt_secret, metrics, oidc_config) =
        setup_phase2_context(vec![], ISSUER).await;
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
            .service(
                web::scope("/connect")
                    .route(
                        "/register",
                        web::post().to(oauth2_actix::handlers::client::dynamic_register),
                    )
                    .route(
                        "/register/{client_id}",
                        web::put().to(oauth2_actix::handlers::client::update_client_configuration),
                    ),
            ),
    )
    .await;

    let registered = register_test_client!(app);

    // Update with a new name and redirect URIs
    let update_body = serde_json::json!({
        "client_name": "Updated App Name",
        "redirect_uris": ["https://app.example/new-callback"],
        "grant_types": ["authorization_code"],
        "scope": "openid"
    });

    let req = test::TestRequest::put()
        .uri(&format!("/connect/register/{}", registered.client_id))
        .insert_header((
            "Authorization",
            format!("Bearer {}", registered.registration_access_token),
        ))
        .set_json(&update_body)
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 200);

    let updated: ClientRegistrationResponse = test::read_body_json(resp).await;
    assert_eq!(updated.client_name, "Updated App Name");
    assert_eq!(
        updated.redirect_uris,
        vec!["https://app.example/new-callback"]
    );
    assert_eq!(updated.grant_types, vec!["authorization_code"]);
    assert_eq!(updated.scope, "openid");
}

/// RFC 7592 §2.3: DELETE /connect/register/{client_id} deletes the client.
///
/// @rfc 7592
/// @section 2.3
/// @requirement DELETE on the client configuration endpoint must remove the client.
/// @level MUST
/// @url https://datatracker.ietf.org/doc/html/rfc7592#section-2.3
#[actix_web::test]
async fn rfc7592_delete_client() {
    const ISSUER: &str = "https://auth.example.com";

    let (token_pool, client_actor, auth_actor, jwt_secret, metrics, oidc_config) =
        setup_phase2_context(vec![], ISSUER).await;
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
            .service(
                web::scope("/connect")
                    .route(
                        "/register",
                        web::post().to(oauth2_actix::handlers::client::dynamic_register),
                    )
                    .route(
                        "/register/{client_id}",
                        web::get().to(oauth2_actix::handlers::client::read_client_configuration),
                    )
                    .route(
                        "/register/{client_id}",
                        web::delete()
                            .to(oauth2_actix::handlers::client::delete_client_configuration),
                    ),
            ),
    )
    .await;

    let registered = register_test_client!(app);

    // DELETE with valid token → 204
    let req = test::TestRequest::delete()
        .uri(&format!("/connect/register/{}", registered.client_id))
        .insert_header((
            "Authorization",
            format!("Bearer {}", registered.registration_access_token),
        ))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 204, "RFC 7592 §2.3: DELETE MUST return 204");

    // Verify client is gone — GET returns 401 (client not found)
    let req = test::TestRequest::get()
        .uri(&format!("/connect/register/{}", registered.client_id))
        .insert_header((
            "Authorization",
            format!("Bearer {}", registered.registration_access_token),
        ))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 401, "Client should be deleted");
}

// ===================================================================
// RFC 7523: JWT Client Authentication
// ===================================================================

/// RFC 7523 §2.2 — client_secret_jwt: token endpoint authenticates client
/// using an HS256 JWT signed with the client's secret.
///
/// @rfc 7523
/// @section 2.2
/// @requirement Token endpoint must accept `client_secret_jwt` (HS256 JWT signed with client_secret).
/// @level MUST
/// @url https://datatracker.ietf.org/doc/html/rfc7523#section-2.2
#[actix_web::test]
async fn rfc7523_client_secret_jwt_authentication() {
    const ISSUER: &str = "https://auth.example.com";

    let mut client = Client::new(
        "client_hmac_jwt".to_string(),
        "super_secret_for_jwt_test_1234".to_string(),
        vec!["https://app.example/cb".to_string()],
        vec!["client_credentials".to_string()],
        "read".to_string(),
        "JWT HMAC Client".to_string(),
    );
    client.token_endpoint_auth_method = "client_secret_jwt".to_string();

    let (token_pool, client_actor, auth_actor, jwt_secret, metrics, oidc_config) =
        setup_phase2_context(vec![client.clone()], ISSUER).await;
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

    // Build a JWT assertion signed with the client secret (HS256).
    let now = chrono::Utc::now().timestamp();
    let claims = serde_json::json!({
        "iss": "client_hmac_jwt",
        "sub": "client_hmac_jwt",
        "aud": format!("{}/oauth/token", ISSUER),
        "exp": now + 300,
        "iat": now,
        "jti": uuid::Uuid::new_v4().to_string()
    });

    let header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256);
    let key = jsonwebtoken::EncodingKey::from_secret(client.client_secret.as_bytes());
    let assertion = jsonwebtoken::encode(&header, &claims, &key).expect("encode JWT");

    let form_body = format!(
        "grant_type=client_credentials&client_id=client_hmac_jwt\
         &client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer\
         &client_assertion={assertion}&scope=read"
    );

    let req = test::TestRequest::post()
        .uri("/oauth/token")
        .insert_header(("Content-Type", "application/x-www-form-urlencoded"))
        .set_payload(form_body)
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(
        resp.status(),
        200,
        "client_secret_jwt should authenticate successfully"
    );
}

/// RFC 7523: client_secret_jwt with wrong secret must fail.
///
/// @rfc 7523
/// @section 2.2
/// @requirement A client_secret_jwt assertion signed with the wrong secret must be rejected.
/// @level MUST
/// @url https://datatracker.ietf.org/doc/html/rfc7523#section-2.2
#[actix_web::test]
async fn rfc7523_client_secret_jwt_wrong_secret_fails() {
    const ISSUER: &str = "https://auth.example.com";

    let mut client = Client::new(
        "client_hmac_bad".to_string(),
        "correct_secret_for_hmac_test_12".to_string(),
        vec!["https://app.example/cb".to_string()],
        vec!["client_credentials".to_string()],
        "read".to_string(),
        "Bad JWT Client".to_string(),
    );
    client.token_endpoint_auth_method = "client_secret_jwt".to_string();

    let (token_pool, client_actor, auth_actor, jwt_secret, metrics, oidc_config) =
        setup_phase2_context(vec![client], ISSUER).await;
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

    // Sign with a WRONG secret.
    let now = chrono::Utc::now().timestamp();
    let claims = serde_json::json!({
        "iss": "client_hmac_bad",
        "sub": "client_hmac_bad",
        "aud": format!("{}/oauth/token", ISSUER),
        "exp": now + 300,
        "iat": now,
        "jti": uuid::Uuid::new_v4().to_string()
    });
    let key = jsonwebtoken::EncodingKey::from_secret(b"this_is_the_wrong_secret_12345!");
    let assertion = jsonwebtoken::encode(
        &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256),
        &claims,
        &key,
    )
    .expect("encode JWT");

    let form_body = format!(
        "grant_type=client_credentials&client_id=client_hmac_bad\
         &client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer\
         &client_assertion={assertion}&scope=read"
    );

    let req = test::TestRequest::post()
        .uri("/oauth/token")
        .insert_header(("Content-Type", "application/x-www-form-urlencoded"))
        .set_payload(form_body)
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 401, "Wrong secret JWT must fail");
}

/// RFC 7523 §2.2 — private_key_jwt: token endpoint authenticates client
/// using an RS256 JWT signed with the client's private key, verified against
/// the registered JWKS.
///
/// @rfc 7523
/// @section 2.2
/// @requirement Token endpoint must accept `private_key_jwt` (RS256 JWT verified against registered JWKS).
/// @level MUST
/// @url https://datatracker.ietf.org/doc/html/rfc7523#section-2.2
#[actix_web::test]
async fn rfc7523_private_key_jwt_authentication() {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use rsa::pkcs8::EncodePrivateKey;
    use rsa::traits::PublicKeyParts;

    const ISSUER: &str = "https://auth.example.com";

    // Generate an RSA key pair for the client.
    let private_key =
        rsa::RsaPrivateKey::new(&mut rand_core::OsRng, 2048).expect("generate RSA key");
    let public_key = private_key.to_public_key();
    let n = URL_SAFE_NO_PAD.encode(public_key.n().to_bytes_be());
    let e = URL_SAFE_NO_PAD.encode(public_key.e().to_bytes_be());

    let jwks = serde_json::json!({
        "keys": [{
            "kty": "RSA",
            "kid": "test-kid",
            "use": "sig",
            "alg": "RS256",
            "n": n,
            "e": e,
        }]
    });

    let mut client = Client::new(
        "client_rsa_jwt".to_string(),
        "placeholder_secret_not_used!!!".to_string(),
        vec!["https://app.example/cb".to_string()],
        vec!["client_credentials".to_string()],
        "read".to_string(),
        "RSA JWT Client".to_string(),
    );
    client.token_endpoint_auth_method = "private_key_jwt".to_string();
    client.jwks = serde_json::to_string(&jwks).unwrap();

    let (token_pool, client_actor, auth_actor, jwt_secret, metrics, oidc_config) =
        setup_phase2_context(vec![client], ISSUER).await;
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

    // Build a JWT assertion signed with the client's RSA private key.
    let now = chrono::Utc::now().timestamp();
    let claims = serde_json::json!({
        "iss": "client_rsa_jwt",
        "sub": "client_rsa_jwt",
        "aud": format!("{}/oauth/token", ISSUER),
        "exp": now + 300,
        "iat": now,
        "jti": uuid::Uuid::new_v4().to_string()
    });

    let pem = private_key
        .to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)
        .expect("encode PEM");
    let encoding_key =
        jsonwebtoken::EncodingKey::from_rsa_pem(pem.as_bytes()).expect("encoding key from PEM");
    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
    header.kid = Some("test-kid".to_string());
    let assertion = jsonwebtoken::encode(&header, &claims, &encoding_key).expect("encode JWT");

    let form_body = format!(
        "grant_type=client_credentials&client_id=client_rsa_jwt\
         &client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer\
         &client_assertion={assertion}&scope=read"
    );

    let req = test::TestRequest::post()
        .uri("/oauth/token")
        .insert_header(("Content-Type", "application/x-www-form-urlencoded"))
        .set_payload(form_body)
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(
        resp.status(),
        200,
        "private_key_jwt should authenticate successfully"
    );
}

// ===================================================================
// RFC 8414: Discovery Document updates
// ===================================================================

/// RFC 8414 §2: the discovery document MUST reflect the new auth methods
/// and registration endpoint.
///
/// @rfc 8414
/// @section 2
/// @requirement Discovery doc must reflect supported client auth methods (incl. client_secret_jwt, private_key_jwt) and registration endpoint.
/// @level MUST
/// @url https://datatracker.ietf.org/doc/html/rfc8414#section-2
#[actix_web::test]
async fn rfc8414_discovery_reflects_phase2() {
    const ISSUER: &str = "https://auth.example.com";

    let (token_pool, client_actor, auth_actor, jwt_secret, metrics, oidc_config) =
        setup_phase2_context(vec![], ISSUER).await;
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
            .service(web::scope("/.well-known").route(
                "/openid-configuration",
                web::get().to(oauth2_actix::handlers::wellknown::openid_configuration),
            )),
    )
    .await;

    let req = test::TestRequest::get()
        .uri("/.well-known/openid-configuration")
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 200);

    let doc: serde_json::Value = test::read_body_json(resp).await;

    // Registration endpoint must point to /connect/register
    assert_eq!(
        doc["registration_endpoint"],
        format!("{}/connect/register", ISSUER)
    );

    // token_endpoint_auth_methods_supported must include JWT methods
    let auth_methods = doc["token_endpoint_auth_methods_supported"]
        .as_array()
        .expect("auth methods array");
    let methods: Vec<&str> = auth_methods.iter().map(|v| v.as_str().unwrap()).collect();
    assert!(
        methods.contains(&"client_secret_jwt"),
        "Must include client_secret_jwt"
    );
    assert!(
        methods.contains(&"private_key_jwt"),
        "Must include private_key_jwt"
    );
    assert!(methods.contains(&"none"), "Must include none");
    assert!(
        methods.contains(&"client_secret_basic"),
        "Must include client_secret_basic"
    );
    assert!(
        methods.contains(&"client_secret_post"),
        "Must include client_secret_post"
    );
}

// ===================================================================
// OIDC metadata fields (2.8)
// ===================================================================

/// OIDC Core: client registration should accept and preserve full OIDC
/// metadata fields (contacts, logo_uri, client_uri, policy_uri, tos_uri,
/// response_types).
///
/// @rfc oidc-registration-1.0
/// @section 2
/// @requirement Registration must accept and round-trip OIDC client metadata (contacts, *_uri fields, response_types).
/// @level MUST
/// @url https://openid.net/specs/openid-connect-registration-1_0.html#ClientMetadata
#[actix_web::test]
async fn oidc_metadata_preserved_in_registration() {
    const ISSUER: &str = "https://auth.example.com";

    let (token_pool, client_actor, auth_actor, jwt_secret, metrics, oidc_config) =
        setup_phase2_context(vec![], ISSUER).await;
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
            .service(
                web::scope("/connect")
                    .route(
                        "/register",
                        web::post().to(oauth2_actix::handlers::client::dynamic_register),
                    )
                    .route(
                        "/register/{client_id}",
                        web::get().to(oauth2_actix::handlers::client::read_client_configuration),
                    ),
            ),
    )
    .await;

    let body = serde_json::json!({
        "client_name": "Full Metadata App",
        "redirect_uris": ["https://app.example/callback"],
        "grant_types": ["authorization_code"],
        "scope": "openid profile email",
        "response_types": ["code"],
        "contacts": ["admin@example.com", "dev@example.com"],
        "logo_uri": "https://app.example/logo.png",
        "client_uri": "https://app.example",
        "policy_uri": "https://app.example/privacy",
        "tos_uri": "https://app.example/tos"
    });

    let req = test::TestRequest::post()
        .uri("/connect/register")
        .set_json(&body)
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 201);
    let reg: ClientRegistrationResponse = test::read_body_json(resp).await;

    // Read it back via the configuration endpoint
    let req = test::TestRequest::get()
        .uri(&format!("/connect/register/{}", reg.client_id))
        .insert_header((
            "Authorization",
            format!("Bearer {}", reg.registration_access_token),
        ))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 200);
    let config: ClientRegistrationResponse = test::read_body_json(resp).await;

    assert_eq!(config.response_types, vec!["code"]);
    assert_eq!(
        config.contacts,
        vec!["admin@example.com", "dev@example.com"]
    );
    assert_eq!(
        config.logo_uri,
        Some("https://app.example/logo.png".to_string())
    );
    assert_eq!(config.client_uri, Some("https://app.example".to_string()));
    assert_eq!(
        config.policy_uri,
        Some("https://app.example/privacy".to_string())
    );
    assert_eq!(config.tos_uri, Some("https://app.example/tos".to_string()));
}

/// RFC 7591: private_key_jwt registration requires jwks or jwks_uri.
///
/// @rfc 7591
/// @section 2
/// @requirement Registering with `token_endpoint_auth_method=private_key_jwt` must require `jwks` or `jwks_uri`.
/// @level MUST
/// @url https://datatracker.ietf.org/doc/html/rfc7591#section-2
#[actix_web::test]
async fn rfc7591_private_key_jwt_requires_jwks() {
    const ISSUER: &str = "https://auth.example.com";

    let (token_pool, client_actor, auth_actor, jwt_secret, metrics, oidc_config) =
        setup_phase2_context(vec![], ISSUER).await;
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
            .service(web::scope("/connect").route(
                "/register",
                web::post().to(oauth2_actix::handlers::client::dynamic_register),
            )),
    )
    .await;

    // private_key_jwt without jwks → error
    let body = serde_json::json!({
        "client_name": "Missing JWKS",
        "redirect_uris": ["https://app.example/cb"],
        "grant_types": ["authorization_code"],
        "token_endpoint_auth_method": "private_key_jwt"
    });
    let req = test::TestRequest::post()
        .uri("/connect/register")
        .set_json(&body)
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 400);
    let err: OAuth2Error = test::read_body_json(resp).await;
    assert!(
        err.error_description.unwrap_or_default().contains("jwks"),
        "Error should mention jwks requirement"
    );

    // With jwks → should succeed
    let body = serde_json::json!({
        "client_name": "Has JWKS",
        "redirect_uris": ["https://app.example/cb"],
        "grant_types": ["authorization_code"],
        "token_endpoint_auth_method": "private_key_jwt",
        "jwks": {"keys": [{"kty": "RSA", "n": "test", "e": "AQAB"}]}
    });
    let req = test::TestRequest::post()
        .uri("/connect/register")
        .set_json(&body)
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 201);
}

/// RFC 7591 §2: jwks and jwks_uri MUST NOT both be present.
///
/// @rfc 7591
/// @section 2
/// @requirement Registration request must not contain both `jwks` and `jwks_uri`.
/// @level MUST
/// @url https://datatracker.ietf.org/doc/html/rfc7591#section-2
#[actix_web::test]
async fn rfc7591_jwks_and_jwks_uri_mutually_exclusive() {
    const ISSUER: &str = "https://auth.example.com";

    let (token_pool, client_actor, auth_actor, jwt_secret, metrics, oidc_config) =
        setup_phase2_context(vec![], ISSUER).await;
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
            .service(web::scope("/connect").route(
                "/register",
                web::post().to(oauth2_actix::handlers::client::dynamic_register),
            )),
    )
    .await;

    let body = serde_json::json!({
        "client_name": "Both JWKS",
        "redirect_uris": ["https://app.example/cb"],
        "grant_types": ["authorization_code"],
        "token_endpoint_auth_method": "private_key_jwt",
        "jwks": {"keys": [{"kty": "RSA", "n": "test", "e": "AQAB"}]},
        "jwks_uri": "https://app.example/.well-known/jwks.json"
    });
    let req = test::TestRequest::post()
        .uri("/connect/register")
        .set_json(&body)
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 400);
    let err: OAuth2Error = test::read_body_json(resp).await;
    assert!(
        err.error_description
            .unwrap_or_default()
            .contains("mutually exclusive"),
        "Error should mention mutual exclusivity"
    );
}
