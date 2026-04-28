//! RFC 8628 — OAuth 2.0 Device Authorization Grant
//!
//! Compliance tests that map directly to RFC 8628 sections.
//! See docs/compliance/RFC_COMPLIANCE.md for the full matrix.

use actix::{Actor, Addr};
use actix_session::{storage::CookieSessionStore, Session, SessionMiddleware};
use actix_web::{cookie::Key, test, web, App, HttpResponse};

use oauth2_actix::actors::TokenActorPool;
use oauth2_actix::handlers::wellknown::OidcConfig;
use oauth2_core::{Client, OAuth2Error, TokenResponse, User};
use oauth2_observability::Metrics;
use oauth2_ports::DynStorage;

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

async fn test_set_session(session: Session) -> HttpResponse {
    session.insert("user_id", "user_123").unwrap();
    session.insert("authenticated", true).unwrap();
    HttpResponse::Ok().finish()
}

fn extract_session_cookie(
    resp: &actix_web::dev::ServiceResponse<impl actix_web::body::MessageBody>,
) -> String {
    resp.response()
        .headers()
        .get(actix_web::http::header::SET_COOKIE)
        .and_then(|h| h.to_str().ok())
        .expect("session cookie should be set")
        .split(';')
        .next()
        .unwrap()
        .to_string()
}

async fn setup_context(
    client: Client,
) -> (
    TokenActorPool,
    Addr<oauth2_actix::actors::ClientActor>,
    Addr<oauth2_actix::actors::AuthActor>,
    DynStorage,
    String,
    Metrics,
    OidcConfig,
) {
    // Device flow requires shared cross-request storage; use a file-based DB.
    let db_path = format!("/tmp/oauth2_rfc8628_{}.db", uuid::Uuid::new_v4());
    let storage = oauth2_storage_factory::create_storage(&format!("sqlite:{db_path}"))
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
        storage,
        jwt_secret,
        metrics,
        oidc_config,
    )
}

fn device_client() -> Client {
    Client::new(
        "device_client".to_string(),
        "device_secret".to_string(),
        vec!["https://unused.example/cb".to_string()],
        vec![
            "urn:ietf:params:oauth:grant-type:device_code".to_string(),
            "refresh_token".to_string(),
        ],
        "read".to_string(),
        "test".to_string(),
    )
}

/// Build a test app with device flow endpoints.
macro_rules! device_app {
    ($token_actor:expr, $client_actor:expr, $auth_actor:expr,
     $storage:expr, $jwt_secret:expr, $metrics:expr, $oidc_config:expr) => {
        test::init_service(
            App::new()
                .wrap(SessionMiddleware::new(
                    CookieSessionStore::default(),
                    Key::generate(),
                ))
                .route("/test/login", web::get().to(test_set_session))
                .app_data(web::Data::new($token_actor))
                .app_data(web::Data::new($client_actor))
                .app_data(web::Data::new($auth_actor))
                .app_data(web::Data::new($storage))
                .app_data(web::Data::new($jwt_secret))
                .app_data(web::Data::new($metrics))
                .app_data(web::Data::new($oidc_config))
                .app_data(web::Data::new(false))
                .service(
                    web::scope("/oauth")
                        .route(
                            "/device_authorization",
                            web::post().to(oauth2_actix::handlers::device::device_authorization),
                        )
                        .route(
                            "/device/verify",
                            web::post().to(oauth2_actix::handlers::device::verify_submit),
                        )
                        .route(
                            "/token",
                            web::post().to(oauth2_actix::handlers::oauth::token),
                        ),
                ),
        )
        .await
    };
}

// ===========================================================================
// RFC 8628 §3.1 — Device Authorization Request
// ===========================================================================

/// RFC 8628 §3.1: A valid device authorization request MUST return a JSON
/// body containing `device_code`, `user_code`, `verification_uri`, and
/// `expires_in`.
///
/// @rfc 8628
/// @section 3.1
/// @requirement Device authorization response must include device_code, user_code, verification_uri, expires_in.
/// @level MUST
/// @url https://datatracker.ietf.org/doc/html/rfc8628#section-3.1
#[actix_web::test]
async fn rfc8628_s3_1_response_contains_required_fields() {
    let (token_actor, client_actor, auth_actor, storage, jwt_secret, metrics, oidc_config) =
        setup_context(device_client()).await;
    let app = device_app!(
        token_actor,
        client_actor,
        auth_actor,
        storage,
        jwt_secret,
        metrics,
        oidc_config
    );

    let resp = test::call_service(
        &app,
        test::TestRequest::post()
            .uri("/oauth/device_authorization")
            .set_form([
                ("client_id", "device_client"),
                ("client_secret", "device_secret"),
                ("scope", "read"),
            ])
            .to_request(),
    )
    .await;

    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = test::read_body_json(resp).await;

    assert!(
        body["device_code"]
            .as_str()
            .map(|s| !s.is_empty())
            .unwrap_or(false),
        "device_code must be present and non-empty"
    );
    assert!(
        body["user_code"]
            .as_str()
            .map(|s| !s.is_empty())
            .unwrap_or(false),
        "user_code must be present and non-empty"
    );
    assert!(
        body["verification_uri"]
            .as_str()
            .map(|s| !s.is_empty())
            .unwrap_or(false),
        "verification_uri must be present and non-empty"
    );
    assert!(
        body["expires_in"].is_number(),
        "expires_in must be a numeric value"
    );
}

/// RFC 8628 §3.1: A missing or unknown `client_id` MUST return an error.
///
/// @rfc 8628
/// @section 3.1
/// @requirement Device authorization endpoint must reject missing or unknown client_id.
/// @level MUST
/// @url https://datatracker.ietf.org/doc/html/rfc8628#section-3.1
#[actix_web::test]
async fn rfc8628_s3_1_missing_client_id_returns_error() {
    let (token_actor, client_actor, auth_actor, storage, jwt_secret, metrics, oidc_config) =
        setup_context(device_client()).await;
    let app = device_app!(
        token_actor,
        client_actor,
        auth_actor,
        storage,
        jwt_secret,
        metrics,
        oidc_config
    );

    let resp = test::call_service(
        &app,
        test::TestRequest::post()
            .uri("/oauth/device_authorization")
            .set_form([("client_secret", "device_secret"), ("scope", "read")])
            .to_request(),
    )
    .await;

    assert!(
        resp.status().is_client_error(),
        "missing client_id must be rejected, got {}",
        resp.status()
    );
}

/// RFC 8628 §3.1: A client that is not authorized to use the device_code
/// grant type MUST receive an `unauthorized_client` error.
///
/// @rfc 8628
/// @section 3.1
/// @requirement A client without device_code grant must receive `unauthorized_client`.
/// @level MUST
/// @url https://datatracker.ietf.org/doc/html/rfc8628#section-3.1
#[actix_web::test]
async fn rfc8628_s3_1_unauthorized_client_is_rejected() {
    let non_device_client = Client::new(
        "cc_only_client".to_string(),
        "cc_only_secret".to_string(),
        vec!["https://unused.example/cb".to_string()],
        vec!["client_credentials".to_string()],
        "read".to_string(),
        "test".to_string(),
    );
    let (token_actor, client_actor, auth_actor, storage, jwt_secret, metrics, oidc_config) =
        setup_context(non_device_client).await;
    let app = device_app!(
        token_actor,
        client_actor,
        auth_actor,
        storage,
        jwt_secret,
        metrics,
        oidc_config
    );

    let resp = test::call_service(
        &app,
        test::TestRequest::post()
            .uri("/oauth/device_authorization")
            .set_form([
                ("client_id", "cc_only_client"),
                ("client_secret", "cc_only_secret"),
                ("scope", "read"),
            ])
            .to_request(),
    )
    .await;

    assert!(
        resp.status().is_client_error(),
        "client not authorized for device_code grant must be rejected"
    );
    let body: OAuth2Error = test::read_body_json(resp).await;
    assert_eq!(body.error, "unauthorized_client");
}

// ===========================================================================
// RFC 8628 §3.3 — User Interaction
// ===========================================================================

/// RFC 8628 §3.3: A user who approves a valid `user_code` MUST receive a
/// successful (2xx) response from the verification endpoint.
///
/// @rfc 8628
/// @section 3.3
/// @requirement Approving a valid user_code at the verification endpoint must return a 2xx response.
/// @level MUST
/// @url https://datatracker.ietf.org/doc/html/rfc8628#section-3.3
#[actix_web::test]
async fn rfc8628_s3_3_approve_returns_success() {
    let (token_actor, client_actor, auth_actor, storage, jwt_secret, metrics, oidc_config) =
        setup_context(device_client()).await;
    let app = device_app!(
        token_actor,
        client_actor,
        auth_actor,
        storage,
        jwt_secret,
        metrics,
        oidc_config
    );

    // Step 1: initiate device flow
    let init_resp = test::call_service(
        &app,
        test::TestRequest::post()
            .uri("/oauth/device_authorization")
            .set_form([
                ("client_id", "device_client"),
                ("client_secret", "device_secret"),
                ("scope", "read"),
            ])
            .to_request(),
    )
    .await;
    assert_eq!(init_resp.status(), 200);
    let init_body: serde_json::Value = test::read_body_json(init_resp).await;
    let user_code = init_body["user_code"]
        .as_str()
        .expect("user_code")
        .to_string();

    // Step 2: login to get session
    let login_resp = test::call_service(
        &app,
        test::TestRequest::get().uri("/test/login").to_request(),
    )
    .await;
    let session_cookie = extract_session_cookie(&login_resp);

    // Step 3: approve
    let approve_resp = test::call_service(
        &app,
        test::TestRequest::post()
            .uri("/oauth/device/verify")
            .insert_header(("Cookie", session_cookie.as_str()))
            .set_form([("user_code", user_code.as_str()), ("action", "approve")])
            .to_request(),
    )
    .await;
    assert!(
        approve_resp.status().is_success(),
        "approve must return 2xx, got {}",
        approve_resp.status()
    );
}

/// RFC 8628 §3.3: A user who denies a valid `user_code` MUST receive a
/// successful (2xx) response from the verification endpoint.
///
/// @rfc 8628
/// @section 3.3
/// @requirement Denying a valid user_code at the verification endpoint must return a 2xx response.
/// @level MUST
/// @url https://datatracker.ietf.org/doc/html/rfc8628#section-3.3
#[actix_web::test]
async fn rfc8628_s3_3_deny_returns_success() {
    let (token_actor, client_actor, auth_actor, storage, jwt_secret, metrics, oidc_config) =
        setup_context(device_client()).await;
    let app = device_app!(
        token_actor,
        client_actor,
        auth_actor,
        storage,
        jwt_secret,
        metrics,
        oidc_config
    );

    let init_resp = test::call_service(
        &app,
        test::TestRequest::post()
            .uri("/oauth/device_authorization")
            .set_form([
                ("client_id", "device_client"),
                ("client_secret", "device_secret"),
                ("scope", "read"),
            ])
            .to_request(),
    )
    .await;
    let init_body: serde_json::Value = test::read_body_json(init_resp).await;
    let user_code = init_body["user_code"]
        .as_str()
        .expect("user_code")
        .to_string();

    let login_resp = test::call_service(
        &app,
        test::TestRequest::get().uri("/test/login").to_request(),
    )
    .await;
    let session_cookie = extract_session_cookie(&login_resp);

    let deny_resp = test::call_service(
        &app,
        test::TestRequest::post()
            .uri("/oauth/device/verify")
            .insert_header(("Cookie", session_cookie.as_str()))
            .set_form([("user_code", user_code.as_str()), ("action", "deny")])
            .to_request(),
    )
    .await;
    assert!(
        deny_resp.status().is_success(),
        "deny must return 2xx, got {}",
        deny_resp.status()
    );
}

// ===========================================================================
// RFC 8628 §3.4 — Device Access Token Request
// ===========================================================================

/// RFC 8628 §3.4: Polling before the user approves MUST return a 400 with
/// `error=authorization_pending`.
///
/// @rfc 8628
/// @section 3.4
/// @requirement Token polling before approval must return 400 with error=authorization_pending.
/// @level MUST
/// @url https://datatracker.ietf.org/doc/html/rfc8628#section-3.4
#[actix_web::test]
async fn rfc8628_s3_4_pending_returns_authorization_pending() {
    let (token_actor, client_actor, auth_actor, storage, jwt_secret, metrics, oidc_config) =
        setup_context(device_client()).await;
    let app = device_app!(
        token_actor,
        client_actor,
        auth_actor,
        storage,
        jwt_secret,
        metrics,
        oidc_config
    );

    let init_resp = test::call_service(
        &app,
        test::TestRequest::post()
            .uri("/oauth/device_authorization")
            .set_form([
                ("client_id", "device_client"),
                ("client_secret", "device_secret"),
                ("scope", "read"),
            ])
            .to_request(),
    )
    .await;
    let init_body: serde_json::Value = test::read_body_json(init_resp).await;
    let device_code = init_body["device_code"]
        .as_str()
        .expect("device_code")
        .to_string();

    let poll_resp = test::call_service(
        &app,
        test::TestRequest::post()
            .uri("/oauth/token")
            .set_form([
                ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
                ("client_id", "device_client"),
                ("client_secret", "device_secret"),
                ("device_code", device_code.as_str()),
            ])
            .to_request(),
    )
    .await;

    assert_eq!(poll_resp.status(), 400);
    let body: OAuth2Error = test::read_body_json(poll_resp).await;
    assert_eq!(
        body.error, "authorization_pending",
        "error must be `authorization_pending` while user has not yet acted"
    );
}

/// RFC 8628 §3.4: After the user approves, polling MUST return 200 with a
/// valid access token.
///
/// @rfc 8628
/// @section 3.4
/// @requirement After user approval, token polling must return 200 with an access token.
/// @level MUST
/// @url https://datatracker.ietf.org/doc/html/rfc8628#section-3.4
#[actix_web::test]
async fn rfc8628_s3_4_approved_returns_access_token() {
    let (token_actor, client_actor, auth_actor, storage, jwt_secret, metrics, oidc_config) =
        setup_context(device_client()).await;
    let app = device_app!(
        token_actor,
        client_actor,
        auth_actor,
        storage,
        jwt_secret,
        metrics,
        oidc_config
    );

    // Initiate
    let init_resp = test::call_service(
        &app,
        test::TestRequest::post()
            .uri("/oauth/device_authorization")
            .set_form([
                ("client_id", "device_client"),
                ("client_secret", "device_secret"),
                ("scope", "read"),
            ])
            .to_request(),
    )
    .await;
    let init_body: serde_json::Value = test::read_body_json(init_resp).await;
    let device_code = init_body["device_code"]
        .as_str()
        .expect("device_code")
        .to_string();
    let user_code = init_body["user_code"]
        .as_str()
        .expect("user_code")
        .to_string();

    // Approve
    let login_resp = test::call_service(
        &app,
        test::TestRequest::get().uri("/test/login").to_request(),
    )
    .await;
    let session_cookie = extract_session_cookie(&login_resp);
    test::call_service(
        &app,
        test::TestRequest::post()
            .uri("/oauth/device/verify")
            .insert_header(("Cookie", session_cookie.as_str()))
            .set_form([("user_code", user_code.as_str()), ("action", "approve")])
            .to_request(),
    )
    .await;

    // Poll
    let poll_resp = test::call_service(
        &app,
        test::TestRequest::post()
            .uri("/oauth/token")
            .set_form([
                ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
                ("client_id", "device_client"),
                ("client_secret", "device_secret"),
                ("device_code", device_code.as_str()),
            ])
            .to_request(),
    )
    .await;

    assert_eq!(poll_resp.status(), 200);
    let token: TokenResponse = test::read_body_json(poll_resp).await;
    assert!(
        !token.access_token.is_empty(),
        "access_token must be present after approval"
    );
}

/// RFC 8628 §3.4: An unknown or invalid `device_code` MUST return a 4xx
/// error (not a 200 or 5xx).
///
/// @rfc 8628
/// @section 3.4
/// @requirement Unknown or invalid device_code at the token endpoint must return a 4xx error.
/// @level MUST
/// @url https://datatracker.ietf.org/doc/html/rfc8628#section-3.4
#[actix_web::test]
async fn rfc8628_s3_4_unknown_device_code_returns_error() {
    let (token_actor, client_actor, auth_actor, storage, jwt_secret, metrics, oidc_config) =
        setup_context(device_client()).await;
    let app = device_app!(
        token_actor,
        client_actor,
        auth_actor,
        storage,
        jwt_secret,
        metrics,
        oidc_config
    );

    let resp = test::call_service(
        &app,
        test::TestRequest::post()
            .uri("/oauth/token")
            .set_form([
                ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
                ("client_id", "device_client"),
                ("client_secret", "device_secret"),
                ("device_code", "this_device_code_does_not_exist"),
            ])
            .to_request(),
    )
    .await;

    assert!(
        resp.status().is_client_error(),
        "unknown device_code must return 4xx, got {}",
        resp.status()
    );
}

/// RFC 8628 §3.1 + RFC 6749 §2.3.1: confidential clients may authenticate at
/// `/device_authorization` using `client_secret_basic` — the handler must
/// accept credentials from the `Authorization` header when the form body
/// omits `client_id`/`client_secret`.
///
/// @rfc 8628
/// @section 3.1
/// @requirement Device authorization endpoint must accept client_secret_basic credentials.
/// @level MUST
/// @url https://datatracker.ietf.org/doc/html/rfc8628#section-3.1
#[actix_web::test]
async fn rfc8628_s3_1_accepts_client_secret_basic() {
    use base64::{engine::general_purpose::STANDARD, Engine};

    let (token_actor, client_actor, auth_actor, storage, jwt_secret, metrics, oidc_config) =
        setup_context(device_client()).await;
    let app = device_app!(
        token_actor,
        client_actor,
        auth_actor,
        storage,
        jwt_secret,
        metrics,
        oidc_config
    );

    let basic = STANDARD.encode("device_client:device_secret");
    let resp = test::call_service(
        &app,
        test::TestRequest::post()
            .uri("/oauth/device_authorization")
            .insert_header(("Authorization", format!("Basic {basic}")))
            .set_form([("scope", "read")])
            .to_request(),
    )
    .await;

    assert_eq!(
        resp.status(),
        200,
        "Basic-authenticated device auth must succeed without client_id in body"
    );
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert!(
        body["device_code"].as_str().is_some_and(|s| !s.is_empty()),
        "device_code must be present"
    );
}
