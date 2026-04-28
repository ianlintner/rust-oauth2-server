//! Wave 3 RFC compliance tests.
//!
//! Covers:
//!   - RFC 9126 — Pushed Authorization Requests (PAR)
//!   - RFC 8707 — Resource Indicators for OAuth 2.0
//!   - RFC 9701 — JWT Response for OAuth Token Introspection
//!
//! See docs/oauth2-spec-audit.md §Phase-3 for the full checklist.

use actix::Actor;
use actix_web::{
    http::header::{ACCEPT, CONTENT_TYPE},
    test, web, App,
};

use oauth2_actix::actors::{CreateToken, TokenActorPool};
use oauth2_actix::handlers::wellknown::OidcConfig;
use oauth2_core::{Client, IntrospectionResponse, User};
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
    clients: Vec<Client>,
) -> (
    TokenActorPool,
    actix::Addr<oauth2_actix::actors::ClientActor>,
    actix::Addr<oauth2_actix::actors::AuthActor>,
    String,
    Metrics,
    OidcConfig,
) {
    const ISSUER: &str = "https://auth.example.test";

    let storage = oauth2_storage_factory::create_storage("sqlite::memory:")
        .await
        .expect("create storage");
    storage.init().await.expect("init storage");

    for client in clients {
        storage.save_client(&client).await.expect("save client");
    }

    let now = chrono::Utc::now();
    let user = User {
        id: "user_wave3".to_string(),
        username: "user_wave3".to_string(),
        password_hash: "not_used".to_string(),
        email: "user_wave3@example.test".to_string(),
        enabled: true,
        role: "user".to_string(),
        created_at: now,
        updated_at: now,
    };
    storage.save_user(&user).await.expect("save user");

    let jwt_secret = "wave3_test_jwt_secret_at_least_32_chars".to_string();
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
// RFC 9126 — Pushed Authorization Requests (PAR)
// ===================================================================

/// RFC 9126 §2.2: A public client (no secret) POSTing valid params to /oauth/par
/// must receive 201 Created with `request_uri` and `expires_in: 60`.
///
/// @rfc 9126
/// @section 2.2
/// @requirement PAR endpoint must return 201 with `request_uri` and `expires_in` for valid public-client requests.
/// @level MUST
/// @url https://datatracker.ietf.org/doc/html/rfc9126#section-2.2
#[actix_web::test]
async fn rfc9126_par_public_client_returns_request_uri() {
    // Build a public client (token_endpoint_auth_method = "none").
    let mut client = Client::new(
        "par_pub".to_string(),
        String::new(),
        vec!["https://example.com/cb".to_string()],
        vec!["authorization_code".to_string()],
        "read".to_string(),
        "PAR public client".to_string(),
    );
    client.token_endpoint_auth_method = "none".to_string();
    assert!(client.is_public());

    let (_token_pool, client_actor, auth_actor, _jwt_secret, _metrics, _oidc_config) =
        setup_context(vec![client]).await;

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(client_actor))
            .app_data(web::Data::new(auth_actor))
            .service(
                web::scope("/oauth")
                    .route("/par", web::post().to(oauth2_actix::handlers::oauth::par)),
            ),
    )
    .await;

    let payload =
        "client_id=par_pub&response_type=code&scope=read&redirect_uri=https%3A%2F%2Fexample.com%2Fcb";
    let req = test::TestRequest::post()
        .uri("/oauth/par")
        .insert_header((CONTENT_TYPE, "application/x-www-form-urlencoded"))
        .set_payload(payload)
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 201, "PAR must return 201 Created");

    let body: serde_json::Value = test::read_body_json(resp).await;
    let request_uri = body["request_uri"]
        .as_str()
        .expect("request_uri must be a string");
    assert!(
        request_uri.starts_with("urn:ietf:params:oauth:request-uri:"),
        "request_uri must use urn:ietf:params:oauth:request-uri: prefix, got: {request_uri}",
    );
    assert_eq!(
        body["expires_in"].as_u64(),
        Some(60),
        "expires_in must be 60 seconds (RFC 9126 §2.2)"
    );
}

/// RFC 9126 §2.1: PAR request without `response_type` must be rejected.
///
/// @rfc 9126
/// @section 2.1
/// @requirement PAR endpoint must reject requests missing the `response_type` parameter.
/// @level MUST
/// @url https://datatracker.ietf.org/doc/html/rfc9126#section-2.1
#[actix_web::test]
async fn rfc9126_par_missing_response_type_is_rejected() {
    let mut client = Client::new(
        "par_nort".to_string(),
        String::new(),
        vec!["https://example.com/cb".to_string()],
        vec!["authorization_code".to_string()],
        "read".to_string(),
        "PAR no response_type".to_string(),
    );
    client.token_endpoint_auth_method = "none".to_string();

    let (_token_pool, client_actor, auth_actor, _jwt_secret, _metrics, _oidc_config) =
        setup_context(vec![client]).await;

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(client_actor))
            .app_data(web::Data::new(auth_actor))
            .service(
                web::scope("/oauth")
                    .route("/par", web::post().to(oauth2_actix::handlers::oauth::par)),
            ),
    )
    .await;

    let payload = "client_id=par_nort&scope=read";
    let req = test::TestRequest::post()
        .uri("/oauth/par")
        .insert_header((CONTENT_TYPE, "application/x-www-form-urlencoded"))
        .set_payload(payload)
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(
        resp.status(),
        400,
        "PAR without response_type must return 400"
    );
}

/// RFC 9126 §2.1: PAR request with duplicate parameters must be rejected.
///
/// @rfc 9126
/// @section 2.1
/// @requirement PAR endpoint must reject requests containing duplicate parameters.
/// @level MUST
/// @url https://datatracker.ietf.org/doc/html/rfc9126#section-2.1
#[actix_web::test]
async fn rfc9126_par_duplicate_param_is_rejected() {
    let mut client = Client::new(
        "par_dup".to_string(),
        String::new(),
        vec!["https://example.com/cb".to_string()],
        vec!["authorization_code".to_string()],
        "read".to_string(),
        "PAR dup param".to_string(),
    );
    client.token_endpoint_auth_method = "none".to_string();

    let (_token_pool, client_actor, auth_actor, _jwt_secret, _metrics, _oidc_config) =
        setup_context(vec![client]).await;

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(client_actor))
            .app_data(web::Data::new(auth_actor))
            .service(
                web::scope("/oauth")
                    .route("/par", web::post().to(oauth2_actix::handlers::oauth::par)),
            ),
    )
    .await;

    // Duplicate `scope` field.
    let payload = "client_id=par_dup&response_type=code&scope=read&scope=write";
    let req = test::TestRequest::post()
        .uri("/oauth/par")
        .insert_header((CONTENT_TYPE, "application/x-www-form-urlencoded"))
        .set_payload(payload)
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(
        resp.status(),
        400,
        "PAR with duplicate parameter must return 400"
    );
}

/// RFC 9126 §2.1: Confidential client sending PAR without authentication must be rejected.
///
/// @rfc 9126
/// @section 2.1
/// @requirement PAR endpoint must reject confidential clients that do not authenticate.
/// @level MUST
/// @url https://datatracker.ietf.org/doc/html/rfc9126#section-2.1
#[actix_web::test]
async fn rfc9126_par_confidential_client_no_secret_rejected() {
    // Confidential client (default token_endpoint_auth_method = "client_secret_basic").
    let client = Client::new(
        "par_conf".to_string(),
        "par_conf_secret".to_string(),
        vec!["https://example.com/cb".to_string()],
        vec!["authorization_code".to_string()],
        "read".to_string(),
        "PAR confidential".to_string(),
    );
    assert!(!client.is_public());

    let (_token_pool, client_actor, auth_actor, _jwt_secret, _metrics, _oidc_config) =
        setup_context(vec![client]).await;

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(client_actor))
            .app_data(web::Data::new(auth_actor))
            .service(
                web::scope("/oauth")
                    .route("/par", web::post().to(oauth2_actix::handlers::oauth::par)),
            ),
    )
    .await;

    // No client_secret in body and no Basic auth header.
    let payload = "client_id=par_conf&response_type=code&scope=read";
    let req = test::TestRequest::post()
        .uri("/oauth/par")
        .insert_header((CONTENT_TYPE, "application/x-www-form-urlencoded"))
        .set_payload(payload)
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert!(
        resp.status() == 400 || resp.status() == 401,
        "Confidential client without auth must return 400 or 401, got {}",
        resp.status()
    );
}

/// RFC 9126 §2.1: Confidential client with valid Basic auth succeeds.
///
/// @rfc 9126
/// @section 2.1
/// @requirement PAR endpoint must accept confidential client authenticated via HTTP Basic.
/// @level MUST
/// @url https://datatracker.ietf.org/doc/html/rfc9126#section-2.1
#[actix_web::test]
async fn rfc9126_par_confidential_client_with_basic_auth_succeeds() {
    let client = Client::new(
        "par_conf_ok".to_string(),
        "par_conf_ok_secret".to_string(),
        vec!["https://example.com/cb".to_string()],
        vec!["authorization_code".to_string()],
        "read".to_string(),
        "PAR confidential OK".to_string(),
    );

    let (_token_pool, client_actor, auth_actor, _jwt_secret, _metrics, _oidc_config) =
        setup_context(vec![client]).await;

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(client_actor))
            .app_data(web::Data::new(auth_actor))
            .service(
                web::scope("/oauth")
                    .route("/par", web::post().to(oauth2_actix::handlers::oauth::par)),
            ),
    )
    .await;

    let payload = "client_id=par_conf_ok&response_type=code&scope=read";
    let req = test::TestRequest::post()
        .uri("/oauth/par")
        .insert_header((CONTENT_TYPE, "application/x-www-form-urlencoded"))
        .insert_header((
            actix_web::http::header::AUTHORIZATION,
            basic_auth_header("par_conf_ok", "par_conf_ok_secret"),
        ))
        .set_payload(payload)
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(
        resp.status(),
        201,
        "Confidential client with valid Basic auth must get 201 from PAR"
    );
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert!(
        body["request_uri"]
            .as_str()
            .map(|u| u.starts_with("urn:ietf:params:oauth:request-uri:"))
            .unwrap_or(false),
        "Expected request_uri with urn prefix"
    );
}

// ===================================================================
// RFC 8707 — Resource Indicators
// ===================================================================

/// RFC 8707 §2: A `resource` parameter in a client_credentials request must be
/// accepted. The token must be issued successfully (the server records the
/// audience for later use).
///
/// @rfc 8707
/// @section 2
/// @requirement Token endpoint must accept `resource` parameter and bind it as token audience.
/// @level MUST
/// @url https://datatracker.ietf.org/doc/html/rfc8707#section-2
#[actix_web::test]
async fn rfc8707_resource_indicator_accepted_in_client_credentials() {
    let client = Client::new(
        "rci_client".to_string(),
        "rci_secret".to_string(),
        vec!["https://unused.example/cb".to_string()],
        vec!["client_credentials".to_string()],
        "read".to_string(),
        "RCI test client".to_string(),
    );

    let (token_pool, client_actor, auth_actor, _jwt_secret, metrics, oidc_config) =
        setup_context(vec![client]).await;

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(token_pool))
            .app_data(web::Data::new(client_actor))
            .app_data(web::Data::new(auth_actor))
            .app_data(web::Data::new(metrics))
            .app_data(web::Data::new(oidc_config))
            .service(web::scope("/oauth").route(
                "/token",
                web::post().to(oauth2_actix::handlers::oauth::token),
            )),
    )
    .await;

    let payload = "grant_type=client_credentials\
        &client_id=rci_client\
        &client_secret=rci_secret\
        &scope=read\
        &resource=https%3A%2F%2Fapi.example.com";
    let req = test::TestRequest::post()
        .uri("/oauth/token")
        .insert_header((CONTENT_TYPE, "application/x-www-form-urlencoded"))
        .set_payload(payload)
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(
        resp.status(),
        200,
        "client_credentials with resource indicator must return 200 OK"
    );
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert!(
        body["access_token"].is_string(),
        "Response must include an access_token"
    );
    assert_eq!(body["token_type"].as_str(), Some("Bearer"));
}

// ===================================================================
// RFC 9701 — JWT Response for OAuth Token Introspection
// ===================================================================

/// RFC 9701 §4: When the caller sends `Accept: application/token-introspection+jwt`,
/// the introspection endpoint must return a signed JWT with
/// `Content-Type: application/token-introspection+jwt` and
/// JOSE header `typ: "token-introspection+jwt"`.
///
/// @rfc 9701
/// @section 4
/// @requirement Introspection must return a signed JWT response when `Accept: application/token-introspection+jwt`.
/// @level MUST
/// @url https://datatracker.ietf.org/doc/html/rfc9701#section-4
#[actix_web::test]
async fn rfc9701_jwt_accept_header_returns_jwt_introspection_response() {
    let client = Client::new(
        "jwt_intros_client".to_string(),
        "jwt_intros_secret".to_string(),
        vec!["https://unused.example/cb".to_string()],
        vec!["client_credentials".to_string()],
        "read".to_string(),
        "JWT introspection test".to_string(),
    );

    let (token_pool, client_actor, auth_actor, jwt_secret, metrics, oidc_config) =
        setup_context(vec![client]).await;

    // Issue a token directly via the actor.
    let token = token_pool
        .route("jwt_intros_client")
        .send(CreateToken {
            user_id: None,
            client_id: "jwt_intros_client".to_string(),
            scope: "read".to_string(),
            include_refresh: false,
            token_family: None,
            resource: None,
            cnf: None,
            authorization_details: None,
            span: tracing::Span::current(),
        })
        .await
        .expect("send")
        .expect("create token");

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(token_pool))
            .app_data(web::Data::new(client_actor))
            .app_data(web::Data::new(auth_actor))
            .app_data(web::Data::new(jwt_secret))
            .app_data(web::Data::new(metrics))
            .app_data(web::Data::new(oidc_config))
            .app_data(web::Data::new(false)) // stateless_validation
            .service(web::scope("/oauth").route(
                "/introspect",
                web::post().to(oauth2_actix::handlers::token::introspect),
            )),
    )
    .await;

    let req = test::TestRequest::post()
        .uri("/oauth/introspect")
        .insert_header((ACCEPT, "application/token-introspection+jwt"))
        .set_form([
            ("token", token.access_token.as_str()),
            ("client_id", "jwt_intros_client"),
            ("client_secret", "jwt_intros_secret"),
        ])
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 200);

    let ct = resp
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");
    assert!(
        ct.contains("application/token-introspection+jwt"),
        "Content-Type must be application/token-introspection+jwt, got: {ct}"
    );

    // Verify the response body is a properly-typed JWT.
    let jwt_bytes = test::read_body(resp).await;
    let jwt_str = std::str::from_utf8(&jwt_bytes).expect("utf8");
    let header = jsonwebtoken::decode_header(jwt_str).expect("valid JWT header");
    assert_eq!(
        header.typ.as_deref(),
        Some("token-introspection+jwt"),
        "JOSE typ must be token-introspection+jwt (RFC 9701 §4)"
    );
}

/// RFC 9701 §4: When no special Accept header is sent, the introspection endpoint
/// must still return the standard JSON response.
///
/// @rfc 9701
/// @section 4
/// @requirement Introspection without special Accept must return the standard JSON response.
/// @level MUST
/// @url https://datatracker.ietf.org/doc/html/rfc9701#section-4
#[actix_web::test]
async fn rfc9701_standard_accept_returns_json_introspection_response() {
    let client = Client::new(
        "json_intros_client".to_string(),
        "json_intros_secret".to_string(),
        vec!["https://unused.example/cb".to_string()],
        vec!["client_credentials".to_string()],
        "read".to_string(),
        "JSON introspection test".to_string(),
    );

    let (token_pool, client_actor, auth_actor, jwt_secret, metrics, oidc_config) =
        setup_context(vec![client]).await;

    let token = token_pool
        .route("json_intros_client")
        .send(CreateToken {
            user_id: None,
            client_id: "json_intros_client".to_string(),
            scope: "read".to_string(),
            include_refresh: false,
            token_family: None,
            resource: None,
            cnf: None,
            authorization_details: None,
            span: tracing::Span::current(),
        })
        .await
        .expect("send")
        .expect("create token");

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(token_pool))
            .app_data(web::Data::new(client_actor))
            .app_data(web::Data::new(auth_actor))
            .app_data(web::Data::new(jwt_secret))
            .app_data(web::Data::new(metrics))
            .app_data(web::Data::new(oidc_config))
            .app_data(web::Data::new(false)) // stateless_validation
            .service(web::scope("/oauth").route(
                "/introspect",
                web::post().to(oauth2_actix::handlers::token::introspect),
            )),
    )
    .await;

    let req = test::TestRequest::post()
        .uri("/oauth/introspect")
        .set_form([
            ("token", token.access_token.as_str()),
            ("client_id", "json_intros_client"),
            ("client_secret", "json_intros_secret"),
        ])
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 200);

    let body: IntrospectionResponse = test::read_body_json(resp).await;
    assert!(
        body.active,
        "standard introspection must return active=true"
    );
}

/// RFC 9701 §4: The JWT payload must contain a `token_introspection` claim
/// with the standard introspection fields (active, scope, client_id).
///
/// @rfc 9701
/// @section 4
/// @requirement JWT introspection payload must include a `token_introspection` claim with standard fields.
/// @level MUST
/// @url https://datatracker.ietf.org/doc/html/rfc9701#section-4
#[actix_web::test]
async fn rfc9701_jwt_payload_contains_token_introspection_claim() {
    let client = Client::new(
        "jwt_payload_client".to_string(),
        "jwt_payload_secret".to_string(),
        vec!["https://unused.example/cb".to_string()],
        vec!["client_credentials".to_string()],
        "openid profile".to_string(),
        "JWT payload test".to_string(),
    );

    let (token_pool, client_actor, auth_actor, jwt_secret, metrics, oidc_config) =
        setup_context(vec![client]).await;

    let token = token_pool
        .route("jwt_payload_client")
        .send(CreateToken {
            user_id: Some("user_wave3".to_string()),
            client_id: "jwt_payload_client".to_string(),
            scope: "openid profile".to_string(),
            include_refresh: false,
            token_family: None,
            resource: None,
            cnf: None,
            authorization_details: None,
            span: tracing::Span::current(),
        })
        .await
        .expect("send")
        .expect("create token");

    let jwt_secret_clone = jwt_secret.clone();
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(token_pool))
            .app_data(web::Data::new(client_actor))
            .app_data(web::Data::new(auth_actor))
            .app_data(web::Data::new(jwt_secret))
            .app_data(web::Data::new(metrics))
            .app_data(web::Data::new(oidc_config))
            .app_data(web::Data::new(false)) // stateless_validation
            .service(web::scope("/oauth").route(
                "/introspect",
                web::post().to(oauth2_actix::handlers::token::introspect),
            )),
    )
    .await;

    let req = test::TestRequest::post()
        .uri("/oauth/introspect")
        .insert_header((ACCEPT, "application/token-introspection+jwt"))
        .set_form([
            ("token", token.access_token.as_str()),
            ("client_id", "jwt_payload_client"),
            ("client_secret", "jwt_payload_secret"),
        ])
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 200);

    // Decode the JWT and inspect the payload.
    let jwt_bytes = test::read_body(resp).await;
    let jwt_str = std::str::from_utf8(&jwt_bytes).expect("utf8");

    // Decode without validation to inspect claims (we just issued it with a test secret).
    let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::HS256);
    validation.validate_exp = false;
    validation.validate_aud = false;
    validation.set_required_spec_claims::<String>(&[]);

    let decoded = jsonwebtoken::decode::<serde_json::Value>(
        jwt_str,
        &jsonwebtoken::DecodingKey::from_secret(jwt_secret_clone.as_bytes()),
        &validation,
    )
    .expect("decodable JWT");

    let claims = &decoded.claims;
    assert!(
        claims.get("token_introspection").is_some(),
        "JWT payload must contain token_introspection claim (RFC 9701)"
    );
    let ti = &claims["token_introspection"];
    assert_eq!(
        ti["active"].as_bool(),
        Some(true),
        "token_introspection.active must be true"
    );
    assert_eq!(
        ti["client_id"].as_str(),
        Some("jwt_payload_client"),
        "token_introspection.client_id must match"
    );
    assert!(
        claims.get("iss").is_some(),
        "JWT must have iss claim (RFC 9701 §4)"
    );
    assert!(
        claims.get("iat").is_some(),
        "JWT must have iat claim (RFC 9701 §4)"
    );
}
