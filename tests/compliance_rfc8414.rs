//! RFC 8414 — OAuth 2.0 Authorization Server Metadata
//! OpenID Connect Discovery 1.0
//!
//! Compliance tests that map directly to RFC 8414 §2 and OIDC Discovery §3.
//! See docs/compliance/RFC_COMPLIANCE.md for the full matrix.

use actix_web::{test, web, App};

use oauth2_actix::handlers::wellknown::OidcConfig;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn oidc_config() -> OidcConfig {
    OidcConfig {
        issuer: "https://auth.example.test".to_string(),
        jwt_secret: "test_jwt_secret".to_string(),
        id_token_alg: "HS256".to_string(),
        id_token_kid: None,
        id_token_private_key_pem: None,
    }
}

macro_rules! app {
    ($oidc_config:expr) => {
        test::init_service(App::new().app_data(web::Data::new($oidc_config)).service(
            web::scope("/.well-known").route(
                "/openid-configuration",
                web::get().to(oauth2_actix::handlers::wellknown::openid_configuration),
            ),
        ))
        .await
    };
}

// ---------------------------------------------------------------------------
// RFC 8414 §2 — Authorization Server Metadata
// ---------------------------------------------------------------------------

/// RFC 8414 §2: `GET /.well-known/openid-configuration` must return 200 OK.
///
/// @rfc 8414
/// @section 2
/// @requirement Authorization-server metadata endpoint must return 200 OK.
/// @level MUST
/// @url https://datatracker.ietf.org/doc/html/rfc8414#section-2
#[actix_web::test]
async fn rfc8414_s2_metadata_endpoint_returns_200() {
    let app = app!(oidc_config());

    let req = test::TestRequest::get()
        .uri("/.well-known/openid-configuration")
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 200);
}

/// RFC 8414 §2: The `issuer` field in the metadata must exactly match the
/// configured issuer identifier.
///
/// @rfc 8414
/// @section 2
/// @requirement The `issuer` metadata value must match the configured issuer URL.
/// @level MUST
/// @url https://datatracker.ietf.org/doc/html/rfc8414#section-2
#[actix_web::test]
async fn rfc8414_s2_issuer_matches_configured_value() {
    let app = app!(oidc_config());

    let req = test::TestRequest::get()
        .uri("/.well-known/openid-configuration")
        .to_request();
    let resp = test::call_service(&app, req).await;
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(
        body["issuer"].as_str(),
        Some("https://auth.example.test"),
        "issuer must match the configured issuer"
    );
}

/// RFC 8414 §2: The metadata document must include `authorization_endpoint`.
///
/// @rfc 8414
/// @section 2
/// @requirement Metadata must include the `authorization_endpoint` field.
/// @level MUST
/// @url https://datatracker.ietf.org/doc/html/rfc8414#section-2
#[actix_web::test]
async fn rfc8414_s2_authorization_endpoint_present() {
    let app = app!(oidc_config());

    let req = test::TestRequest::get()
        .uri("/.well-known/openid-configuration")
        .to_request();
    let resp = test::call_service(&app, req).await;
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert!(
        body.get("authorization_endpoint").is_some(),
        "authorization_endpoint must be present"
    );
    assert!(
        body["authorization_endpoint"]
            .as_str()
            .unwrap_or("")
            .contains("/oauth/authorize"),
        "authorization_endpoint must point to /oauth/authorize"
    );
}

/// RFC 8414 §2: The metadata document must include `token_endpoint`.
///
/// @rfc 8414
/// @section 2
/// @requirement Metadata must include the `token_endpoint` field.
/// @level MUST
/// @url https://datatracker.ietf.org/doc/html/rfc8414#section-2
#[actix_web::test]
async fn rfc8414_s2_token_endpoint_present() {
    let app = app!(oidc_config());

    let req = test::TestRequest::get()
        .uri("/.well-known/openid-configuration")
        .to_request();
    let resp = test::call_service(&app, req).await;
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert!(
        body.get("token_endpoint").is_some(),
        "token_endpoint must be present"
    );
}

/// RFC 8414 §2: `response_types_supported` must include `"code"`.
///
/// @rfc 8414
/// @section 2
/// @requirement `response_types_supported` must include `code`.
/// @level MUST
/// @url https://datatracker.ietf.org/doc/html/rfc8414#section-2
#[actix_web::test]
async fn rfc8414_s2_response_types_includes_code() {
    let app = app!(oidc_config());

    let req = test::TestRequest::get()
        .uri("/.well-known/openid-configuration")
        .to_request();
    let resp = test::call_service(&app, req).await;
    let body: serde_json::Value = test::read_body_json(resp).await;
    let types = body["response_types_supported"]
        .as_array()
        .expect("response_types_supported must be an array");
    let has_code = types.iter().any(|v| v.as_str() == Some("code"));
    assert!(has_code, "response_types_supported must include \"code\"");
}

/// RFC 8414 §2 / RFC 7636 §4: `code_challenge_methods_supported` must include
/// `"S256"`.
///
/// @rfc 8414
/// @section 2
/// @requirement `code_challenge_methods_supported` must include `S256`.
/// @level MUST
/// @url https://datatracker.ietf.org/doc/html/rfc8414#section-2
#[actix_web::test]
async fn rfc8414_s2_code_challenge_methods_includes_s256() {
    let app = app!(oidc_config());

    let req = test::TestRequest::get()
        .uri("/.well-known/openid-configuration")
        .to_request();
    let resp = test::call_service(&app, req).await;
    let body: serde_json::Value = test::read_body_json(resp).await;
    let methods = body["code_challenge_methods_supported"]
        .as_array()
        .expect("code_challenge_methods_supported must be an array");
    let has_s256 = methods.iter().any(|v| v.as_str() == Some("S256"));
    assert!(
        has_s256,
        "code_challenge_methods_supported must include \"S256\""
    );
}

/// OIDC Discovery §3: The metadata must include a `userinfo_endpoint`.
///
/// @rfc oidc-discovery-1.0
/// @section 3
/// @requirement OIDC discovery metadata must include `userinfo_endpoint`.
/// @level MUST
/// @url https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata
#[actix_web::test]
async fn rfc8414_s2_userinfo_endpoint_present() {
    let app = app!(oidc_config());

    let req = test::TestRequest::get()
        .uri("/.well-known/openid-configuration")
        .to_request();
    let resp = test::call_service(&app, req).await;
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert!(
        body.get("userinfo_endpoint").is_some(),
        "userinfo_endpoint must be present"
    );
}

/// RFC 8414 §2: `token_endpoint_auth_methods_supported` must include
/// `"client_secret_basic"`.
///
/// @rfc 8414
/// @section 2
/// @requirement `token_endpoint_auth_methods_supported` must include `client_secret_basic`.
/// @level MUST
/// @url https://datatracker.ietf.org/doc/html/rfc8414#section-2
#[actix_web::test]
async fn rfc8414_s2_token_endpoint_auth_methods_include_basic() {
    let app = app!(oidc_config());

    let req = test::TestRequest::get()
        .uri("/.well-known/openid-configuration")
        .to_request();
    let resp = test::call_service(&app, req).await;
    let body: serde_json::Value = test::read_body_json(resp).await;
    let methods = body["token_endpoint_auth_methods_supported"]
        .as_array()
        .expect("token_endpoint_auth_methods_supported must be an array");
    let has_basic = methods
        .iter()
        .any(|v| v.as_str() == Some("client_secret_basic"));
    assert!(
        has_basic,
        "token_endpoint_auth_methods_supported must include client_secret_basic"
    );
}

/// RFC 8414 §2: `grant_types_supported` must include `"authorization_code"`.
///
/// @rfc 8414
/// @section 2
/// @requirement `grant_types_supported` must include `authorization_code`.
/// @level MUST
/// @url https://datatracker.ietf.org/doc/html/rfc8414#section-2
#[actix_web::test]
async fn rfc8414_s2_grant_types_includes_authorization_code() {
    let app = app!(oidc_config());

    let req = test::TestRequest::get()
        .uri("/.well-known/openid-configuration")
        .to_request();
    let resp = test::call_service(&app, req).await;
    let body: serde_json::Value = test::read_body_json(resp).await;
    let grants = body["grant_types_supported"]
        .as_array()
        .expect("grant_types_supported must be an array");
    let has_ac = grants
        .iter()
        .any(|v| v.as_str() == Some("authorization_code"));
    assert!(
        has_ac,
        "grant_types_supported must include authorization_code"
    );
}
