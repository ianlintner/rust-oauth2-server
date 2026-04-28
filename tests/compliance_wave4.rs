//! Wave 4 OAuth2/OIDC compliance tests.
//!
//! Covers: DPoP (RFC 9449), mTLS (RFC 8705), Token Exchange (RFC 8693),
//! RAR (RFC 9396), Step-Up Auth (RFC 9470), Protected Resource Metadata (RFC 9728),
//! Token Status List (draft), OIDC Claims Request (OIDC Core §5.5).
//!
//! These tests verify that the discovery document and new well-known endpoints
//! advertise the correct Wave 4 capabilities.

use actix_web::{test, web, App};
use serde_json::Value;

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

macro_rules! discovery_app {
    ($oidc_config:expr) => {
        test::init_service(
            App::new().app_data(web::Data::new($oidc_config)).service(
                web::scope("/.well-known")
                    .route(
                        "/openid-configuration",
                        web::get().to(oauth2_actix::handlers::wellknown::openid_configuration),
                    )
                    .route(
                        "/oauth-protected-resource",
                        web::get()
                            .to(oauth2_actix::handlers::wellknown::protected_resource_metadata),
                    )
                    .route(
                        "/oauth-authorization-server/status",
                        web::get().to(oauth2_actix::handlers::wellknown::token_status_list),
                    ),
            ),
        )
        .await
    };
}

async fn discovery_body(oidc_config: OidcConfig) -> Value {
    let app = discovery_app!(oidc_config);
    let req = test::TestRequest::get()
        .uri("/.well-known/openid-configuration")
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 200, "discovery endpoint must return 200");
    test::read_body_json(resp).await
}

// ---------------------------------------------------------------------------
// 4.1 DPoP — RFC 9449
// ---------------------------------------------------------------------------

/// RFC 9449 §5: Discovery document MUST advertise `dpop_signing_alg_values_supported`.
///
/// @rfc 9449
/// @section 5
/// @requirement Discovery metadata must advertise `dpop_signing_alg_values_supported`.
/// @level MUST
/// @url https://datatracker.ietf.org/doc/html/rfc9449#section-5
#[actix_web::test]
async fn wave4_rfc9449_dpop_signing_alg_values_supported_advertised() {
    let body = discovery_body(oidc_config()).await;
    let algs = body["dpop_signing_alg_values_supported"]
        .as_array()
        .expect("dpop_signing_alg_values_supported must be an array");
    assert!(
        !algs.is_empty(),
        "dpop_signing_alg_values_supported must not be empty"
    );
    // ES256 is required by RFC 9449 §5
    assert!(
        algs.iter().any(|v| v.as_str() == Some("ES256")),
        "ES256 must be advertised in dpop_signing_alg_values_supported"
    );
}

// ---------------------------------------------------------------------------
// 4.2 mTLS — RFC 8705
// ---------------------------------------------------------------------------

/// RFC 8705 §3: Discovery document MUST advertise
/// `tls_client_certificate_bound_access_tokens: true`.
///
/// @rfc 8705
/// @section 3
/// @requirement Discovery metadata must advertise `tls_client_certificate_bound_access_tokens: true`.
/// @level MUST
/// @url https://datatracker.ietf.org/doc/html/rfc8705#section-3
#[actix_web::test]
async fn wave4_rfc8705_mtls_advertised_in_discovery() {
    let body = discovery_body(oidc_config()).await;
    assert_eq!(
        body["tls_client_certificate_bound_access_tokens"].as_bool(),
        Some(true),
        "tls_client_certificate_bound_access_tokens must be true"
    );
}

// ---------------------------------------------------------------------------
// 4.3 Token Exchange — RFC 8693
// ---------------------------------------------------------------------------

/// RFC 8693 §2.1: Token Exchange grant type MUST appear in
/// `grant_types_supported`.
///
/// @rfc 8693
/// @section 2.1
/// @requirement Discovery metadata must include `urn:ietf:params:oauth:grant-type:token-exchange` in grant_types_supported.
/// @level MUST
/// @url https://datatracker.ietf.org/doc/html/rfc8693#section-2.1
#[actix_web::test]
async fn wave4_rfc8693_token_exchange_grant_type_in_discovery() {
    let body = discovery_body(oidc_config()).await;
    let grants = body["grant_types_supported"]
        .as_array()
        .expect("grant_types_supported must be an array");
    assert!(
        grants
            .iter()
            .any(|v| v.as_str() == Some("urn:ietf:params:oauth:grant-type:token-exchange")),
        "urn:ietf:params:oauth:grant-type:token-exchange must appear in grant_types_supported"
    );
}

// ---------------------------------------------------------------------------
// 4.4 RAR — RFC 9396
// ---------------------------------------------------------------------------

/// RFC 9396 §7: Discovery document MUST advertise
/// `authorization_details_types_supported`.
///
/// @rfc 9396
/// @section 7
/// @requirement Discovery metadata must advertise `authorization_details_types_supported`.
/// @level MUST
/// @url https://datatracker.ietf.org/doc/html/rfc9396#section-7
#[actix_web::test]
async fn wave4_rfc9396_rar_advertised_in_discovery() {
    let body = discovery_body(oidc_config()).await;
    let types = body["authorization_details_types_supported"]
        .as_array()
        .expect("authorization_details_types_supported must be an array");
    assert!(
        !types.is_empty(),
        "authorization_details_types_supported must not be empty"
    );
}

// ---------------------------------------------------------------------------
// 4.5 Step-Up Authentication — RFC 9470
// ---------------------------------------------------------------------------

/// RFC 9470 §4: Discovery document MUST advertise `acr_values_supported`.
///
/// @rfc 9470
/// @section 4
/// @requirement Discovery metadata must advertise `acr_values_supported`.
/// @level MUST
/// @url https://datatracker.ietf.org/doc/html/rfc9470#section-4
#[actix_web::test]
async fn wave4_rfc9470_acr_values_supported_advertised() {
    let body = discovery_body(oidc_config()).await;
    let values = body["acr_values_supported"]
        .as_array()
        .expect("acr_values_supported must be an array");
    assert!(!values.is_empty(), "acr_values_supported must not be empty");
}

// ---------------------------------------------------------------------------
// 4.6 Protected Resource Metadata — RFC 9728
// ---------------------------------------------------------------------------

/// RFC 9728 §3: GET /.well-known/oauth-protected-resource MUST return 200.
///
/// @rfc 9728
/// @section 3
/// @requirement /.well-known/oauth-protected-resource must return 200.
/// @level MUST
/// @url https://datatracker.ietf.org/doc/html/rfc9728#section-3
#[actix_web::test]
async fn wave4_rfc9728_protected_resource_metadata_returns_200() {
    let app = discovery_app!(oidc_config());
    let req = test::TestRequest::get()
        .uri("/.well-known/oauth-protected-resource")
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(
        resp.status(),
        200,
        "/.well-known/oauth-protected-resource must return 200"
    );
}

/// RFC 9728 §3: Protected resource metadata MUST include a `resource` field.
///
/// @rfc 9728
/// @section 3
/// @requirement Protected resource metadata must include a `resource` field.
/// @level MUST
/// @url https://datatracker.ietf.org/doc/html/rfc9728#section-3
#[actix_web::test]
async fn wave4_rfc9728_protected_resource_metadata_has_resource_field() {
    let app = discovery_app!(oidc_config());
    let req = test::TestRequest::get()
        .uri("/.well-known/oauth-protected-resource")
        .to_request();
    let resp = test::call_service(&app, req).await;
    let body: Value = test::read_body_json(resp).await;
    assert!(
        body["resource"].as_str().is_some(),
        "protected resource metadata must include a `resource` field"
    );
}

/// RFC 9728 §3: Protected resource metadata MUST include
/// `authorization_servers`.
///
/// @rfc 9728
/// @section 3
/// @requirement Protected resource metadata must include an `authorization_servers` array.
/// @level MUST
/// @url https://datatracker.ietf.org/doc/html/rfc9728#section-3
#[actix_web::test]
async fn wave4_rfc9728_protected_resource_metadata_has_authorization_servers() {
    let app = discovery_app!(oidc_config());
    let req = test::TestRequest::get()
        .uri("/.well-known/oauth-protected-resource")
        .to_request();
    let resp = test::call_service(&app, req).await;
    let body: Value = test::read_body_json(resp).await;
    let servers = body["authorization_servers"]
        .as_array()
        .expect("protected resource metadata must include authorization_servers");
    assert!(
        !servers.is_empty(),
        "authorization_servers must not be empty"
    );
}

// ---------------------------------------------------------------------------
// 4.7 Token Status List — draft-ietf-oauth-status-list
// ---------------------------------------------------------------------------

/// Token Status List: GET /.well-known/oauth-authorization-server/status MUST
/// return 200.
///
/// @rfc draft-ietf-oauth-status-list
/// @section 5
/// @requirement Token Status List discovery endpoint must return 200.
/// @level MUST
/// @url https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list
#[actix_web::test]
async fn wave4_token_status_list_returns_200() {
    let app = discovery_app!(oidc_config());
    let req = test::TestRequest::get()
        .uri("/.well-known/oauth-authorization-server/status")
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(
        resp.status(),
        200,
        "/.well-known/oauth-authorization-server/status must return 200"
    );
}

/// Token Status List: Response must be valid JSON.
///
/// @rfc draft-ietf-oauth-status-list
/// @section 5
/// @requirement Token Status List response must be valid JSON.
/// @level MUST
/// @url https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list
#[actix_web::test]
async fn wave4_token_status_list_returns_valid_json() {
    let app = discovery_app!(oidc_config());
    let req = test::TestRequest::get()
        .uri("/.well-known/oauth-authorization-server/status")
        .to_request();
    let resp = test::call_service(&app, req).await;
    let _body: Value = test::read_body_json(resp).await;
    // If we get here without panic, the response body is valid JSON.
}

// ---------------------------------------------------------------------------
// 4.8 OIDC Claims Request — OIDC Core §5.5
// ---------------------------------------------------------------------------

/// OIDC Core §5.5: Discovery document MUST include `acr` and `auth_time` in
/// `claims_supported` to advertise support for Claims Request parameter.
///
/// @rfc oidc-core-1.0
/// @section 5.5
/// @requirement Discovery `claims_supported` must advertise `acr` and `auth_time` to indicate Claims Request support.
/// @level MUST
/// @url https://openid.net/specs/openid-connect-core-1_0.html#ClaimsParameter
#[actix_web::test]
async fn wave4_oidc_claims_request_acr_auth_time_in_claims_supported() {
    let body = discovery_body(oidc_config()).await;
    let claims = body["claims_supported"]
        .as_array()
        .expect("claims_supported must be an array");
    let claim_strs: Vec<&str> = claims.iter().filter_map(|v| v.as_str()).collect();

    assert!(
        claim_strs.contains(&"acr"),
        "claims_supported must include `acr` for Claims Request support"
    );
    assert!(
        claim_strs.contains(&"auth_time"),
        "claims_supported must include `auth_time` for Claims Request support"
    );
    assert!(
        claim_strs.contains(&"amr"),
        "claims_supported must include `amr` for Claims Request support"
    );
}
