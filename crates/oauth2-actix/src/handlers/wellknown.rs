use std::sync::Arc;

use actix_web::{web, HttpRequest, HttpResponse, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use rsa::pkcs1::DecodeRsaPrivateKey;
use rsa::pkcs8::DecodePrivateKey;
use rsa::traits::PublicKeyParts;
use rsa::RsaPrivateKey;
use serde_json::json;
use tokio::sync::RwLock;

use crate::actors::{TokenActorPool, ValidateToken};
use oauth2_core::models::key_set::{Algorithm as KeyAlgorithm, KeySet};
use oauth2_ports::DynStorage;

/// Shared OIDC / server configuration injected as `web::Data<OidcConfig>`.
#[derive(Debug, Clone)]
pub struct OidcConfig {
    /// The public issuer URL (e.g. `https://roauth2.cat-herding.net`).
    pub issuer: String,
    /// The HMAC secret used for signing JWTs (HS256).
    pub jwt_secret: String,

    /// Signing algorithm used for OIDC id_tokens (e.g. `HS256` or `RS256`).
    pub id_token_alg: String,
    /// Optional key id for the OIDC signing key.
    pub id_token_kid: Option<String>,
    /// Optional RSA private key PEM used for RS256 id_token signing.
    /// When present and `id_token_alg` is RS256, the JWKS endpoint will publish
    /// the corresponding public key.
    pub id_token_private_key_pem: Option<String>,
}

/// OAuth2 / OIDC discovery endpoint
/// Returns server metadata according to RFC 8414 + OpenID Connect Discovery 1.0
pub async fn openid_configuration(
    oidc: web::Data<OidcConfig>,
    config: Option<web::Data<oauth2_config::Config>>,
) -> Result<HttpResponse> {
    let base = oidc.issuer.trim_end_matches('/');
    let public_introspection = config
        .as_ref()
        .map(|cfg| cfg.jwt.public_introspection)
        .unwrap_or(false);

    let id_token_algs = if oidc.id_token_alg.eq_ignore_ascii_case("RS256") {
        ["RS256"]
    } else {
        ["HS256"]
    };
    let introspection_auth_methods = if public_introspection {
        vec!["none", "client_secret_basic", "client_secret_post"]
    } else {
        vec!["client_secret_basic", "client_secret_post"]
    };
    let config = json!({
        "issuer": base,
        "authorization_endpoint": format!("{}/oauth/authorize", base),
        "token_endpoint": format!("{}/oauth/token", base),
        "end_session_endpoint": format!("{}/oauth/logout", base),
        "introspection_endpoint": format!("{}/oauth/introspect", base),
        "introspection_endpoint_auth_methods_supported": introspection_auth_methods,
        "revocation_endpoint": format!("{}/oauth/revoke", base),
        "revocation_endpoint_auth_methods_supported": [
            "client_secret_basic",
            "client_secret_post"
        ],
        "token_introspection_endpoint": format!("{}/oauth/introspect", base),
        "token_revocation_endpoint": format!("{}/oauth/revoke", base),
        "userinfo_endpoint": format!("{}/oauth/userinfo", base),
        "device_authorization_endpoint": format!("{}/oauth/device_authorization", base),
        "jwks_uri": format!("{}/.well-known/jwks.json", base),
        "registration_endpoint": format!("{}/connect/register", base),
        "scopes_supported": ["openid", "profile", "email", "read", "write", "admin"],
        "response_types_supported": ["code", "code id_token"],
        "grant_types_supported": [
            "authorization_code",
            "client_credentials",
            "refresh_token",
            "urn:ietf:params:oauth:grant-type:device_code",
            "urn:ietf:params:oauth:grant-type:token-exchange"
        ],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": id_token_algs,
        "token_endpoint_auth_methods_supported": [
            "client_secret_basic",
            "client_secret_post",
            "client_secret_jwt",
            "private_key_jwt",
            "tls_client_auth",
            "self_signed_tls_client_auth",
            "none"
        ],
        "claims_supported": [
            "sub", "iss", "aud", "exp", "iat", "nonce", "at_hash", "c_hash",
            "email", "preferred_username", "acr", "amr", "auth_time"
        ],
        "code_challenge_methods_supported": ["S256"],
        "authorization_response_iss_parameter_supported": true,
        "prompt_values_supported": ["none", "login", "consent", "select_account"],
        // OIDC Session Management 1.0
        "check_session_iframe": format!("{}/oauth/check_session", base),
        // OIDC Back-Channel Logout 1.0
        "backchannel_logout_supported": true,
        "backchannel_logout_session_supported": true,
        // OIDC Front-Channel Logout 1.0
        "frontchannel_logout_supported": true,
        "frontchannel_logout_session_supported": true,
        // RFC 9198: Form Post Response Mode / RFC 9101: JAR fragment mode
        "response_modes_supported": ["query", "form_post", "fragment"],
        // RFC 9126: Pushed Authorization Requests
        "pushed_authorization_request_endpoint": format!("{}/oauth/par", base),
        "require_pushed_authorization_requests": false,
        // RFC 9101: JWT-Secured Authorization Requests (JAR)
        "request_parameter_supported": true,
        "request_uri_parameter_supported": true,
        "request_object_signing_alg_values_supported": ["RS256", "ES256", "HS256"],
        // RFC 8707: Resource Indicators
        "resource_indicators_supported": true,
        "service_documentation": format!("{}/docs", base),
        // RFC 9449: DPoP
        "dpop_signing_alg_values_supported": ["ES256", "RS256"],
        // RFC 8705: mTLS client certificate bound access tokens
        "tls_client_certificate_bound_access_tokens": true,
        // RFC 9396: Rich Authorization Requests
        "authorization_details_types_supported": ["openid"],
        // RFC 9470: Step-Up Authentication
        "acr_values_supported": [
            "urn:mace:incommon:iap:silver",
            "urn:mace:incommon:iap:bronze"
        ]
    });

    Ok(HttpResponse::Ok().json(config))
}

/// JWKS endpoint.
///
/// Returns all active RS256 keys from the KeySet.
/// HS256 keys are NOT included (shared secrets must not be published).
pub async fn jwks(
    keyset: web::Data<Arc<RwLock<KeySet>>>,
    oidc: web::Data<OidcConfig>,
) -> Result<HttpResponse> {
    let ks = keyset.read().await;
    let mut jwk_entries = Vec::new();

    for key in ks.active_keys() {
        if key.algorithm != KeyAlgorithm::RS256 {
            continue;
        }

        // Parse the PEM to extract RSA public key components
        let pem_str = std::str::from_utf8(&key.key_material)
            .map_err(|_| actix_web::error::ErrorInternalServerError("Invalid key encoding"))?;

        let private_key = RsaPrivateKey::from_pkcs8_pem(pem_str)
            .or_else(|_| RsaPrivateKey::from_pkcs1_pem(pem_str))
            .map_err(|_| {
                actix_web::error::ErrorInternalServerError("Invalid RSA private key PEM")
            })?;
        let public_key = private_key.to_public_key();
        let n = URL_SAFE_NO_PAD.encode(public_key.n().to_bytes_be());
        let e = URL_SAFE_NO_PAD.encode(public_key.e().to_bytes_be());

        jwk_entries.push(json!({
            "kid": &key.kid,
            "kty": "RSA",
            "use": "sig",
            "alg": "RS256",
            "n": n,
            "e": e,
        }));
    }

    // Fallback: if no RS256 keys in KeySet, try OidcConfig (backward compat during migration)
    if jwk_entries.is_empty() && oidc.id_token_alg.eq_ignore_ascii_case("RS256") {
        if let Some(pem) = oidc
            .id_token_private_key_pem
            .as_deref()
            .filter(|s| !s.trim().is_empty())
        {
            let private_key = RsaPrivateKey::from_pkcs8_pem(pem)
                .or_else(|_| RsaPrivateKey::from_pkcs1_pem(pem))
                .map_err(|_| {
                    actix_web::error::ErrorInternalServerError("Invalid RSA private key PEM")
                })?;
            let public_key = private_key.to_public_key();
            let n = URL_SAFE_NO_PAD.encode(public_key.n().to_bytes_be());
            let e = URL_SAFE_NO_PAD.encode(public_key.e().to_bytes_be());
            let mut jwk = json!({
                "kty": "RSA", "use": "sig", "alg": "RS256", "n": n, "e": e,
            });
            if let Some(kid) = oidc
                .id_token_kid
                .as_deref()
                .filter(|s| !s.trim().is_empty())
            {
                jwk["kid"] = json!(kid);
            }
            jwk_entries.push(jwk);
        }
    }

    Ok(HttpResponse::Ok()
        .insert_header(("Cache-Control", "public, max-age=3600"))
        .json(json!({ "keys": jwk_entries })))
}

/// OIDC UserInfo endpoint – returns claims about the authenticated user.
pub async fn userinfo(
    req: HttpRequest,
    token_actor: web::Data<TokenActorPool>,
    oidc: web::Data<OidcConfig>,
    storage: Option<web::Data<DynStorage>>,
) -> Result<HttpResponse> {
    // Extract Bearer token from the Authorization header only.
    let token_str = req
        .headers()
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string());

    let token_str = match token_str {
        Some(t) => t,
        None => {
            return Ok(HttpResponse::Unauthorized()
                .insert_header(("WWW-Authenticate", "Bearer"))
                .json(
                    json!({"error": "invalid_token", "error_description": "Missing access token"}),
                ));
        }
    };

    let token_result = token_actor
        .route(&token_str)
        .send(ValidateToken {
            token: token_str,
            span: tracing::Span::current(),
        })
        .await
        .map_err(actix_web::error::ErrorInternalServerError)?;

    match token_result {
        Ok(token) => {
            let Some(subject) = token.user_id.clone() else {
                return Ok(HttpResponse::Unauthorized()
                    .insert_header(("WWW-Authenticate", "Bearer error=\"invalid_token\""))
                    .json(json!({
                        "error": "invalid_token",
                        "error_description": "Access token does not represent an authenticated user"
                    })));
            };

            let scopes: Vec<&str> = token.scope.split_whitespace().collect();

            // Look up real user claims from storage when available.
            let user = if let Some(ref storage) = storage {
                storage.get_user_by_id(&subject).await.ok().flatten()
            } else {
                None
            };

            let mut response = serde_json::Map::new();
            response.insert("sub".into(), json!(subject));
            response.insert("iss".into(), json!(oidc.issuer));
            response.insert("aud".into(), json!(token.client_id));

            // Scope-gated claims (OIDC Core §5.4)
            // Only include claims when we have real user data — never return placeholders.
            if let Some(ref u) = user {
                if scopes.contains(&"email") {
                    response.insert("email".into(), json!(u.email));
                }

                if scopes.contains(&"profile") {
                    response.insert("preferred_username".into(), json!(u.username));
                }
            }

            Ok(HttpResponse::Ok().json(serde_json::Value::Object(response)))
        }
        Err(_) => Ok(HttpResponse::Unauthorized()
            .insert_header(("WWW-Authenticate", "Bearer error=\"invalid_token\""))
            .json(json!({"error": "invalid_token", "error_description": "Invalid or expired access token"}))),
    }
}

/// RFC 9728: OAuth 2.0 Protected Resource Metadata endpoint.
///
/// Advertises the resource server's capabilities so clients can discover
/// accepted token types, required token binding, and authorization servers.
pub async fn protected_resource_metadata(oidc: web::Data<OidcConfig>) -> Result<HttpResponse> {
    let base = oidc.issuer.trim_end_matches('/');
    let metadata = json!({
        "resource": base,
        "authorization_servers": [base],
        "bearer_methods_supported": ["header"],
        // RFC 9449: announce DPoP support
        "dpop_signing_alg_values_supported": ["ES256", "RS256"],
        // RFC 8705: mTLS token binding is supported
        "tls_client_certificate_bound_access_tokens": true,
        "token_introspection_endpoint": format!("{}/oauth/introspect", base),
        "jwks_uri": format!("{}/.well-known/jwks.json", base),
        "scopes_supported": ["openid", "profile", "email", "read", "write", "admin"]
    });
    Ok(HttpResponse::Ok()
        .insert_header(("Cache-Control", "public, max-age=3600"))
        .json(metadata))
}

/// Token Status List endpoint (draft-ietf-oauth-status-list).
///
/// Returns a compact status list for active tokens. This is a minimal
/// placeholder implementation that advertises support without issuing
/// actual status list JWTs (full implementation requires a status list registry).
pub async fn token_status_list(oidc: web::Data<OidcConfig>) -> Result<HttpResponse> {
    let base = oidc.issuer.trim_end_matches('/');
    // Minimal status list response: all tokens are valid (bits = all-zeros bit array).
    // In production this would be generated from the revocation store.
    let response = json!({
        "status_list": {
            "bits": 1,
            "lst": "eNrb2FgAAQABAAE"  // base64url of a minimal all-valid bit array
        },
        "issuer": base,
        "status_list_uri": format!("{}/.well-known/oauth-authorization-server/status", base)
    });
    Ok(HttpResponse::Ok()
        .content_type("application/json")
        .json(response))
}
