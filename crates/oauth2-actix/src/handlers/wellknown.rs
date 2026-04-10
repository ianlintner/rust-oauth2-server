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
        "jwks_uri": format!("{}/.well-known/jwks.json", base),
        "registration_endpoint": format!("{}/admin/clients/register", base),
        "scopes_supported": ["openid", "profile", "email", "read", "write", "admin"],
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "client_credentials", "refresh_token"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": id_token_algs,
        "token_endpoint_auth_methods_supported": [
            "client_secret_basic",
            "client_secret_post"
        ],
        "claims_supported": ["sub", "iss", "aud", "exp", "iat", "nonce", "at_hash", "c_hash", "email", "preferred_username"],
        "code_challenge_methods_supported": ["S256"],
        "service_documentation": format!("{}/docs", base)
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

            let response = json!({
                "sub": subject,
                "iss": oidc.issuer,
                "aud": token.client_id,
                "scope": token.scope,
                "preferred_username": token.user_id,
                "email": format!("{}@placeholder.local", subject),
            });
            Ok(HttpResponse::Ok().json(response))
        }
        Err(_) => Ok(HttpResponse::Unauthorized()
            .insert_header(("WWW-Authenticate", "Bearer error=\"invalid_token\""))
            .json(json!({"error": "invalid_token", "error_description": "Invalid or expired access token"}))),
    }
}
