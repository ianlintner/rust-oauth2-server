use std::sync::Arc;

use actix_web::{web, HttpRequest, HttpResponse, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use rsa::pkcs1::DecodeRsaPrivateKey;
use rsa::pkcs8::DecodePrivateKey;
use rsa::traits::PublicKeyParts;
use rsa::RsaPrivateKey;
use serde::Deserialize;
use serde_json::json;
use tokio::sync::RwLock;

use oauth2_core::models::key_set::{Algorithm as KeyAlgorithm, KeySet};
use oauth2_core::Claims;

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
pub async fn openid_configuration(oidc: web::Data<OidcConfig>) -> Result<HttpResponse> {
    let base = oidc.issuer.trim_end_matches('/');

    let id_token_algs = if oidc.id_token_alg.eq_ignore_ascii_case("RS256") {
        ["RS256"]
    } else {
        ["HS256"]
    };
    let config = json!({
        "issuer": base,
        "authorization_endpoint": format!("{}/oauth/authorize", base),
        "token_endpoint": format!("{}/oauth/token", base),
        "token_introspection_endpoint": format!("{}/oauth/introspect", base),
        "token_revocation_endpoint": format!("{}/oauth/revoke", base),
        "userinfo_endpoint": format!("{}/oauth/userinfo", base),
        "jwks_uri": format!("{}/.well-known/jwks.json", base),
        "registration_endpoint": format!("{}/admin/clients/register", base),
        "scopes_supported": ["openid", "profile", "email", "read", "write", "admin"],
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "client_credentials"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": id_token_algs,
        "token_endpoint_auth_methods_supported": [
            "client_secret_basic",
            "client_secret_post"
        ],
        "claims_supported": ["sub", "iss", "aud", "exp", "iat", "email", "preferred_username"],
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

/// Query parameters for userinfo (not commonly used, but spec allows GET).
#[derive(Debug, Deserialize)]
pub struct UserinfoQuery {
    pub access_token: Option<String>,
}

/// OIDC UserInfo endpoint – returns claims about the authenticated user.
pub async fn userinfo(
    req: HttpRequest,
    query: web::Query<UserinfoQuery>,
    oidc: web::Data<OidcConfig>,
) -> Result<HttpResponse> {
    // Extract Bearer token from Authorization header or query parameter
    let token_str = req
        .headers()
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(|s| s.to_string())
        .or_else(|| query.access_token.clone());

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

    // Decode the access token JWT against the keyset
    let keyset_read = if let Some(ks) = req.app_data::<web::Data<Arc<RwLock<KeySet>>>>() {
        Some(ks.read().await)
    } else {
        None
    };

    let claims_result = if let Some(ref ks) = keyset_read {
        Claims::decode_with_keyset(&token_str, ks)
    } else {
        // Fallback to single-secret decode
        Claims::decode(&token_str, &oidc.jwt_secret)
    };

    match claims_result {
        Ok(claims) => {
            let response = json!({
                "sub": claims.sub,
                "iss": oidc.issuer,
                "aud": claims.aud,
                "scope": claims.scope,
                "preferred_username": claims.sub,
                "email": format!("{}@placeholder.local", claims.sub),
            });
            Ok(HttpResponse::Ok().json(response))
        }
        Err(_) => Ok(HttpResponse::Unauthorized()
            .insert_header(("WWW-Authenticate", "Bearer error=\"invalid_token\""))
            .json(json!({"error": "invalid_token", "error_description": "Invalid or expired access token"}))),
    }
}
