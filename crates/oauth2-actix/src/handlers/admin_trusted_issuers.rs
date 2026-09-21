//! Admin endpoints for the trusted issuers registry.
//!
//! Trusted issuers back the `urn:ietf:params:oauth:grant-type:jwt-bearer`
//! grant (RFC 7523) used by agent / A2A OAuth flows: each row describes an
//! external issuer whose signed JWTs may be exchanged for a local token.

use actix_web::{web, HttpResponse, Result};
use serde::Deserialize;
use url::Url;

use oauth2_core::TrustedIssuer;
use oauth2_ports::DynStorage;

const ALLOWED_SUBJECT_MAPPINGS: &[&str] = &["sub", "email"];

/// Validate that `jwks_uri` is a well-formed, `https`-only URL with a host
/// and no fragment. Rejects `http://`, `file://`, and malformed values to
/// close an SSRF / MITM signature-verification gap: this URI is later
/// fetched to obtain the keys used to verify JWT-bearer assertions.
fn validate_jwks_uri(uri: &str) -> Result<(), String> {
    let parsed = Url::parse(uri).map_err(|_| "jwks_uri must be a valid URL".to_string())?;

    if parsed.scheme() != "https" {
        return Err("jwks_uri must use the https scheme".to_string());
    }

    if parsed.host_str().unwrap_or("").is_empty() {
        return Err("jwks_uri must include a host".to_string());
    }

    if parsed.fragment().is_some() {
        return Err("jwks_uri must not contain a fragment".to_string());
    }

    Ok(())
}

#[derive(Deserialize)]
pub struct CreateTrustedIssuerRequest {
    pub issuer: String,
    pub jwks_uri: String,
    #[serde(default)]
    pub allowed_audiences: Option<Vec<String>>,
    #[serde(default)]
    pub subject_mapping: Option<String>,
    #[serde(default)]
    pub jit_provision: Option<bool>,
    #[serde(default)]
    pub allowed_client_ids: Option<Vec<String>>,
}

/// `GET /admin/trusted-issuers` — list all registered trusted issuers.
pub async fn list_trusted_issuers(db: web::Data<DynStorage>) -> Result<HttpResponse> {
    let items = db
        .list_trusted_issuers()
        .await
        .map_err(actix_web::error::ErrorInternalServerError)?;

    Ok(HttpResponse::Ok().json(serde_json::json!({ "trusted_issuers": items })))
}

/// `POST /admin/trusted-issuers` — register a new trusted issuer.
pub async fn create_trusted_issuer(
    db: web::Data<DynStorage>,
    body: web::Json<CreateTrustedIssuerRequest>,
) -> Result<HttpResponse> {
    let body = body.into_inner();

    if body.issuer.trim().is_empty() || body.jwks_uri.trim().is_empty() {
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "error": "invalid_request",
            "error_description": "issuer and jwks_uri are required"
        })));
    }

    if let Err(description) = validate_jwks_uri(&body.jwks_uri) {
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "error": "invalid_request",
            "error_description": description
        })));
    }

    let subject_mapping = body.subject_mapping.unwrap_or_else(|| "sub".to_string());
    if !ALLOWED_SUBJECT_MAPPINGS.contains(&subject_mapping.as_str()) {
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "error": "invalid_request",
            "error_description": format!(
                "subject_mapping must be one of: {}",
                ALLOWED_SUBJECT_MAPPINGS.join(", ")
            )
        })));
    }

    let mut trusted_issuer = TrustedIssuer::new(body.issuer, body.jwks_uri);
    trusted_issuer.subject_mapping = subject_mapping;
    if let Some(audiences) = body.allowed_audiences {
        trusted_issuer.allowed_audiences =
            serde_json::to_string(&audiences).unwrap_or_else(|_| "[]".to_string());
    }
    if let Some(jit) = body.jit_provision {
        trusted_issuer.jit_provision = jit;
    }
    if let Some(client_ids) = body.allowed_client_ids {
        trusted_issuer.allowed_client_ids =
            serde_json::to_string(&client_ids).unwrap_or_else(|_| "[]".to_string());
    }

    db.save_trusted_issuer(&trusted_issuer)
        .await
        .map_err(actix_web::error::ErrorInternalServerError)?;

    Ok(HttpResponse::Created().json(trusted_issuer))
}

/// `DELETE /admin/trusted-issuers/{id}` — remove a trusted issuer.
pub async fn delete_trusted_issuer(
    db: web::Data<DynStorage>,
    path: web::Path<String>,
) -> Result<HttpResponse> {
    let id = path.into_inner();
    db.delete_trusted_issuer(&id)
        .await
        .map_err(actix_web::error::ErrorInternalServerError)?;

    Ok(HttpResponse::Ok().json(serde_json::json!({ "message": "Trusted issuer deleted" })))
}
