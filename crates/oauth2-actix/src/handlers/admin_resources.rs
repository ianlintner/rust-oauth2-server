//! Admin CRUD for the protected resources registry (RFC 8707 / RFC 9728),
//! used by agent / A2A OAuth flows to validate the `resource` parameter and
//! advertise per-resource metadata.

use actix_web::{web, HttpResponse, Result};
use serde::{Deserialize, Serialize};

use oauth2_core::ProtectedResource;
use oauth2_ports::DynStorage;

#[derive(Serialize)]
pub struct ResourceResponse {
    pub id: String,
    pub resource_uri: String,
    pub name: String,
    pub scopes: Vec<String>,
    pub authorization_details_types: Vec<String>,
    pub txn_challenge_jwks_uri: String,
    pub created_at: String,
    pub updated_at: String,
}

impl From<ProtectedResource> for ResourceResponse {
    fn from(r: ProtectedResource) -> Self {
        Self {
            id: r.id.clone(),
            resource_uri: r.resource_uri.clone(),
            name: r.name.clone(),
            scopes: r.scopes_vec(),
            authorization_details_types: r.authorization_details_types_vec(),
            txn_challenge_jwks_uri: r.txn_challenge_jwks_uri.clone(),
            created_at: r.created_at.to_rfc3339(),
            updated_at: r.updated_at.to_rfc3339(),
        }
    }
}

/// `GET /admin/resources` — list all registered protected resources.
pub async fn list_resources(db: web::Data<DynStorage>) -> Result<HttpResponse> {
    let resources = db
        .list_resources()
        .await
        .map_err(actix_web::error::ErrorInternalServerError)?;

    let items: Vec<ResourceResponse> = resources.into_iter().map(ResourceResponse::from).collect();
    Ok(HttpResponse::Ok().json(serde_json::json!({ "resources": items })))
}

#[derive(Deserialize)]
pub struct CreateResourceRequest {
    pub resource_uri: String,
    pub name: String,
    #[serde(default)]
    pub scopes: Vec<String>,
    #[serde(default)]
    pub authorization_details_types: Vec<String>,
    #[serde(default)]
    pub txn_challenge_jwks_uri: String,
}

/// `POST /admin/resources` — register a new protected resource.
pub async fn create_resource(
    db: web::Data<DynStorage>,
    body: web::Json<CreateResourceRequest>,
) -> Result<HttpResponse> {
    let body = body.into_inner();

    if let Err(e) = ProtectedResource::validate_uri(&body.resource_uri) {
        return Ok(HttpResponse::BadRequest().json(e));
    }

    if body.name.trim().is_empty() {
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "error": "invalid_request",
            "error_description": "name is required"
        })));
    }

    let mut resource = ProtectedResource::new(body.resource_uri, body.name, body.scopes);
    resource.authorization_details_types = serde_json::to_string(&body.authorization_details_types)
        .unwrap_or_else(|_| "[]".to_string());
    resource.txn_challenge_jwks_uri = body.txn_challenge_jwks_uri;

    db.save_resource(&resource)
        .await
        .map_err(actix_web::error::ErrorInternalServerError)?;

    Ok(HttpResponse::Created().json(ResourceResponse::from(resource)))
}

/// `DELETE /admin/resources/{id}` — remove a registered protected resource.
pub async fn delete_resource(
    db: web::Data<DynStorage>,
    path: web::Path<String>,
) -> Result<HttpResponse> {
    let id = path.into_inner();
    db.delete_resource(&id)
        .await
        .map_err(actix_web::error::ErrorInternalServerError)?;
    Ok(HttpResponse::NoContent().finish())
}
