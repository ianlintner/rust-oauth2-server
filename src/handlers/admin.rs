use crate::metrics::Metrics;
use crate::storage::DynStorage;
use actix_web::{web, HttpResponse, Result};
use serde::Serialize;

#[derive(Serialize)]
pub struct DashboardData {
    pub total_clients: i64,
    pub total_users: i64,
    pub total_tokens: i64,
    pub active_tokens: i64,
}

#[derive(Serialize)]
pub struct ClientInfo {
    pub client_id: String,
    pub name: String,
    pub created_at: String,
}

#[derive(Serialize)]
pub struct TokenInfo {
    pub id: String,
    pub client_id: String,
    pub user_id: String,
    pub scope: String,
    pub expires_at: String,
    pub revoked: bool,
}

/// Admin dashboard - shows overview statistics
pub async fn dashboard(_db: web::Data<DynStorage>) -> Result<HttpResponse> {
    // In a real implementation, fetch actual stats from storage.
    let data = DashboardData {
        total_clients: 0,
        total_users: 0,
        total_tokens: 0,
        active_tokens: 0,
    };

    Ok(HttpResponse::Ok().json(data))
}

/// List all registered clients
pub async fn list_clients(_db: web::Data<DynStorage>) -> Result<HttpResponse> {
    // In a real implementation, fetch from storage.
    let clients: Vec<ClientInfo> = vec![];
    Ok(HttpResponse::Ok().json(clients))
}

/// List all active tokens
pub async fn list_tokens(_db: web::Data<DynStorage>) -> Result<HttpResponse> {
    // In a real implementation, fetch from storage.
    let tokens: Vec<TokenInfo> = vec![];
    Ok(HttpResponse::Ok().json(tokens))
}

/// Revoke a token by ID (admin function)
pub async fn admin_revoke_token(
    token_id: web::Path<String>,
    db: web::Data<DynStorage>,
) -> Result<HttpResponse> {
    // Revoke token
    db.revoke_token(&token_id)
        .await
        .map_err(actix_web::error::ErrorInternalServerError)?;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "message": "Token revoked successfully"
    })))
}

/// Delete a client (admin function)
pub async fn delete_client(
    _client_id: web::Path<String>,
    _db: web::Data<DynStorage>,
) -> Result<HttpResponse> {
    // In a real implementation, delete client and associated tokens
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "message": "Client deleted successfully"
    })))
}

/// Get system metrics
pub async fn system_metrics(metrics: web::Data<Metrics>) -> Result<HttpResponse> {
    let buffer = oauth2_observability::encode_prometheus_text(&metrics.registry)
        .map_err(actix_web::error::ErrorInternalServerError)?;

    Ok(HttpResponse::Ok()
        .content_type("text/plain; version=0.0.4")
        .body(buffer))
}

/// Health check endpoint
pub async fn health() -> Result<HttpResponse> {
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "status": "healthy",
        "service": "oauth2_server",
        "timestamp": chrono::Utc::now().to_rfc3339()
    })))
}

/// Readiness check endpoint
pub async fn readiness(db: web::Data<DynStorage>) -> Result<HttpResponse> {
    db.healthcheck()
        .await
        .map_err(actix_web::error::ErrorServiceUnavailable)?;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "status": "ready",
        "checks": {
            "database": "ok"
        }
    })))
}
