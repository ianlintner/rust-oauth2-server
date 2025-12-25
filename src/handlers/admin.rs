use crate::db::Database;
use crate::metrics::Metrics;
use actix_web::{web, HttpResponse, Result};
use serde::Serialize;
use std::sync::Arc;

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
pub async fn dashboard(_db: web::Data<Arc<Database>>) -> Result<HttpResponse> {
    // In a real implementation, fetch actual stats from database
    let data = DashboardData {
        total_clients: 0,
        total_users: 0,
        total_tokens: 0,
        active_tokens: 0,
    };

    Ok(HttpResponse::Ok().json(data))
}

/// List all registered clients
pub async fn list_clients(_db: web::Data<Arc<Database>>) -> Result<HttpResponse> {
    // In a real implementation, fetch from database
    let clients: Vec<ClientInfo> = vec![];
    Ok(HttpResponse::Ok().json(clients))
}

/// List all active tokens
pub async fn list_tokens(_db: web::Data<Arc<Database>>) -> Result<HttpResponse> {
    // In a real implementation, fetch from database
    let tokens: Vec<TokenInfo> = vec![];
    Ok(HttpResponse::Ok().json(tokens))
}

/// Revoke a token by ID (admin function)
pub async fn admin_revoke_token(
    token_id: web::Path<String>,
    db: web::Data<Arc<Database>>,
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
    _db: web::Data<Arc<Database>>,
) -> Result<HttpResponse> {
    // In a real implementation, delete client and associated tokens
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "message": "Client deleted successfully"
    })))
}

/// Get system metrics
pub async fn system_metrics(metrics: web::Data<Metrics>) -> Result<HttpResponse> {
    use prometheus::Encoder;
    let encoder = prometheus::TextEncoder::new();
    let metric_families = metrics.registry.gather();
    let mut buffer = vec![];
    encoder.encode(&metric_families, &mut buffer).unwrap();

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
pub async fn readiness(_db: web::Data<Arc<Database>>) -> Result<HttpResponse> {
    // Check database connectivity
    // In a real implementation, execute a simple query

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "status": "ready",
        "checks": {
            "database": "ok"
        }
    })))
}
