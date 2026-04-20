use actix_web::{web, HttpResponse, Result};
use serde::Serialize;

use oauth2_core::{ListQuery, Page};
use oauth2_observability::Metrics;
use oauth2_ports::DynStorage;

// --- Response types ---

#[derive(Serialize)]
pub struct DashboardSummary {
    pub total_clients: i64,
    pub public_clients: i64,
    pub confidential_clients: i64,
    pub total_users: i64,
    pub enabled_users: i64,
    pub total_tokens: i64,
    pub active_tokens: i64,
    pub revoked_tokens: i64,
    pub expired_tokens: i64,
    pub pending_device_codes: i64,
}

#[derive(Serialize)]
pub struct ClientInfo {
    pub id: String,
    pub client_id: String,
    pub name: String,
    pub scope: String,
    pub grant_types: String,
    pub token_endpoint_auth_method: String,
    pub redirect_uris: String,
    pub created_at: String,
}

#[derive(Serialize)]
pub struct ClientDetail {
    pub id: String,
    pub client_id: String,
    pub name: String,
    pub scope: String,
    pub grant_types: String,
    pub redirect_uris: String,
    pub token_endpoint_auth_method: String,
    pub response_types: String,
    pub contacts: String,
    pub logo_uri: String,
    pub client_uri: String,
    pub policy_uri: String,
    pub tos_uri: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Serialize)]
pub struct TokenInfo {
    pub id: String,
    pub client_id: String,
    pub user_id: String,
    pub scope: String,
    pub expires_at: String,
    pub created_at: String,
    pub revoked: bool,
    pub expired: bool,
}

#[derive(Serialize)]
pub struct UserInfo {
    pub id: String,
    pub username: String,
    pub email: String,
    pub role: String,
    pub enabled: bool,
    pub created_at: String,
}

#[derive(Serialize)]
pub struct DeviceInfo {
    pub id: String,
    pub device_code: String,
    pub user_code: String,
    pub client_id: String,
    pub scope: String,
    pub created_at: String,
    pub expires_at: String,
    pub approved: bool,
    pub denied: bool,
    pub used: bool,
    pub expired: bool,
    pub user_id: Option<String>,
}

// --- Handlers ---

/// Enhanced dashboard summary with full stats.
pub async fn dashboard(db: web::Data<DynStorage>) -> Result<HttpResponse> {
    let clients = db.list_all_clients().await.unwrap_or_default();
    let users = db.list_all_users().await.unwrap_or_default();
    let tokens = db.list_all_tokens().await.unwrap_or_default();
    let devices = db
        .list_all_device_authorizations()
        .await
        .unwrap_or_default();

    let public_clients = clients.iter().filter(|c| c.is_public()).count() as i64;
    let active_tokens = tokens.iter().filter(|t| t.is_valid()).count() as i64;
    let revoked_tokens = tokens.iter().filter(|t| t.revoked).count() as i64;
    let expired_tokens = tokens
        .iter()
        .filter(|t| t.is_expired() && !t.revoked)
        .count() as i64;
    let pending_device_codes = devices
        .iter()
        .filter(|d| !d.approved && !d.denied && !d.is_expired())
        .count() as i64;

    let summary = DashboardSummary {
        total_clients: clients.len() as i64,
        public_clients,
        confidential_clients: clients.len() as i64 - public_clients,
        total_users: users.len() as i64,
        enabled_users: users.iter().filter(|u| u.enabled).count() as i64,
        total_tokens: tokens.len() as i64,
        active_tokens,
        revoked_tokens,
        expired_tokens,
        pending_device_codes,
    };

    Ok(HttpResponse::Ok().json(summary))
}

/// Paginated client list.
pub async fn list_clients(
    db: web::Data<DynStorage>,
    query: web::Query<ListQuery>,
) -> Result<HttpResponse> {
    let page: Page<_> = db
        .list_clients_page(&query)
        .await
        .map_err(actix_web::error::ErrorInternalServerError)?;

    let items: Vec<ClientInfo> = page
        .items
        .into_iter()
        .map(|c| ClientInfo {
            id: c.id,
            client_id: c.client_id,
            name: c.name,
            scope: c.scope,
            grant_types: c.grant_types,
            token_endpoint_auth_method: c.token_endpoint_auth_method,
            redirect_uris: c.redirect_uris,
            created_at: c.created_at.to_rfc3339(),
        })
        .collect();

    Ok(HttpResponse::Ok().json(Page {
        items,
        total: page.total,
        limit: page.limit,
        offset: page.offset,
    }))
}

/// Single client detail (looked up by internal UUID `id`).
pub async fn get_client(
    client_id: web::Path<String>,
    db: web::Data<DynStorage>,
) -> Result<HttpResponse> {
    let all = db
        .list_all_clients()
        .await
        .map_err(actix_web::error::ErrorInternalServerError)?;
    let c = all.into_iter().find(|c| c.id == client_id.as_str());

    match c {
        None => {
            Ok(HttpResponse::NotFound().json(serde_json::json!({ "error": "client not found" })))
        }
        Some(c) => Ok(HttpResponse::Ok().json(ClientDetail {
            id: c.id,
            client_id: c.client_id,
            name: c.name,
            scope: c.scope,
            grant_types: c.grant_types,
            redirect_uris: c.redirect_uris,
            token_endpoint_auth_method: c.token_endpoint_auth_method,
            response_types: c.response_types,
            contacts: c.contacts,
            logo_uri: c.logo_uri,
            client_uri: c.client_uri,
            policy_uri: c.policy_uri,
            tos_uri: c.tos_uri,
            created_at: c.created_at.to_rfc3339(),
            updated_at: c.updated_at.to_rfc3339(),
        })),
    }
}

/// Delete a client by internal id.
pub async fn delete_client(
    client_id: web::Path<String>,
    db: web::Data<DynStorage>,
) -> Result<HttpResponse> {
    // Resolve internal id → client_id field used by delete_client storage method.
    // The storage trait's delete_client takes the *client_id* string (not the uuid id).
    // The admin UI sends the `id` (uuid). We need to find the client first.
    let all = db
        .list_all_clients()
        .await
        .map_err(actix_web::error::ErrorInternalServerError)?;
    let target = all.iter().find(|c| c.id == client_id.as_str());
    match target {
        None => {
            Ok(HttpResponse::NotFound().json(serde_json::json!({ "error": "client not found" })))
        }
        Some(c) => {
            db.delete_client(&c.client_id)
                .await
                .map_err(actix_web::error::ErrorInternalServerError)?;
            Ok(HttpResponse::Ok().json(serde_json::json!({ "message": "Client deleted" })))
        }
    }
}

/// Paginated token list.
pub async fn list_tokens(
    db: web::Data<DynStorage>,
    query: web::Query<ListQuery>,
) -> Result<HttpResponse> {
    let page: Page<_> = db
        .list_tokens_page(&query)
        .await
        .map_err(actix_web::error::ErrorInternalServerError)?;

    let items: Vec<TokenInfo> = page
        .items
        .into_iter()
        .map(|t| {
            let expired = t.is_expired();
            TokenInfo {
                id: t.id,
                client_id: t.client_id,
                user_id: t.user_id.unwrap_or_default(),
                scope: t.scope,
                expires_at: t.expires_at.to_rfc3339(),
                created_at: t.created_at.to_rfc3339(),
                revoked: t.revoked,
                expired,
            }
        })
        .collect();

    Ok(HttpResponse::Ok().json(Page {
        items,
        total: page.total,
        limit: page.limit,
        offset: page.offset,
    }))
}

/// Single token detail.
pub async fn get_token(
    token_id: web::Path<String>,
    db: web::Data<DynStorage>,
) -> Result<HttpResponse> {
    let all = db
        .list_all_tokens()
        .await
        .map_err(actix_web::error::ErrorInternalServerError)?;
    match all.into_iter().find(|t| t.id == token_id.as_str()) {
        None => {
            Ok(HttpResponse::NotFound().json(serde_json::json!({ "error": "token not found" })))
        }
        Some(t) => {
            let expired = t.is_expired();
            Ok(HttpResponse::Ok().json(TokenInfo {
                id: t.id,
                client_id: t.client_id,
                user_id: t.user_id.unwrap_or_default(),
                scope: t.scope,
                expires_at: t.expires_at.to_rfc3339(),
                created_at: t.created_at.to_rfc3339(),
                revoked: t.revoked,
                expired,
            }))
        }
    }
}

/// Revoke a token by ID (admin action).
pub async fn admin_revoke_token(
    token_id: web::Path<String>,
    db: web::Data<DynStorage>,
) -> Result<HttpResponse> {
    db.revoke_token(&token_id)
        .await
        .map_err(actix_web::error::ErrorInternalServerError)?;

    Ok(HttpResponse::Ok().json(serde_json::json!({ "message": "Token revoked" })))
}

/// Paginated user list.
pub async fn list_users(
    db: web::Data<DynStorage>,
    query: web::Query<ListQuery>,
) -> Result<HttpResponse> {
    let page: Page<_> = db
        .list_users_page(&query)
        .await
        .map_err(actix_web::error::ErrorInternalServerError)?;

    let items: Vec<UserInfo> = page
        .items
        .into_iter()
        .map(|u| UserInfo {
            id: u.id,
            username: u.username,
            email: u.email,
            role: u.role,
            enabled: u.enabled,
            created_at: u.created_at.to_rfc3339(),
        })
        .collect();

    Ok(HttpResponse::Ok().json(Page {
        items,
        total: page.total,
        limit: page.limit,
        offset: page.offset,
    }))
}

/// Single user detail.
pub async fn get_user(
    user_id: web::Path<String>,
    db: web::Data<DynStorage>,
) -> Result<HttpResponse> {
    match db
        .get_user_by_id(&user_id)
        .await
        .map_err(actix_web::error::ErrorInternalServerError)?
    {
        None => Ok(HttpResponse::NotFound().json(serde_json::json!({ "error": "user not found" }))),
        Some(u) => Ok(HttpResponse::Ok().json(UserInfo {
            id: u.id,
            username: u.username,
            email: u.email,
            role: u.role,
            enabled: u.enabled,
            created_at: u.created_at.to_rfc3339(),
        })),
    }
}

/// Paginated device authorization list.
pub async fn list_device_authorizations(
    db: web::Data<DynStorage>,
    query: web::Query<ListQuery>,
) -> Result<HttpResponse> {
    let page: Page<_> = db
        .list_device_authorizations_page(&query)
        .await
        .map_err(actix_web::error::ErrorInternalServerError)?;

    let items: Vec<DeviceInfo> = page
        .items
        .into_iter()
        .map(|d| {
            let expired = d.is_expired();
            DeviceInfo {
                id: d.id,
                device_code: d.device_code,
                user_code: d.user_code,
                client_id: d.client_id,
                scope: d.scope,
                created_at: d.created_at.to_rfc3339(),
                expires_at: d.expires_at.to_rfc3339(),
                approved: d.approved,
                denied: d.denied,
                used: d.used,
                expired,
                user_id: d.user_id,
            }
        })
        .collect();

    Ok(HttpResponse::Ok().json(Page {
        items,
        total: page.total,
        limit: page.limit,
        offset: page.offset,
    }))
}

/// Force-expire a pending device code.
pub async fn expire_device_code(
    device_code: web::Path<String>,
    db: web::Data<DynStorage>,
) -> Result<HttpResponse> {
    db.expire_device_authorization(&device_code)
        .await
        .map_err(actix_web::error::ErrorInternalServerError)?;

    Ok(HttpResponse::Ok().json(serde_json::json!({ "message": "Device code expired" })))
}

/// Server capability flags (used by UI to show/hide feature sections).
#[derive(Serialize)]
pub struct Capabilities {
    pub events: bool,
    pub device_flow: bool,
    pub key_rotation: bool,
    pub user_crud: bool,
    pub client_crud: bool,
    pub denylist: bool,
    pub audit_log: bool,
    pub bulk_revoke: bool,
}

pub async fn capabilities() -> Result<HttpResponse> {
    Ok(HttpResponse::Ok().json(Capabilities {
        events: true,
        device_flow: true,
        key_rotation: true,
        user_crud: true,
        client_crud: true,
        denylist: true,
        audit_log: true,
        bulk_revoke: true,
    }))
}

/// Get system metrics (Prometheus text format).
pub async fn system_metrics(metrics: web::Data<Metrics>) -> Result<HttpResponse> {
    let buffer = oauth2_observability::encode_prometheus_text(&metrics.registry)
        .map_err(actix_web::error::ErrorInternalServerError)?;

    Ok(HttpResponse::Ok()
        .content_type("text/plain; version=0.0.4")
        .body(buffer))
}

/// Health check endpoint.
pub async fn health() -> Result<HttpResponse> {
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "status": "healthy",
        "service": "oauth2_server",
        "timestamp": chrono::Utc::now().to_rfc3339()
    })))
}

/// Readiness check endpoint.
pub async fn readiness(db: web::Data<DynStorage>) -> Result<HttpResponse> {
    db.healthcheck()
        .await
        .map_err(actix_web::error::ErrorServiceUnavailable)?;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "status": "ready",
        "checks": { "database": "ok" }
    })))
}
