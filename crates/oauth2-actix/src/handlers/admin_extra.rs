//! Extended admin handlers: user CRUD, client CRUD extensions,
//! denylist management, audit log, and bulk token operations.

use actix_session::SessionExt;
use actix_web::{web, HttpRequest, HttpResponse, Result};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use oauth2_core::{
    AuditLogEntry, Client, ClientRegistration, DenylistEntry, ListQuery, Page, User,
};
use oauth2_ports::DynStorage;

use super::events::RecentEventsStore;
use super::login::hash_password;

// --- Audit helper -----------------------------------------------------------

/// Build an `AuditLogEntry` seeded from the request (session actor, IP, UA).
pub fn build_audit(
    req: &HttpRequest,
    action: &str,
    target_kind: &str,
    target_id: &str,
    metadata: serde_json::Value,
) -> AuditLogEntry {
    let session = req.get_session();
    let actor_id: String = session.get("user_id").unwrap_or(None).unwrap_or_default();
    let actor_email: String = session.get("email").unwrap_or(None).unwrap_or_default();
    let ip = req
        .connection_info()
        .realip_remote_addr()
        .unwrap_or("")
        .to_string();
    let user_agent = req
        .headers()
        .get("User-Agent")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("")
        .to_string();

    AuditLogEntry::new(&actor_id, &actor_email, action)
        .with_target(target_kind, target_id)
        .with_request_meta(&ip, &user_agent)
        .with_metadata_json(metadata)
}

/// Write an audit log entry and mirror it into the in-memory recent-events
/// ring buffer so admin mutations show up on the dashboard Events tab.
///
/// Errors are logged but never surfaced to the caller — audit failures must
/// not block the original admin action.
async fn record_audit(db: &DynStorage, store: &RecentEventsStore, entry: AuditLogEntry) {
    if let Err(e) = db.write_audit_log(&entry).await {
        tracing::warn!(error = %e, action = %entry.action, "Failed to write audit log");
    }

    // Metadata is stored as a JSON string; re-parse so consumers see structured fields.
    let metadata: serde_json::Value = serde_json::from_str(&entry.metadata)
        .unwrap_or_else(|_| serde_json::Value::String(entry.metadata.clone()));

    let envelope = serde_json::json!({
        "event_type": entry.action,
        "source": "admin",
        "idempotency_key": entry.id,
        "received_at": entry.created_at.to_rfc3339(),
        "actor_id": entry.actor_id,
        "actor_email": entry.actor_email,
        "target_kind": entry.target_kind,
        "target_id": entry.target_id,
        "metadata": metadata,
    });
    store.push(envelope).await;
}

// --- User CRUD --------------------------------------------------------------

#[derive(Deserialize)]
pub struct CreateUserRequest {
    pub username: String,
    pub email: String,
    pub password: String,
    #[serde(default)]
    pub role: Option<String>,
    #[serde(default)]
    pub enabled: Option<bool>,
}

#[derive(Serialize)]
pub struct UserResponse {
    pub id: String,
    pub username: String,
    pub email: String,
    pub role: String,
    pub enabled: bool,
    pub created_at: String,
    pub updated_at: String,
}

impl From<User> for UserResponse {
    fn from(u: User) -> Self {
        Self {
            id: u.id,
            username: u.username,
            email: u.email,
            role: u.role,
            enabled: u.enabled,
            created_at: u.created_at.to_rfc3339(),
            updated_at: u.updated_at.to_rfc3339(),
        }
    }
}

pub async fn create_user(
    req: HttpRequest,
    db: web::Data<DynStorage>,
    events_store: web::Data<RecentEventsStore>,
    body: web::Json<CreateUserRequest>,
) -> Result<HttpResponse> {
    let CreateUserRequest {
        username,
        email,
        password,
        role,
        enabled,
    } = body.into_inner();

    if username.is_empty() || email.is_empty() || password.is_empty() {
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "error": "invalid_request",
            "error_description": "username, email, password are required"
        })));
    }

    if let Ok(Some(_)) = db.get_user_by_username(&username).await {
        return Ok(HttpResponse::Conflict().json(serde_json::json!({
            "error": "already_exists",
            "error_description": "username already registered"
        })));
    }

    let hash = hash_password(&password).map_err(|e| {
        tracing::error!(error = %e, "hash_password failed");
        actix_web::error::ErrorInternalServerError("failed to hash password")
    })?;

    let mut user = User::new(username, hash, email);
    if let Some(r) = role {
        if r == "admin" || r == "user" {
            user.role = r;
        }
    }
    if let Some(e) = enabled {
        user.enabled = e;
    }

    db.save_user(&user)
        .await
        .map_err(actix_web::error::ErrorInternalServerError)?;

    let audit = build_audit(
        &req,
        "user.create",
        "user",
        &user.id,
        serde_json::json!({
            "username": user.username,
            "email": user.email,
            "role": user.role,
            "enabled": user.enabled,
        }),
    );
    record_audit(db.as_ref(), events_store.as_ref(), audit).await;

    Ok(HttpResponse::Created().json(UserResponse::from(user)))
}

#[derive(Deserialize)]
pub struct UpdateUserRequest {
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub role: Option<String>,
    #[serde(default)]
    pub enabled: Option<bool>,
}

pub async fn update_user(
    req: HttpRequest,
    path: web::Path<String>,
    db: web::Data<DynStorage>,
    events_store: web::Data<RecentEventsStore>,
    body: web::Json<UpdateUserRequest>,
) -> Result<HttpResponse> {
    let user_id = path.into_inner();
    let mut user = match db
        .get_user_by_id(&user_id)
        .await
        .map_err(actix_web::error::ErrorInternalServerError)?
    {
        None => {
            return Ok(
                HttpResponse::NotFound().json(serde_json::json!({ "error": "user not found" }))
            )
        }
        Some(u) => u,
    };

    if let Some(e) = &body.email {
        user.email = e.clone();
    }
    if let Some(r) = &body.role {
        if r == "admin" || r == "user" {
            user.role = r.clone();
        }
    }
    if let Some(en) = body.enabled {
        user.enabled = en;
    }
    user.updated_at = Utc::now();

    db.update_user(&user)
        .await
        .map_err(actix_web::error::ErrorInternalServerError)?;

    let audit = build_audit(
        &req,
        "user.update",
        "user",
        &user.id,
        serde_json::json!({
            "email": body.email,
            "role": body.role,
            "enabled": body.enabled,
        }),
    );
    record_audit(db.as_ref(), events_store.as_ref(), audit).await;

    Ok(HttpResponse::Ok().json(UserResponse::from(user)))
}

pub async fn delete_user(
    req: HttpRequest,
    path: web::Path<String>,
    db: web::Data<DynStorage>,
    events_store: web::Data<RecentEventsStore>,
) -> Result<HttpResponse> {
    let user_id = path.into_inner();
    if db
        .get_user_by_id(&user_id)
        .await
        .map_err(actix_web::error::ErrorInternalServerError)?
        .is_none()
    {
        return Ok(HttpResponse::NotFound().json(serde_json::json!({ "error": "user not found" })));
    }
    db.delete_user(&user_id)
        .await
        .map_err(actix_web::error::ErrorInternalServerError)?;
    let _ = db.revoke_tokens_by_user_id(&user_id).await;

    let audit = build_audit(&req, "user.delete", "user", &user_id, serde_json::json!({}));
    record_audit(db.as_ref(), events_store.as_ref(), audit).await;

    Ok(HttpResponse::Ok().json(serde_json::json!({ "message": "User deleted" })))
}

#[derive(Deserialize)]
pub struct SetEnabledRequest {
    pub enabled: bool,
}

pub async fn set_user_enabled(
    req: HttpRequest,
    path: web::Path<String>,
    db: web::Data<DynStorage>,
    events_store: web::Data<RecentEventsStore>,
    body: web::Json<SetEnabledRequest>,
) -> Result<HttpResponse> {
    let user_id = path.into_inner();
    db.set_user_enabled(&user_id, body.enabled)
        .await
        .map_err(actix_web::error::ErrorInternalServerError)?;
    if !body.enabled {
        let _ = db.revoke_tokens_by_user_id(&user_id).await;
    }

    let audit = build_audit(
        &req,
        if body.enabled {
            "user.enable"
        } else {
            "user.disable"
        },
        "user",
        &user_id,
        serde_json::json!({ "enabled": body.enabled }),
    );
    record_audit(db.as_ref(), events_store.as_ref(), audit).await;

    Ok(HttpResponse::Ok().json(serde_json::json!({ "enabled": body.enabled })))
}

#[derive(Deserialize)]
pub struct SetRoleRequest {
    pub role: String,
}

pub async fn set_user_role(
    req: HttpRequest,
    path: web::Path<String>,
    db: web::Data<DynStorage>,
    events_store: web::Data<RecentEventsStore>,
    body: web::Json<SetRoleRequest>,
) -> Result<HttpResponse> {
    let user_id = path.into_inner();
    let role = body.role.clone();
    if role != "admin" && role != "user" {
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "error": "invalid_request",
            "error_description": "role must be 'admin' or 'user'"
        })));
    }
    db.set_user_role(&user_id, &role)
        .await
        .map_err(actix_web::error::ErrorInternalServerError)?;

    let audit = build_audit(
        &req,
        "user.set_role",
        "user",
        &user_id,
        serde_json::json!({ "role": role }),
    );
    record_audit(db.as_ref(), events_store.as_ref(), audit).await;

    Ok(HttpResponse::Ok().json(serde_json::json!({ "role": role })))
}

#[derive(Deserialize)]
pub struct ResetPasswordRequest {
    pub password: String,
}

pub async fn reset_user_password(
    req: HttpRequest,
    path: web::Path<String>,
    db: web::Data<DynStorage>,
    events_store: web::Data<RecentEventsStore>,
    body: web::Json<ResetPasswordRequest>,
) -> Result<HttpResponse> {
    let user_id = path.into_inner();
    if body.password.len() < 8 {
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "error": "weak_password",
            "error_description": "password must be at least 8 characters"
        })));
    }
    let hash = hash_password(&body.password).map_err(|e| {
        tracing::error!(error = %e, "hash_password failed");
        actix_web::error::ErrorInternalServerError("failed to hash password")
    })?;
    db.set_user_password_hash(&user_id, &hash)
        .await
        .map_err(actix_web::error::ErrorInternalServerError)?;
    let _ = db.revoke_tokens_by_user_id(&user_id).await;

    let audit = build_audit(
        &req,
        "user.reset_password",
        "user",
        &user_id,
        serde_json::json!({}),
    );
    record_audit(db.as_ref(), events_store.as_ref(), audit).await;

    Ok(HttpResponse::Ok().json(serde_json::json!({ "message": "Password reset" })))
}

// --- Client CRUD extensions -------------------------------------------------

/// Full client create payload (admin). Mirrors RFC 7591 client registration
/// but lets admins set arbitrary fields including `client_id`/`client_secret`.
#[derive(Deserialize)]
pub struct CreateClientRequest {
    pub name: String,
    #[serde(default)]
    pub client_id: Option<String>,
    #[serde(default)]
    pub client_secret: Option<String>,
    #[serde(default)]
    pub redirect_uris: Vec<String>,
    #[serde(default)]
    pub grant_types: Vec<String>,
    #[serde(default)]
    pub scope: String,
    #[serde(default = "default_auth_method")]
    pub token_endpoint_auth_method: String,
}

fn default_auth_method() -> String {
    "client_secret_basic".to_string()
}

pub async fn create_client(
    req: HttpRequest,
    db: web::Data<DynStorage>,
    events_store: web::Data<RecentEventsStore>,
    body: web::Json<CreateClientRequest>,
) -> Result<HttpResponse> {
    let body = body.into_inner();
    if body.name.is_empty() {
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "error": "invalid_request",
            "error_description": "name is required"
        })));
    }

    let client_id = body
        .client_id
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| format!("client-{}", &Uuid::new_v4().to_string()[..12]));
    let is_public = body.token_endpoint_auth_method == "none";
    let client_secret = if is_public {
        String::new()
    } else {
        body.client_secret
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| Uuid::new_v4().to_string().replace('-', ""))
    };
    let grant_types = if body.grant_types.is_empty() {
        vec![
            "authorization_code".to_string(),
            "refresh_token".to_string(),
        ]
    } else {
        body.grant_types
    };

    let mut client = Client::new(
        client_id.clone(),
        client_secret,
        body.redirect_uris,
        grant_types,
        body.scope,
        body.name.clone(),
    );
    client.token_endpoint_auth_method = body.token_endpoint_auth_method;
    // Preserve the ClientRegistrationResponse shape consumers rely on.
    let _ = ClientRegistration {
        client_name: body.name,
        redirect_uris: client.get_redirect_uris(),
        grant_types: client.get_grant_types(),
        scope: client.scope.clone(),
        token_endpoint_auth_method: client.token_endpoint_auth_method.clone(),
        response_types: client.get_response_types(),
        contacts: vec![],
        logo_uri: None,
        client_uri: None,
        policy_uri: None,
        tos_uri: None,
        jwks: None,
        jwks_uri: None,
        backchannel_logout_uri: None,
        backchannel_logout_session_required: None,
        frontchannel_logout_uri: None,
        frontchannel_logout_session_required: None,
        post_logout_redirect_uris: None,
    };

    db.save_client(&client)
        .await
        .map_err(actix_web::error::ErrorInternalServerError)?;

    let audit = build_audit(
        &req,
        "client.create",
        "client",
        &client.client_id,
        serde_json::json!({
            "name": client.name,
            "token_endpoint_auth_method": client.token_endpoint_auth_method,
            "grant_types": client.get_grant_types(),
        }),
    );
    record_audit(db.as_ref(), events_store.as_ref(), audit).await;

    // Return secret exactly once on creation.
    Ok(HttpResponse::Created().json(serde_json::json!({
        "id": client.id,
        "client_id": client.client_id,
        "client_secret": if client.is_public() { None } else { Some(client.client_secret.clone()) },
        "name": client.name,
        "redirect_uris": client.get_redirect_uris(),
        "grant_types": client.get_grant_types(),
        "scope": client.scope,
        "token_endpoint_auth_method": client.token_endpoint_auth_method,
        "enabled": client.enabled,
        "created_at": client.created_at.to_rfc3339(),
    })))
}

#[derive(Deserialize)]
pub struct UpdateClientRequest {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub redirect_uris: Option<Vec<String>>,
    #[serde(default)]
    pub grant_types: Option<Vec<String>>,
    #[serde(default)]
    pub scope: Option<String>,
    #[serde(default)]
    pub token_endpoint_auth_method: Option<String>,
    #[serde(default)]
    pub enabled: Option<bool>,
}

/// PUT /admin/api/clients/{id} — id is the internal uuid.
pub async fn update_client(
    req: HttpRequest,
    path: web::Path<String>,
    db: web::Data<DynStorage>,
    events_store: web::Data<RecentEventsStore>,
    body: web::Json<UpdateClientRequest>,
) -> Result<HttpResponse> {
    let id = path.into_inner();
    let all = db
        .list_all_clients()
        .await
        .map_err(actix_web::error::ErrorInternalServerError)?;
    let mut client = match all.into_iter().find(|c| c.id == id) {
        None => {
            return Ok(
                HttpResponse::NotFound().json(serde_json::json!({ "error": "client not found" }))
            )
        }
        Some(c) => c,
    };

    if let Some(name) = &body.name {
        client.name = name.clone();
    }
    if let Some(uris) = &body.redirect_uris {
        client.redirect_uris = serde_json::to_string(uris).unwrap_or_else(|_| "[]".to_string());
    }
    if let Some(gts) = &body.grant_types {
        client.grant_types = serde_json::to_string(gts).unwrap_or_else(|_| "[]".to_string());
    }
    if let Some(scope) = &body.scope {
        client.scope = scope.clone();
    }
    if let Some(method) = &body.token_endpoint_auth_method {
        client.token_endpoint_auth_method = method.clone();
    }
    if let Some(en) = body.enabled {
        client.enabled = en;
    }
    client.updated_at = Utc::now();

    db.update_client(&client)
        .await
        .map_err(actix_web::error::ErrorInternalServerError)?;

    let audit = build_audit(
        &req,
        "client.update",
        "client",
        &client.client_id,
        serde_json::json!({
            "name": body.name,
            "enabled": body.enabled,
        }),
    );
    record_audit(db.as_ref(), events_store.as_ref(), audit).await;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "id": client.id,
        "client_id": client.client_id,
        "name": client.name,
        "enabled": client.enabled,
        "updated_at": client.updated_at.to_rfc3339(),
    })))
}

pub async fn set_client_enabled(
    req: HttpRequest,
    path: web::Path<String>,
    db: web::Data<DynStorage>,
    events_store: web::Data<RecentEventsStore>,
    body: web::Json<SetEnabledRequest>,
) -> Result<HttpResponse> {
    // Resolve internal id → client_id (same pattern as delete_client).
    let all = db
        .list_all_clients()
        .await
        .map_err(actix_web::error::ErrorInternalServerError)?;
    let target = match all.into_iter().find(|c| c.id == *path) {
        None => {
            return Ok(
                HttpResponse::NotFound().json(serde_json::json!({ "error": "client not found" }))
            )
        }
        Some(c) => c,
    };
    db.set_client_enabled(&target.client_id, body.enabled)
        .await
        .map_err(actix_web::error::ErrorInternalServerError)?;
    if !body.enabled {
        let _ = db.revoke_tokens_by_client_id(&target.client_id).await;
    }

    let audit = build_audit(
        &req,
        if body.enabled {
            "client.enable"
        } else {
            "client.disable"
        },
        "client",
        &target.client_id,
        serde_json::json!({ "enabled": body.enabled }),
    );
    record_audit(db.as_ref(), events_store.as_ref(), audit).await;

    Ok(HttpResponse::Ok().json(serde_json::json!({ "enabled": body.enabled })))
}

pub async fn regenerate_client_secret(
    req: HttpRequest,
    path: web::Path<String>,
    db: web::Data<DynStorage>,
    events_store: web::Data<RecentEventsStore>,
) -> Result<HttpResponse> {
    let all = db
        .list_all_clients()
        .await
        .map_err(actix_web::error::ErrorInternalServerError)?;
    let target = match all.into_iter().find(|c| c.id == *path) {
        None => {
            return Ok(
                HttpResponse::NotFound().json(serde_json::json!({ "error": "client not found" }))
            )
        }
        Some(c) => c,
    };
    if target.is_public() {
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "error": "invalid_request",
            "error_description": "public clients have no secret"
        })));
    }
    let new_secret = Uuid::new_v4().to_string().replace('-', "");
    db.set_client_secret(&target.client_id, &new_secret)
        .await
        .map_err(actix_web::error::ErrorInternalServerError)?;

    let audit = build_audit(
        &req,
        "client.regenerate_secret",
        "client",
        &target.client_id,
        serde_json::json!({}),
    );
    record_audit(db.as_ref(), events_store.as_ref(), audit).await;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "client_id": target.client_id,
        "client_secret": new_secret,
    })))
}

// --- Bulk token operations --------------------------------------------------

#[derive(Deserialize)]
pub struct BulkRevokeByUserRequest {
    pub user_id: String,
}

pub async fn bulk_revoke_by_user(
    req: HttpRequest,
    db: web::Data<DynStorage>,
    events_store: web::Data<RecentEventsStore>,
    body: web::Json<BulkRevokeByUserRequest>,
) -> Result<HttpResponse> {
    let count = db
        .revoke_tokens_by_user_id(&body.user_id)
        .await
        .map_err(actix_web::error::ErrorInternalServerError)?;

    let audit = build_audit(
        &req,
        "token.bulk_revoke_by_user",
        "user",
        &body.user_id,
        serde_json::json!({ "revoked": count }),
    );
    record_audit(db.as_ref(), events_store.as_ref(), audit).await;

    Ok(HttpResponse::Ok().json(serde_json::json!({ "revoked": count })))
}

#[derive(Deserialize)]
pub struct BulkRevokeByClientRequest {
    pub client_id: String,
}

pub async fn bulk_revoke_by_client(
    req: HttpRequest,
    db: web::Data<DynStorage>,
    events_store: web::Data<RecentEventsStore>,
    body: web::Json<BulkRevokeByClientRequest>,
) -> Result<HttpResponse> {
    let count = db
        .revoke_tokens_by_client_id(&body.client_id)
        .await
        .map_err(actix_web::error::ErrorInternalServerError)?;

    let audit = build_audit(
        &req,
        "token.bulk_revoke_by_client",
        "client",
        &body.client_id,
        serde_json::json!({ "revoked": count }),
    );
    record_audit(db.as_ref(), events_store.as_ref(), audit).await;

    Ok(HttpResponse::Ok().json(serde_json::json!({ "revoked": count })))
}

// --- Denylist ---------------------------------------------------------------

const ALLOWED_DENYLIST_KINDS: &[&str] = &["ip", "user_id", "username", "email", "client_id"];

#[derive(Deserialize)]
pub struct AddDenylistRequest {
    pub kind: String,
    pub value: String,
    #[serde(default)]
    pub reason: String,
    #[serde(default)]
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Serialize)]
pub struct DenylistResponse {
    pub id: String,
    pub kind: String,
    pub value: String,
    pub reason: String,
    pub created_by: String,
    pub created_at: String,
    pub expires_at: Option<String>,
    pub active: bool,
}

impl From<DenylistEntry> for DenylistResponse {
    fn from(e: DenylistEntry) -> Self {
        let active = e.is_active();
        Self {
            id: e.id,
            kind: e.kind,
            value: e.value,
            reason: e.reason,
            created_by: e.created_by,
            created_at: e.created_at.to_rfc3339(),
            expires_at: e.expires_at.map(|d| d.to_rfc3339()),
            active,
        }
    }
}

pub async fn list_denylist(
    db: web::Data<DynStorage>,
    query: web::Query<ListQuery>,
) -> Result<HttpResponse> {
    let page = db
        .list_denylist(&query)
        .await
        .map_err(actix_web::error::ErrorInternalServerError)?;

    let items: Vec<DenylistResponse> = page.items.into_iter().map(DenylistResponse::from).collect();

    Ok(HttpResponse::Ok().json(Page::new(items, page.total, page.limit, page.offset)))
}

pub async fn add_denylist(
    req: HttpRequest,
    db: web::Data<DynStorage>,
    events_store: web::Data<RecentEventsStore>,
    body: web::Json<AddDenylistRequest>,
) -> Result<HttpResponse> {
    let kind = body.kind.to_lowercase();
    if !ALLOWED_DENYLIST_KINDS.contains(&kind.as_str()) {
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "error": "invalid_request",
            "error_description": format!(
                "kind must be one of: {}",
                ALLOWED_DENYLIST_KINDS.join(", ")
            )
        })));
    }
    if body.value.trim().is_empty() {
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "error": "invalid_request",
            "error_description": "value is required"
        })));
    }

    let session = req.get_session();
    let actor_email: String = session.get("email").unwrap_or(None).unwrap_or_default();

    let mut entry = DenylistEntry::new(&kind, body.value.trim(), &body.reason, &actor_email);
    entry.expires_at = body.expires_at;

    db.add_denylist_entry(&entry)
        .await
        .map_err(actix_web::error::ErrorInternalServerError)?;

    let audit = build_audit(
        &req,
        "denylist.add",
        "denylist",
        &entry.id,
        serde_json::json!({
            "kind": entry.kind,
            "value": entry.value,
            "reason": entry.reason,
        }),
    );
    record_audit(db.as_ref(), events_store.as_ref(), audit).await;

    Ok(HttpResponse::Created().json(DenylistResponse::from(entry)))
}

pub async fn remove_denylist(
    req: HttpRequest,
    path: web::Path<String>,
    db: web::Data<DynStorage>,
    events_store: web::Data<RecentEventsStore>,
) -> Result<HttpResponse> {
    let id = path.into_inner();
    db.remove_denylist_entry(&id)
        .await
        .map_err(actix_web::error::ErrorInternalServerError)?;

    let audit = build_audit(
        &req,
        "denylist.remove",
        "denylist",
        &id,
        serde_json::json!({}),
    );
    record_audit(db.as_ref(), events_store.as_ref(), audit).await;

    Ok(HttpResponse::Ok().json(serde_json::json!({ "message": "Denylist entry removed" })))
}

// --- Audit log --------------------------------------------------------------

#[derive(Serialize)]
pub struct AuditLogResponse {
    pub id: String,
    pub actor_id: String,
    pub actor_email: String,
    pub action: String,
    pub target_kind: String,
    pub target_id: String,
    pub ip: String,
    pub user_agent: String,
    pub metadata: String,
    pub created_at: String,
}

impl From<AuditLogEntry> for AuditLogResponse {
    fn from(e: AuditLogEntry) -> Self {
        Self {
            id: e.id,
            actor_id: e.actor_id,
            actor_email: e.actor_email,
            action: e.action,
            target_kind: e.target_kind,
            target_id: e.target_id,
            ip: e.ip,
            user_agent: e.user_agent,
            metadata: e.metadata,
            created_at: e.created_at.to_rfc3339(),
        }
    }
}

pub async fn list_audit_log(
    db: web::Data<DynStorage>,
    query: web::Query<ListQuery>,
) -> Result<HttpResponse> {
    let page = db
        .list_audit_log(&query)
        .await
        .map_err(actix_web::error::ErrorInternalServerError)?;

    let items: Vec<AuditLogResponse> = page.items.into_iter().map(AuditLogResponse::from).collect();

    Ok(HttpResponse::Ok().json(Page::new(items, page.total, page.limit, page.offset)))
}
