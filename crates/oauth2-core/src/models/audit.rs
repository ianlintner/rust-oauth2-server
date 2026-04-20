#![allow(dead_code)]

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Row from the `audit_log` table. Represents a single admin-triggered
/// mutation (user/client/token CRUD, denylist changes, key rotations, …).
#[cfg_attr(feature = "sqlx", derive(sqlx::FromRow))]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLogEntry {
    pub id: String,
    /// User id of the admin that performed the action (empty for anonymous /
    /// bearer-token callers).
    pub actor_id: String,
    pub actor_email: String,
    /// Dot-separated action code, e.g. `user.create`, `client.delete`,
    /// `denylist.add`, `token.revoke`.
    pub action: String,
    /// One of: `user`, `client`, `token`, `denylist`, `device`, `key`, ``.
    pub target_kind: String,
    pub target_id: String,
    pub ip: String,
    pub user_agent: String,
    /// JSON blob with extra details (before/after, reason, etc).
    pub metadata: String,
    pub created_at: DateTime<Utc>,
}

impl AuditLogEntry {
    pub fn new(actor_id: &str, actor_email: &str, action: &str) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            actor_id: actor_id.to_string(),
            actor_email: actor_email.to_string(),
            action: action.to_string(),
            target_kind: String::new(),
            target_id: String::new(),
            ip: String::new(),
            user_agent: String::new(),
            metadata: String::new(),
            created_at: Utc::now(),
        }
    }

    pub fn with_target(mut self, kind: &str, id: &str) -> Self {
        self.target_kind = kind.to_string();
        self.target_id = id.to_string();
        self
    }

    pub fn with_request_meta(mut self, ip: &str, user_agent: &str) -> Self {
        self.ip = ip.to_string();
        self.user_agent = user_agent.to_string();
        self
    }

    pub fn with_metadata_json(mut self, metadata: serde_json::Value) -> Self {
        self.metadata = metadata.to_string();
        self
    }
}
