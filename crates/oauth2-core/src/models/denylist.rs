#![allow(dead_code)]

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Kinds of subject that may be denylisted.
///
/// Serialized as a lowercase string (`"ip"`, `"user_id"`, …) to match the
/// `denylist.kind` column.
pub const DENYLIST_KIND_IP: &str = "ip";
pub const DENYLIST_KIND_USER_ID: &str = "user_id";
pub const DENYLIST_KIND_USERNAME: &str = "username";
pub const DENYLIST_KIND_EMAIL: &str = "email";
pub const DENYLIST_KIND_CLIENT_ID: &str = "client_id";

#[cfg_attr(feature = "sqlx", derive(sqlx::FromRow))]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DenylistEntry {
    pub id: String,
    /// One of: `ip`, `user_id`, `username`, `email`, `client_id`.
    pub kind: String,
    pub value: String,
    pub reason: String,
    pub created_by: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
}

impl DenylistEntry {
    pub fn new(kind: &str, value: &str, reason: &str, created_by: &str) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            kind: kind.to_string(),
            value: value.to_string(),
            reason: reason.to_string(),
            created_by: created_by.to_string(),
            created_at: Utc::now(),
            expires_at: None,
        }
    }

    pub fn is_active(&self) -> bool {
        match self.expires_at {
            Some(exp) => exp > Utc::now(),
            None => true,
        }
    }
}
