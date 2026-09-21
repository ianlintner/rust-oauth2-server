//! Transaction Authorization Challenge
//! (`draft-rosomakho-oauth-txn-challenge-00`).
//!
//! A protected resource that wants a human to approve a specific operation
//! signs a *transaction challenge* JWT. The client submits it to the
//! authorization server, which stores the pending approval as a
//! [`TransactionAuthorization`] and hands back a polling handle.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Default poll interval advertised to the client, in seconds.
pub const DEFAULT_TRANSACTION_POLL_INTERVAL_SECONDS: i32 = 5;

/// A pending (or settled) human-in-the-loop approval for one operation.
#[cfg_attr(feature = "sqlx", derive(sqlx::FromRow))]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionAuthorization {
    pub id: String,
    /// Opaque handle the client polls the token endpoint with.
    pub transaction_authorization_id: String,
    /// The client that submitted the challenge; only it may redeem the grant.
    pub client_id: String,
    /// The human who approved or denied, once they have.
    pub user_id: Option<String>,
    /// `iss` of the challenge: the protected resource that raised it.
    pub resource_uri: String,
    /// The challenge's `txn` claim, copied into the issued access token.
    pub txn: String,
    /// RFC 9396 `authorization_details`, stored as a JSON array string.
    pub authorization_details: String,
    /// Human-readable explanation shown on the approval page.
    pub reason: String,
    /// Optional URI with more detail about the operation.
    pub reason_uri: String,
    /// Optional RFC 8693 `act` chain from the challenge, as a JSON string.
    pub act: Option<String>,
    #[serde(deserialize_with = "crate::chrono_serde::deserialize")]
    pub created_at: DateTime<Utc>,
    #[serde(deserialize_with = "crate::chrono_serde::deserialize")]
    pub expires_at: DateTime<Utc>,
    pub interval_seconds: i32,
    pub approved: bool,
    pub denied: bool,
    pub used: bool,
}

impl TransactionAuthorization {
    pub fn new(
        client_id: String,
        resource_uri: String,
        txn: String,
        authorization_details: String,
        expires_in_seconds: i64,
    ) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4().to_string(),
            transaction_authorization_id: Uuid::new_v4().to_string(),
            client_id,
            user_id: None,
            resource_uri,
            txn,
            authorization_details,
            reason: String::new(),
            reason_uri: String::new(),
            act: None,
            created_at: now,
            expires_at: now + Duration::seconds(expires_in_seconds),
            interval_seconds: DEFAULT_TRANSACTION_POLL_INTERVAL_SECONDS,
            approved: false,
            denied: false,
            used: false,
        }
    }

    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at
    }

    /// Seconds remaining until expiry, never negative.
    pub fn expires_in(&self) -> i64 {
        (self.expires_at - Utc::now()).num_seconds().max(0)
    }

    /// The stored `authorization_details` parsed back into JSON, falling back
    /// to an empty array when the column holds something unparseable.
    pub fn authorization_details_value(&self) -> serde_json::Value {
        serde_json::from_str(&self.authorization_details)
            .unwrap_or_else(|_| serde_json::Value::Array(Vec::new()))
    }

    /// The stored `act` chain parsed back into JSON, if present.
    pub fn act_value(&self) -> Option<serde_json::Value> {
        self.act
            .as_deref()
            .filter(|s| !s.trim().is_empty())
            .and_then(|s| serde_json::from_str(s).ok())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_starts_pending_and_unexpired() {
        let ta = TransactionAuthorization::new(
            "client".to_string(),
            "https://rs.example".to_string(),
            "txn-1".to_string(),
            r#"[{"type":"payment"}]"#.to_string(),
            600,
        );
        assert!(!ta.approved);
        assert!(!ta.denied);
        assert!(!ta.used);
        assert!(!ta.is_expired());
        assert!(ta.expires_in() > 0);
        assert_eq!(ta.interval_seconds, 5);
        assert_eq!(ta.authorization_details_value()[0]["type"], "payment");
        assert!(ta.act_value().is_none());
    }

    #[test]
    fn expired_row_reports_zero_remaining() {
        let mut ta = TransactionAuthorization::new(
            "client".to_string(),
            "https://rs.example".to_string(),
            "txn-1".to_string(),
            "[]".to_string(),
            600,
        );
        ta.expires_at = Utc::now() - Duration::seconds(5);
        assert!(ta.is_expired());
        assert_eq!(ta.expires_in(), 0);
    }

    #[test]
    fn malformed_json_columns_degrade_gracefully() {
        let mut ta = TransactionAuthorization::new(
            "client".to_string(),
            "https://rs.example".to_string(),
            "txn-1".to_string(),
            "not json".to_string(),
            600,
        );
        assert_eq!(ta.authorization_details_value(), serde_json::json!([]));
        ta.act = Some("   ".to_string());
        assert!(ta.act_value().is_none());
        ta.act = Some(r#"{"sub":"a","iss":"b"}"#.to_string());
        assert_eq!(ta.act_value().unwrap()["sub"], "a");
    }
}
