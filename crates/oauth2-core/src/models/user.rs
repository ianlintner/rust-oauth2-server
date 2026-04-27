#![allow(dead_code)]

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[cfg_attr(feature = "sqlx", derive(sqlx::FromRow))]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: String,
    pub username: String,
    pub password_hash: String,
    pub email: String,
    pub enabled: bool,
    /// User role: "admin" or "user" (default).
    #[serde(default = "default_role")]
    pub role: String,
    #[serde(deserialize_with = "crate::chrono_serde::deserialize")]
    pub created_at: DateTime<Utc>,
    #[serde(deserialize_with = "crate::chrono_serde::deserialize")]
    pub updated_at: DateTime<Utc>,
}

fn default_role() -> String {
    "user".to_string()
}

impl User {
    pub fn new(username: String, password_hash: String, email: String) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4().to_string(),
            username,
            password_hash,
            email,
            enabled: true,
            role: "user".to_string(),
            created_at: now,
            updated_at: now,
        }
    }

    /// Check if the user has admin privileges.
    ///
    /// A user is admin if their `role` field is `"admin"` or their email appears
    /// in the `OAUTH2_ADMIN_EMAILS` environment variable (comma-separated list).
    /// Username alone never grants admin — set the role field in the database.
    pub fn is_admin(&self) -> bool {
        if self.role == "admin" {
            return true;
        }
        if let Ok(admin_emails) = std::env::var("OAUTH2_ADMIN_EMAILS") {
            let email_lower = self.email.to_lowercase();
            return admin_emails
                .split(',')
                .map(|e| e.trim().to_lowercase())
                .any(|e| e == email_lower);
        }
        false
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UserCredentials {
    pub username: String,
    pub password: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn user_json_with_dates(created: &str, updated: &str) -> String {
        format!(
            r#"{{
                "id": "u1",
                "username": "alice",
                "password_hash": "x",
                "email": "a@b.test",
                "enabled": true,
                "role": "user",
                "created_at": {created},
                "updated_at": {updated}
            }}"#
        )
    }

    #[test]
    fn deserializes_rfc3339_string_dates() {
        let json =
            user_json_with_dates("\"2026-04-27T12:00:00Z\"", "\"2026-04-27T12:00:00+00:00\"");
        let user: User = serde_json::from_str(&json).expect("RFC 3339 strings should parse");
        assert_eq!(user.created_at.timestamp(), 1_777_291_200);
        assert_eq!(user.updated_at.timestamp(), 1_777_291_200);
    }

    #[test]
    fn deserializes_bson_extended_json_millis() {
        // BSON extended JSON v1 form: {"$date": <i64 millis>}
        let json =
            user_json_with_dates(r#"{"$date": 1714219200000}"#, r#"{"$date": 1714219200000}"#);
        let user: User = serde_json::from_str(&json).expect("BSON $date millis form should parse");
        assert_eq!(user.created_at.timestamp_millis(), 1_714_219_200_000);
        assert_eq!(user.updated_at.timestamp_millis(), 1_714_219_200_000);
    }

    #[test]
    fn deserializes_bson_extended_json_wrapped() {
        // BSON extended JSON v2 (canonical) form: {"$date": {"$numberLong": "<ms>"}}
        let json = user_json_with_dates(
            r#"{"$date": {"$numberLong": "1714219200000"}}"#,
            r#"{"$date": {"$numberLong": "1714219200000"}}"#,
        );
        let user: User =
            serde_json::from_str(&json).expect("BSON $date+$numberLong form should parse");
        assert_eq!(user.created_at.timestamp_millis(), 1_714_219_200_000);
        assert_eq!(user.updated_at.timestamp_millis(), 1_714_219_200_000);
    }

    #[test]
    fn mixed_encodings_round_trip() {
        // Real-world corrupted shape: insert_one wrote String, $set later wrote BSON Date.
        let json = user_json_with_dates("\"2026-04-27T12:00:00Z\"", r#"{"$date": 1714219200000}"#);
        let user: User = serde_json::from_str(&json).expect("mixed encodings should parse");
        assert_eq!(user.created_at.timestamp(), 1_777_291_200);
        assert_eq!(user.updated_at.timestamp_millis(), 1_714_219_200_000);
    }
}
