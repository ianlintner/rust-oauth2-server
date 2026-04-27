use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[cfg_attr(feature = "sqlx", derive(sqlx::FromRow))]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceAuthorization {
    pub id: String,
    pub device_code: String,
    pub user_code: String,
    pub client_id: String,
    pub scope: String,
    #[serde(deserialize_with = "crate::chrono_serde::deserialize")]
    pub created_at: DateTime<Utc>,
    #[serde(deserialize_with = "crate::chrono_serde::deserialize")]
    pub expires_at: DateTime<Utc>,
    pub interval_seconds: i32,
    pub approved: bool,
    pub denied: bool,
    pub used: bool,
    pub user_id: Option<String>,
}

impl DeviceAuthorization {
    pub fn new(
        device_code: String,
        user_code: String,
        client_id: String,
        scope: String,
        expires_in_seconds: i64,
        interval_seconds: i32,
    ) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4().to_string(),
            device_code,
            user_code,
            client_id,
            scope,
            created_at: now,
            expires_at: now + Duration::seconds(expires_in_seconds),
            interval_seconds,
            approved: false,
            denied: false,
            used: false,
            user_id: None,
        }
    }

    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DeviceAuthorizationResponse {
    pub device_code: String,
    pub user_code: String,
    pub verification_uri: String,
    pub verification_uri_complete: String,
    pub expires_in: i64,
    pub interval: i32,
}
