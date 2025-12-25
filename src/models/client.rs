#![allow(dead_code)]

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use utoipa::ToSchema;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, FromRow, ToSchema)]
pub struct Client {
    pub id: String,
    pub client_id: String,
    #[schema(write_only)]
    pub client_secret: String,
    pub redirect_uris: String, // JSON array stored as string
    pub grant_types: String,   // JSON array stored as string
    pub scope: String,
    pub name: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl Client {
    pub fn new(
        client_id: String,
        client_secret: String,
        redirect_uris: Vec<String>,
        grant_types: Vec<String>,
        scope: String,
        name: String,
    ) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4().to_string(),
            client_id,
            client_secret,
            redirect_uris: serde_json::to_string(&redirect_uris)
                .unwrap_or_else(|_| "[]".to_string()),
            grant_types: serde_json::to_string(&grant_types).unwrap_or_else(|_| "[]".to_string()),
            scope,
            name,
            created_at: now,
            updated_at: now,
        }
    }

    pub fn get_redirect_uris(&self) -> Vec<String> {
        serde_json::from_str(&self.redirect_uris).unwrap_or_default()
    }

    pub fn get_grant_types(&self) -> Vec<String> {
        serde_json::from_str(&self.grant_types).unwrap_or_default()
    }

    pub fn supports_grant_type(&self, grant_type: &str) -> bool {
        self.get_grant_types().contains(&grant_type.to_string())
    }

    pub fn validate_redirect_uri(&self, redirect_uri: &str) -> bool {
        self.get_redirect_uris().contains(&redirect_uri.to_string())
    }
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct ClientRegistration {
    pub client_name: String,
    pub redirect_uris: Vec<String>,
    pub grant_types: Vec<String>,
    pub scope: String,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct ClientCredentials {
    pub client_id: String,
    pub client_secret: String,
}
