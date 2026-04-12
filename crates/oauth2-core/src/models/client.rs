#![allow(dead_code)]

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[cfg(feature = "openapi")]
use utoipa::ToSchema;

fn default_token_endpoint_auth_method() -> String {
    "client_secret_basic".to_string()
}

#[cfg_attr(feature = "sqlx", derive(sqlx::FromRow))]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Client {
    pub id: String,
    pub client_id: String,
    #[cfg_attr(feature = "openapi", schema(write_only))]
    pub client_secret: String,
    pub redirect_uris: String, // JSON array stored as string
    pub grant_types: String,   // JSON array stored as string
    pub scope: String,
    pub name: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    /// RFC 7591 §2: client authentication method for the token endpoint.
    /// `"client_secret_basic"` (default), `"client_secret_post"`, or `"none"` (public client).
    #[serde(default = "default_token_endpoint_auth_method")]
    pub token_endpoint_auth_method: String,
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
            token_endpoint_auth_method: default_token_endpoint_auth_method(),
        }
    }

    /// Returns `true` for public clients that use PKCE without a client secret.
    pub fn is_public(&self) -> bool {
        self.token_endpoint_auth_method == "none"
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

#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[derive(Debug, Serialize, Deserialize)]
pub struct ClientRegistration {
    pub client_name: String,
    pub redirect_uris: Vec<String>,
    pub grant_types: Vec<String>,
    pub scope: String,
    /// Optional: `"client_secret_basic"` (default), `"client_secret_post"`, or `"none"`.
    #[serde(default = "default_token_endpoint_auth_method")]
    pub token_endpoint_auth_method: String,
}

#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[derive(Debug, Serialize, Deserialize)]
pub struct ClientCredentials {
    pub client_id: String,
    pub client_secret: String,
}
