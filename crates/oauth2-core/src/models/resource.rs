use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use url::Url;
use uuid::Uuid;

use crate::models::error::OAuth2Error;

fn default_scopes() -> String {
    "[]".to_string()
}

fn default_authorization_details_types() -> String {
    "[]".to_string()
}

fn default_empty_string() -> String {
    String::new()
}

/// A registered protected resource (RFC 8707 / RFC 9728), used by agent /
/// A2A OAuth flows to validate the `resource` parameter and to advertise
/// per-resource metadata (scopes, supported `authorization_details` types,
/// and the JWKS URI used for transaction confirmation challenges).
#[cfg_attr(feature = "sqlx", derive(sqlx::FromRow))]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtectedResource {
    pub id: String,
    pub resource_uri: String,
    pub name: String,
    /// JSON array stored as string.
    #[serde(default = "default_scopes")]
    #[cfg_attr(feature = "sqlx", sqlx(default))]
    pub scopes: String,
    /// JSON array stored as string.
    #[serde(default = "default_authorization_details_types")]
    #[cfg_attr(feature = "sqlx", sqlx(default))]
    pub authorization_details_types: String,
    #[serde(default = "default_empty_string")]
    #[cfg_attr(feature = "sqlx", sqlx(default))]
    pub txn_challenge_jwks_uri: String,
    #[serde(deserialize_with = "crate::chrono_serde::deserialize")]
    pub created_at: DateTime<Utc>,
    #[serde(deserialize_with = "crate::chrono_serde::deserialize")]
    pub updated_at: DateTime<Utc>,
}

impl ProtectedResource {
    pub fn new(resource_uri: String, name: String, scopes: Vec<String>) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4().to_string(),
            resource_uri,
            name,
            scopes: serde_json::to_string(&scopes).unwrap_or_else(|_| "[]".to_string()),
            authorization_details_types: default_authorization_details_types(),
            txn_challenge_jwks_uri: default_empty_string(),
            created_at: now,
            updated_at: now,
        }
    }

    pub fn scopes_vec(&self) -> Vec<String> {
        serde_json::from_str(&self.scopes).unwrap_or_default()
    }

    pub fn authorization_details_types_vec(&self) -> Vec<String> {
        serde_json::from_str(&self.authorization_details_types).unwrap_or_default()
    }

    /// Validate a resource URI per RFC 8707 §2: it MUST be an absolute URI,
    /// MUST NOT include a fragment component, and here we additionally
    /// require an `https` or `http` scheme (matches how this server treats
    /// other resource/redirect URIs elsewhere).
    pub fn validate_uri(uri: &str) -> Result<(), OAuth2Error> {
        let parsed = Url::parse(uri).map_err(|_| {
            OAuth2Error::new(
                "invalid_target",
                Some("resource_uri must be an absolute URI"),
            )
        })?;

        if parsed.scheme() != "https" && parsed.scheme() != "http" {
            return Err(OAuth2Error::new(
                "invalid_target",
                Some("resource_uri must use the https or http scheme"),
            ));
        }

        if parsed.fragment().is_some() {
            return Err(OAuth2Error::new(
                "invalid_target",
                Some("resource_uri must not contain a fragment"),
            ));
        }

        Ok(())
    }
}
