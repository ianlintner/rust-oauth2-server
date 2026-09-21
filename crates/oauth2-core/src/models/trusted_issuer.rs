use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A trusted external issuer whose signed JWTs may be exchanged for a token
/// on this server via the `urn:ietf:params:oauth:grant-type:jwt-bearer` grant
/// (RFC 7523) — the basis for agent / A2A OAuth flows.
#[cfg_attr(feature = "sqlx", derive(sqlx::FromRow))]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustedIssuer {
    pub id: String,
    /// Issuer URL (`iss` claim value). Unique.
    pub issuer: String,
    /// JWKS endpoint used to validate incoming JWT signatures.
    pub jwks_uri: String,
    /// JSON array of audiences this issuer's tokens may target. Empty array
    /// means only our issuer/token endpoint is an acceptable audience.
    #[serde(default = "default_allowed_audiences")]
    #[cfg_attr(feature = "sqlx", sqlx(default))]
    pub allowed_audiences: String,
    /// Which claim maps to the local subject: `"sub"` or `"email"`.
    #[serde(default = "default_subject_mapping")]
    #[cfg_attr(feature = "sqlx", sqlx(default))]
    pub subject_mapping: String,
    /// Whether unknown subjects should be just-in-time provisioned as users.
    #[serde(default)]
    #[cfg_attr(feature = "sqlx", sqlx(default))]
    pub jit_provision: bool,
    /// JSON array of client_ids allowed to use this issuer. Empty array means any.
    #[serde(default = "default_allowed_client_ids")]
    #[cfg_attr(feature = "sqlx", sqlx(default))]
    pub allowed_client_ids: String,
    #[serde(default = "default_enabled")]
    #[cfg_attr(feature = "sqlx", sqlx(default))]
    pub enabled: bool,
    #[serde(deserialize_with = "crate::chrono_serde::deserialize")]
    pub created_at: DateTime<Utc>,
    #[serde(deserialize_with = "crate::chrono_serde::deserialize")]
    pub updated_at: DateTime<Utc>,
}

fn default_allowed_audiences() -> String {
    "[]".to_string()
}

fn default_subject_mapping() -> String {
    "sub".to_string()
}

fn default_allowed_client_ids() -> String {
    "[]".to_string()
}

fn default_enabled() -> bool {
    true
}

impl TrustedIssuer {
    pub fn new(issuer: String, jwks_uri: String) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4().to_string(),
            issuer,
            jwks_uri,
            allowed_audiences: default_allowed_audiences(),
            subject_mapping: default_subject_mapping(),
            jit_provision: false,
            allowed_client_ids: default_allowed_client_ids(),
            enabled: default_enabled(),
            created_at: now,
            updated_at: now,
        }
    }

    /// Parse `allowed_audiences` as a `Vec<String>`. Malformed JSON is
    /// treated as an empty list.
    pub fn allowed_audiences_vec(&self) -> Vec<String> {
        serde_json::from_str(&self.allowed_audiences).unwrap_or_default()
    }

    /// Parse `allowed_client_ids` as a `Vec<String>`. Malformed JSON is
    /// treated as an empty list.
    pub fn allowed_client_ids_vec(&self) -> Vec<String> {
        serde_json::from_str(&self.allowed_client_ids).unwrap_or_default()
    }

    /// Whether `client_id` may use this trusted issuer. An empty
    /// `allowed_client_ids` list means any client is allowed.
    pub fn allows_client(&self, client_id: &str) -> bool {
        let allowed = self.allowed_client_ids_vec();
        allowed.is_empty() || allowed.iter().any(|c| c == client_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_sets_defaults() {
        let ti = TrustedIssuer::new(
            "https://issuer.example".to_string(),
            "https://issuer.example/.well-known/jwks.json".to_string(),
        );
        assert_eq!(ti.allowed_audiences, "[]");
        assert_eq!(ti.subject_mapping, "sub");
        assert!(!ti.jit_provision);
        assert_eq!(ti.allowed_client_ids, "[]");
        assert!(ti.enabled);
        assert!(ti.allowed_audiences_vec().is_empty());
        assert!(ti.allowed_client_ids_vec().is_empty());
    }

    #[test]
    fn allows_client_empty_list_allows_any() {
        let ti = TrustedIssuer::new("https://issuer.example".to_string(), "".to_string());
        assert!(ti.allows_client("any-client"));
    }

    #[test]
    fn allows_client_respects_allowlist() {
        let mut ti = TrustedIssuer::new("https://issuer.example".to_string(), "".to_string());
        ti.allowed_client_ids = serde_json::to_string(&vec!["agent-1", "agent-2"]).unwrap();
        assert!(ti.allows_client("agent-1"));
        assert!(!ti.allows_client("agent-3"));
    }
}
