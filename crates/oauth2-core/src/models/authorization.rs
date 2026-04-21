#![allow(dead_code)]

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[cfg_attr(feature = "sqlx", derive(sqlx::FromRow))]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizationCode {
    pub id: String,
    pub code: String,
    pub client_id: String,
    pub user_id: String,
    pub redirect_uri: String,
    pub scope: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub used: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code_challenge: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code_challenge_method: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    /// RFC 8707: resource indicator — the requested resource server URI.
    /// When present, limits the audience of the issued access token.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource: Option<String>,
    /// RFC 9396: Rich Authorization Request details (JSON string).
    #[serde(skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "sqlx", sqlx(default))]
    pub authorization_details: Option<String>,
    /// OIDC Core §5.5: JSON-encoded claims request parameter.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "sqlx", sqlx(default))]
    pub claims_request: Option<String>,
    /// RFC 9700 §2.1.5: same `token_family` UUID assigned to every access /
    /// refresh token issued from this code. On authorization-code replay the
    /// AS looks up this family and cascade-revokes the entire lineage.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "sqlx", sqlx(default))]
    pub token_family: Option<String>,
}

impl AuthorizationCode {
    /// Build an authorization code with the RFC-default 10-minute lifetime.
    ///
    /// Prefer [`new_with_ttl`] when a configurable TTL is available.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        code: String,
        client_id: String,
        user_id: String,
        redirect_uri: String,
        scope: String,
        code_challenge: Option<String>,
        code_challenge_method: Option<String>,
        nonce: Option<String>,
        resource: Option<String>,
        authorization_details: Option<String>,
        claims_request: Option<String>,
    ) -> Self {
        Self::new_with_ttl(
            code,
            client_id,
            user_id,
            redirect_uri,
            scope,
            code_challenge,
            code_challenge_method,
            nonce,
            resource,
            authorization_details,
            claims_request,
            600,
        )
    }

    /// Build an authorization code with an explicit TTL in seconds.
    ///
    /// Caps at RFC 6749 §4.1.2's 10-minute maximum; values greater than 600
    /// are clamped. RFC 9700 §2.1.5 recommends values well under the max.
    #[allow(clippy::too_many_arguments)]
    pub fn new_with_ttl(
        code: String,
        client_id: String,
        user_id: String,
        redirect_uri: String,
        scope: String,
        code_challenge: Option<String>,
        code_challenge_method: Option<String>,
        nonce: Option<String>,
        resource: Option<String>,
        authorization_details: Option<String>,
        claims_request: Option<String>,
        ttl_seconds: i64,
    ) -> Self {
        let now = Utc::now();
        let clamped_ttl = ttl_seconds.clamp(1, 600);
        let expires_at = now + Duration::seconds(clamped_ttl);

        Self {
            id: Uuid::new_v4().to_string(),
            code,
            client_id,
            user_id,
            redirect_uri,
            scope,
            created_at: now,
            expires_at,
            used: false,
            code_challenge,
            code_challenge_method,
            nonce,
            resource,
            authorization_details,
            claims_request,
            // RFC 9700 §2.1.5: mint a fresh token_family UUID per code so
            // every derived access/refresh token shares a lineage that can
            // be cascade-revoked on code replay.
            token_family: Some(Uuid::new_v4().to_string()),
        }
    }

    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at
    }

    pub fn is_valid(&self) -> bool {
        !self.used && !self.is_expired()
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthorizationRequest {
    pub response_type: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub scope: Option<String>,
    pub state: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthorizationResponse {
    pub code: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
}
