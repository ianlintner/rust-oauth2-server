use async_trait::async_trait;
use std::sync::Arc;

use oauth2_core::{AuthorizationCode, Client, DeviceAuthorization, OAuth2Error, Token, User};

/// Trait implemented by all persistence backends.
///
/// This intentionally mirrors the operations currently used by actors/handlers.
#[async_trait]
pub trait Storage: Send + Sync {
    /// Initialize the backing store (e.g., bootstrap schema / create indexes).
    async fn init(&self) -> Result<(), OAuth2Error>;

    // Client operations
    async fn save_client(&self, client: &Client) -> Result<(), OAuth2Error>;
    async fn get_client(&self, client_id: &str) -> Result<Option<Client>, OAuth2Error>;

    // User operations
    // NOTE: These methods are implemented by all backends and covered by contract tests,
    // but the current HTTP flows don't yet wire in real user persistence.
    #[allow(dead_code)]
    async fn save_user(&self, user: &User) -> Result<(), OAuth2Error>;
    #[allow(dead_code)]
    async fn get_user_by_username(&self, username: &str) -> Result<Option<User>, OAuth2Error>;

    /// Look up a user by their unique id.
    /// Default implementation returns None so older backends are not broken.
    async fn get_user_by_id(&self, user_id: &str) -> Result<Option<User>, OAuth2Error> {
        let _ = user_id;
        Ok(None)
    }

    // Token operations
    async fn save_token(&self, token: &Token) -> Result<(), OAuth2Error>;
    async fn get_token_by_access_token(
        &self,
        access_token: &str,
    ) -> Result<Option<Token>, OAuth2Error>;
    async fn get_token_by_refresh_token(
        &self,
        refresh_token: &str,
    ) -> Result<Option<Token>, OAuth2Error>;
    async fn revoke_token(&self, token: &str) -> Result<(), OAuth2Error>;

    /// Assign (or update) the token-family UUID on an existing token row.
    /// Used during refresh-token rotation when a legacy token has no family yet,
    /// so that replay detection can revoke the entire grant lineage.
    /// Default impl is a no-op so existing backends are not broken.
    async fn set_token_family(&self, access_token: &str, family: &str) -> Result<(), OAuth2Error> {
        let (_, _) = (access_token, family);
        Ok(())
    }

    /// Revoke every token in a refresh-token family (replay detection).
    /// Returns number of rows affected. Default impl is a no-op so existing
    /// backends are not broken.
    async fn revoke_token_family(&self, family: &str) -> Result<u64, OAuth2Error> {
        let _ = family;
        Ok(0)
    }

    /// Revoke all tokens belonging to a specific user.
    /// Used by OIDC logout when `id_token_hint` identifies a user.
    /// Returns number of rows affected. Default impl is a no-op.
    async fn revoke_tokens_by_user_id(&self, user_id: &str) -> Result<u64, OAuth2Error> {
        let _ = user_id;
        Ok(0)
    }

    // Authorization code operations
    async fn save_authorization_code(
        &self,
        auth_code: &AuthorizationCode,
    ) -> Result<(), OAuth2Error>;
    async fn get_authorization_code(
        &self,
        code: &str,
    ) -> Result<Option<AuthorizationCode>, OAuth2Error>;
    async fn mark_authorization_code_used(&self, code: &str) -> Result<(), OAuth2Error>;

    // OAuth2 Device Authorization Grant (RFC 8628) operations.
    // Default implementations are no-ops so older backends stay source-compatible.
    async fn save_device_authorization(
        &self,
        device_auth: &DeviceAuthorization,
    ) -> Result<(), OAuth2Error> {
        let _ = device_auth;
        Ok(())
    }

    async fn get_device_authorization_by_device_code(
        &self,
        device_code: &str,
    ) -> Result<Option<DeviceAuthorization>, OAuth2Error> {
        let _ = device_code;
        Ok(None)
    }

    async fn get_device_authorization_by_user_code(
        &self,
        user_code: &str,
    ) -> Result<Option<DeviceAuthorization>, OAuth2Error> {
        let _ = user_code;
        Ok(None)
    }

    async fn approve_device_authorization(
        &self,
        user_code: &str,
        user_id: &str,
    ) -> Result<(), OAuth2Error> {
        let (_, _) = (user_code, user_id);
        Ok(())
    }

    async fn deny_device_authorization(&self, user_code: &str) -> Result<(), OAuth2Error> {
        let _ = user_code;
        Ok(())
    }

    async fn mark_device_authorization_used(&self, device_code: &str) -> Result<(), OAuth2Error> {
        let _ = device_code;
        Ok(())
    }

    // Listing / counting operations for admin dashboard.
    // Default implementations return empty / zero so that backends can opt in
    // incrementally.

    /// List all registered clients.
    async fn list_all_clients(&self) -> Result<Vec<Client>, OAuth2Error> {
        Ok(vec![])
    }

    /// List all users.
    async fn list_all_users(&self) -> Result<Vec<User>, OAuth2Error> {
        Ok(vec![])
    }

    /// List all tokens (active and revoked).
    async fn list_all_tokens(&self) -> Result<Vec<Token>, OAuth2Error> {
        Ok(vec![])
    }

    /// Lightweight liveness/readiness check.
    ///
    /// Implementations may override to do something cheaper than `init()`.
    async fn healthcheck(&self) -> Result<(), OAuth2Error> {
        self.init().await
    }
}

pub type DynStorage = Arc<dyn Storage>;
