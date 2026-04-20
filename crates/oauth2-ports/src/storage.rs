use async_trait::async_trait;
use std::sync::Arc;

use oauth2_core::{
    AuditLogEntry, AuthorizationCode, Client, DenylistEntry, DeviceAuthorization, ListQuery,
    OAuth2Error, Page, Token, User,
};

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

    /// Update an existing client's metadata (RFC 7592).
    async fn update_client(&self, client: &Client) -> Result<(), OAuth2Error>;

    /// Delete a client by `client_id` (RFC 7592).
    async fn delete_client(&self, client_id: &str) -> Result<(), OAuth2Error>;

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

    // --- Paginated listing methods (for admin API) ---
    // Default impls fall back to list_all_* + in-memory paging so backends can
    // opt in to native paging incrementally.

    async fn list_clients_page(&self, q: &ListQuery) -> Result<Page<Client>, OAuth2Error> {
        let all = self.list_all_clients().await?;
        Ok(Page::from_vec(all, q))
    }

    async fn list_users_page(&self, q: &ListQuery) -> Result<Page<User>, OAuth2Error> {
        let all = self.list_all_users().await?;
        Ok(Page::from_vec(all, q))
    }

    async fn list_tokens_page(&self, q: &ListQuery) -> Result<Page<Token>, OAuth2Error> {
        let all = self.list_all_tokens().await?;
        Ok(Page::from_vec(all, q))
    }

    async fn list_device_authorizations_page(
        &self,
        q: &ListQuery,
    ) -> Result<Page<DeviceAuthorization>, OAuth2Error> {
        let all = self.list_all_device_authorizations().await?;
        Ok(Page::from_vec(all, q))
    }

    /// List all device authorizations. Default returns empty vec; backends override.
    async fn list_all_device_authorizations(
        &self,
    ) -> Result<Vec<DeviceAuthorization>, OAuth2Error> {
        Ok(vec![])
    }

    /// Force-expire a pending device code (admin action).
    async fn expire_device_authorization(&self, _device_code: &str) -> Result<(), OAuth2Error> {
        Ok(())
    }

    /// Lightweight liveness/readiness check.
    ///
    /// Implementations may override to do something cheaper than `init()`.
    async fn healthcheck(&self) -> Result<(), OAuth2Error> {
        self.init().await
    }

    // --- Admin: user management ---

    /// Update an existing user's mutable fields (email, role, enabled,
    /// password_hash). Default no-op.
    async fn update_user(&self, user: &User) -> Result<(), OAuth2Error> {
        let _ = user;
        Ok(())
    }

    /// Delete a user by id. Default no-op.
    async fn delete_user(&self, user_id: &str) -> Result<(), OAuth2Error> {
        let _ = user_id;
        Ok(())
    }

    /// Soft-enable or disable a user. Default no-op.
    async fn set_user_enabled(&self, user_id: &str, enabled: bool) -> Result<(), OAuth2Error> {
        let (_, _) = (user_id, enabled);
        Ok(())
    }

    /// Change a user's role (e.g. "admin" / "user"). Default no-op.
    async fn set_user_role(&self, user_id: &str, role: &str) -> Result<(), OAuth2Error> {
        let (_, _) = (user_id, role);
        Ok(())
    }

    /// Replace a user's password hash. Default no-op.
    async fn set_user_password_hash(
        &self,
        user_id: &str,
        password_hash: &str,
    ) -> Result<(), OAuth2Error> {
        let (_, _) = (user_id, password_hash);
        Ok(())
    }

    // --- Admin: client management extensions ---

    /// Soft-enable or disable a client. Default no-op.
    async fn set_client_enabled(&self, client_id: &str, enabled: bool) -> Result<(), OAuth2Error> {
        let (_, _) = (client_id, enabled);
        Ok(())
    }

    /// Replace a client's secret (hashed or plaintext per impl convention).
    /// Default no-op.
    async fn set_client_secret(
        &self,
        client_id: &str,
        client_secret: &str,
    ) -> Result<(), OAuth2Error> {
        let (_, _) = (client_id, client_secret);
        Ok(())
    }

    // --- Admin: denylist ---

    async fn add_denylist_entry(&self, entry: &DenylistEntry) -> Result<(), OAuth2Error> {
        let _ = entry;
        Ok(())
    }

    async fn remove_denylist_entry(&self, id: &str) -> Result<(), OAuth2Error> {
        let _ = id;
        Ok(())
    }

    async fn list_denylist(&self, q: &ListQuery) -> Result<Page<DenylistEntry>, OAuth2Error> {
        let _ = q;
        Ok(Page::from_vec(vec![], q))
    }

    /// Returns the matching active denylist entry (not expired) if any.
    async fn find_denylist_entry(
        &self,
        kind: &str,
        value: &str,
    ) -> Result<Option<DenylistEntry>, OAuth2Error> {
        let (_, _) = (kind, value);
        Ok(None)
    }

    // --- Admin: audit log ---

    async fn write_audit_log(&self, entry: &AuditLogEntry) -> Result<(), OAuth2Error> {
        let _ = entry;
        Ok(())
    }

    async fn list_audit_log(&self, q: &ListQuery) -> Result<Page<AuditLogEntry>, OAuth2Error> {
        let _ = q;
        Ok(Page::from_vec(vec![], q))
    }

    // --- Admin: bulk token revocation ---

    /// Revoke every non-expired token issued to a given client.
    /// Returns number of rows affected. Default no-op.
    async fn revoke_tokens_by_client_id(&self, client_id: &str) -> Result<u64, OAuth2Error> {
        let _ = client_id;
        Ok(0)
    }

    // --- Backend capability flags ---
    //
    // These let the admin UI hide sections that would silently no-op on the
    // current backend (e.g. Mongo, which has not yet implemented denylist
    // / audit log). Default `false` so backends opt in explicitly.

    /// Whether this backend persists denylist entries.
    async fn supports_denylist(&self) -> bool {
        false
    }

    /// Whether this backend persists audit-log entries.
    async fn supports_audit_log(&self) -> bool {
        false
    }
}

pub type DynStorage = Arc<dyn Storage>;
