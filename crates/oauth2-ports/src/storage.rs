use async_trait::async_trait;
use std::sync::Arc;

use oauth2_core::{AuthorizationCode, Client, OAuth2Error, Token, User};

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

    // Token operations
    async fn save_token(&self, token: &Token) -> Result<(), OAuth2Error>;
    async fn get_token_by_access_token(
        &self,
        access_token: &str,
    ) -> Result<Option<Token>, OAuth2Error>;
    async fn revoke_token(&self, token: &str) -> Result<(), OAuth2Error>;

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

    /// Lightweight liveness/readiness check.
    ///
    /// Implementations may override to do something cheaper than `init()`.
    async fn healthcheck(&self) -> Result<(), OAuth2Error> {
        self.init().await
    }
}

pub type DynStorage = Arc<dyn Storage>;
