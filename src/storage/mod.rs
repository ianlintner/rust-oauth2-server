use async_trait::async_trait;
use std::sync::Arc;

use crate::models::{AuthorizationCode, Client, OAuth2Error, Token, User};

pub mod sqlx;

#[cfg(feature = "mongo")]
pub mod mongo;

/// Trait implemented by all persistence backends.
///
/// This is intentionally small and mirrors the operations currently used by actors/handlers.
#[async_trait]
#[allow(dead_code)]
pub trait Storage: Send + Sync {
    /// Initialize the backing store (e.g., bootstrap schema / create indexes).
    async fn init(&self) -> Result<(), OAuth2Error>;

    // Client operations
    async fn save_client(&self, client: &Client) -> Result<(), OAuth2Error>;
    async fn get_client(&self, client_id: &str) -> Result<Option<Client>, OAuth2Error>;

    // User operations
    async fn save_user(&self, user: &User) -> Result<(), OAuth2Error>;
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
        // Default: ensure the store is reachable.
        // For SQL, `init()` runs a cheap `SELECT 1` after bootstrapping.
        self.init().await
    }
}

pub type DynStorage = Arc<dyn Storage>;

/// Create a storage backend based on URL scheme.
///
/// Supported:
/// - `postgres://...` and `sqlite:...` -> SQLx backend
/// - `mongodb://...` and `mongodb+srv://...` -> Mongo backend (requires `--features mongo`)
pub async fn create_storage(database_url: &str) -> Result<DynStorage, OAuth2Error> {
    if database_url.starts_with("mongodb://") || database_url.starts_with("mongodb+srv://") {
        #[cfg(feature = "mongo")]
        {
            let storage = mongo::MongoStorage::new(database_url).await?;
            return Ok(Arc::new(storage));
        }

        #[cfg(not(feature = "mongo"))]
        {
            return Err(OAuth2Error::new(
                "server_error",
                Some("MongoDB backend requested but the binary was built without the `mongo` feature"),
            ));
        }
    }

    // Default to SQLx backend for sqlite/postgres.
    let storage = sqlx::SqlxStorage::new(database_url).await?;
    Ok(Arc::new(storage))
}
