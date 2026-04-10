use async_trait::async_trait;
use oauth2_core::{AuthorizationCode, Client, OAuth2Error, Token, User};
use oauth2_ports::Storage;

/// Azure Cosmos DB NoSQL (SQL API) storage adapter scaffold.
///
/// This is intentionally feature-gated and non-functional until the full
/// implementation lands.
pub struct CosmosDbStorage {
    #[allow(dead_code)]
    database_url: String,
}

impl CosmosDbStorage {
    pub async fn new(database_url: &str) -> Result<Self, OAuth2Error> {
        if !database_url.starts_with("cosmosdb://") {
            return Err(OAuth2Error::invalid_request(
                "invalid Cosmos DB URL; expected cosmosdb://",
            ));
        }

        Ok(Self {
            database_url: database_url.to_string(),
        })
    }

    fn not_implemented_error() -> OAuth2Error {
        OAuth2Error::new(
            "server_error",
            Some("Cosmos DB storage backend is scaffolded but not yet implemented"),
        )
    }
}

#[async_trait]
impl Storage for CosmosDbStorage {
    async fn init(&self) -> Result<(), OAuth2Error> {
        Err(Self::not_implemented_error())
    }

    async fn save_client(&self, _client: &Client) -> Result<(), OAuth2Error> {
        Err(Self::not_implemented_error())
    }

    async fn get_client(&self, _client_id: &str) -> Result<Option<Client>, OAuth2Error> {
        Err(Self::not_implemented_error())
    }

    async fn save_user(&self, _user: &User) -> Result<(), OAuth2Error> {
        Err(Self::not_implemented_error())
    }

    async fn get_user_by_username(&self, _username: &str) -> Result<Option<User>, OAuth2Error> {
        Err(Self::not_implemented_error())
    }

    async fn save_token(&self, _token: &Token) -> Result<(), OAuth2Error> {
        Err(Self::not_implemented_error())
    }

    async fn get_token_by_access_token(
        &self,
        _access_token: &str,
    ) -> Result<Option<Token>, OAuth2Error> {
        Err(Self::not_implemented_error())
    }

    async fn revoke_token(&self, _token: &str) -> Result<(), OAuth2Error> {
        Err(Self::not_implemented_error())
    }

    async fn save_authorization_code(
        &self,
        _auth_code: &AuthorizationCode,
    ) -> Result<(), OAuth2Error> {
        Err(Self::not_implemented_error())
    }

    async fn get_authorization_code(
        &self,
        _code: &str,
    ) -> Result<Option<AuthorizationCode>, OAuth2Error> {
        Err(Self::not_implemented_error())
    }

    async fn mark_authorization_code_used(&self, _code: &str) -> Result<(), OAuth2Error> {
        Err(Self::not_implemented_error())
    }
}
