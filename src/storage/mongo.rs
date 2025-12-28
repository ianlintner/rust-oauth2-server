use async_trait::async_trait;
use mongodb::{
    bson::doc,
    options::{ClientOptions, IndexOptions},
    Client as MongoClient,
    Collection,
    Database,
    IndexModel,
};

use crate::models::{AuthorizationCode, Client, OAuth2Error, Token, User};

use super::Storage;

/// MongoDB-backed storage implementation.
///
/// Notes:
/// - Uses your existing models as documents via `serde`.
/// - Uses unique indexes on the same fields that are unique in SQL.
pub struct MongoStorage {
    db: Database,
    clients: Collection<Client>,
    users: Collection<User>,
    tokens: Collection<Token>,
    authorization_codes: Collection<AuthorizationCode>,
}

impl MongoStorage {
    pub async fn new(uri: &str) -> Result<Self, OAuth2Error> {
        // Use Rustls by default (controlled via crate features in Cargo.toml).
        let mut opts = ClientOptions::parse(uri)
            .await
            .map_err(Self::mongo_err_to_oauth)?;
        if opts.app_name.is_none() {
            opts.app_name = Some("rust_oauth2_server".to_string());
        }

        let client = MongoClient::with_options(opts).map_err(Self::mongo_err_to_oauth)?;

        // If URI doesn't specify a database, fall back to "oauth2".
        let db_name = client
            .default_database()
            .map(|d| d.name().to_string())
            .unwrap_or_else(|| "oauth2".to_string());

        let db = client.database(&db_name);

        let clients = db.collection::<Client>("clients");
        let users = db.collection::<User>("users");
        let tokens = db.collection::<Token>("tokens");
        let authorization_codes = db.collection::<AuthorizationCode>("authorization_codes");

        Ok(Self {
            db,
            clients,
            users,
            tokens,
            authorization_codes,
        })
    }

    async fn ensure_indexes(&self) -> Result<(), OAuth2Error> {
        // clients.client_id unique
        self.clients
            .create_index(
                IndexModel::builder()
                    .keys(doc! { "client_id": 1 })
                    .options(IndexOptions::builder().unique(true).build())
                    .build(),
                None,
            )
            .await
            .map_err(Self::mongo_err_to_oauth)?;

        // users.username unique
        self.users
            .create_index(
                IndexModel::builder()
                    .keys(doc! { "username": 1 })
                    .options(IndexOptions::builder().unique(true).build())
                    .build(),
                None,
            )
            .await
            .map_err(Self::mongo_err_to_oauth)?;

        // users.email non-unique index (matches SQL's index; not unique constraint)
        self.users
            .create_index(
                IndexModel::builder().keys(doc! { "email": 1 }).build(),
                None,
            )
            .await
            .map_err(Self::mongo_err_to_oauth)?;

        // tokens.access_token unique
        self.tokens
            .create_index(
                IndexModel::builder()
                    .keys(doc! { "access_token": 1 })
                    .options(IndexOptions::builder().unique(true).build())
                    .build(),
                None,
            )
            .await
            .map_err(Self::mongo_err_to_oauth)?;

        // tokens.refresh_token unique sparse (allow many nulls)
        self.tokens
            .create_index(
                IndexModel::builder()
                    .keys(doc! { "refresh_token": 1 })
                    .options(
                        IndexOptions::builder()
                            .unique(true)
                            .sparse(true)
                            .build(),
                    )
                    .build(),
                None,
            )
            .await
            .map_err(Self::mongo_err_to_oauth)?;

        // authorization_codes.code unique
        self.authorization_codes
            .create_index(
                IndexModel::builder()
                    .keys(doc! { "code": 1 })
                    .options(IndexOptions::builder().unique(true).build())
                    .build(),
                None,
            )
            .await
            .map_err(Self::mongo_err_to_oauth)?;

        Ok(())
    }

    fn duplicate_key_error(err: &mongodb::error::Error) -> bool {
        // Be conservative and avoid relying on driver-internal error structures (which have
        // changed across mongodb crate versions). The canonical server-side message includes
        // "E11000".
        err.to_string().contains("E11000")
    }

    fn mongo_err_to_oauth(err: mongodb::error::Error) -> OAuth2Error {
        if Self::duplicate_key_error(&err) {
            return OAuth2Error::new("server_error", Some("duplicate key"));
        }

        OAuth2Error::new("server_error", Some(&err.to_string()))
    }
}

#[async_trait]
impl Storage for MongoStorage {
    async fn init(&self) -> Result<(), OAuth2Error> {
        // Ping and ensure indexes.
        self.db
            .run_command(doc! { "ping": 1 }, None)
            .await
            .map_err(Self::mongo_err_to_oauth)?;
        self.ensure_indexes().await
    }

    async fn save_client(&self, client: &Client) -> Result<(), OAuth2Error> {
        self.clients
            .insert_one(client, None)
            .await
            .map(|_| ())
            .map_err(Self::mongo_err_to_oauth)
    }

    async fn get_client(&self, client_id: &str) -> Result<Option<Client>, OAuth2Error> {
        self.clients
            .find_one(doc! { "client_id": client_id }, None)
            .await
            .map_err(Self::mongo_err_to_oauth)
    }

    async fn save_user(&self, user: &User) -> Result<(), OAuth2Error> {
        self.users
            .insert_one(user, None)
            .await
            .map(|_| ())
            .map_err(Self::mongo_err_to_oauth)
    }

    async fn get_user_by_username(&self, username: &str) -> Result<Option<User>, OAuth2Error> {
        self.users
            .find_one(doc! { "username": username }, None)
            .await
            .map_err(Self::mongo_err_to_oauth)
    }

    async fn save_token(&self, token: &Token) -> Result<(), OAuth2Error> {
        self.tokens
            .insert_one(token, None)
            .await
            .map(|_| ())
            .map_err(Self::mongo_err_to_oauth)
    }

    async fn get_token_by_access_token(
        &self,
        access_token: &str,
    ) -> Result<Option<Token>, OAuth2Error> {
        self.tokens
            .find_one(doc! { "access_token": access_token }, None)
            .await
            .map_err(Self::mongo_err_to_oauth)
    }

    async fn revoke_token(&self, token: &str) -> Result<(), OAuth2Error> {
        self.tokens
            .update_many(
                doc! { "$or": [ {"access_token": token }, {"refresh_token": token } ] },
                doc! { "$set": { "revoked": true } },
                None,
            )
            .await
            .map(|_| ())
            .map_err(Self::mongo_err_to_oauth)
    }

    async fn save_authorization_code(
        &self,
        auth_code: &AuthorizationCode,
    ) -> Result<(), OAuth2Error> {
        self.authorization_codes
            .insert_one(auth_code, None)
            .await
            .map(|_| ())
            .map_err(Self::mongo_err_to_oauth)
    }

    async fn get_authorization_code(
        &self,
        code: &str,
    ) -> Result<Option<AuthorizationCode>, OAuth2Error> {
        self.authorization_codes
            .find_one(doc! { "code": code }, None)
            .await
            .map_err(Self::mongo_err_to_oauth)
    }

    async fn mark_authorization_code_used(&self, code: &str) -> Result<(), OAuth2Error> {
        self.authorization_codes
            .update_one(
                doc! { "code": code },
                doc! { "$set": { "used": true } },
                None,
            )
            .await
            .map(|_| ())
            .map_err(Self::mongo_err_to_oauth)
    }

    async fn healthcheck(&self) -> Result<(), OAuth2Error> {
        self.db
            .run_command(doc! { "ping": 1 }, None)
            .await
            .map(|_| ())
            .map_err(Self::mongo_err_to_oauth)
    }
}
