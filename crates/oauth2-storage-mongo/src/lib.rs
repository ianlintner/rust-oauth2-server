use async_trait::async_trait;
use mongodb::{
    bson::doc,
    options::{ClientOptions, IndexOptions},
    Client as MongoClient, Collection, Database, IndexModel,
};

use oauth2_core::{
    AuthorizationCode, Client, DeviceAuthorization, ListQuery, OAuth2Error, Page, Token, User,
};
use oauth2_ports::Storage;

/// MongoDB-backed storage implementation.
///
/// Notes:
/// - Uses the core models as documents via `serde`.
/// - Uses unique indexes on the same fields that are unique in SQL.
pub struct MongoStorage {
    db: Database,
    clients: Collection<Client>,
    users: Collection<User>,
    tokens: Collection<Token>,
    authorization_codes: Collection<AuthorizationCode>,
    device_authorizations: Collection<DeviceAuthorization>,
}

impl MongoStorage {
    pub async fn new(uri: &str) -> Result<Self, OAuth2Error> {
        let mut opts = ClientOptions::parse(uri)
            .await
            .map_err(Self::mongo_err_to_oauth)?;
        if opts.app_name.is_none() {
            opts.app_name = Some("oauth2-storage-mongo".to_string());
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
        let device_authorizations = db.collection::<DeviceAuthorization>("device_authorizations");

        Ok(Self {
            db,
            clients,
            users,
            tokens,
            authorization_codes,
            device_authorizations,
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
            )
            .await
            .map_err(Self::mongo_err_to_oauth)?;

        // users.email non-unique index
        self.users
            .create_index(IndexModel::builder().keys(doc! { "email": 1 }).build())
            .await
            .map_err(Self::mongo_err_to_oauth)?;

        // tokens.access_token unique
        self.tokens
            .create_index(
                IndexModel::builder()
                    .keys(doc! { "access_token": 1 })
                    .options(IndexOptions::builder().unique(true).build())
                    .build(),
            )
            .await
            .map_err(Self::mongo_err_to_oauth)?;

        // tokens.refresh_token non-unique index for lookups.
        // NOTE: sparse+unique is unsupported by Azure Cosmos DB for MongoDB —
        // Cosmos silently drops the sparse flag, causing E11000 when multiple
        // tokens have no refresh_token.  Use a plain (non-unique) index instead
        // and rely on application-level uniqueness of non-null refresh tokens.
        self.tokens
            .create_index(
                IndexModel::builder()
                    .keys(doc! { "refresh_token": 1 })
                    .build(),
            )
            .await
            .map_err(Self::mongo_err_to_oauth)?;

        // created_at indexes — CosmosDB for MongoDB rejects sorts on un-indexed
        // fields with BadValue (error code 2); all list_all_* queries sort by this.
        self.clients
            .create_index(
                IndexModel::builder()
                    .keys(doc! { "created_at": -1 })
                    .build(),
            )
            .await
            .map_err(Self::mongo_err_to_oauth)?;
        self.users
            .create_index(
                IndexModel::builder()
                    .keys(doc! { "created_at": -1 })
                    .build(),
            )
            .await
            .map_err(Self::mongo_err_to_oauth)?;
        self.tokens
            .create_index(
                IndexModel::builder()
                    .keys(doc! { "created_at": -1 })
                    .build(),
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
            )
            .await
            .map_err(Self::mongo_err_to_oauth)?;

        // device_authorizations.device_code unique
        self.device_authorizations
            .create_index(
                IndexModel::builder()
                    .keys(doc! { "device_code": 1 })
                    .options(IndexOptions::builder().unique(true).build())
                    .build(),
            )
            .await
            .map_err(Self::mongo_err_to_oauth)?;

        // device_authorizations.user_code unique
        self.device_authorizations
            .create_index(
                IndexModel::builder()
                    .keys(doc! { "user_code": 1 })
                    .options(IndexOptions::builder().unique(true).build())
                    .build(),
            )
            .await
            .map_err(Self::mongo_err_to_oauth)?;

        self.device_authorizations
            .create_index(IndexModel::builder().keys(doc! { "client_id": 1 }).build())
            .await
            .map_err(Self::mongo_err_to_oauth)?;

        Ok(())
    }

    /// Heal legacy documents across every collection whose timestamp fields
    /// were written as BSON Date by historical `$set` paths. Reading those
    /// fields through chrono's default deserializer fails — surfaced as the
    /// `/auth/callback/github` 500 in production (PR #288 fixed `User`; this
    /// extends the same fix to `Token`, `Client`, `AuthorizationCode`,
    /// `DeviceAuthorization`). Idempotent: filters by `$type: 9` so it only
    /// touches the rows that still need fixing and is a no-op once healthy.
    async fn normalize_legacy_timestamps(&self) -> Result<(), OAuth2Error> {
        // (collection_name, key_field, [datetime_fields_to_check])
        let targets: [(&str, &str, &[&str]); 5] = [
            ("users", "id", &["created_at", "updated_at"]),
            ("clients", "client_id", &["created_at", "updated_at"]),
            ("tokens", "access_token", &["created_at", "expires_at"]),
            ("authorization_codes", "code", &["created_at", "expires_at"]),
            (
                "device_authorizations",
                "device_code",
                &["created_at", "expires_at"],
            ),
        ];

        for (coll_name, key_field, fields) in targets {
            self.normalize_collection_timestamps(coll_name, key_field, fields)
                .await?;
        }
        Ok(())
    }

    /// Per-collection helper for `normalize_legacy_timestamps`.
    async fn normalize_collection_timestamps(
        &self,
        coll_name: &str,
        key_field: &str,
        datetime_fields: &[&str],
    ) -> Result<(), OAuth2Error> {
        use futures::TryStreamExt;
        use mongodb::bson::{Bson, Document};

        // BSON type number 9 = Date. `$type` lets us touch only the rows that
        // need fixing (cheap on the common case where no rows match).
        let or_clauses: Vec<Document> = datetime_fields
            .iter()
            .map(|f| doc! { *f: { "$type": 9 } })
            .collect();
        let filter = doc! { "$or": or_clauses };

        let coll = self.db.collection::<Document>(coll_name);
        let mut cursor = coll.find(filter).await.map_err(Self::mongo_err_to_oauth)?;

        let mut fixed: u64 = 0;
        while let Some(d) = cursor.try_next().await.map_err(Self::mongo_err_to_oauth)? {
            let key = match d.get(key_field).and_then(Bson::as_str) {
                Some(s) => s.to_string(),
                None => continue, // pathological doc without key; skip
            };

            let mut set = Document::new();
            for field in datetime_fields {
                if let Some(Bson::DateTime(bdt)) = d.get(*field) {
                    // bson 2.x is built without the chrono-0_4 feature in this
                    // workspace, so go through millis instead of `to_chrono()`.
                    let ms = bdt.timestamp_millis();
                    let chrono_dt = chrono::DateTime::<chrono::Utc>::from_timestamp_millis(ms)
                        .ok_or_else(|| {
                            OAuth2Error::new("server_error", Some("invalid BSON DateTime millis"))
                        })?;
                    set.insert(*field, chrono_dt.to_rfc3339());
                }
            }
            if set.is_empty() {
                continue;
            }

            coll.update_one(doc! { key_field: &key }, doc! { "$set": set })
                .await
                .map_err(Self::mongo_err_to_oauth)?;
            fixed += 1;
        }

        if fixed > 0 {
            tracing::info!(
                collection = coll_name,
                fixed,
                "normalized legacy BSON Date timestamps"
            );
        }
        Ok(())
    }

    fn duplicate_key_error(err: &mongodb::error::Error) -> bool {
        // Canonical server-side message includes "E11000".
        err.to_string().contains("E11000")
    }

    fn mongo_err_to_oauth(err: mongodb::error::Error) -> OAuth2Error {
        if Self::duplicate_key_error(&err) {
            return OAuth2Error::invalid_request("duplicate key");
        }

        OAuth2Error::new("server_error", Some(&err.to_string()))
    }
}

#[async_trait]
impl Storage for MongoStorage {
    async fn init(&self) -> Result<(), OAuth2Error> {
        self.db
            .run_command(doc! { "ping": 1 })
            .await
            .map_err(Self::mongo_err_to_oauth)?;
        self.ensure_indexes().await?;
        self.normalize_legacy_timestamps().await?;
        Ok(())
    }

    async fn save_client(&self, client: &Client) -> Result<(), OAuth2Error> {
        self.clients
            .insert_one(client)
            .await
            .map(|_| ())
            .map_err(Self::mongo_err_to_oauth)
    }

    async fn get_client(&self, client_id: &str) -> Result<Option<Client>, OAuth2Error> {
        self.clients
            .find_one(doc! { "client_id": client_id })
            .await
            .map_err(Self::mongo_err_to_oauth)
    }

    async fn update_client(&self, client: &Client) -> Result<(), OAuth2Error> {
        let filter = doc! { "client_id": &client.client_id };
        self.clients
            .replace_one(filter, client)
            .await
            .map(|_| ())
            .map_err(Self::mongo_err_to_oauth)
    }

    async fn delete_client(&self, client_id: &str) -> Result<(), OAuth2Error> {
        self.clients
            .delete_one(doc! { "client_id": client_id })
            .await
            .map(|_| ())
            .map_err(Self::mongo_err_to_oauth)
    }

    async fn save_user(&self, user: &User) -> Result<(), OAuth2Error> {
        self.users
            .insert_one(user)
            .await
            .map(|_| ())
            .map_err(Self::mongo_err_to_oauth)
    }

    async fn get_user_by_username(&self, username: &str) -> Result<Option<User>, OAuth2Error> {
        self.users
            .find_one(doc! { "username": username })
            .await
            .map_err(Self::mongo_err_to_oauth)
    }

    async fn save_token(&self, token: &Token) -> Result<(), OAuth2Error> {
        self.tokens
            .insert_one(token)
            .await
            .map(|_| ())
            .map_err(Self::mongo_err_to_oauth)
    }

    async fn get_token_by_access_token(
        &self,
        access_token: &str,
    ) -> Result<Option<Token>, OAuth2Error> {
        self.tokens
            .find_one(doc! { "access_token": access_token })
            .await
            .map_err(Self::mongo_err_to_oauth)
    }

    async fn get_token_by_refresh_token(
        &self,
        refresh_token: &str,
    ) -> Result<Option<Token>, OAuth2Error> {
        self.tokens
            .find_one(doc! { "refresh_token": refresh_token })
            .await
            .map_err(Self::mongo_err_to_oauth)
    }

    async fn revoke_token(&self, token: &str) -> Result<(), OAuth2Error> {
        self.tokens
            .update_many(
                doc! { "$or": [ {"access_token": token }, {"refresh_token": token } ] },
                doc! { "$set": { "revoked": true } },
            )
            .await
            .map(|_| ())
            .map_err(Self::mongo_err_to_oauth)
    }

    async fn set_token_family(&self, access_token: &str, family: &str) -> Result<(), OAuth2Error> {
        self.tokens
            .update_one(
                doc! { "access_token": access_token },
                doc! { "$set": { "token_family": family } },
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
            .insert_one(auth_code)
            .await
            .map(|_| ())
            .map_err(Self::mongo_err_to_oauth)
    }

    async fn get_authorization_code(
        &self,
        code: &str,
    ) -> Result<Option<AuthorizationCode>, OAuth2Error> {
        self.authorization_codes
            .find_one(doc! { "code": code })
            .await
            .map_err(Self::mongo_err_to_oauth)
    }

    async fn mark_authorization_code_used(&self, code: &str) -> Result<(), OAuth2Error> {
        self.authorization_codes
            .update_one(doc! { "code": code }, doc! { "$set": { "used": true } })
            .await
            .map(|_| ())
            .map_err(Self::mongo_err_to_oauth)
    }

    async fn save_device_authorization(
        &self,
        device_auth: &DeviceAuthorization,
    ) -> Result<(), OAuth2Error> {
        self.device_authorizations
            .insert_one(device_auth)
            .await
            .map(|_| ())
            .map_err(Self::mongo_err_to_oauth)
    }

    async fn get_device_authorization_by_device_code(
        &self,
        device_code: &str,
    ) -> Result<Option<DeviceAuthorization>, OAuth2Error> {
        self.device_authorizations
            .find_one(doc! { "device_code": device_code })
            .await
            .map_err(Self::mongo_err_to_oauth)
    }

    async fn get_device_authorization_by_user_code(
        &self,
        user_code: &str,
    ) -> Result<Option<DeviceAuthorization>, OAuth2Error> {
        self.device_authorizations
            .find_one(doc! { "user_code": user_code })
            .await
            .map_err(Self::mongo_err_to_oauth)
    }

    async fn approve_device_authorization(
        &self,
        user_code: &str,
        user_id: &str,
    ) -> Result<(), OAuth2Error> {
        self.device_authorizations
            .update_one(
                doc! { "user_code": user_code },
                doc! { "$set": { "approved": true, "denied": false, "user_id": user_id } },
            )
            .await
            .map(|_| ())
            .map_err(Self::mongo_err_to_oauth)
    }

    async fn deny_device_authorization(&self, user_code: &str) -> Result<(), OAuth2Error> {
        self.device_authorizations
            .update_one(
                doc! { "user_code": user_code },
                doc! { "$set": { "approved": false, "denied": true } },
            )
            .await
            .map(|_| ())
            .map_err(Self::mongo_err_to_oauth)
    }

    async fn mark_device_authorization_used(&self, device_code: &str) -> Result<(), OAuth2Error> {
        self.device_authorizations
            .update_one(
                doc! { "device_code": device_code },
                doc! { "$set": { "used": true } },
            )
            .await
            .map(|_| ())
            .map_err(Self::mongo_err_to_oauth)
    }

    async fn list_all_clients(&self) -> Result<Vec<Client>, OAuth2Error> {
        use futures::TryStreamExt;
        // Sort application-side: CosmosDB for MongoDB rejects DB-level ORDER BY on
        // fields not in its indexing policy, and silently ignores create_index calls
        // for those fields.
        let cursor = self
            .clients
            .find(doc! {})
            .await
            .map_err(Self::mongo_err_to_oauth)?;
        let mut clients: Vec<Client> = cursor
            .try_collect()
            .await
            .map_err(Self::mongo_err_to_oauth)?;
        clients.sort_by_key(|c| std::cmp::Reverse(c.created_at));
        Ok(clients)
    }

    async fn list_all_users(&self) -> Result<Vec<User>, OAuth2Error> {
        use futures::TryStreamExt;
        let cursor = self
            .users
            .find(doc! {})
            .await
            .map_err(Self::mongo_err_to_oauth)?;
        let mut users: Vec<User> = cursor
            .try_collect()
            .await
            .map_err(Self::mongo_err_to_oauth)?;
        users.sort_by_key(|u| std::cmp::Reverse(u.created_at));
        Ok(users)
    }

    async fn list_all_tokens(&self) -> Result<Vec<Token>, OAuth2Error> {
        use futures::TryStreamExt;
        let cursor = self
            .tokens
            .find(doc! {})
            .await
            .map_err(Self::mongo_err_to_oauth)?;
        let mut tokens: Vec<Token> = cursor
            .try_collect()
            .await
            .map_err(Self::mongo_err_to_oauth)?;
        tokens.sort_by_key(|t| std::cmp::Reverse(t.created_at));
        // Match the SQLx 200-token cap
        tokens.truncate(200);
        Ok(tokens)
    }

    async fn list_clients_page(&self, q: &ListQuery) -> Result<Page<Client>, OAuth2Error> {
        use futures::TryStreamExt;
        let cursor = self
            .clients
            .find(doc! {})
            .await
            .map_err(Self::mongo_err_to_oauth)?;
        let mut all: Vec<Client> = cursor
            .try_collect()
            .await
            .map_err(Self::mongo_err_to_oauth)?;
        // App-side sort for CosmosDB compatibility.
        if q.sort_by.as_deref() == Some("name") {
            if q.sort_dir_sql() == "ASC" {
                all.sort_by(|a, b| a.name.cmp(&b.name));
            } else {
                all.sort_by(|a, b| b.name.cmp(&a.name));
            }
        } else if q.sort_dir_sql() == "ASC" {
            all.sort_by_key(|c| c.created_at);
        } else {
            all.sort_by_key(|c| std::cmp::Reverse(c.created_at));
        }
        // Search filter app-side.
        let pat = q.search_pattern();
        let all: Vec<Client> = if pat != "%" {
            let p = pat.trim_matches('%').to_lowercase();
            all.into_iter()
                .filter(|c| {
                    c.name.to_lowercase().contains(&p) || c.client_id.to_lowercase().contains(&p)
                })
                .collect()
        } else {
            all
        };
        Ok(Page::from_vec(all, q))
    }

    async fn list_users_page(&self, q: &ListQuery) -> Result<Page<User>, OAuth2Error> {
        use futures::TryStreamExt;
        let cursor = self
            .users
            .find(doc! {})
            .await
            .map_err(Self::mongo_err_to_oauth)?;
        let mut all: Vec<User> = cursor
            .try_collect()
            .await
            .map_err(Self::mongo_err_to_oauth)?;
        if q.sort_dir_sql() == "ASC" {
            all.sort_by_key(|u| u.created_at);
        } else {
            all.sort_by_key(|u| std::cmp::Reverse(u.created_at));
        }
        let pat = q.search_pattern();
        let all: Vec<User> = if pat != "%" {
            let p = pat.trim_matches('%').to_lowercase();
            all.into_iter()
                .filter(|u| {
                    u.username.to_lowercase().contains(&p) || u.email.to_lowercase().contains(&p)
                })
                .collect()
        } else {
            all
        };
        Ok(Page::from_vec(all, q))
    }

    async fn list_tokens_page(&self, q: &ListQuery) -> Result<Page<Token>, OAuth2Error> {
        use futures::TryStreamExt;
        let cursor = self
            .tokens
            .find(doc! {})
            .await
            .map_err(Self::mongo_err_to_oauth)?;
        let mut all: Vec<Token> = cursor
            .try_collect()
            .await
            .map_err(Self::mongo_err_to_oauth)?;
        if q.sort_dir_sql() == "ASC" {
            all.sort_by_key(|t| t.created_at);
        } else {
            all.sort_by_key(|t| std::cmp::Reverse(t.created_at));
        }
        // Status filter.
        let all: Vec<Token> = match q.status.as_deref() {
            Some("active") => all.into_iter().filter(|t| t.is_valid()).collect(),
            Some("revoked") => all.into_iter().filter(|t| t.revoked).collect(),
            Some("expired") => all
                .into_iter()
                .filter(|t| t.is_expired() && !t.revoked)
                .collect(),
            _ => all,
        };
        let pat = q.search_pattern();
        let all: Vec<Token> = if pat != "%" {
            let p = pat.trim_matches('%').to_lowercase();
            all.into_iter()
                .filter(|t| {
                    t.client_id.to_lowercase().contains(&p)
                        || t.user_id
                            .as_deref()
                            .unwrap_or("")
                            .to_lowercase()
                            .contains(&p)
                })
                .collect()
        } else {
            all
        };
        Ok(Page::from_vec(all, q))
    }

    async fn list_all_device_authorizations(
        &self,
    ) -> Result<Vec<DeviceAuthorization>, OAuth2Error> {
        use futures::TryStreamExt;
        let cursor = self
            .device_authorizations
            .find(doc! {})
            .await
            .map_err(Self::mongo_err_to_oauth)?;
        let mut all: Vec<DeviceAuthorization> = cursor
            .try_collect()
            .await
            .map_err(Self::mongo_err_to_oauth)?;
        all.sort_by_key(|d| std::cmp::Reverse(d.created_at));
        Ok(all)
    }

    async fn expire_device_authorization(&self, device_code: &str) -> Result<(), OAuth2Error> {
        // Write `expires_at` as RFC 3339 string to match the encoding produced
        // by `insert_one`, preventing the mixed-encoding deserialization bug.
        let past = (chrono::Utc::now() - chrono::Duration::seconds(1)).to_rfc3339();
        self.device_authorizations
            .update_one(
                doc! { "device_code": device_code },
                doc! { "$set": { "expires_at": past } },
            )
            .await
            .map(|_| ())
            .map_err(Self::mongo_err_to_oauth)
    }

    async fn healthcheck(&self) -> Result<(), OAuth2Error> {
        self.db
            .run_command(doc! { "ping": 1 })
            .await
            .map(|_| ())
            .map_err(Self::mongo_err_to_oauth)
    }

    // --- Admin: user management ---

    async fn update_user(&self, user: &User) -> Result<(), OAuth2Error> {
        // Write `updated_at` as an RFC 3339 string to match how `insert_one`
        // serializes via chrono's default impl. Mixing BSON Date and BSON String
        // in the same document breaks `Collection<User>::find_one` deserialization.
        let updated_at = user.updated_at.to_rfc3339();
        self.users
            .update_one(
                doc! { "id": &user.id },
                doc! {
                    "$set": {
                        "username": &user.username,
                        "email": &user.email,
                        "enabled": user.enabled,
                        "role": &user.role,
                        "password_hash": &user.password_hash,
                        "updated_at": updated_at,
                    }
                },
            )
            .await
            .map(|_| ())
            .map_err(Self::mongo_err_to_oauth)
    }

    async fn delete_user(&self, user_id: &str) -> Result<(), OAuth2Error> {
        self.users
            .delete_one(doc! { "id": user_id })
            .await
            .map(|_| ())
            .map_err(Self::mongo_err_to_oauth)
    }

    async fn set_user_enabled(&self, user_id: &str, enabled: bool) -> Result<(), OAuth2Error> {
        let now = chrono::Utc::now().to_rfc3339();
        self.users
            .update_one(
                doc! { "id": user_id },
                doc! { "$set": { "enabled": enabled, "updated_at": now } },
            )
            .await
            .map(|_| ())
            .map_err(Self::mongo_err_to_oauth)
    }

    async fn set_user_role(&self, user_id: &str, role: &str) -> Result<(), OAuth2Error> {
        let now = chrono::Utc::now().to_rfc3339();
        self.users
            .update_one(
                doc! { "id": user_id },
                doc! { "$set": { "role": role, "updated_at": now } },
            )
            .await
            .map(|_| ())
            .map_err(Self::mongo_err_to_oauth)
    }

    async fn set_user_password_hash(
        &self,
        user_id: &str,
        password_hash: &str,
    ) -> Result<(), OAuth2Error> {
        let now = chrono::Utc::now().to_rfc3339();
        self.users
            .update_one(
                doc! { "id": user_id },
                doc! { "$set": { "password_hash": password_hash, "updated_at": now } },
            )
            .await
            .map(|_| ())
            .map_err(Self::mongo_err_to_oauth)
    }

    // --- Admin: client management extensions ---

    async fn set_client_enabled(&self, client_id: &str, enabled: bool) -> Result<(), OAuth2Error> {
        let now = chrono::Utc::now().to_rfc3339();
        self.clients
            .update_one(
                doc! { "client_id": client_id },
                doc! { "$set": { "enabled": enabled, "updated_at": now } },
            )
            .await
            .map(|_| ())
            .map_err(Self::mongo_err_to_oauth)
    }

    async fn set_client_secret(
        &self,
        client_id: &str,
        client_secret: &str,
    ) -> Result<(), OAuth2Error> {
        let now = chrono::Utc::now().to_rfc3339();
        self.clients
            .update_one(
                doc! { "client_id": client_id },
                doc! { "$set": { "client_secret": client_secret, "updated_at": now } },
            )
            .await
            .map(|_| ())
            .map_err(Self::mongo_err_to_oauth)
    }

    async fn revoke_tokens_by_client_id(&self, client_id: &str) -> Result<u64, OAuth2Error> {
        let result = self
            .tokens
            .update_many(
                doc! { "client_id": client_id, "revoked": false },
                doc! { "$set": { "revoked": true } },
            )
            .await
            .map_err(Self::mongo_err_to_oauth)?;
        Ok(result.modified_count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mongodb::bson;

    #[test]
    fn token_serde_omits_refresh_token_when_none() {
        let token = Token::new(
            "access".to_string(),
            None,
            "client".to_string(),
            None,
            "read".to_string(),
            3600,
            None,
        );

        let doc = bson::to_document(&token).expect("token should serialize to bson document");
        assert!(
            !doc.contains_key("refresh_token"),
            "refresh_token should be omitted when None to avoid unique+sparse collisions"
        );
    }

    #[test]
    fn token_serde_includes_refresh_token_when_some() {
        let token = Token::new(
            "access".to_string(),
            Some("refresh".to_string()),
            "client".to_string(),
            None,
            "read".to_string(),
            3600,
            None,
        );

        let doc = bson::to_document(&token).expect("token should serialize to bson document");
        assert!(
            doc.contains_key("refresh_token"),
            "refresh_token should be present when Some"
        );
    }

    /// Reproduces the bug from `/auth/callback/github` where a `User` document
    /// previously touched by an admin op had `updated_at` written as a BSON
    /// Date. Pre-fix, deserializing such a document panicked with
    /// "invalid type: map, expected an RFC 3339 formatted date and time string".
    /// The tolerant deserializer in `oauth2_core::User` heals it.
    #[test]
    fn user_deserializes_with_bson_date_updated_at() {
        let mut doc = bson::Document::new();
        doc.insert("id", "u1");
        doc.insert("username", "github:42");
        doc.insert("password_hash", "x");
        doc.insert("email", "a@b.test");
        doc.insert("enabled", true);
        doc.insert("role", "user");
        // Mixed encoding: created_at as String (insert_one path), updated_at
        // as BSON Date (admin update path) — exactly the corrupted shape.
        doc.insert("created_at", "2026-04-27T12:00:00Z");
        doc.insert("updated_at", bson::DateTime::from_millis(1_714_219_200_000));

        let user: User = bson::from_document(doc).expect(
            "User must deserialize when updated_at is BSON Date — \
             this reproduces the GitHub callback 500 from production",
        );
        assert_eq!(user.updated_at.timestamp_millis(), 1_714_219_200_000);
    }

    /// Same encoding-mismatch class as the User bug, applied to `Token`. A
    /// token whose `expires_at` was overwritten as BSON Date (e.g. by the old
    /// `expire_device_authorization` path) would 500 every introspect /
    /// refresh / revoke call until this fix.
    #[test]
    fn token_deserializes_with_bson_date_expires_at() {
        let mut doc = bson::Document::new();
        doc.insert("id", "t1");
        doc.insert("access_token", "at");
        doc.insert("token_type", "Bearer");
        doc.insert("expires_in", 3600i32);
        doc.insert("scope", "read");
        doc.insert("client_id", "c1");
        doc.insert("user_id", bson::Bson::Null);
        doc.insert("created_at", "2026-04-27T12:00:00Z");
        doc.insert("expires_at", bson::DateTime::from_millis(1_714_219_200_000));
        doc.insert("revoked", false);

        let token: Token =
            bson::from_document(doc).expect("Token must accept BSON Date expires_at");
        assert_eq!(token.expires_at.timestamp_millis(), 1_714_219_200_000);
    }

    /// `Client` had the same latent bug via `set_client_enabled` and
    /// `set_client_secret`, both of which wrote `updated_at` as `bson::DateTime`.
    #[test]
    fn client_deserializes_with_bson_date_updated_at() {
        let mut doc = bson::Document::new();
        doc.insert("id", "x");
        doc.insert("client_id", "c1");
        doc.insert("client_secret", "s");
        doc.insert("redirect_uris", "[]");
        doc.insert("grant_types", "[]");
        doc.insert("scope", "read");
        doc.insert("name", "n");
        doc.insert("created_at", "2026-04-27T12:00:00Z");
        doc.insert("updated_at", bson::DateTime::from_millis(1_714_219_200_000));

        let client: Client =
            bson::from_document(doc).expect("Client must accept BSON Date updated_at");
        assert_eq!(client.updated_at.timestamp_millis(), 1_714_219_200_000);
    }

    /// `DeviceAuthorization` had the same latent bug via
    /// `expire_device_authorization`, which wrote `expires_at` as `bson::DateTime`.
    #[test]
    fn device_auth_deserializes_with_bson_date_expires_at() {
        let mut doc = bson::Document::new();
        doc.insert("id", "d1");
        doc.insert("device_code", "dev");
        doc.insert("user_code", "ABCD-EFGH");
        doc.insert("client_id", "c1");
        doc.insert("scope", "read");
        doc.insert("created_at", "2026-04-27T12:00:00Z");
        doc.insert("expires_at", bson::DateTime::from_millis(1_714_219_200_000));
        doc.insert("interval_seconds", 5i32);
        doc.insert("approved", false);
        doc.insert("denied", false);
        doc.insert("used", false);
        doc.insert("user_id", bson::Bson::Null);

        let dev: DeviceAuthorization =
            bson::from_document(doc).expect("DeviceAuthorization must accept BSON Date");
        assert_eq!(dev.expires_at.timestamp_millis(), 1_714_219_200_000);
    }

    /// `AuthorizationCode` has the same `created_at` / `expires_at` shape and
    /// would surface the same 500 if any future path wrote a BSON Date there.
    #[test]
    fn authorization_code_deserializes_with_bson_date_expires_at() {
        let mut doc = bson::Document::new();
        doc.insert("id", "ac1");
        doc.insert("code", "code");
        doc.insert("client_id", "c1");
        doc.insert("user_id", "u1");
        doc.insert("redirect_uri", "https://x/cb");
        doc.insert("scope", "read");
        doc.insert("created_at", "2026-04-27T12:00:00Z");
        doc.insert("expires_at", bson::DateTime::from_millis(1_714_219_200_000));
        doc.insert("used", false);

        let ac: AuthorizationCode =
            bson::from_document(doc).expect("AuthorizationCode must accept BSON Date");
        assert_eq!(ac.expires_at.timestamp_millis(), 1_714_219_200_000);
    }
}
