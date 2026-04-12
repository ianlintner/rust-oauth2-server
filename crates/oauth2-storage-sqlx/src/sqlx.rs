use async_trait::async_trait;
use oauth2_core::{AuthorizationCode, Client, DeviceAuthorization, OAuth2Error, Token, User};
use oauth2_ports::Storage;
use sqlx::pool::PoolOptions;
use sqlx::{Pool, Postgres, Sqlite};
use std::borrow::Cow;
use std::path::PathBuf;
use std::time::Duration;

/// Database connection pool configuration.
#[derive(Debug, Clone)]
pub struct PoolConfig {
    pub max_connections: u32,
    pub min_connections: u32,
    pub acquire_timeout: Duration,
    pub idle_timeout: Duration,
}

impl Default for PoolConfig {
    fn default() -> Self {
        Self {
            max_connections: 10,
            min_connections: 1,
            acquire_timeout: Duration::from_secs(30),
            idle_timeout: Duration::from_secs(600),
        }
    }
}

#[derive(Clone, Debug)]
enum DatabasePool {
    Sqlite(Pool<Sqlite>),
    Postgres(Pool<Postgres>),
}

/// SQL-backed storage implementation (SQLite/Postgres) using SQLx.
///
/// When `read_pool` is set, read-only queries (get, list, healthcheck) are
/// routed to the read replica while mutations (save, revoke, mark_used) go
/// through the primary pool.
pub struct SqlxStorage {
    pool: DatabasePool,
    /// Optional read-replica pool for offloading read queries.
    read_pool: Option<DatabasePool>,
}

impl SqlxStorage {
    /// Create a new storage instance with default pool settings.
    pub async fn new(database_url: &str) -> Result<Self, sqlx::Error> {
        Self::with_pool_config(database_url, PoolConfig::default()).await
    }

    /// Create a new storage instance with explicit pool configuration.
    pub async fn with_pool_config(
        database_url: &str,
        pool_config: PoolConfig,
    ) -> Result<Self, sqlx::Error> {
        let pool = Self::create_pool(database_url, &pool_config).await?;
        Ok(Self {
            pool,
            read_pool: None,
        })
    }

    /// Create a storage instance with a dedicated read-replica pool.
    ///
    /// Read-only operations (get/list) are routed to the replica while
    /// mutations go through the primary pool.
    pub async fn with_read_replica(
        database_url: &str,
        read_url: &str,
        pool_config: PoolConfig,
    ) -> Result<Self, sqlx::Error> {
        let pool = Self::create_pool(database_url, &pool_config).await?;
        let read_pool = Self::create_pool(read_url, &pool_config).await?;
        Ok(Self {
            pool,
            read_pool: Some(read_pool),
        })
    }

    /// Internal helper: build a `DatabasePool` from a URL and config.
    async fn create_pool(
        database_url: &str,
        pool_config: &PoolConfig,
    ) -> Result<DatabasePool, sqlx::Error> {
        // In containerized environments (KIND/Kubernetes), a common failure mode is that the
        // directory for the sqlite DB file doesn't exist or isn't writable yet.
        // This proactively creates the parent directory (when we can infer one) and tells sqlx
        // to create the database file if missing.
        let pool = if database_url.starts_with("postgres") {
            let pg_pool = PoolOptions::<Postgres>::new()
                .max_connections(pool_config.max_connections)
                .min_connections(pool_config.min_connections)
                .acquire_timeout(pool_config.acquire_timeout)
                .idle_timeout(pool_config.idle_timeout)
                .connect(database_url)
                .await?;
            DatabasePool::Postgres(pg_pool)
        } else {
            // Best-effort: if we can't create it (permissions, etc.), sqlx will surface the
            // underlying error on connect.
            if let Some(path) = sqlite_db_path(database_url) {
                if let Some(parent) = path.parent() {
                    if !parent.as_os_str().is_empty() {
                        let _ = std::fs::create_dir_all(parent);
                    }
                }

                // Some sqlx/sqlite configurations will not create the DB file automatically.
                // Pre-creating it avoids "unable to open database file" for local/dev defaults.
                if !path.as_os_str().is_empty() && !path.exists() {
                    let _ = std::fs::File::create(&path);
                }
            }

            let connect_url = sqlite_url_with_create_mode(database_url);
            // SQLite is single-writer; don't over-provision connections.
            let sqlite_max = pool_config.max_connections.min(5);
            let sqlite_pool = PoolOptions::<Sqlite>::new()
                .max_connections(sqlite_max)
                .min_connections(pool_config.min_connections.min(sqlite_max))
                .acquire_timeout(pool_config.acquire_timeout)
                .idle_timeout(pool_config.idle_timeout)
                .connect(connect_url.as_ref())
                .await?;
            DatabasePool::Sqlite(sqlite_pool)
        };

        Ok(pool)
    }

    /// Return the pool to use for read-only queries.
    /// Falls back to the primary pool when no read replica is configured.
    fn read_pool(&self) -> &DatabasePool {
        self.read_pool.as_ref().unwrap_or(&self.pool)
    }

    async fn init_sqlx(&self) -> Result<(), sqlx::Error> {
        match &self.pool {
            DatabasePool::Sqlite(pool) => {
                // In Kubernetes/KIND E2E runs without Flyway, make sure the schema exists.
                // These statements are idempotent and cheap for SQLite.
                self.bootstrap_sqlite_schema(pool).await?;
                sqlx::query("SELECT 1").execute(pool).await?;
            }
            DatabasePool::Postgres(pool) => {
                // Postgres schema is expected to be created by Flyway migrations.
                sqlx::query("SELECT 1").execute(pool).await?;
            }
        }

        Ok(())
    }

    async fn bootstrap_sqlite_schema(&self, pool: &Pool<Sqlite>) -> Result<(), sqlx::Error> {
        // Clients
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS clients (
                id TEXT PRIMARY KEY,
                client_id TEXT NOT NULL UNIQUE,
                client_secret TEXT NOT NULL,
                redirect_uris TEXT NOT NULL,
                grant_types TEXT NOT NULL,
                scope TEXT NOT NULL,
                name TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                token_endpoint_auth_method TEXT NOT NULL DEFAULT 'client_secret_basic'
            );
            "#,
        )
        .execute(pool)
        .await?;

        sqlx::query(r#"CREATE INDEX IF NOT EXISTS idx_clients_client_id ON clients(client_id);"#)
            .execute(pool)
            .await?;

        // Users
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                email TEXT NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 1,
                role TEXT NOT NULL DEFAULT 'user',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            "#,
        )
        .execute(pool)
        .await?;

        sqlx::query(r#"CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);"#)
            .execute(pool)
            .await?;
        sqlx::query(r#"CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);"#)
            .execute(pool)
            .await?;

        // Tokens
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS tokens (
                id TEXT PRIMARY KEY,
                access_token TEXT NOT NULL UNIQUE,
                refresh_token TEXT,
                token_type TEXT NOT NULL,
                expires_in INTEGER NOT NULL,
                scope TEXT NOT NULL,
                client_id TEXT NOT NULL,
                user_id TEXT,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                revoked INTEGER NOT NULL DEFAULT 0,
                token_family TEXT,
                FOREIGN KEY (client_id) REFERENCES clients(client_id),
                FOREIGN KEY (user_id) REFERENCES users(id)
            );
            "#,
        )
        .execute(pool)
        .await?;

        sqlx::query(
            r#"CREATE INDEX IF NOT EXISTS idx_tokens_access_token ON tokens(access_token);"#,
        )
        .execute(pool)
        .await?;
        sqlx::query(
            r#"CREATE INDEX IF NOT EXISTS idx_tokens_refresh_token ON tokens(refresh_token);"#,
        )
        .execute(pool)
        .await?;
        sqlx::query(r#"CREATE INDEX IF NOT EXISTS idx_tokens_client_id ON tokens(client_id);"#)
            .execute(pool)
            .await?;
        sqlx::query(r#"CREATE INDEX IF NOT EXISTS idx_tokens_user_id ON tokens(user_id);"#)
            .execute(pool)
            .await?;
        sqlx::query(
            r#"CREATE INDEX IF NOT EXISTS idx_tokens_token_family ON tokens(token_family);"#,
        )
        .execute(pool)
        .await?;

        // Authorization codes
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS authorization_codes (
                id TEXT PRIMARY KEY,
                code TEXT NOT NULL UNIQUE,
                client_id TEXT NOT NULL,
                user_id TEXT NOT NULL,
                redirect_uri TEXT NOT NULL,
                scope TEXT NOT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                used INTEGER NOT NULL DEFAULT 0,
                code_challenge TEXT,
                code_challenge_method TEXT,
                nonce TEXT,
                FOREIGN KEY (client_id) REFERENCES clients(client_id),
                FOREIGN KEY (user_id) REFERENCES users(id)
            );
            "#,
        )
        .execute(pool)
        .await?;

        sqlx::query(
            r#"CREATE INDEX IF NOT EXISTS idx_authorization_codes_code ON authorization_codes(code);"#,
        )
        .execute(pool)
        .await?;
        sqlx::query(
            r#"CREATE INDEX IF NOT EXISTS idx_authorization_codes_client_id ON authorization_codes(client_id);"#,
        )
        .execute(pool)
        .await?;
        sqlx::query(
            r#"CREATE INDEX IF NOT EXISTS idx_authorization_codes_user_id ON authorization_codes(user_id);"#,
        )
        .execute(pool)
        .await?;

        // Device authorizations (OAuth2 Device Flow, RFC 8628)
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS device_authorizations (
                id TEXT PRIMARY KEY,
                device_code TEXT NOT NULL UNIQUE,
                user_code TEXT NOT NULL UNIQUE,
                client_id TEXT NOT NULL,
                scope TEXT NOT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                interval_seconds INTEGER NOT NULL,
                approved INTEGER NOT NULL DEFAULT 0,
                denied INTEGER NOT NULL DEFAULT 0,
                used INTEGER NOT NULL DEFAULT 0,
                user_id TEXT,
                FOREIGN KEY (client_id) REFERENCES clients(client_id),
                FOREIGN KEY (user_id) REFERENCES users(id)
            );
            "#,
        )
        .execute(pool)
        .await?;

        sqlx::query(
            r#"CREATE INDEX IF NOT EXISTS idx_device_authorizations_device_code ON device_authorizations(device_code);"#,
        )
        .execute(pool)
        .await?;
        sqlx::query(
            r#"CREATE INDEX IF NOT EXISTS idx_device_authorizations_user_code ON device_authorizations(user_code);"#,
        )
        .execute(pool)
        .await?;
        sqlx::query(
            r#"CREATE INDEX IF NOT EXISTS idx_device_authorizations_client_id ON device_authorizations(client_id);"#,
        )
        .execute(pool)
        .await?;

        Ok(())
    }
}

#[async_trait]
impl Storage for SqlxStorage {
    async fn init(&self) -> Result<(), OAuth2Error> {
        self.init_sqlx().await.map_err(Into::into)
    }

    async fn healthcheck(&self) -> Result<(), OAuth2Error> {
        // Keep readiness/liveness cheap: don't run bootstrap or migrations.
        match self.read_pool() {
            DatabasePool::Sqlite(pool) => {
                sqlx::query("SELECT 1").execute(pool).await?;
            }
            DatabasePool::Postgres(pool) => {
                sqlx::query("SELECT 1").execute(pool).await?;
            }
        }

        Ok(())
    }

    async fn save_client(&self, client: &Client) -> Result<(), OAuth2Error> {
        match &self.pool {
            DatabasePool::Sqlite(pool) => {
                sqlx::query(
                    r#"
                    INSERT INTO clients (id, client_id, client_secret, redirect_uris, grant_types, scope, name, created_at, updated_at, token_endpoint_auth_method)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    "#,
                )
                .bind(&client.id)
                .bind(&client.client_id)
                .bind(&client.client_secret)
                .bind(&client.redirect_uris)
                .bind(&client.grant_types)
                .bind(&client.scope)
                .bind(&client.name)
                .bind(client.created_at)
                .bind(client.updated_at)
                .bind(&client.token_endpoint_auth_method)
                .execute(pool)
                .await?;
            }
            DatabasePool::Postgres(pool) => {
                sqlx::query(
                    r#"
                    INSERT INTO clients (id, client_id, client_secret, redirect_uris, grant_types, scope, name, created_at, updated_at, token_endpoint_auth_method)
                    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
                    "#,
                )
                .bind(&client.id)
                .bind(&client.client_id)
                .bind(&client.client_secret)
                .bind(&client.redirect_uris)
                .bind(&client.grant_types)
                .bind(&client.scope)
                .bind(&client.name)
                .bind(client.created_at)
                .bind(client.updated_at)
                .bind(&client.token_endpoint_auth_method)
                .execute(pool)
                .await?;
            }
        }

        Ok(())
    }

    async fn get_client(&self, client_id: &str) -> Result<Option<Client>, OAuth2Error> {
        let client = match self.read_pool() {
            DatabasePool::Sqlite(pool) => {
                sqlx::query_as::<_, Client>("SELECT * FROM clients WHERE client_id = ?")
                    .bind(client_id)
                    .fetch_optional(pool)
                    .await?
            }
            DatabasePool::Postgres(pool) => {
                sqlx::query_as::<_, Client>("SELECT * FROM clients WHERE client_id = $1")
                    .bind(client_id)
                    .fetch_optional(pool)
                    .await?
            }
        };

        Ok(client)
    }

    async fn save_user(&self, user: &User) -> Result<(), OAuth2Error> {
        match &self.pool {
            DatabasePool::Sqlite(pool) => {
                sqlx::query(
                    r#"
                    INSERT INTO users (id, username, password_hash, email, enabled, created_at, updated_at, role)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    "#,
                )
                .bind(&user.id)
                .bind(&user.username)
                .bind(&user.password_hash)
                .bind(&user.email)
                .bind(user.enabled)
                .bind(user.created_at)
                .bind(user.updated_at)
                .bind(&user.role)
                .execute(pool)
                .await?;
            }
            DatabasePool::Postgres(pool) => {
                sqlx::query(
                    r#"
                    INSERT INTO users (id, username, password_hash, email, enabled, created_at, updated_at, role)
                    VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                    "#,
                )
                .bind(&user.id)
                .bind(&user.username)
                .bind(&user.password_hash)
                .bind(&user.email)
                .bind(user.enabled)
                .bind(user.created_at)
                .bind(user.updated_at)
                .bind(&user.role)
                .execute(pool)
                .await?;
            }
        }

        Ok(())
    }

    async fn get_user_by_username(&self, username: &str) -> Result<Option<User>, OAuth2Error> {
        let user = match self.read_pool() {
            DatabasePool::Sqlite(pool) => {
                sqlx::query_as::<_, User>("SELECT * FROM users WHERE username = ?")
                    .bind(username)
                    .fetch_optional(pool)
                    .await?
            }
            DatabasePool::Postgres(pool) => {
                sqlx::query_as::<_, User>("SELECT * FROM users WHERE username = $1")
                    .bind(username)
                    .fetch_optional(pool)
                    .await?
            }
        };

        Ok(user)
    }

    async fn get_user_by_id(&self, user_id: &str) -> Result<Option<User>, OAuth2Error> {
        let user = match self.read_pool() {
            DatabasePool::Sqlite(pool) => {
                sqlx::query_as::<_, User>(
                    "SELECT id, username, password_hash, email, enabled, role, created_at, updated_at FROM users WHERE id = ?",
                )
                .bind(user_id)
                .fetch_optional(pool)
                .await?
            }
            DatabasePool::Postgres(pool) => {
                sqlx::query_as::<_, User>(
                    "SELECT id, username, password_hash, email, enabled, role, created_at, updated_at FROM users WHERE id = $1",
                )
                .bind(user_id)
                .fetch_optional(pool)
                .await?
            }
        };

        Ok(user)
    }

    async fn save_token(&self, token: &Token) -> Result<(), OAuth2Error> {
        match &self.pool {
            DatabasePool::Sqlite(pool) => {
                sqlx::query(
                    r#"
                    INSERT INTO tokens (id, access_token, refresh_token, token_type, expires_in, scope, client_id, user_id, created_at, expires_at, revoked, token_family)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    "#,
                )
                .bind(&token.id)
                .bind(&token.access_token)
                .bind(&token.refresh_token)
                .bind(&token.token_type)
                .bind(token.expires_in)
                .bind(&token.scope)
                .bind(&token.client_id)
                .bind(&token.user_id)
                .bind(token.created_at)
                .bind(token.expires_at)
                .bind(token.revoked)
                .bind(&token.token_family)
                .execute(pool)
                .await?;
            }
            DatabasePool::Postgres(pool) => {
                sqlx::query(
                    r#"
                    INSERT INTO tokens (id, access_token, refresh_token, token_type, expires_in, scope, client_id, user_id, created_at, expires_at, revoked, token_family)
                    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
                    "#,
                )
                .bind(&token.id)
                .bind(&token.access_token)
                .bind(&token.refresh_token)
                .bind(&token.token_type)
                .bind(token.expires_in)
                .bind(&token.scope)
                .bind(&token.client_id)
                .bind(&token.user_id)
                .bind(token.created_at)
                .bind(token.expires_at)
                .bind(token.revoked)
                .bind(&token.token_family)
                .execute(pool)
                .await?;
            }
        }

        Ok(())
    }

    async fn get_token_by_access_token(
        &self,
        access_token: &str,
    ) -> Result<Option<Token>, OAuth2Error> {
        let token = match self.read_pool() {
            DatabasePool::Sqlite(pool) => {
                sqlx::query_as::<_, Token>("SELECT * FROM tokens WHERE access_token = ?")
                    .bind(access_token)
                    .fetch_optional(pool)
                    .await?
            }
            DatabasePool::Postgres(pool) => {
                sqlx::query_as::<_, Token>("SELECT * FROM tokens WHERE access_token = $1")
                    .bind(access_token)
                    .fetch_optional(pool)
                    .await?
            }
        };

        Ok(token)
    }

    async fn get_token_by_refresh_token(
        &self,
        refresh_token: &str,
    ) -> Result<Option<Token>, OAuth2Error> {
        let token = match self.read_pool() {
            DatabasePool::Sqlite(pool) => {
                sqlx::query_as::<_, Token>("SELECT * FROM tokens WHERE refresh_token = ?")
                    .bind(refresh_token)
                    .fetch_optional(pool)
                    .await?
            }
            DatabasePool::Postgres(pool) => {
                sqlx::query_as::<_, Token>("SELECT * FROM tokens WHERE refresh_token = $1")
                    .bind(refresh_token)
                    .fetch_optional(pool)
                    .await?
            }
        };

        Ok(token)
    }

    async fn revoke_token(&self, token: &str) -> Result<(), OAuth2Error> {
        match &self.pool {
            DatabasePool::Sqlite(pool) => {
                sqlx::query(
                    "UPDATE tokens SET revoked = 1 WHERE access_token = ? OR refresh_token = ?",
                )
                .bind(token)
                .bind(token)
                .execute(pool)
                .await?;
            }
            DatabasePool::Postgres(pool) => {
                sqlx::query(
                    "UPDATE tokens SET revoked = true WHERE access_token = $1 OR refresh_token = $2",
                )
                .bind(token)
                .bind(token)
                .execute(pool)
                .await?;
            }
        }

        Ok(())
    }

    async fn set_token_family(&self, access_token: &str, family: &str) -> Result<(), OAuth2Error> {
        match &self.pool {
            DatabasePool::Sqlite(pool) => {
                sqlx::query("UPDATE tokens SET token_family = ? WHERE access_token = ?")
                    .bind(family)
                    .bind(access_token)
                    .execute(pool)
                    .await?;
            }
            DatabasePool::Postgres(pool) => {
                sqlx::query("UPDATE tokens SET token_family = $1 WHERE access_token = $2")
                    .bind(family)
                    .bind(access_token)
                    .execute(pool)
                    .await?;
            }
        }

        Ok(())
    }

    async fn revoke_token_family(&self, family: &str) -> Result<u64, OAuth2Error> {
        let rows = match &self.pool {
            DatabasePool::Sqlite(pool) => {
                sqlx::query("UPDATE tokens SET revoked = 1 WHERE token_family = ?")
                    .bind(family)
                    .execute(pool)
                    .await?
                    .rows_affected()
            }
            DatabasePool::Postgres(pool) => {
                sqlx::query("UPDATE tokens SET revoked = true WHERE token_family = $1")
                    .bind(family)
                    .execute(pool)
                    .await?
                    .rows_affected()
            }
        };

        Ok(rows)
    }

    async fn revoke_tokens_by_user_id(&self, user_id: &str) -> Result<u64, OAuth2Error> {
        let rows = match &self.pool {
            DatabasePool::Sqlite(pool) => {
                sqlx::query("UPDATE tokens SET revoked = 1 WHERE user_id = ? AND revoked = 0")
                    .bind(user_id)
                    .execute(pool)
                    .await?
                    .rows_affected()
            }
            DatabasePool::Postgres(pool) => sqlx::query(
                "UPDATE tokens SET revoked = true WHERE user_id = $1 AND revoked = false",
            )
            .bind(user_id)
            .execute(pool)
            .await?
            .rows_affected(),
        };

        Ok(rows)
    }

    async fn save_authorization_code(
        &self,
        auth_code: &AuthorizationCode,
    ) -> Result<(), OAuth2Error> {
        match &self.pool {
            DatabasePool::Sqlite(pool) => {
                sqlx::query(
                    r#"
                    INSERT INTO authorization_codes (id, code, client_id, user_id, redirect_uri, scope, created_at, expires_at, used, code_challenge, code_challenge_method, nonce)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    "#,
                )
                .bind(&auth_code.id)
                .bind(&auth_code.code)
                .bind(&auth_code.client_id)
                .bind(&auth_code.user_id)
                .bind(&auth_code.redirect_uri)
                .bind(&auth_code.scope)
                .bind(auth_code.created_at)
                .bind(auth_code.expires_at)
                .bind(auth_code.used)
                .bind(&auth_code.code_challenge)
                .bind(&auth_code.code_challenge_method)
                .bind(&auth_code.nonce)
                .execute(pool)
                .await?;
            }
            DatabasePool::Postgres(pool) => {
                sqlx::query(
                    r#"
                    INSERT INTO authorization_codes (id, code, client_id, user_id, redirect_uri, scope, created_at, expires_at, used, code_challenge, code_challenge_method, nonce)
                    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
                    "#,
                )
                .bind(&auth_code.id)
                .bind(&auth_code.code)
                .bind(&auth_code.client_id)
                .bind(&auth_code.user_id)
                .bind(&auth_code.redirect_uri)
                .bind(&auth_code.scope)
                .bind(auth_code.created_at)
                .bind(auth_code.expires_at)
                .bind(auth_code.used)
                .bind(&auth_code.code_challenge)
                .bind(&auth_code.code_challenge_method)
                .bind(&auth_code.nonce)
                .execute(pool)
                .await?;
            }
        }

        Ok(())
    }

    async fn get_authorization_code(
        &self,
        code: &str,
    ) -> Result<Option<AuthorizationCode>, OAuth2Error> {
        let auth_code = match self.read_pool() {
            DatabasePool::Sqlite(pool) => {
                sqlx::query_as::<_, AuthorizationCode>(
                    "SELECT * FROM authorization_codes WHERE code = ?",
                )
                .bind(code)
                .fetch_optional(pool)
                .await?
            }
            DatabasePool::Postgres(pool) => {
                sqlx::query_as::<_, AuthorizationCode>(
                    "SELECT * FROM authorization_codes WHERE code = $1",
                )
                .bind(code)
                .fetch_optional(pool)
                .await?
            }
        };

        Ok(auth_code)
    }

    async fn mark_authorization_code_used(&self, code: &str) -> Result<(), OAuth2Error> {
        match &self.pool {
            DatabasePool::Sqlite(pool) => {
                sqlx::query("UPDATE authorization_codes SET used = 1 WHERE code = ?")
                    .bind(code)
                    .execute(pool)
                    .await?;
            }
            DatabasePool::Postgres(pool) => {
                sqlx::query("UPDATE authorization_codes SET used = true WHERE code = $1")
                    .bind(code)
                    .execute(pool)
                    .await?;
            }
        }

        Ok(())
    }

    async fn save_device_authorization(
        &self,
        device_auth: &DeviceAuthorization,
    ) -> Result<(), OAuth2Error> {
        match &self.pool {
            DatabasePool::Sqlite(pool) => {
                sqlx::query(
                    r#"
                    INSERT INTO device_authorizations (id, device_code, user_code, client_id, scope, created_at, expires_at, interval_seconds, approved, denied, used, user_id)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    "#,
                )
                .bind(&device_auth.id)
                .bind(&device_auth.device_code)
                .bind(&device_auth.user_code)
                .bind(&device_auth.client_id)
                .bind(&device_auth.scope)
                .bind(device_auth.created_at)
                .bind(device_auth.expires_at)
                .bind(device_auth.interval_seconds)
                .bind(device_auth.approved)
                .bind(device_auth.denied)
                .bind(device_auth.used)
                .bind(&device_auth.user_id)
                .execute(pool)
                .await?;
            }
            DatabasePool::Postgres(pool) => {
                sqlx::query(
                    r#"
                    INSERT INTO device_authorizations (id, device_code, user_code, client_id, scope, created_at, expires_at, interval_seconds, approved, denied, used, user_id)
                    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
                    "#,
                )
                .bind(&device_auth.id)
                .bind(&device_auth.device_code)
                .bind(&device_auth.user_code)
                .bind(&device_auth.client_id)
                .bind(&device_auth.scope)
                .bind(device_auth.created_at)
                .bind(device_auth.expires_at)
                .bind(device_auth.interval_seconds)
                .bind(device_auth.approved)
                .bind(device_auth.denied)
                .bind(device_auth.used)
                .bind(&device_auth.user_id)
                .execute(pool)
                .await?;
            }
        }

        Ok(())
    }

    async fn get_device_authorization_by_device_code(
        &self,
        device_code: &str,
    ) -> Result<Option<DeviceAuthorization>, OAuth2Error> {
        let record = match self.read_pool() {
            DatabasePool::Sqlite(pool) => {
                sqlx::query_as::<_, DeviceAuthorization>(
                    "SELECT * FROM device_authorizations WHERE device_code = ?",
                )
                .bind(device_code)
                .fetch_optional(pool)
                .await?
            }
            DatabasePool::Postgres(pool) => {
                sqlx::query_as::<_, DeviceAuthorization>(
                    "SELECT * FROM device_authorizations WHERE device_code = $1",
                )
                .bind(device_code)
                .fetch_optional(pool)
                .await?
            }
        };

        Ok(record)
    }

    async fn get_device_authorization_by_user_code(
        &self,
        user_code: &str,
    ) -> Result<Option<DeviceAuthorization>, OAuth2Error> {
        let record = match self.read_pool() {
            DatabasePool::Sqlite(pool) => {
                sqlx::query_as::<_, DeviceAuthorization>(
                    "SELECT * FROM device_authorizations WHERE user_code = ?",
                )
                .bind(user_code)
                .fetch_optional(pool)
                .await?
            }
            DatabasePool::Postgres(pool) => {
                sqlx::query_as::<_, DeviceAuthorization>(
                    "SELECT * FROM device_authorizations WHERE user_code = $1",
                )
                .bind(user_code)
                .fetch_optional(pool)
                .await?
            }
        };

        Ok(record)
    }

    async fn approve_device_authorization(
        &self,
        user_code: &str,
        user_id: &str,
    ) -> Result<(), OAuth2Error> {
        match &self.pool {
            DatabasePool::Sqlite(pool) => {
                sqlx::query(
                    "UPDATE device_authorizations SET approved = 1, denied = 0, user_id = ? WHERE user_code = ?",
                )
                .bind(user_id)
                .bind(user_code)
                .execute(pool)
                .await?;
            }
            DatabasePool::Postgres(pool) => {
                sqlx::query(
                    "UPDATE device_authorizations SET approved = true, denied = false, user_id = $1 WHERE user_code = $2",
                )
                .bind(user_id)
                .bind(user_code)
                .execute(pool)
                .await?;
            }
        }

        Ok(())
    }

    async fn deny_device_authorization(&self, user_code: &str) -> Result<(), OAuth2Error> {
        match &self.pool {
            DatabasePool::Sqlite(pool) => {
                sqlx::query(
                    "UPDATE device_authorizations SET denied = 1, approved = 0 WHERE user_code = ?",
                )
                .bind(user_code)
                .execute(pool)
                .await?;
            }
            DatabasePool::Postgres(pool) => {
                sqlx::query(
                    "UPDATE device_authorizations SET denied = true, approved = false WHERE user_code = $1",
                )
                .bind(user_code)
                .execute(pool)
                .await?;
            }
        }

        Ok(())
    }

    async fn mark_device_authorization_used(&self, device_code: &str) -> Result<(), OAuth2Error> {
        match &self.pool {
            DatabasePool::Sqlite(pool) => {
                sqlx::query("UPDATE device_authorizations SET used = 1 WHERE device_code = ?")
                    .bind(device_code)
                    .execute(pool)
                    .await?;
            }
            DatabasePool::Postgres(pool) => {
                sqlx::query("UPDATE device_authorizations SET used = true WHERE device_code = $1")
                    .bind(device_code)
                    .execute(pool)
                    .await?;
            }
        }

        Ok(())
    }

    async fn list_all_clients(&self) -> Result<Vec<Client>, OAuth2Error> {
        let clients = match self.read_pool() {
            DatabasePool::Sqlite(pool) => {
                sqlx::query_as::<_, Client>("SELECT * FROM clients ORDER BY created_at DESC")
                    .fetch_all(pool)
                    .await?
            }
            DatabasePool::Postgres(pool) => {
                sqlx::query_as::<_, Client>("SELECT * FROM clients ORDER BY created_at DESC")
                    .fetch_all(pool)
                    .await?
            }
        };
        Ok(clients)
    }

    async fn list_all_users(&self) -> Result<Vec<User>, OAuth2Error> {
        let users = match self.read_pool() {
            DatabasePool::Sqlite(pool) => {
                sqlx::query_as::<_, User>("SELECT * FROM users ORDER BY created_at DESC")
                    .fetch_all(pool)
                    .await?
            }
            DatabasePool::Postgres(pool) => {
                sqlx::query_as::<_, User>("SELECT * FROM users ORDER BY created_at DESC")
                    .fetch_all(pool)
                    .await?
            }
        };
        Ok(users)
    }

    async fn list_all_tokens(&self) -> Result<Vec<Token>, OAuth2Error> {
        let tokens = match self.read_pool() {
            DatabasePool::Sqlite(pool) => {
                sqlx::query_as::<_, Token>(
                    "SELECT * FROM tokens ORDER BY created_at DESC LIMIT 200",
                )
                .fetch_all(pool)
                .await?
            }
            DatabasePool::Postgres(pool) => {
                sqlx::query_as::<_, Token>(
                    "SELECT * FROM tokens ORDER BY created_at DESC LIMIT 200",
                )
                .fetch_all(pool)
                .await?
            }
        };
        Ok(tokens)
    }
}

fn sqlite_db_path(database_url: &str) -> Option<PathBuf> {
    if !database_url.starts_with("sqlite:") {
        return None;
    }
    if database_url.starts_with("sqlite::memory:") {
        return None;
    }

    let mut rest = &database_url["sqlite:".len()..];

    // Normalize URL-ish forms into a filesystem-ish path by reducing multiple
    // leading slashes to a single leading slash.
    if rest.starts_with("///") {
        rest = &rest[2..];
    } else if rest.starts_with("//") {
        rest = &rest[1..];
    }

    // Drop any query string.
    let path_part = rest.split('?').next().unwrap_or(rest);
    if path_part.is_empty() {
        return None;
    }

    Some(PathBuf::from(path_part))
}

fn sqlite_url_with_create_mode(database_url: &str) -> Cow<'_, str> {
    if !database_url.starts_with("sqlite:") {
        return Cow::Borrowed(database_url);
    }
    if database_url.starts_with("sqlite::memory:") {
        return Cow::Borrowed(database_url);
    }

    // Ensure we can create the sqlite database file when it doesn't exist.
    // This is a common footgun with URI mode in SQLite.
    if database_url.contains("mode=") {
        return Cow::Borrowed(database_url);
    }

    let sep = if database_url.contains('?') { '&' } else { '?' };
    Cow::Owned(format!("{database_url}{sep}mode=rwc"))
}
