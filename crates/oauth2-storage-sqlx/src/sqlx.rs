use async_trait::async_trait;
use oauth2_core::{AuthorizationCode, Client, OAuth2Error, Token, User};
use oauth2_ports::Storage;
use sqlx::{Pool, Postgres, Sqlite};
use std::path::Path;

#[derive(Clone, Debug)]
enum DatabasePool {
    Sqlite(Pool<Sqlite>),
    Postgres(Pool<Postgres>),
}

/// SQL-backed storage implementation (SQLite/Postgres) using SQLx.
pub struct SqlxStorage {
    pool: DatabasePool,
}

impl SqlxStorage {
    pub async fn new(database_url: &str) -> Result<Self, sqlx::Error> {
        // In containerized environments (KIND/Kubernetes), a common failure mode is that the
        // directory for the sqlite DB file doesn't exist or isn't writable yet.
        // This proactively creates the parent directory (when we can infer one) and tells sqlx
        // to create the database file if missing.
        let pool = if database_url.starts_with("postgres") {
            DatabasePool::Postgres(Pool::<Postgres>::connect(database_url).await?)
        } else {
            if let Some(parent_dir) = sqlite_parent_dir(database_url) {
                // Best-effort: if we can't create it (permissions, etc.), sqlx will surface the
                // underlying error on connect.
                let _ = std::fs::create_dir_all(parent_dir);
            }

            DatabasePool::Sqlite(Pool::<Sqlite>::connect(database_url).await?)
        };

        Ok(Self { pool })
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
                updated_at TEXT NOT NULL
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
                FOREIGN KEY (client_id) REFERENCES clients(client_id),
                FOREIGN KEY (user_id) REFERENCES users(id)
            );
            "#,
        )
        .execute(pool)
        .await?;

        sqlx::query(r#"CREATE INDEX IF NOT EXISTS idx_tokens_access_token ON tokens(access_token);"#)
            .execute(pool)
            .await?;
        sqlx::query(r#"CREATE INDEX IF NOT EXISTS idx_tokens_refresh_token ON tokens(refresh_token);"#)
            .execute(pool)
            .await?;
        sqlx::query(r#"CREATE INDEX IF NOT EXISTS idx_tokens_client_id ON tokens(client_id);"#)
            .execute(pool)
            .await?;
        sqlx::query(r#"CREATE INDEX IF NOT EXISTS idx_tokens_user_id ON tokens(user_id);"#)
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
        match &self.pool {
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
                    INSERT INTO clients (id, client_id, client_secret, redirect_uris, grant_types, scope, name, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                .execute(pool)
                .await?;
            }
            DatabasePool::Postgres(pool) => {
                sqlx::query(
                    r#"
                    INSERT INTO clients (id, client_id, client_secret, redirect_uris, grant_types, scope, name, created_at, updated_at)
                    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
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
                .execute(pool)
                .await?;
            }
        }

        Ok(())
    }

    async fn get_client(&self, client_id: &str) -> Result<Option<Client>, OAuth2Error> {
        let client = match &self.pool {
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
                    INSERT INTO users (id, username, password_hash, email, enabled, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    "#,
                )
                .bind(&user.id)
                .bind(&user.username)
                .bind(&user.password_hash)
                .bind(&user.email)
                .bind(user.enabled)
                .bind(user.created_at)
                .bind(user.updated_at)
                .execute(pool)
                .await?;
            }
            DatabasePool::Postgres(pool) => {
                sqlx::query(
                    r#"
                    INSERT INTO users (id, username, password_hash, email, enabled, created_at, updated_at)
                    VALUES ($1, $2, $3, $4, $5, $6, $7)
                    "#,
                )
                .bind(&user.id)
                .bind(&user.username)
                .bind(&user.password_hash)
                .bind(&user.email)
                .bind(user.enabled)
                .bind(user.created_at)
                .bind(user.updated_at)
                .execute(pool)
                .await?;
            }
        }

        Ok(())
    }

    async fn get_user_by_username(&self, username: &str) -> Result<Option<User>, OAuth2Error> {
        let user = match &self.pool {
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

    async fn save_token(&self, token: &Token) -> Result<(), OAuth2Error> {
        match &self.pool {
            DatabasePool::Sqlite(pool) => {
                sqlx::query(
                    r#"
                    INSERT INTO tokens (id, access_token, refresh_token, token_type, expires_in, scope, client_id, user_id, created_at, expires_at, revoked)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                .execute(pool)
                .await?;
            }
            DatabasePool::Postgres(pool) => {
                sqlx::query(
                    r#"
                    INSERT INTO tokens (id, access_token, refresh_token, token_type, expires_in, scope, client_id, user_id, created_at, expires_at, revoked)
                    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
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
        let token = match &self.pool {
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

    async fn save_authorization_code(
        &self,
        auth_code: &AuthorizationCode,
    ) -> Result<(), OAuth2Error> {
        match &self.pool {
            DatabasePool::Sqlite(pool) => {
                sqlx::query(
                    r#"
                    INSERT INTO authorization_codes (id, code, client_id, user_id, redirect_uri, scope, created_at, expires_at, used, code_challenge, code_challenge_method)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                .execute(pool)
                .await?;
            }
            DatabasePool::Postgres(pool) => {
                sqlx::query(
                    r#"
                    INSERT INTO authorization_codes (id, code, client_id, user_id, redirect_uri, scope, created_at, expires_at, used, code_challenge, code_challenge_method)
                    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
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
        let auth_code = match &self.pool {
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
}

fn sqlite_parent_dir(database_url: &str) -> Option<&Path> {
    // sqlx accepts connection strings like:
    // - sqlite::memory:
    // - sqlite:oauth2.db
    // - sqlite:/app/data/oauth2.db
    // - sqlite:///app/data/oauth2.db
    // Potentially with query params appended.
    if !database_url.starts_with("sqlite:") {
        return None;
    }
    if database_url.starts_with("sqlite::memory:") {
        return None;
    }

    let mut rest = &database_url["sqlite:".len()..];

    // Normalize URL-ish forms into a filesystem-ish path by reducing multiple
    // leading slashes to a single leading slash.
    // - "///app/data/x.db" -> "/app/data/x.db"
    // - "//app/data/x.db"  -> "/app/data/x.db" (rare, but keep consistent)
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

    Path::new(path_part).parent()
}
