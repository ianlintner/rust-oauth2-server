#![allow(dead_code)]

use crate::models::{AuthorizationCode, Client, OAuth2Error, Token, User};
use sqlx::sqlite::SqliteConnectOptions;
use sqlx::{Pool, Sqlite, SqlitePool};
use std::path::Path;
use std::str::FromStr;

pub struct Database {
    pool: Pool<Sqlite>,
}

impl Database {
    pub async fn new(database_url: &str) -> Result<Self, sqlx::Error> {
        // In containerized environments (KIND/Kubernetes), a common failure mode is that the
        // directory for the sqlite DB file doesn't exist or isn't writable yet.
        // This proactively creates the parent directory (when we can infer one) and tells sqlx
        // to create the database file if missing.
        if let Some(parent_dir) = sqlite_parent_dir(database_url) {
            // Best-effort: if we can't create it (permissions, etc.), sqlx will surface the
            // underlying error on connect.
            let _ = std::fs::create_dir_all(parent_dir);
        }

        let options = SqliteConnectOptions::from_str(database_url)?.create_if_missing(true);
        let pool = SqlitePool::connect_with(options).await?;
        Ok(Self { pool })
    }

    pub async fn init(&self) -> Result<(), sqlx::Error> {
        // With Flyway, we don't need to create tables here
        // Just verify the connection works
        sqlx::query("SELECT 1").execute(&self.pool).await?;
        Ok(())
    }

    // Client operations
    pub async fn save_client(&self, client: &Client) -> Result<(), OAuth2Error> {
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
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn get_client(&self, client_id: &str) -> Result<Option<Client>, OAuth2Error> {
        let client = sqlx::query_as::<_, Client>("SELECT * FROM clients WHERE client_id = ?")
            .bind(client_id)
            .fetch_optional(&self.pool)
            .await?;
        Ok(client)
    }

    // User operations
    pub async fn save_user(&self, user: &User) -> Result<(), OAuth2Error> {
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
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn get_user_by_username(&self, username: &str) -> Result<Option<User>, OAuth2Error> {
        let user = sqlx::query_as::<_, User>("SELECT * FROM users WHERE username = ?")
            .bind(username)
            .fetch_optional(&self.pool)
            .await?;
        Ok(user)
    }

    // Token operations
    pub async fn save_token(&self, token: &Token) -> Result<(), OAuth2Error> {
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
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn get_token_by_access_token(
        &self,
        access_token: &str,
    ) -> Result<Option<Token>, OAuth2Error> {
        let token = sqlx::query_as::<_, Token>("SELECT * FROM tokens WHERE access_token = ?")
            .bind(access_token)
            .fetch_optional(&self.pool)
            .await?;
        Ok(token)
    }

    pub async fn revoke_token(&self, token: &str) -> Result<(), OAuth2Error> {
        sqlx::query("UPDATE tokens SET revoked = 1 WHERE access_token = ? OR refresh_token = ?")
            .bind(token)
            .bind(token)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    // Authorization code operations
    pub async fn save_authorization_code(
        &self,
        auth_code: &AuthorizationCode,
    ) -> Result<(), OAuth2Error> {
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
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn get_authorization_code(
        &self,
        code: &str,
    ) -> Result<Option<AuthorizationCode>, OAuth2Error> {
        let auth_code = sqlx::query_as::<_, AuthorizationCode>(
            "SELECT * FROM authorization_codes WHERE code = ?",
        )
        .bind(code)
        .fetch_optional(&self.pool)
        .await?;
        Ok(auth_code)
    }

    pub async fn mark_authorization_code_used(&self, code: &str) -> Result<(), OAuth2Error> {
        sqlx::query("UPDATE authorization_codes SET used = 1 WHERE code = ?")
            .bind(code)
            .execute(&self.pool)
            .await?;
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
