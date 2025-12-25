#![allow(dead_code)]

use crate::models::{AuthorizationCode, Client, OAuth2Error, Token, User};
use sqlx::{Pool, Sqlite, SqlitePool};

pub struct Database {
    pool: Pool<Sqlite>,
}

impl Database {
    pub async fn new(database_url: &str) -> Result<Self, sqlx::Error> {
        let pool = SqlitePool::connect(database_url).await?;
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
