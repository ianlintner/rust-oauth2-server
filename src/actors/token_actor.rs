use crate::db::Database;
use crate::models::{Claims, OAuth2Error, Token};
use actix::prelude::*;
use std::sync::Arc;

pub struct TokenActor {
    db: Arc<Database>,
    jwt_secret: String,
}

impl TokenActor {
    pub fn new(db: Arc<Database>, jwt_secret: String) -> Self {
        Self { db, jwt_secret }
    }
}

impl Actor for TokenActor {
    type Context = Context<Self>;
}

#[derive(Message)]
#[rtype(result = "Result<Token, OAuth2Error>")]
pub struct CreateToken {
    pub user_id: String,
    pub client_id: String,
    pub scope: String,
    pub include_refresh: bool,
}

impl Handler<CreateToken> for TokenActor {
    type Result = ResponseFuture<Result<Token, OAuth2Error>>;

    fn handle(&mut self, msg: CreateToken, _: &mut Self::Context) -> Self::Result {
        let db = self.db.clone();
        let jwt_secret = self.jwt_secret.clone();

        Box::pin(async move {
            // Create access token
            let access_claims = Claims::new(
                msg.user_id.clone(),
                msg.client_id.clone(),
                msg.scope.clone(),
                3600, // 1 hour
            );
            let access_token = access_claims
                .encode(&jwt_secret)
                .map_err(|e| OAuth2Error::new("server_error", Some(&e.to_string())))?;

            // Create refresh token if requested
            let refresh_token = if msg.include_refresh {
                let refresh_claims = Claims::new(
                    msg.user_id.clone(),
                    msg.client_id.clone(),
                    msg.scope.clone(),
                    2592000, // 30 days
                );
                Some(
                    refresh_claims
                        .encode(&jwt_secret)
                        .map_err(|e| OAuth2Error::new("server_error", Some(&e.to_string())))?,
                )
            } else {
                None
            };

            let token = Token::new(
                access_token,
                refresh_token,
                msg.client_id,
                msg.user_id,
                msg.scope,
                3600,
            );

            db.save_token(&token).await?;
            Ok(token)
        })
    }
}

#[derive(Message)]
#[rtype(result = "Result<Token, OAuth2Error>")]
pub struct ValidateToken {
    pub token: String,
}

impl Handler<ValidateToken> for TokenActor {
    type Result = ResponseFuture<Result<Token, OAuth2Error>>;

    fn handle(&mut self, msg: ValidateToken, _: &mut Self::Context) -> Self::Result {
        let db = self.db.clone();

        Box::pin(async move {
            let token = db
                .get_token_by_access_token(&msg.token)
                .await?
                .ok_or_else(|| OAuth2Error::invalid_grant("Token not found"))?;

            if !token.is_valid() {
                return Err(OAuth2Error::invalid_grant("Token is expired or revoked"));
            }

            Ok(token)
        })
    }
}

#[derive(Message)]
#[rtype(result = "Result<(), OAuth2Error>")]
pub struct RevokeToken {
    pub token: String,
}

impl Handler<RevokeToken> for TokenActor {
    type Result = ResponseFuture<Result<(), OAuth2Error>>;

    fn handle(&mut self, msg: RevokeToken, _: &mut Self::Context) -> Self::Result {
        let db = self.db.clone();

        Box::pin(async move {
            db.revoke_token(&msg.token).await?;
            Ok(())
        })
    }
}
