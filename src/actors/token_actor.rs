use crate::db::Database;
use crate::events::{
    event_actor::{EmitEvent, EventActor},
    AuthEvent, EventSeverity, EventType,
};
use crate::models::{Claims, OAuth2Error, Token};
use actix::prelude::*;
use std::sync::Arc;

pub struct TokenActor {
    db: Arc<Database>,
    jwt_secret: String,
    event_actor: Option<Addr<EventActor>>,
}

impl TokenActor {
    pub fn new(db: Arc<Database>, jwt_secret: String) -> Self {
        Self {
            db,
            jwt_secret,
            event_actor: None,
        }
    }

    pub fn with_events(
        db: Arc<Database>,
        jwt_secret: String,
        event_actor: Addr<EventActor>,
    ) -> Self {
        Self {
            db,
            jwt_secret,
            event_actor: Some(event_actor),
        }
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
        let event_actor = self.event_actor.clone();

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
                msg.client_id.clone(),
                msg.user_id.clone(),
                msg.scope.clone(),
                3600,
            );

            db.save_token(&token).await?;

            // Emit event
            if let Some(event_actor) = event_actor {
                let event = AuthEvent::new(
                    EventType::TokenCreated,
                    EventSeverity::Info,
                    Some(msg.user_id),
                    Some(msg.client_id),
                )
                .with_metadata("scope", msg.scope)
                .with_metadata("has_refresh_token", msg.include_refresh.to_string());

                event_actor.do_send(EmitEvent { event });
            }

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
        let event_actor = self.event_actor.clone();

        Box::pin(async move {
            let token = db
                .get_token_by_access_token(&msg.token)
                .await?
                .ok_or_else(|| OAuth2Error::invalid_grant("Token not found"))?;

            if !token.is_valid() {
                // Emit expired/invalid event
                if let Some(event_actor) = &event_actor {
                    let event = AuthEvent::new(
                        EventType::TokenExpired,
                        EventSeverity::Warning,
                        Some(token.user_id.clone()),
                        Some(token.client_id.clone()),
                    );
                    event_actor.do_send(EmitEvent { event });
                }

                return Err(OAuth2Error::invalid_grant("Token is expired or revoked"));
            }

            // Emit validated event
            if let Some(event_actor) = event_actor {
                let event = AuthEvent::new(
                    EventType::TokenValidated,
                    EventSeverity::Info,
                    Some(token.user_id.clone()),
                    Some(token.client_id.clone()),
                );
                event_actor.do_send(EmitEvent { event });
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
        let event_actor = self.event_actor.clone();

        Box::pin(async move {
            // Get token info before revoking for event
            let token_info = db.get_token_by_access_token(&msg.token).await?;

            db.revoke_token(&msg.token).await?;

            // Emit revoked event
            if let Some(event_actor) = event_actor {
                if let Some(token) = token_info {
                    let event = AuthEvent::new(
                        EventType::TokenRevoked,
                        EventSeverity::Info,
                        Some(token.user_id),
                        Some(token.client_id),
                    );
                    event_actor.do_send(EmitEvent { event });
                }
            }

            Ok(())
        })
    }
}
