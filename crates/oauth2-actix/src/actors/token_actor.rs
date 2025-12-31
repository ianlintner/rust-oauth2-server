use actix::prelude::*;
use oauth2_events::{AuthEvent, EventBusHandle, EventEnvelope, EventSeverity, EventType};
use oauth2_observability::annotate_span_with_trace_ids;
use oauth2_ports::DynStorage;
use tracing::Instrument;

use oauth2_core::{Claims, OAuth2Error, Token};

pub struct TokenActor {
    db: DynStorage,
    jwt_secret: String,
    event_bus: Option<EventBusHandle>,
}

impl TokenActor {
    pub fn new(db: DynStorage, jwt_secret: String) -> Self {
        Self {
            db,
            jwt_secret,
            event_bus: None,
        }
    }

    pub fn with_events(db: DynStorage, jwt_secret: String, event_bus: EventBusHandle) -> Self {
        Self {
            db,
            jwt_secret,
            event_bus: Some(event_bus),
        }
    }
}

impl Actor for TokenActor {
    type Context = Context<Self>;
}

#[derive(Message)]
#[rtype(result = "Result<Token, OAuth2Error>")]
pub struct CreateToken {
    pub user_id: Option<String>,
    pub client_id: String,
    pub scope: String,
    pub include_refresh: bool,
    pub span: tracing::Span,
}

impl Handler<CreateToken> for TokenActor {
    type Result = ResponseFuture<Result<Token, OAuth2Error>>;

    fn handle(&mut self, msg: CreateToken, _: &mut Self::Context) -> Self::Result {
        let db = self.db.clone();
        let jwt_secret = self.jwt_secret.clone();
        let event_bus = self.event_bus.clone();

        let parent_span = msg.span.clone();
        let actor_span = tracing::info_span!(
            parent: &parent_span,
            "actor.token.create",
            trace_id = tracing::field::Empty,
            span_id = tracing::field::Empty,
            client_id = %msg.client_id,
            user_id = %msg.user_id.as_deref().unwrap_or(""),
            include_refresh = msg.include_refresh
        );
        annotate_span_with_trace_ids(&actor_span);

        Box::pin(
            async move {
                let subject = msg.user_id.clone().unwrap_or_else(|| msg.client_id.clone());

                // Create access token
                let access_claims = Claims::new(
                    subject.clone(),
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
                        subject,
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
                if let Some(event_bus) = event_bus {
                    let event = AuthEvent::new(
                        EventType::TokenCreated,
                        EventSeverity::Info,
                        msg.user_id,
                        Some(msg.client_id),
                    )
                    .with_metadata("scope", msg.scope)
                    .with_metadata("has_refresh_token", msg.include_refresh.to_string());

                    let envelope = EventEnvelope::from_current_span(event, "oauth2_server");
                    event_bus.publish_best_effort(envelope);
                }

                Ok(token)
            }
            .instrument(actor_span),
        )
    }
}

#[derive(Message)]
#[rtype(result = "Result<Token, OAuth2Error>")]
pub struct ValidateToken {
    pub token: String,
    pub span: tracing::Span,
}

impl Handler<ValidateToken> for TokenActor {
    type Result = ResponseFuture<Result<Token, OAuth2Error>>;

    fn handle(&mut self, msg: ValidateToken, _: &mut Self::Context) -> Self::Result {
        let db = self.db.clone();
        let event_bus = self.event_bus.clone();
        let parent_span = msg.span.clone();
        let raw_token = msg.token;
        let token_prefix = raw_token.trim().chars().take(12).collect::<String>();
        let actor_span = tracing::info_span!(
            parent: &parent_span,
            "actor.token.validate",
            trace_id = tracing::field::Empty,
            span_id = tracing::field::Empty,
            token_prefix = %token_prefix,
            token_len = raw_token.len()
        );
        annotate_span_with_trace_ids(&actor_span);

        Box::pin(
            async move {
                // Be forgiving about whitespace and callers that accidentally include a Bearer prefix.
                let token_trimmed = raw_token.trim();
                let token_normalized = token_trimmed
                    .strip_prefix("Bearer ")
                    .unwrap_or(token_trimmed)
                    .trim();

                let token_prefix = token_normalized.chars().take(20).collect::<String>();
                tracing::info!(
                    token_len = token_normalized.len(),
                    token_prefix = %token_prefix,
                    "ValidateToken called"
                );

                let token = db
                    .get_token_by_access_token(token_normalized)
                    .await?
                    .ok_or_else(|| OAuth2Error::invalid_grant("Token not found"))?;

                if !token.is_valid() {
                    tracing::warn!(
                        revoked = token.revoked,
                        expires_at = %token.expires_at,
                        now = %chrono::Utc::now(),
                        token_len = token_normalized.len(),
                        token_prefix = %token_prefix,
                        "Token is not valid (expired or revoked)"
                    );
                    // Emit expired/invalid event
                    if let Some(event_bus) = &event_bus {
                        let event = AuthEvent::new(
                            EventType::TokenExpired,
                            EventSeverity::Warning,
                            token.user_id.clone(),
                            Some(token.client_id.clone()),
                        );
                        let envelope = EventEnvelope::from_current_span(event, "oauth2_server");
                        event_bus.publish_best_effort(envelope);
                    }

                    return Err(OAuth2Error::invalid_grant("Token is expired or revoked"));
                }

                // Emit validated event
                if let Some(event_bus) = event_bus {
                    let event = AuthEvent::new(
                        EventType::TokenValidated,
                        EventSeverity::Info,
                        token.user_id.clone(),
                        Some(token.client_id.clone()),
                    );
                    let envelope = EventEnvelope::from_current_span(event, "oauth2_server");
                    event_bus.publish_best_effort(envelope);
                }

                Ok(token)
            }
            .instrument(actor_span),
        )
    }
}

#[derive(Message)]
#[rtype(result = "Result<(), OAuth2Error>")]
pub struct RevokeToken {
    pub token: String,
    pub span: tracing::Span,
}

impl Handler<RevokeToken> for TokenActor {
    type Result = ResponseFuture<Result<(), OAuth2Error>>;

    fn handle(&mut self, msg: RevokeToken, _: &mut Self::Context) -> Self::Result {
        let db = self.db.clone();
        let event_bus = self.event_bus.clone();

        let parent_span = msg.span.clone();
        let token_prefix = msg.token.trim().chars().take(12).collect::<String>();
        let actor_span = tracing::info_span!(
            parent: &parent_span,
            "actor.token.revoke",
            trace_id = tracing::field::Empty,
            span_id = tracing::field::Empty,
            token_prefix = %token_prefix,
            token_len = msg.token.len()
        );
        annotate_span_with_trace_ids(&actor_span);

        Box::pin(
            async move {
                // Get token info before revoking for event
                let token_info = db.get_token_by_access_token(&msg.token).await?;

                db.revoke_token(&msg.token).await?;

                // Emit revoked event
                if let Some(event_bus) = event_bus {
                    if let Some(token) = token_info {
                        let event = AuthEvent::new(
                            EventType::TokenRevoked,
                            EventSeverity::Info,
                            token.user_id,
                            Some(token.client_id),
                        );
                        let envelope = EventEnvelope::from_current_span(event, "oauth2_server");
                        event_bus.publish_best_effort(envelope);
                    }
                }

                Ok(())
            }
            .instrument(actor_span),
        )
    }
}
