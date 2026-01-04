use actix::prelude::*;
use oauth2_events::{AuthEvent, EventBusHandle, EventEnvelope, EventSeverity, EventType};
use oauth2_observability::annotate_span_with_trace_ids;
use oauth2_ports::DynStorage;
use rand::Rng;
use tracing::Instrument;

use oauth2_core::{AuthorizationCode, OAuth2Error};

pub struct AuthActor {
    db: DynStorage,
    event_bus: Option<EventBusHandle>,
}

impl AuthActor {
    pub fn new(db: DynStorage) -> Self {
        Self {
            db,
            event_bus: None,
        }
    }

    pub fn with_events(db: DynStorage, event_bus: EventBusHandle) -> Self {
        Self {
            db,
            event_bus: Some(event_bus),
        }
    }
}

impl Actor for AuthActor {
    type Context = Context<Self>;
}

#[derive(Message)]
#[rtype(result = "Result<AuthorizationCode, OAuth2Error>")]
pub struct CreateAuthorizationCode {
    pub client_id: String,
    pub user_id: String,
    pub redirect_uri: String,
    pub scope: String,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
    pub span: tracing::Span,
}

impl Handler<CreateAuthorizationCode> for AuthActor {
    type Result = ResponseFuture<Result<AuthorizationCode, OAuth2Error>>;

    fn handle(&mut self, msg: CreateAuthorizationCode, _: &mut Self::Context) -> Self::Result {
        let db = self.db.clone();
        let event_bus = self.event_bus.clone();

        let parent_span = msg.span.clone();
        let actor_span = tracing::info_span!(
            parent: &parent_span,
            "actor.auth.create_authorization_code",
            trace_id = tracing::field::Empty,
            span_id = tracing::field::Empty,
            client_id = %msg.client_id,
            user_id = %msg.user_id
        );
        annotate_span_with_trace_ids(&actor_span);

        Box::pin(
            async move {
                let code = generate_code();
                let auth_code = AuthorizationCode::new(
                    code,
                    msg.client_id.clone(),
                    msg.user_id.clone(),
                    msg.redirect_uri.clone(),
                    msg.scope.clone(),
                    msg.code_challenge,
                    msg.code_challenge_method,
                );

                db.save_authorization_code(&auth_code).await?;

                // Emit event
                if let Some(event_bus) = event_bus {
                    let event = AuthEvent::new(
                        EventType::AuthorizationCodeCreated,
                        EventSeverity::Info,
                        Some(msg.user_id.clone()),
                        Some(msg.client_id.clone()),
                    )
                    .with_metadata("scope", msg.scope)
                    .with_metadata("redirect_uri", msg.redirect_uri);

                    let envelope = EventEnvelope::from_current_span(event, "oauth2_server");
                    event_bus.publish_best_effort(envelope);
                }

                Ok(auth_code)
            }
            .instrument(actor_span),
        )
    }
}

#[derive(Message)]
#[rtype(result = "Result<AuthorizationCode, OAuth2Error>")]
pub struct ValidateAuthorizationCode {
    pub code: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub code_verifier: Option<String>,
    pub span: tracing::Span,
}

#[derive(Message)]
#[rtype(result = "Result<(), OAuth2Error>")]
pub struct MarkAuthorizationCodeUsed {
    pub code: String,
    pub span: tracing::Span,
}

impl Handler<ValidateAuthorizationCode> for AuthActor {
    type Result = ResponseFuture<Result<AuthorizationCode, OAuth2Error>>;

    fn handle(&mut self, msg: ValidateAuthorizationCode, _: &mut Self::Context) -> Self::Result {
        let db = self.db.clone();
        let event_bus = self.event_bus.clone();

        let parent_span = msg.span.clone();
        let code_prefix = msg.code.chars().take(12).collect::<String>();
        let actor_span = tracing::info_span!(
            parent: &parent_span,
            "actor.auth.validate_authorization_code",
            trace_id = tracing::field::Empty,
            span_id = tracing::field::Empty,
            client_id = %msg.client_id,
            code_prefix = %code_prefix,
            code_len = msg.code.len()
        );
        annotate_span_with_trace_ids(&actor_span);

        Box::pin(
            async move {
                let auth_code = db
                    .get_authorization_code(&msg.code)
                    .await?
                    .ok_or_else(|| OAuth2Error::invalid_grant("Authorization code not found"))?;

                if !auth_code.is_valid() {
                    // Emit expired event
                    if let Some(event_bus) = &event_bus {
                        let event = AuthEvent::new(
                            EventType::AuthorizationCodeExpired,
                            EventSeverity::Warning,
                            Some(auth_code.user_id.clone()),
                            Some(auth_code.client_id.clone()),
                        );
                        let envelope = EventEnvelope::from_current_span(event, "oauth2_server");
                        event_bus.publish_best_effort(envelope);
                    }

                    return Err(OAuth2Error::invalid_grant(
                        "Authorization code is expired or used",
                    ));
                }

                if auth_code.client_id != msg.client_id {
                    return Err(OAuth2Error::invalid_grant("Client ID mismatch"));
                }

                if auth_code.redirect_uri != msg.redirect_uri {
                    return Err(OAuth2Error::invalid_grant("Redirect URI mismatch"));
                }

                // Validate PKCE if present
                if let Some(challenge) = &auth_code.code_challenge {
                    let verifier = msg
                        .code_verifier
                        .ok_or_else(|| OAuth2Error::invalid_grant("Code verifier required"))?;

                    let method = auth_code
                        .code_challenge_method
                        .as_deref()
                        .unwrap_or("plain");
                    if !validate_pkce(challenge, &verifier, method) {
                        return Err(OAuth2Error::invalid_grant("Invalid code verifier"));
                    }
                }

                Ok(auth_code)
            }
            .instrument(actor_span),
        )
    }
}

impl Handler<MarkAuthorizationCodeUsed> for AuthActor {
    type Result = ResponseFuture<Result<(), OAuth2Error>>;

    fn handle(&mut self, msg: MarkAuthorizationCodeUsed, _: &mut Self::Context) -> Self::Result {
        let db = self.db.clone();
        let event_bus = self.event_bus.clone();

        let parent_span = msg.span.clone();
        let code_prefix = msg.code.chars().take(12).collect::<String>();
        let actor_span = tracing::info_span!(
            parent: &parent_span,
            "actor.auth.mark_authorization_code_used",
            trace_id = tracing::field::Empty,
            span_id = tracing::field::Empty,
            code_prefix = %code_prefix,
            code_len = msg.code.len()
        );
        annotate_span_with_trace_ids(&actor_span);

        Box::pin(
            async move {
                // Idempotent in storage implementations: marking an already-used code used again
                // should be safe.
                let auth_code = db
                    .get_authorization_code(&msg.code)
                    .await?
                    .ok_or_else(|| OAuth2Error::invalid_grant("Authorization code not found"))?;

                db.mark_authorization_code_used(&msg.code).await?;

                // Emit validated/consumed event
                if let Some(event_bus) = event_bus {
                    let event = AuthEvent::new(
                        EventType::AuthorizationCodeValidated,
                        EventSeverity::Info,
                        Some(auth_code.user_id.clone()),
                        Some(auth_code.client_id.clone()),
                    );
                    let envelope = EventEnvelope::from_current_span(event, "oauth2_server");
                    event_bus.publish_best_effort(envelope);
                }

                Ok(())
            }
            .instrument(actor_span),
        )
    }
}

fn generate_code() -> String {
    let mut rng = rand::rng();
    let code: String = (0..32)
        .map(|_| {
            let idx = rng.random_range(0..62);
            match idx {
                0..=25 => (b'a' + idx) as char,
                26..=51 => (b'A' + (idx - 26)) as char,
                _ => (b'0' + (idx - 52)) as char,
            }
        })
        .collect();
    code
}

fn validate_pkce(challenge: &str, verifier: &str, method: &str) -> bool {
    match method {
        "plain" => challenge == verifier,
        "S256" => {
            use base64::{engine::general_purpose, Engine as _};
            use sha2::{Digest, Sha256};

            let mut hasher = Sha256::new();
            hasher.update(verifier.as_bytes());
            let result = hasher.finalize();
            let encoded = general_purpose::URL_SAFE_NO_PAD.encode(result);
            challenge == encoded
        }
        _ => false,
    }
}
