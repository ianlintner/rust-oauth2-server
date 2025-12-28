use crate::events::{
    event_actor::{EmitEvent, EventActor},
    AuthEvent, EventSeverity, EventType,
};
use crate::models::{AuthorizationCode, OAuth2Error};
use crate::storage::DynStorage;
use actix::prelude::*;
use rand::Rng;

pub struct AuthActor {
    db: DynStorage,
    event_actor: Option<Addr<EventActor>>,
}

impl AuthActor {
    pub fn new(db: DynStorage) -> Self {
        Self {
            db,
            event_actor: None,
        }
    }

    pub fn with_events(db: DynStorage, event_actor: Addr<EventActor>) -> Self {
        Self {
            db,
            event_actor: Some(event_actor),
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
}

impl Handler<CreateAuthorizationCode> for AuthActor {
    type Result = ResponseFuture<Result<AuthorizationCode, OAuth2Error>>;

    fn handle(&mut self, msg: CreateAuthorizationCode, _: &mut Self::Context) -> Self::Result {
        let db = self.db.clone();
        let event_actor = self.event_actor.clone();

        Box::pin(async move {
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
            if let Some(event_actor) = event_actor {
                let event = AuthEvent::new(
                    EventType::AuthorizationCodeCreated,
                    EventSeverity::Info,
                    Some(msg.user_id.clone()),
                    Some(msg.client_id.clone()),
                )
                .with_metadata("scope", msg.scope)
                .with_metadata("redirect_uri", msg.redirect_uri);

                event_actor.do_send(EmitEvent { event });
            }

            Ok(auth_code)
        })
    }
}

#[derive(Message)]
#[rtype(result = "Result<AuthorizationCode, OAuth2Error>")]
pub struct ValidateAuthorizationCode {
    pub code: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub code_verifier: Option<String>,
}

impl Handler<ValidateAuthorizationCode> for AuthActor {
    type Result = ResponseFuture<Result<AuthorizationCode, OAuth2Error>>;

    fn handle(&mut self, msg: ValidateAuthorizationCode, _: &mut Self::Context) -> Self::Result {
        let db = self.db.clone();
        let event_actor = self.event_actor.clone();

        Box::pin(async move {
            let auth_code = db
                .get_authorization_code(&msg.code)
                .await?
                .ok_or_else(|| OAuth2Error::invalid_grant("Authorization code not found"))?;

            if !auth_code.is_valid() {
                // Emit expired event
                if let Some(event_actor) = &event_actor {
                    let event = AuthEvent::new(
                        EventType::AuthorizationCodeExpired,
                        EventSeverity::Warning,
                        Some(auth_code.user_id.clone()),
                        Some(auth_code.client_id.clone()),
                    );
                    event_actor.do_send(EmitEvent { event });
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

            // Mark as used
            db.mark_authorization_code_used(&msg.code).await?;

            // Emit validated event
            if let Some(event_actor) = event_actor {
                let event = AuthEvent::new(
                    EventType::AuthorizationCodeValidated,
                    EventSeverity::Info,
                    Some(auth_code.user_id.clone()),
                    Some(auth_code.client_id.clone()),
                );
                event_actor.do_send(EmitEvent { event });
            }

            Ok(auth_code)
        })
    }
}

fn generate_code() -> String {
    let mut rng = rand::thread_rng();
    let code: String = (0..32)
        .map(|_| {
            let idx = rng.gen_range(0..62);
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
