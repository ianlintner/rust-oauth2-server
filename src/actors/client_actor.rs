use crate::db::Database;
use crate::events::{
    event_actor::{EmitEvent, EventActor},
    AuthEvent, EventSeverity, EventType,
};
use crate::models::{Client, ClientRegistration, OAuth2Error};
use actix::prelude::*;
use rand::Rng;
use std::sync::Arc;

pub struct ClientActor {
    db: Arc<Database>,
    event_actor: Option<Addr<EventActor>>,
}

impl ClientActor {
    pub fn new(db: Arc<Database>) -> Self {
        Self {
            db,
            event_actor: None,
        }
    }

    pub fn with_events(db: Arc<Database>, event_actor: Addr<EventActor>) -> Self {
        Self {
            db,
            event_actor: Some(event_actor),
        }
    }
}

impl Actor for ClientActor {
    type Context = Context<Self>;
}

#[derive(Message)]
#[rtype(result = "Result<Client, OAuth2Error>")]
pub struct RegisterClient {
    pub registration: ClientRegistration,
}

impl Handler<RegisterClient> for ClientActor {
    type Result = ResponseFuture<Result<Client, OAuth2Error>>;

    fn handle(&mut self, msg: RegisterClient, _: &mut Self::Context) -> Self::Result {
        let db = self.db.clone();
        let event_actor = self.event_actor.clone();

        Box::pin(async move {
            // Generate client credentials
            let client_id = format!("client_{}", uuid::Uuid::new_v4());
            let client_secret = generate_secret();

            let client = Client::new(
                client_id.clone(),
                client_secret,
                msg.registration.redirect_uris,
                msg.registration.grant_types,
                msg.registration.scope.clone(),
                msg.registration.client_name.clone(),
            );

            db.save_client(&client).await?;

            // Emit event
            if let Some(event_actor) = event_actor {
                let event = AuthEvent::new(
                    EventType::ClientRegistered,
                    EventSeverity::Info,
                    None,
                    Some(client_id),
                )
                .with_metadata("client_name", msg.registration.client_name)
                .with_metadata("scope", msg.registration.scope);

                event_actor.do_send(EmitEvent { event });
            }

            Ok(client)
        })
    }
}

#[derive(Message)]
#[rtype(result = "Result<Client, OAuth2Error>")]
pub struct GetClient {
    pub client_id: String,
}

impl Handler<GetClient> for ClientActor {
    type Result = ResponseFuture<Result<Client, OAuth2Error>>;

    fn handle(&mut self, msg: GetClient, _: &mut Self::Context) -> Self::Result {
        let db = self.db.clone();

        Box::pin(async move {
            db.get_client(&msg.client_id)
                .await?
                .ok_or_else(|| OAuth2Error::invalid_client("Client not found"))
        })
    }
}

#[derive(Message)]
#[rtype(result = "Result<bool, OAuth2Error>")]
pub struct ValidateClient {
    pub client_id: String,
    pub client_secret: String,
}

impl Handler<ValidateClient> for ClientActor {
    type Result = ResponseFuture<Result<bool, OAuth2Error>>;

    fn handle(&mut self, msg: ValidateClient, _: &mut Self::Context) -> Self::Result {
        let db = self.db.clone();
        let event_actor = self.event_actor.clone();

        Box::pin(async move {
            let client = db
                .get_client(&msg.client_id)
                .await?
                .ok_or_else(|| OAuth2Error::invalid_client("Client not found"))?;

            // Use constant-time comparison to prevent timing attacks
            use subtle::ConstantTimeEq;
            let secret_match = client
                .client_secret
                .as_bytes()
                .ct_eq(msg.client_secret.as_bytes())
                .into();

            // Emit event
            if let Some(event_actor) = event_actor {
                let event = AuthEvent::new(
                    EventType::ClientValidated,
                    EventSeverity::Info,
                    None,
                    Some(msg.client_id),
                )
                .with_metadata("success", if secret_match { "true" } else { "false" });

                event_actor.do_send(EmitEvent { event });
            }

            Ok(secret_match)
        })
    }
}

fn generate_secret() -> String {
    let mut rng = rand::thread_rng();
    let secret: String = (0..32)
        .map(|_| {
            let idx = rng.gen_range(0..62);
            match idx {
                0..=25 => (b'a' + idx) as char,
                26..=51 => (b'A' + (idx - 26)) as char,
                _ => (b'0' + (idx - 52)) as char,
            }
        })
        .collect();
    secret
}
