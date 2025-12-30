use crate::events::{AuthEvent, EventBusHandle, EventEnvelope, EventSeverity, EventType};
use crate::models::{Client, ClientRegistration, OAuth2Error};
use crate::storage::DynStorage;
use actix::prelude::*;
use rand::Rng;
use tracing::Instrument;

pub struct ClientActor {
    db: DynStorage,
    event_bus: Option<EventBusHandle>,
}

impl ClientActor {
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

impl Actor for ClientActor {
    type Context = Context<Self>;
}

#[derive(Message)]
#[rtype(result = "Result<Client, OAuth2Error>")]
pub struct RegisterClient {
    pub registration: ClientRegistration,
    pub span: tracing::Span,
}

impl Handler<RegisterClient> for ClientActor {
    type Result = ResponseFuture<Result<Client, OAuth2Error>>;

    fn handle(&mut self, msg: RegisterClient, _: &mut Self::Context) -> Self::Result {
        let db = self.db.clone();
        let event_bus = self.event_bus.clone();

        let parent_span = msg.span.clone();
        let actor_span = tracing::info_span!(
            parent: &parent_span,
            "actor.client.register",
            trace_id = tracing::field::Empty,
            span_id = tracing::field::Empty,
            client_name = %msg.registration.client_name,
            scope = %msg.registration.scope
        );
        crate::telemetry::annotate_span_with_trace_ids(&actor_span);

        Box::pin(
            async move {
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
                if let Some(event_bus) = event_bus {
                    let event = AuthEvent::new(
                        EventType::ClientRegistered,
                        EventSeverity::Info,
                        None,
                        Some(client_id),
                    )
                    .with_metadata("client_name", msg.registration.client_name)
                    .with_metadata("scope", msg.registration.scope);

                    let envelope = EventEnvelope::from_current_span(event, "oauth2_server");
                    event_bus.publish_best_effort(envelope);
                }

                Ok(client)
            }
            .instrument(actor_span),
        )
    }
}

#[derive(Message)]
#[rtype(result = "Result<Client, OAuth2Error>")]
pub struct GetClient {
    pub client_id: String,
    pub span: tracing::Span,
}

impl Handler<GetClient> for ClientActor {
    type Result = ResponseFuture<Result<Client, OAuth2Error>>;

    fn handle(&mut self, msg: GetClient, _: &mut Self::Context) -> Self::Result {
        let db = self.db.clone();

        let parent_span = msg.span.clone();
        let actor_span = tracing::info_span!(
            parent: &parent_span,
            "actor.client.get",
            trace_id = tracing::field::Empty,
            span_id = tracing::field::Empty,
            client_id = %msg.client_id
        );
        crate::telemetry::annotate_span_with_trace_ids(&actor_span);

        Box::pin(
            async move {
                db.get_client(&msg.client_id)
                    .await?
                    .ok_or_else(|| OAuth2Error::invalid_client("Client not found"))
            }
            .instrument(actor_span),
        )
    }
}

#[derive(Message)]
#[rtype(result = "Result<bool, OAuth2Error>")]
pub struct ValidateClient {
    pub client_id: String,
    pub client_secret: String,
    pub span: tracing::Span,
}

impl Handler<ValidateClient> for ClientActor {
    type Result = ResponseFuture<Result<bool, OAuth2Error>>;

    fn handle(&mut self, msg: ValidateClient, _: &mut Self::Context) -> Self::Result {
        let db = self.db.clone();
        let event_bus = self.event_bus.clone();

        let parent_span = msg.span.clone();
        let actor_span = tracing::info_span!(
            parent: &parent_span,
            "actor.client.validate",
            trace_id = tracing::field::Empty,
            span_id = tracing::field::Empty,
            client_id = %msg.client_id
        );
        crate::telemetry::annotate_span_with_trace_ids(&actor_span);

        Box::pin(
            async move {
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
                if let Some(event_bus) = event_bus {
                    let event = AuthEvent::new(
                        EventType::ClientValidated,
                        EventSeverity::Info,
                        None,
                        Some(msg.client_id),
                    )
                    .with_metadata("success", if secret_match { "true" } else { "false" });

                    let envelope = EventEnvelope::from_current_span(event, "oauth2_server");
                    event_bus.publish_best_effort(envelope);
                }

                Ok(secret_match)
            }
            .instrument(actor_span),
        )
    }
}

fn generate_secret() -> String {
    let mut rng = rand::rng();
    let secret: String = (0..32)
        .map(|_| {
            let idx = rng.random_range(0..62);
            match idx {
                0..=25 => (b'a' + idx) as char,
                26..=51 => (b'A' + (idx - 26)) as char,
                _ => (b'0' + (idx - 52)) as char,
            }
        })
        .collect();
    secret
}
