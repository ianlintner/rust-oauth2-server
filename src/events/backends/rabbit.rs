use crate::events::{EventEnvelope, EventPlugin};
use async_trait::async_trait;
use lapin::{
    options::{BasicPublishOptions, ExchangeDeclareOptions},
    types::FieldTable,
    BasicProperties, Channel, Connection, ConnectionProperties, ExchangeKind,
};

/// RabbitMQ event publisher.
///
/// Publishes envelopes as JSON to a Rabbit exchange with a routing key.
pub struct RabbitEventPublisher {
    channel: Channel,
    exchange: String,
    routing_key: String,
}

impl RabbitEventPublisher {
    pub async fn connect(
        amqp_url: &str,
        exchange: impl Into<String>,
        routing_key: impl Into<String>,
    ) -> Result<Self, String> {
        let exchange = exchange.into();
        let routing_key = routing_key.into();

        let conn = Connection::connect(amqp_url, ConnectionProperties::default())
            .await
            .map_err(|e| format!("rabbit connect: {e}"))?;

        let channel = conn
            .create_channel()
            .await
            .map_err(|e| format!("rabbit create_channel: {e}"))?;

        // Ensure the exchange exists. Topic is flexible and common for event routing.
        channel
            .exchange_declare(
                &exchange,
                ExchangeKind::Topic,
                ExchangeDeclareOptions {
                    durable: true,
                    ..Default::default()
                },
                FieldTable::default(),
            )
            .await
            .map_err(|e| format!("rabbit exchange_declare: {e}"))?;

        Ok(Self {
            channel,
            exchange,
            routing_key,
        })
    }
}

#[async_trait]
impl EventPlugin for RabbitEventPublisher {
    async fn emit(&self, envelope: &EventEnvelope) -> Result<(), String> {
        let payload =
            serde_json::to_vec(envelope).map_err(|e| format!("serialize envelope: {e}"))?;

        // Best-effort publish. We still await server ack for immediate errors.
        self.channel
            .basic_publish(
                &self.exchange,
                &self.routing_key,
                BasicPublishOptions::default(),
                &payload,
                BasicProperties::default()
                    .with_content_type("application/json".into())
                    .with_message_id(envelope.event.id.to_string().into())
                    .with_correlation_id(envelope.correlation_id.clone().into()),
            )
            .await
            .map_err(|e| format!("rabbit basic_publish: {e}"))?
            .await
            .map_err(|e| format!("rabbit publish_confirm: {e}"))?;

        Ok(())
    }

    fn name(&self) -> &str {
        "rabbit"
    }

    async fn health_check(&self) -> bool {
        // `status()` is cheap and doesn't require extra network ops.
        self.channel.status().connected()
    }
}
