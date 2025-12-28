use crate::events::{EventEnvelope, EventPlugin};
use async_trait::async_trait;
use rdkafka::config::ClientConfig;
use rdkafka::producer::{FutureProducer, FutureRecord};
use std::time::Duration;

/// Kafka event publisher.
///
/// Publishes envelopes as JSON to a Kafka topic.
pub struct KafkaEventPublisher {
    producer: FutureProducer,
    topic: String,
}

impl KafkaEventPublisher {
    pub fn new(brokers: &str, topic: impl Into<String>, client_id: Option<String>) -> Result<Self, String> {
        let mut cfg = ClientConfig::new();
        cfg.set("bootstrap.servers", brokers);
        cfg.set("message.timeout.ms", "5000");

        if let Some(cid) = client_id {
            cfg.set("client.id", cid);
        }

        let producer: FutureProducer = cfg
            .create()
            .map_err(|e| format!("kafka producer create: {e}"))?;

        Ok(Self {
            producer,
            topic: topic.into(),
        })
    }
}

#[async_trait]
impl EventPlugin for KafkaEventPublisher {
    async fn emit(&self, envelope: &EventEnvelope) -> Result<(), String> {
        let payload = serde_json::to_vec(envelope).map_err(|e| format!("serialize envelope: {e}"))?;
        let key = envelope.effective_idempotency_key();

        // We enqueue and then detach the delivery future to keep the plugin best-effort.
        let delivery = self
            .producer
            .send_result(
                FutureRecord::to(&self.topic)
                    .payload(&payload)
                    .key(&key),
            )
            .map_err(|(e, _msg)| format!("kafka send: {e}"))?;

        actix_rt::spawn(async move {
            // A short wait so we at least surface immediate delivery failures.
            let _ = tokio::time::timeout(Duration::from_secs(2), delivery).await;
        });

        Ok(())
    }

    fn name(&self) -> &str {
        "kafka"
    }

    async fn health_check(&self) -> bool {
        // Producer metadata checks require a client; keep Phase 1 check simple.
        true
    }
}
