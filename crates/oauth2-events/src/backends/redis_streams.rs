use crate::{EventEnvelope, EventPlugin};
use async_trait::async_trait;
use redis::aio::ConnectionManager;
use std::time::Duration;
use tokio::sync::Mutex;

/// Redis Streams event publisher.
///
/// Publishes envelopes as JSON to a Redis Stream via `XADD`.
pub struct RedisStreamsEventPublisher {
    stream: String,
    maxlen: Option<usize>,
    conn: Mutex<ConnectionManager>,
}

impl RedisStreamsEventPublisher {
    pub async fn connect(
        url: &str,
        stream: impl Into<String>,
        maxlen: Option<usize>,
    ) -> Result<Self, String> {
        let client = redis::Client::open(url).map_err(|e| format!("redis client: {e}"))?;
        let conn = client
            .get_connection_manager()
            .await
            .map_err(|e| format!("redis connect: {e}"))?;

        Ok(Self {
            stream: stream.into(),
            maxlen,
            conn: Mutex::new(conn),
        })
    }

    fn xadd_cmd(&self, envelope: &EventEnvelope, payload_json: &str) -> redis::Cmd {
        let mut cmd = redis::cmd("XADD");
        cmd.arg(&self.stream);

        if let Some(maxlen) = self.maxlen {
            cmd.arg("MAXLEN").arg("~").arg(maxlen);
        }

        cmd.arg("*")
            .arg("idempotency_key")
            .arg(envelope.effective_idempotency_key())
            .arg("event_type")
            .arg(envelope.event.event_type.as_str())
            .arg("event_id")
            .arg(envelope.event.id.as_str())
            .arg("correlation_id")
            .arg(envelope.correlation_id.as_str())
            .arg("producer")
            .arg(envelope.producer.as_str())
            .arg("payload")
            .arg(payload_json);

        cmd
    }
}

#[async_trait]
impl EventPlugin for RedisStreamsEventPublisher {
    async fn emit(&self, envelope: &EventEnvelope) -> Result<(), String> {
        let payload_json =
            serde_json::to_string(envelope).map_err(|e| format!("serialize envelope: {e}"))?;

        let cmd = self.xadd_cmd(envelope, &payload_json);
        let mut conn = self.conn.lock().await;

        // XADD returns the stream entry ID.
        let _id: String = cmd
            .query_async(&mut *conn)
            .await
            .map_err(|e| format!("redis XADD: {e}"))?;

        Ok(())
    }

    fn name(&self) -> &str {
        "redis_streams"
    }

    async fn health_check(&self) -> bool {
        let fut = async {
            let mut conn = self.conn.lock().await;
            redis::cmd("PING")
                .query_async::<_, String>(&mut *conn)
                .await
        };

        matches!(
            tokio::time::timeout(default_healthcheck_timeout(), fut).await,
            Ok(Ok(_))
        )
    }
}

/// Conservative defaults used when env vars are absent.
pub fn default_stream_name() -> String {
    "oauth2_events".to_string()
}

pub fn default_maxlen() -> Option<usize> {
    // Keep unlimited by default; let Redis memory policy handle it.
    None
}

pub fn default_healthcheck_timeout() -> Duration {
    Duration::from_millis(500)
}
