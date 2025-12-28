use crate::events::AuthEvent;
use chrono::{DateTime, Utc};
use opentelemetry::propagation::{Injector, TextMapPropagator};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::Span;
use tracing_opentelemetry::OpenTelemetrySpanExt;

/// A transport-ready envelope for events.
///
/// Phase 1:
/// - This is best-effort: publishing an envelope should never break core OAuth2 flows.
/// - The envelope carries W3C trace context (`traceparent`/`tracestate`) so Phase 2+ can persist/replay
///   and preserve distributed tracing across async boundaries.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventEnvelope {
    pub event: AuthEvent,

    /// W3C trace context header value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub traceparent: Option<String>,

    /// W3C tracestate header value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tracestate: Option<String>,

    /// Correlation identifier for the producing request/job.
    pub correlation_id: String,

    /// Logical producer identifier (service / subsystem).
    pub producer: String,

    /// When the envelope was created.
    pub produced_at: DateTime<Utc>,

    /// Optional extension metadata for future backends.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub attributes: HashMap<String, String>,
}

impl EventEnvelope {
    /// Create an envelope with trace context captured from the provided span.
    pub fn from_span(event: AuthEvent, span: &Span, producer: impl Into<String>) -> Self {
        let (traceparent, tracestate) = extract_w3c_trace_context(span);

        Self {
            event,
            traceparent,
            tracestate,
            correlation_id: uuid::Uuid::new_v4().to_string(),
            producer: producer.into(),
            produced_at: Utc::now(),
            attributes: HashMap::new(),
        }
    }

    /// Convenience: create an envelope from the current span.
    pub fn from_current_span(event: AuthEvent, producer: impl Into<String>) -> Self {
        Self::from_span(event, &Span::current(), producer)
    }

    pub fn with_attribute(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.attributes.insert(key.into(), value.into());
        self
    }
}

fn extract_w3c_trace_context(span: &Span) -> (Option<String>, Option<String>) {
    // We rely on `telemetry::init_telemetry()` installing the W3C propagator.
    // Even if there is no exporter configured, the span should still carry valid IDs.
    struct HeaderInjector<'a> {
        map: &'a mut HashMap<String, String>,
    }

    impl<'a> Injector for HeaderInjector<'a> {
        fn set(&mut self, key: &str, value: String) {
            self.map.insert(key.to_string(), value);
        }
    }

    let cx = span.context();
    let propagator = opentelemetry::global::get_text_map_propagator(|p| p.clone());
    let mut headers = HashMap::<String, String>::new();
    propagator.inject_context(&cx, &mut HeaderInjector { map: &mut headers });

    let traceparent = headers
        .get("traceparent")
        .cloned()
        .filter(|v| !v.trim().is_empty());
    let tracestate = headers
        .get("tracestate")
        .cloned()
        .filter(|v| !v.trim().is_empty());

    (traceparent, tracestate)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::{AuthEvent, EventSeverity, EventType};

    #[test]
    fn envelope_serializes_roundtrip() {
        let event = AuthEvent::new(
            EventType::TokenCreated,
            EventSeverity::Info,
            Some("u".to_string()),
            Some("c".to_string()),
        );

        let env = EventEnvelope::from_current_span(event, "test");
        let json = serde_json::to_string(&env).unwrap();
        let decoded: EventEnvelope = serde_json::from_str(&json).unwrap();

        assert_eq!(decoded.producer, "test");
        assert!(!decoded.correlation_id.is_empty());
        assert_eq!(decoded.event.event_type, EventType::TokenCreated);
    }
}
