pub mod metrics;
pub mod storage;
pub mod telemetry;

#[cfg(feature = "actix")]
pub mod actix;

pub use metrics::{Metrics, STANDARD_LATENCY_BUCKETS, STANDARD_SIZE_BUCKETS};
pub use storage::ObservedStorage;
pub use telemetry::{annotate_span_with_trace_ids, init_telemetry, shutdown_telemetry};

/// Encode a Prometheus registry into the text exposition format ("version=0.0.4").
///
/// Useful for implementing a `/metrics` endpoint.
pub fn encode_prometheus_text(
    registry: &prometheus::Registry,
) -> Result<Vec<u8>, prometheus::Error> {
    use prometheus::Encoder;
    let encoder = prometheus::TextEncoder::new();
    let metric_families = registry.gather();
    let mut buffer = Vec::new();
    encoder.encode(&metric_families, &mut buffer)?;
    Ok(buffer)
}
