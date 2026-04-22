#[cfg(feature = "otel")]
use opentelemetry::{global, KeyValue};
#[cfg(feature = "otel")]
use opentelemetry_sdk::{trace as sdktrace, Resource};
#[cfg(feature = "otel")]
use std::sync::OnceLock;
#[cfg(feature = "otel")]
use std::time::Duration;
use tracing::Span;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

/// Sampler strategy mirror of `oauth2_config::SamplerKind`.
///
/// Duplicated here so `oauth2-observability` does not gain a `oauth2-config`
/// dependency (which would introduce a workspace cycle). The caller in
/// `oauth2-server` converts once at startup.
#[derive(Debug, Clone, Default)]
pub enum SamplerKind {
    #[default]
    ParentBasedAlwaysOn,
    TraceIdRatio {
        ratio: f64,
    },
    AlwaysOff,
}

/// Runtime telemetry wiring parameters accepted by [`init_telemetry`].
///
/// Keeping this struct local (rather than borrowing `oauth2_config::TelemetryConfig`)
/// avoids forcing every consumer of `oauth2-observability` to depend on the
/// configuration crate.
#[derive(Debug, Clone)]
pub struct TelemetryInit {
    /// Sampler strategy. Maps directly to `opentelemetry_sdk::trace::Sampler`.
    pub sampler: SamplerKind,
    /// Maximum queue length for the batch span processor.
    pub batch_max_queue: usize,
    /// Delay between batch flushes, in milliseconds.
    pub batch_scheduled_delay_ms: u64,
}

impl Default for TelemetryInit {
    fn default() -> Self {
        Self {
            sampler: SamplerKind::default(),
            batch_max_queue: 2048,
            batch_scheduled_delay_ms: 5000,
        }
    }
}

#[cfg(feature = "otel")]
static TELEMETRY_PROVIDER: OnceLock<sdktrace::SdkTracerProvider> = OnceLock::new();

#[cfg(feature = "otel")]
fn build_sampler(kind: &SamplerKind) -> sdktrace::Sampler {
    match kind {
        SamplerKind::ParentBasedAlwaysOn => {
            sdktrace::Sampler::ParentBased(Box::new(sdktrace::Sampler::AlwaysOn))
        }
        SamplerKind::TraceIdRatio { ratio } => {
            sdktrace::Sampler::ParentBased(Box::new(sdktrace::Sampler::TraceIdRatioBased(*ratio)))
        }
        SamplerKind::AlwaysOff => sdktrace::Sampler::AlwaysOff,
    }
}

#[cfg(feature = "otel")]
fn build_resource(service_name: &str) -> Resource {
    // Start with OTEL standard detectors, add service.* + deployment.* attrs.
    let mut builder = Resource::builder().with_service_name(service_name.to_string());

    if let Some(namespace) = std::env::var("POD_NAMESPACE")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
    {
        builder = builder.with_attribute(KeyValue::new("service.namespace", namespace));
    }

    let version = std::env::var("IMAGE_SHA")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| env!("APP_INFO_VERSION").to_string());
    builder = builder.with_attribute(KeyValue::new("service.version", version));

    if let Some(env_name) = std::env::var("DEPLOYMENT_ENVIRONMENT")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
    {
        builder = builder.with_attribute(KeyValue::new("deployment.environment", env_name));
    }

    builder.build()
}

/// Initialize tracing/logging and (optionally) OpenTelemetry export.
///
/// - Always emits structured JSON logs via `tracing_subscriber`.
/// - Bridges `log` records into `tracing` so `log::info!` etc. are correlated.
/// - When built with the `otel` feature, also enables OpenTelemetry spans:
///   - If `OTEL_EXPORTER_OTLP_ENDPOINT` (or `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT`) is set,
///     traces are exported via OTLP through a `BatchSpanProcessor` configured from `telemetry`.
///   - Otherwise, a local tracer provider is installed to generate trace/span IDs for log correlation.
/// - Without the `otel` feature, only JSON logs are set up; no OTEL SDK is linked.
#[cfg(feature = "otel")]
pub fn init_telemetry(
    service_name: &str,
    telemetry: &TelemetryInit,
) -> Result<(), Box<dyn std::error::Error>> {
    // Back-compat / convenience: this repo historically documented `OAUTH2_OTLP_ENDPOINT`.
    // OpenTelemetry SDKs use `OTEL_EXPORTER_OTLP_ENDPOINT` (or `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT`).
    // If the standard OTEL vars are not set but the app-specific one is, bridge it.
    let oauth2_otlp_endpoint = std::env::var("OAUTH2_OTLP_ENDPOINT")
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty());

    let otel_endpoint_missing = std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT")
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
        .is_none();

    let otel_traces_endpoint_missing = std::env::var("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT")
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
        .is_none();

    if otel_endpoint_missing && otel_traces_endpoint_missing {
        if let Some(endpoint) = oauth2_otlp_endpoint {
            std::env::set_var("OTEL_EXPORTER_OTLP_ENDPOINT", endpoint);
        }
    }

    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    // Use W3C trace-context for propagation (traceparent/tracestate).
    // Resource attributes must be set BEFORE the first span is created.
    global::set_text_map_propagator(opentelemetry_sdk::propagation::TraceContextPropagator::new());

    let resource = build_resource(service_name);
    let sampler = build_sampler(&telemetry.sampler);

    // Prefer OTLP export when configured; otherwise still install a provider to generate IDs.
    let otlp_endpoint_set = std::env::var("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .is_some()
        || std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT")
            .ok()
            .filter(|v| !v.trim().is_empty())
            .is_some();

    let provider = if otlp_endpoint_set {
        let exporter = opentelemetry_otlp::SpanExporter::builder()
            .with_tonic()
            .build()?;

        // Build a `BatchSpanProcessor` with queue size + scheduled delay
        // sourced from `TelemetryInit`. Other knobs stay at SDK defaults.
        let batch_config = sdktrace::BatchConfigBuilder::default()
            .with_max_queue_size(telemetry.batch_max_queue)
            .with_scheduled_delay(Duration::from_millis(telemetry.batch_scheduled_delay_ms))
            .build();
        let processor = sdktrace::BatchSpanProcessor::builder(exporter)
            .with_batch_config(batch_config)
            .build();

        sdktrace::SdkTracerProvider::builder()
            .with_resource(resource.clone())
            .with_sampler(sampler)
            .with_span_processor(processor)
            .build()
    } else {
        sdktrace::SdkTracerProvider::builder()
            .with_resource(resource.clone())
            .with_sampler(sampler)
            .build()
    };

    let tracer = {
        use opentelemetry::trace::TracerProvider as _;
        provider.tracer(service_name.to_string())
    };

    global::set_tracer_provider(provider.clone());
    let _ = TELEMETRY_PROVIDER.set(provider);

    let otel_layer = tracing_opentelemetry::layer().with_tracer(tracer);

    let formatting_layer = tracing_subscriber::fmt::layer()
        .json()
        .with_current_span(true)
        .with_span_list(true);

    tracing_subscriber::registry()
        .with(env_filter)
        .with(otel_layer)
        .with(formatting_layer)
        .init();

    let _ = tracing_log::LogTracer::init();

    Ok(())
}

/// Initialize structured JSON logging only (no OpenTelemetry export).
///
/// Used when the crate is built without the `otel` feature. The signature
/// matches the `otel`-enabled variant so downstream callers are unchanged;
/// the `telemetry` argument is ignored because no SDK is linked.
#[cfg(not(feature = "otel"))]
pub fn init_telemetry(
    _service_name: &str,
    _telemetry: &TelemetryInit,
) -> Result<(), Box<dyn std::error::Error>> {
    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    let formatting_layer = tracing_subscriber::fmt::layer()
        .json()
        .with_current_span(true)
        .with_span_list(true);

    tracing_subscriber::registry()
        .with(env_filter)
        .with(formatting_layer)
        .init();

    let _ = tracing_log::LogTracer::init();

    Ok(())
}

/// Record OpenTelemetry trace/span identifiers onto a span.
///
/// This is primarily used to ensure every JSON log line carries `trace_id` and `span_id`
/// via `with_current_span(true)` / `with_span_list(true)`.
#[cfg(feature = "otel")]
pub fn annotate_span_with_trace_ids(span: &Span) {
    use opentelemetry::trace::TraceContextExt;
    use tracing_opentelemetry::OpenTelemetrySpanExt;
    let cx = span.context();
    let otel_span = cx.span();
    let sc = otel_span.span_context();
    if sc.is_valid() {
        span.record("trace_id", tracing::field::display(sc.trace_id()));
        span.record("span_id", tracing::field::display(sc.span_id()));
    }
}

/// No-op stub when the `otel` feature is disabled.
///
/// Signature matches the `otel`-enabled variant so callers are unchanged.
#[cfg(not(feature = "otel"))]
pub fn annotate_span_with_trace_ids(_span: &Span) {}

#[cfg(feature = "otel")]
pub fn shutdown_telemetry() {
    if let Some(provider) = TELEMETRY_PROVIDER.get() {
        let _ = provider.shutdown();
    }
}

/// No-op stub when the `otel` feature is disabled.
#[cfg(not(feature = "otel"))]
pub fn shutdown_telemetry() {}
