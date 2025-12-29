use opentelemetry::{global, KeyValue};
use opentelemetry_sdk::{trace as sdktrace, Resource};
use tracing::Span;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

/// Initialize tracing/logging and (optionally) OpenTelemetry export.
///
/// - Always emits structured JSON logs via `tracing_subscriber`.
/// - Bridges `log` records into `tracing` so `log::info!` etc. are correlated.
/// - Enables OpenTelemetry spans:
///   - If `OTEL_EXPORTER_OTLP_ENDPOINT` (or `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT`) is set,
///     traces are exported via OTLP.
///   - Otherwise, a local tracer provider is installed to generate trace/span IDs for log correlation.
pub fn init_telemetry(service_name: &str) -> Result<(), Box<dyn std::error::Error>> {
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
    global::set_text_map_propagator(opentelemetry_sdk::propagation::TraceContextPropagator::new());

    let resource = Resource::new(vec![KeyValue::new(
        "service.name",
        service_name.to_string(),
    )]);

    // Prefer OTLP export when configured; otherwise still install a provider to generate IDs.
    let otlp_endpoint_set = std::env::var("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .is_some()
        || std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT")
            .ok()
            .filter(|v| !v.trim().is_empty())
            .is_some();

    let tracer = if otlp_endpoint_set {
        opentelemetry_otlp::new_pipeline()
            .tracing()
            .with_exporter(opentelemetry_otlp::new_exporter().tonic())
            .with_trace_config(sdktrace::config().with_resource(resource))
            .install_batch(opentelemetry_sdk::runtime::Tokio)?
    } else {
        let provider = sdktrace::TracerProvider::builder()
            .with_config(sdktrace::config().with_resource(resource).with_sampler(
                sdktrace::Sampler::ParentBased(Box::new(sdktrace::Sampler::AlwaysOn)),
            ))
            .build();
        let tracer = {
            use opentelemetry::trace::TracerProvider as _;
            provider.tracer(service_name.to_string())
        };
        global::set_tracer_provider(provider);
        tracer
    };

    // Export tracing spans to OpenTelemetry.
    let otel_layer = tracing_opentelemetry::layer().with_tracer(tracer);

    // JSON formatting for structured logging.
    // with_current_span + with_span_list ensures every event includes the active span stack
    // (which we enrich with trace_id/span_id fields).
    let formatting_layer = tracing_subscriber::fmt::layer()
        .json()
        .with_current_span(true)
        .with_span_list(true);

    tracing_subscriber::registry()
        .with(env_filter)
        .with(otel_layer)
        .with(formatting_layer)
        .init();

    // Bridge `log` records (e.g., actix-web Logger middleware) into tracing.
    // Ignore errors if a logger was already set (e.g., tests).
    let _ = tracing_log::LogTracer::init();

    Ok(())
}

/// Record OpenTelemetry trace/span identifiers onto a span.
///
/// This is primarily used to ensure every JSON log line carries `trace_id` and `span_id`
/// via `with_current_span(true)` / `with_span_list(true)`.
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

pub fn shutdown_telemetry() {
    // Flush any pending spans (when an exporter is installed).
    global::shutdown_tracer_provider();
}
