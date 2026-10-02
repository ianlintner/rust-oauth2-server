//! Member-crate outbound propagation seam.
//!
//! `oauth2-social-login` builds its outbound provider client with
//! `reqwest-tracing`'s `TracingMiddleware` in `src/service.rs`
//! (`build_http_client`). That middleware injects W3C `traceparent` from the
//! current `tracing::Span`'s OpenTelemetry context, reading it through the
//! `opentelemetry 0.32` registry that `tracing-opentelemetry 0.33` writes to.
//!
//! If the workspace's OTel family is bumped to 0.33/0.34 without a matching
//! `reqwest-tracing` feature (0.7.1 has none), the span context types differ:
//! the middleware sees an empty context and NO `traceparent` is injected before transport.
//! Compilation still succeeds, so this must be asserted behaviourally.
//!
//! This test lives in the member crate on purpose. The workspace root is a
//! real package (non-virtual workspace), so the plain
//! `cargo nextest run --all-features` at the root runs ONLY
//! `rust_oauth2_server`, not member crates. A dedicated CI step
//! (`Run member OTel propagation guard`) runs this binary explicitly, so the
//! member seam is exercised from inside the crate that owns it. The test drives
//! the REAL middleware — not a re-implementation — with a capturing observer
//! registered after it in the `reqwest_middleware` chain, and asserts a live,
//! non-zero `traceparent` is present before the request leaves the process.

#![cfg(feature = "otel")]

use std::sync::{Arc, Mutex};

use reqwest_middleware::ClientBuilder;
use reqwest_tracing::TracingMiddleware;

/// Observe the request *after* `TracingMiddleware` runs. Middlewares execute in
/// registration order on the way out, so registering this one after the tracing
/// middleware shows the headers it injected, before the HTTP layer. Needs no
/// extra dependency and touches no network.
struct HeaderCapture {
    seen: Arc<Mutex<Option<String>>>,
}

#[async_trait::async_trait]
impl reqwest_middleware::Middleware for HeaderCapture {
    async fn handle(
        &self,
        req: reqwest::Request,
        _extensions: &mut http::Extensions,
        _next: reqwest_middleware::Next<'_>,
    ) -> reqwest_middleware::Result<reqwest::Response> {
        if let Some(value) = req
            .headers()
            .get("traceparent")
            .and_then(|v| v.to_str().ok())
        {
            *self.seen.lock().unwrap() = Some(value.to_string());
        }
        // Test-only response fixture: observe header injection, then stop before
        // transport. No socket, proxy, or external endpoint is contacted.
        Ok(reqwest::Response::from(http::Response::new(String::new())))
    }
}

/// `00-<32 hex trace_id>-<16 hex span_id>-<2 hex flags>`, non-zero ids.
fn is_live_traceparent(value: &str) -> bool {
    let parts: Vec<&str> = value.split('-').collect();
    parts.len() == 4
        && parts[1].len() == 32
        && parts[2].len() == 16
        && parts[1].chars().any(|c| c != '0')
        && parts[2].chars().any(|c| c != '0')
}

/// Install the tracing-opentelemetry layer + W3C propagator exactly as
/// `oauth2-observability::init_telemetry` does, on the same `opentelemetry`
/// global the middleware injects through.
fn install_app_tracing_layer() -> (
    opentelemetry_sdk::trace::SdkTracerProvider,
    tracing::subscriber::DefaultGuard,
) {
    use opentelemetry::global;
    use opentelemetry::trace::TracerProvider as _;
    use opentelemetry_sdk::propagation::TraceContextPropagator;
    use opentelemetry_sdk::trace::SdkTracerProvider;
    use tracing_subscriber::prelude::*;

    global::set_text_map_propagator(TraceContextPropagator::new());

    let provider = SdkTracerProvider::builder().build();
    let tracer = provider.tracer("otel_middleware_seam_test");
    let otel_layer = tracing_opentelemetry::layer().with_tracer(tracer);

    let subscriber = tracing_subscriber::registry().with(otel_layer);
    let guard = tracing::subscriber::set_default(subscriber);
    (provider, guard)
}

#[tokio::test]
async fn reqwest_tracing_middleware_injects_live_traceparent() {
    let (provider, _guard) = install_app_tracing_layer();

    let seen = Arc::new(Mutex::new(None::<String>));
    let client = ClientBuilder::new(reqwest::Client::new())
        .with(TracingMiddleware::default())
        .with(HeaderCapture { seen: seen.clone() })
        .build();

    {
        let span = tracing::info_span!("social_oauth_call", peer = "google");
        let _entered = span.enter();
        // HeaderCapture returns a response fixture without invoking transport.
        let response = client
            .get("http://127.0.0.1:9/token")
            .send()
            .await
            .expect("middleware chain should return the test response fixture");
        assert_eq!(response.status(), http::StatusCode::OK);
    }

    let observed = seen.lock().unwrap().clone();
    let value = observed.unwrap_or_else(|| {
        panic!(
            "reqwest-tracing did not inject any `traceparent`. The tracing-\
             opentelemetry layer installed for this app is NOT the one \
             reqwest-tracing extracts from — the OpenTelemetry version family is \
             split (e.g. observability on 0.33/0.34 while reqwest-tracing injects \
             via 0.32). Distributed trace propagation is silently broken."
        )
    });
    assert!(
        is_live_traceparent(&value),
        "reqwest-tracing injected a non-live `traceparent` ({value}); the span \
         context was empty, which means the OTel registry is split."
    );

    let _ = provider.force_flush();
}
