//! OTel compatibility guard — real outbound `traceparent` propagation.
//!
//! ## Why this test exists
//!
//! `oauth2-social-login` wraps its outbound provider client with
//! `reqwest-tracing 0.7.1`'s `TracingMiddleware` (see
//! `crates/oauth2-social-login/src/service.rs`,
//! `build_http_client`). That middleware injects a W3C `traceparent` header
//! from the *current* `tracing::Span`'s OpenTelemetry context.
//!
//! The supported family is `opentelemetry 0.32` with
//! `tracing-opentelemetry 0.33` (0.33 pairs with 0.32; 0.34 pairs with 0.33).
//! `reqwest-tracing 0.7.1` exposes features `opentelemetry_0_20` .. `_0_32`
//! and nothing above `_0_32`, so its `opentelemetry_0_32` injection reads the
//! 0.32 span context the 0.33 layer writes. That is the only coherent pairing.
//!
//! A naive whole-workspace bump to `opentelemetry 0.33` /
//! `tracing-opentelemetry 0.34` compiles cleanly but silently breaks
//! propagation: the span context stored by the 0.34 layer is of the
//! `opentelemetry 0.33` type, while `reqwest-tracing 0.7.1` (having no `_0_33`
//! feature) reads the `opentelemetry 0.32` type. The two `opentelemetry` crate
//! instances do not alias, so the extraction yields an empty context and NO
//! `traceparent` header is emitted. Distributed tracing fails open — no error,
//! no header.
//!
//! This test drives the REAL production outbound middleware and asserts a
//! live, non-zero W3C `traceparent` is injected before transport. It fails closed on a
//! split OTel registry.
//!
//! ## Seam covered here vs. the member test
//!
//! Root CI (`checks`) runs `cargo nextest run --all-features` and executes this
//! root-package integration test. A sister test,
//! `crates/oauth2-social-login/tests/otel_middleware_seam.rs`, exercises the
//! same real middleware from inside the member crate, because the root suite
//! does not descend into member crates; a dedicated CI step runs it. The static
//! manifest/lock invariant is guarded in `otel_dependency_coherence.rs`.

#![cfg(feature = "otel")]

use std::sync::{Arc, Mutex};

use reqwest_middleware::ClientBuilder;
use reqwest_tracing::TracingMiddleware;

/// A `reqwest_middleware` middleware that observes the request *after* the
/// `TracingMiddleware` ran. `reqwest_middleware` runs middlewares in
/// registration order on the way out, so one registered after
/// `TracingMiddleware` sees the headers it injected, before the HTTP layer.
/// This needs no extra dependency and no server.
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

/// Validate a W3C traceparent: `00-<32 hex trace_id>-<16 hex span_id>-<2 hex>`
/// with non-zero trace and span ids.
fn is_live_traceparent(value: &str) -> bool {
    let parts: Vec<&str> = value.split('-').collect();
    parts.len() == 4
        && parts[1].len() == 32
        && parts[2].len() == 16
        && parts[1].chars().any(|c| c != '0')
        && parts[2].chars().any(|c| c != '0')
}

/// Install a tracing subscriber with a real `tracing-opentelemetry` layer and
/// the W3C propagator on the workspace's `opentelemetry` global, exactly as
/// `oauth2-observability::init_telemetry` does. Returns a guard that keeps the
/// subscriber installed for the duration of the test.
fn install_app_tracing_layer() -> (
    opentelemetry_sdk::trace::SdkTracerProvider,
    tracing::subscriber::DefaultGuard,
) {
    use opentelemetry::global;
    use opentelemetry::trace::TracerProvider as _;
    use opentelemetry_sdk::propagation::TraceContextPropagator;
    use opentelemetry_sdk::trace::SdkTracerProvider;
    use tracing_subscriber::prelude::*;

    // W3C propagator on the same `opentelemetry` registry reqwest-tracing
    // injects through. Safe here: the OTEL globals are process-wide, but this
    // test binary is single-test-per-seam and installs once before any span.
    global::set_text_map_propagator(TraceContextPropagator::new());

    let provider = SdkTracerProvider::builder().build();
    let tracer = provider.tracer("otel_outbound_propagation_test");
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
             opentelemetry layer the app installs is NOT the one reqwest-tracing \
             extracts from — the OpenTelemetry version family is split (e.g. \
             observability on 0.33/0.34 while reqwest-tracing injects via 0.32). \
             Distributed trace propagation is silently broken."
        )
    });
    assert!(
        is_live_traceparent(&value),
        "reqwest-tracing injected a non-live `traceparent` ({value}); the span \
         context was empty, which means the OTel registry is split."
    );

    let _ = provider.force_flush();
}
