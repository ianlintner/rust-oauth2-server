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
    // Reject anything that is not EXACTLY the W3C version-00 field shape:
    // `00` / 32 lower-hex trace id / 16 lower-hex span id / 2 lower-hex flags,
    // four fields and nothing more; reject any missing or extra field.
    let mut fields = value.split('-');
    let (Some(version), Some(trace_id), Some(span_id), Some(flags)) =
        (fields.next(), fields.next(), fields.next(), fields.next())
    else {
        return false;
    };
    // There must be no fifth field, even an empty one.
    version == "00"
        && fields.next().is_none()
        && is_nonzero_lower_hex(trace_id, 32)
        && is_nonzero_lower_hex(span_id, 16)
        && is_lower_hex(flags, 2)
}

/// `s` is exactly `len` lower-case ASCII hex digits.
fn is_lower_hex(s: &str, len: usize) -> bool {
    s.len() == len
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// `s` is exactly `len` lower-case ASCII hex digits and not all zero.
fn is_nonzero_lower_hex(s: &str, len: usize) -> bool {
    is_lower_hex(s, len) && s.bytes().any(|b| b != b'0')
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

/// Table-driven coverage for `is_live_traceparent`: every accepted value must
/// be EXACTLY a W3C version-00 traceparent, and everything else — wrong or
/// `ff` version, upper-case or non-hex ids/flags, zero ids, wrong field
/// lengths, missing/extra fields, non-hex or wrong-length flags (flags are
/// hex `00`..`ff`, so `01` and `ff` are valid) — must be rejected.
#[test]
fn traceparent_predicate_accepts_only_exact_w3c_version_00() {
    let trace = "4bf92f3577b34da6a3ce929d0e0e4736";
    let span = "00f067aa0ba902b7";

    let positives = [
        format!("00-{trace}-{span}-01"),
        format!("00-{trace}-{span}-00"),
        // Flags are 8-bit: any lower-hex byte is valid, not only 00/01.
        format!("00-{trace}-{span}-ff"),
        format!("00-{trace}-{span}-a7"),
    ];
    for value in positives {
        assert!(
            is_live_traceparent(&value),
            "valid W3C version-00 traceparent was rejected: {value}"
        );
    }

    let zero_trace = "0".repeat(32);
    let zero_span = "0".repeat(16);
    let negatives = [
        // Wrong / non-00 version.
        format!("ff-{trace}-{span}-01"),
        format!("01-{trace}-{span}-01"),
        format!("0-{trace}-{span}-01"),
        format!("000-{trace}-{span}-01"),
        // Uppercase hex (W3C requires lower case).
        format!("00-{}-{span}-01", trace.to_uppercase()),
        format!("00-{trace}-{}-01", span.to_uppercase()),
        format!("00-{trace}-{span}-0A"),
        // Non-hex characters.
        format!("00-{}-{span}-01", "g".repeat(32)),
        format!("00-{trace}-{}-01", "g".repeat(16)),
        format!("00-{trace}-{span}-zz"),
        // Zero ids.
        format!("00-{zero_trace}-{span}-01"),
        format!("00-{trace}-{zero_span}-01"),
        format!("00-{zero_trace}-{zero_span}-01"),
        // Wrong field lengths.
        format!("00-{}-{span}-01", &trace[..31]),
        format!("00-{trace}-{}-01", &span[..15]),
        format!("00-{trace}-{span}-0"),
        format!("00-{trace}-{span}-001"),
        "0-0".to_string(),
        // Missing fields.
        format!("00-{trace}-{span}"),
        format!("00-{trace}"),
        "00".to_string(),
        String::new(),
        // Extra fields.
        format!("00-{trace}-{span}-01-extra"),
        format!("00-{trace}-{span}-01-"),
        // Non-traceparent junk.
        "not-a-traceparent".to_string(),
    ];
    for value in negatives {
        assert!(
            !is_live_traceparent(&value),
            "invalid traceparent was accepted: {value:?}"
        );
    }
}
