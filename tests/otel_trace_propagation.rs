//! Wave 3.1 — end-to-end OpenTelemetry trace propagation validation.
//!
//! This integration test exists to prove that when the `otel` feature is
//! enabled, a single OAuth2 `/token` request produces an OTEL trace with the
//! expected parent/child shape:
//!
//! ```text
//! test.http.post /oauth/token  (root, created by this test)
//! └── actor.token.create       (from TokenActor's CreateToken handler)
//!     └── db.query             (db.system = "sqlite", from ObservedStorage)
//! ```
//!
//! Scope intentionally small: the HTTP layer and DB layer are the only legs we
//! need to prove end-to-end. We explicitly do NOT cover:
//!
//! - Outbound reqwest spans (`oauth2-social-login`) — requires mocking an IdP.
//!   Unit-tested in W1.4 with the reqwest-tracing middleware directly.
//! - Event bus publisher spans (Kafka/Rabbit/Redis) — requires a running broker.
//!   Unit-tested in W1.5 where header injection is asserted on encoded envelopes.
//! - Redis cache/rate-limit spans — covered by `TracedRedis` unit tests in W1.3.
//!
//! The in-memory exporter wiring is test-only: production code uses
//! `BatchSpanProcessor` + OTLP. Using `SimpleSpanProcessor` here avoids flush
//! races during the test's single synchronous request.

#![cfg(feature = "otel")]

use actix::Actor;
use actix_web::{test, web, App};
use std::sync::Arc;
use tokio::sync::RwLock;

use oauth2_actix::actors::TokenActorPool;
use oauth2_actix::handlers::wellknown::OidcConfig;
use oauth2_core::{Client, TokenResponse, User};
use oauth2_observability::Metrics;

use opentelemetry::global;
use opentelemetry::trace::SpanId;
use opentelemetry_sdk::propagation::TraceContextPropagator;
use opentelemetry_sdk::trace::{
    InMemorySpanExporter, InMemorySpanExporterBuilder, SdkTracerProvider, SimpleSpanProcessor,
};

use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

/// Install a tracer provider backed by an in-memory exporter and wire it into
/// `tracing` via `tracing-opentelemetry` so that `tracing::info_span!` spans
/// (created by the actix handlers and `ObservedStorage`) are exported.
///
/// Returns the exporter (for later assertion) and the provider (so the caller
/// can force a flush). The tracer provider is installed as the global
/// opentelemetry provider; the tracing subscriber is installed as the global
/// default. This test file owns the process — no other tests share its binary.
fn install_in_memory_telemetry() -> (InMemorySpanExporter, SdkTracerProvider) {
    global::set_text_map_propagator(TraceContextPropagator::new());

    let exporter = InMemorySpanExporterBuilder::new().build();
    // SimpleSpanProcessor exports each span synchronously on end — avoids the
    // batch-flush races that plague tests.
    let provider = SdkTracerProvider::builder()
        .with_span_processor(SimpleSpanProcessor::new(exporter.clone()))
        .build();

    let tracer = {
        use opentelemetry::trace::TracerProvider as _;
        provider.tracer("oauth2_trace_propagation_test")
    };

    global::set_tracer_provider(provider.clone());

    let otel_layer = tracing_opentelemetry::layer().with_tracer(tracer);
    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    // try_init so a second initialization in the same binary would be a no-op
    // rather than a panic. This test file is the only consumer, but being
    // defensive is cheap.
    let _ = tracing_subscriber::registry()
        .with(env_filter)
        .with(otel_layer)
        .try_init();

    (exporter, provider)
}

#[actix_web::test]
async fn otel_spans_are_exported_with_correct_parent_child_shape() {
    let (exporter, provider) = install_in_memory_telemetry();

    // Build the OAuth2 server wiring using the same shape as rfc_compliance.rs
    // (no shared helper — see CLAUDE.md pitfall #4).
    const ISSUER: &str = "https://auth.example.com";

    let client = Client::new(
        "client_otel".to_string(),
        "secret_otel".to_string(),
        vec!["https://unused/cb".to_string()],
        vec!["client_credentials".to_string()],
        "read".to_string(),
        "otel_test".to_string(),
    );

    let storage = oauth2_storage_factory::create_storage("sqlite::memory:")
        .await
        .expect("create storage");
    storage.init().await.expect("init");
    storage.save_client(&client).await.expect("save client");

    let now = chrono::Utc::now();
    let user = User {
        id: "user_rfc".to_string(),
        username: "user_rfc".to_string(),
        password_hash: "unused".to_string(),
        email: "user_rfc@example.test".to_string(),
        enabled: true,
        role: "user".to_string(),
        created_at: now,
        updated_at: now,
    };
    storage.save_user(&user).await.expect("save user");

    let jwt_secret = "otel_trace_propagation_jwt_secret_at_least_32_chars".to_string();
    let metrics = Metrics::new().expect("metrics");

    let token_actor = oauth2_actix::actors::TokenActor::new(
        storage.clone(),
        jwt_secret.clone(),
        ISSUER.to_string(),
    )
    .start();
    let token_pool = TokenActorPool::new(vec![token_actor]);
    let client_actor = oauth2_actix::actors::ClientActor::new(storage.clone()).start();
    let auth_actor = oauth2_actix::actors::AuthActor::new(storage.clone()).start();

    let oidc_config = OidcConfig {
        issuer: ISSUER.to_string(),
        jwt_secret: jwt_secret.clone(),
        id_token_alg: "HS256".to_string(),
        id_token_kid: None,
        id_token_private_key_pem: None,
    };
    let keyset = Arc::new(RwLock::new(oauth2_core::models::key_set::KeySet::default()));

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(token_pool))
            .app_data(web::Data::new(client_actor))
            .app_data(web::Data::new(auth_actor))
            .app_data(web::Data::new(jwt_secret))
            .app_data(web::Data::new(metrics))
            .app_data(web::Data::new(oidc_config))
            .app_data(web::Data::new(keyset))
            .app_data(web::Data::new(false)) // stateless_validation
            .service(web::scope("/oauth").route(
                "/token",
                web::post().to(oauth2_actix::handlers::oauth::token),
            )),
    )
    .await;

    // Drive the whole request through our own root span so the HTTP layer has a
    // parent to link against. Without this, the actor span would be top-level
    // and there would be nothing to assert "parent" against.
    let root_span = tracing::info_span!(
        "test.http.post /oauth/token",
        "http.method" = "POST",
        "http.route" = "/oauth/token",
    );

    use tracing::Instrument as _;

    let resp = async {
        test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/oauth/token")
                .set_form([
                    ("grant_type", "client_credentials"),
                    ("client_id", "client_otel"),
                    ("client_secret", "secret_otel"),
                    ("scope", "read"),
                ])
                .to_request(),
        )
        .await
    }
    .instrument(root_span.clone())
    .await;

    assert_eq!(resp.status(), 200, "token endpoint must succeed");
    let _body: TokenResponse = test::read_body_json(resp).await;

    // Drop the root span so it ends and flushes through the SimpleSpanProcessor.
    drop(root_span);

    // Belt-and-braces: explicitly flush and shut down so every finished span is
    // in the exporter before we read it.
    provider.force_flush().expect("force_flush");

    let spans = exporter.get_finished_spans().expect("get_finished_spans");
    assert!(
        spans.len() >= 2,
        "expected at least a root + db.query span, got {}: {:?}",
        spans.len(),
        spans.iter().map(|s| s.name.as_ref()).collect::<Vec<_>>()
    );

    // All spans produced by this single request must share a trace_id. Find it
    // from the root span (parent_span_id is zero / invalid).
    let invalid_parent = SpanId::INVALID;
    let root = spans
        .iter()
        .find(|s| s.parent_span_id == invalid_parent && s.name.contains("/oauth/token"))
        .unwrap_or_else(|| {
            panic!(
                "no root span with name containing '/oauth/token' found; names = {:?}",
                spans.iter().map(|s| s.name.as_ref()).collect::<Vec<_>>()
            )
        });
    let trace_id = root.span_context.trace_id();
    let root_span_id = root.span_context.span_id();

    // Find the DB span. ObservedStorage names every span "db.query" and sets
    // `db.system` as an attribute. For this client_credentials flow the handler
    // reads the client via `get_client` and later writes the token via
    // `save_token`; either is acceptable here — we just require one.
    //
    // The setup-phase DB calls (init / save_client / save_user) ran outside
    // our root span and therefore live under different trace IDs. Filter by
    // the request's trace_id to ignore them.
    let db_span = spans
        .iter()
        .find(|s| {
            s.name == "db.query"
                && s.span_context.trace_id() == trace_id
                && s.attributes
                    .iter()
                    .any(|kv| kv.key.as_str() == "db.system" && kv.value.as_str() == "sqlite")
        })
        .unwrap_or_else(|| {
            panic!(
                "no db.query span with db.system=sqlite; spans = {:?}",
                spans
                    .iter()
                    .map(|s| (
                        s.name.as_ref(),
                        s.attributes
                            .iter()
                            .map(|kv| (kv.key.as_str().to_string(), kv.value.to_string()))
                            .collect::<Vec<_>>()
                    ))
                    .collect::<Vec<_>>()
            )
        });

    // Trace IDs must match across root and DB span.
    assert_eq!(
        db_span.span_context.trace_id(),
        trace_id,
        "db.query must share trace_id with the root HTTP span"
    );

    // Parent/child relationship: walk the parent chain from the db.query span
    // back up and require that the root span is an ancestor. There may be
    // intermediate spans (e.g., `actor.token.create`), which is expected.
    let mut ancestor_ids = Vec::new();
    let mut current_parent = db_span.parent_span_id;
    // Guard against cycles (shouldn't happen, but don't loop forever).
    for _ in 0..32 {
        if current_parent == invalid_parent {
            break;
        }
        ancestor_ids.push(current_parent);
        match spans
            .iter()
            .find(|s| s.span_context.span_id() == current_parent)
        {
            Some(next) => current_parent = next.parent_span_id,
            None => break,
        }
    }
    assert!(
        ancestor_ids.contains(&root_span_id),
        "db.query span's ancestor chain must include the root HTTP span; \
         db_span.parent={:?}, ancestors={:?}, root_id={:?}",
        db_span.parent_span_id,
        ancestor_ids,
        root_span_id,
    );

    // Also verify the actor span exists — that's the bridge between HTTP and DB
    // and is explicitly part of the documented shape.
    let actor_span = spans
        .iter()
        .find(|s| s.name.as_ref() == "actor.token.create")
        .unwrap_or_else(|| {
            panic!(
                "expected 'actor.token.create' span; got names = {:?}",
                spans.iter().map(|s| s.name.as_ref()).collect::<Vec<_>>()
            )
        });
    assert_eq!(
        actor_span.span_context.trace_id(),
        trace_id,
        "actor.token.create must share trace_id with root"
    );

    let _ = provider.shutdown();
}
