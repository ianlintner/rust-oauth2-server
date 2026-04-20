use actix::Addr;
use actix_web::{web, HttpRequest, HttpResponse, Result};
use serde::Serialize;
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};
use subtle::ConstantTimeEq;
use tokio::sync::Mutex;

use oauth2_core::{ListQuery, Page};
use oauth2_events::{event_actor::GetPluginHealth, EventBusHandle, EventEnvelope};

fn extract_bearer_token(req: &HttpRequest) -> Option<String> {
    req.headers()
        .get(actix_web::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| value.to_string())
}

/// Best-effort in-memory idempotency store for `/events/ingest`.
///
/// Phase 1 semantics:
/// - Dedupes by effective idempotency key (header preferred; else `envelope.idempotency_key`; else `event.id`).
/// - TTL-based eviction; no persistence.
///
/// Phase 2+ should replace this with a persistent inbox/outbox.
#[derive(Clone)]
pub struct IdempotencyStore {
    ttl: Duration,
    max_entries: usize,
    inner: Arc<Mutex<HashMap<String, Instant>>>,
}

impl IdempotencyStore {
    pub fn new(ttl: Duration) -> Self {
        Self {
            ttl,
            max_entries: 100_000,
            inner: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn with_max_entries(mut self, max_entries: usize) -> Self {
        self.max_entries = max_entries;
        self
    }

    /// Returns `true` if the key was already present (duplicate), else records it and returns `false`.
    pub async fn is_duplicate_and_record(&self, key: &str) -> bool {
        let now = Instant::now();
        let mut guard = self.inner.lock().await;

        // Prune expired entries opportunistically.
        if !guard.is_empty() {
            let ttl = self.ttl;
            guard.retain(|_, ts| now.duration_since(*ts) <= ttl);
        }

        if guard.contains_key(key) {
            return true;
        }

        if guard.len() >= self.max_entries {
            tracing::warn!(
                max_entries = self.max_entries,
                current_entries = guard.len(),
                "idempotency cache full; clearing (best-effort)"
            );
            guard.clear();
        }

        guard.insert(key.to_string(), now);
        false
    }
}

/// In-memory ring-buffer of recently ingested events (admin visibility, best-effort).
#[derive(Clone)]
pub struct RecentEventsStore {
    capacity: usize,
    inner: Arc<Mutex<VecDeque<serde_json::Value>>>,
}

impl RecentEventsStore {
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            inner: Arc::new(Mutex::new(VecDeque::with_capacity(capacity))),
        }
    }

    pub async fn push(&self, value: serde_json::Value) {
        let mut guard = self.inner.lock().await;
        if guard.len() >= self.capacity {
            guard.pop_front();
        }
        guard.push_back(value);
    }

    pub async fn snapshot(&self) -> Vec<serde_json::Value> {
        self.inner.lock().await.iter().rev().cloned().collect()
    }
}

#[derive(Serialize)]
struct IngestResponse {
    status: &'static str,
    idempotency_key: String,
    event_id: String,
}

/// Ingest an externally-produced event envelope.
///
/// Best practice for callers: set `Idempotency-Key` header.
pub async fn ingest(
    req: HttpRequest,
    envelope: web::Json<EventEnvelope>,
    idempotency: web::Data<IdempotencyStore>,
    recent_store: Option<web::Data<RecentEventsStore>>,
    event_bus: Option<web::Data<EventBusHandle>>,
    config: Option<web::Data<oauth2_config::Config>>,
) -> Result<HttpResponse> {
    let public_ingest = config
        .as_ref()
        .map(|cfg| cfg.events.public_ingest)
        .unwrap_or(false);

    if !public_ingest {
        let Some(expected_token) = config
            .as_ref()
            .and_then(|cfg| cfg.events.ingest_bearer_token.as_deref())
            .map(str::trim)
            .filter(|token| !token.is_empty())
        else {
            return Ok(HttpResponse::ServiceUnavailable().json(serde_json::json!({
                "error": "event_ingest_auth_not_configured"
            })));
        };

        let authorized = extract_bearer_token(&req)
            .as_deref()
            .map(|presented| expected_token.as_bytes().ct_eq(presented.as_bytes()).into())
            .unwrap_or(false);

        if !authorized {
            return Ok(HttpResponse::Unauthorized()
                .insert_header(("WWW-Authenticate", "Bearer"))
                .json(serde_json::json!({
                    "error": "invalid_token",
                    "error_description": "Missing or invalid bearer token"
                })));
        }
    }

    let Some(event_bus) = event_bus else {
        return Ok(HttpResponse::ServiceUnavailable().json(serde_json::json!({
            "error": "eventing_disabled"
        })));
    };

    let header_idempotency_key = req
        .headers()
        .get("Idempotency-Key")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());

    let mut envelope = envelope.into_inner();
    if let Some(k) = header_idempotency_key {
        envelope = envelope.with_idempotency_key(k);
    }

    let effective_key = envelope.effective_idempotency_key();
    let event_id = envelope.event.id.clone();

    if idempotency.is_duplicate_and_record(&effective_key).await {
        return Ok(HttpResponse::Accepted().json(IngestResponse {
            status: "duplicate",
            idempotency_key: effective_key,
            event_id,
        }));
    }

    if let Some(store) = &recent_store {
        if let Ok(value) = serde_json::to_value(&envelope) {
            store.push(value).await;
        }
    }

    event_bus.publish_best_effort(envelope);

    Ok(HttpResponse::Accepted().json(IngestResponse {
        status: "accepted",
        idempotency_key: effective_key,
        event_id,
    }))
}

#[derive(Serialize)]
struct PluginHealth {
    name: String,
    healthy: bool,
}

/// Event system health endpoint.
pub async fn health(
    event_actor: Option<web::Data<Addr<oauth2_events::event_actor::EventActor>>>,
) -> Result<HttpResponse> {
    let Some(event_actor) = event_actor else {
        return Ok(HttpResponse::Ok().json(serde_json::json!({
            "enabled": false,
            "plugins": []
        })));
    };

    let statuses = event_actor
        .send(GetPluginHealth)
        .await
        .map_err(actix_web::error::ErrorServiceUnavailable)?;

    let plugins: Vec<PluginHealth> = statuses
        .into_iter()
        .map(|(name, healthy)| PluginHealth { name, healthy })
        .collect();

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "enabled": true,
        "plugins": plugins
    })))
}

/// Admin: paginated list of recently ingested events (newest first, in-memory, best-effort).
pub async fn recent_events(
    store: web::Data<RecentEventsStore>,
    query: web::Query<ListQuery>,
) -> Result<HttpResponse> {
    let all = store.snapshot().await;
    let page: Page<serde_json::Value> = Page::from_vec(all, &query);
    Ok(HttpResponse::Ok().json(page))
}
