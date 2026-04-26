/// JWKS URI TTL cache (RFC 7517 / RFC 7636 / RFC 7523 §2.2)
///
/// Fetches and caches JWKS documents from `jwks_uri` endpoints.
/// TTL is derived from `Cache-Control: max-age` in the HTTP response;
/// falls back to [`DEFAULT_TTL_SECS`] if the header is absent or unparseable.
///
/// The cache is a simple `Arc<Mutex<HashMap>>` — suitable for an OAuth2 AS
/// that has at most hundreds of registered clients and low jwks_uri fetch
/// concurrency. For very high concurrency a lock-free structure could be used,
/// but the complexity is not warranted here.
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use serde_json::Value;

use oauth2_core::OAuth2Error;

/// Default TTL when the server does not advertise `Cache-Control: max-age`.
const DEFAULT_TTL_SECS: u64 = 300; // 5 minutes

/// Minimum TTL to prevent hammering a slow JWKS endpoint.
const MIN_TTL_SECS: u64 = 30;

/// Maximum TTL to ensure keys are eventually rotated even if the server says
/// to cache forever.
const MAX_TTL_SECS: u64 = 86_400; // 24 hours

#[derive(Clone, Debug)]
struct CachedJwks {
    value: Value,
    fetched_at: Instant,
    ttl: Duration,
}

impl CachedJwks {
    fn is_fresh(&self) -> bool {
        self.fetched_at.elapsed() < self.ttl
    }
}

/// Shared, cloneable JWKS URI cache.
///
/// Register this as Actix `app_data` so all handlers share one cache.
#[derive(Clone, Debug)]
pub struct JwksCache {
    inner: Arc<Mutex<HashMap<String, CachedJwks>>>,
}

impl JwksCache {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Fetch JWKS from `url`, using the cache when the entry is still fresh.
    ///
    /// On a cache miss (or stale entry) this performs an HTTP GET with
    /// `reqwest` and updates the cache before returning.
    pub async fn fetch(&self, url: &str) -> Result<Value, OAuth2Error> {
        // Fast path: check the cache under a short lock.
        {
            let guard: std::sync::MutexGuard<HashMap<String, CachedJwks>> = self
                .inner
                .lock()
                .map_err(|_| OAuth2Error::new("server_error", Some("JWKS cache lock poisoned")))?;
            if let Some(entry) = guard.get(url) {
                if entry.is_fresh() {
                    return Ok(entry.value.clone());
                }
            }
        }

        // Slow path: fetch from the network.
        let (jwks, ttl): (Value, Duration) = fetch_jwks_from_url(url).await?;

        // Store in cache.
        {
            let mut guard: std::sync::MutexGuard<HashMap<String, CachedJwks>> =
                self.inner.lock().map_err(|_| {
                    OAuth2Error::new("server_error", Some("JWKS cache lock poisoned"))
                })?;
            guard.insert(
                url.to_string(),
                CachedJwks {
                    value: jwks.clone(),
                    fetched_at: Instant::now(),
                    ttl,
                },
            );
        }

        Ok(jwks)
    }
}

impl Default for JwksCache {
    fn default() -> Self {
        Self::new()
    }
}

/// Perform the actual HTTP GET and parse the JWKS document.
///
/// Returns `(jwks_value, ttl)` where `ttl` is derived from `Cache-Control:
/// max-age`, clamped to `[MIN_TTL_SECS, MAX_TTL_SECS]`.
async fn fetch_jwks_from_url(url: &str) -> Result<(Value, Duration), OAuth2Error> {
    let http_client: reqwest::Client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .map_err(|e| {
            OAuth2Error::new(
                "server_error",
                Some(&format!("Failed to build HTTP client: {e}")),
            )
        })?;

    let response: reqwest::Response = http_client
        .get(url)
        .header("Accept", "application/json")
        .send()
        .await
        .map_err(|e| {
            OAuth2Error::invalid_client(&format!("Failed to fetch jwks_uri '{url}': {e}"))
        })?;

    if !response.status().is_success() {
        return Err(OAuth2Error::invalid_client(&format!(
            "jwks_uri '{url}' returned HTTP {}",
            response.status()
        )));
    }

    let ttl = parse_cache_control_max_age(response.headers());

    let text: String = response.text().await.map_err(|e| {
        OAuth2Error::invalid_client(&format!(
            "Failed to read jwks_uri '{url}' response body: {e}"
        ))
    })?;

    let jwks: Value = serde_json::from_str(&text).map_err(|e| {
        OAuth2Error::invalid_client(&format!("jwks_uri '{url}' returned invalid JSON: {e}"))
    })?;

    // Basic structural validation.
    if jwks
        .get("keys")
        .and_then(|v: &Value| v.as_array())
        .is_none()
    {
        return Err(OAuth2Error::invalid_client(&format!(
            "jwks_uri '{url}' JWKS document missing 'keys' array"
        )));
    }

    Ok((jwks, ttl))
}

/// Parse `Cache-Control: max-age=N` from response headers.
///
/// Returns a TTL in `[MIN_TTL_SECS, MAX_TTL_SECS]`, falling back to
/// `DEFAULT_TTL_SECS` when the header is absent or unparseable.
fn parse_cache_control_max_age(headers: &reqwest::header::HeaderMap) -> Duration {
    let secs = headers
        .get(reqwest::header::CACHE_CONTROL)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| {
            s.split(',')
                .map(str::trim)
                .find(|d| d.starts_with("max-age="))
                .and_then(|d| d["max-age=".len()..].parse::<u64>().ok())
        })
        .unwrap_or(DEFAULT_TTL_SECS);

    Duration::from_secs(secs.clamp(MIN_TTL_SECS, MAX_TTL_SECS))
}
