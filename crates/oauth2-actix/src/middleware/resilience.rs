//! Resilience middleware.
//!
//! Provides three complementary layers applied in the following order:
//!
//! 1. **Circuit breaker (fast-fail)** — when the circuit is fully **open**,
//!    all requests are rejected with 503 immediately (cheapest path).
//! 2. **Back-pressure** — a global bounded semaphore; when all permits are
//!    taken the request is rejected with 503 immediately.
//! 3. **Bulkheads** — per-route-group concurrency limits so a surge in one
//!    area (e.g. `/oauth`) cannot starve another (e.g. `/admin`).
//! 4. **Circuit breaker (probing)** — in **half-open** state a limited
//!    number of probe requests are forwarded.  This check runs *after*
//!    back-pressure / bulkhead admission so a probe slot is never wasted on
//!    a request that would have been rejected by capacity limits anyway.
//!
//! Requests to exempt paths (health, ready, metrics) skip all checks.

use std::future::{ready, Ready};
use std::rc::Rc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use actix_web::body::EitherBody;
use actix_web::dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform};
use actix_web::{Error, HttpResponse};
use futures::future::LocalBoxFuture;
use oauth2_observability::Metrics;
use oauth2_resilience::{BulkheadRegistry, CircuitBreaker, CircuitState, ConcurrencyLimiter};

/// Configures the resilience middleware.
pub struct ResilienceMiddleware {
    /// Global (server-wide) concurrency limiter for back-pressure.
    /// `None` disables back-pressure.
    concurrency: Option<Arc<ConcurrencyLimiter>>,
    /// Per-scope bulkhead registry.
    /// `None` disables bulkhead isolation.
    bulkheads: Option<Arc<BulkheadRegistry>>,
    /// Circuit breaker shared across the whole server.
    /// `None` disables the circuit breaker.
    circuit_breaker: Option<Arc<CircuitBreaker>>,
    /// Prometheus metrics handle.
    metrics: Arc<Metrics>,
    /// Paths that bypass all resilience checks.
    exempt_paths: Vec<String>,
    /// Tracks the last observed trip count for delta-increment of the
    /// Prometheus counter (which can only go up).
    last_trips: Arc<AtomicU32>,
}

impl ResilienceMiddleware {
    pub fn new(
        concurrency: Option<Arc<ConcurrencyLimiter>>,
        bulkheads: Option<Arc<BulkheadRegistry>>,
        circuit_breaker: Option<Arc<CircuitBreaker>>,
        metrics: Arc<Metrics>,
        exempt_paths: Vec<String>,
    ) -> Self {
        Self {
            concurrency,
            bulkheads,
            circuit_breaker,
            metrics,
            exempt_paths,
            last_trips: Arc::new(AtomicU32::new(0)),
        }
    }
}

impl<S, B> Transform<S, ServiceRequest> for ResilienceMiddleware
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = Error;
    type InitError = ();
    type Transform = ResilienceService<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(ResilienceService {
            service: Rc::new(service),
            concurrency: self.concurrency.clone(),
            bulkheads: self.bulkheads.clone(),
            circuit_breaker: self.circuit_breaker.clone(),
            metrics: self.metrics.clone(),
            exempt_paths: self.exempt_paths.clone(),
            last_trips: self.last_trips.clone(),
        }))
    }
}

pub struct ResilienceService<S> {
    service: Rc<S>,
    concurrency: Option<Arc<ConcurrencyLimiter>>,
    bulkheads: Option<Arc<BulkheadRegistry>>,
    circuit_breaker: Option<Arc<CircuitBreaker>>,
    metrics: Arc<Metrics>,
    exempt_paths: Vec<String>,
    last_trips: Arc<AtomicU32>,
}

impl<S, B> Service<ServiceRequest> for ResilienceService<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let svc = self.service.clone();
        let concurrency = self.concurrency.clone();
        let bulkheads = self.bulkheads.clone();
        let circuit_breaker = self.circuit_breaker.clone();
        let metrics = self.metrics.clone();
        let exempt = self.exempt_paths.clone();
        let path = req.path().to_string();
        let last_trips = self.last_trips.clone();

        Box::pin(async move {
            // --- exempt paths bypass all checks ---
            if exempt.iter().any(|p| path.starts_with(p)) {
                let res = svc.call(req).await?;
                return Ok(res.map_into_left_body());
            }

            // --- circuit breaker fast-fail (Open state only) ---
            // When the circuit is fully Open, reject immediately — this is
            // the cheapest path and doesn't consume a probe slot.
            if let Some(ref cb) = circuit_breaker {
                let state = cb.state();
                if state == CircuitState::Open {
                    tracing::warn!(
                        path = %path,
                        state = ?state,
                        "Circuit breaker open — fast failing request"
                    );
                    metrics
                        .circuit_breaker_state
                        .with_label_values(&["global"])
                        .set(state.as_gauge_value());

                    let retry_secs = cb.open_duration().as_secs().max(1).to_string();
                    let response = HttpResponse::ServiceUnavailable()
                        .insert_header(("Retry-After", retry_secs))
                        .json(serde_json::json!({
                            "error": "service_unavailable",
                            "error_description":
                                "Server is temporarily unavailable. Please retry later.",
                        }));
                    return Ok(req.into_response(response).map_into_right_body());
                }
            }

            // Track whether the in-flight gauge has been incremented so we
            // can decrement it exactly once regardless of the exit path.
            let mut in_flight_incremented = false;

            // --- global back-pressure check ---
            let _global_permit = if let Some(ref lim) = concurrency {
                match lim.try_acquire() {
                    Some(p) => {
                        metrics.concurrent_requests_in_flight.inc();
                        in_flight_incremented = true;
                        Some(p)
                    }
                    None => {
                        tracing::warn!(
                            path = %path,
                            in_flight = lim.in_flight(),
                            max = lim.max_concurrent(),
                            "Back-pressure: global concurrency limit reached"
                        );
                        metrics.back_pressure_rejected_total.inc();
                        let response = HttpResponse::ServiceUnavailable()
                            .insert_header(("Retry-After", "1"))
                            .json(serde_json::json!({
                                "error": "service_unavailable",
                                "error_description":
                                    "Server is at capacity. Please retry later.",
                            }));
                        return Ok(req.into_response(response).map_into_right_body());
                    }
                }
            } else {
                None
            };

            // Helper: decrement the in-flight gauge exactly once.
            let dec_in_flight = |incremented: &mut bool, m: &Metrics| {
                if *incremented {
                    m.concurrent_requests_in_flight.dec();
                    *incremented = false;
                }
            };

            // --- bulkhead check ---
            let _bulkhead_permit = if let Some(ref reg) = bulkheads {
                let (name, permit) = reg.try_acquire(&path);
                match permit {
                    Some(p) => Some(p),
                    None => {
                        // `name == "none"` means no bulkhead matched — allow through.
                        if name == "none" {
                            None
                        } else {
                            tracing::warn!(
                                path = %path,
                                bulkhead = %name,
                                "Bulkhead at capacity — rejecting request"
                            );
                            metrics
                                .bulkhead_rejected_total
                                .with_label_values(&[name])
                                .inc();
                            dec_in_flight(&mut in_flight_incremented, &metrics);
                            let response = HttpResponse::ServiceUnavailable()
                                .insert_header(("Retry-After", "1"))
                                .json(serde_json::json!({
                                    "error": "service_unavailable",
                                    "error_description":
                                        "Endpoint is at capacity. Please retry later.",
                                }));
                            return Ok(req.into_response(response).map_into_right_body());
                        }
                    }
                }
            } else {
                None
            };

            // --- circuit breaker probing (HalfOpen state) ---
            // This runs AFTER back-pressure / bulkhead admission so a probe
            // slot is never wasted on a request that would be rejected by
            // capacity limits anyway.
            let is_cb_probe = if let Some(ref cb) = circuit_breaker {
                if cb.state() == CircuitState::HalfOpen {
                    if !cb.allow_request() {
                        tracing::warn!(
                            path = %path,
                            "Circuit breaker half-open — probe limit reached, rejecting"
                        );
                        dec_in_flight(&mut in_flight_incremented, &metrics);
                        let retry_secs = cb.open_duration().as_secs().max(1).to_string();
                        let response = HttpResponse::ServiceUnavailable()
                            .insert_header(("Retry-After", retry_secs))
                            .json(serde_json::json!({
                                "error": "service_unavailable",
                                "error_description":
                                    "Server is temporarily unavailable. Please retry later.",
                            }));
                        return Ok(req.into_response(response).map_into_right_body());
                    }
                    true
                } else {
                    false
                }
            } else {
                false
            };

            // --- forward the request ---
            let res = svc.call(req).await?;

            // --- decrement in-flight gauge ---
            dec_in_flight(&mut in_flight_incremented, &metrics);

            // --- update circuit breaker based on outcome ---
            if let Some(ref cb) = circuit_breaker {
                let status = res.status().as_u16();
                // Only record success/failure when the CB is tracking
                // (Closed for failure counting, HalfOpen for probes).
                if is_cb_probe || cb.state() == CircuitState::Closed {
                    if status >= 500 {
                        cb.record_failure();
                    } else {
                        cb.record_success();
                    }
                }
                // Reflect current state in the gauge.
                let new_state = cb.state();
                metrics
                    .circuit_breaker_state
                    .with_label_values(&["global"])
                    .set(new_state.as_gauge_value());

                // Increment the trips counter by the delta since we last checked.
                // Use compare_exchange to ensure only one worker thread claims
                // each increment, preventing double-counting under concurrent load.
                let current_trips = cb.total_trips();
                let prev = last_trips.load(Ordering::Acquire);
                if current_trips > prev
                    && last_trips
                        .compare_exchange(prev, current_trips, Ordering::AcqRel, Ordering::Relaxed)
                        .is_ok()
                {
                    let delta = current_trips - prev;
                    metrics
                        .circuit_breaker_trips_total
                        .with_label_values(&["global"])
                        .inc_by(f64::from(delta));
                }
            }

            Ok(res.map_into_left_body())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::{test, web, App, HttpResponse};
    use oauth2_observability::Metrics;

    fn make_metrics() -> Arc<Metrics> {
        Arc::new(Metrics::new().unwrap())
    }

    #[actix_web::test]
    async fn exempt_path_bypasses_back_pressure() {
        let lim = Arc::new(ConcurrencyLimiter::new(0)); // capacity 0 → always rejected
        let metrics = make_metrics();

        let app = test::init_service(
            App::new()
                .wrap(ResilienceMiddleware::new(
                    Some(lim),
                    None,
                    None,
                    metrics,
                    vec!["/health".into()],
                ))
                .route(
                    "/health",
                    web::get().to(|| async { HttpResponse::Ok().finish() }),
                ),
        )
        .await;

        let req = test::TestRequest::get().uri("/health").to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);
    }

    #[actix_web::test]
    async fn back_pressure_rejects_when_at_capacity() {
        let lim = Arc::new(ConcurrencyLimiter::new(1));
        // Hold the only permit so the next request is rejected.
        let _held = lim.try_acquire();
        let metrics = make_metrics();

        let app = test::init_service(
            App::new()
                .wrap(ResilienceMiddleware::new(
                    Some(lim),
                    None,
                    None,
                    metrics,
                    vec![],
                ))
                .route(
                    "/oauth/token",
                    web::post().to(|| async { HttpResponse::Ok().finish() }),
                ),
        )
        .await;

        let req = test::TestRequest::post().uri("/oauth/token").to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 503);
    }

    #[actix_web::test]
    async fn circuit_breaker_open_returns_503() {
        use oauth2_resilience::{CircuitBreaker, CircuitBreakerConfig};
        use std::time::Duration;

        let cfg = CircuitBreakerConfig {
            failure_threshold: 1,
            success_threshold: 1,
            open_duration: Duration::from_secs(60),
            half_open_max_probes: 1,
        };
        let cb = Arc::new(CircuitBreaker::new("test", cfg));
        // Open the circuit.
        cb.record_failure();
        assert_eq!(cb.state(), oauth2_resilience::CircuitState::Open);

        let metrics = make_metrics();
        let app = test::init_service(
            App::new()
                .wrap(ResilienceMiddleware::new(
                    None,
                    None,
                    Some(cb),
                    metrics,
                    vec![],
                ))
                .route(
                    "/oauth/token",
                    web::post().to(|| async { HttpResponse::Ok().finish() }),
                ),
        )
        .await;

        let req = test::TestRequest::post().uri("/oauth/token").to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 503);
    }

    #[actix_web::test]
    async fn bulkhead_rejects_when_full() {
        use oauth2_resilience::{BulkheadConfig, BulkheadRegistry};

        let reg = Arc::new(BulkheadRegistry::from_configs(vec![BulkheadConfig {
            name: "oauth".into(),
            path_prefix: "/oauth".into(),
            max_concurrent: 1,
        }]));

        // Exhaust the bulkhead.
        let (_n, _held) = reg.try_acquire("/oauth/token");
        let metrics = make_metrics();

        let app = test::init_service(
            App::new()
                .wrap(ResilienceMiddleware::new(
                    None,
                    Some(reg),
                    None,
                    metrics,
                    vec![],
                ))
                .route(
                    "/oauth/token",
                    web::post().to(|| async { HttpResponse::Ok().finish() }),
                ),
        )
        .await;

        let req = test::TestRequest::post().uri("/oauth/token").to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 503);
    }
}
