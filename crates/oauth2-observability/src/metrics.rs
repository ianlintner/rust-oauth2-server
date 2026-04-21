use prometheus::{
    Counter, CounterVec, Gauge, GaugeVec, Histogram, HistogramOpts, HistogramVec, IntCounter,
    IntCounterVec, IntGauge, IntGaugeVec, Opts, Registry,
};
use std::sync::Arc;

/// Standardized latency histogram buckets (seconds).
///
/// Paved-path spec §3: one curated set across all services so dashboards and
/// alert thresholds port cleanly between workloads. Covers sub-millisecond
/// internal work up through 10-second deadlines at the edge.
pub const STANDARD_LATENCY_BUCKETS: &[f64] = &[
    0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
];

/// Standardized size histogram buckets (bytes).
///
/// Paved-path spec §3. Log-spaced from 128B to 8MiB.
pub const STANDARD_SIZE_BUCKETS: &[f64] = &[
    128.0,
    512.0,
    2048.0,
    8192.0,
    32768.0,
    131072.0,
    524288.0,
    2_097_152.0,
    8_388_608.0,
];

#[derive(Clone)]
pub struct Metrics {
    pub registry: Arc<Registry>,

    // Request metrics
    pub http_requests_total: Counter,
    pub http_request_duration_seconds: Histogram,

    /// HTTP request counter bucketed by response status class.
    ///
    /// Label `status_class` values: `2xx`, `3xx`, `4xx`, `5xx`, `other`.
    /// Kept separate from `http_requests_total_by_route` so existing
    /// time-series (without a `status_class` label) are not broken.
    pub http_requests_by_class_total: CounterVec,

    /// Labeled HTTP request counter.
    ///
    /// Labels:
    /// - method: HTTP method
    /// - route: actix route pattern (preferred) or path fallback
    /// - status: HTTP status code
    pub http_requests_total_by_route: CounterVec,

    /// Labeled HTTP request latency histogram.
    ///
    /// Labels:
    /// - method: HTTP method
    /// - route: actix route pattern (preferred) or path fallback
    /// - status: HTTP status code
    pub http_request_duration_seconds_by_route: HistogramVec,

    // OAuth2 metrics
    #[allow(dead_code)]
    pub oauth_token_issued_total: IntCounter,
    #[allow(dead_code)]
    pub oauth_token_revoked_total: IntCounter,
    #[allow(dead_code)]
    pub oauth_authorization_codes_issued: IntCounter,
    #[allow(dead_code)]
    pub oauth_failed_authentications: IntCounter,

    // Client metrics
    #[allow(dead_code)]
    pub oauth_clients_total: IntGauge,
    #[allow(dead_code)]
    pub oauth_active_tokens: IntGauge,

    // Database metrics
    #[allow(dead_code)]
    pub db_queries_total: Counter,
    #[allow(dead_code)]
    pub db_query_duration_seconds: Histogram,

    // Rate limiting metrics
    pub rate_limit_rejected_total: CounterVec,
    pub rate_limit_remaining: Histogram,

    // Resilience metrics
    /// Current circuit breaker state (0=Closed, 1=Open, 2=HalfOpen).
    /// Label: `circuit` — the circuit breaker name.
    pub circuit_breaker_state: GaugeVec,
    /// Total number of times a circuit has tripped open.
    /// Label: `circuit` — the circuit breaker name.
    pub circuit_breaker_trips_total: CounterVec,
    /// Total requests rejected because the global concurrency limit was reached
    /// (back-pressure).
    pub back_pressure_rejected_total: Counter,
    /// Current number of in-flight requests across all concurrency limiters.
    pub concurrent_requests_in_flight: Gauge,
    /// Total requests rejected because a specific bulkhead was at capacity.
    /// Label: `bulkhead` — the bulkhead name.
    pub bulkhead_rejected_total: CounterVec,

    // ---------------------------------------------------------------------
    // Paved-path baseline (see the `prometheus-metrics` skill spec)
    // ---------------------------------------------------------------------
    /// Static-1 gauge carrying build / version metadata as labels. Emit
    /// exactly one series of value 1; dashboards join it with RED metrics
    /// to correlate deployments with latency / error shifts. Labels:
    /// `service`, `version`, `rust_version`.
    pub app_info: IntGaugeVec,

    /// Domain error counter bucketed by kind. Labels: `kind` — one of
    /// `validation`, `upstream`, `internal`, `auth`, `ratelimit`.
    /// Populated by the handler error paths; complements
    /// `oauth_failed_authentications` which is auth-specific.
    pub errors_total: IntCounterVec,

    /// Outbound HTTP client request counter. Labels: `peer_service`
    /// (e.g. `github`, `google`, `microsoft`, `jwks`), `http_method`,
    /// `http_status_code`. Populated by social-login + JWKS-fetch paths.
    pub http_client_requests_total: IntCounterVec,

    /// Outbound HTTP client request latency histogram. Same labels as
    /// `http_client_requests_total` minus `http_status_code` — status
    /// lives on the counter to keep the histogram's cardinality low.
    pub http_client_request_duration_seconds: HistogramVec,

    /// Event bus publish counter. Labels: `backend`
    /// (e.g. `in_memory`, `kafka`, `rabbit`, `redis_streams`),
    /// `event_type`, `outcome` (`success` | `failure`).
    pub events_published_total: IntCounterVec,

    /// Event bus publish latency histogram. Labels: `backend`, `outcome`.
    pub events_publish_duration_seconds: HistogramVec,

    /// Redis client operation counter. Labels: `backend`
    /// (`rate_limit`, `cache`, `events`), `operation`
    /// (`get`, `set`, `del`, `xadd`, `incr`, …), `outcome`.
    pub redis_client_operations_total: IntCounterVec,

    /// Redis client operation latency histogram. Same labels minus
    /// `outcome`; failures and successes share one histogram so p95
    /// picks up both.
    pub redis_client_operation_duration_seconds: HistogramVec,
}

impl Metrics {
    pub fn new() -> Result<Self, prometheus::Error> {
        let registry = Registry::new();

        let http_requests_total = Counter::with_opts(
            Opts::new("http_requests_total", "Total number of HTTP requests")
                .namespace("oauth2_server"),
        )?;
        registry.register(Box::new(http_requests_total.clone()))?;

        let http_request_duration_seconds = Histogram::with_opts(
            HistogramOpts::new(
                "http_request_duration_seconds",
                "HTTP request duration in seconds",
            )
            .namespace("oauth2_server")
            .buckets(vec![
                0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
            ]),
        )?;
        registry.register(Box::new(http_request_duration_seconds.clone()))?;

        let http_requests_by_class_total = CounterVec::new(
            Opts::new(
                "http_requests_by_class_total",
                "Total number of HTTP requests bucketed by response status class (2xx/3xx/4xx/5xx/other)",
            )
            .namespace("oauth2_server"),
            &["status_class"],
        )?;
        registry.register(Box::new(http_requests_by_class_total.clone()))?;

        let http_requests_total_by_route = CounterVec::new(
            Opts::new(
                "http_requests_total_by_route",
                "Total number of HTTP requests (labeled by method/route/status)",
            )
            .namespace("oauth2_server"),
            &["method", "route", "status"],
        )?;
        registry.register(Box::new(http_requests_total_by_route.clone()))?;

        let http_request_duration_seconds_by_route = HistogramVec::new(
            HistogramOpts::new(
                "http_request_duration_seconds_by_route",
                "HTTP request duration in seconds (labeled by method/route/status)",
            )
            .namespace("oauth2_server"),
            &["method", "route", "status"],
        )?;
        registry.register(Box::new(http_request_duration_seconds_by_route.clone()))?;

        let oauth_token_issued_total = IntCounter::with_opts(
            Opts::new("oauth_token_issued_total", "Total number of tokens issued")
                .namespace("oauth2_server"),
        )?;
        registry.register(Box::new(oauth_token_issued_total.clone()))?;

        let oauth_token_revoked_total = IntCounter::with_opts(
            Opts::new(
                "oauth_token_revoked_total",
                "Total number of tokens revoked",
            )
            .namespace("oauth2_server"),
        )?;
        registry.register(Box::new(oauth_token_revoked_total.clone()))?;

        let oauth_authorization_codes_issued = IntCounter::with_opts(
            Opts::new(
                "oauth_authorization_codes_issued",
                "Total number of authorization codes issued",
            )
            .namespace("oauth2_server"),
        )?;
        registry.register(Box::new(oauth_authorization_codes_issued.clone()))?;

        let oauth_failed_authentications = IntCounter::with_opts(
            Opts::new(
                "oauth_failed_authentications",
                "Total number of failed authentication attempts",
            )
            .namespace("oauth2_server"),
        )?;
        registry.register(Box::new(oauth_failed_authentications.clone()))?;

        let oauth_clients_total = IntGauge::with_opts(
            Opts::new("oauth_clients_total", "Total number of registered clients")
                .namespace("oauth2_server"),
        )?;
        registry.register(Box::new(oauth_clients_total.clone()))?;

        let oauth_active_tokens = IntGauge::with_opts(
            Opts::new("oauth_active_tokens", "Number of active tokens").namespace("oauth2_server"),
        )?;
        registry.register(Box::new(oauth_active_tokens.clone()))?;

        let db_queries_total = Counter::with_opts(
            Opts::new("db_queries_total", "Total number of database queries")
                .namespace("oauth2_server"),
        )?;
        registry.register(Box::new(db_queries_total.clone()))?;

        let db_query_duration_seconds = Histogram::with_opts(
            HistogramOpts::new(
                "db_query_duration_seconds",
                "Database query duration in seconds",
            )
            .namespace("oauth2_server"),
        )?;
        registry.register(Box::new(db_query_duration_seconds.clone()))?;

        let rate_limit_rejected_total = CounterVec::new(
            Opts::new("rate_limit_rejected_total", "Total rate-limited requests")
                .namespace("oauth2_server"),
            &["ip_prefix"],
        )
        .expect("rate_limit_rejected_total metric");
        registry
            .register(Box::new(rate_limit_rejected_total.clone()))
            .expect("register rate_limit_rejected_total");

        let rate_limit_remaining = Histogram::with_opts(
            HistogramOpts::new(
                "rate_limit_remaining",
                "Distribution of remaining tokens on allowed requests",
            )
            .namespace("oauth2_server")
            .buckets(vec![0.0, 1.0, 5.0, 10.0, 25.0, 50.0, 75.0, 100.0]),
        )
        .expect("rate_limit_remaining metric");
        registry
            .register(Box::new(rate_limit_remaining.clone()))
            .expect("register rate_limit_remaining");

        // --- Resilience metrics ---

        let circuit_breaker_state = GaugeVec::new(
            Opts::new(
                "circuit_breaker_state",
                "Current circuit breaker state (0=Closed, 1=Open, 2=HalfOpen)",
            )
            .namespace("oauth2_server"),
            &["circuit"],
        )
        .expect("circuit_breaker_state metric");
        registry
            .register(Box::new(circuit_breaker_state.clone()))
            .expect("register circuit_breaker_state");

        let circuit_breaker_trips_total = CounterVec::new(
            Opts::new(
                "circuit_breaker_trips_total",
                "Total number of times the circuit breaker has tripped open",
            )
            .namespace("oauth2_server"),
            &["circuit"],
        )
        .expect("circuit_breaker_trips_total metric");
        registry
            .register(Box::new(circuit_breaker_trips_total.clone()))
            .expect("register circuit_breaker_trips_total");

        let back_pressure_rejected_total = Counter::with_opts(
            Opts::new(
                "back_pressure_rejected_total",
                "Total requests rejected due to global concurrency limit (back-pressure)",
            )
            .namespace("oauth2_server"),
        )
        .expect("back_pressure_rejected_total metric");
        registry
            .register(Box::new(back_pressure_rejected_total.clone()))
            .expect("register back_pressure_rejected_total");

        let concurrent_requests_in_flight = Gauge::with_opts(
            Opts::new(
                "concurrent_requests_in_flight",
                "Current number of in-flight requests",
            )
            .namespace("oauth2_server"),
        )
        .expect("concurrent_requests_in_flight metric");
        registry
            .register(Box::new(concurrent_requests_in_flight.clone()))
            .expect("register concurrent_requests_in_flight");

        let bulkhead_rejected_total = CounterVec::new(
            Opts::new(
                "bulkhead_rejected_total",
                "Total requests rejected because a bulkhead was at capacity",
            )
            .namespace("oauth2_server"),
            &["bulkhead"],
        )
        .expect("bulkhead_rejected_total metric");
        registry
            .register(Box::new(bulkhead_rejected_total.clone()))
            .expect("register bulkhead_rejected_total");

        // -----------------------------------------------------------------
        // Paved-path baseline — see the `prometheus-metrics` skill spec.
        // -----------------------------------------------------------------
        let app_info = IntGaugeVec::new(
            Opts::new("app_info", "Static build metadata (always 1)").namespace("oauth2_server"),
            &["service", "version", "rust_version"],
        )?;
        registry.register(Box::new(app_info.clone()))?;
        // Emit exactly one series: ("oauth2-server", <crate version>, <rustc version>).
        // `rustc_version_runtime` avoids a build.rs; the value is fixed at
        // compile time and reported at startup.
        app_info
            .with_label_values(&[
                "oauth2-server",
                env!("CARGO_PKG_VERSION"),
                option_env!("RUSTC_VERSION").unwrap_or("unknown"),
            ])
            .set(1);

        let errors_total = IntCounterVec::new(
            Opts::new(
                "errors_total",
                "Domain errors bucketed by kind (validation|upstream|internal|auth|ratelimit)",
            )
            .namespace("oauth2_server"),
            &["kind"],
        )?;
        registry.register(Box::new(errors_total.clone()))?;

        let http_client_requests_total = IntCounterVec::new(
            Opts::new(
                "http_client_requests_total",
                "Outbound HTTP requests issued by this service",
            )
            .namespace("oauth2_server"),
            &["peer_service", "http_method", "http_status_code"],
        )?;
        registry.register(Box::new(http_client_requests_total.clone()))?;

        let http_client_request_duration_seconds = HistogramVec::new(
            HistogramOpts::new(
                "http_client_request_duration_seconds",
                "Outbound HTTP request latency",
            )
            .namespace("oauth2_server")
            .buckets(STANDARD_LATENCY_BUCKETS.to_vec()),
            &["peer_service", "http_method"],
        )?;
        registry.register(Box::new(http_client_request_duration_seconds.clone()))?;

        let events_published_total = IntCounterVec::new(
            Opts::new(
                "events_published_total",
                "Event bus publish attempts, by backend and outcome",
            )
            .namespace("oauth2_server"),
            &["backend", "event_type", "outcome"],
        )?;
        registry.register(Box::new(events_published_total.clone()))?;

        let events_publish_duration_seconds = HistogramVec::new(
            HistogramOpts::new(
                "events_publish_duration_seconds",
                "Event bus publish latency, by backend",
            )
            .namespace("oauth2_server")
            .buckets(STANDARD_LATENCY_BUCKETS.to_vec()),
            &["backend", "outcome"],
        )?;
        registry.register(Box::new(events_publish_duration_seconds.clone()))?;

        let redis_client_operations_total = IntCounterVec::new(
            Opts::new(
                "redis_client_operations_total",
                "Redis client operations, by backend and outcome",
            )
            .namespace("oauth2_server"),
            &["backend", "operation", "outcome"],
        )?;
        registry.register(Box::new(redis_client_operations_total.clone()))?;

        let redis_client_operation_duration_seconds = HistogramVec::new(
            HistogramOpts::new(
                "redis_client_operation_duration_seconds",
                "Redis client operation latency, by backend",
            )
            .namespace("oauth2_server")
            .buckets(STANDARD_LATENCY_BUCKETS.to_vec()),
            &["backend", "operation"],
        )?;
        registry.register(Box::new(redis_client_operation_duration_seconds.clone()))?;

        // Seed each labeled family with a zero-value "boot" series so that
        // /metrics exposes the TYPE + HELP lines and dashboards can find
        // the series immediately after a cold start, before any real
        // request has been processed. The prometheus-client crate only
        // emits a family once a concrete label combination has been
        // observed — without this seed a brand-new replica would scrape
        // an empty response for these counters/histograms.
        errors_total.with_label_values(&["internal"]).inc_by(0);
        http_client_requests_total
            .with_label_values(&["bootstrap", "GET", "0"])
            .inc_by(0);
        http_client_request_duration_seconds
            .with_label_values(&["bootstrap", "GET"])
            .observe(0.0);
        events_published_total
            .with_label_values(&["bootstrap", "boot", "success"])
            .inc_by(0);
        events_publish_duration_seconds
            .with_label_values(&["bootstrap", "success"])
            .observe(0.0);
        redis_client_operations_total
            .with_label_values(&["bootstrap", "ping", "success"])
            .inc_by(0);
        redis_client_operation_duration_seconds
            .with_label_values(&["bootstrap", "ping"])
            .observe(0.0);

        Ok(Self {
            registry: Arc::new(registry),
            http_requests_total,
            http_request_duration_seconds,
            http_requests_by_class_total,
            http_requests_total_by_route,
            http_request_duration_seconds_by_route,
            oauth_token_issued_total,
            oauth_token_revoked_total,
            oauth_authorization_codes_issued,
            oauth_failed_authentications,
            oauth_clients_total,
            oauth_active_tokens,
            db_queries_total,
            db_query_duration_seconds,
            rate_limit_rejected_total,
            rate_limit_remaining,
            circuit_breaker_state,
            circuit_breaker_trips_total,
            back_pressure_rejected_total,
            concurrent_requests_in_flight,
            bulkhead_rejected_total,
            app_info,
            errors_total,
            http_client_requests_total,
            http_client_request_duration_seconds,
            events_published_total,
            events_publish_duration_seconds,
            redis_client_operations_total,
            redis_client_operation_duration_seconds,
        })
    }
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new().expect("Failed to create metrics")
    }
}
