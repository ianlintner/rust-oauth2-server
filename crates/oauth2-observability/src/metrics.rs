use prometheus::{
    Counter, CounterVec, Gauge, GaugeVec, Histogram, HistogramOpts, HistogramVec, IntCounter,
    IntGauge, Opts, Registry,
};
use std::sync::Arc;

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
        })
    }
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new().expect("Failed to create metrics")
    }
}
