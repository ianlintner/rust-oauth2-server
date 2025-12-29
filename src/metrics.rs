use prometheus::{Counter, CounterVec, Histogram, HistogramOpts, HistogramVec, IntCounter, IntGauge, Opts, Registry};
use std::sync::Arc;

#[derive(Clone)]
pub struct Metrics {
    pub registry: Arc<Registry>,

    // Request metrics
    pub http_requests_total: Counter,
    pub http_request_duration_seconds: Histogram,

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
    #[allow(dead_code)] // Planned for observability implementation
    pub oauth_token_issued_total: IntCounter,
    #[allow(dead_code)] // Planned for observability implementation
    pub oauth_token_revoked_total: IntCounter,
    #[allow(dead_code)] // Planned for observability implementation
    pub oauth_authorization_codes_issued: IntCounter,
    #[allow(dead_code)] // Planned for observability implementation
    pub oauth_failed_authentications: IntCounter,

    // Client metrics
    #[allow(dead_code)] // Planned for observability implementation
    pub oauth_clients_total: IntGauge,
    #[allow(dead_code)] // Planned for observability implementation
    pub oauth_active_tokens: IntGauge,

    // Database metrics
    #[allow(dead_code)] // Planned for observability implementation
    pub db_queries_total: Counter,
    #[allow(dead_code)] // Planned for observability implementation
    pub db_query_duration_seconds: Histogram,
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
            .namespace("oauth2_server"),
        )?;
        registry.register(Box::new(http_request_duration_seconds.clone()))?;

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

        Ok(Self {
            registry: Arc::new(registry),
            http_requests_total,
            http_request_duration_seconds,
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
        })
    }
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new().expect("Failed to create metrics")
    }
}
