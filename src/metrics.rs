use prometheus::{Counter, Histogram, HistogramOpts, IntCounter, IntGauge, Opts, Registry};
use std::sync::Arc;

#[derive(Clone)]
pub struct Metrics {
    pub registry: Arc<Registry>,

    // Request metrics
    pub http_requests_total: Counter,
    pub http_request_duration_seconds: Histogram,

    // OAuth2 metrics
    pub oauth_token_issued_total: IntCounter,
    pub oauth_token_revoked_total: IntCounter,
    pub oauth_authorization_codes_issued: IntCounter,
    pub oauth_failed_authentications: IntCounter,

    // Client metrics
    pub oauth_clients_total: IntGauge,
    pub oauth_active_tokens: IntGauge,

    // Database metrics
    pub db_queries_total: Counter,
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
