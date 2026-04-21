use hocon::HoconLoader;
use serde::{Deserialize, Serialize};
use std::path::Path;

/// The well-known insecure JWT secret used as a fallback when `OAUTH2_JWT_SECRET`
/// is not set. Detected by `validate_for_production()` to prevent accidental
/// use in production deployments.
pub const INSECURE_DEFAULT_JWT_SECRET: &str =
    "insecure-default-for-testing-only-change-in-production";

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Config {
    pub server: ServerConfig,
    pub database: DatabaseConfig,
    pub jwt: JwtConfig,
    pub events: EventConfig,
    #[serde(default)]
    pub social: Option<SocialConfig>,
    #[serde(default)]
    pub session: Option<SessionConfig>,
    #[serde(default)]
    pub debug: Option<DebugConfig>,
    #[serde(default)]
    pub rate_limit: Option<RateLimitConfig>,
    #[serde(default)]
    pub cache: Option<CacheConfig>,
    #[serde(default)]
    pub resilience: Option<ResilienceConfig>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    /// Optional explicit worker count for the Actix HTTP server.
    /// When unset, Actix chooses a sensible default based on available CPUs.
    #[serde(default)]
    pub workers: Option<usize>,
    /// Optional externally-visible base URL (scheme + host + optional path prefix).
    ///
    /// When set, this is used for issuer / endpoint URLs in discovery docs (e.g. OIDC well-known)
    /// so the server can run behind a reverse proxy or local tunnel.
    #[serde(default)]
    pub public_base_url: Option<String>,

    /// Whether to trust proxy-provided headers (e.g. Forwarded / X-Forwarded-*).
    ///
    /// Default is false for safety. Enable only when running behind a trusted proxy.
    #[serde(default)]
    pub trust_proxy_headers: bool,
    /// Public issuer URL for OIDC discovery. Falls back to `http://{host}:{port}`.
    #[serde(default)]
    pub public_url: Option<String>,
    /// Allowlist of origins permitted to make cross-origin requests.
    /// When empty, CORS is fail-closed (all cross-origin requests are denied).
    #[serde(default)]
    pub allowed_origins: Vec<String>,
    /// RFC 9700 §2.6: when `true`, application-layer middleware rejects
    /// plain-HTTP requests with an HTTP 308 redirect to the matching
    /// `https://` URL. Safe to enable behind TLS-terminating reverse proxies
    /// that set `X-Forwarded-Proto`; requires `trust_proxy_headers = true`
    /// for the header to be honored. Defaults to `false` so development
    /// setups keep working without TLS.
    #[serde(default)]
    pub enforce_https: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DatabaseConfig {
    pub url: String,
    /// Optional read-replica URL for routing read queries.
    #[serde(default)]
    pub read_url: Option<String>,
    /// Maximum number of connections in the pool (default: 10).
    #[serde(default = "default_max_connections")]
    pub max_connections: u32,
    /// Minimum number of idle connections maintained in the pool (default: 1).
    #[serde(default = "default_min_connections")]
    pub min_connections: u32,
    /// Connection acquire timeout in seconds (default: 30).
    #[serde(default = "default_acquire_timeout_secs")]
    pub acquire_timeout_secs: u64,
    /// Maximum connection idle duration in seconds before being closed (default: 600).
    #[serde(default = "default_idle_timeout_secs")]
    pub idle_timeout_secs: u64,
}

fn default_max_connections() -> u32 {
    std::env::var("OAUTH2_DATABASE_MAX_CONNECTIONS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(50)
}
fn default_min_connections() -> u32 {
    std::env::var("OAUTH2_DATABASE_MIN_CONNECTIONS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(1)
}
fn default_acquire_timeout_secs() -> u64 {
    std::env::var("OAUTH2_DATABASE_ACQUIRE_TIMEOUT_SECS")
        .ok()
        .or_else(|| std::env::var("OAUTH2_DATABASE_CONNECT_TIMEOUT").ok())
        .and_then(|v| v.parse().ok())
        .unwrap_or(30)
}
fn default_idle_timeout_secs() -> u64 {
    std::env::var("OAUTH2_DATABASE_IDLE_TIMEOUT_SECS")
        .ok()
        .or_else(|| std::env::var("OAUTH2_DATABASE_IDLE_TIMEOUT").ok())
        .and_then(|v| v.parse().ok())
        .unwrap_or(600)
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct JwtConfig {
    pub secret: String,
    #[serde(default = "default_grace_hours")]
    pub key_rotation_grace_hours: u64,
    /// Enable stateless JWT-only token validation (skip DB lookup).
    /// Trades revocation checking for higher throughput.
    #[serde(default)]
    pub stateless_validation: bool,
    /// Allow anonymous callers to use the introspection endpoint.
    /// Default is false so introspection is authenticated unless explicitly opened.
    #[serde(default)]
    pub public_introspection: bool,
    /// Issue opaque (reference-style) access tokens instead of JWT access tokens.
    /// Refresh tokens remain JWT-backed for rotation/replay checks.
    #[serde(default)]
    pub access_tokens_opaque: bool,
    /// Access token lifetime, in seconds. RFC 9700 §2.3 recommends short
    /// access-token lifetimes compensated by refresh rotation.
    #[serde(default = "default_access_token_ttl_secs")]
    pub access_token_ttl_secs: u64,
    /// Refresh token lifetime, in seconds. Defaults to 30 days.
    #[serde(default = "default_refresh_token_ttl_secs")]
    pub refresh_token_ttl_secs: u64,
    /// Authorization-code lifetime, in seconds. RFC 6749 §4.1.2 caps at
    /// 10 minutes; RFC 9700 §2.1.5 encourages even shorter windows.
    #[serde(default = "default_authorization_code_ttl_secs")]
    pub authorization_code_ttl_secs: u64,
}

fn default_grace_hours() -> u64 {
    24
}

fn default_access_token_ttl_secs() -> u64 {
    std::env::var("OAUTH2_ACCESS_TOKEN_TTL_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(3600)
}

fn default_refresh_token_ttl_secs() -> u64 {
    std::env::var("OAUTH2_REFRESH_TOKEN_TTL_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(2_592_000) // 30 days
}

fn default_authorization_code_ttl_secs() -> u64 {
    std::env::var("OAUTH2_AUTHORIZATION_CODE_TTL_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(600) // 10 minutes — RFC 6749 §4.1.2 max
}

/// Configuration for distributed caching (Redis L2 behind in-process LRU).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CacheConfig {
    /// Redis URL for the shared L2 cache tier.
    #[serde(default)]
    pub redis_url: Option<String>,
    /// Number of TokenActor shards for parallelism (default: 1 = no sharding).
    #[serde(default = "default_token_actor_shards")]
    pub token_actor_shards: usize,
}

fn default_token_actor_shards() -> usize {
    1
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            redis_url: None,
            token_actor_shards: default_token_actor_shards(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct EventConfig {
    pub enabled: bool,
    pub backend: String,
    pub filter_mode: String,
    #[serde(default)]
    pub event_types: Vec<String>,
    /// Allow unauthenticated callers to POST external event envelopes.
    /// Default is false so `/events/ingest` requires a bearer secret unless explicitly opened.
    #[serde(default)]
    pub public_ingest: bool,
    /// Shared bearer token for `/events/ingest` when `public_ingest` is false.
    #[serde(skip_serializing)]
    pub ingest_bearer_token: Option<String>,

    // Nested backend-specific settings
    #[serde(default)]
    pub redis: Option<RedisConfig>,
    #[serde(default)]
    pub kafka: Option<KafkaConfig>,
    #[serde(default)]
    pub rabbit: Option<RabbitConfig>,

    // Legacy flat fields for backward compatibility
    #[serde(skip_serializing)]
    pub redis_url: Option<String>,
    #[serde(skip_serializing)]
    pub redis_stream: Option<String>,
    #[serde(skip_serializing)]
    pub redis_maxlen: Option<usize>,
    #[serde(skip_serializing)]
    pub kafka_brokers: Option<String>,
    #[serde(skip_serializing)]
    pub kafka_topic: Option<String>,
    #[serde(skip_serializing)]
    pub kafka_client_id: Option<String>,
    #[serde(skip_serializing)]
    pub rabbit_url: Option<String>,
    #[serde(skip_serializing)]
    pub rabbit_exchange: Option<String>,
    #[serde(skip_serializing)]
    pub rabbit_routing_key: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RedisConfig {
    pub url: String,
    pub stream: String,
    pub maxlen: Option<usize>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct KafkaConfig {
    pub brokers: String,
    pub topic: String,
    pub client_id: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RabbitConfig {
    pub url: String,
    pub exchange: String,
    pub routing_key: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SocialConfig {
    #[serde(default)]
    pub google: Option<ProviderConfig>,
    #[serde(default)]
    pub microsoft: Option<ProviderConfig>,
    #[serde(default)]
    pub github: Option<ProviderConfig>,
    #[serde(default)]
    pub azure: Option<ProviderConfig>,
    #[serde(default)]
    pub okta: Option<ProviderConfig>,
    #[serde(default)]
    pub auth0: Option<ProviderConfig>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ProviderConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub client_id: Option<String>,
    #[serde(default)]
    pub client_secret: Option<String>,
    #[serde(default)]
    pub redirect_uri: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SessionConfig {
    pub key: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DebugConfig {
    pub config: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RateLimitConfig {
    #[serde(default = "default_rate_limit_enabled")]
    pub enabled: bool,
    #[serde(default = "default_max_requests")]
    pub max_requests: u32,
    #[serde(default = "default_window_secs")]
    pub window_secs: u64,
    #[serde(default = "default_rate_limit_backend")]
    pub backend: String,
    #[serde(default)]
    pub redis_url: Option<String>,
    /// Max invalid_client failures per IP per window before returning 429.
    /// Protects token endpoints from credential-stuffing attacks (RFC 9700 §2.5).
    #[serde(default = "default_invalid_client_max_requests")]
    pub invalid_client_max_requests: u32,
}

fn default_rate_limit_enabled() -> bool {
    true
}
fn default_max_requests() -> u32 {
    100
}
fn default_window_secs() -> u64 {
    60
}
fn default_rate_limit_backend() -> String {
    "in_memory".to_string()
}
fn default_invalid_client_max_requests() -> u32 {
    5
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            enabled: default_rate_limit_enabled(),
            max_requests: default_max_requests(),
            window_secs: default_window_secs(),
            backend: default_rate_limit_backend(),
            redis_url: None,
            invalid_client_max_requests: default_invalid_client_max_requests(),
        }
    }
}

/// Top-level resilience configuration.
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct ResilienceConfig {
    /// When `false` (default) the middleware is a no-op.
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub circuit_breaker: Option<CircuitBreakerConfig>,
    #[serde(default)]
    pub back_pressure: Option<BackPressureConfig>,
    /// Per-route-group concurrency limits (bulkheads).
    #[serde(default)]
    pub bulkheads: Vec<BulkheadEntry>,
}

/// Circuit-breaker configuration.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CircuitBreakerConfig {
    /// Consecutive failures before opening.
    #[serde(default = "default_cb_failure_threshold")]
    pub failure_threshold: u32,
    /// Consecutive successes in half-open before closing.
    #[serde(default = "default_cb_success_threshold")]
    pub success_threshold: u32,
    /// Seconds the circuit remains open before probing.
    #[serde(default = "default_cb_open_secs")]
    pub open_secs: u64,
    /// Maximum concurrent probes in half-open state.
    #[serde(default = "default_cb_half_open_max_probes")]
    pub half_open_max_probes: u32,
}

fn default_cb_failure_threshold() -> u32 {
    5
}
fn default_cb_success_threshold() -> u32 {
    2
}
fn default_cb_open_secs() -> u64 {
    30
}
fn default_cb_half_open_max_probes() -> u32 {
    3
}

impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        Self {
            failure_threshold: default_cb_failure_threshold(),
            success_threshold: default_cb_success_threshold(),
            open_secs: default_cb_open_secs(),
            half_open_max_probes: default_cb_half_open_max_probes(),
        }
    }
}

/// Global (server-wide) concurrency / back-pressure configuration.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BackPressureConfig {
    /// Maximum number of simultaneously active requests.
    #[serde(default = "default_bp_max_concurrent")]
    pub max_concurrent: u32,
}

fn default_bp_max_concurrent() -> u32 {
    1000
}

impl Default for BackPressureConfig {
    fn default() -> Self {
        Self {
            max_concurrent: default_bp_max_concurrent(),
        }
    }
}

/// A single bulkhead entry (name + path prefix + concurrency limit).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BulkheadEntry {
    pub name: String,
    pub path_prefix: String,
    #[serde(default = "default_bulkhead_max_concurrent")]
    pub max_concurrent: u32,
}

fn default_bulkhead_max_concurrent() -> u32 {
    200
}

impl Default for Config {
    fn default() -> Self {
        // Try to load from HOCON file first, fall back to environment variables
        Self::from_hocon().unwrap_or_else(|e| {
            tracing::warn!(
                "Failed to load HOCON config: {}. Falling back to environment variables.",
                e
            );
            Self::from_env_fallback()
        })
    }
}

impl Config {
    /// Load configuration from HOCON file with environment variable substitution
    pub fn from_hocon() -> Result<Self, String> {
        Self::from_hocon_path("application.conf")
    }

    /// Load configuration from a specific HOCON file path
    pub fn from_hocon_path<P: AsRef<Path>>(path: P) -> Result<Self, String> {
        let path = path.as_ref();

        if !path.exists() {
            return Err(format!("Configuration file not found: {}", path.display()));
        }

        let mut config: Config = HoconLoader::new()
            .load_file(path)
            .map_err(|e| format!("Failed to load HOCON file: {}", e))?
            .resolve()
            .map_err(|e| format!("Failed to parse and resolve HOCON: {}", e))?;

        // Post-process to maintain backward compatibility with flat event config
        config.normalize_event_config();
        config.normalize_server_config();

        // Handle OAUTH2_EVENTS_TYPES environment variable if set
        // HOCON doesn't support array substitution from env vars directly
        if let Ok(event_types_str) = std::env::var("OAUTH2_EVENTS_TYPES") {
            config.events.event_types = event_types_str
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
        }

        // Handle social provider configuration from environment variables
        config.load_social_from_env();

        // Handle OAUTH2_ALLOWED_ORIGINS environment variable if set
        // HOCON doesn't support array substitution from env vars directly
        if let Ok(val) = std::env::var("OAUTH2_ALLOWED_ORIGINS") {
            if !val.trim().is_empty() {
                config.server.allowed_origins = val
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect();
            }
        }

        Ok(config)
    }

    /// Legacy method for loading from environment variables only
    #[allow(dead_code)]
    pub fn from_env() -> Result<Self, config::ConfigError> {
        let config = config::Config::builder()
            .add_source(config::Environment::with_prefix("OAUTH2"))
            .build()?;

        config.try_deserialize()
    }

    /// Fallback configuration from environment variables (old behavior)
    fn from_env_fallback() -> Self {
        let mut config = Self {
            server: ServerConfig {
                host: std::env::var("OAUTH2_SERVER_HOST")
                    .unwrap_or_else(|_| "127.0.0.1".to_string()),
                port: std::env::var("OAUTH2_SERVER_PORT")
                    .ok()
                    .and_then(|p| p.parse().ok())
                    .unwrap_or(8080),
                workers: std::env::var("OAUTH2_SERVER_WORKERS")
                    .ok()
                    .and_then(|w| w.parse::<usize>().ok())
                    .filter(|w| *w > 0),
                public_base_url: std::env::var("OAUTH2_SERVER_PUBLIC_BASE_URL")
                    .ok()
                    .or_else(|| std::env::var("OAUTH2_PUBLIC_BASE_URL").ok())
                    // Alias for compatibility with docs/tools that already use OAUTH2_BASE_URL
                    .or_else(|| std::env::var("OAUTH2_BASE_URL").ok())
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty()),
                trust_proxy_headers: std::env::var("OAUTH2_SERVER_TRUST_PROXY_HEADERS")
                    .ok()
                    .or_else(|| std::env::var("OAUTH2_TRUST_PROXY_HEADERS").ok())
                    .and_then(|v| v.parse::<bool>().ok())
                    .unwrap_or(false),
                public_url: std::env::var("OAUTH2_PUBLIC_URL")
                    .ok()
                    .or_else(|| std::env::var("OAUTH2_ISSUER_URL").ok())
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty()),
                allowed_origins: vec![],
                enforce_https: std::env::var("OAUTH2_SERVER_ENFORCE_HTTPS")
                    .ok()
                    .or_else(|| std::env::var("OAUTH2_ENFORCE_HTTPS").ok())
                    .and_then(|v| v.parse::<bool>().ok())
                    .unwrap_or(false),
            },
            database: DatabaseConfig {
                url: std::env::var("OAUTH2_DATABASE_URL")
                    .unwrap_or_else(|_| "sqlite:oauth2.db?mode=rwc".to_string()),
                read_url: std::env::var("OAUTH2_DATABASE_READ_URL").ok(),
                max_connections: default_max_connections(),
                min_connections: default_min_connections(),
                acquire_timeout_secs: default_acquire_timeout_secs(),
                idle_timeout_secs: default_idle_timeout_secs(),
            },
            jwt: JwtConfig {
                secret: std::env::var("OAUTH2_JWT_SECRET").unwrap_or_else(|_| {
                    eprintln!("WARNING: OAUTH2_JWT_SECRET not set. Using insecure default for testing only!");
                    eprintln!("NEVER use this in production! Set OAUTH2_JWT_SECRET environment variable.");
                    INSECURE_DEFAULT_JWT_SECRET.to_string()
                }),
                key_rotation_grace_hours: std::env::var("OAUTH2_JWT_KEY_ROTATION_GRACE_HOURS")
                    .ok()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(24),
                stateless_validation: std::env::var("OAUTH2_JWT_STATELESS_VALIDATION")
                    .ok()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(false),
                public_introspection: std::env::var("OAUTH2_PUBLIC_INTROSPECTION")
                    .ok()
                    .or_else(|| std::env::var("OAUTH2_INTROSPECTION_PUBLIC").ok())
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(false),
                access_tokens_opaque: std::env::var("OAUTH2_ACCESS_TOKENS_OPAQUE")
                    .ok()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(false),
                access_token_ttl_secs: default_access_token_ttl_secs(),
                refresh_token_ttl_secs: default_refresh_token_ttl_secs(),
                authorization_code_ttl_secs: default_authorization_code_ttl_secs(),
            },
            events: EventConfig {
                enabled: std::env::var("OAUTH2_EVENTS_ENABLED")
                    .ok()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(true),
                backend: std::env::var("OAUTH2_EVENTS_BACKEND")
                    .unwrap_or_else(|_| "in_memory".to_string()),
                filter_mode: std::env::var("OAUTH2_EVENTS_FILTER_MODE")
                    .unwrap_or_else(|_| "allow_all".to_string()),
                event_types: std::env::var("OAUTH2_EVENTS_TYPES")
                    .unwrap_or_default()
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect(),
                public_ingest: std::env::var("OAUTH2_EVENTS_PUBLIC_INGEST")
                    .ok()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(false),
                ingest_bearer_token: std::env::var("OAUTH2_EVENTS_INGEST_BEARER_TOKEN")
                    .ok()
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty()),
                redis: None,
                kafka: None,
                rabbit: None,
                redis_url: std::env::var("OAUTH2_EVENTS_REDIS_URL").ok(),
                redis_stream: std::env::var("OAUTH2_EVENTS_REDIS_STREAM").ok(),
                redis_maxlen: std::env::var("OAUTH2_EVENTS_REDIS_MAXLEN")
                    .ok()
                    .and_then(|v| v.parse().ok()),
                kafka_brokers: std::env::var("OAUTH2_EVENTS_KAFKA_BROKERS").ok(),
                kafka_topic: std::env::var("OAUTH2_EVENTS_KAFKA_TOPIC").ok(),
                kafka_client_id: std::env::var("OAUTH2_EVENTS_KAFKA_CLIENT_ID").ok(),
                rabbit_url: std::env::var("OAUTH2_EVENTS_RABBIT_URL").ok(),
                rabbit_exchange: std::env::var("OAUTH2_EVENTS_RABBIT_EXCHANGE").ok(),
                rabbit_routing_key: std::env::var("OAUTH2_EVENTS_RABBIT_ROUTING_KEY").ok(),
            },
            rate_limit: Some(RateLimitConfig {
                enabled: std::env::var("OAUTH2_RATE_LIMIT_ENABLED")
                    .ok()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(true),
                max_requests: std::env::var("OAUTH2_RATE_LIMIT_MAX_REQUESTS")
                    .ok()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(100),
                window_secs: std::env::var("OAUTH2_RATE_LIMIT_WINDOW_SECS")
                    .ok()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(60),
                backend: std::env::var("OAUTH2_RATE_LIMIT_BACKEND")
                    .unwrap_or_else(|_| "in_memory".to_string()),
                redis_url: std::env::var("OAUTH2_RATE_LIMIT_REDIS_URL").ok(),
                invalid_client_max_requests: std::env::var(
                    "OAUTH2_RATE_LIMIT_INVALID_CLIENT_MAX_REQUESTS",
                )
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(5),
            }),
            social: None,
            session: None,
            debug: None,
            cache: Some(CacheConfig {
                redis_url: std::env::var("OAUTH2_CACHE_REDIS_URL").ok(),
                token_actor_shards: std::env::var("OAUTH2_TOKEN_ACTOR_SHARDS")
                    .ok()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(1),
            }),
            resilience: Self::resilience_from_env(),
        };

        config.normalize_event_config();
        config.normalize_server_config();

        if let Ok(val) = std::env::var("OAUTH2_ALLOWED_ORIGINS") {
            if !val.trim().is_empty() {
                config.server.allowed_origins = val
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect();
            }
        }

        config
    }

    /// Normalize event config to support both nested and flat structures
    fn normalize_event_config(&mut self) {
        // If nested redis config exists, populate flat fields for backward compatibility
        if let Some(ref redis) = self.events.redis {
            if self.events.redis_url.is_none() {
                self.events.redis_url = Some(redis.url.clone());
            }
            if self.events.redis_stream.is_none() {
                self.events.redis_stream = Some(redis.stream.clone());
            }
            if self.events.redis_maxlen.is_none() {
                self.events.redis_maxlen = redis.maxlen;
            }
        }

        // If nested kafka config exists, populate flat fields for backward compatibility
        if let Some(ref kafka) = self.events.kafka {
            if self.events.kafka_brokers.is_none() {
                self.events.kafka_brokers = Some(kafka.brokers.clone());
            }
            if self.events.kafka_topic.is_none() {
                self.events.kafka_topic = Some(kafka.topic.clone());
            }
            if self.events.kafka_client_id.is_none() {
                self.events.kafka_client_id = kafka.client_id.clone();
            }
        }

        // If nested rabbit config exists, populate flat fields for backward compatibility
        if let Some(ref rabbit) = self.events.rabbit {
            if self.events.rabbit_url.is_none() {
                self.events.rabbit_url = Some(rabbit.url.clone());
            }
            if self.events.rabbit_exchange.is_none() {
                self.events.rabbit_exchange = Some(rabbit.exchange.clone());
            }
            if self.events.rabbit_routing_key.is_none() {
                self.events.rabbit_routing_key = Some(rabbit.routing_key.clone());
            }
        }
    }

    /// Normalize server URL aliases so docs and config examples can use the
    /// externally-visible base URL name without breaking OIDC discovery.
    fn normalize_server_config(&mut self) {
        let public_base_url = self
            .server
            .public_base_url
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(ToOwned::to_owned);

        let public_url = self
            .server
            .public_url
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(ToOwned::to_owned);

        self.server.public_base_url = public_base_url;
        self.server.public_url = public_url.or_else(|| self.server.public_base_url.clone());
    }

    /// Load social provider configurations from environment variables
    fn load_social_from_env(&mut self) {
        if let Some(ref mut social) = self.social {
            Self::load_provider_from_env(&mut social.google, "GOOGLE");
            Self::load_provider_from_env(&mut social.microsoft, "MICROSOFT");
            Self::load_provider_from_env(&mut social.github, "GITHUB");
            Self::load_provider_from_env(&mut social.azure, "AZURE");
            Self::load_provider_from_env(&mut social.okta, "OKTA");
            Self::load_provider_from_env(&mut social.auth0, "AUTH0");
        }
    }

    /// Load a single provider configuration from environment variables
    fn load_provider_from_env(provider: &mut Option<ProviderConfig>, prefix: &str) {
        // Check if any environment variables are set for this provider
        let client_id = std::env::var(format!("OAUTH2_{}_CLIENT_ID", prefix)).ok();
        let client_secret = std::env::var(format!("OAUTH2_{}_CLIENT_SECRET", prefix)).ok();

        // If client_id and client_secret are set, enable the provider
        if client_id.is_some() && client_secret.is_some() {
            // Provide default redirect_uri if not set (for backward compatibility)
            let redirect_uri = std::env::var(format!("OAUTH2_{}_REDIRECT_URI", prefix))
                .ok()
                .or_else(|| {
                    Some(format!(
                        "http://localhost:8080/auth/callback/{}",
                        prefix.to_lowercase()
                    ))
                });

            let tenant_id = std::env::var(format!("OAUTH2_{}_TENANT_ID", prefix)).ok();
            let domain = std::env::var(format!("OAUTH2_{}_DOMAIN", prefix)).ok();

            *provider = Some(ProviderConfig {
                enabled: true,
                client_id,
                client_secret,
                redirect_uri,
                tenant_id,
                domain,
            });
        }
    }

    /// Validate configuration for production use.
    ///
    /// Returns `Ok(())` if:
    /// - JWT secret is not the insecure default and is ≥32 bytes, OR
    /// - `OAUTH2_ALLOW_INSECURE_DEFAULTS=1` is explicitly set (test/dev opt-in).
    ///
    /// **Warning**: The opt-in flag bypasses ALL validation, including the minimum
    /// length check. It is intended solely for test and local development environments.
    pub fn validate_for_production(&self) -> Result<(), String> {
        // Allow test/dev environments to skip validation via explicit opt-in.
        if std::env::var("OAUTH2_ALLOW_INSECURE_DEFAULTS").as_deref() == Ok("1") {
            return Ok(());
        }

        // Check JWT secret is not the default
        if self.jwt.secret == INSECURE_DEFAULT_JWT_SECRET {
            return Err("OAUTH2_JWT_SECRET must be explicitly set for production. \
                Generate a secure random string (minimum 32 characters). \
                Set OAUTH2_ALLOW_INSECURE_DEFAULTS=1 to suppress this in test environments."
                .to_string());
        }

        // Check JWT secret length (measured in bytes, which is correct for HMAC keys)
        if self.jwt.secret.len() < 32 {
            return Err(format!(
                "OAUTH2_JWT_SECRET must be at least 32 bytes long (current: {} bytes)",
                self.jwt.secret.len()
            ));
        }

        Ok(())
    }

    /// Produce a version safe to log (secrets masked).
    pub fn sanitized(&self) -> Self {
        let mut clone = self.clone();
        clone.jwt.secret = "***MASKED***".to_string();

        // Sanitize social provider secrets
        if let Some(ref mut social) = clone.social {
            Self::sanitize_provider(&mut social.google);
            Self::sanitize_provider(&mut social.microsoft);
            Self::sanitize_provider(&mut social.github);
            Self::sanitize_provider(&mut social.azure);
            Self::sanitize_provider(&mut social.okta);
            Self::sanitize_provider(&mut social.auth0);
        }

        clone
    }

    fn sanitize_provider(provider: &mut Option<ProviderConfig>) {
        if let Some(ref mut p) = provider {
            if let Some(ref mut secret) = p.client_secret {
                *secret = "***MASKED***".to_string();
            }
        }
    }

    /// Build a `ResilienceConfig` from environment variables.
    ///
    /// Returns `None` when `OAUTH2_RESILIENCE_ENABLED` is absent or `false`.
    /// In that case, all other `OAUTH2_RESILIENCE_*` variables are intentionally
    /// ignored — resilience is entirely disabled and the middleware is a no-op.
    /// To activate resilience, set `OAUTH2_RESILIENCE_ENABLED=true`; the
    /// remaining variables then control the individual sub-features.
    ///
    /// Each sub-feature (back-pressure, circuit breaker) can be independently
    /// disabled by setting `OAUTH2_RESILIENCE_BP_ENABLED=false` or
    /// `OAUTH2_RESILIENCE_CB_ENABLED=false`.
    fn resilience_from_env() -> Option<ResilienceConfig> {
        let enabled = std::env::var("OAUTH2_RESILIENCE_ENABLED")
            .ok()
            .and_then(|v| v.parse::<bool>().ok())
            .unwrap_or(false);

        if !enabled {
            return None;
        }

        // Back-pressure — disabled when OAUTH2_RESILIENCE_BP_ENABLED=false.
        let bp_enabled = std::env::var("OAUTH2_RESILIENCE_BP_ENABLED")
            .ok()
            .and_then(|v| v.parse::<bool>().ok())
            .unwrap_or(true);
        let back_pressure = if bp_enabled {
            Some(BackPressureConfig {
                max_concurrent: std::env::var("OAUTH2_RESILIENCE_MAX_CONCURRENT")
                    .ok()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or_else(default_bp_max_concurrent),
            })
        } else {
            None
        };

        // Circuit breaker — disabled when OAUTH2_RESILIENCE_CB_ENABLED=false.
        let cb_enabled = std::env::var("OAUTH2_RESILIENCE_CB_ENABLED")
            .ok()
            .and_then(|v| v.parse::<bool>().ok())
            .unwrap_or(true);
        let circuit_breaker = if cb_enabled {
            Some(CircuitBreakerConfig {
                failure_threshold: std::env::var("OAUTH2_RESILIENCE_CB_FAILURE_THRESHOLD")
                    .ok()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or_else(default_cb_failure_threshold),
                success_threshold: std::env::var("OAUTH2_RESILIENCE_CB_SUCCESS_THRESHOLD")
                    .ok()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or_else(default_cb_success_threshold),
                open_secs: std::env::var("OAUTH2_RESILIENCE_CB_OPEN_SECS")
                    .ok()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or_else(default_cb_open_secs),
                half_open_max_probes: std::env::var("OAUTH2_RESILIENCE_CB_HALF_OPEN_MAX_PROBES")
                    .ok()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or_else(default_cb_half_open_max_probes),
            })
        } else {
            None
        };

        Some(ResilienceConfig {
            enabled,
            circuit_breaker,
            back_pressure,
            bulkheads: vec![],
        })
    }
}

#[cfg(test)]
mod tests {
    use super::Config;
    use std::fs;

    #[test]
    fn loads_distributed_scaling_settings_from_hocon() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let config_path = tempdir.path().join("application.conf");

        fs::write(
            &config_path,
            r#"
server {
    host = "127.0.0.1"
    port = 8080
    workers = 8
}

database {
    url = "postgresql://primary.example.internal:5432/oauth2"
    read_url = "postgresql://replica.example.internal:5432/oauth2"
    max_connections = 75
    min_connections = 5
    acquire_timeout_secs = 12
    idle_timeout_secs = 240
}

jwt {
    secret = "test-jwt-secret-for-ci-only-do-not-use-in-production-32chars"
    key_rotation_grace_hours = 24
    stateless_validation = true
}

events {
    enabled = false
    backend = "in_memory"
    filter_mode = "allow_all"
}

cache {
    redis_url = "redis://redis.internal:6379"
    token_actor_shards = 8
}
                        "#,
        )
        .expect("write config");

        let config = Config::from_hocon_path(&config_path).expect("load config");

        assert_eq!(
            config.database.read_url.as_deref(),
            Some("postgresql://replica.example.internal:5432/oauth2")
        );
        assert_eq!(config.database.max_connections, 75);
        assert_eq!(config.database.min_connections, 5);
        assert_eq!(config.database.acquire_timeout_secs, 12);
        assert_eq!(config.database.idle_timeout_secs, 240);
        assert_eq!(config.server.workers, Some(8));
        assert!(config.jwt.stateless_validation);

        let cache = config.cache.expect("cache config");
        assert_eq!(
            cache.redis_url.as_deref(),
            Some("redis://redis.internal:6379")
        );
        assert_eq!(cache.token_actor_shards, 8);
    }

    #[test]
    fn public_base_url_alias_populates_public_url() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let config_path = tempdir.path().join("application.conf");

        fs::write(
            &config_path,
            r#"
        server {
            host = "127.0.0.1"
            port = 8080
            public_base_url = "https://auth.example.com"
        }

        database {
            url = "sqlite:oauth2.db?mode=rwc"
        }

        jwt {
            secret = "test-jwt-secret-for-ci-only-do-not-use-in-production-32chars"
        }

        events {
            enabled = false
            backend = "in_memory"
            filter_mode = "allow_all"
        }
                    "#,
        )
        .expect("write config");

        let config = Config::from_hocon_path(&config_path).expect("load config");

        assert_eq!(
            config.server.public_base_url.as_deref(),
            Some("https://auth.example.com")
        );
        assert_eq!(
            config.server.public_url.as_deref(),
            Some("https://auth.example.com")
        );
    }
}
