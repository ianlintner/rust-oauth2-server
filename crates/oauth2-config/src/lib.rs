use hocon::HoconLoader;
use serde::{Deserialize, Serialize};
use std::path::Path;

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
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DatabaseConfig {
    pub url: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct JwtConfig {
    pub secret: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct EventConfig {
    pub enabled: bool,
    pub backend: String,
    pub filter_mode: String,
    #[serde(default)]
    pub event_types: Vec<String>,

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
            },
            database: DatabaseConfig {
                url: std::env::var("OAUTH2_DATABASE_URL")
                    .unwrap_or_else(|_| "sqlite:oauth2.db?mode=rwc".to_string()),
            },
            jwt: JwtConfig {
                secret: std::env::var("OAUTH2_JWT_SECRET").unwrap_or_else(|_| {
                    eprintln!("WARNING: OAUTH2_JWT_SECRET not set. Using insecure default for testing only!");
                    eprintln!("NEVER use this in production! Set OAUTH2_JWT_SECRET environment variable.");
                    "insecure-default-for-testing-only-change-in-production".to_string()
                }),
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
            social: None,
            session: None,
            debug: None,
        };

        config.normalize_event_config();
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

    /// Validate configuration for production use
    pub fn validate_for_production(&self) -> Result<(), String> {
        // Check JWT secret is not the default
        if self.jwt.secret == "insecure-default-for-testing-only-change-in-production" {
            return Err("OAUTH2_JWT_SECRET must be explicitly set for production. Generate a secure random string (minimum 32 characters).".to_string());
        }

        // Check JWT secret length
        if self.jwt.secret.len() < 32 {
            return Err(format!(
                "OAUTH2_JWT_SECRET must be at least 32 characters long (current: {} characters)",
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
}
