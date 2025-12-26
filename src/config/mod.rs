use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub server: ServerConfig,
    pub database: DatabaseConfig,
    pub jwt: JwtConfig,
    pub events: EventConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DatabaseConfig {
    pub url: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct JwtConfig {
    pub secret: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct EventConfig {
    pub enabled: bool,
    pub backend: String,
    pub filter_mode: String,
    pub event_types: Vec<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            server: ServerConfig {
                host: std::env::var("OAUTH2_SERVER_HOST").unwrap_or_else(|_| "127.0.0.1".to_string()),
                port: std::env::var("OAUTH2_SERVER_PORT")
                    .ok()
                    .and_then(|p| p.parse().ok())
                    .unwrap_or(8080),
            },
            database: DatabaseConfig {
                url: std::env::var("OAUTH2_DATABASE_URL").unwrap_or_else(|_| "sqlite:oauth2.db".to_string()),
            },
            jwt: JwtConfig {
                // Use environment variable or fail-safe default for testing
                // Production deployments MUST set OAUTH2_JWT_SECRET
                secret: std::env::var("OAUTH2_JWT_SECRET")
                    .unwrap_or_else(|_| {
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
            },
        }
    }
}

impl Config {
    #[allow(dead_code)] // Planned for future environment-based configuration
    pub fn from_env() -> Result<Self, config::ConfigError> {
        let config = config::Config::builder()
            .add_source(config::Environment::with_prefix("OAUTH2"))
            .build()?;

        config.try_deserialize()
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
}
