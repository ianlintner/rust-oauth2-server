use oauth2::{
    basic::BasicClient, AuthUrl, ClientId, ClientSecret, EndpointNotSet, EndpointSet, RedirectUrl,
    TokenUrl,
};
use serde::Deserialize;
use std::sync::Arc;
use std::time::Duration;

use oauth2_config::ProviderConfig;
use oauth2_core::OAuth2Error;

use crate::circuit_breaker::CircuitBreaker;
use crate::models::SocialUserInfo;

/// Outbound HTTP client type. With `otel` enabled this is the middleware-wrapped
/// client that emits a CLIENT span and injects W3C traceparent/tracestate per
/// request; without it this is a plain `reqwest::Client`.
#[cfg(feature = "otel")]
type HttpClient = reqwest_middleware::ClientWithMiddleware;
#[cfg(not(feature = "otel"))]
type HttpClient = reqwest::Client;

fn build_http_client(timeout: Duration) -> HttpClient {
    let inner = reqwest::Client::builder()
        .timeout(timeout)
        .build()
        .expect("reqwest client");

    #[cfg(feature = "otel")]
    {
        // reqwest-tracing 0.5.x only exposes opentelemetry features through
        // 0.30. It injects headers via `opentelemetry_0_30::global::get_text_map_propagator`,
        // which is a *different* global static from the workspace's OTEL 0.31
        // propagator installed by W0.1 `init_telemetry`. Install a
        // `TraceContextPropagator` on the 0.30 global here (once) so that the
        // middleware actually serialises the current span's context into
        // traceparent/tracestate. This bridge can be removed once upstream
        // reqwest-tracing gains `opentelemetry_0_31` support AND permits
        // reqwest 0.12.
        use std::sync::Once;
        static INIT_0_30_PROPAGATOR: Once = Once::new();
        INIT_0_30_PROPAGATOR.call_once(|| {
            opentelemetry_0_30_pkg::global::set_text_map_propagator(
                opentelemetry_sdk_0_30_pkg::propagation::TraceContextPropagator::new(),
            );
        });

        reqwest_middleware::ClientBuilder::new(inner)
            .with(reqwest_tracing::TracingMiddleware::default())
            .build()
    }
    #[cfg(not(feature = "otel"))]
    {
        inner
    }
}

// Type alias for a fully configured OAuth2 client with all required endpoints set.
// This is necessary due to oauth2 5.0's typestate pattern which tracks endpoint
// configuration at compile time.
type ConfiguredClient = oauth2::Client<
    oauth2::StandardErrorResponse<oauth2::basic::BasicErrorResponseType>,
    oauth2::StandardTokenResponse<oauth2::EmptyExtraTokenFields, oauth2::basic::BasicTokenType>,
    oauth2::StandardTokenIntrospectionResponse<
        oauth2::EmptyExtraTokenFields,
        oauth2::basic::BasicTokenType,
    >,
    oauth2::StandardRevocableToken,
    oauth2::StandardErrorResponse<oauth2::RevocationErrorResponseType>,
    EndpointSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointSet,
>;

/// Default request timeout for social provider HTTP calls.
const PROVIDER_TIMEOUT: Duration = Duration::from_secs(10);
/// Open the circuit after 5 consecutive failures.
const CB_FAILURE_THRESHOLD: u32 = 5;
/// Re-allow a probe request after 30 seconds.
const CB_COOLDOWN: Duration = Duration::from_secs(30);

pub struct SocialLoginService {
    /// Shared HTTP client with timeout. When built with `otel`, the client is
    /// wrapped with `reqwest-tracing`'s middleware for W3C context propagation
    /// and per-request CLIENT spans.
    http: HttpClient,
    /// Per-provider circuit breakers.
    pub cb_google: Arc<CircuitBreaker>,
    pub cb_microsoft: Arc<CircuitBreaker>,
    pub cb_github: Arc<CircuitBreaker>,
}

impl Default for SocialLoginService {
    fn default() -> Self {
        Self::new()
    }
}

impl SocialLoginService {
    pub fn new() -> Self {
        Self {
            http: build_http_client(PROVIDER_TIMEOUT),
            cb_google: Arc::new(CircuitBreaker::new(CB_FAILURE_THRESHOLD, CB_COOLDOWN)),
            cb_microsoft: Arc::new(CircuitBreaker::new(CB_FAILURE_THRESHOLD, CB_COOLDOWN)),
            cb_github: Arc::new(CircuitBreaker::new(CB_FAILURE_THRESHOLD, CB_COOLDOWN)),
        }
    }
}

impl SocialLoginService {
    /// Helper function to validate and extract required provider configuration fields
    fn validate_provider_config(
        config: &ProviderConfig,
        provider_name: &str,
    ) -> Result<(String, String, String), OAuth2Error> {
        let client_id = config
            .client_id
            .as_ref()
            .ok_or_else(|| {
                OAuth2Error::new(
                    "invalid_configuration",
                    Some(&format!("{} client_id not set", provider_name)),
                )
            })?
            .clone();
        let client_secret = config
            .client_secret
            .as_ref()
            .ok_or_else(|| {
                OAuth2Error::new(
                    "invalid_configuration",
                    Some(&format!("{} client_secret not set", provider_name)),
                )
            })?
            .clone();
        let redirect_uri = config
            .redirect_uri
            .as_ref()
            .ok_or_else(|| {
                OAuth2Error::new(
                    "invalid_configuration",
                    Some(&format!("{} redirect_uri not set", provider_name)),
                )
            })?
            .clone();

        Ok((client_id, client_secret, redirect_uri))
    }

    pub fn get_google_client(config: &ProviderConfig) -> Result<ConfiguredClient, OAuth2Error> {
        let (client_id, client_secret, redirect_uri) =
            Self::validate_provider_config(config, "Google")?;

        Ok(BasicClient::new(ClientId::new(client_id))
            .set_client_secret(ClientSecret::new(client_secret))
            .set_auth_uri(
                AuthUrl::new("https://accounts.google.com/o/oauth2/v2/auth".to_string())
                    .map_err(|e| OAuth2Error::new("invalid_configuration", Some(&e.to_string())))?,
            )
            .set_token_uri(
                TokenUrl::new("https://oauth2.googleapis.com/token".to_string())
                    .map_err(|e| OAuth2Error::new("invalid_configuration", Some(&e.to_string())))?,
            )
            .set_redirect_uri(
                RedirectUrl::new(redirect_uri)
                    .map_err(|e| OAuth2Error::new("invalid_configuration", Some(&e.to_string())))?,
            ))
    }

    pub fn get_microsoft_client(config: &ProviderConfig) -> Result<ConfiguredClient, OAuth2Error> {
        let (client_id, client_secret, redirect_uri) =
            Self::validate_provider_config(config, "Microsoft")?;

        let tenant = config.tenant_id.as_deref().unwrap_or("common");
        Ok(BasicClient::new(ClientId::new(client_id))
            .set_client_secret(ClientSecret::new(client_secret))
            .set_auth_uri(
                AuthUrl::new(format!(
                    "https://login.microsoftonline.com/{}/oauth2/v2.0/authorize",
                    tenant
                ))
                .map_err(|e| OAuth2Error::new("invalid_configuration", Some(&e.to_string())))?,
            )
            .set_token_uri(
                TokenUrl::new(format!(
                    "https://login.microsoftonline.com/{}/oauth2/v2.0/token",
                    tenant
                ))
                .map_err(|e| OAuth2Error::new("invalid_configuration", Some(&e.to_string())))?,
            )
            .set_redirect_uri(
                RedirectUrl::new(redirect_uri)
                    .map_err(|e| OAuth2Error::new("invalid_configuration", Some(&e.to_string())))?,
            ))
    }

    pub fn get_github_client(config: &ProviderConfig) -> Result<ConfiguredClient, OAuth2Error> {
        let (client_id, client_secret, redirect_uri) =
            Self::validate_provider_config(config, "GitHub")?;

        Ok(BasicClient::new(ClientId::new(client_id))
            .set_client_secret(ClientSecret::new(client_secret))
            .set_auth_uri(
                AuthUrl::new("https://github.com/login/oauth/authorize".to_string())
                    .map_err(|e| OAuth2Error::new("invalid_configuration", Some(&e.to_string())))?,
            )
            .set_token_uri(
                TokenUrl::new("https://github.com/login/oauth/access_token".to_string())
                    .map_err(|e| OAuth2Error::new("invalid_configuration", Some(&e.to_string())))?,
            )
            .set_redirect_uri(
                RedirectUrl::new(redirect_uri)
                    .map_err(|e| OAuth2Error::new("invalid_configuration", Some(&e.to_string())))?,
            ))
    }

    #[tracing::instrument(
        level = "info",
        name = "social.fetch_user_info",
        skip_all,
        fields(provider = "google"),
        err
    )]
    pub async fn fetch_google_user_info(
        &self,
        access_token: &str,
    ) -> Result<SocialUserInfo, OAuth2Error> {
        if !self.cb_google.allow_request() {
            return Err(OAuth2Error::new(
                "provider_unavailable",
                Some("Google circuit breaker open"),
            ));
        }

        let result = self.do_fetch_google(access_token).await;
        match &result {
            Ok(_) => self.cb_google.on_success(),
            Err(_) => self.cb_google.on_failure(),
        }
        result
    }

    async fn do_fetch_google(&self, access_token: &str) -> Result<SocialUserInfo, OAuth2Error> {
        let response = self
            .http
            .get("https://www.googleapis.com/oauth2/v2/userinfo")
            .bearer_auth(access_token)
            .send()
            .await
            .map_err(|e| OAuth2Error::new("provider_error", Some(&e.to_string())))?;

        #[derive(Deserialize)]
        struct GoogleUser {
            id: String,
            email: String,
            name: Option<String>,
            picture: Option<String>,
        }

        let user: GoogleUser = response
            .json()
            .await
            .map_err(|e| OAuth2Error::new("provider_error", Some(&e.to_string())))?;

        Ok(SocialUserInfo {
            provider: "google".to_string(),
            provider_user_id: user.id,
            email: user.email,
            name: user.name,
            picture: user.picture,
        })
    }

    #[tracing::instrument(
        level = "info",
        name = "social.fetch_user_info",
        skip_all,
        fields(provider = "microsoft"),
        err
    )]
    pub async fn fetch_microsoft_user_info(
        &self,
        access_token: &str,
    ) -> Result<SocialUserInfo, OAuth2Error> {
        if !self.cb_microsoft.allow_request() {
            return Err(OAuth2Error::new(
                "provider_unavailable",
                Some("Microsoft circuit breaker open"),
            ));
        }

        let result = self.do_fetch_microsoft(access_token).await;
        match &result {
            Ok(_) => self.cb_microsoft.on_success(),
            Err(_) => self.cb_microsoft.on_failure(),
        }
        result
    }

    async fn do_fetch_microsoft(&self, access_token: &str) -> Result<SocialUserInfo, OAuth2Error> {
        let response = self
            .http
            .get("https://graph.microsoft.com/v1.0/me")
            .bearer_auth(access_token)
            .send()
            .await
            .map_err(|e| OAuth2Error::new("provider_error", Some(&e.to_string())))?;

        #[derive(Deserialize)]
        struct MicrosoftUser {
            id: String,
            #[serde(rename = "userPrincipalName")]
            email: String,
            #[serde(rename = "displayName")]
            name: Option<String>,
        }

        let user: MicrosoftUser = response
            .json()
            .await
            .map_err(|e| OAuth2Error::new("provider_error", Some(&e.to_string())))?;

        Ok(SocialUserInfo {
            provider: "microsoft".to_string(),
            provider_user_id: user.id,
            email: user.email,
            name: user.name,
            picture: None,
        })
    }

    #[tracing::instrument(
        level = "info",
        name = "social.fetch_user_info",
        skip_all,
        fields(provider = "github"),
        err
    )]
    pub async fn fetch_github_user_info(
        &self,
        access_token: &str,
    ) -> Result<SocialUserInfo, OAuth2Error> {
        if !self.cb_github.allow_request() {
            return Err(OAuth2Error::new(
                "provider_unavailable",
                Some("GitHub circuit breaker open"),
            ));
        }

        let result = self.do_fetch_github(access_token).await;
        match &result {
            Ok(_) => self.cb_github.on_success(),
            Err(_) => self.cb_github.on_failure(),
        }
        result
    }

    async fn do_fetch_github(&self, access_token: &str) -> Result<SocialUserInfo, OAuth2Error> {
        let response = self
            .http
            .get("https://api.github.com/user")
            .bearer_auth(access_token)
            .header("User-Agent", "rust_oauth2_server")
            .send()
            .await
            .map_err(|e| OAuth2Error::new("provider_error", Some(&e.to_string())))?;

        #[derive(Deserialize)]
        struct GitHubUser {
            id: i64,
            email: Option<String>,
            name: Option<String>,
            avatar_url: Option<String>,
        }

        let user: GitHubUser = response
            .json()
            .await
            .map_err(|e| OAuth2Error::new("provider_error", Some(&e.to_string())))?;

        // GitHub might not provide email in the main call
        let email = if let Some(email) = user.email {
            email
        } else {
            // Fetch primary email
            let email_response = self
                .http
                .get("https://api.github.com/user/emails")
                .bearer_auth(access_token)
                .header("User-Agent", "rust_oauth2_server")
                .send()
                .await
                .map_err(|e| OAuth2Error::new("provider_error", Some(&e.to_string())))?;

            #[derive(Deserialize)]
            struct GitHubEmail {
                email: String,
                primary: bool,
            }

            let emails: Vec<GitHubEmail> = email_response
                .json()
                .await
                .map_err(|e| OAuth2Error::new("provider_error", Some(&e.to_string())))?;

            emails
                .into_iter()
                .find(|e| e.primary)
                .map(|e| e.email)
                .ok_or_else(|| OAuth2Error::new("provider_error", Some("No email found")))?
        };

        Ok(SocialUserInfo {
            provider: "github".to_string(),
            provider_user_id: user.id.to_string(),
            email,
            name: user.name,
            picture: user.avatar_url,
        })
    }
}
