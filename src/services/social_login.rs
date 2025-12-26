#![allow(dead_code)]

use crate::models::{OAuth2Error, ProviderConfig, SocialUserInfo};
use oauth2::{basic::BasicClient, AuthUrl, ClientId, ClientSecret, RedirectUrl, TokenUrl, EndpointSet, EndpointNotSet};
use serde::Deserialize;

// Type alias for a fully configured OAuth2 client with all required endpoints set.
// This is necessary due to oauth2 5.0's typestate pattern which tracks endpoint
// configuration at compile time. The generic parameters represent:
// - Error types for standard responses and revocation
// - Token response and introspection types
// - Endpoint states: auth URL (Set), token URL (Set), device/introspection/revocation (NotSet)
type ConfiguredClient = oauth2::Client<
    oauth2::StandardErrorResponse<oauth2::basic::BasicErrorResponseType>,
    oauth2::StandardTokenResponse<
        oauth2::EmptyExtraTokenFields,
        oauth2::basic::BasicTokenType,
    >,
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

pub struct SocialLoginService;

impl SocialLoginService {
    pub fn get_google_client(config: &ProviderConfig) -> Result<ConfiguredClient, OAuth2Error> {
        Ok(BasicClient::new(ClientId::new(config.client_id.clone()))
            .set_client_secret(ClientSecret::new(config.client_secret.clone()))
            .set_auth_uri(
                AuthUrl::new("https://accounts.google.com/o/oauth2/v2/auth".to_string())
                    .map_err(|e| OAuth2Error::new("invalid_configuration", Some(&e.to_string())))?,
            )
            .set_token_uri(
                TokenUrl::new("https://oauth2.googleapis.com/token".to_string())
                    .map_err(|e| OAuth2Error::new("invalid_configuration", Some(&e.to_string())))?,
            )
            .set_redirect_uri(
                RedirectUrl::new(config.redirect_uri.clone())
                    .map_err(|e| OAuth2Error::new("invalid_configuration", Some(&e.to_string())))?,
            ))
    }

    pub fn get_microsoft_client(config: &ProviderConfig) -> Result<ConfiguredClient, OAuth2Error> {
        let tenant = config.tenant_id.as_deref().unwrap_or("common");
        Ok(BasicClient::new(ClientId::new(config.client_id.clone()))
            .set_client_secret(ClientSecret::new(config.client_secret.clone()))
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
                RedirectUrl::new(config.redirect_uri.clone())
                    .map_err(|e| OAuth2Error::new("invalid_configuration", Some(&e.to_string())))?,
            ))
    }

    pub fn get_github_client(config: &ProviderConfig) -> Result<ConfiguredClient, OAuth2Error> {
        Ok(BasicClient::new(ClientId::new(config.client_id.clone()))
            .set_client_secret(ClientSecret::new(config.client_secret.clone()))
            .set_auth_uri(
                AuthUrl::new("https://github.com/login/oauth/authorize".to_string())
                    .map_err(|e| OAuth2Error::new("invalid_configuration", Some(&e.to_string())))?,
            )
            .set_token_uri(
                TokenUrl::new("https://github.com/login/oauth/access_token".to_string())
                    .map_err(|e| OAuth2Error::new("invalid_configuration", Some(&e.to_string())))?,
            )
            .set_redirect_uri(
                RedirectUrl::new(config.redirect_uri.clone())
                    .map_err(|e| OAuth2Error::new("invalid_configuration", Some(&e.to_string())))?,
            ))
    }

    pub fn get_okta_client(config: &ProviderConfig) -> Result<ConfiguredClient, OAuth2Error> {
        let domain = config.domain.as_ref().ok_or_else(|| {
            OAuth2Error::new("invalid_configuration", Some("Okta domain is required"))
        })?;

        Ok(BasicClient::new(ClientId::new(config.client_id.clone()))
            .set_client_secret(ClientSecret::new(config.client_secret.clone()))
            .set_auth_uri(
                AuthUrl::new(format!("https://{}/oauth2/default/v1/authorize", domain))
                    .map_err(|e| OAuth2Error::new("invalid_configuration", Some(&e.to_string())))?,
            )
            .set_token_uri(
                TokenUrl::new(format!("https://{}/oauth2/default/v1/token", domain))
                    .map_err(|e| OAuth2Error::new("invalid_configuration", Some(&e.to_string())))?,
            )
            .set_redirect_uri(
                RedirectUrl::new(config.redirect_uri.clone())
                    .map_err(|e| OAuth2Error::new("invalid_configuration", Some(&e.to_string())))?,
            ))
    }

    pub fn get_auth0_client(config: &ProviderConfig) -> Result<ConfiguredClient, OAuth2Error> {
        let domain = config.domain.as_ref().ok_or_else(|| {
            OAuth2Error::new("invalid_configuration", Some("Auth0 domain is required"))
        })?;

        Ok(BasicClient::new(ClientId::new(config.client_id.clone()))
            .set_client_secret(ClientSecret::new(config.client_secret.clone()))
            .set_auth_uri(
                AuthUrl::new(format!("https://{}/authorize", domain))
                    .map_err(|e| OAuth2Error::new("invalid_configuration", Some(&e.to_string())))?,
            )
            .set_token_uri(
                TokenUrl::new(format!("https://{}/oauth/token", domain))
                    .map_err(|e| OAuth2Error::new("invalid_configuration", Some(&e.to_string())))?,
            )
            .set_redirect_uri(
                RedirectUrl::new(config.redirect_uri.clone())
                    .map_err(|e| OAuth2Error::new("invalid_configuration", Some(&e.to_string())))?,
            ))
    }

    pub async fn fetch_google_user_info(access_token: &str) -> Result<SocialUserInfo, OAuth2Error> {
        let client = reqwest::Client::new();
        let response = client
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

    pub async fn fetch_microsoft_user_info(
        access_token: &str,
    ) -> Result<SocialUserInfo, OAuth2Error> {
        let client = reqwest::Client::new();
        let response = client
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

    pub async fn fetch_github_user_info(access_token: &str) -> Result<SocialUserInfo, OAuth2Error> {
        let client = reqwest::Client::new();
        let response = client
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
            let email_response = client
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
