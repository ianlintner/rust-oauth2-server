#![allow(dead_code)]

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize)]
pub struct SocialLoginConfig {
    pub google: Option<ProviderConfig>,
    pub microsoft: Option<ProviderConfig>,
    pub github: Option<ProviderConfig>,
    pub azure: Option<ProviderConfig>,
    pub okta: Option<ProviderConfig>,
    pub auth0: Option<ProviderConfig>,
}

#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
pub struct ProviderConfig {
    #[serde(default)]
    pub enabled: bool,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub redirect_uri: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>, // For Azure/Microsoft
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>, // For Auth0/Okta
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SocialUserInfo {
    pub provider: String,
    pub provider_user_id: String,
    pub email: String,
    pub name: Option<String>,
    pub picture: Option<String>,
}

impl SocialLoginConfig {
    pub fn from_env() -> Self {
        Self {
            google: Self::provider_from_env("GOOGLE"),
            microsoft: Self::provider_from_env("MICROSOFT"),
            github: Self::provider_from_env("GITHUB"),
            azure: Self::provider_from_env("AZURE"),
            okta: Self::provider_from_env("OKTA"),
            auth0: Self::provider_from_env("AUTH0"),
        }
    }
    
    /// Create SocialLoginConfig from the main config's social section
    pub fn from_config_social(social: &crate::config::SocialConfig) -> Self {
        Self {
            google: social.google.clone().map(Self::convert_provider),
            microsoft: social.microsoft.clone().map(Self::convert_provider),
            github: social.github.clone().map(Self::convert_provider),
            azure: social.azure.clone().map(Self::convert_provider),
            okta: social.okta.clone().map(Self::convert_provider),
            auth0: social.auth0.clone().map(Self::convert_provider),
        }
    }
    
    fn convert_provider(p: crate::config::ProviderConfig) -> ProviderConfig {
        ProviderConfig {
            enabled: p.enabled,
            client_id: p.client_id,
            client_secret: p.client_secret,
            redirect_uri: p.redirect_uri,
            tenant_id: p.tenant_id,
            domain: p.domain,
        }
    }

    fn provider_from_env(prefix: &str) -> Option<ProviderConfig> {
        let client_id = std::env::var(format!("OAUTH2_{}_CLIENT_ID", prefix)).ok();
        let client_secret = std::env::var(format!("OAUTH2_{}_CLIENT_SECRET", prefix)).ok();
        
        // Only create config if both client_id and client_secret are set
        if client_id.is_some() && client_secret.is_some() {
            let redirect_uri = std::env::var(format!("OAUTH2_{}_REDIRECT_URI", prefix))
                .ok()
                .or_else(|| {
                    Some(format!(
                        "http://localhost:8080/auth/callback/{}",
                        prefix.to_lowercase()
                    ))
                });

            Some(ProviderConfig {
                enabled: true,
                client_id,
                client_secret,
                redirect_uri,
                tenant_id: std::env::var(format!("OAUTH2_{}_TENANT_ID", prefix)).ok(),
                domain: std::env::var(format!("OAUTH2_{}_DOMAIN", prefix)).ok(),
            })
        } else {
            None
        }
    }
}
