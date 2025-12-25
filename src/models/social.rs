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
    pub client_id: String,
    pub client_secret: String,
    pub redirect_uri: String,
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

    fn provider_from_env(prefix: &str) -> Option<ProviderConfig> {
        let client_id = std::env::var(format!("OAUTH2_{}_CLIENT_ID", prefix)).ok()?;
        let client_secret = std::env::var(format!("OAUTH2_{}_CLIENT_SECRET", prefix)).ok()?;
        let redirect_uri =
            std::env::var(format!("OAUTH2_{}_REDIRECT_URI", prefix)).unwrap_or_else(|_| {
                format!(
                    "http://localhost:8080/auth/callback/{}",
                    prefix.to_lowercase()
                )
            });

        Some(ProviderConfig {
            client_id,
            client_secret,
            redirect_uri,
            tenant_id: std::env::var(format!("OAUTH2_{}_TENANT_ID", prefix)).ok(),
            domain: std::env::var(format!("OAUTH2_{}_DOMAIN", prefix)).ok(),
        })
    }
}
