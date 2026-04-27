#![allow(dead_code)]

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[cfg(feature = "openapi")]
use utoipa::ToSchema;

fn default_token_endpoint_auth_method() -> String {
    "client_secret_basic".to_string()
}

fn default_empty_string() -> String {
    String::new()
}

#[cfg_attr(feature = "sqlx", derive(sqlx::FromRow))]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Client {
    pub id: String,
    pub client_id: String,
    #[cfg_attr(feature = "openapi", schema(write_only))]
    pub client_secret: String,
    pub redirect_uris: String, // JSON array stored as string
    pub grant_types: String,   // JSON array stored as string
    pub scope: String,
    pub name: String,
    #[serde(deserialize_with = "crate::chrono_serde::deserialize")]
    pub created_at: DateTime<Utc>,
    #[serde(deserialize_with = "crate::chrono_serde::deserialize")]
    pub updated_at: DateTime<Utc>,
    /// RFC 7591 §2: client authentication method for the token endpoint.
    /// Supported: `"client_secret_basic"` (default), `"client_secret_post"`,
    /// `"client_secret_jwt"`, `"private_key_jwt"`, or `"none"` (public client).
    #[serde(default = "default_token_endpoint_auth_method")]
    pub token_endpoint_auth_method: String,
    /// RFC 7591 §3.2.1: token used to access the client configuration endpoint.
    #[serde(default = "default_empty_string")]
    pub registration_access_token: String,
    /// RFC 7591 §2: response types the client may use. JSON array stored as string.
    #[serde(default = "default_empty_string")]
    pub response_types: String,
    /// RFC 7591 §2: contacts (email addresses). JSON array stored as string.
    #[serde(default = "default_empty_string")]
    pub contacts: String,
    /// RFC 7591 §2: URL of the client's logo.
    #[serde(default = "default_empty_string")]
    pub logo_uri: String,
    /// RFC 7591 §2: URL of the client's home page.
    #[serde(default = "default_empty_string")]
    pub client_uri: String,
    /// RFC 7591 §2: URL of the client's privacy policy.
    #[serde(default = "default_empty_string")]
    pub policy_uri: String,
    /// RFC 7591 §2: URL of the client's terms of service.
    #[serde(default = "default_empty_string")]
    pub tos_uri: String,
    /// RFC 7523 §2.2: client's JWKS document (inline JSON). Used for
    /// `private_key_jwt` authentication; `client_secret_jwt` uses the
    /// shared `client_secret` instead.
    #[serde(default = "default_empty_string")]
    pub jwks: String,
    /// RFC 7523 §2.2: URL referencing the client's JWKS.
    #[serde(default = "default_empty_string")]
    pub jwks_uri: String,
    /// OIDC Back-Channel Logout §2.1: URL to receive logout tokens via HTTP POST.
    #[serde(default = "default_empty_string")]
    pub backchannel_logout_uri: String,
    /// OIDC Back-Channel Logout §2.1: whether `sid` is required in logout tokens.
    #[serde(default)]
    pub backchannel_logout_session_required: bool,
    /// OIDC Front-Channel Logout §2: URL rendered in an iframe during logout.
    #[serde(default = "default_empty_string")]
    pub frontchannel_logout_uri: String,
    /// OIDC Front-Channel Logout §2: whether `sid` is included in the iframe URL.
    #[serde(default)]
    pub frontchannel_logout_session_required: bool,
    /// OIDC RP-Initiated Logout §2: registered post-logout redirect URIs (JSON array).
    #[serde(default = "default_empty_string")]
    pub post_logout_redirect_uris: String,
    /// Admin soft-disable flag. Disabled clients are rejected at authorization
    /// and token endpoints. Defaults to `true` so existing code paths remain
    /// unaffected.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// RFC 9700 §4.7: when `true`, the AS rejects authorization requests that
    /// omit the `state` parameter. Defense-in-depth for CSRF on the redirect
    /// path that PKCE already covers. Defaults to `false` so existing clients
    /// continue to work; operators opt in per-client.
    #[serde(default)]
    #[cfg_attr(feature = "sqlx", sqlx(default))]
    pub require_state: bool,
    /// RFC 8705 §2.1.2: Subject DN of the expected TLS client certificate.
    /// Used when `token_endpoint_auth_method = "tls_client_auth"`.
    /// Empty string means no DN restriction (any valid cert thumbprint accepted).
    #[serde(default = "default_empty_string")]
    #[cfg_attr(feature = "sqlx", sqlx(default))]
    pub tls_client_certificate_subject_dn: String,
}

fn default_true() -> bool {
    true
}

impl Client {
    pub fn new(
        client_id: String,
        client_secret: String,
        redirect_uris: Vec<String>,
        grant_types: Vec<String>,
        scope: String,
        name: String,
    ) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4().to_string(),
            client_id,
            client_secret,
            redirect_uris: serde_json::to_string(&redirect_uris)
                .unwrap_or_else(|_| "[]".to_string()),
            grant_types: serde_json::to_string(&grant_types).unwrap_or_else(|_| "[]".to_string()),
            scope,
            name,
            created_at: now,
            updated_at: now,
            token_endpoint_auth_method: default_token_endpoint_auth_method(),
            registration_access_token: String::new(),
            response_types: serde_json::to_string(&["code"]).unwrap_or_else(|_| "[]".to_string()),
            contacts: String::new(),
            logo_uri: String::new(),
            client_uri: String::new(),
            policy_uri: String::new(),
            tos_uri: String::new(),
            jwks: String::new(),
            jwks_uri: String::new(),
            backchannel_logout_uri: String::new(),
            backchannel_logout_session_required: false,
            frontchannel_logout_uri: String::new(),
            frontchannel_logout_session_required: false,
            post_logout_redirect_uris: String::new(),
            enabled: true,
            require_state: false,
            tls_client_certificate_subject_dn: String::new(),
        }
    }

    /// Returns `true` for public clients that use PKCE without a client secret.
    pub fn is_public(&self) -> bool {
        self.token_endpoint_auth_method == "none"
    }

    /// Returns `true` for clients using JWT-based authentication.
    pub fn uses_jwt_auth(&self) -> bool {
        self.token_endpoint_auth_method == "private_key_jwt"
            || self.token_endpoint_auth_method == "client_secret_jwt"
    }

    pub fn get_redirect_uris(&self) -> Vec<String> {
        serde_json::from_str(&self.redirect_uris).unwrap_or_default()
    }

    pub fn get_grant_types(&self) -> Vec<String> {
        serde_json::from_str(&self.grant_types).unwrap_or_default()
    }

    pub fn get_response_types(&self) -> Vec<String> {
        serde_json::from_str(&self.response_types).unwrap_or_default()
    }

    pub fn get_contacts(&self) -> Vec<String> {
        serde_json::from_str(&self.contacts).unwrap_or_default()
    }

    pub fn get_post_logout_redirect_uris(&self) -> Vec<String> {
        serde_json::from_str(&self.post_logout_redirect_uris).unwrap_or_default()
    }

    pub fn supports_grant_type(&self, grant_type: &str) -> bool {
        self.get_grant_types().contains(&grant_type.to_string())
    }

    pub fn validate_redirect_uri(&self, redirect_uri: &str) -> bool {
        let registered = self.get_redirect_uris();
        // Fast path: exact match. A client that literally registered
        // `http://localhost:3000/callback` may still use that exact URI —
        // only the port-wildcard loopback exception below is tightened.
        if registered.contains(&redirect_uri.to_string()) {
            return true;
        }
        // RFC 8252 §7.3: loopback redirect URIs — the AS accepts any port
        // on the loopback host at request time, even if the client
        // registered a different (or zero) port.
        //
        // RFC 8252 §8.3 requires the IP literal representation
        // (`127.0.0.1` or `[::1]`); the `localhost` hostname is
        // non-deterministic (Windows `hosts` overrides, split-horizon
        // DNS, IPv4/IPv6 resolution) and MUST NOT benefit from the
        // port-wildcard exception. Registering a `localhost` loopback
        // URI still works via the exact-match fast path above — what
        // this check tightens is "registered `127.0.0.1:3000` →
        // requested `127.0.0.1:54321` accepted" vs "registered
        // `localhost:3000` → requested `localhost:54321` accepted".
        if let Ok(requested) = redirect_uri.parse::<url::Url>() {
            let host_is_ip_loopback = matches!(
                requested.host_str(),
                Some("127.0.0.1") | Some("::1") | Some("[::1]")
            );
            if host_is_ip_loopback && matches!(requested.scheme(), "http" | "https") {
                for reg in &registered {
                    if let Ok(reg_url) = reg.parse::<url::Url>() {
                        let reg_ip_loopback = matches!(
                            reg_url.host_str(),
                            Some("127.0.0.1") | Some("::1") | Some("[::1]")
                        );
                        if reg_ip_loopback
                            && reg_url.scheme() == requested.scheme()
                            && reg_url.host_str() == requested.host_str()
                            && reg_url.path() == requested.path()
                        {
                            return true;
                        }
                    }
                }
            }
        }
        false
    }
}

/// RFC 7591 §2: Client registration request metadata.
///
/// Used for both the admin endpoint and the standards-compliant
/// `POST /connect/register` endpoint.
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[derive(Debug, Serialize, Deserialize)]
pub struct ClientRegistration {
    pub client_name: String,
    pub redirect_uris: Vec<String>,
    #[serde(default)]
    pub grant_types: Vec<String>,
    #[serde(default)]
    pub scope: String,
    /// `"client_secret_basic"` (default), `"client_secret_post"`,
    /// `"client_secret_jwt"`, `"private_key_jwt"`, or `"none"`.
    #[serde(default = "default_token_endpoint_auth_method")]
    pub token_endpoint_auth_method: String,
    /// RFC 7591 §2: response types the client may use.
    #[serde(default)]
    pub response_types: Vec<String>,
    /// RFC 7591 §2: contact email addresses.
    #[serde(default)]
    pub contacts: Vec<String>,
    /// RFC 7591 §2: URL of the client's logo.
    #[serde(default)]
    pub logo_uri: Option<String>,
    /// RFC 7591 §2: URL of the client's home page.
    #[serde(default)]
    pub client_uri: Option<String>,
    /// RFC 7591 §2: URL of the client's privacy policy.
    #[serde(default)]
    pub policy_uri: Option<String>,
    /// RFC 7591 §2: URL of the client's terms of service.
    #[serde(default)]
    pub tos_uri: Option<String>,
    /// RFC 7523 §2.2: client's JWKS document (inline).
    #[serde(default)]
    pub jwks: Option<serde_json::Value>,
    /// RFC 7523 §2.2: URL referencing the client's JWKS.
    #[serde(default)]
    pub jwks_uri: Option<String>,
    /// OIDC Back-Channel Logout §2.1: URL to receive logout tokens.
    #[serde(default)]
    pub backchannel_logout_uri: Option<String>,
    /// OIDC Back-Channel Logout §2.1: whether `sid` is required in the logout token.
    #[serde(default)]
    pub backchannel_logout_session_required: Option<bool>,
    /// OIDC Front-Channel Logout §2: URL rendered in an iframe during logout.
    #[serde(default)]
    pub frontchannel_logout_uri: Option<String>,
    /// OIDC Front-Channel Logout §2: whether `sid` is included in the iframe URL.
    #[serde(default)]
    pub frontchannel_logout_session_required: Option<bool>,
    /// OIDC RP-Initiated Logout §2: registered post-logout redirect URIs.
    #[serde(default)]
    pub post_logout_redirect_uris: Option<Vec<String>>,
    /// RFC 8705 §2.1.2: Subject DN of the expected TLS client certificate.
    /// Only relevant when `token_endpoint_auth_method = "tls_client_auth"`.
    #[serde(default)]
    pub tls_client_certificate_subject_dn: Option<String>,
}

#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[derive(Debug, Serialize, Deserialize)]
pub struct ClientCredentials {
    pub client_id: String,
    pub client_secret: String,
}

/// RFC 7591 §3.2.1: Client Information Response returned after successful
/// dynamic registration. Includes all registered metadata plus server-assigned
/// values like `client_id`, `client_secret`, and `registration_access_token`.
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[derive(Debug, Serialize, Deserialize)]
pub struct ClientRegistrationResponse {
    pub client_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_secret: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_secret_expires_at: Option<i64>,
    pub registration_access_token: String,
    pub registration_client_uri: String,
    pub client_name: String,
    pub redirect_uris: Vec<String>,
    pub grant_types: Vec<String>,
    pub scope: String,
    pub token_endpoint_auth_method: String,
    pub response_types: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub contacts: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logo_uri: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_uri: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_uri: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tos_uri: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwks: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwks_uri: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backchannel_logout_uri: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backchannel_logout_session_required: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub frontchannel_logout_uri: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub frontchannel_logout_session_required: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub post_logout_redirect_uris: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_client_certificate_subject_dn: Option<String>,
    pub client_id_issued_at: i64,
}

impl ClientRegistrationResponse {
    /// Build a registration response from a `Client` and the server's issuer base URL.
    pub fn from_client(client: &Client, issuer_base: &str) -> Self {
        let base = issuer_base.trim_end_matches('/');
        let client_secret = if client.is_public() {
            None
        } else {
            Some(client.client_secret.clone())
        };
        Self {
            client_id: client.client_id.clone(),
            client_secret_expires_at: client_secret.as_ref().map(|_| 0), // 0 = never expires
            client_secret,
            registration_access_token: client.registration_access_token.clone(),
            registration_client_uri: format!("{}/connect/register/{}", base, client.client_id),
            client_name: client.name.clone(),
            redirect_uris: client.get_redirect_uris(),
            grant_types: client.get_grant_types(),
            scope: client.scope.clone(),
            token_endpoint_auth_method: client.token_endpoint_auth_method.clone(),
            response_types: client.get_response_types(),
            contacts: client.get_contacts(),
            logo_uri: if client.logo_uri.is_empty() {
                None
            } else {
                Some(client.logo_uri.clone())
            },
            client_uri: if client.client_uri.is_empty() {
                None
            } else {
                Some(client.client_uri.clone())
            },
            policy_uri: if client.policy_uri.is_empty() {
                None
            } else {
                Some(client.policy_uri.clone())
            },
            tos_uri: if client.tos_uri.is_empty() {
                None
            } else {
                Some(client.tos_uri.clone())
            },
            jwks: if client.jwks.is_empty() {
                None
            } else {
                serde_json::from_str(&client.jwks).ok()
            },
            jwks_uri: if client.jwks_uri.is_empty() {
                None
            } else {
                Some(client.jwks_uri.clone())
            },
            backchannel_logout_uri: if client.backchannel_logout_uri.is_empty() {
                None
            } else {
                Some(client.backchannel_logout_uri.clone())
            },
            backchannel_logout_session_required: if client.backchannel_logout_session_required {
                Some(true)
            } else {
                None
            },
            frontchannel_logout_uri: if client.frontchannel_logout_uri.is_empty() {
                None
            } else {
                Some(client.frontchannel_logout_uri.clone())
            },
            frontchannel_logout_session_required: if client.frontchannel_logout_session_required {
                Some(true)
            } else {
                None
            },
            post_logout_redirect_uris: {
                let uris = client.get_post_logout_redirect_uris();
                if uris.is_empty() {
                    None
                } else {
                    Some(uris)
                }
            },
            tls_client_certificate_subject_dn: if client
                .tls_client_certificate_subject_dn
                .is_empty()
            {
                None
            } else {
                Some(client.tls_client_certificate_subject_dn.clone())
            },
            client_id_issued_at: client.created_at.timestamp(),
        }
    }
}
