use actix::Addr;
use actix_web::{web, HttpRequest, HttpResponse, Result};

use crate::actors::{ClientActor, DeleteClient, GetClient, RegisterClient, UpdateClient};
use oauth2_core::{ClientCredentials, ClientRegistration, ClientRegistrationResponse, OAuth2Error};

use crate::handlers::wellknown::OidcConfig;

fn validate_redirect_uri(uri: &str) -> Result<(), OAuth2Error> {
    let uri = uri.trim();
    if uri.is_empty() {
        return Err(OAuth2Error::invalid_request(
            "redirect_uri must not be empty",
        ));
    }

    // OAuth 2.0 requires redirection URIs to be absolute and MUST NOT include fragments.
    // Keep this validation intentionally simple and conservative.
    if uri.contains('#') {
        return Err(OAuth2Error::invalid_request(
            "redirect_uri must not contain a fragment",
        ));
    }
    if uri.contains('\r') || uri.contains('\n') {
        return Err(OAuth2Error::invalid_request(
            "redirect_uri contains invalid characters",
        ));
    }

    let lower = uri.to_ascii_lowercase();
    if lower.starts_with("javascript:") || lower.starts_with("data:") {
        return Err(OAuth2Error::invalid_request(
            "redirect_uri uses a disallowed URI scheme",
        ));
    }

    // Minimal absolute-URI check.
    if !uri.contains("://") {
        return Err(OAuth2Error::invalid_request(
            "redirect_uri must be an absolute URI",
        ));
    }

    Ok(())
}

fn validate_grant_types(grant_types: &[String]) -> Result<(), OAuth2Error> {
    // Keep registration honest: only allow grant types that the server actually supports.
    // (prevents clients from registering for unsupported grants like implicit).
    const SUPPORTED: [&str; 4] = [
        "authorization_code",
        "client_credentials",
        "refresh_token",
        "urn:ietf:params:oauth:grant-type:device_code",
    ];

    if grant_types.is_empty() {
        return Err(OAuth2Error::invalid_request(
            "grant_types must not be empty",
        ));
    }

    for gt in grant_types {
        if !SUPPORTED.contains(&gt.as_str()) {
            return Err(OAuth2Error::invalid_request(
                "unsupported or disabled grant_type in registration",
            ));
        }
    }

    Ok(())
}

/// Supported `token_endpoint_auth_method` values.
const SUPPORTED_AUTH_METHODS: [&str; 5] = [
    "client_secret_basic",
    "client_secret_post",
    "client_secret_jwt",
    "private_key_jwt",
    "none",
];

fn validate_token_endpoint_auth_method(
    method: &str,
    grant_types: &[String],
) -> Result<(), OAuth2Error> {
    if !SUPPORTED_AUTH_METHODS.contains(&method) {
        return Err(OAuth2Error::invalid_request(
            "unsupported token_endpoint_auth_method",
        ));
    }
    // Public clients (`none`) may only use authorization_code (with PKCE).
    if method == "none" {
        let non_pkce: Vec<&str> = grant_types
            .iter()
            .filter(|g| g.as_str() != "authorization_code" && g.as_str() != "refresh_token")
            .map(String::as_str)
            .collect();
        if !non_pkce.is_empty() {
            return Err(OAuth2Error::invalid_request(
                "public clients (token_endpoint_auth_method=none) \
                 may only use authorization_code and refresh_token",
            ));
        }
    }
    // private_key_jwt requires jwks or jwks_uri — validated at a higher level
    Ok(())
}

/// Common validation for a `ClientRegistration`, shared between the admin
/// endpoint and the RFC 7591 public endpoint.
fn validate_registration(reg: &ClientRegistration) -> Result<(), OAuth2Error> {
    // Default grant_types when empty (RFC 7591 §2 default: authorization_code)
    let grant_types = if reg.grant_types.is_empty() {
        vec!["authorization_code".to_string()]
    } else {
        reg.grant_types.clone()
    };
    validate_grant_types(&grant_types)?;
    validate_token_endpoint_auth_method(&reg.token_endpoint_auth_method, &grant_types)?;

    if reg.redirect_uris.is_empty() {
        return Err(OAuth2Error::invalid_request(
            "redirect_uris must not be empty",
        ));
    }
    for uri in &reg.redirect_uris {
        validate_redirect_uri(uri)?;
    }

    // private_key_jwt requires a JWKS or JWKS URI
    if reg.token_endpoint_auth_method == "private_key_jwt"
        && reg.jwks.is_none()
        && reg.jwks_uri.as_deref().is_none_or(str::is_empty)
    {
        return Err(OAuth2Error::invalid_request(
            "private_key_jwt requires jwks or jwks_uri",
        ));
    }

    // jwks and jwks_uri are mutually exclusive (RFC 7591 §2)
    if reg.jwks.is_some() && reg.jwks_uri.as_deref().is_some_and(|u| !u.is_empty()) {
        return Err(OAuth2Error::invalid_request(
            "jwks and jwks_uri are mutually exclusive",
        ));
    }

    Ok(())
}

/// Normalise a `ClientRegistration`, filling in RFC 7591 defaults.
fn normalise_registration(reg: &mut ClientRegistration) {
    if reg.grant_types.is_empty() {
        reg.grant_types = vec!["authorization_code".to_string()];
    }
    if reg.response_types.is_empty() {
        reg.response_types = vec!["code".to_string()];
    }
    if reg.scope.trim().is_empty() {
        reg.scope = "openid".to_string();
    }
}

// ---------------------------------------------------------------------------
// Admin registration endpoint (legacy, unchanged API contract)
// ---------------------------------------------------------------------------

/// Register a new OAuth2 client (admin endpoint — `POST /admin/clients/register`).
pub async fn register_client(
    registration: web::Json<ClientRegistration>,
    client_actor: web::Data<Addr<ClientActor>>,
) -> Result<HttpResponse, OAuth2Error> {
    let reg: &ClientRegistration = &registration;
    validate_grant_types(&reg.grant_types)?;
    validate_token_endpoint_auth_method(&reg.token_endpoint_auth_method, &reg.grant_types)?;

    if reg.redirect_uris.is_empty() {
        return Err(OAuth2Error::invalid_request(
            "redirect_uris must not be empty",
        ));
    }
    for uri in &reg.redirect_uris {
        validate_redirect_uri(uri)?;
    }

    if reg.scope.trim().is_empty() {
        return Err(OAuth2Error::invalid_request("scope must not be empty"));
    }

    let client = client_actor
        .send(RegisterClient {
            registration: registration.into_inner(),
            span: tracing::Span::current(),
        })
        .await
        .map_err(|e| OAuth2Error::new("server_error", Some(&e.to_string())))??;

    let credentials = ClientCredentials {
        client_id: client.client_id,
        client_secret: client.client_secret,
    };

    Ok(HttpResponse::Created().json(credentials))
}

// ---------------------------------------------------------------------------
// RFC 7591 Dynamic Client Registration
// ---------------------------------------------------------------------------

/// `POST /connect/register` — RFC 7591 §3.1 client registration.
pub async fn dynamic_register(
    mut registration: web::Json<ClientRegistration>,
    client_actor: web::Data<Addr<ClientActor>>,
    oidc_config: web::Data<OidcConfig>,
) -> Result<HttpResponse, OAuth2Error> {
    normalise_registration(&mut registration);
    validate_registration(&registration)?;

    let client = client_actor
        .send(RegisterClient {
            registration: registration.into_inner(),
            span: tracing::Span::current(),
        })
        .await
        .map_err(|e| OAuth2Error::new("server_error", Some(&e.to_string())))??;

    let resp = ClientRegistrationResponse::from_client(&client, &oidc_config.issuer);
    Ok(HttpResponse::Created().json(resp))
}

// ---------------------------------------------------------------------------
// RFC 7592 Client Configuration Endpoint (read / update / delete)
// ---------------------------------------------------------------------------

/// Extract and validate the `Bearer <registration_access_token>` from
/// the request, returning the `Client` it belongs to.
async fn authenticate_registration_token(
    req: &HttpRequest,
    client_id: &str,
    client_actor: &Addr<ClientActor>,
) -> Result<oauth2_core::Client, OAuth2Error> {
    let token = req
        .headers()
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| OAuth2Error::invalid_client("Missing registration_access_token"))?;

    let client = client_actor
        .send(GetClient {
            client_id: client_id.to_string(),
            span: tracing::Span::current(),
        })
        .await
        .map_err(|e| OAuth2Error::new("server_error", Some(&e.to_string())))??;

    if client.registration_access_token.is_empty() {
        return Err(OAuth2Error::invalid_client(
            "Client has no registration_access_token",
        ));
    }

    // Constant-time comparison
    use subtle::ConstantTimeEq;
    let matches: bool = client
        .registration_access_token
        .as_bytes()
        .ct_eq(token.as_bytes())
        .into();
    if !matches {
        return Err(OAuth2Error::invalid_client(
            "Invalid registration_access_token",
        ));
    }

    Ok(client)
}

/// `GET /connect/register/{client_id}` — RFC 7592 §2.1 read client configuration.
pub async fn read_client_configuration(
    req: HttpRequest,
    path: web::Path<String>,
    client_actor: web::Data<Addr<ClientActor>>,
    oidc_config: web::Data<OidcConfig>,
) -> Result<HttpResponse, OAuth2Error> {
    let client_id = path.into_inner();
    let client = authenticate_registration_token(&req, &client_id, &client_actor).await?;

    let resp = ClientRegistrationResponse::from_client(&client, &oidc_config.issuer);
    Ok(HttpResponse::Ok().json(resp))
}

/// `PUT /connect/register/{client_id}` — RFC 7592 §2.2 update client.
pub async fn update_client_configuration(
    req: HttpRequest,
    path: web::Path<String>,
    mut body: web::Json<ClientRegistration>,
    client_actor: web::Data<Addr<ClientActor>>,
    oidc_config: web::Data<OidcConfig>,
) -> Result<HttpResponse, OAuth2Error> {
    let client_id = path.into_inner();
    let mut client = authenticate_registration_token(&req, &client_id, &client_actor).await?;

    normalise_registration(&mut body);
    validate_registration(&body)?;

    // Apply updated fields
    client.name = body.client_name.clone();
    client.redirect_uris = serde_json::to_string(&body.redirect_uris).unwrap_or_default();
    client.grant_types = serde_json::to_string(&body.grant_types).unwrap_or_default();
    client.scope = body.scope.clone();
    client.token_endpoint_auth_method = body.token_endpoint_auth_method.clone();
    client.response_types = serde_json::to_string(&body.response_types).unwrap_or_default();
    client.contacts = serde_json::to_string(&body.contacts).unwrap_or_default();
    client.logo_uri = body.logo_uri.clone().unwrap_or_default();
    client.client_uri = body.client_uri.clone().unwrap_or_default();
    client.policy_uri = body.policy_uri.clone().unwrap_or_default();
    client.tos_uri = body.tos_uri.clone().unwrap_or_default();
    client.jwks = body
        .jwks
        .as_ref()
        .map(|v| serde_json::to_string(v).unwrap_or_default())
        .unwrap_or_default();
    client.jwks_uri = body.jwks_uri.clone().unwrap_or_default();
    client.updated_at = chrono::Utc::now();

    let updated = client_actor
        .send(UpdateClient {
            client,
            span: tracing::Span::current(),
        })
        .await
        .map_err(|e| OAuth2Error::new("server_error", Some(&e.to_string())))??;

    let resp = ClientRegistrationResponse::from_client(&updated, &oidc_config.issuer);
    Ok(HttpResponse::Ok().json(resp))
}

/// `DELETE /connect/register/{client_id}` — RFC 7592 §2.3 delete client.
pub async fn delete_client_configuration(
    req: HttpRequest,
    path: web::Path<String>,
    client_actor: web::Data<Addr<ClientActor>>,
) -> Result<HttpResponse, OAuth2Error> {
    let client_id = path.into_inner();
    let _client = authenticate_registration_token(&req, &client_id, &client_actor).await?;

    client_actor
        .send(DeleteClient {
            client_id,
            span: tracing::Span::current(),
        })
        .await
        .map_err(|e| OAuth2Error::new("server_error", Some(&e.to_string())))??;

    Ok(HttpResponse::NoContent().finish())
}
