use actix::Addr;
use actix_web::{web, HttpResponse, Result};

use crate::actors::{ClientActor, RegisterClient};
use oauth2_core::{ClientCredentials, ClientRegistration, OAuth2Error};

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
    // (prevents clients from registering for 'implicit' / 'refresh_token' etc.)
    const SUPPORTED: [&str; 3] = ["authorization_code", "client_credentials", "password"];

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

/// Register a new OAuth2 client
pub async fn register_client(
    registration: web::Json<ClientRegistration>,
    client_actor: web::Data<Addr<ClientActor>>,
) -> Result<HttpResponse, OAuth2Error> {
    // Validate registration input early (OWASP OAuth guidance: strict redirect URI handling).
    let reg: &ClientRegistration = &registration;
    validate_grant_types(&reg.grant_types)?;

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
