use actix_session::Session;
use actix_web::{web, HttpResponse, Result};
use serde::Deserialize;
use serde_json::json;
use url::Url;

use oauth2_core::OAuth2Error;
use oauth2_ports::DynStorage;

use crate::handlers::wellknown::OidcConfig;

#[derive(Debug, Deserialize)]
pub struct LogoutQuery {
    pub id_token_hint: Option<String>,
    pub post_logout_redirect_uri: Option<String>,
    pub state: Option<String>,
}

fn validate_post_logout_redirect_uri_shape(uri: &str) -> Result<Url, OAuth2Error> {
    let parsed = Url::parse(uri)
        .map_err(|_| OAuth2Error::invalid_request("Invalid post_logout_redirect_uri"))?;

    match parsed.scheme() {
        "http" | "https" => {}
        _ => {
            return Err(OAuth2Error::invalid_request(
                "post_logout_redirect_uri must use http or https",
            ));
        }
    }

    if parsed.fragment().is_some() {
        return Err(OAuth2Error::invalid_request(
            "post_logout_redirect_uri must not contain a fragment",
        ));
    }

    Ok(parsed)
}

async fn is_registered_post_logout_redirect(
    storage: &DynStorage,
    candidate: &str,
) -> Result<bool, OAuth2Error> {
    let clients = storage.list_all_clients().await?;
    Ok(clients.iter().any(|client| {
        client
            .get_redirect_uris()
            .iter()
            .any(|uri| uri == candidate)
    }))
}

/// Extract audiences from a JWT `aud` claim, handling both string and array forms.
fn extract_audiences(claims: &serde_json::Value) -> Vec<String> {
    match claims.get("aud") {
        Some(serde_json::Value::String(aud)) => vec![aud.clone()],
        Some(serde_json::Value::Array(auds)) => auds
            .iter()
            .filter_map(|v| v.as_str().map(|s| s.to_string()))
            .collect(),
        _ => Vec::new(),
    }
}

/// OIDC RP-Initiated Logout endpoint.
///
/// Current behavior:
/// - Always terminates the local user session.
/// - If `id_token_hint` is present, validate it with signature verification,
///   verify `aud` matches a registered client, and revoke tokens for the `sub` user.
/// - Optionally redirects to a registered `post_logout_redirect_uri`.
/// - Preserves `state` by appending it as a query parameter to the redirect URI.
pub async fn logout(
    query: web::Query<LogoutQuery>,
    session: Session,
    storage: web::Data<DynStorage>,
    oidc: web::Data<OidcConfig>,
) -> Result<HttpResponse, OAuth2Error> {
    // If id_token_hint is provided, validate and extract claims.
    if let Some(ref id_token_hint) = query.id_token_hint {
        // Validate the id_token_hint with signature verification.
        let mut validation = jsonwebtoken::Validation::default();
        // ID tokens use the issuer as audience in some flows, and client_id
        // in others; we verify aud against registered clients below instead.
        validation.validate_aud = false;
        validation.set_issuer(&[&oidc.issuer]);

        let decoding_key = jsonwebtoken::DecodingKey::from_secret(oidc.jwt_secret.as_bytes());
        let token_result =
            jsonwebtoken::decode::<serde_json::Value>(id_token_hint, &decoding_key, &validation);

        if let Ok(token_data) = token_result {
            // Verify aud matches a registered client (handles string or array).
            let audiences = extract_audiences(&serde_json::Value::Object(
                token_data.claims.as_object().cloned().unwrap_or_default(),
            ));

            if !audiences.is_empty() {
                let mut has_registered_audience = false;
                for aud in &audiences {
                    if storage.get_client(aud).await?.is_some() {
                        has_registered_audience = true;
                        break;
                    }
                }
                if !has_registered_audience {
                    return Err(OAuth2Error::invalid_request(
                        "id_token_hint audience does not match a registered client",
                    ));
                }
            }

            // Use sub to revoke all tokens for the user via targeted storage operation.
            if let Some(sub) = token_data.claims.get("sub").and_then(|v| v.as_str()) {
                let _ = storage.revoke_tokens_by_user_id(sub).await;
            }
        }
        // If validation fails, we still purge the session (best-effort).
    }

    // Invalidate local session.
    session.purge();

    if let Some(post_logout_redirect_uri) = query.post_logout_redirect_uri.as_deref() {
        let mut parsed = validate_post_logout_redirect_uri_shape(post_logout_redirect_uri)?;

        let is_registered =
            is_registered_post_logout_redirect(storage.get_ref(), post_logout_redirect_uri).await?;

        if !is_registered {
            return Err(OAuth2Error::invalid_request(
                "Unregistered post_logout_redirect_uri",
            ));
        }

        if let Some(state) = query.state.as_deref() {
            parsed.query_pairs_mut().append_pair("state", state);
        }

        return Ok(HttpResponse::Found()
            .append_header(("Location", parsed.to_string()))
            .finish());
    }

    Ok(HttpResponse::Ok().json(json!({ "status": "logged_out" })))
}
