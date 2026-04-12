use actix_session::Session;
use actix_web::{web, HttpResponse, Result};
use serde::Deserialize;
use serde_json::json;
use url::Url;

use oauth2_core::OAuth2Error;
use oauth2_ports::DynStorage;

use crate::actors::{RevokeToken, TokenActorPool};
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

/// OIDC RP-Initiated Logout endpoint.
///
/// Current behavior:
/// - Always terminates the local user session.
/// - If `id_token_hint` is present, decode it (without full signature verification),
///   verify `aud` matches a registered client, and revoke tokens for the `sub` user.
/// - Optionally redirects to a registered `post_logout_redirect_uri`.
/// - Preserves `state` by appending it as a query parameter to the redirect URI.
pub async fn logout(
    query: web::Query<LogoutQuery>,
    session: Session,
    storage: web::Data<DynStorage>,
    _oidc: web::Data<OidcConfig>,
    token_actor: web::Data<TokenActorPool>,
) -> Result<HttpResponse, OAuth2Error> {
    // If id_token_hint is provided, validate and extract claims.
    if let Some(ref id_token_hint) = query.id_token_hint {
        // Decode without signature verification — we only need sub/aud.
        if let Ok(token_data) =
            jsonwebtoken::dangerous::insecure_decode::<serde_json::Value>(id_token_hint)
        {
            // Verify aud matches a registered client.
            let aud = token_data
                .claims
                .get("aud")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());

            if let Some(ref aud) = aud {
                let client = storage.get_client(aud).await?;
                if client.is_none() {
                    return Err(OAuth2Error::invalid_request(
                        "id_token_hint audience does not match a registered client",
                    ));
                }
            }

            // Use sub to revoke all tokens for the user.
            if let Some(sub) = token_data.claims.get("sub").and_then(|v| v.as_str()) {
                // Revoke all tokens owned by this user by iterating stored tokens.
                let all_tokens = storage.list_all_tokens().await?;
                for t in all_tokens {
                    if t.user_id.as_deref() == Some(sub) && !t.revoked {
                        let _ = token_actor
                            .route(&t.access_token)
                            .send(RevokeToken {
                                token: t.access_token.clone(),
                                span: tracing::Span::current(),
                            })
                            .await;
                    }
                }
            }
        }
        // If decoding fails, we still purge the session (best-effort).
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
