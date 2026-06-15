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
    /// Session ID from the OP session — used for back-channel/front-channel logout.
    pub sid: Option<String>,
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

/// Check whether `candidate` is a registered `post_logout_redirect_uri` for any client.
/// Also falls back to checking `redirect_uris` for backwards compatibility.
async fn is_registered_post_logout_redirect(
    storage: &DynStorage,
    candidate: &str,
) -> Result<bool, OAuth2Error> {
    let clients = storage.list_all_clients().await?;
    Ok(clients.iter().any(|client| {
        // Prefer dedicated post_logout_redirect_uris field.
        let plru = client.get_post_logout_redirect_uris();
        if plru.iter().any(|uri| uri == candidate) {
            return true;
        }
        // Fallback: accept redirect_uris for backwards compatibility.
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

/// Build an OIDC Back-Channel Logout Token (JWT) per
/// https://openid.net/specs/openid-connect-backchannel-1_0.html#LogoutToken
///
/// Returns `Err` if neither `sub` nor `sid` is provided — the spec (§2.5)
/// requires at least one to be present for the token to be valid.
fn build_logout_token(
    issuer: &str,
    audience: &str,
    sub: Option<&str>,
    sid: Option<&str>,
    jwt_secret: &str,
) -> Result<String, OAuth2Error> {
    use jsonwebtoken::{encode, EncodingKey, Header};
    use std::collections::HashMap;

    if sub.is_none() && sid.is_none() {
        return Err(OAuth2Error::new(
            "server_error",
            Some("logout token requires at least one of sub or sid"),
        ));
    }

    let now = chrono::Utc::now().timestamp();
    let jti = uuid::Uuid::new_v4().to_string();

    let mut claims: HashMap<String, serde_json::Value> = HashMap::new();
    claims.insert("iss".into(), json!(issuer));
    claims.insert("aud".into(), json!(audience));
    claims.insert("iat".into(), json!(now));
    claims.insert("exp".into(), json!(now + 120)); // 2-minute validity window
    claims.insert("jti".into(), json!(jti));
    // Back-Channel Logout §2.4: events claim with the logout event URI.
    claims.insert(
        "events".into(),
        json!({
            "http://schemas.openid.net/event/backchannel-logout": {}
        }),
    );
    if let Some(sub) = sub {
        claims.insert("sub".into(), json!(sub));
    }
    if let Some(sid) = sid {
        claims.insert("sid".into(), json!(sid));
    }

    // §2.4: typ MUST be "logout+JWT"
    let header = Header {
        typ: Some("logout+JWT".to_string()),
        ..Default::default()
    };
    let key = EncodingKey::from_secret(jwt_secret.as_bytes());
    encode(&header, &claims, &key)
        .map_err(|e| OAuth2Error::new("server_error", Some(&e.to_string())))
}

/// Send back-channel logout tokens to all clients that have
/// `backchannel_logout_uri` configured.
async fn send_backchannel_logout_tokens(
    storage: &DynStorage,
    issuer: &str,
    sub: Option<&str>,
    sid: Option<&str>,
    jwt_secret: &str,
) {
    // Per spec §2.5, a valid logout token requires at least one of sub or sid.
    if sub.is_none() && sid.is_none() {
        return;
    }

    let clients = match storage.list_all_clients().await {
        Ok(c) => c,
        Err(_) => return,
    };

    let http_client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
    {
        Ok(c) => c,
        Err(_) => return,
    };

    for client in &clients {
        if client.backchannel_logout_uri.is_empty() {
            continue;
        }
        let eff_sid = if client.backchannel_logout_session_required {
            sid
        } else {
            None
        };
        let token = match build_logout_token(issuer, &client.client_id, sub, eff_sid, jwt_secret) {
            Ok(t) => t,
            Err(_) => continue,
        };

        // POST the logout_token as application/x-www-form-urlencoded.
        let _ = http_client
            .post(&client.backchannel_logout_uri)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(format!("logout_token={}", token))
            .send()
            .await;
    }
}

/// Build an HTML page containing iframes for front-channel logout.
fn build_frontchannel_logout_page(
    storage_clients: &[oauth2_core::Client],
    issuer: &str,
    sid: Option<&str>,
    post_logout_redirect: Option<&str>,
) -> String {
    let mut iframes = String::new();
    for client in storage_clients {
        if client.frontchannel_logout_uri.is_empty() {
            continue;
        }
        let mut uri = match Url::parse(&client.frontchannel_logout_uri) {
            Ok(u) => u,
            Err(_) => continue,
        };
        // OIDC Front-Channel Logout §3: iss and sid parameters.
        uri.query_pairs_mut().append_pair("iss", issuer);
        if client.frontchannel_logout_session_required {
            if let Some(sid) = sid {
                uri.query_pairs_mut().append_pair("sid", sid);
            }
        }
        iframes.push_str(&format!(
            r#"<iframe src="{}" style="display:none;" sandbox="allow-scripts allow-same-origin"></iframe>"#,
            uri
        ));
        iframes.push('\n');
    }

    let redirect_script = if let Some(redirect_uri) = post_logout_redirect {
        // The caller has already validated this URI against registered values and
        // appended any `state`. JSON-encode it into a safe JS string literal so a
        // quote/backslash cannot break out of the <script> context. serde_json
        // does NOT escape `<` or `/`, so additionally neutralize the script-closing
        // sequence (`</script>`) by escaping those characters to their JS unicode
        // form — otherwise a URL containing `</script>` could close the element.
        let url_js = serde_json::to_string(redirect_uri)
            .unwrap_or_else(|_| "\"\"".to_string())
            .replace('<', "\\u003C")
            .replace('/', "\\/");
        format!(
            r#"<script>setTimeout(function(){{ window.location.href = {}; }}, 2000);</script>"#,
            url_js
        )
    } else {
        String::new()
    };

    format!(
        r#"<!DOCTYPE html>
<html>
<head><title>Logging out...</title></head>
<body>
<p>Logging out...</p>
{}
{}
</body>
</html>"#,
        iframes, redirect_script
    )
}

/// OIDC RP-Initiated Logout endpoint.
///
/// Implements:
/// - OIDC RP-Initiated Logout 1.0
/// - OIDC Back-Channel Logout 1.0 (sends logout_token to registered URIs)
/// - OIDC Front-Channel Logout 1.0 (renders iframes for registered URIs)
pub async fn logout(
    query: web::Query<LogoutQuery>,
    session: Session,
    storage: web::Data<DynStorage>,
    oidc: web::Data<OidcConfig>,
) -> Result<HttpResponse, OAuth2Error> {
    let mut sub: Option<String> = None;
    let sid: Option<String> = query.sid.clone().or_else(|| {
        // Derive session ID from session if available.
        session.get::<String>("session_id").unwrap_or(None)
    });

    // If id_token_hint is provided, validate and extract claims.
    //
    // W2-H3: The server can issue id_tokens as either HS256 (signed with
    // `jwt_secret`) or RS256 (signed with `id_token_private_key_pem`). The
    // `alg` in the JOSE header is the authoritative source of truth for
    // which key material to check against. Never trust the token to pick its
    // own algorithm — that is the classic `alg` confusion attack. We read the
    // header only to pick the matching *configured* key, then pin
    // `Validation::new(alg)` so jsonwebtoken will reject any token whose
    // signature algorithm does not match.
    if let Some(ref id_token_hint) = query.id_token_hint {
        let token_result = (|| -> Result<jsonwebtoken::TokenData<serde_json::Value>, jsonwebtoken::errors::Error> {
            let header = jsonwebtoken::decode_header(id_token_hint)?;
            let (decoding_key, alg) = match header.alg {
                jsonwebtoken::Algorithm::HS256 => (
                    jsonwebtoken::DecodingKey::from_secret(oidc.jwt_secret.as_bytes()),
                    jsonwebtoken::Algorithm::HS256,
                ),
                jsonwebtoken::Algorithm::RS256 => {
                    let pem = oidc.id_token_private_key_pem.as_deref().ok_or_else(|| {
                        jsonwebtoken::errors::Error::from(
                            jsonwebtoken::errors::ErrorKind::InvalidAlgorithm,
                        )
                    })?;
                    (
                        jsonwebtoken::DecodingKey::from_rsa_pem(pem.as_bytes())?,
                        jsonwebtoken::Algorithm::RS256,
                    )
                }
                // Any other algorithm (including `none`) is rejected.
                _ => {
                    return Err(jsonwebtoken::errors::Error::from(
                        jsonwebtoken::errors::ErrorKind::InvalidAlgorithm,
                    ));
                }
            };
            let mut validation = jsonwebtoken::Validation::new(alg);
            validation.validate_aud = false;
            validation.set_issuer(&[&oidc.issuer]);
            jsonwebtoken::decode::<serde_json::Value>(id_token_hint, &decoding_key, &validation)
        })();

        if let Ok(token_data) = token_result {
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

            if let Some(s) = token_data.claims.get("sub").and_then(|v| v.as_str()) {
                sub = Some(s.to_string());
                let _ = storage.revoke_tokens_by_user_id(s).await;
            }
        }
    }

    // Invalidate local session.
    session.purge();

    // --- Back-channel logout: best-effort delivery to all registered clients ---
    send_backchannel_logout_tokens(
        storage.get_ref(),
        &oidc.issuer,
        sub.as_deref(),
        sid.as_deref(),
        &oidc.jwt_secret,
    )
    .await;

    // --- Front-channel logout: if any client has frontchannel_logout_uri, render iframes ---
    let clients = storage.list_all_clients().await.unwrap_or_default();
    let has_frontchannel = clients
        .iter()
        .any(|c| !c.frontchannel_logout_uri.is_empty());

    if has_frontchannel {
        // Validate post_logout_redirect_uri the SAME way the standard branch does,
        // BEFORE rendering it — the previous code skipped this, enabling an open
        // redirect and reflected XSS. Bake any `state` into the validated URL here.
        let redirect_target: Option<String> = match query.post_logout_redirect_uri.as_deref() {
            Some(uri) => {
                let mut parsed = validate_post_logout_redirect_uri_shape(uri)?;
                if !is_registered_post_logout_redirect(storage.get_ref(), uri).await? {
                    return Err(OAuth2Error::invalid_request(
                        "Unregistered post_logout_redirect_uri",
                    ));
                }
                if let Some(state) = query.state.as_deref() {
                    parsed.query_pairs_mut().append_pair("state", state);
                }
                Some(parsed.to_string())
            }
            None => None,
        };

        let html = build_frontchannel_logout_page(
            &clients,
            &oidc.issuer,
            sid.as_deref(),
            redirect_target.as_deref(),
        );
        return Ok(HttpResponse::Ok()
            .content_type("text/html; charset=utf-8")
            .body(html));
    }

    // --- Standard redirect flow (no front-channel) ---
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

#[cfg(test)]
mod tests {
    use super::*;

    fn client_with_frontchannel(uri: &str) -> oauth2_core::Client {
        let mut c = oauth2_core::Client::new(
            "rp".to_string(),
            "secret".to_string(),
            vec!["https://rp.example/cb".to_string()],
            vec!["authorization_code".to_string()],
            "openid".to_string(),
            "test".to_string(),
        );
        c.frontchannel_logout_uri = uri.to_string();
        c
    }

    #[test]
    fn redirect_url_is_json_encoded_not_raw() {
        let clients = vec![client_with_frontchannel("https://rp.example/fc")];
        // A value containing a double-quote must not break out of the JS string.
        let html = build_frontchannel_logout_page(
            &clients,
            "https://issuer.example",
            None,
            Some(r#"https://rp.example/done?x="+alert(1)+""#),
        );
        // No raw breakout: the quote must be backslash-escaped by JSON encoding.
        assert!(!html.contains(r#"href = "https://rp.example/done?x="+alert(1)+"";"#));
        assert!(html.contains(r#"\"+alert(1)+\""#));
    }

    #[test]
    fn redirect_url_does_not_allow_script_breakout() {
        let clients = vec![client_with_frontchannel("https://rp.example/fc")];
        // serde_json escapes `"` and `\` but NOT `<` or `/`, so a redirect URI
        // containing the literal `</script>` could otherwise close the <script>
        // element and inject markup.
        let html = build_frontchannel_logout_page(
            &clients,
            "https://issuer.example",
            None,
            Some("https://rp.example/done?x=</script><script>alert(1)</script>"),
        );
        // The only literal </script> must be our own closing tag — the redirect
        // URL's </script> must be neutralized, not break out of the element.
        assert_eq!(html.matches("</script>").count(), 1);
        // The injected opening tag must not appear raw either.
        assert!(!html.contains("<script>alert(1)"));
    }

    #[test]
    fn no_redirect_script_when_absent() {
        let clients = vec![client_with_frontchannel("https://rp.example/fc")];
        let html = build_frontchannel_logout_page(&clients, "https://issuer.example", None, None);
        assert!(!html.contains("window.location.href"));
    }
}
