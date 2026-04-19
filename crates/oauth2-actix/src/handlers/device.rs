use actix::Addr;
use actix_session::Session;
use actix_web::{web, HttpRequest, HttpResponse, Result};
use serde::Deserialize;

use crate::actors::{ClientActor, GetClient};
use crate::handlers::oauth::{client_secret_matches, parse_client_basic_auth};
use crate::handlers::wellknown::OidcConfig;
use oauth2_core::{DeviceAuthorization, DeviceAuthorizationResponse, OAuth2Error};
use oauth2_ports::DynStorage;

const DEVICE_CODE_GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:device_code";
const DEVICE_EXPIRES_IN_SECONDS: i64 = 600;
const DEVICE_POLL_INTERVAL_SECONDS: i32 = 5;

#[derive(Debug, Deserialize)]
pub struct DeviceAuthorizationRequest {
    // RFC 8628 §3.1 allows the client to be identified via
    // `client_secret_basic`, in which case `client_id` is NOT present in
    // the form body. Keep it optional and resolve from the Authorization
    // header when absent.
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub scope: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct DeviceVerifyQuery {
    pub user_code: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct DeviceVerifyForm {
    pub user_code: String,
    pub action: Option<String>,
}

fn generate_user_code() -> String {
    use rand::{Rng, SeedableRng};

    const ALPHABET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    let mut rng = rand::rngs::StdRng::from_os_rng();

    let mut buf = String::with_capacity(9);
    for i in 0..8 {
        if i == 4 {
            buf.push('-');
        }
        let idx = rng.random_range(0..ALPHABET.len());
        buf.push(ALPHABET[idx] as char);
    }

    buf
}

fn generate_device_code() -> String {
    use rand::{Rng, SeedableRng};

    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let mut rng = rand::rngs::StdRng::from_os_rng();

    let mut buf = String::with_capacity(48);
    for _ in 0..48 {
        let idx = rng.random_range(0..ALPHABET.len());
        buf.push(ALPHABET[idx] as char);
    }

    buf
}

pub async fn device_authorization(
    req: HttpRequest,
    form: web::Form<DeviceAuthorizationRequest>,
    client_actor: web::Data<Addr<ClientActor>>,
    storage: web::Data<DynStorage>,
    oidc: web::Data<OidcConfig>,
) -> Result<HttpResponse, OAuth2Error> {
    let basic = parse_client_basic_auth(&req)?;
    let basic_client_id = basic.as_ref().map(|(id, _)| id.clone());
    let basic_client_secret = basic.as_ref().map(|(_, s)| s.clone());

    // Resolve client_id from the body, falling back to the Basic auth
    // header when the body omits it (RFC 8628 §3.1 + RFC 6749 §2.3.1).
    let client_id = match (form.client_id.as_ref(), basic_client_id.as_ref()) {
        (Some(body_id), Some(basic_id)) if body_id != basic_id => {
            return Err(OAuth2Error::invalid_request(
                "client_id mismatch between body and Basic auth",
            ));
        }
        (Some(id), _) | (None, Some(id)) => id.clone(),
        (None, None) => {
            return Err(OAuth2Error::invalid_client("Missing client_id"));
        }
    };

    let client_secret = form
        .client_secret
        .clone()
        .or(basic_client_secret)
        .ok_or_else(|| OAuth2Error::invalid_client("Missing client_secret"))?;

    let client = client_actor
        .send(GetClient {
            client_id: client_id.clone(),
            span: tracing::Span::current(),
        })
        .await
        .map_err(|e| OAuth2Error::new("server_error", Some(&e.to_string())))??;

    if !client_secret_matches(&client, &client_secret) {
        return Err(OAuth2Error::invalid_client("Invalid client_secret"));
    }

    if !client.supports_grant_type(DEVICE_CODE_GRANT_TYPE)
        && !client.supports_grant_type("device_code")
    {
        return Err(OAuth2Error::unauthorized_client(
            "Client is not allowed to use device_code grant",
        ));
    }

    let scope = form.scope.clone().unwrap_or_else(|| "read".to_string());

    let device_code = generate_device_code();
    let user_code = generate_user_code();

    let device_auth = DeviceAuthorization::new(
        device_code.clone(),
        user_code.clone(),
        client_id.clone(),
        scope,
        DEVICE_EXPIRES_IN_SECONDS,
        DEVICE_POLL_INTERVAL_SECONDS,
    );

    storage.save_device_authorization(&device_auth).await?;

    let verify_uri = format!("{}/oauth/device/verify", oidc.issuer.trim_end_matches('/'));

    let response = DeviceAuthorizationResponse {
        device_code,
        user_code: user_code.clone(),
        verification_uri: verify_uri.clone(),
        verification_uri_complete: format!("{}?user_code={}", verify_uri, user_code),
        expires_in: DEVICE_EXPIRES_IN_SECONDS,
        interval: DEVICE_POLL_INTERVAL_SECONDS,
    };

    Ok(HttpResponse::Ok().json(response))
}

pub async fn verify_page(
    query: web::Query<DeviceVerifyQuery>,
    session: Session,
) -> Result<HttpResponse, OAuth2Error> {
    let user_id: Option<String> = session.get("user_id").unwrap_or(None);
    if user_id.is_none() {
        let return_to = format!(
            "/oauth/device/verify{}",
            query
                .user_code
                .as_ref()
                .map(|c| format!("?user_code={c}"))
                .unwrap_or_default()
        );
        session
            .insert("return_to", return_to)
            .map_err(|e| OAuth2Error::new("server_error", Some(&e.to_string())))?;

        return Ok(HttpResponse::Found()
            .append_header(("Location", "/auth/login"))
            .finish());
    }

    let value = query.user_code.clone().unwrap_or_default();
    let html = format!(
        r#"<!DOCTYPE html>
<html>
<head><title>Device Verification</title></head>
<body>
  <h1>Authorize Device</h1>
  <p>Enter the code shown on your device.</p>
  <form method="post" action="/oauth/device/verify">
    <label for="user_code">User code</label>
    <input id="user_code" name="user_code" value="{value}" required />
    <button type="submit" name="action" value="approve">Approve</button>
    <button type="submit" name="action" value="deny">Deny</button>
  </form>
</body>
</html>"#
    );

    Ok(HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(html))
}

pub async fn verify_submit(
    form: web::Form<DeviceVerifyForm>,
    session: Session,
    storage: web::Data<DynStorage>,
) -> Result<HttpResponse, OAuth2Error> {
    let user_id: Option<String> = session.get("user_id").unwrap_or(None);
    let user_id = user_id.ok_or_else(|| OAuth2Error::access_denied("Authentication required"))?;

    let record = storage
        .get_device_authorization_by_user_code(&form.user_code)
        .await?
        .ok_or_else(|| OAuth2Error::invalid_request("Unknown user_code"))?;

    if record.is_expired() {
        return Err(OAuth2Error::invalid_request("user_code expired"));
    }

    if record.used {
        return Err(OAuth2Error::invalid_request("user_code already used"));
    }

    let action = form.action.as_deref().unwrap_or("approve");
    if action == "deny" {
        storage.deny_device_authorization(&form.user_code).await?;
        return Ok(HttpResponse::Ok()
            .content_type("text/html; charset=utf-8")
            .body("<h1>Device access denied</h1>"));
    }

    storage
        .approve_device_authorization(&form.user_code, &user_id)
        .await?;

    Ok(HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body("<h1>Device authorized. You can return to your device.</h1>"))
}
