use crate::models::{OAuth2Error, SocialLoginConfig, SocialUserInfo};
use crate::services::SocialLoginService;
use actix_session::Session;
use actix_web::{web, HttpResponse, Result};
use oauth2::{
    AuthorizationCode, CsrfToken, PkceCodeChallenge, Scope,
    TokenResponse as OAuth2TokenResponse,
};
use serde::Deserialize;
use std::sync::Arc;

#[derive(Deserialize)]
pub struct AuthCallbackQuery {
    code: String,
    state: Option<String>,
}

/// Initiate Google login
pub async fn google_login(
    config: web::Data<Arc<SocialLoginConfig>>,
    session: Session,
) -> Result<HttpResponse, OAuth2Error> {
    let provider_config = config.google.as_ref().ok_or_else(|| {
        OAuth2Error::new(
            "provider_not_configured",
            Some("Google login not configured"),
        )
    })?;

    let client = SocialLoginService::get_google_client(provider_config)?;

    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

    let (auth_url, csrf_token) = client
        .authorize_url(CsrfToken::new_random)
        .add_scope(Scope::new("openid".to_string()))
        .add_scope(Scope::new("email".to_string()))
        .add_scope(Scope::new("profile".to_string()))
        .set_pkce_challenge(pkce_challenge)
        .url();

    // Store CSRF token and PKCE verifier in session
    session
        .insert("csrf_token", csrf_token.secret())
        .map_err(|e| OAuth2Error::new("session_error", Some(&e.to_string())))?;
    session
        .insert("pkce_verifier", pkce_verifier.secret())
        .map_err(|e| OAuth2Error::new("session_error", Some(&e.to_string())))?;
    session
        .insert("provider", "google")
        .map_err(|e| OAuth2Error::new("session_error", Some(&e.to_string())))?;

    Ok(HttpResponse::Found()
        .append_header(("Location", auth_url.to_string()))
        .finish())
}

/// Initiate Microsoft login
pub async fn microsoft_login(
    config: web::Data<Arc<SocialLoginConfig>>,
    session: Session,
) -> Result<HttpResponse, OAuth2Error> {
    let provider_config = config.microsoft.as_ref().ok_or_else(|| {
        OAuth2Error::new(
            "provider_not_configured",
            Some("Microsoft login not configured"),
        )
    })?;

    let client = SocialLoginService::get_microsoft_client(provider_config)?;

    let (auth_url, csrf_token) = client
        .authorize_url(CsrfToken::new_random)
        .add_scope(Scope::new("openid".to_string()))
        .add_scope(Scope::new("email".to_string()))
        .add_scope(Scope::new("profile".to_string()))
        .url();

    session
        .insert("csrf_token", csrf_token.secret())
        .map_err(|e| OAuth2Error::new("session_error", Some(&e.to_string())))?;
    session
        .insert("provider", "microsoft")
        .map_err(|e| OAuth2Error::new("session_error", Some(&e.to_string())))?;

    Ok(HttpResponse::Found()
        .append_header(("Location", auth_url.to_string()))
        .finish())
}

/// Initiate GitHub login
pub async fn github_login(
    config: web::Data<Arc<SocialLoginConfig>>,
    session: Session,
) -> Result<HttpResponse, OAuth2Error> {
    let provider_config = config.github.as_ref().ok_or_else(|| {
        OAuth2Error::new(
            "provider_not_configured",
            Some("GitHub login not configured"),
        )
    })?;

    let client = SocialLoginService::get_github_client(provider_config)?;

    let (auth_url, csrf_token) = client
        .authorize_url(CsrfToken::new_random)
        .add_scope(Scope::new("user:email".to_string()))
        .url();

    session
        .insert("csrf_token", csrf_token.secret())
        .map_err(|e| OAuth2Error::new("session_error", Some(&e.to_string())))?;
    session
        .insert("provider", "github")
        .map_err(|e| OAuth2Error::new("session_error", Some(&e.to_string())))?;

    Ok(HttpResponse::Found()
        .append_header(("Location", auth_url.to_string()))
        .finish())
}

/// Handle OAuth callback from providers
pub async fn auth_callback(
    query: web::Query<AuthCallbackQuery>,
    provider: web::Path<String>,
    config: web::Data<Arc<SocialLoginConfig>>,
    session: Session,
) -> Result<HttpResponse, OAuth2Error> {
    // Verify CSRF token
    let stored_csrf: Option<String> = session
        .get("csrf_token")
        .map_err(|e| OAuth2Error::new("session_error", Some(&e.to_string())))?;

    if let Some(state) = &query.state {
        if Some(state.clone()) != stored_csrf {
            return Err(OAuth2Error::access_denied("CSRF token mismatch"));
        }
    }

    let stored_provider: Option<String> = session
        .get("provider")
        .map_err(|e| OAuth2Error::new("session_error", Some(&e.to_string())))?;

    if stored_provider.as_deref() != Some(provider.as_str()) {
        return Err(OAuth2Error::invalid_request("Provider mismatch"));
    }

    // Exchange code for token based on provider
    let user_info = match provider.as_str() {
        "google" => handle_google_callback(&query.code, config.as_ref(), &session).await?,
        "microsoft" => handle_microsoft_callback(&query.code, config.as_ref(), &session).await?,
        "github" => handle_github_callback(&query.code, config.as_ref(), &session).await?,
        _ => return Err(OAuth2Error::invalid_request("Unsupported provider")),
    };

    // Store user info in session
    session
        .insert("user_info", serde_json::to_string(&user_info).unwrap())
        .map_err(|e| OAuth2Error::new("session_error", Some(&e.to_string())))?;
    session
        .insert("authenticated", true)
        .map_err(|e| OAuth2Error::new("session_error", Some(&e.to_string())))?;

    // Redirect to success page
    Ok(HttpResponse::Found()
        .append_header(("Location", "/auth/success"))
        .finish())
}

async fn handle_google_callback(
    code: &str,
    config: &SocialLoginConfig,
    _session: &Session,
) -> Result<SocialUserInfo, OAuth2Error> {
    let provider_config = config.google.as_ref().ok_or_else(|| {
        OAuth2Error::new("provider_not_configured", Some("Google not configured"))
    })?;

    let client = SocialLoginService::get_google_client(provider_config)?;

    let http_client = reqwest::Client::new();
    let token_result = client
        .exchange_code(AuthorizationCode::new(code.to_string()))
        .request_async(&http_client)
        .await
        .map_err(|e| OAuth2Error::new("token_exchange_failed", Some(&e.to_string())))?;

    let access_token = token_result.access_token().secret();
    SocialLoginService::fetch_google_user_info(access_token).await
}

async fn handle_microsoft_callback(
    code: &str,
    config: &SocialLoginConfig,
    _session: &Session,
) -> Result<SocialUserInfo, OAuth2Error> {
    let provider_config = config.microsoft.as_ref().ok_or_else(|| {
        OAuth2Error::new("provider_not_configured", Some("Microsoft not configured"))
    })?;

    let client = SocialLoginService::get_microsoft_client(provider_config)?;

    let http_client = reqwest::Client::new();
    let token_result = client
        .exchange_code(AuthorizationCode::new(code.to_string()))
        .request_async(&http_client)
        .await
        .map_err(|e| OAuth2Error::new("token_exchange_failed", Some(&e.to_string())))?;

    let access_token = token_result.access_token().secret();
    SocialLoginService::fetch_microsoft_user_info(access_token).await
}

async fn handle_github_callback(
    code: &str,
    config: &SocialLoginConfig,
    _session: &Session,
) -> Result<SocialUserInfo, OAuth2Error> {
    let provider_config = config.github.as_ref().ok_or_else(|| {
        OAuth2Error::new("provider_not_configured", Some("GitHub not configured"))
    })?;

    let client = SocialLoginService::get_github_client(provider_config)?;

    let http_client = reqwest::Client::new();
    let token_result = client
        .exchange_code(AuthorizationCode::new(code.to_string()))
        .request_async(&http_client)
        .await
        .map_err(|e| OAuth2Error::new("token_exchange_failed", Some(&e.to_string())))?;

    let access_token = token_result.access_token().secret();
    SocialLoginService::fetch_github_user_info(access_token).await
}

/// Display login page
pub async fn login_page() -> Result<HttpResponse> {
    let html = std::fs::read_to_string("templates/login.html")
        .unwrap_or_else(|_| include_str!("../../templates/login.html").to_string());

    Ok(HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(html))
}

/// Authentication success page
pub async fn auth_success(session: Session) -> Result<HttpResponse> {
    let authenticated: Option<bool> = session.get("authenticated").unwrap_or(None);

    if !authenticated.unwrap_or(false) {
        return Ok(HttpResponse::Found()
            .append_header(("Location", "/auth/login"))
            .finish());
    }

    let user_info: Option<String> = session.get("user_info").unwrap_or(None);

    let html = format!(
        r#"
        <!DOCTYPE html>
        <html>
        <head>
            <title>Login Success</title>
            <link rel="stylesheet" href="/static/css/admin.css">
        </head>
        <body>
            <div class="container">
                <h1>Login Successful!</h1>
                <p>You have been authenticated successfully.</p>
                <pre>{}</pre>
                <a href="/admin">Go to Dashboard</a>
            </div>
        </body>
        </html>
        "#,
        user_info.unwrap_or_else(|| "No user info".to_string())
    );

    Ok(HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(html))
}

/// Logout handler
pub async fn logout(session: Session) -> Result<HttpResponse> {
    session.purge();

    Ok(HttpResponse::Found()
        .append_header(("Location", "/auth/login"))
        .finish())
}
