use actix_session::Session;
use actix_web::{web, HttpResponse, Result};
use oauth2::{
    AuthorizationCode, CsrfToken, PkceCodeChallenge, PkceCodeVerifier, Scope,
    TokenResponse as OAuth2TokenResponse,
};
use serde::Deserialize;
use std::sync::Arc;

use oauth2_core::utils::redirect::is_safe_redirect;
use oauth2_core::{OAuth2Error, User};
use oauth2_ports::DynStorage;

use crate::models::{SocialLoginConfig, SocialUserInfo};
use crate::service::SocialLoginService;

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

/// Initiate Azure login.
///
/// This uses the same Microsoft identity platform flow as `microsoft_login`,
/// but allows deployments to configure a separate `azure` provider alias.
pub async fn azure_login(
    config: web::Data<Arc<SocialLoginConfig>>,
    session: Session,
) -> Result<HttpResponse, OAuth2Error> {
    let provider_config = config
        .azure
        .as_ref()
        .or(config.microsoft.as_ref())
        .ok_or_else(|| {
            OAuth2Error::new(
                "provider_not_configured",
                Some("Azure login not configured"),
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
        .insert("provider", "azure")
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
    storage: web::Data<DynStorage>,
    social_svc: web::Data<SocialLoginService>,
    session: Session,
) -> Result<HttpResponse, OAuth2Error> {
    // Verify CSRF token
    let stored_csrf: Option<String> = session
        .get("csrf_token")
        .map_err(|e| OAuth2Error::new("session_error", Some(&e.to_string())))?;

    match (&query.state, &stored_csrf) {
        (Some(state), Some(expected)) if state == expected => {
            // CSRF check passed — continue
        }
        (None, _) => {
            return Err(OAuth2Error::access_denied(
                "CSRF state parameter is required",
            ));
        }
        _ => {
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
        "google" => {
            handle_google_callback(&query.code, config.as_ref(), &social_svc, &session).await?
        }
        "microsoft" => {
            handle_microsoft_callback(&query.code, config.as_ref(), &social_svc, &session).await?
        }
        "azure" => {
            handle_azure_callback(&query.code, config.as_ref(), &social_svc, &session).await?
        }
        "github" => {
            handle_github_callback(&query.code, config.as_ref(), &social_svc, &session).await?
        }
        _ => return Err(OAuth2Error::invalid_request("Unsupported provider")),
    };

    // Find-or-create a local user for this social identity.
    // Username format: "provider:provider_user_id" (e.g. "github:12345")
    let social_username = format!("{}:{}", user_info.provider, user_info.provider_user_id);
    let local_user = find_or_create_social_user(&storage, &social_username, &user_info).await?;

    tracing::info!(
        user_id = %local_user.id,
        provider = %user_info.provider,
        provider_user_id = %user_info.provider_user_id,
        email = %user_info.email,
        "Social login successful"
    );

    // Store user info in session (for /auth/success display)
    session
        .insert("user_info", serde_json::to_string(&user_info).unwrap())
        .map_err(|e| OAuth2Error::new("session_error", Some(&e.to_string())))?;

    // Set the same session keys that the username/password login sets,
    // so the OAuth2 authorize handler recognises the user as authenticated.
    session
        .insert("user_id", &local_user.id)
        .map_err(|e| OAuth2Error::new("session_error", Some(&e.to_string())))?;
    session
        .insert("authenticated", true)
        .map_err(|e| OAuth2Error::new("session_error", Some(&e.to_string())))?;
    session
        .insert("username", &local_user.username)
        .map_err(|e| OAuth2Error::new("session_error", Some(&e.to_string())))?;
    session
        .insert("email", &local_user.email)
        .map_err(|e| OAuth2Error::new("session_error", Some(&e.to_string())))?;
    session
        .insert("role", &local_user.role)
        .map_err(|e| OAuth2Error::new("session_error", Some(&e.to_string())))?;

    // Redirect to the pending OAuth authorize URL (saved before login redirect),
    // or fall back to the success page.
    let return_to: Option<String> = session
        .get("return_to")
        .map_err(|e| OAuth2Error::new("session_error", Some(&e.to_string())))?;
    session.remove("return_to");

    // Only allow safe relative redirects; anything untrusted falls back to /profile.
    let redirect_url = return_to
        .filter(|u| is_safe_redirect(u))
        .unwrap_or_else(|| "/profile".to_string());

    Ok(HttpResponse::Found()
        .append_header(("Location", redirect_url))
        .finish())
}

/// Look up a local user by the social username (e.g. "github:12345").
/// If none exists, create one with a random placeholder password hash.
async fn find_or_create_social_user(
    storage: &DynStorage,
    social_username: &str,
    user_info: &SocialUserInfo,
) -> Result<User, OAuth2Error> {
    // Try to find existing user
    if let Some(existing) = storage.get_user_by_username(social_username).await? {
        return Ok(existing);
    }

    // Create a new local user for this social identity.
    // The password hash is a random value — social users don't use passwords.
    let placeholder_hash = {
        use argon2::password_hash::{rand_core::OsRng, SaltString};
        use argon2::{Argon2, PasswordHasher};
        let salt = SaltString::generate(&mut OsRng);
        Argon2::default()
            .hash_password(uuid::Uuid::new_v4().to_string().as_bytes(), &salt)
            .map_err(|e| OAuth2Error::new("server_error", Some(&e.to_string())))?
            .to_string()
    };

    let user = User::new(
        social_username.to_string(),
        placeholder_hash,
        user_info.email.clone(),
    );

    storage.save_user(&user).await?;
    tracing::info!(
        user_id = %user.id,
        username = %social_username,
        provider = %user_info.provider,
        "Created new local user for social login"
    );

    Ok(user)
}

async fn handle_google_callback(
    code: &str,
    config: &SocialLoginConfig,
    social_svc: &SocialLoginService,
    session: &Session,
) -> Result<SocialUserInfo, OAuth2Error> {
    let provider_config = config.google.as_ref().ok_or_else(|| {
        OAuth2Error::new("provider_not_configured", Some("Google not configured"))
    })?;

    let client = SocialLoginService::get_google_client(provider_config)?;

    // Retrieve the PKCE code verifier stored during login initiation.
    let pkce_verifier_secret: Option<String> = session
        .get("pkce_verifier")
        .map_err(|e| OAuth2Error::new("session_error", Some(&e.to_string())))?;
    let pkce_verifier = pkce_verifier_secret
        .map(PkceCodeVerifier::new)
        .ok_or_else(|| {
            OAuth2Error::new("session_error", Some("PKCE verifier missing from session"))
        })?;

    // oauth2 implements its async HTTP client trait for reqwest 0.12.
    // We standardize on reqwest 0.12 (rustls) here to keep cross-compilation (arm64) OpenSSL-free.
    let http_client = reqwest::Client::new();
    let token_result = client
        .exchange_code(AuthorizationCode::new(code.to_string()))
        .set_pkce_verifier(pkce_verifier)
        .request_async(&http_client)
        .await
        .map_err(|e| OAuth2Error::new("token_exchange_failed", Some(&e.to_string())))?;

    let access_token = token_result.access_token().secret();
    social_svc.fetch_google_user_info(access_token).await
}

async fn handle_microsoft_callback(
    code: &str,
    config: &SocialLoginConfig,
    social_svc: &SocialLoginService,
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
    social_svc.fetch_microsoft_user_info(access_token).await
}

async fn handle_azure_callback(
    code: &str,
    config: &SocialLoginConfig,
    social_svc: &SocialLoginService,
    _session: &Session,
) -> Result<SocialUserInfo, OAuth2Error> {
    let provider_config = config
        .azure
        .as_ref()
        .or(config.microsoft.as_ref())
        .ok_or_else(|| OAuth2Error::new("provider_not_configured", Some("Azure not configured")))?;

    let client = SocialLoginService::get_microsoft_client(provider_config)?;

    let http_client = reqwest::Client::new();
    let token_result = client
        .exchange_code(AuthorizationCode::new(code.to_string()))
        .request_async(&http_client)
        .await
        .map_err(|e| OAuth2Error::new("token_exchange_failed", Some(&e.to_string())))?;

    let access_token = token_result.access_token().secret();
    social_svc.fetch_microsoft_user_info(access_token).await
}

async fn handle_github_callback(
    code: &str,
    config: &SocialLoginConfig,
    social_svc: &SocialLoginService,
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
    social_svc.fetch_github_user_info(access_token).await
}

/// Display login page
pub async fn login_page() -> Result<HttpResponse> {
    let html = std::fs::read_to_string("templates/login.html")
        .unwrap_or_else(|_| include_str!("../../../../templates/login.html").to_string());

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
            <link rel=\"stylesheet\" href=\"/static/css/admin.css\">
        </head>
        <body>
            <div class=\"container\">
                <h1>Login Successful!</h1>
                <p>You have been authenticated successfully.</p>
                <pre>{}</pre>
                <a href=\"/admin\">Go to Dashboard</a>
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
