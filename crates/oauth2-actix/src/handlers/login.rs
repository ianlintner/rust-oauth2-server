//! Username/password login handlers for the OAuth2 authorization code flow.
//!
//! The authorize endpoint redirects unauthenticated users here. After
//! successful credential verification the user is redirected back to
//! `/oauth/authorize` with the original query string so the authorization
//! code grant can complete.

use actix_session::Session;
use actix_web::{web, HttpResponse};
use argon2::{Argon2, PasswordHash, PasswordVerifier};
use serde::Deserialize;

use oauth2_core::utils::redirect::is_safe_redirect;
use oauth2_ports::DynStorage;

/// Query parameters accepted by `GET /auth/login`.
#[derive(Debug, Deserialize)]
pub struct LoginQuery {
    /// Optional error key shown to the user (e.g. `invalid_credentials`).
    pub error: Option<String>,
}

/// Form body submitted by `POST /auth/login`.
#[derive(Debug, Deserialize)]
pub struct LoginForm {
    pub username: String,
    pub password: String,
}

/// Serve the login page.
///
/// If `?error=…` is present the page will display an alert banner.
pub async fn login_page(query: web::Query<LoginQuery>) -> actix_web::Result<HttpResponse> {
    let mut html = std::fs::read_to_string("templates/login.html")
        .unwrap_or_else(|_| include_str!("../../../../templates/login.html").to_string());

    // Inject a server-side error banner when the query string contains `?error=…`
    if let Some(ref error) = query.error {
        let message = match error.as_str() {
            "invalid_credentials" => "Invalid username or password. Please try again.",
            "account_disabled" => "This account has been disabled.",
            "login_required" => "Please log in to continue.",
            _ => "An error occurred. Please try again.",
        };
        let error_html = format!(
            r#"<div class="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded mb-4" role="alert">
                <div class="flex items-center">
                    <svg class="w-5 h-5 mr-2" fill="currentColor" viewBox="0 0 20 20">
                        <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clip-rule="evenodd"/>
                    </svg>
                    <span>{}</span>
                </div>
            </div>"#,
            html_escape(message)
        );
        html = html.replace("<!--SERVER_ERROR-->", &error_html);
    }

    Ok(HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(html))
}

/// Validate credentials and establish an authenticated session.
///
/// On success the user is redirected to the pending `/oauth/authorize` URL
/// (stored in the session by the authorize handler) or to `/auth/success`.
///
/// On failure the user is redirected back to `GET /auth/login?error=…`.
pub async fn login_submit(
    session: Session,
    form: web::Form<LoginForm>,
    storage: web::Data<DynStorage>,
) -> actix_web::Result<HttpResponse> {
    // Look up user by username
    let user = storage
        .get_user_by_username(&form.username)
        .await
        .map_err(|e| {
            tracing::error!("Storage error during login: {e}");
            actix_web::error::ErrorInternalServerError("Internal error")
        })?;

    let user = match user {
        Some(u) if u.enabled => u,
        Some(_) => {
            // Account exists but is disabled
            return Ok(HttpResponse::Found()
                .append_header(("Location", "/auth/login?error=account_disabled"))
                .finish());
        }
        None => {
            // Unknown username — return generic error to avoid user enumeration
            return Ok(HttpResponse::Found()
                .append_header(("Location", "/auth/login?error=invalid_credentials"))
                .finish());
        }
    };

    // Verify password against stored Argon2 hash
    let parsed_hash = match PasswordHash::new(&user.password_hash) {
        Ok(h) => h,
        Err(e) => {
            tracing::error!(
                "Invalid password hash format for user {}: {e}",
                user.username
            );
            return Ok(HttpResponse::Found()
                .append_header(("Location", "/auth/login?error=invalid_credentials"))
                .finish());
        }
    };

    if Argon2::default()
        .verify_password(form.password.as_bytes(), &parsed_hash)
        .is_err()
    {
        return Ok(HttpResponse::Found()
            .append_header(("Location", "/auth/login?error=invalid_credentials"))
            .finish());
    }

    // --- Credentials valid — establish session ---
    session.renew(); // Rotate session ID to prevent session fixation attacks
    session
        .insert("user_id", &user.id)
        .map_err(|e| actix_web::error::ErrorInternalServerError(e.to_string()))?;
    session
        .insert("authenticated", true)
        .map_err(|e| actix_web::error::ErrorInternalServerError(e.to_string()))?;
    session
        .insert("username", &user.username)
        .map_err(|e| actix_web::error::ErrorInternalServerError(e.to_string()))?;
    session
        .insert("email", &user.email)
        .map_err(|e| actix_web::error::ErrorInternalServerError(e.to_string()))?;
    session
        .insert("role", &user.role)
        .map_err(|e| actix_web::error::ErrorInternalServerError(e.to_string()))?;
    // OIDC Core §2: auth_time — time at which the user authentication occurred.
    // Used by `max_age` enforcement in the authorize handler.
    session
        .insert("auth_time", chrono::Utc::now().timestamp())
        .map_err(|e| actix_web::error::ErrorInternalServerError(e.to_string()))?;

    tracing::info!(user_id = %user.id, username = %user.username, "User authenticated successfully");

    // Redirect to the OAuth authorize URL that was saved before the login redirect,
    // or fall back to the success page.
    let return_to: Option<String> = session.get("return_to")?;
    session.remove("return_to");

    // Only allow safe relative redirects; anything else falls back to /profile.
    let redirect_url = return_to
        .filter(|u| is_safe_redirect(u))
        .unwrap_or_else(|| "/profile".to_string());

    Ok(HttpResponse::Found()
        .append_header(("Location", redirect_url))
        .finish())
}

/// Hash a plaintext password using Argon2id.
///
/// This is exposed so the server crate can seed users at startup.
pub fn hash_password(password: &str) -> Result<String, argon2::password_hash::Error> {
    use argon2::password_hash::{rand_core::OsRng, SaltString};
    use argon2::PasswordHasher;

    let salt = SaltString::generate(&mut OsRng);
    let hash = Argon2::default().hash_password(password.as_bytes(), &salt)?;
    Ok(hash.to_string())
}

/// Minimal HTML entity escaping to prevent XSS in server-injected content.
fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
}
