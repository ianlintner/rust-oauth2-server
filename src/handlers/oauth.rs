use crate::actors::{AuthActor, CreateAuthorizationCode, CreateToken, TokenActor};
use crate::metrics::Metrics;
use crate::models::{OAuth2Error, TokenResponse};
use actix::Addr;
use actix_web::{web, HttpResponse, Result};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct AuthorizeQuery {
    #[allow(dead_code)] // OAuth2 spec field, will be validated in future
    response_type: String,
    client_id: String,
    redirect_uri: String,
    scope: Option<String>,
    state: Option<String>,
    code_challenge: Option<String>,
    code_challenge_method: Option<String>,
}

/// OAuth2 authorize endpoint
/// Initiates the authorization code flow
pub async fn authorize(
    query: web::Query<AuthorizeQuery>,
    auth_actor: web::Data<Addr<AuthActor>>,
    metrics: web::Data<Metrics>,
) -> Result<HttpResponse, OAuth2Error> {
    // In a real implementation, this would show a consent page
    // For now, we'll auto-approve with a mock user
    let user_id = "user_123".to_string(); // Mock user

    let scope = query.scope.clone().unwrap_or_else(|| "read".to_string());

    let auth_code = auth_actor
        .send(CreateAuthorizationCode {
            client_id: query.client_id.clone(),
            user_id,
            redirect_uri: query.redirect_uri.clone(),
            scope,
            code_challenge: query.code_challenge.clone(),
            code_challenge_method: query.code_challenge_method.clone(),
            span: tracing::Span::current(),
        })
        .await
        .map_err(|e| OAuth2Error::new("server_error", Some(&e.to_string())))??;

    metrics.oauth_authorization_codes_issued.inc();

    // Redirect back to client with code
    let mut redirect_url = format!("{}?code={}", query.redirect_uri, auth_code.code);
    if let Some(state) = &query.state {
        redirect_url.push_str(&format!("&state={}", state));
    }

    Ok(HttpResponse::Found()
        .append_header(("Location", redirect_url))
        .finish())
}

#[derive(Debug, Deserialize)]
pub struct TokenRequest {
    grant_type: String,
    code: Option<String>,
    redirect_uri: Option<String>,
    client_id: String,
    client_secret: Option<String>,
    #[allow(dead_code)] // OAuth2 refresh token grant, planned for future
    refresh_token: Option<String>,
    username: Option<String>,
    password: Option<String>,
    scope: Option<String>,
    code_verifier: Option<String>,
}

/// OAuth2 token endpoint
/// Exchanges authorization code for access token
pub async fn token(
    form: web::Form<TokenRequest>,
    token_actor: web::Data<Addr<TokenActor>>,
    auth_actor: web::Data<Addr<AuthActor>>,
    metrics: web::Data<Metrics>,
) -> Result<HttpResponse, OAuth2Error> {
    match form.grant_type.as_str() {
        "authorization_code" => {
            handle_authorization_code_grant(form.into_inner(), token_actor, auth_actor, metrics)
                .await
        }
        "client_credentials" => {
            handle_client_credentials_grant(form.into_inner(), token_actor, metrics).await
        }
        "password" => handle_password_grant(form.into_inner(), token_actor, metrics).await,
        "refresh_token" => {
            handle_refresh_token_grant(form.into_inner(), token_actor, metrics).await
        }
        _ => Err(OAuth2Error::unsupported_grant_type(&format!(
            "Grant type '{}' not supported",
            form.grant_type
        ))),
    }
}

async fn handle_authorization_code_grant(
    req: TokenRequest,
    token_actor: web::Data<Addr<TokenActor>>,
    auth_actor: web::Data<Addr<AuthActor>>,
    metrics: web::Data<Metrics>,
) -> Result<HttpResponse, OAuth2Error> {
    let code = req
        .code
        .ok_or_else(|| OAuth2Error::invalid_request("Missing code"))?;
    let redirect_uri = req
        .redirect_uri
        .ok_or_else(|| OAuth2Error::invalid_request("Missing redirect_uri"))?;

    // Validate authorization code
    let auth_code = auth_actor
        .send(crate::actors::ValidateAuthorizationCode {
            code,
            client_id: req.client_id.clone(),
            redirect_uri,
            code_verifier: req.code_verifier,
            span: tracing::Span::current(),
        })
        .await
        .map_err(|e| OAuth2Error::new("server_error", Some(&e.to_string())))??;

    // Create token
    let token = token_actor
        .send(CreateToken {
            user_id: Some(auth_code.user_id),
            client_id: auth_code.client_id,
            scope: auth_code.scope,
            include_refresh: true,
            span: tracing::Span::current(),
        })
        .await
        .map_err(|e| OAuth2Error::new("server_error", Some(&e.to_string())))??;

    metrics.oauth_token_issued_total.inc();

    Ok(HttpResponse::Ok().json(TokenResponse::from(token)))
}

async fn handle_client_credentials_grant(
    req: TokenRequest,
    token_actor: web::Data<Addr<TokenActor>>,
    metrics: web::Data<Metrics>,
) -> Result<HttpResponse, OAuth2Error> {
    // Validate client credentials
    let _client_secret = req
        .client_secret
        .ok_or_else(|| OAuth2Error::invalid_client("Missing client_secret"))?;

    let scope = req.scope.unwrap_or_else(|| "read".to_string());

    // Create token (no user, client-only)
    let token = token_actor
        .send(CreateToken {
            user_id: None,
            client_id: req.client_id,
            scope,
            include_refresh: false,
            span: tracing::Span::current(),
        })
        .await
        .map_err(|e| OAuth2Error::new("server_error", Some(&e.to_string())))??;

    metrics.oauth_token_issued_total.inc();

    Ok(HttpResponse::Ok().json(TokenResponse::from(token)))
}

async fn handle_password_grant(
    req: TokenRequest,
    token_actor: web::Data<Addr<TokenActor>>,
    metrics: web::Data<Metrics>,
) -> Result<HttpResponse, OAuth2Error> {
    let username = req
        .username
        .ok_or_else(|| OAuth2Error::invalid_request("Missing username"))?;
    let _password = req
        .password
        .ok_or_else(|| OAuth2Error::invalid_request("Missing password"))?;

    // In real implementation, validate username/password
    let scope = req.scope.unwrap_or_else(|| "read".to_string());

    let token = token_actor
        .send(CreateToken {
            user_id: Some(username),
            client_id: req.client_id,
            scope,
            include_refresh: true,
            span: tracing::Span::current(),
        })
        .await
        .map_err(|e| OAuth2Error::new("server_error", Some(&e.to_string())))??;

    metrics.oauth_token_issued_total.inc();

    Ok(HttpResponse::Ok().json(TokenResponse::from(token)))
}

async fn handle_refresh_token_grant(
    _req: TokenRequest,
    _token_actor: web::Data<Addr<TokenActor>>,
    _metrics: web::Data<Metrics>,
) -> Result<HttpResponse, OAuth2Error> {
    // Simplified refresh token handling
    Err(OAuth2Error::unsupported_grant_type(
        "Refresh token grant not yet implemented",
    ))
}
