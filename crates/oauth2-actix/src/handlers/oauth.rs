use actix::Addr;
use actix_web::{web, HttpResponse, Result};
use serde::Deserialize;

use oauth2_observability::Metrics;

use crate::actors::{
    AuthActor, ClientActor, CreateAuthorizationCode, CreateToken, GetClient, TokenActor,
    MarkAuthorizationCodeUsed, ValidateAuthorizationCode, ValidateClient,
};
use oauth2_core::{OAuth2Error, TokenResponse};

fn validate_scope_subset(requested: &str, allowed: &str) -> Result<(), OAuth2Error> {
    let allowed_scopes: Vec<&str> = allowed.split_whitespace().filter(|s| !s.is_empty()).collect();
    let requested_scopes: Vec<&str> = requested
        .split_whitespace()
        .filter(|s| !s.is_empty())
        .collect();

    if requested_scopes.is_empty() {
        return Err(OAuth2Error::invalid_scope("scope must not be empty"));
    }

    let all_allowed = requested_scopes
        .iter()
        .all(|s| allowed_scopes.contains(s));

    if !all_allowed {
        return Err(OAuth2Error::invalid_scope(
            "requested scope exceeds client permissions",
        ));
    }

    Ok(())
}

fn no_store_headers(mut resp: HttpResponse) -> HttpResponse {
    resp.headers_mut()
        .insert(actix_web::http::header::CACHE_CONTROL, "no-store".parse().unwrap());
    resp.headers_mut()
        .insert(actix_web::http::header::PRAGMA, "no-cache".parse().unwrap());
    resp
}

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
    client_actor: web::Data<Addr<ClientActor>>,
    metrics: web::Data<Metrics>,
) -> Result<HttpResponse, OAuth2Error> {
    // Only Authorization Code flow is supported.
    if query.response_type != "code" {
        return Err(OAuth2Error::invalid_request("Unsupported response_type"));
    }

    // Validate client and redirect_uri to prevent open redirect / code exfiltration.
    let client = client_actor
        .send(GetClient {
            client_id: query.client_id.clone(),
            span: tracing::Span::current(),
        })
        .await
        .map_err(|e| OAuth2Error::new("server_error", Some(&e.to_string())))??;

    if !client.supports_grant_type("authorization_code") {
        return Err(OAuth2Error::unauthorized_client(
            "Client is not allowed to use authorization_code",
        ));
    }

    if !client.validate_redirect_uri(&query.redirect_uri) {
        return Err(OAuth2Error::invalid_request("Invalid redirect_uri"));
    }

    // In a real implementation, this would show a consent page
    // For now, we'll auto-approve with a mock user
    let user_id = "user_123".to_string(); // Mock user

    let scope = query.scope.clone().unwrap_or_else(|| "read".to_string());

    // Enforce that requested scopes are within the client's allowed scope set.
    validate_scope_subset(&scope, &client.scope)?;

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
    client_actor: web::Data<Addr<ClientActor>>,
    auth_actor: web::Data<Addr<AuthActor>>,
    metrics: web::Data<Metrics>,
) -> Result<HttpResponse, OAuth2Error> {
    match form.grant_type.as_str() {
        "authorization_code" => {
            handle_authorization_code_grant(
                form.into_inner(),
                token_actor,
                client_actor,
                auth_actor,
                metrics,
            )
            .await
        }
        "client_credentials" => {
            handle_client_credentials_grant(form.into_inner(), token_actor, client_actor, metrics)
                .await
        }
        "password" => {
            handle_password_grant(form.into_inner(), token_actor, client_actor, metrics).await
        }
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
    client_actor: web::Data<Addr<ClientActor>>,
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
        .send(ValidateAuthorizationCode {
            code: code.clone(),
            client_id: req.client_id.clone(),
            redirect_uri,
            code_verifier: req.code_verifier,
            span: tracing::Span::current(),
        })
        .await
        .map_err(|e| OAuth2Error::new("server_error", Some(&e.to_string())))??;

    // Validate client grant permissions + authenticate if required.
    let client = client_actor
        .send(GetClient {
            client_id: req.client_id.clone(),
            span: tracing::Span::current(),
        })
        .await
        .map_err(|e| OAuth2Error::new("server_error", Some(&e.to_string())))??;

    if !client.supports_grant_type("authorization_code") {
        return Err(OAuth2Error::unauthorized_client(
            "Client is not allowed to use authorization_code",
        ));
    }

    match req.client_secret {
        Some(secret) => {
            let ok = client_actor
                .send(ValidateClient {
                    client_id: req.client_id.clone(),
                    client_secret: secret,
                    span: tracing::Span::current(),
                })
                .await
                .map_err(|e| OAuth2Error::new("server_error", Some(&e.to_string())))??;

            if !ok {
                return Err(OAuth2Error::invalid_client("Invalid client_secret"));
            }
        }
        None => {
            // Allow public clients only when PKCE was used.
            if auth_code.code_challenge.is_none() {
                return Err(OAuth2Error::invalid_client("Missing client_secret"));
            }
        }
    }

    // Only consume (burn) the authorization code after we've authenticated/authorized the client.
    // This prevents invalid_client errors from exhausting valid codes.
    auth_actor
        .send(MarkAuthorizationCodeUsed {
            code,
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

    Ok(no_store_headers(
        HttpResponse::Ok().json(TokenResponse::from(token)),
    ))
}

async fn handle_client_credentials_grant(
    req: TokenRequest,
    token_actor: web::Data<Addr<TokenActor>>,
    client_actor: web::Data<Addr<ClientActor>>,
    metrics: web::Data<Metrics>,
) -> Result<HttpResponse, OAuth2Error> {
    // Validate client exists + grant permissions.
    let client = client_actor
        .send(GetClient {
            client_id: req.client_id.clone(),
            span: tracing::Span::current(),
        })
        .await
        .map_err(|e| OAuth2Error::new("server_error", Some(&e.to_string())))??;

    if !client.supports_grant_type("client_credentials") {
        return Err(OAuth2Error::unauthorized_client(
            "Client is not allowed to use client_credentials",
        ));
    }

    // Validate client credentials (required for this grant).
    let client_secret = req
        .client_secret
        .ok_or_else(|| OAuth2Error::invalid_client("Missing client_secret"))?;
    let ok = client_actor
        .send(ValidateClient {
            client_id: req.client_id.clone(),
            client_secret,
            span: tracing::Span::current(),
        })
        .await
        .map_err(|e| OAuth2Error::new("server_error", Some(&e.to_string())))??;
    if !ok {
        return Err(OAuth2Error::invalid_client("Invalid client_secret"));
    }

    let scope = req.scope.unwrap_or_else(|| "read".to_string());

    validate_scope_subset(&scope, &client.scope)?;

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

    Ok(no_store_headers(
        HttpResponse::Ok().json(TokenResponse::from(token)),
    ))
}

async fn handle_password_grant(
    req: TokenRequest,
    token_actor: web::Data<Addr<TokenActor>>,
    client_actor: web::Data<Addr<ClientActor>>,
    metrics: web::Data<Metrics>,
) -> Result<HttpResponse, OAuth2Error> {
    // Validate client exists + grant permissions.
    let client = client_actor
        .send(GetClient {
            client_id: req.client_id.clone(),
            span: tracing::Span::current(),
        })
        .await
        .map_err(|e| OAuth2Error::new("server_error", Some(&e.to_string())))??;

    if !client.supports_grant_type("password") {
        return Err(OAuth2Error::unauthorized_client(
            "Client is not allowed to use password",
        ));
    }

    // Validate client credentials (required for this grant).
    let client_secret = req
        .client_secret
        .ok_or_else(|| OAuth2Error::invalid_client("Missing client_secret"))?;
    let ok = client_actor
        .send(ValidateClient {
            client_id: req.client_id.clone(),
            client_secret,
            span: tracing::Span::current(),
        })
        .await
        .map_err(|e| OAuth2Error::new("server_error", Some(&e.to_string())))??;
    if !ok {
        return Err(OAuth2Error::invalid_client("Invalid client_secret"));
    }

    let username = req
        .username
        .ok_or_else(|| OAuth2Error::invalid_request("Missing username"))?;
    let _password = req
        .password
        .ok_or_else(|| OAuth2Error::invalid_request("Missing password"))?;

    // In real implementation, validate username/password
    let scope = req.scope.unwrap_or_else(|| "read".to_string());

    validate_scope_subset(&scope, &client.scope)?;

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

    Ok(no_store_headers(
        HttpResponse::Ok().json(TokenResponse::from(token)),
    ))
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
