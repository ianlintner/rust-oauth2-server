use actix::Addr;
use actix_web::{web, HttpResponse, Result};
use serde::Deserialize;

use crate::actors::{RevokeToken, TokenActor, ValidateToken};
use oauth2_core::{Claims, IntrospectionResponse, OAuth2Error};

#[derive(Debug, Deserialize)]
pub struct IntrospectRequest {
    token: String,
    #[allow(dead_code)] // OAuth2 spec field, can be used for optimization
    token_type_hint: Option<String>,
}

/// Token introspection endpoint
/// Returns information about a token
pub async fn introspect(
    form: web::Form<IntrospectRequest>,
    token_actor: web::Data<Addr<TokenActor>>,
    jwt_secret: web::Data<String>,
) -> Result<HttpResponse, OAuth2Error> {
    let token_prefix = form.token.chars().take(20).collect::<String>();
    tracing::info!(
        token_len = form.token.len(),
        token_prefix = %token_prefix,
        "Token introspection requested"
    );

    // Try to validate the token
    let token_result = token_actor
        .send(ValidateToken {
            token: form.token.clone(),
            span: tracing::Span::current(),
        })
        .await
        .map_err(|e| OAuth2Error::new("server_error", Some(&e.to_string())))?;

    match token_result {
        Ok(token) => {
            // Decode JWT to get claims
            let claims = Claims::decode(&token.access_token, &jwt_secret).ok();

            let active = token.is_valid();
            let user_id = token.user_id.clone();
            let scope = token.scope;
            let client_id = token.client_id;
            let token_type = token.token_type;

            let response = IntrospectionResponse {
                active,
                scope: Some(scope),
                client_id: Some(client_id),
                username: user_id.clone(),
                token_type: Some(token_type),
                exp: claims.as_ref().map(|c| c.exp),
                iat: claims.as_ref().map(|c| c.iat),
                sub: claims.as_ref().map(|c| c.sub.clone()).or(user_id),
            };

            Ok(HttpResponse::Ok()
                .insert_header((actix_web::http::header::CACHE_CONTROL, "no-store"))
                .insert_header((actix_web::http::header::PRAGMA, "no-cache"))
                .json(response))
        }
        Err(err) => {
            tracing::warn!(
                error = %err,
                token_len = form.token.len(),
                token_prefix = %token_prefix,
                "Token introspection failed; returning inactive"
            );
            // Token is invalid
            let response = IntrospectionResponse {
                active: false,
                scope: None,
                client_id: None,
                username: None,
                token_type: None,
                exp: None,
                iat: None,
                sub: None,
            };
            Ok(HttpResponse::Ok()
                .insert_header((actix_web::http::header::CACHE_CONTROL, "no-store"))
                .insert_header((actix_web::http::header::PRAGMA, "no-cache"))
                .json(response))
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct RevokeRequest {
    token: String,
    #[allow(dead_code)] // OAuth2 spec field, can be used for optimization
    token_type_hint: Option<String>,
}

/// Token revocation endpoint
/// Revokes an access or refresh token
pub async fn revoke(
    form: web::Form<RevokeRequest>,
    token_actor: web::Data<Addr<TokenActor>>,
) -> Result<HttpResponse, OAuth2Error> {
    token_actor
        .send(RevokeToken {
            token: form.token.clone(),
            span: tracing::Span::current(),
        })
        .await
        .map_err(|e| OAuth2Error::new("server_error", Some(&e.to_string())))??;

    Ok(HttpResponse::Ok()
        .insert_header((actix_web::http::header::CACHE_CONTROL, "no-store"))
        .insert_header((actix_web::http::header::PRAGMA, "no-cache"))
        .finish())
}
