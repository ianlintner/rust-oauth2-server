use crate::actors::{RevokeToken, TokenActor, ValidateToken};
use crate::models::{Claims, IntrospectionResponse, OAuth2Error};
use actix::Addr;
use actix_web::{web, HttpResponse, Result};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct IntrospectRequest {
    token: String,
    token_type_hint: Option<String>,
}

/// Token introspection endpoint
/// Returns information about a token
pub async fn introspect(
    form: web::Form<IntrospectRequest>,
    token_actor: web::Data<Addr<TokenActor>>,
    jwt_secret: web::Data<String>,
) -> Result<HttpResponse, OAuth2Error> {
    // Try to validate the token
    let token_result = token_actor
        .send(ValidateToken {
            token: form.token.clone(),
        })
        .await
        .map_err(|e| OAuth2Error::new("server_error", Some(&e.to_string())))?;

    match token_result {
        Ok(token) => {
            // Decode JWT to get claims
            let claims = Claims::decode(&token.access_token, &jwt_secret).ok();

            let response = IntrospectionResponse {
                active: token.is_valid(),
                scope: Some(token.scope),
                client_id: Some(token.client_id),
                username: Some(token.user_id.clone()),
                token_type: Some(token.token_type),
                exp: claims.as_ref().map(|c| c.exp),
                iat: claims.as_ref().map(|c| c.iat),
                sub: Some(token.user_id),
            };

            Ok(HttpResponse::Ok().json(response))
        }
        Err(_) => {
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
            Ok(HttpResponse::Ok().json(response))
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct RevokeRequest {
    token: String,
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
        })
        .await
        .map_err(|e| OAuth2Error::new("server_error", Some(&e.to_string())))??;

    Ok(HttpResponse::Ok().finish())
}
