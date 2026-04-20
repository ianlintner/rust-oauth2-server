use actix::Addr;
use actix_web::{web, HttpRequest, HttpResponse, Result};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header as JwtHeader};
use serde::{Deserialize, Serialize};

use crate::actors::{
    ClientActor, GetClient, LookupToken, RevokeToken, TokenActorPool, ValidateToken,
    ValidateTokenStateless,
};
use crate::handlers::oauth::{client_secret_matches, parse_client_basic_auth};
use crate::handlers::wellknown::OidcConfig;
use oauth2_config::Config;
use oauth2_core::{Claims, IntrospectionResponse, OAuth2Error};
use oauth2_observability::Metrics;

fn no_store_headers(mut response: HttpResponse) -> HttpResponse {
    response.headers_mut().insert(
        actix_web::http::header::CACHE_CONTROL,
        "no-store".parse().unwrap(),
    );
    response
        .headers_mut()
        .insert(actix_web::http::header::PRAGMA, "no-cache".parse().unwrap());
    response
}

fn inactive_introspection_response() -> HttpResponse {
    no_store_headers(HttpResponse::Ok().json(IntrospectionResponse {
        active: false,
        scope: None,
        client_id: None,
        username: None,
        token_type: None,
        exp: None,
        iat: None,
        nbf: None,
        sub: None,
        aud: None,
        jti: None,
        iss: None,
    }))
}

async fn authenticate_client(
    req: &HttpRequest,
    form_client_id: Option<&str>,
    form_client_secret: Option<&str>,
    client_actor: &web::Data<Addr<ClientActor>>,
    require_auth: bool,
) -> Result<Option<oauth2_core::Client>, OAuth2Error> {
    let basic = parse_client_basic_auth(req)?;
    let basic_client_id = basic.as_ref().map(|(client_id, _)| client_id.as_str());
    let basic_client_secret = basic
        .as_ref()
        .map(|(_, client_secret)| client_secret.as_str());

    if let (Some(body_id), Some(basic_id)) = (form_client_id, basic_client_id) {
        if body_id != basic_id {
            return Err(OAuth2Error::invalid_request(
                "client_id mismatch between body and Basic auth",
            ));
        }
    }

    if let (Some(body_secret), Some(basic_secret)) = (form_client_secret, basic_client_secret) {
        if body_secret != basic_secret {
            return Err(OAuth2Error::invalid_client(
                "client_secret mismatch between body and Basic auth",
            ));
        }
    }

    let client_id = form_client_id.or(basic_client_id);
    let client_secret = form_client_secret.or(basic_client_secret);

    match (client_id, client_secret) {
        (None, None) if !require_auth => Ok(None),
        (None, None) => Err(OAuth2Error::invalid_client("Missing client authentication")),
        (Some(_), None) => Err(OAuth2Error::invalid_client("Missing client_secret")),
        (None, Some(_)) => Err(OAuth2Error::invalid_request("Missing client_id")),
        (Some(client_id), Some(client_secret)) => {
            let client = client_actor
                .send(GetClient {
                    client_id: client_id.to_string(),
                    span: tracing::Span::current(),
                })
                .await
                .map_err(|e| OAuth2Error::new("server_error", Some(&e.to_string())))??;

            if !client_secret_matches(&client, client_secret) {
                return Err(OAuth2Error::invalid_client("Invalid client credentials"));
            }

            Ok(Some(client))
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct IntrospectRequest {
    token: String,
    #[allow(dead_code)] // OAuth2 spec field, can be used for optimization
    token_type_hint: Option<String>,
    client_id: Option<String>,
    client_secret: Option<String>,
}

/// JWT payload for RFC 9701 token introspection JWT responses.
/// The `token_introspection` claim carries the normalised introspection object.
#[derive(Serialize)]
struct IntrospectionJwtClaims<'a> {
    iss: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    aud: Option<String>,
    iat: i64,
    token_introspection: &'a IntrospectionResponse,
}

/// Token introspection endpoint
/// Returns information about a token
#[allow(clippy::too_many_arguments)]
pub async fn introspect(
    req: HttpRequest,
    form: web::Form<IntrospectRequest>,
    token_actor: web::Data<TokenActorPool>,
    client_actor: web::Data<Addr<ClientActor>>,
    jwt_secret: web::Data<String>,
    stateless: web::Data<bool>,
    metrics: web::Data<Metrics>,
    config: Option<web::Data<Config>>,
    oidc_config: Option<web::Data<OidcConfig>>,
) -> Result<HttpResponse, OAuth2Error> {
    let opaque_access_tokens = config
        .as_ref()
        .map(|cfg| cfg.jwt.access_tokens_opaque)
        .unwrap_or(false);
    let public_introspection = config
        .as_ref()
        .map(|cfg| cfg.jwt.public_introspection)
        .unwrap_or(false);
    let caller = match authenticate_client(
        &req,
        form.client_id.as_deref(),
        form.client_secret.as_deref(),
        &client_actor,
        !public_introspection,
    )
    .await
    {
        Ok(c) => c,
        Err(err) => {
            if err.error == "invalid_client" {
                metrics.oauth_failed_authentications.inc();
            }
            return Err(err);
        }
    };

    let token_prefix = form.token.chars().take(20).collect::<String>();
    tracing::info!(
        token_len = form.token.len(),
        token_prefix = %token_prefix,
        stateless = **stateless,
        opaque_access_tokens,
        "Token introspection requested"
    );

    let use_stateless_validation = **stateless && !opaque_access_tokens;

    // Fast path: validate token purely from JWT claims (no DB lookup).
    let token_result = if use_stateless_validation {
        token_actor
            .route(&form.token)
            .send(ValidateTokenStateless {
                token: form.token.clone(),
                span: tracing::Span::current(),
            })
            .await
            .map_err(|e| OAuth2Error::new("server_error", Some(&e.to_string())))?
    } else {
        // Standard path: full DB-backed validation with caching.
        token_actor
            .route(&form.token)
            .send(ValidateToken {
                token: form.token.clone(),
                span: tracing::Span::current(),
            })
            .await
            .map_err(|e| OAuth2Error::new("server_error", Some(&e.to_string())))?
    };

    match token_result {
        Ok(token) => {
            if let Some(caller) = caller.as_ref() {
                if token.client_id != caller.client_id {
                    tracing::warn!(
                        caller_client_id = %caller.client_id,
                        token_client_id = %token.client_id,
                        token_prefix = %token_prefix,
                        "Authenticated caller attempted to introspect a token owned by another client"
                    );
                    return Ok(inactive_introspection_response());
                }
            }

            // Decode JWT claims to surface them in the introspection response.
            // We must use the unverified decode path because production
            // tokens may be signed with RS256 (see OidcConfig) while the
            // server-side `jwt_secret` is only the HS256 fallback — signature
            // verification would fail and we'd miss the real `jti`/`iss`/etc.
            // The token was already authenticated via the preceding storage
            // lookup, so skipping signature verification here is safe.
            let claims = Claims::decode_unverified(&token.access_token)
                .or_else(|| Claims::decode(&token.access_token, &jwt_secret).ok());

            let active = token.is_valid();
            let user_id = token.user_id.clone();
            let scope = token.scope.clone();
            let client_id = token.client_id.clone();
            let token_type = token.token_type.clone();

            let response = IntrospectionResponse {
                active,
                scope: Some(scope),
                client_id: Some(client_id.clone()),
                username: user_id.clone(),
                token_type: Some(token_type),
                exp: claims
                    .as_ref()
                    .map(|c| c.exp)
                    .or(Some(token.expires_at.timestamp())),
                iat: claims
                    .as_ref()
                    .map(|c| c.iat)
                    .or(Some(token.created_at.timestamp())),
                // nbf mirrors iat (token is valid from issuance; no future-dated tokens)
                nbf: claims
                    .as_ref()
                    .map(|c| c.iat)
                    .or(Some(token.created_at.timestamp())),
                sub: claims.as_ref().map(|c| c.sub.clone()).or(user_id),
                aud: claims.as_ref().map(|c| c.aud.clone()).or(Some(client_id)),
                jti: claims
                    .as_ref()
                    .map(|c| c.jti.clone())
                    .or(Some(token.id.clone())),
                iss: claims
                    .as_ref()
                    .map(|c| c.iss.clone())
                    .or_else(|| oidc_config.as_ref().map(|c| c.issuer.clone())),
            };

            // RFC 9701: if the caller explicitly accepts token-introspection+jwt,
            // wrap the response in a signed JWT instead of returning plain JSON.
            let accept = req
                .headers()
                .get(actix_web::http::header::ACCEPT)
                .and_then(|h| h.to_str().ok())
                .unwrap_or("");

            if accept.contains("application/token-introspection+jwt") {
                let iss = oidc_config
                    .as_ref()
                    .map(|c| c.issuer.as_str())
                    .unwrap_or("");
                let iat = chrono::Utc::now().timestamp();
                let aud = caller.as_ref().map(|c| c.client_id.clone());
                let jwt_claims = IntrospectionJwtClaims {
                    iss,
                    aud,
                    iat,
                    token_introspection: &response,
                };

                let (alg, encoding_key) = match oidc_config.as_ref() {
                    Some(cfg) if cfg.id_token_alg.eq_ignore_ascii_case("RS256") => {
                        if let Some(ref pem) = cfg.id_token_private_key_pem {
                            match EncodingKey::from_rsa_pem(pem.as_bytes()) {
                                Ok(key) => (Algorithm::RS256, key),
                                Err(_) => (
                                    Algorithm::HS256,
                                    EncodingKey::from_secret(jwt_secret.as_bytes()),
                                ),
                            }
                        } else {
                            (
                                Algorithm::HS256,
                                EncodingKey::from_secret(jwt_secret.as_bytes()),
                            )
                        }
                    }
                    _ => (
                        Algorithm::HS256,
                        EncodingKey::from_secret(jwt_secret.as_bytes()),
                    ),
                };

                let mut jwt_header = JwtHeader::new(alg);
                jwt_header.typ = Some("token-introspection+jwt".to_string());
                if let Some(ref cfg) = oidc_config {
                    jwt_header.kid = cfg.id_token_kid.clone();
                }

                match encode(&jwt_header, &jwt_claims, &encoding_key) {
                    Ok(jwt) => Ok(no_store_headers(
                        HttpResponse::Ok()
                            .content_type("application/token-introspection+jwt")
                            .body(jwt),
                    )),
                    Err(e) => Err(OAuth2Error::new("server_error", Some(&e.to_string()))),
                }
            } else {
                Ok(no_store_headers(HttpResponse::Ok().json(response)))
            }
        }
        Err(err) => {
            tracing::warn!(
                error = %err,
                token_len = form.token.len(),
                token_prefix = %token_prefix,
                "Token introspection failed; returning inactive"
            );
            Ok(inactive_introspection_response())
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct RevokeRequest {
    token: String,
    #[allow(dead_code)] // OAuth2 spec field, can be used for optimization
    token_type_hint: Option<String>,
    client_id: Option<String>,
    client_secret: Option<String>,
}

/// Token revocation endpoint
/// Revokes an access or refresh token
pub async fn revoke(
    req: HttpRequest,
    form: web::Form<RevokeRequest>,
    token_actor: web::Data<TokenActorPool>,
    client_actor: web::Data<Addr<ClientActor>>,
    metrics: web::Data<Metrics>,
) -> Result<HttpResponse, OAuth2Error> {
    let caller = match authenticate_client(
        &req,
        form.client_id.as_deref(),
        form.client_secret.as_deref(),
        &client_actor,
        true,
    )
    .await
    {
        Ok(c) => c.expect("client auth is required for token revocation"),
        Err(err) => {
            if err.error == "invalid_client" {
                metrics.oauth_failed_authentications.inc();
            }
            return Err(err);
        }
    };

    // RFC 7009 §4.1.2: if token_type_hint is unrecognized or the token isn't
    // found under the hinted type, the server MUST extend its search across
    // all supported token types. We ignore the hint for ordering (try access
    // first, then refresh) because both lookups are cheap and correct.
    let by_access = token_actor
        .route(&form.token)
        .send(LookupToken {
            token: form.token.clone(),
            span: tracing::Span::current(),
        })
        .await
        .map_err(|e| OAuth2Error::new("server_error", Some(&e.to_string())))??;

    let token = if by_access.is_some() {
        by_access
    } else {
        token_actor
            .route(&form.token)
            .send(crate::actors::LookupRefreshToken {
                refresh_token: form.token.clone(),
                span: tracing::Span::current(),
            })
            .await
            .map_err(|e| OAuth2Error::new("server_error", Some(&e.to_string())))??
    };

    match token {
        Some(token) if token.client_id == caller.client_id => {
            token_actor
                .route(&form.token)
                .send(RevokeToken {
                    token: form.token.clone(),
                    span: tracing::Span::current(),
                })
                .await
                .map_err(|e| OAuth2Error::new("server_error", Some(&e.to_string())))??;
            metrics.oauth_token_revoked_total.inc();
        }
        Some(token) => {
            tracing::warn!(
                caller_client_id = %caller.client_id,
                token_client_id = %token.client_id,
                "Authenticated caller attempted to revoke a token owned by another client"
            );
        }
        None => {
            // Token not found in storage. RFC 7009 §2.2 requires 200 OK
            // regardless, but still forward to RevokeToken so that any
            // stale entry in a local/distributed cache is evicted. The
            // underlying db.revoke_token() is idempotent.
            tracing::debug!(
                token_type_hint = ?form.token_type_hint,
                "Revocation request for token not found in storage; evicting caches"
            );
            let _ = token_actor
                .route(&form.token)
                .send(RevokeToken {
                    token: form.token.clone(),
                    span: tracing::Span::current(),
                })
                .await;
        }
    }

    Ok(no_store_headers(HttpResponse::Ok().finish()))
}
