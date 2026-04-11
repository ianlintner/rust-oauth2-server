use actix::Addr;
use actix_session::Session;
use actix_web::{web, HttpRequest, HttpResponse, Result};
use base64::{engine::general_purpose, Engine as _};
use percent_encoding::percent_decode_str;
use serde::Deserialize;
use std::collections::{HashMap, HashSet};
use subtle::ConstantTimeEq;
use url::{form_urlencoded, Url};
use uuid::Uuid;

use oauth2_observability::Metrics;

use crate::actors::{
    AuthActor, ClientActor, CreateAuthorizationCode, CreateToken, GetClient,
    MarkAuthorizationCodeUsed, TokenActorPool, ValidateAuthorizationCode, ValidateRefreshToken,
};
use crate::handlers::wellknown::OidcConfig;
use oauth2_core::{IdTokenClaims, OAuth2Error, TokenResponse};

/// Parse RFC6749 client authentication via HTTP Basic.
///
/// Header format (RFC7617): `Authorization: Basic base64(client_id:client_secret)`
pub(crate) fn parse_client_basic_auth(
    req: &HttpRequest,
) -> Result<Option<(String, String)>, OAuth2Error> {
    let header = match req.headers().get(actix_web::http::header::AUTHORIZATION) {
        Some(h) => h,
        None => return Ok(None),
    };
    let header = header
        .to_str()
        .map_err(|_| OAuth2Error::invalid_request("Invalid Authorization header"))?;

    let b64 = match header.strip_prefix("Basic ") {
        Some(v) => v.trim(),
        None => return Ok(None),
    };

    let decoded = general_purpose::STANDARD
        .decode(b64)
        .map_err(|_| OAuth2Error::invalid_request("Invalid Basic auth encoding"))?;
    let decoded = String::from_utf8(decoded)
        .map_err(|_| OAuth2Error::invalid_request("Invalid Basic auth bytes"))?;

    let (client_id, client_secret) = decoded
        .split_once(':')
        .ok_or_else(|| OAuth2Error::invalid_request("Invalid Basic auth format"))?;

    if client_id.is_empty() {
        return Err(OAuth2Error::invalid_request("Missing client_id"));
    }
    if client_secret.is_empty() {
        return Err(OAuth2Error::invalid_client("Missing client_secret"));
    }

    // RFC 6749 §2.3.1: credentials are application/x-www-form-urlencoded before
    // being combined and base64-encoded.  Decode percent-encoded chars so the
    // values match what is stored in the database.
    let client_id = percent_decode_str(client_id)
        .decode_utf8()
        .map_err(|_| OAuth2Error::invalid_request("Invalid client_id encoding"))?
        .into_owned();
    let client_secret = percent_decode_str(client_secret)
        .decode_utf8()
        .map_err(|_| OAuth2Error::invalid_request("Invalid client_secret encoding"))?
        .into_owned();

    Ok(Some((client_id, client_secret)))
}

fn validate_scope_subset(requested: &str, allowed: &str) -> Result<(), OAuth2Error> {
    let allowed_scopes: Vec<&str> = allowed
        .split_whitespace()
        .filter(|s| !s.is_empty())
        .collect();
    let requested_scopes: Vec<&str> = requested
        .split_whitespace()
        .filter(|s| !s.is_empty())
        .collect();

    if requested_scopes.is_empty() {
        return Err(OAuth2Error::invalid_scope("scope must not be empty"));
    }

    let all_allowed = requested_scopes.iter().all(|s| allowed_scopes.contains(s));

    if !all_allowed {
        return Err(OAuth2Error::invalid_scope(
            "requested scope exceeds client permissions",
        ));
    }

    Ok(())
}

pub(crate) fn client_secret_matches(client: &oauth2_core::Client, presented_secret: &str) -> bool {
    client
        .client_secret
        .as_bytes()
        .ct_eq(presented_secret.as_bytes())
        .into()
}

fn no_store_headers(mut resp: HttpResponse) -> HttpResponse {
    resp.headers_mut().insert(
        actix_web::http::header::CACHE_CONTROL,
        "no-store".parse().unwrap(),
    );
    resp.headers_mut()
        .insert(actix_web::http::header::PRAGMA, "no-cache".parse().unwrap());
    resp
}

fn auth_response_security_headers(mut resp: HttpResponse) -> HttpResponse {
    // These headers are aligned with OAuth 2.0 Security BCP and help with OAuch's
    // clickjacking/referrer leakage checks.
    resp.headers_mut().insert(
        actix_web::http::header::REFERRER_POLICY,
        "no-referrer".parse().unwrap(),
    );
    resp.headers_mut().insert(
        actix_web::http::header::X_FRAME_OPTIONS,
        "DENY".parse().unwrap(),
    );
    resp.headers_mut().insert(
        actix_web::http::header::CONTENT_SECURITY_POLICY,
        "frame-ancestors 'none'".parse().unwrap(),
    );
    resp.headers_mut().insert(
        actix_web::http::header::X_CONTENT_TYPE_OPTIONS,
        "nosniff".parse().unwrap(),
    );
    resp
}

fn ensure_no_duplicate_query_params(req: &HttpRequest) -> Result<(), OAuth2Error> {
    let mut seen: HashSet<String> = HashSet::new();
    for (k, _v) in form_urlencoded::parse(req.query_string().as_bytes()) {
        let key = k.into_owned();
        if !seen.insert(key) {
            return Err(OAuth2Error::invalid_request(
                "Duplicate query parameters are not allowed",
            ));
        }
    }
    Ok(())
}

fn parse_form_no_dupes(body: &web::Bytes) -> Result<HashMap<String, String>, OAuth2Error> {
    let mut map: HashMap<String, String> = HashMap::new();
    for (k, v) in form_urlencoded::parse(body) {
        let key = k.into_owned();
        let val = v.into_owned();
        if map.contains_key(&key) {
            return Err(OAuth2Error::invalid_request(
                "Duplicate form parameters are not allowed",
            ));
        }
        map.insert(key, val);
    }
    Ok(map)
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
    nonce: Option<String>,
}

/// OAuth2 authorize endpoint
/// Initiates the authorization code flow
pub async fn authorize(
    req: HttpRequest,
    query: web::Query<AuthorizeQuery>,
    session: Session,
    auth_actor: web::Data<Addr<AuthActor>>,
    client_actor: web::Data<Addr<ClientActor>>,
    metrics: web::Data<Metrics>,
) -> Result<HttpResponse, OAuth2Error> {
    // OAuch: reject duplicate parameters (prevents ambiguous parsing).
    ensure_no_duplicate_query_params(&req)?;

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

    // Require PKCE (S256 only). This follows OAuth 2.0 Security BCP guidance.
    let code_challenge = query
        .code_challenge
        .as_deref()
        .ok_or_else(|| OAuth2Error::invalid_request("Missing code_challenge"))?;
    let code_challenge_method = query
        .code_challenge_method
        .as_deref()
        .ok_or_else(|| OAuth2Error::invalid_request("Missing code_challenge_method"))?;
    if code_challenge_method != "S256" {
        return Err(OAuth2Error::invalid_request(
            "Only S256 code_challenge_method is supported",
        ));
    }
    if code_challenge.trim().is_empty() {
        return Err(OAuth2Error::invalid_request(
            "code_challenge must not be empty",
        ));
    }

    // --- User authentication gate ---
    // Check if there is an authenticated session. If not, save the current
    // authorize URL and redirect to the login page.
    let user_id: Option<String> = session.get("user_id").unwrap_or(None);
    let user_id = match user_id {
        Some(uid) => uid,
        None => {
            // Persist the full authorize URL so we can replay after login.
            let return_to = format!("/oauth/authorize?{}", req.query_string());
            session
                .insert("return_to", &return_to)
                .map_err(|e| OAuth2Error::new("server_error", Some(&e.to_string())))?;

            return Ok(auth_response_security_headers(
                HttpResponse::Found()
                    .append_header(("Location", "/auth/login"))
                    .finish(),
            ));
        }
    };

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
            nonce: query.nonce.clone(),
            span: tracing::Span::current(),
        })
        .await
        .map_err(|e| OAuth2Error::new("server_error", Some(&e.to_string())))??;

    metrics.oauth_authorization_codes_issued.inc();

    // Redirect back to client with code (and optional state) while safely preserving existing query.
    let mut url = Url::parse(&query.redirect_uri)
        .map_err(|_| OAuth2Error::invalid_request("Invalid redirect_uri"))?;
    if url.fragment().is_some() {
        return Err(OAuth2Error::invalid_request(
            "redirect_uri must not contain a fragment",
        ));
    }
    {
        let mut qp = url.query_pairs_mut();
        qp.append_pair("code", &auth_code.code);
        if let Some(state) = &query.state {
            qp.append_pair("state", state);
        }
    }

    Ok(auth_response_security_headers(no_store_headers(
        HttpResponse::Found()
            .append_header(("Location", url.to_string()))
            .finish(),
    )))
}

#[derive(Debug, Deserialize)]
pub struct TokenRequest {
    grant_type: String,
    code: Option<String>,
    redirect_uri: Option<String>,
    client_id: String,
    client_secret: Option<String>,
    refresh_token: Option<String>,
    #[allow(dead_code)] // OAuth2 password grant, intentionally disabled by default
    username: Option<String>,
    #[allow(dead_code)] // OAuth2 password grant, intentionally disabled by default
    password: Option<String>,
    scope: Option<String>,
    code_verifier: Option<String>,
}

/// OAuth2 token endpoint
/// Exchanges authorization code for access token
pub async fn token(
    req: HttpRequest,
    body: web::Bytes,
    token_actor: web::Data<TokenActorPool>,
    client_actor: web::Data<Addr<ClientActor>>,
    auth_actor: web::Data<Addr<AuthActor>>,
    metrics: web::Data<Metrics>,
    oidc_config: web::Data<OidcConfig>,
) -> Result<HttpResponse, OAuth2Error> {
    // OAuch: reject duplicate parameters (prevents parser differentials / smuggling).
    ensure_no_duplicate_query_params(&req)?;
    let form_map = parse_form_no_dupes(&body)?;

    // Support confidential client auth via either:
    // - client_secret_post (body)
    // - client_secret_basic (Authorization header)
    let basic = parse_client_basic_auth(&req)?;
    let basic_client_id = basic.as_ref().map(|(id, _)| id.clone());
    let basic_client_secret = basic.as_ref().map(|(_, s)| s.clone());

    let body_client_id = form_map.get("client_id").cloned();
    let body_client_secret = form_map.get("client_secret").cloned();

    // If both are present, require they match to avoid ambiguous credentials.
    if let (Some(ref body_id), Some(ref basic_id)) = (&body_client_id, &basic_client_id) {
        if body_id != basic_id {
            return Err(OAuth2Error::invalid_request(
                "client_id mismatch between body and Basic auth",
            ));
        }
    }
    if let (Some(ref body_secret), Some(ref basic_secret)) =
        (&body_client_secret, &basic_client_secret)
    {
        if body_secret != basic_secret {
            // Treat secret mismatches as invalid_client to avoid information leaks.
            return Err(OAuth2Error::invalid_client(
                "client_secret mismatch between body and Basic auth",
            ));
        }
    }

    let client_id = body_client_id
        .or(basic_client_id)
        .ok_or_else(|| OAuth2Error::invalid_request("Missing client_id"))?;
    let client_secret = body_client_secret.or(basic_client_secret);

    let form = TokenRequest {
        grant_type: form_map
            .get("grant_type")
            .cloned()
            .ok_or_else(|| OAuth2Error::invalid_request("Missing grant_type"))?,
        code: form_map.get("code").cloned(),
        redirect_uri: form_map.get("redirect_uri").cloned(),
        client_id,
        client_secret,
        refresh_token: form_map.get("refresh_token").cloned(),
        username: form_map.get("username").cloned(),
        password: form_map.get("password").cloned(),
        scope: form_map.get("scope").cloned(),
        code_verifier: form_map.get("code_verifier").cloned(),
    };

    match form.grant_type.as_str() {
        "authorization_code" => {
            handle_authorization_code_grant(
                form,
                token_actor,
                client_actor,
                auth_actor,
                metrics,
                oidc_config,
            )
            .await
        }
        "client_credentials" => {
            handle_client_credentials_grant(form, token_actor, client_actor, metrics).await
        }
        "refresh_token" => {
            handle_refresh_token_grant(form, token_actor, client_actor, metrics).await
        }
        // Password grant is intentionally disabled by default
        // (OAuth 2.0 Security BCP).
        "password" => Err(OAuth2Error::unsupported_grant_type("Grant type disabled")),
        _ => Err(OAuth2Error::unsupported_grant_type(&format!(
            "Grant type '{}' not supported",
            form.grant_type
        ))),
    }
}

async fn handle_authorization_code_grant(
    req: TokenRequest,
    token_actor: web::Data<TokenActorPool>,
    client_actor: web::Data<Addr<ClientActor>>,
    auth_actor: web::Data<Addr<AuthActor>>,
    metrics: web::Data<Metrics>,
    oidc_config: web::Data<OidcConfig>,
) -> Result<HttpResponse, OAuth2Error> {
    let code = req
        .code
        .ok_or_else(|| OAuth2Error::invalid_request("Missing code"))?;

    if matches!(req.redirect_uri.as_deref(), Some("")) {
        return Err(OAuth2Error::invalid_request(
            "redirect_uri must not be empty",
        ));
    }

    // Validate authorization code
    let auth_code = auth_actor
        .send(ValidateAuthorizationCode {
            code: code.clone(),
            client_id: req.client_id.clone(),
            redirect_uri: req.redirect_uri,
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
            if !client_secret_matches(&client, &secret) {
                return Err(OAuth2Error::invalid_client("Invalid client_secret"));
            }
        }
        None => {
            // Require client authentication for the token endpoint.
            return Err(OAuth2Error::invalid_client("Missing client_secret"));
        }
    }

    // Only consume (burn) the authorization code after we've authenticated/authorized the client.
    // This prevents invalid_client errors from exhausting valid codes.
    auth_actor
        .send(MarkAuthorizationCodeUsed {
            code,
            user_id: Some(auth_code.user_id.clone()),
            client_id: Some(auth_code.client_id.clone()),
            span: tracing::Span::current(),
        })
        .await
        .map_err(|e| OAuth2Error::new("server_error", Some(&e.to_string())))??;

    // Create token — only include a refresh token when the client is authorized
    // to use the refresh_token grant and the `offline_access` scope was requested
    // (or the client explicitly supports refresh_token without scope restriction).
    let include_refresh = client.supports_grant_type("refresh_token");
    let token_family = if include_refresh {
        Some(Uuid::new_v4().to_string())
    } else {
        None
    };
    let token = token_actor
        .route(&auth_code.client_id)
        .send(CreateToken {
            user_id: Some(auth_code.user_id.clone()),
            client_id: auth_code.client_id.clone(),
            scope: auth_code.scope.clone(),
            include_refresh,
            token_family,
            span: tracing::Span::current(),
        })
        .await
        .map_err(|e| OAuth2Error::new("server_error", Some(&e.to_string())))??;

    metrics.oauth_token_issued_total.inc();

    let mut response = TokenResponse::from(token.clone());

    // Generate OIDC id_token when `openid` scope was requested
    if auth_code.scope.split_whitespace().any(|s| s == "openid") {
        let mut id_claims = IdTokenClaims::new(
            &oidc_config.issuer,
            auth_code.user_id,
            auth_code.client_id,
            3600, // same lifetime as access token
            Some(&token.access_token),
        );
        id_claims.nonce = auth_code.nonce.clone();
        // Compute c_hash: left half of SHA-256 of the authorization code, base64url-encoded
        // (OIDC Core §3.3.2.11)
        {
            use sha2::{Digest, Sha256};
            let hash = Sha256::digest(auth_code.code.as_bytes());
            id_claims.c_hash = Some(general_purpose::URL_SAFE_NO_PAD.encode(&hash[..16]));
        }

        let id_token = if oidc_config.id_token_alg.eq_ignore_ascii_case("RS256") {
            let pem = oidc_config
                .id_token_private_key_pem
                .as_deref()
                .ok_or_else(|| {
                    OAuth2Error::new("server_error", Some("RS256 configured but key missing"))
                })?;
            id_claims
                .encode_rs256(pem, oidc_config.id_token_kid.as_deref())
                .map_err(|e| OAuth2Error::new("server_error", Some(&e.to_string())))?
        } else {
            id_claims
                .encode(&oidc_config.jwt_secret)
                .map_err(|e| OAuth2Error::new("server_error", Some(&e.to_string())))?
        };
        response = response.with_id_token(id_token);
    }

    Ok(no_store_headers(HttpResponse::Ok().json(response)))
}

async fn handle_client_credentials_grant(
    req: TokenRequest,
    token_actor: web::Data<TokenActorPool>,
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
    if !client_secret_matches(&client, &client_secret) {
        return Err(OAuth2Error::invalid_client("Invalid client_secret"));
    }

    let scope = req.scope.unwrap_or_else(|| "read".to_string());

    validate_scope_subset(&scope, &client.scope)?;

    // Create token (no user, client-only)
    let token = token_actor
        .route(&req.client_id)
        .send(CreateToken {
            user_id: None,
            client_id: req.client_id,
            scope,
            include_refresh: false,
            token_family: None,
            span: tracing::Span::current(),
        })
        .await
        .map_err(|e| OAuth2Error::new("server_error", Some(&e.to_string())))??;

    metrics.oauth_token_issued_total.inc();

    Ok(no_store_headers(
        HttpResponse::Ok().json(TokenResponse::from(token)),
    ))
}

/// RFC 6749 §6 — Refresh Token Grant
///
/// Exchanges a valid, non-revoked refresh token for a fresh access + refresh token pair.
/// Supports optional scope down-scoping: the requested scope must be a subset of the
/// original scope bound to the refresh token.
async fn handle_refresh_token_grant(
    req: TokenRequest,
    token_actor: web::Data<TokenActorPool>,
    client_actor: web::Data<Addr<ClientActor>>,
    metrics: web::Data<Metrics>,
) -> Result<HttpResponse, OAuth2Error> {
    let refresh_token_str = req
        .refresh_token
        .ok_or_else(|| OAuth2Error::invalid_request("Missing refresh_token"))?;

    // Authenticate the client.
    let client = client_actor
        .send(GetClient {
            client_id: req.client_id.clone(),
            span: tracing::Span::current(),
        })
        .await
        .map_err(|e| OAuth2Error::new("server_error", Some(&e.to_string())))??;

    let client_secret = req
        .client_secret
        .ok_or_else(|| OAuth2Error::invalid_client("Missing client_secret"))?;
    if !client_secret_matches(&client, &client_secret) {
        return Err(OAuth2Error::invalid_client("Invalid client_secret"));
    }

    // Verify the client is authorized to use the refresh_token grant type.
    if !client.supports_grant_type("refresh_token") {
        return Err(OAuth2Error::unauthorized_client(
            "Client is not allowed to use refresh_token",
        ));
    }

    // Look up the refresh token via the actor (DB round-trip).
    let old_token = token_actor
        .route(&req.client_id)
        .send(ValidateRefreshToken {
            refresh_token: refresh_token_str,
            span: tracing::Span::current(),
        })
        .await
        .map_err(|e| OAuth2Error::new("server_error", Some(&e.to_string())))??;

    // The refresh token must belong to the authenticating client.
    if old_token.client_id != req.client_id {
        return Err(OAuth2Error::invalid_grant(
            "Refresh token does not belong to this client",
        ));
    }

    // Determine scope: if the request includes a scope, it must be a subset of the
    // original token's scope. If omitted, inherit the original scope.
    let scope = match req.scope {
        Some(ref requested) => {
            validate_scope_subset(requested, &old_token.scope)?;
            requested.clone()
        }
        None => old_token.scope.clone(),
    };

    // Propagate the token family UUID so replay detection can revoke the entire chain.
    // On first rotation the old token has no family yet — start a new one and persist
    // it onto the old token record BEFORE revoking so that a later replay of the
    // revoked token can still look up the family and revoke the new token.
    let family = match old_token.token_family.clone() {
        Some(f) => f,
        None => {
            let new_family = uuid::Uuid::new_v4().to_string();
            // Best-effort: set the family on the old token so replay detection works.
            let _ = token_actor
                .route(&req.client_id)
                .send(crate::actors::SetTokenFamily {
                    access_token: old_token.access_token.clone(),
                    family: new_family.clone(),
                    span: tracing::Span::current(),
                })
                .await;
            new_family
        }
    };

    // Revoke the old token (access + refresh).
    token_actor
        .route(&req.client_id)
        .send(crate::actors::RevokeToken {
            token: old_token.access_token.clone(),
            span: tracing::Span::current(),
        })
        .await
        .map_err(|e| OAuth2Error::new("server_error", Some(&e.to_string())))??;

    // Mint new access + refresh token pair.
    let token = token_actor
        .route(&req.client_id)
        .send(CreateToken {
            user_id: old_token.user_id.clone(),
            client_id: req.client_id,
            scope,
            include_refresh: true,
            token_family: Some(family),
            span: tracing::Span::current(),
        })
        .await
        .map_err(|e| OAuth2Error::new("server_error", Some(&e.to_string())))??;

    metrics.oauth_token_issued_total.inc();

    Ok(no_store_headers(
        HttpResponse::Ok().json(TokenResponse::from(token)),
    ))
}
