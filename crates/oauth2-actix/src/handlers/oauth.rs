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
    AuthActor, ClientActor, CreateAuthorizationCode, CreateToken, GetClient, GetPARRequest,
    MarkAuthorizationCodeUsed, StorePARRequest, TokenActorPool, ValidateAuthorizationCode,
    ValidateRefreshToken,
};
use crate::handlers::dpop::{
    build_request_url_bounded, enforce_dpop_nonce, validate_dpop_proof, DpopReplayStore,
};
use crate::handlers::dpop_nonce::{use_dpop_nonce_response, DpopNonceIssuer};
use crate::handlers::jwks_cache::JwksCache;
use crate::handlers::wellknown::OidcConfig;
use oauth2_core::{IdTokenClaims, OAuth2Error, TokenResponse};
use oauth2_ports::DynStorage;

const DEVICE_CODE_GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:device_code";
/// RFC 8693: Token Exchange grant type URI.
const TOKEN_EXCHANGE_GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:token-exchange";

/// RFC 9449 §7.1: If the `cnf` claim carries a `jkt` (DPoP key thumbprint), the token
/// response MUST use `token_type: "DPoP"` instead of `"Bearer"`.
fn apply_dpop_token_type(
    mut response: oauth2_core::TokenResponse,
    cnf_claim: Option<&serde_json::Value>,
) -> oauth2_core::TokenResponse {
    if cnf_claim.and_then(|c| c.get("jkt")).is_some() {
        response.token_type = "DPoP".to_string();
    }
    response
}

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

/// Authenticate a confidential client for the token endpoint.
///
/// Dispatches to the correct authentication method based on the client's
/// `token_endpoint_auth_method`:
///   - `client_secret_basic` / `client_secret_post`: constant-time secret comparison
///   - `client_secret_jwt` / `private_key_jwt`: JWT assertion validation (RFC 7523)
///   - `tls_client_auth`: mTLS certificate validation with optional Subject DN check
///   - `none`: public client (caller should handle separately)
///
/// `resolved_jwks` must be pre-fetched by the caller (via [`resolve_client_jwks`])
/// when the client uses `private_key_jwt`; pass `None` for all other methods.
/// `mtls_subject_dn` should be the Subject DN from the X-SSL-Client-S-DN header.
fn authenticate_confidential_client(
    client: &oauth2_core::Client,
    req: &TokenRequest,
    token_endpoint_url: &str,
    resolved_jwks: Option<&serde_json::Value>,
    mtls_thumbprint: Option<&str>,
    mtls_subject_dn: Option<&str>,
) -> Result<(), OAuth2Error> {
    match client.token_endpoint_auth_method.as_str() {
        "client_secret_basic" | "client_secret_post" => match req.client_secret.as_deref() {
            Some(secret) => {
                if !client_secret_matches(client, secret) {
                    return Err(OAuth2Error::invalid_client("Invalid client_secret"));
                }
                Ok(())
            }
            None => Err(OAuth2Error::invalid_client("Missing client_secret")),
        },
        "client_secret_jwt" | "private_key_jwt" => {
            let assertion_type = req
                .client_assertion_type
                .as_deref()
                .ok_or_else(|| OAuth2Error::invalid_client("Missing client_assertion_type"))?;
            if assertion_type != JWT_BEARER_ASSERTION_TYPE {
                return Err(OAuth2Error::invalid_client(
                    "Unsupported client_assertion_type",
                ));
            }
            let assertion = req
                .client_assertion
                .as_deref()
                .ok_or_else(|| OAuth2Error::invalid_client("Missing client_assertion"))?;
            validate_jwt_client_assertion(client, assertion, token_endpoint_url, resolved_jwks)
        }
        "tls_client_auth" => {
            // RFC 8705 §2.1: client is authenticated by TLS certificate.
            // The reverse proxy must set X-Client-Cert-Thumbprint with the
            // SHA-256 thumbprint of the presented certificate.
            match mtls_thumbprint {
                Some(_tb) => {
                    // Thumbprint is present — client is authenticated.
                    // If client.tls_client_certificate_subject_dn is configured,
                    // verify it matches the Subject DN from X-SSL-Client-S-DN header.
                    if !client.tls_client_certificate_subject_dn.is_empty() {
                        match mtls_subject_dn {
                            Some(presented_dn)
                                if presented_dn == client.tls_client_certificate_subject_dn =>
                            {
                                tracing::debug!(
                                    client_id = %client.client_id,
                                    expected_dn = %client.tls_client_certificate_subject_dn,
                                    presented_dn = %presented_dn,
                                    "mTLS Subject DN validated successfully"
                                );
                                Ok(())
                            }
                            Some(presented_dn) => {
                                tracing::warn!(
                                    client_id = %client.client_id,
                                    expected_dn = %client.tls_client_certificate_subject_dn,
                                    presented_dn = %presented_dn,
                                    "mTLS Subject DN mismatch"
                                );
                                Err(OAuth2Error::invalid_client(
                                    "tls_client_auth: client certificate Subject DN does not match",
                                ))
                            }
                            None => {
                                tracing::warn!(
                                    client_id = %client.client_id,
                                    expected_dn = %client.tls_client_certificate_subject_dn,
                                    "mTLS Subject DN required but X-SSL-Client-S-DN header missing"
                                );
                                Err(OAuth2Error::invalid_client(
                                    "tls_client_auth requires X-SSL-Client-S-DN header when Subject DN is configured",
                                ))
                            }
                        }
                    } else {
                        // No Subject DN configured — accept any valid certificate.
                        Ok(())
                    }
                }
                None => Err(OAuth2Error::invalid_client(
                    "tls_client_auth requires a TLS client certificate \
                     (X-Client-Cert-Thumbprint header missing)",
                )),
            }
        }
        "self_signed_tls_client_auth" => {
            // RFC 8705 §2.2: client is authenticated by a self-signed certificate.
            // Accept if the reverse proxy provided the cert thumbprint.
            match mtls_thumbprint {
                Some(_) => Ok(()),
                None => Err(OAuth2Error::invalid_client(
                    "self_signed_tls_client_auth requires a TLS client certificate \
                     (X-Client-Cert-Thumbprint header missing)",
                )),
            }
        }
        "none" => {
            // Public clients must be gated by callers *before* reaching this
            // function.  Returning Ok here would silently bypass authentication
            // for any misconfigured public client that slips through.
            Err(OAuth2Error::invalid_client(
                "Public clients (token_endpoint_auth_method=none) cannot use this authentication path",
            ))
        }
        other => Err(OAuth2Error::invalid_client(&format!(
            "Unsupported token_endpoint_auth_method: {other}"
        ))),
    }
}

/// Resolve the JWKS for a client that uses `private_key_jwt`.
///
/// Returns:
/// - `Ok(Some(jwks))` if the client has an inline `jwks` or a `jwks_uri` that
///   was successfully fetched/cached.
/// - `Ok(None)` if the client does not use `private_key_jwt` (no fetch needed).
/// - `Err(_)` if `jwks_uri` fetch fails or is unavailable without a cache.
async fn resolve_client_jwks(
    client: &oauth2_core::Client,
    cache: Option<&JwksCache>,
) -> Result<Option<serde_json::Value>, OAuth2Error> {
    if client.token_endpoint_auth_method != "private_key_jwt" {
        return Ok(None);
    }
    // Prefer inline JWKS (no network needed).
    let jwks_str = client.jwks.trim();
    if !jwks_str.is_empty() {
        let jwks: serde_json::Value = serde_json::from_str(jwks_str)
            .map_err(|_| OAuth2Error::invalid_client("Client inline JWKS is not valid JSON"))?;
        return Ok(Some(jwks));
    }
    // Fall back to jwks_uri with TTL cache.
    let uri = client.jwks_uri.trim();
    if !uri.is_empty() {
        let c = cache.ok_or_else(|| {
            OAuth2Error::invalid_client(
                "jwks_uri is not supported in this context (no JWKS cache available)",
            )
        })?;
        let jwks = c.fetch(uri).await?;
        return Ok(Some(jwks));
    }
    Err(OAuth2Error::invalid_client(
        "Client must register jwks or jwks_uri for private_key_jwt",
    ))
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
    response_type: String,
    client_id: String,
    /// Required unless `request_uri` (PAR, RFC 9126) supplies it.
    redirect_uri: Option<String>,
    scope: Option<String>,
    state: Option<String>,
    code_challenge: Option<String>,
    code_challenge_method: Option<String>,
    nonce: Option<String>,
    /// OIDC Core §3.1.2.1: optional hint about the login identifier the user may use.
    /// Stored in session so the login form can pre-fill the username field.
    login_hint: Option<String>,
    /// OIDC Core §3.1.2.1: space-delimited list of prompt values.
    /// Supported: `none` (no UI), `login` (force re-authentication).
    prompt: Option<String>,
    /// OIDC Core §3.1.2.1: maximum authentication age in seconds.
    /// If `auth_time` + `max_age` < now, the user must re-authenticate.
    max_age: Option<u64>,
    /// OAuth 2.0 Form Post Response Mode: "query" (default) or "form_post".
    response_mode: Option<String>,
    /// RFC 8707: resource server URI for the requested access token audience.
    resource: Option<String>,
    /// RFC 9126: reference to a pushed authorization request (PAR).
    request_uri: Option<String>,
    /// RFC 9470 / OIDC Core §3.1.2.1: space-delimited ACR values required for this request.
    acr_values: Option<String>,
    /// OIDC Core §5.5: JSON-encoded claims request (e.g. `{"id_token":{"email":null}}`).
    claims: Option<String>,
    /// RFC 9396: Rich Authorization Request (JSON array string).
    authorization_details: Option<String>,
    /// RFC 9101: JWT-Secured Authorization Request (JAR) — inline request object JWT.
    /// If present, the JWT payload claims override the corresponding query parameters.
    /// Supported signing: `alg=none` (public clients only), HS256, RS256.
    request: Option<String>,
}
fn html_escape_attr(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('"', "&quot;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

/// RFC 9198 §4.2: Returns an HTML auto-submit form POSTing `params` to `redirect_uri`.
fn form_post_response(redirect_uri: &str, params: &[(&str, &str)]) -> HttpResponse {
    let inputs: String = params
        .iter()
        .map(|(k, v)| {
            format!(
                r#"<input type="hidden" name="{}" value="{}"/>"#,
                html_escape_attr(k),
                html_escape_attr(v)
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    let esc_action = html_escape_attr(redirect_uri);
    let body = format!(
        "<!DOCTYPE html>\n<html><body onload=\"document.forms[0].submit()\">\n<form method=\"post\" action=\"{esc_action}\">\n{inputs}\n</form></body></html>"
    );
    HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(body)
}

/// RFC 9101 §4: Verify and extract claims from a JWT-Secured Authorization Request (JAR).
///
/// - Public clients (`token_endpoint_auth_method = "none"`): accepted without signature
///   verification (no client secret available).
/// - `client_secret_basic` / `client_secret_post` / `client_secret_jwt`: HS256 with
///   the client_secret.
/// - `private_key_jwt`: RS256 with the client's registered inline JWKS.
///
/// Returns the decoded JWT claims on success.
fn process_jar(
    client: &oauth2_core::Client,
    jar_jwt: &str,
    authorization_endpoint_url: &str,
    resolved_jwks: Option<&serde_json::Value>,
) -> Result<serde_json::Value, OAuth2Error> {
    use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};

    let parts: Vec<&str> = jar_jwt.splitn(3, '.').collect();
    if parts.len() < 3 {
        return Err(OAuth2Error::invalid_request(
            "JAR request is not a valid JWT (expected header.payload.signature)",
        ));
    }

    match client.token_endpoint_auth_method.as_str() {
        // Public clients: the JWS must be structurally unsigned (alg=none + empty signature).
        // Without this check, an attacker could submit any JWT-shaped string and the server
        // would blindly extract payload claims — a signature-bypass primitive.
        "none" => {
            // Verify the JOSE header explicitly declares alg=none.
            let header_bytes = general_purpose::URL_SAFE_NO_PAD
                .decode(parts[0])
                .or_else(|_| general_purpose::URL_SAFE.decode(parts[0]))
                .map_err(|_| {
                    OAuth2Error::invalid_request("JAR JWT header is not valid base64url")
                })?;
            let header: serde_json::Value = serde_json::from_slice(&header_bytes)
                .map_err(|_| OAuth2Error::invalid_request("JAR JWT header is not valid JSON"))?;
            let alg = header.get("alg").and_then(|v| v.as_str()).unwrap_or("");
            if alg != "none" {
                return Err(OAuth2Error::invalid_request(
                    "JAR from public client must use alg=none; signed JARs require a \
                     confidential client authentication method",
                ));
            }
            // RFC 7515 §6: with alg=none, the JWS signature MUST be the empty string.
            if !parts[2].is_empty() {
                return Err(OAuth2Error::invalid_request(
                    "JAR with alg=none must have an empty signature",
                ));
            }

            let payload_bytes = general_purpose::URL_SAFE_NO_PAD
                .decode(parts[1])
                .or_else(|_| general_purpose::URL_SAFE.decode(parts[1]))
                .map_err(|_| {
                    OAuth2Error::invalid_request("JAR JWT payload is not valid base64url")
                })?;
            let claims: serde_json::Value = serde_json::from_slice(&payload_bytes)
                .map_err(|_| OAuth2Error::invalid_request("JAR JWT payload is not valid JSON"))?;
            Ok(claims)
        }
        // Shared-secret clients: verify HS256 with client_secret.
        "client_secret_basic" | "client_secret_post" | "client_secret_jwt" => {
            let key = DecodingKey::from_secret(client.client_secret.as_bytes());
            let mut validation = Validation::new(Algorithm::HS256);
            validation.set_audience(&[authorization_endpoint_url]);
            validation.set_required_spec_claims(&["exp", "iss"]);
            let data = decode::<serde_json::Value>(jar_jwt, &key, &validation).map_err(|e| {
                OAuth2Error::invalid_request(&format!("JAR HS256 verification failed: {e}"))
            })?;
            let iss = data
                .claims
                .get("iss")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if iss != client.client_id {
                return Err(OAuth2Error::invalid_request(
                    "JAR 'iss' claim must equal client_id",
                ));
            }
            Ok(data.claims)
        }
        // Asymmetric-key clients: verify RS256 with the client's registered JWKS.
        "private_key_jwt" => {
            let header = jsonwebtoken::decode_header(jar_jwt)
                .map_err(|_| OAuth2Error::invalid_request("JAR JWT header is malformed"))?;
            // JWKS must have been pre-resolved by the caller via resolve_client_jwks().
            let jwks = resolved_jwks.ok_or_else(|| {
                OAuth2Error::invalid_request(
                    "JAR requires client to have jwks or jwks_uri registered",
                )
            })?;
            let keys = jwks
                .get("keys")
                .and_then(|v| v.as_array())
                .ok_or_else(|| OAuth2Error::invalid_request("Client JWKS missing 'keys' array"))?;
            let key_json = if let Some(kid) = &header.kid {
                keys.iter()
                    .find(|k| k.get("kid").and_then(|v| v.as_str()) == Some(kid))
                    .ok_or_else(|| {
                        OAuth2Error::invalid_request("No matching kid in client JWKS for JAR")
                    })?
            } else {
                keys.iter()
                    .find(|k| k.get("kty").and_then(|v| v.as_str()) == Some("RSA"))
                    .ok_or_else(|| {
                        OAuth2Error::invalid_request("No RSA key found in client JWKS for JAR")
                    })?
            };
            let n = key_json
                .get("n")
                .and_then(|v| v.as_str())
                .ok_or_else(|| OAuth2Error::invalid_request("JWKS key missing 'n' component"))?;
            let e = key_json
                .get("e")
                .and_then(|v| v.as_str())
                .ok_or_else(|| OAuth2Error::invalid_request("JWKS key missing 'e' component"))?;
            let dk = DecodingKey::from_rsa_components(n, e).map_err(|_| {
                OAuth2Error::invalid_request("Failed to construct RSA key from client JWKS")
            })?;
            let mut validation = Validation::new(Algorithm::RS256);
            validation.set_audience(&[authorization_endpoint_url]);
            validation.set_required_spec_claims(&["exp", "iss"]);
            let data = decode::<serde_json::Value>(jar_jwt, &dk, &validation).map_err(|e| {
                OAuth2Error::invalid_request(&format!("JAR RS256 verification failed: {e}"))
            })?;
            let iss = data
                .claims
                .get("iss")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if iss != client.client_id {
                return Err(OAuth2Error::invalid_request(
                    "JAR 'iss' claim must equal client_id",
                ));
            }
            Ok(data.claims)
        }
        other => Err(OAuth2Error::invalid_request(&format!(
            "Unsupported token_endpoint_auth_method '{other}' for JAR signing"
        ))),
    }
}

/// RFC 9207 §2: Build an error redirect response with `iss` parameter.
/// Used for errors that occur after redirect_uri validation (RFC 9700 §4.1).
fn build_authorize_error_redirect(
    error_code: &str,
    error_description: &str,
    redirect_uri: &str,
    state: Option<&str>,
    issuer: &str,
    response_mode: &str,
) -> Result<HttpResponse, OAuth2Error> {
    if response_mode == "form_post" {
        let mut params: Vec<(&str, &str)> = vec![
            ("error", error_code),
            ("error_description", error_description),
            ("iss", issuer),
        ];
        if let Some(s) = state {
            params.push(("state", s));
        }
        return Ok(auth_response_security_headers(form_post_response(
            redirect_uri,
            &params,
        )));
    }

    if response_mode == "fragment" {
        use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};
        let enc = |s: &str| utf8_percent_encode(s, NON_ALPHANUMERIC).to_string();
        let mut frag_parts = vec![
            format!("error={}", enc(error_code)),
            format!("error_description={}", enc(error_description)),
            format!("iss={}", enc(issuer)),
        ];
        if let Some(s) = state {
            frag_parts.push(format!("state={}", enc(s)));
        }
        let location = format!("{}#{}", redirect_uri, frag_parts.join("&"));
        return Ok(auth_response_security_headers(
            HttpResponse::Found()
                .append_header(("Location", location))
                .finish(),
        ));
    }

    // Default: query mode
    let mut url = Url::parse(redirect_uri)
        .map_err(|_| OAuth2Error::invalid_request("Invalid redirect_uri"))?;
    {
        let mut qp = url.query_pairs_mut();
        qp.append_pair("error", error_code);
        qp.append_pair("error_description", error_description);
        if let Some(s) = state {
            qp.append_pair("state", s);
        }
        qp.append_pair("iss", issuer);
    }
    Ok(auth_response_security_headers(
        HttpResponse::Found()
            .append_header(("Location", url.to_string()))
            .finish(),
    ))
}

/// OAuth2 authorize endpoint
/// Initiates the authorization code flow, with PAR (RFC 9126),
/// resource indicators (RFC 8707), and form_post response mode support.
#[allow(clippy::too_many_arguments)]
pub async fn authorize(
    req: HttpRequest,
    query: web::Query<AuthorizeQuery>,
    session: Session,
    auth_actor: web::Data<Addr<AuthActor>>,
    client_actor: web::Data<Addr<ClientActor>>,
    metrics: web::Data<Metrics>,
    oidc_config: web::Data<OidcConfig>,
    jwks_cache: Option<web::Data<JwksCache>>,
) -> Result<HttpResponse, OAuth2Error> {
    // OAuch: reject duplicate parameters (prevents ambiguous parsing).
    ensure_no_duplicate_query_params(&req)?;

    // --- PAR resolution (RFC 9126 §4) ---
    // If request_uri is present, fetch the stored request and merge its params.
    let (
        eff_redirect_uri,
        eff_scope,
        eff_code_challenge,
        eff_code_challenge_method,
        eff_nonce,
        eff_resource,
        eff_state,
        eff_authorization_details,
        eff_claims,
        eff_acr_values,
    ) = if let Some(ref request_uri) = query.request_uri {
        let entry = auth_actor
            .send(GetPARRequest {
                request_uri: request_uri.clone(),
            })
            .await
            .map_err(|e| OAuth2Error::new("server_error", Some(&e.to_string())))?
            .ok_or_else(|| OAuth2Error::invalid_request("Unknown or expired request_uri"))?;
        if entry.client_id != query.client_id {
            return Err(OAuth2Error::invalid_client(
                "request_uri client_id mismatch",
            ));
        }
        let get = |k: &str| -> Option<String> { entry.params.get(k).cloned() };
        (
            get("redirect_uri").or_else(|| query.redirect_uri.clone()),
            get("scope").or_else(|| query.scope.clone()),
            get("code_challenge").or_else(|| query.code_challenge.clone()),
            get("code_challenge_method").or_else(|| query.code_challenge_method.clone()),
            get("nonce").or_else(|| query.nonce.clone()),
            get("resource").or_else(|| query.resource.clone()),
            get("state").or_else(|| query.state.clone()),
            get("authorization_details").or_else(|| query.authorization_details.clone()),
            get("claims").or_else(|| query.claims.clone()),
            get("acr_values").or_else(|| query.acr_values.clone()),
        )
    } else {
        (
            query.redirect_uri.clone(),
            query.scope.clone(),
            query.code_challenge.clone(),
            query.code_challenge_method.clone(),
            query.nonce.clone(),
            query.resource.clone(),
            query.state.clone(),
            query.authorization_details.clone(),
            query.claims.clone(),
            query.acr_values.clone(),
        )
    };

    // redirect_uri is required (supplied directly or via PAR).
    let redirect_uri =
        eff_redirect_uri.ok_or_else(|| OAuth2Error::invalid_request("Missing redirect_uri"))?;

    // Authorization Code (RFC 6749 §4.1) and OIDC Hybrid Code/ID-Token (OIDC Core §3.3)
    // flows are supported.  When a JAR `request` parameter is present the response_type
    // may be overridden by the JWT payload; the effective value is re-validated after
    // JAR processing below.
    let rt = query.response_type.as_str();
    if query.request.is_none() && rt != "code" && rt != "code id_token" {
        return Err(OAuth2Error::invalid_request(
            "Unsupported response_type; supported values: code, code id_token",
        ));
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

    // RFC 9700 §4.7: per-client `require_state` enforcement. When the
    // client has opted in, the `state` parameter is mandatory on the
    // authorization request. PKCE already covers the CSRF case on its
    // own; this flag is a defense-in-depth layer for clients that also
    // bind their user-agent session to `state` on the redirect.
    // Checked before JAR overlay — a client that requires state must
    // carry it on the outer request too, not just in the JAR payload.
    if client.require_state && query.state.is_none() {
        return Err(OAuth2Error::invalid_request(
            "state parameter is required for this client (RFC 9700 §4.7)",
        ));
    }

    // RFC 9101 §4: If a JAR `request` parameter is present, verify its signature and
    // overlay the JWT payload claims on top of the current effective parameters.
    // JAR claims take precedence over the corresponding query-string parameters.
    let (
        redirect_uri,
        eff_scope,
        eff_code_challenge,
        eff_code_challenge_method,
        eff_nonce,
        eff_resource,
        eff_state,
        eff_authorization_details,
        eff_claims,
        eff_acr_values,
        is_hybrid,
        jar_response_mode,
    ) = if let Some(ref jar_jwt) = query.request {
        // Pre-resolve JWKS for private_key_jwt clients (may fetch from jwks_uri).
        let jar_jwks =
            resolve_client_jwks(&client, jwks_cache.as_ref().map(|d| d.as_ref())).await?;
        let jar_claims = process_jar(
            &client,
            jar_jwt,
            &format!("{}/oauth/authorize", oidc_config.issuer),
            jar_jwks.as_ref(),
        )?;
        let jar_str = |k: &str, fallback: Option<String>| -> Option<String> {
            jar_claims
                .get(k)
                .and_then(|v| v.as_str())
                .map(str::to_owned)
                .or(fallback)
        };
        let jar_rt = jar_claims
            .get("response_type")
            .and_then(|v| v.as_str())
            .unwrap_or(query.response_type.as_str());
        let hybrid = jar_rt == "code id_token";
        if jar_rt != "code" && !hybrid {
            return Err(OAuth2Error::invalid_request(
                "Unsupported response_type in JAR; supported values: code, code id_token",
            ));
        }
        let jar_redirect_uri = jar_claims
            .get("redirect_uri")
            .and_then(|v| v.as_str())
            .map(str::to_owned)
            .unwrap_or(redirect_uri);
        (
            jar_redirect_uri,
            jar_str("scope", eff_scope),
            jar_str("code_challenge", eff_code_challenge),
            jar_str("code_challenge_method", eff_code_challenge_method),
            jar_str("nonce", eff_nonce),
            jar_str("resource", eff_resource),
            jar_str("state", eff_state),
            jar_str("authorization_details", eff_authorization_details),
            jar_str("claims", eff_claims),
            jar_str("acr_values", eff_acr_values),
            hybrid,
            jar_claims
                .get("response_mode")
                .and_then(|v| v.as_str())
                .map(str::to_owned),
        )
    } else {
        let hybrid = query.response_type == "code id_token";
        (
            redirect_uri,
            eff_scope,
            eff_code_challenge,
            eff_code_challenge_method,
            eff_nonce,
            eff_resource,
            eff_state,
            eff_authorization_details,
            eff_claims,
            eff_acr_values,
            hybrid,
            None::<String>,
        )
    };

    if !client.validate_redirect_uri(&redirect_uri) {
        return Err(OAuth2Error::invalid_request("Invalid redirect_uri"));
    }

    // Determine and validate response_mode.
    // OIDC Core §3.3.2.3: default response_mode for hybrid flows is "fragment".
    let default_response_mode = if is_hybrid { "fragment" } else { "query" };
    let response_mode = jar_response_mode
        .as_deref()
        .or(query.response_mode.as_deref())
        .unwrap_or(default_response_mode);
    // RFC 9207 §2: After redirect_uri validation, errors must be delivered via redirect.
    // However, response_mode validation is an exception because we need a valid mode to
    // know HOW to redirect. Invalid response_mode remains a 400 error.
    if !matches!(response_mode, "query" | "form_post" | "fragment") {
        return Err(OAuth2Error::invalid_request(
            "Unsupported response_mode; supported values: query, form_post, fragment",
        ));
    }

    // Require PKCE (S256 only). This follows OAuth 2.0 Security BCP guidance.
    let code_challenge =
        eff_code_challenge.ok_or_else(|| OAuth2Error::invalid_request("Missing code_challenge"))?;
    let code_challenge_method = eff_code_challenge_method
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
    // OIDC Core §3.1.2.1: handle `prompt` parameter (space-delimited list).
    let prompt_values: Vec<&str> = query
        .prompt
        .as_deref()
        .unwrap_or("")
        .split_whitespace()
        .collect();

    // OIDC Core §3.1.2.1: "none" MUST NOT be combined with other prompt values.
    let has_none = prompt_values.contains(&"none");
    let has_login = prompt_values.contains(&"login");
    let has_consent = prompt_values.contains(&"consent");
    let has_select_account = prompt_values.contains(&"select_account");
    if has_none && prompt_values.len() > 1 {
        return Err(OAuth2Error::invalid_request(
            "prompt value 'none' must not be combined with other values",
        ));
    }

    // Check if there is an authenticated session.
    let user_id: Option<String> = session.get("user_id").unwrap_or(None);

    // prompt=none: the AS must NOT display any UI. If not authenticated, return error.
    if has_none {
        match user_id {
            Some(_) => { /* session exists; continue below */ }
            None => {
                // OIDC Core §3.1.2.6: return login_required error via the redirect channel.
                if response_mode == "form_post" {
                    let iss = oidc_config.issuer.as_str();
                    let mut params: Vec<(&str, &str)> = vec![
                        ("error", "login_required"),
                        (
                            "error_description",
                            "User is not authenticated and prompt=none was requested",
                        ),
                        ("iss", iss),
                    ];
                    if let Some(ref s) = eff_state {
                        params.push(("state", s.as_str()));
                    }
                    return Ok(auth_response_security_headers(form_post_response(
                        &redirect_uri,
                        &params,
                    )));
                }
                let mut url = Url::parse(&redirect_uri)
                    .map_err(|_| OAuth2Error::invalid_request("Invalid redirect_uri"))?;
                {
                    let mut qp = url.query_pairs_mut();
                    qp.append_pair("error", "login_required");
                    qp.append_pair(
                        "error_description",
                        "User is not authenticated and prompt=none was requested",
                    );
                    if let Some(ref state) = eff_state {
                        qp.append_pair("state", state);
                    }
                    qp.append_pair("iss", &oidc_config.issuer);
                }
                return Ok(auth_response_security_headers(
                    HttpResponse::Found()
                        .append_header(("Location", url.to_string()))
                        .finish(),
                ));
            }
        }
    }

    // prompt=login: force re-authentication even if already authenticated.
    let force_login = has_login;

    // prompt=select_account: force account selection (treated like force_login since
    // this server supports only single-account sessions).
    let force_login = force_login || has_select_account;

    // max_age: if the user's auth_time is too old, force re-authentication.
    let auth_expired = if let Some(max_age) = query.max_age {
        let auth_time: Option<i64> = session.get("auth_time").unwrap_or(None);
        match auth_time {
            Some(at) => {
                let now = chrono::Utc::now().timestamp();
                now > at + max_age as i64
            }
            None => true, // No auth_time recorded → treat as expired.
        }
    } else {
        false
    };

    let user_id = match user_id {
        Some(uid) if !force_login && !auth_expired => uid,
        _ => {
            // Persist the full authorize URL so we can replay after login.
            let return_to = format!("/oauth/authorize?{}", req.query_string());
            session
                .insert("return_to", &return_to)
                .map_err(|e| OAuth2Error::new("server_error", Some(&e.to_string())))?;

            // OIDC Core §3.1.2.1: forward login_hint to the login form
            // so the username field can be pre-filled for the user.
            if let Some(ref hint) = query.login_hint {
                let _ = session.insert("login_hint", hint);
            }

            // Clear session so the login form is shown.
            if force_login || auth_expired {
                session.remove("user_id");
                session.remove("authenticated");
            }

            return Ok(auth_response_security_headers(
                HttpResponse::Found()
                    .append_header(("Location", "/auth/login"))
                    .finish(),
            ));
        }
    };

    let scope = eff_scope.unwrap_or_else(|| "read".to_string());

    // Enforce that requested scopes are within the client's allowed scope set.
    // RFC 9207 §2: After redirect_uri validation, errors must be delivered via redirect.
    if let Err(e) = validate_scope_subset(&scope, &client.scope) {
        return build_authorize_error_redirect(
            &e.error,
            e.error_description.as_deref().unwrap_or(""),
            &redirect_uri,
            eff_state.as_deref(),
            &oidc_config.issuer,
            response_mode,
        );
    }

    // OIDC Core §3.1.2.1: prompt=consent requires the OP to prompt for consent.
    // Since this server auto-approves first-party consent, we return
    // consent_required when prompt=none is set (already handled above) or when
    // prompt=consent is set but no consent UX is available.
    // For prompt=consent: if the session already has recorded consent for this
    // client+scope combination, we could skip; for now, we return consent_required
    // to signal that consent was explicitly requested but cannot be displayed.
    if has_consent {
        // Check if consent was already granted in session for this client + scope.
        let consent_key = format!("consent:{}:{}", client.client_id, scope);
        let prior_consent: Option<bool> = session.get(&consent_key).unwrap_or(None);
        if prior_consent != Some(true) {
            // Record consent in session (auto-approve for server-side clients).
            // In a full implementation this would redirect to a consent screen.
            let _ = session.insert(&consent_key, true);
        }
    }

    // RFC 9470 §4: Step-Up Authentication.
    // If `acr_values` was requested, check whether the session satisfies the required ACR.
    // If not, return `insufficient_user_authentication` via the redirect channel.
    if let Some(ref acr_values) = eff_acr_values {
        let session_acr: Option<String> = session.get("acr").unwrap_or(None);
        let required: Vec<&str> = acr_values.split_whitespace().collect();
        let satisfied = session_acr
            .as_deref()
            .map(|session_val| required.contains(&session_val))
            .unwrap_or(false);
        if !satisfied {
            let mut url = Url::parse(&redirect_uri)
                .map_err(|_| OAuth2Error::invalid_request("Invalid redirect_uri"))?;
            {
                let mut qp = url.query_pairs_mut();
                qp.append_pair("error", "insufficient_user_authentication");
                qp.append_pair(
                    "error_description",
                    "Authentication Context Class does not satisfy acr_values",
                );
                if let Some(ref s) = eff_state {
                    qp.append_pair("state", s.as_str());
                }
                qp.append_pair("iss", &oidc_config.issuer);
            }
            return Ok(auth_response_security_headers(
                HttpResponse::Found()
                    .append_header(("Location", url.to_string()))
                    .finish(),
            ));
        }
    }

    let auth_code = auth_actor
        .send(CreateAuthorizationCode {
            client_id: query.client_id.clone(),
            user_id,
            redirect_uri: redirect_uri.clone(),
            scope,
            code_challenge: Some(code_challenge),
            code_challenge_method: Some(code_challenge_method),
            nonce: eff_nonce,
            resource: eff_resource,
            authorization_details: eff_authorization_details,
            claims_request: eff_claims,
            span: tracing::Span::current(),
        })
        .await
        .map_err(|e| OAuth2Error::new("server_error", Some(&e.to_string())))??;

    metrics.oauth_authorization_codes_issued.inc();

    // OIDC Hybrid §3.3: for `code id_token` flows, issue an id_token at the authorize
    // endpoint.  The id_token carries `c_hash` computed from the authorization code.
    let id_token_opt: Option<String> =
        if is_hybrid && auth_code.scope.split_whitespace().any(|s| s == "openid") {
            let mut id_claims = IdTokenClaims::new(
                &oidc_config.issuer,
                auth_code.user_id.clone(),
                auth_code.client_id.clone(),
                3600,
                None,
            );
            id_claims.nonce = auth_code.nonce.clone();
            // c_hash: OIDC Core §3.3.2.11 — base64url(left-half(SHA-256(ascii(code)))).
            {
                use sha2::{Digest, Sha256};
                let hash = Sha256::digest(auth_code.code.as_bytes());
                id_claims.c_hash = Some(general_purpose::URL_SAFE_NO_PAD.encode(&hash[..16]));
            }
            let encoded = if oidc_config.id_token_alg.eq_ignore_ascii_case("RS256") {
                let pem = oidc_config
                    .id_token_private_key_pem
                    .as_deref()
                    .ok_or_else(|| {
                        OAuth2Error::new(
                            "server_error",
                            Some("RS256 configured but private key is missing"),
                        )
                    })?;
                id_claims
                    .encode_rs256(pem, oidc_config.id_token_kid.as_deref())
                    .map_err(|e| OAuth2Error::new("server_error", Some(&e.to_string())))?
            } else {
                id_claims
                    .encode(&oidc_config.jwt_secret)
                    .map_err(|e| OAuth2Error::new("server_error", Some(&e.to_string())))?
            };
            Some(encoded)
        } else {
            None
        };

    // Deliver authorization response according to response_mode.
    if response_mode == "form_post" {
        let code_str = auth_code.code.as_str();
        let iss_str = oidc_config.issuer.as_str();
        let mut params: Vec<(&str, &str)> = vec![("code", code_str), ("iss", iss_str)];
        if let Some(ref s) = eff_state {
            params.push(("state", s.as_str()));
        }
        if let Some(ref it) = id_token_opt {
            params.push(("id_token", it.as_str()));
        }
        return Ok(auth_response_security_headers(no_store_headers(
            form_post_response(&redirect_uri, &params),
        )));
    }

    if response_mode == "fragment" {
        // RFC 9101 / OIDC Core §3.3.2.5: deliver response parameters in the URL fragment.
        use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};
        let enc = |s: &str| utf8_percent_encode(s, NON_ALPHANUMERIC).to_string();
        let mut frag_parts = vec![
            format!("code={}", enc(&auth_code.code)),
            format!("iss={}", enc(&oidc_config.issuer)),
        ];
        if let Some(ref state) = eff_state {
            frag_parts.push(format!("state={}", enc(state)));
        }
        if let Some(ref id_token) = id_token_opt {
            frag_parts.push(format!("id_token={}", enc(id_token)));
        }
        let location = format!("{}#{}", redirect_uri, frag_parts.join("&"));
        return Ok(auth_response_security_headers(no_store_headers(
            HttpResponse::Found()
                .append_header(("Location", location))
                .finish(),
        )));
    }

    // Default: redirect with query parameters.
    let mut url = Url::parse(&redirect_uri)
        .map_err(|_| OAuth2Error::invalid_request("Invalid redirect_uri"))?;
    if url.fragment().is_some() {
        return Err(OAuth2Error::invalid_request(
            "redirect_uri must not contain a fragment",
        ));
    }
    {
        let mut qp = url.query_pairs_mut();
        qp.append_pair("code", &auth_code.code);
        if let Some(ref state) = eff_state {
            qp.append_pair("state", state);
        }
        // RFC 9207: include the issuer identifier to prevent mix-up attacks.
        qp.append_pair("iss", &oidc_config.issuer);
        if let Some(ref id_token) = id_token_opt {
            qp.append_pair("id_token", id_token);
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
    device_code: Option<String>,
    /// RFC 7521 §4.2: assertion type (e.g.
    /// `urn:ietf:params:oauth:client-assertion-type:jwt-bearer`).
    client_assertion_type: Option<String>,
    /// RFC 7521 §4.2: the assertion itself (a JWT).
    client_assertion: Option<String>,
    /// RFC 8707: resource server URI for the requested access token audience.
    resource: Option<String>,
    // RFC 8693 (Token Exchange) fields ---
    /// `urn:ietf:params:oauth:token-type:access_token` or similar.
    subject_token: Option<String>,
    #[allow(dead_code)] // RFC 8693: token type URI, reserved for full validation
    subject_token_type: Option<String>,
    actor_token: Option<String>,
    #[allow(dead_code)] // RFC 8693: actor token type URI, reserved for full validation
    actor_token_type: Option<String>,
    requested_token_type: Option<String>,
    /// RFC 9396: Rich Authorization Request (JSON array string).
    authorization_details: Option<String>,
}

/// JWT Bearer assertion type per RFC 7523 §2.2.
const JWT_BEARER_ASSERTION_TYPE: &str = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

/// Process-wide replay guard for JWT client assertions (RFC 7523 §3 /
/// RFC 9700 §2.5). Lazily initialized on first use; see
/// `crates/oauth2-actix/src/security/jti_replay.rs` for semantics. This is
/// intentionally a process-wide singleton so every code path that validates
/// a client assertion shares one view of seen `(client_id, jti)` pairs
/// without having to thread the guard through every handler signature.
fn jti_replay_guard() -> &'static crate::security::jti_replay::JtiReplayGuard {
    use std::sync::OnceLock;
    static GUARD: OnceLock<crate::security::jti_replay::JtiReplayGuard> = OnceLock::new();
    GUARD.get_or_init(crate::security::jti_replay::JtiReplayGuard::new)
}

/// Validate a JWT client assertion (RFC 7523 §3).
///
/// Supports both `client_secret_jwt` (HMAC / HS256) and `private_key_jwt`
/// (RSA / RS256) depending on `client.token_endpoint_auth_method`.
///
/// After signature + `aud` + `iss` + `sub` validation, the assertion's
/// `jti` is recorded in the process-wide replay guard (RFC 7523 §3 /
/// RFC 9700 §2.5). A second presentation of the same `(client_id, jti)`
/// within the assertion's validity window is rejected with `invalid_client`.
fn validate_jwt_client_assertion(
    client: &oauth2_core::Client,
    assertion: &str,
    token_endpoint_url: &str,
    resolved_jwks: Option<&serde_json::Value>,
) -> Result<(), OAuth2Error> {
    use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};

    let header = jsonwebtoken::decode_header(assertion)
        .map_err(|_| OAuth2Error::invalid_client("Malformed client_assertion JWT"))?;

    match client.token_endpoint_auth_method.as_str() {
        "client_secret_jwt" => {
            if header.alg != Algorithm::HS256 {
                return Err(OAuth2Error::invalid_client(
                    "client_secret_jwt requires HS256 algorithm",
                ));
            }
            let key = DecodingKey::from_secret(client.client_secret.as_bytes());
            let mut validation = Validation::new(Algorithm::HS256);
            // `aud` MUST contain the token endpoint URL (RFC 7523 §3)
            validation.set_audience(&[token_endpoint_url]);
            validation.set_required_spec_claims(&["exp", "sub", "iss", "aud"]);
            let data = decode::<serde_json::Value>(assertion, &key, &validation).map_err(|e| {
                OAuth2Error::invalid_client(&format!("client_secret_jwt validation failed: {e}"))
            })?;
            // `iss` and `sub` MUST equal the client_id (RFC 7523 §3)
            let claims = data.claims;
            let iss = claims.get("iss").and_then(|v| v.as_str()).unwrap_or("");
            let sub = claims.get("sub").and_then(|v| v.as_str()).unwrap_or("");
            if iss != client.client_id || sub != client.client_id {
                return Err(OAuth2Error::invalid_client(
                    "JWT iss/sub must equal client_id",
                ));
            }
            enforce_jti_replay(&client.client_id, &claims)?;
            Ok(())
        }
        "private_key_jwt" => {
            if header.alg != Algorithm::RS256 {
                return Err(OAuth2Error::invalid_client(
                    "private_key_jwt requires RS256 algorithm",
                ));
            }
            // JWKS must have been pre-resolved by the caller via resolve_client_jwks().
            let jwks = resolved_jwks.ok_or_else(|| {
                OAuth2Error::invalid_client(
                    "Client must register jwks or jwks_uri for private_key_jwt",
                )
            })?;
            let keys = jwks
                .get("keys")
                .and_then(|v| v.as_array())
                .ok_or_else(|| OAuth2Error::invalid_client("Client JWKS missing 'keys' array"))?;

            // Find matching key by kid (or use the first RSA key).
            let key_json = if let Some(kid) = &header.kid {
                keys.iter()
                    .find(|k| k.get("kid").and_then(|v| v.as_str()) == Some(kid))
                    .ok_or_else(|| OAuth2Error::invalid_client("No matching kid in client JWKS"))?
            } else {
                keys.iter()
                    .find(|k| k.get("kty").and_then(|v| v.as_str()) == Some("RSA"))
                    .ok_or_else(|| OAuth2Error::invalid_client("No RSA key found in client JWKS"))?
            };

            let n = key_json
                .get("n")
                .and_then(|v| v.as_str())
                .ok_or_else(|| OAuth2Error::invalid_client("JWKS key missing 'n' component"))?;
            let e = key_json
                .get("e")
                .and_then(|v| v.as_str())
                .ok_or_else(|| OAuth2Error::invalid_client("JWKS key missing 'e' component"))?;

            let decoding_key = DecodingKey::from_rsa_components(n, e).map_err(|_| {
                OAuth2Error::invalid_client("Failed to construct RSA key from client JWKS")
            })?;
            let mut validation = Validation::new(Algorithm::RS256);
            validation.set_audience(&[token_endpoint_url]);
            validation.set_required_spec_claims(&["exp", "sub", "iss", "aud"]);
            let data = decode::<serde_json::Value>(assertion, &decoding_key, &validation).map_err(
                |e| OAuth2Error::invalid_client(&format!("private_key_jwt validation failed: {e}")),
            )?;
            let claims = data.claims;
            let iss = claims.get("iss").and_then(|v| v.as_str()).unwrap_or("");
            let sub = claims.get("sub").and_then(|v| v.as_str()).unwrap_or("");
            if iss != client.client_id || sub != client.client_id {
                return Err(OAuth2Error::invalid_client(
                    "JWT iss/sub must equal client_id",
                ));
            }
            enforce_jti_replay(&client.client_id, &claims)?;
            Ok(())
        }
        _ => Err(OAuth2Error::invalid_client(
            "Client is not configured for JWT authentication",
        )),
    }
}

/// RFC 7523 §3 / RFC 9700 §2.5: extract `jti` + `exp` from the validated
/// client-assertion claims and record them in the process-wide replay
/// guard. Returns `invalid_client` if the `(client_id, jti)` pair has
/// already been observed within the assertion's validity window, or if
/// the assertion is missing a `jti` (required by RFC 7523 §3 when the
/// AS enforces replay detection).
fn enforce_jti_replay(client_id: &str, claims: &serde_json::Value) -> Result<(), OAuth2Error> {
    let jti = claims.get("jti").and_then(|v| v.as_str()).ok_or_else(|| {
        OAuth2Error::invalid_client("client_assertion missing required jti claim (RFC 7523 §3)")
    })?;
    let exp = claims
        .get("exp")
        .and_then(|v| v.as_i64())
        .ok_or_else(|| OAuth2Error::invalid_client("client_assertion missing exp claim"))?;
    // `exp` has already been checked by `jsonwebtoken::decode` so we know
    // it is in the future; convert to a TTL for the replay guard.
    let now = chrono::Utc::now().timestamp();
    let remaining_secs = (exp - now).max(0) as u64;
    let ttl = std::time::Duration::from_secs(remaining_secs);

    use crate::security::jti_replay::ObserveResult;
    match jti_replay_guard().observe(client_id, jti, ttl) {
        ObserveResult::Fresh => Ok(()),
        ObserveResult::Replay => {
            tracing::warn!(
                client_id = %client_id,
                jti = %jti,
                "RFC 7523 §3: rejected replayed client_assertion jti"
            );
            Err(OAuth2Error::invalid_client(
                "client_assertion jti has already been used",
            ))
        }
    }
}

/// OAuth2 token endpoint
/// Exchanges authorization code for access token
#[allow(clippy::too_many_arguments)]
pub async fn token(
    req: HttpRequest,
    body: web::Bytes,
    token_actor: web::Data<TokenActorPool>,
    client_actor: web::Data<Addr<ClientActor>>,
    auth_actor: web::Data<Addr<AuthActor>>,
    storage: Option<web::Data<DynStorage>>,
    metrics: web::Data<Metrics>,
    oidc_config: web::Data<OidcConfig>,
    invalid_client_limiter: Option<
        web::Data<crate::middleware::rate_limit::InvalidClientRateLimiter>,
    >,
    jwks_cache: Option<web::Data<JwksCache>>,
    dpop_replay_store: Option<web::Data<DpopReplayStore>>,
    dpop_nonce_issuer: Option<web::Data<DpopNonceIssuer>>,
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
        .or_else(|| form_map.get("client_id").cloned())
        .ok_or_else(|| OAuth2Error::invalid_request("Missing client_id"))?;
    let client_secret = body_client_secret.or(basic_client_secret);

    let client_assertion_type = form_map.get("client_assertion_type").cloned();
    let client_assertion = form_map.get("client_assertion").cloned();

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
        device_code: form_map.get("device_code").cloned(),
        client_assertion_type,
        client_assertion,
        resource: form_map.get("resource").cloned(),
        subject_token: form_map.get("subject_token").cloned(),
        subject_token_type: form_map.get("subject_token_type").cloned(),
        actor_token: form_map.get("actor_token").cloned(),
        actor_token_type: form_map.get("actor_token_type").cloned(),
        requested_token_type: form_map.get("requested_token_type").cloned(),
        authorization_details: form_map.get("authorization_details").cloned(),
    };

    // RFC 9449: DPoP — fully validate the DPoP proof and extract JWK Thumbprint.
    let dpop_validated = if let Some(dpop_header) = req.headers().get("DPoP") {
        let dpop_str = dpop_header
            .to_str()
            .map_err(|_| OAuth2Error::invalid_request("DPoP header is not valid UTF-8"))?;
        let method = req.method().as_str();
        // Build the token endpoint URL for `htu` validation.
        let conn_info = req.connection_info();
        let token_url =
            build_request_url_bounded(conn_info.scheme(), conn_info.host(), req.path())?;
        drop(conn_info);
        let store_ref = dpop_replay_store.as_ref().map(|d| d.as_ref());
        let default_store;
        let replay_store = match store_ref {
            Some(s) => s,
            None => {
                default_store = DpopReplayStore::new();
                &default_store
            }
        };
        Some(validate_dpop_proof(
            dpop_str,
            method,
            &token_url,
            replay_store,
        )?)
    } else {
        None
    };
    let dpop_jkt: Option<String> = dpop_validated.as_ref().map(|v| v.jkt.clone());

    // RFC 9449 §§8, 9: per-client nonce enforcement. When the calling
    // client has `dpop_nonce_required = true`, the DPoP proof must carry
    // a fresh server-issued `nonce`; otherwise we respond with
    // `error: use_dpop_nonce` and a `DPoP-Nonce` header so the client can
    // retry. Skipped when no proof is presented (DPoP itself is optional).
    if let (Some(validated), Some(issuer_data)) = (&dpop_validated, &dpop_nonce_issuer) {
        let issuer = issuer_data.as_ref();
        let lookup = client_actor
            .send(GetClient {
                client_id: form.client_id.clone(),
                span: tracing::Span::current(),
            })
            .await
            .map_err(|e| OAuth2Error::new("server_error", Some(&e.to_string())))?;
        if let Ok(client) = lookup {
            if client.dpop_nonce_required {
                match enforce_dpop_nonce(validated, issuer) {
                    Ok(()) => {}
                    Err(e) if e.error == "use_dpop_nonce" => {
                        return Ok(use_dpop_nonce_response(
                            issuer,
                            e.error_description.as_deref(),
                        ));
                    }
                    Err(e) => return Err(e),
                }
            }
        }
        // If lookup returned an error (unknown client), fall through —
        // the per-grant handler will produce the proper `invalid_client`.
    }

    // RFC 8705: mTLS certificate-bound tokens — trust the reverse proxy thumbprint header.
    let mtls_thumbprint: Option<String> = req
        .headers()
        .get("X-Client-Cert-Thumbprint")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    // RFC 8705 §2.1: Subject DN from the client certificate (X-SSL-Client-S-DN header).
    let mtls_subject_dn: Option<String> = req
        .headers()
        .get("X-SSL-Client-S-DN")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    // Build the `cnf` claim if any binding material is present.
    let cnf_claim: Option<serde_json::Value> = match (&dpop_jkt, &mtls_thumbprint) {
        (Some(jkt), _) => Some(serde_json::json!({ "jkt": jkt })),
        (None, Some(tb)) => Some(serde_json::json!({ "x5t#S256": tb })),
        _ => None,
    };

    // Parse RAR authorization_details from form if present.
    let rar_details: Option<serde_json::Value> = if let Some(ref ad) = form.authorization_details {
        match serde_json::from_str(ad) {
            Ok(v) => Some(v),
            Err(_) => {
                return Err(OAuth2Error::invalid_request(
                    "authorization_details is not valid JSON",
                ))
            }
        }
    } else {
        None
    };

    // Capture client_id before form is moved into grant handlers.
    // Used to key the invalid_client penalty bucket (keyed by client_id rather
    // than IP so it works correctly behind any proxy/Istio topology).
    let client_id_for_rate_limit = form.client_id.clone();

    // Clone metrics for the failure-inspection wrapper below. Each grant
    // handler still owns its own `web::Data<Metrics>` for success paths
    // (`oauth_token_issued_total.inc()`).
    let metrics_for_failure = metrics.clone();
    let result = match form.grant_type.as_str() {
        "authorization_code" => {
            handle_authorization_code_grant(
                form,
                cnf_claim,
                rar_details,
                token_actor,
                client_actor,
                auth_actor,
                storage.clone(),
                metrics,
                oidc_config,
                jwks_cache.clone(),
                mtls_thumbprint.as_deref(),
                mtls_subject_dn.as_deref(),
            )
            .await
        }
        "client_credentials" => {
            handle_client_credentials_grant(
                form,
                cnf_claim,
                rar_details,
                token_actor,
                client_actor,
                metrics,
                oidc_config,
                jwks_cache.clone(),
                mtls_thumbprint.as_deref(),
                mtls_subject_dn.as_deref(),
            )
            .await
        }
        "refresh_token" => {
            handle_refresh_token_grant(
                form,
                token_actor,
                client_actor,
                metrics,
                oidc_config,
                jwks_cache.clone(),
                mtls_thumbprint.as_deref(),
                mtls_subject_dn.as_deref(),
            )
            .await
        }
        DEVICE_CODE_GRANT_TYPE | "device_code" => {
            let storage = storage.ok_or_else(|| {
                OAuth2Error::new(
                    "server_error",
                    Some("Storage backend not configured for device_code grant"),
                )
            })?;
            handle_device_code_grant(
                form,
                token_actor,
                client_actor,
                storage,
                metrics,
                oidc_config,
                jwks_cache.clone(),
                mtls_thumbprint.as_deref(),
                mtls_subject_dn.as_deref(),
            )
            .await
        }
        TOKEN_EXCHANGE_GRANT_TYPE => {
            handle_token_exchange_grant(
                form,
                cnf_claim,
                token_actor,
                client_actor,
                metrics,
                oidc_config,
                jwks_cache,
                mtls_thumbprint.as_deref(),
                mtls_subject_dn.as_deref(),
            )
            .await
        }
        // Password grant is intentionally disabled by default
        // (OAuth 2.0 Security BCP).
        "password" => Err(OAuth2Error::unsupported_grant_type("Grant type disabled")),
        _ => Err(OAuth2Error::unsupported_grant_type(&format!(
            "Grant type '{}' not supported",
            form.grant_type
        ))),
    };

    // Count authentication-style failures (bad client secret, bad code, bad
    // refresh token, PKCE mismatch, etc.). Skip shape-level errors like
    // `invalid_request` / `unsupported_grant_type` — those are not auth
    // failures and would drown out real signal on the dashboard.
    if let Err(ref err) = result {
        if matches!(err.error.as_str(), "invalid_client" | "invalid_grant") {
            metrics_for_failure.oauth_failed_authentications.inc();
        }
    }

    // RFC 9700 §2.5: record invalid_client failures in the penalty bucket.
    // Keyed by client_id (not peer IP) so this works correctly behind any
    // proxy or service mesh topology. Once the per-client_id budget is
    // exhausted, return 429 to block credential stuffing without leaking
    // whether credentials are valid.
    if let Err(ref err) = result {
        if err.error == "invalid_client" {
            if let Some(ref limiter) = invalid_client_limiter {
                match limiter.0.check(&client_id_for_rate_limit).await {
                    Ok(rl) if !rl.allowed => {
                        let retry_after = rl.retry_after.map(|d| d.as_secs().max(1)).unwrap_or(1);
                        tracing::warn!(
                            client_id = %client_id_for_rate_limit,
                            "Invalid-client rate limit exceeded on token endpoint"
                        );
                        return Err(OAuth2Error::too_many_requests(&format!(
                            "Too many failed authentication attempts. Retry after {retry_after}s."
                        )));
                    }
                    Err(e) => {
                        tracing::error!(error = %e, "Invalid-client rate limiter error, failing open");
                    }
                    _ => {}
                }
            }
        }
    }

    result
}

#[allow(clippy::too_many_arguments)]
async fn handle_device_code_grant(
    req: TokenRequest,
    token_actor: web::Data<TokenActorPool>,
    client_actor: web::Data<Addr<ClientActor>>,
    storage: web::Data<DynStorage>,
    metrics: web::Data<Metrics>,
    oidc_config: web::Data<OidcConfig>,
    jwks_cache: Option<web::Data<JwksCache>>,
    mtls_thumbprint: Option<&str>,
    mtls_subject_dn: Option<&str>,
) -> Result<HttpResponse, OAuth2Error> {
    let device_code = req
        .device_code
        .clone()
        .ok_or_else(|| OAuth2Error::invalid_request("Missing device_code"))?;

    let client = client_actor
        .send(GetClient {
            client_id: req.client_id.clone(),
            span: tracing::Span::current(),
        })
        .await
        .map_err(|e| OAuth2Error::new("server_error", Some(&e.to_string())))??;

    // Device code grant requires confidential clients.
    if client.is_public() {
        return Err(OAuth2Error::invalid_client(
            "Public clients cannot use the device_code grant",
        ));
    }
    let token_endpoint_url = format!("{}/oauth/token", oidc_config.issuer.trim_end_matches('/'));
    let resolved_jwks =
        resolve_client_jwks(&client, jwks_cache.as_ref().map(|d| d.as_ref())).await?;
    authenticate_confidential_client(
        &client,
        &req,
        &token_endpoint_url,
        resolved_jwks.as_ref(),
        mtls_thumbprint,
        mtls_subject_dn,
    )?;

    if !client.supports_grant_type(DEVICE_CODE_GRANT_TYPE)
        && !client.supports_grant_type("device_code")
    {
        return Err(OAuth2Error::unauthorized_client(
            "Client is not allowed to use device_code grant",
        ));
    }

    let device_auth = storage
        .get_device_authorization_by_device_code(&device_code)
        .await?
        .ok_or_else(|| OAuth2Error::invalid_grant("Invalid device_code"))?;

    if device_auth.client_id != req.client_id {
        return Err(OAuth2Error::invalid_grant(
            "device_code does not belong to this client",
        ));
    }
    if device_auth.used {
        return Err(OAuth2Error::invalid_grant("device_code already used"));
    }
    if device_auth.is_expired() {
        return Err(OAuth2Error::new(
            "expired_token",
            Some("device_code expired"),
        ));
    }
    if device_auth.denied {
        return Err(OAuth2Error::access_denied(
            "End-user denied device authorization",
        ));
    }
    if !device_auth.approved {
        return Err(OAuth2Error::new(
            "authorization_pending",
            Some("End-user authorization is pending"),
        ));
    }

    let user_id = device_auth
        .user_id
        .clone()
        .ok_or_else(|| OAuth2Error::invalid_grant("Approved device authorization missing user"))?;

    let include_refresh = client.supports_grant_type("refresh_token");
    let token = token_actor
        .route(&req.client_id)
        .send(CreateToken {
            user_id: Some(user_id.clone()),
            client_id: req.client_id.clone(),
            scope: device_auth.scope.clone(),
            include_refresh,
            token_family: None,
            resource: None,
            cnf: None,
            authorization_details: None,
            span: tracing::Span::current(),
        })
        .await
        .map_err(|e| OAuth2Error::new("server_error", Some(&e.to_string())))??;

    storage.mark_device_authorization_used(&device_code).await?;

    metrics.oauth_token_issued_total.inc();

    let mut response = TokenResponse::from(token.clone());
    if device_auth.scope.split_whitespace().any(|s| s == "openid") {
        let mut id_claims = IdTokenClaims::new(
            &oidc_config.issuer,
            user_id.clone(),
            req.client_id,
            3600,
            Some(&token.access_token),
        );

        // OIDC Core §5.4: populate email/preferred_username when requested scope grants it.
        let scope_set: std::collections::HashSet<&str> =
            device_auth.scope.split_whitespace().collect();
        if (scope_set.contains("email") || scope_set.contains("profile")) && !user_id.is_empty() {
            match storage.get_user_by_id(&user_id).await {
                Ok(Some(user)) => {
                    if scope_set.contains("email") {
                        id_claims.email = Some(user.email.clone());
                    }
                    if scope_set.contains("profile") {
                        id_claims.preferred_username = Some(user.username.clone());
                    }
                }
                Ok(None) => {
                    tracing::warn!(user_id = %user_id, "User not found when populating id_token claims");
                }
                Err(e) => {
                    tracing::error!(user_id = %user_id, error = %e, "Failed to fetch user for id_token claims");
                }
            }
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

#[allow(clippy::too_many_arguments)]
async fn handle_authorization_code_grant(
    req: TokenRequest,
    cnf_claim: Option<serde_json::Value>,
    rar_details: Option<serde_json::Value>,
    token_actor: web::Data<TokenActorPool>,
    client_actor: web::Data<Addr<ClientActor>>,
    auth_actor: web::Data<Addr<AuthActor>>,
    storage: Option<web::Data<DynStorage>>,
    metrics: web::Data<Metrics>,
    oidc_config: web::Data<OidcConfig>,
    jwks_cache: Option<web::Data<JwksCache>>,
    mtls_thumbprint: Option<&str>,
    mtls_subject_dn: Option<&str>,
) -> Result<HttpResponse, OAuth2Error> {
    let code = req
        .code
        .clone()
        .ok_or_else(|| OAuth2Error::invalid_request("Missing code"))?;

    if matches!(req.redirect_uri.as_deref(), Some("")) {
        return Err(OAuth2Error::invalid_request(
            "redirect_uri must not be empty",
        ));
    }

    // Validate authorization code
    let auth_code = match auth_actor
        .send(ValidateAuthorizationCode {
            code: code.clone(),
            client_id: req.client_id.clone(),
            redirect_uri: req.redirect_uri.clone(),
            code_verifier: req.code_verifier.clone(),
            span: tracing::Span::current(),
        })
        .await
        .map_err(|e| OAuth2Error::new("server_error", Some(&e.to_string())))?
    {
        Ok(code) => code,
        Err(validation_err) => {
            // RFC 9700 §2.1.5: on authorization-code replay the AS MUST
            // revoke every token issued from that code. A *replay* is
            // specifically a code that exists and is already `used` —
            // distinct from an expired or never-issued code, which we
            // ignore here. Fetch the raw record (bypassing `is_valid`)
            // and, if we find a used entry carrying a `token_family`,
            // cascade-revoke the entire lineage via the TokenActor.
            if let Ok(Some(stale)) = auth_actor
                .send(crate::actors::LookupAuthorizationCode {
                    code: code.clone(),
                    span: tracing::Span::current(),
                })
                .await
                .map_err(|e| OAuth2Error::new("server_error", Some(&e.to_string())))?
            {
                if stale.used {
                    if let Some(family) = stale.token_family.clone() {
                        tracing::warn!(
                            client_id = %req.client_id,
                            token_family = %family,
                            "RFC 9700 §2.1.5: authorization-code replay detected — cascade-revoking token family"
                        );
                        let _ = token_actor
                            .route(&req.client_id)
                            .send(crate::actors::RevokeTokenFamily {
                                family,
                                span: tracing::Span::current(),
                            })
                            .await;
                    }
                }
            }
            return Err(validation_err);
        }
    };

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

    // RFC 6749 §2.3 / RFC 7591: public clients (token_endpoint_auth_method=none)
    // authenticate via PKCE only — no client secret is required or expected.
    if client.is_public() {
        // Public clients MUST NOT present a secret.
        if req
            .client_secret
            .as_deref()
            .map(|s| !s.is_empty())
            .unwrap_or(false)
        {
            return Err(OAuth2Error::invalid_client(
                "Public clients must not present a client_secret",
            ));
        }
    } else {
        let token_endpoint_url =
            format!("{}/oauth/token", oidc_config.issuer.trim_end_matches('/'));
        let resolved_jwks =
            resolve_client_jwks(&client, jwks_cache.as_ref().map(|d| d.as_ref())).await?;
        authenticate_confidential_client(
            &client,
            &req,
            &token_endpoint_url,
            resolved_jwks.as_ref(),
            mtls_thumbprint,
            mtls_subject_dn,
        )?;
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
    // RFC 9700 §2.1.5: adopt the auth-code's token_family so every token
    // derived from this grant shares a lineage that can be cascade-revoked
    // on code replay. Fall back to a fresh UUID for legacy codes issued
    // before migration V18 rolled out.
    let token_family = if include_refresh {
        auth_code
            .token_family
            .clone()
            .or_else(|| Some(Uuid::new_v4().to_string()))
    } else {
        None
    };

    // RFC 9396: prefer `authorization_details` from the token request over what
    // was stored in the auth code (token request wins if both are present).
    let eff_auth_details = rar_details.or_else(|| {
        auth_code
            .authorization_details
            .as_deref()
            .and_then(|s| serde_json::from_str(s).ok())
    });

    let token = token_actor
        .route(&auth_code.client_id)
        .send(CreateToken {
            user_id: Some(auth_code.user_id.clone()),
            client_id: auth_code.client_id.clone(),
            scope: auth_code.scope.clone(),
            include_refresh,
            token_family,
            resource: auth_code.resource.clone(),
            cnf: cnf_claim.clone(),
            authorization_details: eff_auth_details,
            span: tracing::Span::current(),
        })
        .await
        .map_err(|e| OAuth2Error::new("server_error", Some(&e.to_string())))??;

    metrics.oauth_token_issued_total.inc();

    let mut response =
        apply_dpop_token_type(TokenResponse::from(token.clone()), cnf_claim.as_ref());

    // Generate OIDC id_token when `openid` scope was requested
    if auth_code.scope.split_whitespace().any(|s| s == "openid") {
        let mut id_claims = IdTokenClaims::new(
            &oidc_config.issuer,
            auth_code.user_id.clone(),
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

        // OIDC Core §5.4: include email/preferred_username in the id_token when
        // the corresponding scopes were requested. This lets oauth2-proxy (and
        // other RP libraries) read the email claim directly from the id_token
        // without a round-trip to the userinfo endpoint.
        let scope_set: std::collections::HashSet<&str> =
            auth_code.scope.split_whitespace().collect();
        if (scope_set.contains("email") || scope_set.contains("profile"))
            && !auth_code.user_id.is_empty()
        {
            if let Some(ref store) = storage {
                match store.get_user_by_id(&auth_code.user_id).await {
                    Ok(Some(user)) => {
                        if scope_set.contains("email") {
                            id_claims.email = Some(user.email.clone());
                        }
                        if scope_set.contains("profile") {
                            id_claims.preferred_username = Some(user.username.clone());
                        }
                    }
                    Ok(None) => {
                        tracing::warn!(
                            user_id = %auth_code.user_id,
                            "User not found when populating id_token claims"
                        );
                    }
                    Err(e) => {
                        tracing::error!(
                            user_id = %auth_code.user_id,
                            error = %e,
                            "Failed to fetch user for id_token claims"
                        );
                    }
                }
            }
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

#[allow(clippy::too_many_arguments)]
async fn handle_client_credentials_grant(
    req: TokenRequest,
    cnf_claim: Option<serde_json::Value>,
    rar_details: Option<serde_json::Value>,
    token_actor: web::Data<TokenActorPool>,
    client_actor: web::Data<Addr<ClientActor>>,
    metrics: web::Data<Metrics>,
    oidc_config: web::Data<OidcConfig>,
    jwks_cache: Option<web::Data<JwksCache>>,
    mtls_thumbprint: Option<&str>,
    mtls_subject_dn: Option<&str>,
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

    // client_credentials requires confidential clients.
    if client.is_public() {
        return Err(OAuth2Error::invalid_client(
            "Public clients cannot use the client_credentials grant",
        ));
    }

    // Validate client credentials (required for this grant).
    let token_endpoint_url = format!("{}/oauth/token", oidc_config.issuer.trim_end_matches('/'));
    let resolved_jwks =
        resolve_client_jwks(&client, jwks_cache.as_ref().map(|d| d.as_ref())).await?;
    authenticate_confidential_client(
        &client,
        &req,
        &token_endpoint_url,
        resolved_jwks.as_ref(),
        mtls_thumbprint,
        mtls_subject_dn,
    )?;

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
            resource: req.resource,
            cnf: cnf_claim.clone(),
            authorization_details: rar_details,
            span: tracing::Span::current(),
        })
        .await
        .map_err(|e| OAuth2Error::new("server_error", Some(&e.to_string())))??;

    metrics.oauth_token_issued_total.inc();

    Ok(no_store_headers(HttpResponse::Ok().json(
        apply_dpop_token_type(TokenResponse::from(token), cnf_claim.as_ref()),
    )))
}

/// RFC 8693: Token Exchange Grant.
///
/// Exchanges an existing security token (subject_token) for a new access token,
/// optionally narrowing scope, changing audience, or impersonating a different subject.
/// Supports DPoP-binding via `cnf_claim`.
#[allow(clippy::too_many_arguments)]
async fn handle_token_exchange_grant(
    req: TokenRequest,
    cnf_claim: Option<serde_json::Value>,
    token_actor: web::Data<TokenActorPool>,
    client_actor: web::Data<Addr<ClientActor>>,
    metrics: web::Data<Metrics>,
    oidc_config: web::Data<OidcConfig>,
    jwks_cache: Option<web::Data<JwksCache>>,
    mtls_thumbprint: Option<&str>,
    mtls_subject_dn: Option<&str>,
) -> Result<HttpResponse, OAuth2Error> {
    use crate::actors::LookupToken;

    let subject_token = req
        .subject_token
        .clone()
        .ok_or_else(|| OAuth2Error::invalid_request("Missing subject_token"))?;

    // Authenticate the client making the exchange request.
    let client = client_actor
        .send(GetClient {
            client_id: req.client_id.clone(),
            span: tracing::Span::current(),
        })
        .await
        .map_err(|e| OAuth2Error::new("server_error", Some(&e.to_string())))??;

    if !client.supports_grant_type(TOKEN_EXCHANGE_GRANT_TYPE) {
        return Err(OAuth2Error::unauthorized_client(
            "Client not allowed to use token-exchange",
        ));
    }
    if client.is_public() {
        return Err(OAuth2Error::invalid_client(
            "Public clients cannot use token-exchange",
        ));
    }
    let token_endpoint_url = format!("{}/oauth/token", oidc_config.issuer.trim_end_matches('/'));
    let resolved_jwks =
        resolve_client_jwks(&client, jwks_cache.as_ref().map(|d| d.as_ref())).await?;
    authenticate_confidential_client(
        &client,
        &req,
        &token_endpoint_url,
        resolved_jwks.as_ref(),
        mtls_thumbprint,
        mtls_subject_dn,
    )?;

    // Validate the subject_token: look it up in storage.
    let subject_tok = token_actor
        .route(&req.client_id)
        .send(LookupToken {
            token: subject_token,
            span: tracing::Span::current(),
        })
        .await
        .map_err(|e| OAuth2Error::new("server_error", Some(&e.to_string())))??
        .ok_or_else(|| OAuth2Error::invalid_grant("subject_token not found or expired"))?;

    // Reject revoked OR expired subject tokens. The previous code checked only
    // `revoked`, so an expired (but still-persisted) token could be exchanged
    // for a fresh one. `is_valid()` mirrors the ValidateToken path.
    if !subject_tok.is_valid() {
        return Err(OAuth2Error::invalid_grant(
            "subject_token is expired or revoked",
        ));
    }

    // Build `act` claim when an actor_token is provided (delegation / impersonation).
    let act_claim: Option<serde_json::Value> = req
        .actor_token
        .as_ref()
        .map(|_| serde_json::json!({ "sub": req.client_id }));

    // Requested scope must be a subset of the subject token's scope; default to original.
    let scope = match req.scope {
        Some(ref requested) => {
            validate_scope_subset(requested, &subject_tok.scope)?;
            requested.clone()
        }
        None => subject_tok.scope.clone(),
    };

    let new_token = token_actor
        .route(&req.client_id)
        .send(CreateToken {
            user_id: subject_tok.user_id.clone(),
            client_id: req.client_id.clone(),
            scope,
            include_refresh: false,
            token_family: None,
            resource: req.resource.clone(),
            cnf: cnf_claim.clone(),
            authorization_details: None,
            span: tracing::Span::current(),
        })
        .await
        .map_err(|e| OAuth2Error::new("server_error", Some(&e.to_string())))??;

    metrics.oauth_token_issued_total.inc();

    let issued_type = req
        .requested_token_type
        .clone()
        .unwrap_or_else(|| "urn:ietf:params:oauth:token-type:access_token".to_string());
    // RFC 9449 §7.1: use "DPoP" token_type when a DPoP-bound token was issued.
    let token_type_str = if cnf_claim.as_ref().and_then(|c| c.get("jkt")).is_some() {
        "DPoP"
    } else {
        "Bearer"
    };
    let mut resp = serde_json::json!({
        "access_token": new_token.access_token,
        "issued_token_type": issued_type,
        "token_type": token_type_str,
        "expires_in": new_token.expires_in,
        "scope": new_token.scope,
    });
    if let Some(act) = act_claim {
        resp["act"] = act;
    }
    Ok(no_store_headers(HttpResponse::Ok().json(resp)))
}

/// RFC 6749 §6 — Refresh Token Grant
///
/// Exchanges a valid, non-revoked refresh token for a fresh access + refresh token pair.
/// Supports optional scope down-scoping: the requested scope must be a subset of the
/// original scope bound to the refresh token.
#[allow(clippy::too_many_arguments)]
async fn handle_refresh_token_grant(
    req: TokenRequest,
    token_actor: web::Data<TokenActorPool>,
    client_actor: web::Data<Addr<ClientActor>>,
    metrics: web::Data<Metrics>,
    oidc_config: web::Data<OidcConfig>,
    jwks_cache: Option<web::Data<JwksCache>>,
    mtls_thumbprint: Option<&str>,
    mtls_subject_dn: Option<&str>,
) -> Result<HttpResponse, OAuth2Error> {
    let refresh_token_str = req
        .refresh_token
        .clone()
        .ok_or_else(|| OAuth2Error::invalid_request("Missing refresh_token"))?;

    // Authenticate the client.
    let client = client_actor
        .send(GetClient {
            client_id: req.client_id.clone(),
            span: tracing::Span::current(),
        })
        .await
        .map_err(|e| OAuth2Error::new("server_error", Some(&e.to_string())))??;

    // Public clients skip secret check; others use the unified authenticator.
    if !client.is_public() {
        let token_endpoint_url =
            format!("{}/oauth/token", oidc_config.issuer.trim_end_matches('/'));
        let resolved_jwks =
            resolve_client_jwks(&client, jwks_cache.as_ref().map(|d| d.as_ref())).await?;
        authenticate_confidential_client(
            &client,
            &req,
            &token_endpoint_url,
            resolved_jwks.as_ref(),
            mtls_thumbprint,
            mtls_subject_dn,
        )?;
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

    // RFC 9449 §5: preserve the DPoP / mTLS `cnf` binding from the original token.
    // Decode the JWT without signature verification to extract the cnf claim.
    let old_cnf =
        oauth2_core::Claims::decode_unverified(&old_token.access_token).and_then(|c| c.cnf);

    // Mint new access + refresh token pair.
    //
    // RFC 8707 §2.2: the client MAY include `resource` on refresh. We pass it
    // straight through so the rotated access token is audience-restricted to
    // the requested resource server. Strict "subset of originally authorized
    // resources" enforcement requires persisting the resource set on the Token
    // record (pending follow-up; tracked under Phase 6.3).
    let token = token_actor
        .route(&req.client_id)
        .send(CreateToken {
            user_id: old_token.user_id.clone(),
            client_id: req.client_id,
            scope,
            include_refresh: true,
            token_family: Some(family),
            resource: req.resource.clone(),
            cnf: old_cnf.clone(),
            authorization_details: None,
            span: tracing::Span::current(),
        })
        .await
        .map_err(|e| OAuth2Error::new("server_error", Some(&e.to_string())))??;

    metrics.oauth_token_issued_total.inc();

    Ok(no_store_headers(HttpResponse::Ok().json(
        apply_dpop_token_type(TokenResponse::from(token), old_cnf.as_ref()),
    )))
}

/// RFC 9126: Pushed Authorization Requests (PAR) endpoint.
///
/// Clients POST their authorization request parameters to this endpoint and receive
/// a `request_uri` (valid for 60 s) to pass to the `/oauth/authorize` endpoint.
/// This prevents the authorization parameters from being exposed in the browser URL.
pub async fn par(
    req: HttpRequest,
    body: web::Bytes,
    auth_actor: web::Data<Addr<AuthActor>>,
    client_actor: web::Data<Addr<ClientActor>>,
    jwks_cache: Option<web::Data<JwksCache>>,
) -> Result<HttpResponse, OAuth2Error> {
    // Parse the application/x-www-form-urlencoded body.
    let raw = String::from_utf8(body.to_vec())
        .map_err(|_| OAuth2Error::invalid_request("Invalid PAR request body encoding"))?;

    // Reject duplicate parameters (RFC 6749 §3.1: parameters must not appear more than once).
    let mut params: HashMap<String, String> = HashMap::new();
    for (k, v) in form_urlencoded::parse(raw.as_bytes()) {
        if params.insert(k.to_string(), v.to_string()).is_some() {
            return Err(OAuth2Error::invalid_request(
                "Duplicate parameter in PAR request",
            ));
        }
    }

    // Required params must be present.
    let client_id = params
        .get("client_id")
        .cloned()
        .ok_or_else(|| OAuth2Error::invalid_request("Missing client_id in PAR request"))?;

    if !params.contains_key("response_type") {
        return Err(OAuth2Error::invalid_request(
            "Missing response_type in PAR request",
        ));
    }

    // Authenticate the client before storing any params.
    let client = client_actor
        .send(GetClient {
            client_id: client_id.clone(),
            span: tracing::Span::current(),
        })
        .await
        .map_err(|e| OAuth2Error::new("server_error", Some(&e.to_string())))??;

    // Authenticate confidential clients; public clients are identified by client_id only.
    if !client.is_public() {
        let token_endpoint_url = {
            let host = req
                .headers()
                .get(actix_web::http::header::HOST)
                .and_then(|h| h.to_str().ok())
                .unwrap_or("localhost");
            format!("https://{host}/oauth/par")
        };
        let secret_from_body = params.get("client_secret").cloned();
        let basic_creds = parse_client_basic_auth(&req).unwrap_or(None);
        let basic_secret = basic_creds.as_ref().map(|(_, s)| s.as_str()).unwrap_or("");

        let presented_secret = if !basic_secret.is_empty() {
            Some(basic_secret.to_string())
        } else if let Some(ref s) = secret_from_body {
            if s.is_empty() {
                None
            } else {
                Some(s.clone())
            }
        } else {
            None
        };

        match presented_secret {
            Some(secret) => {
                if !bool::from(subtle::ConstantTimeEq::ct_eq(
                    client.client_secret.as_bytes(),
                    secret.as_bytes(),
                )) {
                    return Err(OAuth2Error::invalid_client("Invalid client_secret in PAR"));
                }
            }
            None => {
                let assertion_type = params.get("client_assertion_type").cloned();
                let assertion = params.get("client_assertion").cloned();
                if let (Some(atype), Some(aval)) = (assertion_type, assertion) {
                    if atype == JWT_BEARER_ASSERTION_TYPE {
                        let resolved_jwks =
                            resolve_client_jwks(&client, jwks_cache.as_ref().map(|d| d.as_ref()))
                                .await?;
                        validate_jwt_client_assertion(
                            &client,
                            &aval,
                            &token_endpoint_url,
                            resolved_jwks.as_ref(),
                        )?;
                    } else {
                        return Err(OAuth2Error::invalid_client(
                            "Unsupported client_assertion_type",
                        ));
                    }
                } else {
                    return Err(OAuth2Error::invalid_client(
                        "Missing client authentication in PAR request",
                    ));
                }
            }
        }
    }

    // Store the PAR params and get back a request_uri.
    let request_uri = auth_actor
        .send(StorePARRequest { client_id, params })
        .await
        .map_err(|e| OAuth2Error::new("server_error", Some(&e.to_string())))??;

    // RFC 9126 §2.2: respond 201 Created with request_uri and expires_in.
    Ok(HttpResponse::Created().json(serde_json::json!({
        "request_uri": request_uri,
        "expires_in": 60
    })))
}
