use actix::Addr;
use actix_web::{web, HttpRequest, HttpResponse, Result};
use jsonwebtoken::{decode, Validation};
use serde_json::Value;

use crate::actors::{ClientActor, DeleteClient, GetClient, RegisterClient, UpdateClient};
use oauth2_core::{ClientCredentials, ClientRegistration, ClientRegistrationResponse, OAuth2Error};
use oauth2_ports::DynStorage;

use crate::handlers::jwks_cache::JwksCache;
use crate::handlers::jwt_bearer::{select_key, ALLOWED_ALGS};
use crate::handlers::wellknown::OidcConfig;

pub(crate) fn validate_redirect_uri(uri: &str) -> Result<(), OAuth2Error> {
    let uri = uri.trim();
    if uri.is_empty() {
        return Err(OAuth2Error::invalid_request(
            "redirect_uri must not be empty",
        ));
    }

    // OAuth 2.0 requires redirection URIs to be absolute and MUST NOT include fragments.
    // Keep this validation intentionally simple and conservative.
    if uri.contains('#') {
        return Err(OAuth2Error::invalid_request(
            "redirect_uri must not contain a fragment",
        ));
    }
    if uri.contains('\r') || uri.contains('\n') {
        return Err(OAuth2Error::invalid_request(
            "redirect_uri contains invalid characters",
        ));
    }

    let lower = uri.to_ascii_lowercase();
    if lower.starts_with("javascript:") || lower.starts_with("data:") {
        return Err(OAuth2Error::invalid_request(
            "redirect_uri uses a disallowed URI scheme",
        ));
    }

    // Minimal absolute-URI check.
    if !uri.contains("://") {
        return Err(OAuth2Error::invalid_request(
            "redirect_uri must be an absolute URI",
        ));
    }

    Ok(())
}

pub(crate) fn validate_grant_types(grant_types: &[String]) -> Result<(), OAuth2Error> {
    // Keep registration honest: only allow grant types that the server actually supports.
    // (prevents clients from registering for unsupported grants like implicit).
    const SUPPORTED: [&str; 4] = [
        "authorization_code",
        "client_credentials",
        "refresh_token",
        "urn:ietf:params:oauth:grant-type:device_code",
    ];

    if grant_types.is_empty() {
        return Err(OAuth2Error::invalid_request(
            "grant_types must not be empty",
        ));
    }

    for gt in grant_types {
        if !SUPPORTED.contains(&gt.as_str()) {
            return Err(OAuth2Error::invalid_request(
                "unsupported or disabled grant_type in registration",
            ));
        }
    }

    Ok(())
}

/// Supported `token_endpoint_auth_method` values.
const SUPPORTED_AUTH_METHODS: [&str; 9] = [
    "client_secret_basic",
    "client_secret_post",
    "client_secret_jwt",
    "private_key_jwt",
    "none",
    "tls_client_auth",
    "self_signed_tls_client_auth",
    "tls_client_auth_san_uri",
    "tls_client_auth_san_dns",
];

/// RFC 8705 §2.1.2: auth methods that bind the client to a certificate
/// `subjectAltName` and therefore require a registered `tls_client_auth_san`.
const SAN_AUTH_METHODS: [&str; 2] = ["tls_client_auth_san_uri", "tls_client_auth_san_dns"];

fn validate_token_endpoint_auth_method(
    method: &str,
    grant_types: &[String],
) -> Result<(), OAuth2Error> {
    if !SUPPORTED_AUTH_METHODS.contains(&method) {
        return Err(OAuth2Error::invalid_request(
            "unsupported token_endpoint_auth_method",
        ));
    }
    // Public clients (`none`) may only use authorization_code (with PKCE).
    if method == "none" {
        let non_pkce: Vec<&str> = grant_types
            .iter()
            .filter(|g| g.as_str() != "authorization_code" && g.as_str() != "refresh_token")
            .map(String::as_str)
            .collect();
        if !non_pkce.is_empty() {
            return Err(OAuth2Error::invalid_request(
                "public clients (token_endpoint_auth_method=none) \
                 may only use authorization_code and refresh_token",
            ));
        }
    }
    // private_key_jwt requires jwks or jwks_uri — validated at a higher level
    Ok(())
}

/// Parse the dynamic-registration enable flag. Defaults to `false` (disabled)
/// for any absent or non-`"true"` value, so open registration is opt-in.
fn parse_registration_enabled(val: Option<&str>) -> bool {
    val.and_then(|v| v.parse::<bool>().ok()).unwrap_or(false)
}

/// Whether the public RFC 7591 `POST /connect/register` endpoint is enabled.
/// Controlled by `OAUTH2_DYNAMIC_REGISTRATION_ENABLED` (trusted env var).
fn dynamic_registration_enabled() -> bool {
    parse_registration_enabled(
        std::env::var("OAUTH2_DYNAMIC_REGISTRATION_ENABLED")
            .ok()
            .as_deref(),
    )
}

/// Scopes that confer elevated authority and must never be self-assigned via
/// the public RFC 7591 registration or RFC 7592 update endpoints. Operators can
/// still grant them deliberately through the admin endpoint.
const PRIVILEGED_SCOPES: &[&str] = &["admin", "write"];

/// True if any space-delimited token in `scope` is a privileged scope
/// (case-insensitive, exact-token match — `"administrator"` does not match).
pub(crate) fn scope_contains_privileged(scope: &str) -> bool {
    scope
        .split_whitespace()
        .any(|s| PRIVILEGED_SCOPES.iter().any(|p| p.eq_ignore_ascii_case(s)))
}

/// Common validation for a `ClientRegistration`, shared between the admin
/// endpoint and the RFC 7591 public endpoint.
fn validate_registration(reg: &ClientRegistration) -> Result<(), OAuth2Error> {
    // Default grant_types when empty (RFC 7591 §2 default: authorization_code)
    let grant_types = if reg.grant_types.is_empty() {
        vec!["authorization_code".to_string()]
    } else {
        reg.grant_types.clone()
    };
    validate_grant_types(&grant_types)?;
    validate_token_endpoint_auth_method(&reg.token_endpoint_auth_method, &grant_types)?;

    if scope_contains_privileged(&reg.scope) {
        return Err(OAuth2Error::invalid_request(
            "requested scope includes a privileged scope that may not be self-registered",
        ));
    }

    if reg.redirect_uris.is_empty() {
        return Err(OAuth2Error::invalid_request(
            "redirect_uris must not be empty",
        ));
    }
    for uri in &reg.redirect_uris {
        validate_redirect_uri(uri)?;
    }

    // private_key_jwt requires a JWKS or JWKS URI
    if reg.token_endpoint_auth_method == "private_key_jwt"
        && reg.jwks.is_none()
        && reg.jwks_uri.as_deref().is_none_or(str::is_empty)
    {
        return Err(OAuth2Error::invalid_request(
            "private_key_jwt requires jwks or jwks_uri",
        ));
    }

    // jwks and jwks_uri are mutually exclusive (RFC 7591 §2)
    if reg.jwks.is_some() && reg.jwks_uri.as_deref().is_some_and(|u| !u.is_empty()) {
        return Err(OAuth2Error::invalid_request(
            "jwks and jwks_uri are mutually exclusive",
        ));
    }

    validate_san_auth_method(reg)?;

    Ok(())
}

/// RFC 8705 §2.1.2: a client registering for SAN-based mTLS authentication is
/// useless (and unauthenticatable) without the SAN value to compare against,
/// so require it up front rather than failing at the token endpoint.
fn validate_san_auth_method(reg: &ClientRegistration) -> Result<(), OAuth2Error> {
    if SAN_AUTH_METHODS.contains(&reg.token_endpoint_auth_method.as_str())
        && reg
            .tls_client_auth_san
            .as_deref()
            .map(str::trim)
            .is_none_or(str::is_empty)
    {
        return Err(OAuth2Error::invalid_request(
            "tls_client_auth_san is required for \
             tls_client_auth_san_uri / tls_client_auth_san_dns",
        ));
    }
    Ok(())
}

/// Normalise a `ClientRegistration`, filling in RFC 7591 defaults.
fn normalise_registration(reg: &mut ClientRegistration) {
    if reg.grant_types.is_empty() {
        reg.grant_types = vec!["authorization_code".to_string()];
    }
    if reg.response_types.is_empty() {
        reg.response_types = vec!["code".to_string()];
    }
    if reg.scope.trim().is_empty() {
        reg.scope = "openid".to_string();
    }
}

// ---------------------------------------------------------------------------
// RFC 7591 §2.3 software statements
// ---------------------------------------------------------------------------

fn invalid_software_statement(detail: &str) -> OAuth2Error {
    OAuth2Error::new("invalid_software_statement", Some(detail))
}

/// Phase 7 (agent/A2A OAuth): `software_id` and `software_version` decide
/// whether a client is treated as an AI agent — which selects the `ai_agent`
/// `sub_profile` and the (shorter) AI-agent access-token TTL. A caller who can
/// set them freely could either claim agent status or shed the TTL cap by
/// dropping the `agent:` prefix, so on the self-service paths they are accepted
/// only from a verified `software_statement`. Body-supplied values are cleared
/// before [`apply_software_statement`] merges the attested ones back in.
///
/// The admin registration endpoint is exempt: an operator setting these
/// deliberately is the intended way to register an agent without a statement.
fn clear_self_asserted_software_metadata(reg: &mut ClientRegistration) {
    reg.software_id = None;
    reg.software_version = None;
}

/// RFC 7591 §2.3 — verify `software_statement` and fold its claims into the
/// registration request.
///
/// The statement must be a JWT whose `iss` names an enabled `TrustedIssuer`;
/// the signature is checked against that issuer's published JWKS. Every
/// client-metadata claim the statement carries overrides the corresponding
/// value in the request body, as RFC 7591 §2.3 requires.
async fn apply_software_statement(
    reg: &mut ClientRegistration,
    storage: Option<&DynStorage>,
    jwks_cache: Option<&JwksCache>,
) -> Result<(), OAuth2Error> {
    let statement = match reg.software_statement.as_deref().map(str::trim) {
        Some(s) if !s.is_empty() => s.to_string(),
        _ => return Ok(()),
    };

    let storage = storage.ok_or_else(|| {
        OAuth2Error::new(
            "server_error",
            Some("Storage backend not configured; cannot verify software statements"),
        )
    })?;

    let header = jsonwebtoken::decode_header(&statement)
        .map_err(|_| invalid_software_statement("software_statement is not a JWT"))?;
    if !ALLOWED_ALGS.contains(&header.alg) {
        return Err(invalid_software_statement(
            "software_statement uses an unsupported signature algorithm",
        ));
    }

    // `iss` is read from the unverified payload only to select the key; the
    // signature check below is what makes it trustworthy.
    let iss = decode_unverified_iss(&statement)?;
    let trusted = storage
        .get_trusted_issuer(&iss)
        .await?
        .filter(|ti| ti.enabled)
        .ok_or_else(|| {
            invalid_software_statement("software_statement iss is not a trusted issuer")
        })?;

    let cache = jwks_cache.ok_or_else(|| {
        OAuth2Error::new(
            "server_error",
            Some("JWKS cache is not configured; cannot verify software statements"),
        )
    })?;
    let jwks = cache.fetch(trusted.jwks_uri.trim()).await.map_err(|e| {
        invalid_software_statement(&format!(
            "could not fetch the trusted issuer's JWKS: {}",
            e.error_description.as_deref().unwrap_or(&e.error)
        ))
    })?;
    let key = select_key(&jwks, &header).map_err(|e| {
        invalid_software_statement(e.error_description.as_deref().unwrap_or(&e.error))
    })?;

    let mut validation = Validation::new(header.alg);
    validation.set_issuer(&[iss.as_str()]);
    // RFC 7591 §2.3 leaves `aud` and `exp` optional; `exp` is still honoured
    // when the statement carries one.
    validation.set_required_spec_claims(&["iss"]);
    validation.validate_aud = false;

    let claims = decode::<Value>(&statement, &key, &validation)
        .map_err(|e| {
            invalid_software_statement(&format!("software_statement validation failed: {e}"))
        })?
        .claims;

    merge_software_statement_claims(reg, &claims);
    Ok(())
}

/// Read the `iss` claim from a JWT payload without verifying the signature.
fn decode_unverified_iss(token: &str) -> Result<String, OAuth2Error> {
    use base64::{engine::general_purpose, Engine as _};
    let payload = token
        .split('.')
        .nth(1)
        .ok_or_else(|| invalid_software_statement("software_statement is not a JWT"))?;
    let bytes = general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .map_err(|_| invalid_software_statement("software_statement payload is not base64url"))?;
    let claims: Value = serde_json::from_slice(&bytes)
        .map_err(|_| invalid_software_statement("software_statement payload is not JSON"))?;
    claims
        .get("iss")
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| invalid_software_statement("software_statement is missing the iss claim"))
}

/// RFC 7591 §2.3: claims present in a verified software statement override the
/// corresponding request-body values. Claims the statement omits are left alone.
fn merge_software_statement_claims(reg: &mut ClientRegistration, claims: &Value) {
    let string_claim = |name: &str| claims.get(name).and_then(Value::as_str).map(str::to_string);
    let string_list = |name: &str| {
        claims.get(name).and_then(Value::as_array).map(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect::<Vec<String>>()
        })
    };

    if let Some(v) = string_claim("software_id") {
        reg.software_id = Some(v);
    }
    if let Some(v) = string_claim("software_version") {
        reg.software_version = Some(v);
    }
    if let Some(v) = string_claim("client_name") {
        reg.client_name = v;
    }
    if let Some(v) = string_list("redirect_uris") {
        reg.redirect_uris = v;
    }
    if let Some(v) = string_list("grant_types") {
        reg.grant_types = v;
    }
    if let Some(v) = string_claim("scope") {
        reg.scope = v;
    }
    if let Some(v) = string_claim("token_endpoint_auth_method") {
        reg.token_endpoint_auth_method = v;
    }
    // `jwks` and `jwks_uri` stay mutually exclusive (RFC 7591 §2): whichever
    // the statement asserts replaces both request-body values.
    if let Some(v) = claims.get("jwks") {
        reg.jwks = Some(v.clone());
        reg.jwks_uri = None;
    } else if let Some(v) = string_claim("jwks_uri") {
        reg.jwks_uri = Some(v);
        reg.jwks = None;
    }
}

// ---------------------------------------------------------------------------
// Admin registration endpoint (legacy, unchanged API contract)
// ---------------------------------------------------------------------------

/// Register a new OAuth2 client (admin endpoint — `POST /admin/clients/register`).
pub async fn register_client(
    mut registration: web::Json<ClientRegistration>,
    client_actor: web::Data<Addr<ClientActor>>,
    storage: Option<web::Data<DynStorage>>,
    jwks_cache: Option<web::Data<JwksCache>>,
) -> Result<HttpResponse, OAuth2Error> {
    // RFC 7591 §2.3: a verified software statement overrides the request body,
    // so apply it before any validation runs.
    apply_software_statement(
        &mut registration,
        storage.as_ref().map(|d| d.as_ref()),
        jwks_cache.as_ref().map(|d| d.as_ref()),
    )
    .await?;

    let reg: &ClientRegistration = &registration;
    validate_grant_types(&reg.grant_types)?;
    validate_token_endpoint_auth_method(&reg.token_endpoint_auth_method, &reg.grant_types)?;

    if reg.redirect_uris.is_empty() {
        return Err(OAuth2Error::invalid_request(
            "redirect_uris must not be empty",
        ));
    }
    for uri in &reg.redirect_uris {
        validate_redirect_uri(uri)?;
    }

    if reg.scope.trim().is_empty() {
        return Err(OAuth2Error::invalid_request("scope must not be empty"));
    }

    validate_san_auth_method(reg)?;

    let client = client_actor
        .send(RegisterClient {
            registration: registration.into_inner(),
            span: tracing::Span::current(),
        })
        .await
        .map_err(|e| OAuth2Error::new("server_error", Some(&e.to_string())))??;

    let credentials = ClientCredentials {
        client_id: client.client_id,
        client_secret: client.client_secret,
    };

    Ok(HttpResponse::Created().json(credentials))
}

// ---------------------------------------------------------------------------
// RFC 7591 Dynamic Client Registration
// ---------------------------------------------------------------------------

/// `POST /connect/register` — RFC 7591 §3.1 client registration.
pub async fn dynamic_register(
    mut registration: web::Json<ClientRegistration>,
    client_actor: web::Data<Addr<ClientActor>>,
    oidc_config: web::Data<OidcConfig>,
    storage: Option<web::Data<DynStorage>>,
    jwks_cache: Option<web::Data<JwksCache>>,
) -> Result<HttpResponse, OAuth2Error> {
    if !dynamic_registration_enabled() {
        return Err(OAuth2Error::access_denied(
            "Dynamic client registration is disabled",
        ));
    }
    // Phase 7 (agent/A2A OAuth): `allowed_actors` grants delegation trust and
    // must only be set through the admin registration endpoint, never via
    // public self-registration.
    registration.allowed_actors = None;
    clear_self_asserted_software_metadata(&mut registration);
    // RFC 7591 §2.3: apply a verified software statement before defaults and
    // validation, so its claims are what gets validated and stored.
    apply_software_statement(
        &mut registration,
        storage.as_ref().map(|d| d.as_ref()),
        jwks_cache.as_ref().map(|d| d.as_ref()),
    )
    .await?;
    normalise_registration(&mut registration);
    validate_registration(&registration)?;

    let client = client_actor
        .send(RegisterClient {
            registration: registration.into_inner(),
            span: tracing::Span::current(),
        })
        .await
        .map_err(|e| OAuth2Error::new("server_error", Some(&e.to_string())))??;

    let resp = ClientRegistrationResponse::from_client(&client, &oidc_config.issuer);
    Ok(HttpResponse::Created().json(resp))
}

// ---------------------------------------------------------------------------
// RFC 7592 Client Configuration Endpoint (read / update / delete)
// ---------------------------------------------------------------------------

/// Extract and validate the `Bearer <registration_access_token>` from
/// the request, returning the `Client` it belongs to.
async fn authenticate_registration_token(
    req: &HttpRequest,
    client_id: &str,
    client_actor: &Addr<ClientActor>,
) -> Result<oauth2_core::Client, OAuth2Error> {
    let token = req
        .headers()
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| OAuth2Error::invalid_client("Missing registration_access_token"))?;

    let client = client_actor
        .send(GetClient {
            client_id: client_id.to_string(),
            span: tracing::Span::current(),
        })
        .await
        .map_err(|e| OAuth2Error::new("server_error", Some(&e.to_string())))??;

    if client.registration_access_token.is_empty() {
        return Err(OAuth2Error::invalid_client(
            "Client has no registration_access_token",
        ));
    }

    // Constant-time comparison
    use subtle::ConstantTimeEq;
    let matches: bool = client
        .registration_access_token
        .as_bytes()
        .ct_eq(token.as_bytes())
        .into();
    if !matches {
        return Err(OAuth2Error::invalid_client(
            "Invalid registration_access_token",
        ));
    }

    Ok(client)
}

/// `GET /connect/register/{client_id}` — RFC 7592 §2.1 read client configuration.
pub async fn read_client_configuration(
    req: HttpRequest,
    path: web::Path<String>,
    client_actor: web::Data<Addr<ClientActor>>,
    oidc_config: web::Data<OidcConfig>,
) -> Result<HttpResponse, OAuth2Error> {
    let client_id = path.into_inner();
    let client = authenticate_registration_token(&req, &client_id, &client_actor).await?;

    let resp = ClientRegistrationResponse::from_client(&client, &oidc_config.issuer);
    Ok(HttpResponse::Ok().json(resp))
}

/// `PUT /connect/register/{client_id}` — RFC 7592 §2.2 update client.
pub async fn update_client_configuration(
    req: HttpRequest,
    path: web::Path<String>,
    mut body: web::Json<ClientRegistration>,
    client_actor: web::Data<Addr<ClientActor>>,
    oidc_config: web::Data<OidcConfig>,
    storage: Option<web::Data<DynStorage>>,
    jwks_cache: Option<web::Data<JwksCache>>,
) -> Result<HttpResponse, OAuth2Error> {
    let client_id = path.into_inner();
    let mut client = authenticate_registration_token(&req, &client_id, &client_actor).await?;

    // The registration access token authenticates the client, not an operator,
    // so this is a self-service path: attested-only metadata may arrive only
    // inside a verified software statement.
    clear_self_asserted_software_metadata(&mut body);
    apply_software_statement(
        &mut body,
        storage.as_ref().map(|d| d.as_ref()),
        jwks_cache.as_ref().map(|d| d.as_ref()),
    )
    .await?;
    normalise_registration(&mut body);
    validate_registration(&body)?;

    // Apply updated fields
    client.name = body.client_name.clone();
    client.redirect_uris = serde_json::to_string(&body.redirect_uris).unwrap_or_default();
    client.grant_types = serde_json::to_string(&body.grant_types).unwrap_or_default();
    client.scope = body.scope.clone();
    client.token_endpoint_auth_method = body.token_endpoint_auth_method.clone();
    client.response_types = serde_json::to_string(&body.response_types).unwrap_or_default();
    client.contacts = serde_json::to_string(&body.contacts).unwrap_or_default();
    client.logo_uri = body.logo_uri.clone().unwrap_or_default();
    client.client_uri = body.client_uri.clone().unwrap_or_default();
    client.policy_uri = body.policy_uri.clone().unwrap_or_default();
    client.tos_uri = body.tos_uri.clone().unwrap_or_default();
    client.jwks = body
        .jwks
        .as_ref()
        .map(|v| serde_json::to_string(v).unwrap_or_default())
        .unwrap_or_default();
    client.jwks_uri = body.jwks_uri.clone().unwrap_or_default();
    client.backchannel_logout_uri = body.backchannel_logout_uri.clone().unwrap_or_default();
    client.backchannel_logout_session_required =
        body.backchannel_logout_session_required.unwrap_or(false);
    client.frontchannel_logout_uri = body.frontchannel_logout_uri.clone().unwrap_or_default();
    client.frontchannel_logout_session_required =
        body.frontchannel_logout_session_required.unwrap_or(false);
    client.post_logout_redirect_uris = body
        .post_logout_redirect_uris
        .as_ref()
        .map(|v| serde_json::to_string(v).unwrap_or_default())
        .unwrap_or_default();
    client.tls_client_certificate_subject_dn = body
        .tls_client_certificate_subject_dn
        .clone()
        .unwrap_or_default();
    client.tls_client_auth_san = body.tls_client_auth_san.clone().unwrap_or_default();
    // Only a verified software statement can reach these (the body copies were
    // cleared above), and an update that carries no statement must leave the
    // stored values alone — silently wiping `software_id` would drop a client
    // out of AI-agent status and out from under the agent TTL cap.
    if let Some(id) = body.software_id.clone() {
        client.software_id = id;
    }
    if let Some(version) = body.software_version.clone() {
        client.software_version = version;
    }
    client.updated_at = chrono::Utc::now();

    let updated = client_actor
        .send(UpdateClient {
            client,
            span: tracing::Span::current(),
        })
        .await
        .map_err(|e| OAuth2Error::new("server_error", Some(&e.to_string())))??;

    let resp = ClientRegistrationResponse::from_client(&updated, &oidc_config.issuer);
    Ok(HttpResponse::Ok().json(resp))
}

/// `DELETE /connect/register/{client_id}` — RFC 7592 §2.3 delete client.
pub async fn delete_client_configuration(
    req: HttpRequest,
    path: web::Path<String>,
    client_actor: web::Data<Addr<ClientActor>>,
) -> Result<HttpResponse, OAuth2Error> {
    let client_id = path.into_inner();
    let _client = authenticate_registration_token(&req, &client_id, &client_actor).await?;

    client_actor
        .send(DeleteClient {
            client_id,
            span: tracing::Span::current(),
        })
        .await
        .map_err(|e| OAuth2Error::new("server_error", Some(&e.to_string())))??;

    Ok(HttpResponse::NoContent().finish())
}

#[cfg(test)]
mod registration_security_tests {
    use super::*;

    #[test]
    fn registration_disabled_by_default() {
        assert!(!parse_registration_enabled(None));
    }

    #[test]
    fn registration_enabled_only_for_true() {
        assert!(parse_registration_enabled(Some("true")));
        assert!(!parse_registration_enabled(Some("false")));
        assert!(!parse_registration_enabled(Some("1")));
        assert!(!parse_registration_enabled(Some("garbage")));
    }

    #[test]
    fn rejects_privileged_scopes() {
        assert!(scope_contains_privileged("openid admin"));
        assert!(scope_contains_privileged("write"));
        assert!(scope_contains_privileged("ADMIN")); // case-insensitive
    }

    #[test]
    fn allows_normal_scopes() {
        assert!(!scope_contains_privileged("openid profile email read"));
        assert!(!scope_contains_privileged("")); // empty handled elsewhere
        assert!(!scope_contains_privileged("administrator")); // not an exact token match
    }
}
