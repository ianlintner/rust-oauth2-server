//! Transaction Authorization Challenge
//! (`draft-rosomakho-oauth-txn-challenge-00`) — human-in-the-loop approval of
//! a single agent operation.
//!
//! Flow:
//!
//! 1. A protected resource refuses an operation and hands the client a signed
//!    *transaction challenge* JWT describing what it wants approved.
//! 2. The client POSTs it to `/oauth/transaction_authorization` with its own
//!    client credentials. The challenge's `iss` must name a registered
//!    [`oauth2_core::ProtectedResource`] that publishes a
//!    `txn_challenge_jwks_uri`; the signature is verified against that JWKS.
//!    The AS stores a pending approval and returns a polling handle.
//! 3. A human opens `/oauth/transaction_authorization/approve`, sees the
//!    reason and the requested `authorization_details`, and approves or denies.
//! 4. The client polls the token endpoint with
//!    `grant_type=urn:ietf:params:oauth:grant-type:transaction-authorization`
//!    until the approval settles, then receives a short-lived access token
//!    carrying the challenge's `txn` claim and the approved
//!    `authorization_details`.
//!
//! The whole feature is gated on `AgentConfig::tac_enabled`
//! (`OAUTH2_TAC_ENABLED`); with the flag off the endpoints refuse every
//! request and discovery does not advertise them.
//!
//! # RFC 9470 step-up (not yet enforced)
//!
//! A challenge may carry `acr_values` / `max_age` to demand that the approving
//! session be fresh or authenticated at a given assurance level; when the
//! session does not satisfy them the approval page should bounce the user
//! through `/auth/login` with `prompt=login` before showing the approval form.
//! That is **not implemented yet**: the Phase 1.D `max_age` check lives inline
//! in `handlers::oauth::authorize` rather than in a reusable helper, and this
//! module deliberately does not fork a second copy of it. Implementing it means
//! extracting that check into a shared helper, persisting the challenge's
//! `acr_values` / `max_age` on the pending row, and applying the helper here.

use actix::Addr;
use actix_session::Session;
use actix_web::{web, HttpRequest, HttpResponse, Result};
use jsonwebtoken::{decode, Algorithm, Validation};
use serde::Deserialize;
use serde_json::{json, Value};

use oauth2_config::AgentConfig;
use oauth2_core::token_types::GRANT_TRANSACTION_AUTHORIZATION;
use oauth2_core::{
    Actor as DelegationActor, OAuth2Error, ProtectedResource, TokenResponse,
    TransactionAuthorization,
};
use oauth2_observability::Metrics;
use oauth2_ports::DynStorage;

use crate::actors::{ClientActor, CreateToken, GetClient, TokenActorPool};
use crate::handlers::jwks_cache::JwksCache;
use crate::handlers::jwt_bearer::{decode_unverified_claims, select_key};
use crate::handlers::login::html_escape;
use crate::handlers::oauth::{
    apply_dpop_token_type, authenticate_confidential_client, enforce_jti_replay, no_store_headers,
    parse_client_basic_auth, resolve_client_jwks, TokenRequest,
};
use crate::handlers::wellknown::OidcConfig;

/// Upper bound on how long a pending approval stays open, regardless of how
/// far in the future the challenge's own `exp` is.
const MAX_PENDING_SECS: i64 = 600;

/// Ceiling on the lifetime of the access token issued for an approved
/// transaction: approval is per-operation, so the token must not outlive it by
/// much.
const TOKEN_TTL_CAP_SECS: u64 = 300;

/// Signature algorithms accepted on a challenge. Symmetric algorithms are
/// excluded on purpose: the key comes from the resource's public JWKS.
const ALLOWED_ALGS: [Algorithm; 3] = [Algorithm::RS256, Algorithm::ES256, Algorithm::PS256];

/// Body of `POST /oauth/transaction_authorization`.
#[derive(Debug, Deserialize)]
pub struct TransactionChallengeForm {
    pub transaction_challenge: String,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub client_assertion: Option<String>,
    pub client_assertion_type: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ApproveQuery {
    pub transaction_authorization_id: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ApproveForm {
    pub transaction_authorization_id: String,
    pub action: Option<String>,
}

/// Read the agent feature flags, falling back to defaults (all off) when the
/// app was built without them.
fn agent_config(agent: &Option<web::Data<AgentConfig>>) -> AgentConfig {
    agent
        .as_ref()
        .map(|c| c.get_ref().clone())
        .unwrap_or_default()
}

fn require_tac_enabled(agent: &AgentConfig) -> Result<(), OAuth2Error> {
    if agent.tac_enabled {
        Ok(())
    } else {
        Err(OAuth2Error::invalid_request(
            "transaction authorization is not enabled on this authorization server",
        ))
    }
}

/// Build the minimal [`TokenRequest`] that
/// [`authenticate_confidential_client`] needs. This endpoint is not the token
/// endpoint, so every grant-specific field is absent.
fn client_auth_request(
    client_id: String,
    client_secret: Option<String>,
    client_assertion: Option<String>,
    client_assertion_type: Option<String>,
) -> TokenRequest {
    TokenRequest {
        grant_type: GRANT_TRANSACTION_AUTHORIZATION.to_string(),
        code: None,
        redirect_uri: None,
        client_id,
        client_secret,
        refresh_token: None,
        username: None,
        password: None,
        scope: None,
        code_verifier: None,
        device_code: None,
        client_assertion_type,
        client_assertion,
        resource: Vec::new(),
        assertion: None,
        audience: Vec::new(),
        subject_token: None,
        subject_token_type: None,
        actor_token: None,
        actor_token_type: None,
        requested_token_type: None,
        authorization_details: None,
        transaction_authorization_id: None,
    }
}

/// `POST /oauth/transaction_authorization` — accept a signed challenge from a
/// protected resource and open a pending human approval for it.
pub async fn transaction_authorization(
    req: HttpRequest,
    form: web::Form<TransactionChallengeForm>,
    client_actor: web::Data<Addr<ClientActor>>,
    storage: web::Data<DynStorage>,
    oidc_config: web::Data<OidcConfig>,
    agent: Option<web::Data<AgentConfig>>,
    jwks_cache: Option<web::Data<JwksCache>>,
) -> Result<HttpResponse, OAuth2Error> {
    let agent = agent_config(&agent);
    require_tac_enabled(&agent)?;

    // --- 1. Authenticate the calling client ------------------------------
    //
    // Before anything that touches the network, so an unauthenticated caller
    // cannot drive outbound JWKS fetches.
    let basic = parse_client_basic_auth(&req)?;
    let client_id = match (form.client_id.as_ref(), basic.as_ref().map(|(id, _)| id)) {
        (Some(body_id), Some(basic_id)) if body_id != basic_id => {
            return Err(OAuth2Error::invalid_request(
                "client_id mismatch between body and Basic auth",
            ));
        }
        (Some(id), _) | (None, Some(id)) => id.clone(),
        (None, None) => return Err(OAuth2Error::invalid_client("Missing client_id")),
    };
    let client_secret = form
        .client_secret
        .clone()
        .or_else(|| basic.as_ref().map(|(_, s)| s.clone()));

    let client = client_actor
        .send(GetClient {
            client_id: client_id.clone(),
            span: tracing::Span::current(),
        })
        .await
        .map_err(|e| OAuth2Error::new("server_error", Some(&e.to_string())))??;

    if client.is_public() {
        return Err(OAuth2Error::invalid_client(
            "Public clients cannot use transaction authorization",
        ));
    }

    let auth_request = client_auth_request(
        client_id.clone(),
        client_secret,
        form.client_assertion.clone(),
        form.client_assertion_type.clone(),
    );
    let token_endpoint_url = format!("{}/oauth/token", oidc_config.issuer.trim_end_matches('/'));
    let resolved_jwks =
        resolve_client_jwks(&client, jwks_cache.as_ref().map(|d| d.as_ref())).await?;
    authenticate_confidential_client(
        &client,
        &auth_request,
        &token_endpoint_url,
        &oidc_config.issuer,
        resolved_jwks.as_ref(),
        mtls_thumbprint(&req).as_deref(),
        mtls_subject_dn(&req).as_deref(),
    )?;

    // --- 2. Verify the challenge against the resource's JWKS --------------
    let verified = verify_challenge(
        &form.transaction_challenge,
        storage.as_ref(),
        jwks_cache.as_ref().map(|d| d.as_ref()),
        &oidc_config.issuer,
        &agent,
    )
    .await?;

    // --- 3. Open the pending approval -------------------------------------
    let now = chrono::Utc::now().timestamp();
    // The pending row never outlives the challenge, and never stays open for
    // longer than `MAX_PENDING_SECS` even if the challenge says it may.
    let expires_in = (verified.exp.min(now + MAX_PENDING_SECS) - now).max(1);

    let mut record = TransactionAuthorization::new(
        client_id,
        verified.resource.resource_uri.clone(),
        verified.txn,
        verified.authorization_details.to_string(),
        expires_in,
    );
    record.reason = verified.reason;
    record.reason_uri = verified.reason_uri;
    record.act = verified.act.map(|a| a.to_string());

    storage.save_transaction_authorization(&record).await?;

    tracing::info!(
        client_id = %record.client_id,
        resource_uri = %record.resource_uri,
        transaction_authorization_id = %record.transaction_authorization_id,
        "Transaction authorization challenge accepted; awaiting human approval"
    );

    Ok(no_store_headers(HttpResponse::Ok().json(json!({
        "transaction_authorization_id": record.transaction_authorization_id,
        "expires_in": expires_in,
        "interval": record.interval_seconds,
    }))))
}

fn mtls_thumbprint(req: &HttpRequest) -> Option<String> {
    req.headers()
        .get("X-Client-Cert-Thumbprint")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
}

fn mtls_subject_dn(req: &HttpRequest) -> Option<String> {
    req.headers()
        .get("X-SSL-Client-S-DN")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
}

/// The claims this server requires from a transaction challenge, already
/// validated.
struct VerifiedChallenge {
    resource: ProtectedResource,
    txn: String,
    authorization_details: Value,
    reason: String,
    reason_uri: String,
    act: Option<Value>,
    exp: i64,
}

/// Resolve the issuing protected resource from the challenge's unverified
/// `iss`, verify the signature against that resource's
/// `txn_challenge_jwks_uri`, and check every required claim.
async fn verify_challenge(
    challenge: &str,
    storage: &DynStorage,
    jwks_cache: Option<&JwksCache>,
    our_issuer: &str,
    agent: &AgentConfig,
) -> Result<VerifiedChallenge, OAuth2Error> {
    let header = jsonwebtoken::decode_header(challenge)
        .map_err(|_| OAuth2Error::invalid_request("malformed transaction_challenge JWT header"))?;
    if !ALLOWED_ALGS.contains(&header.alg) {
        return Err(OAuth2Error::invalid_request(
            "transaction_challenge uses an unsupported signature algorithm",
        ));
    }

    let unverified = decode_unverified_claims(challenge)
        .map_err(|e| OAuth2Error::invalid_request(e.error_description.as_deref().unwrap_or("")))?;
    let iss = unverified
        .get("iss")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            OAuth2Error::invalid_request("transaction_challenge is missing the iss claim")
        })?
        .to_string();

    // The issuer must be a registered protected resource that publishes a
    // challenge JWKS; anything else is an unknown issuer.
    let resource = storage
        .get_resource_by_uri(&iss)
        .await?
        .filter(|r| !r.txn_challenge_jwks_uri.trim().is_empty())
        .ok_or_else(|| {
            OAuth2Error::invalid_request(
                "transaction_challenge iss is not a known protected resource",
            )
        })?;

    let cache = jwks_cache.ok_or_else(|| {
        OAuth2Error::new(
            "server_error",
            Some("JWKS cache is not configured; cannot verify transaction challenges"),
        )
    })?;
    let jwks = cache
        .fetch(resource.txn_challenge_jwks_uri.trim())
        .await
        .map_err(|e| {
            OAuth2Error::invalid_request(&format!(
                "could not fetch the protected resource's challenge JWKS: {}",
                e.error_description.as_deref().unwrap_or(&e.error)
            ))
        })?;
    let key = select_key(&jwks, &header)
        .map_err(|e| OAuth2Error::invalid_request(e.error_description.as_deref().unwrap_or("")))?;

    let mut validation = Validation::new(header.alg);
    validation.set_issuer(&[&iss]);
    validation.set_audience(&[our_issuer]);
    validation.set_required_spec_claims(&["iss", "aud", "exp", "iat", "jti"]);
    let claims = decode::<Value>(challenge, &key, &validation)
        .map_err(|e| {
            OAuth2Error::invalid_request(&format!("transaction_challenge validation failed: {e}"))
        })?
        .claims;

    // Single use: a challenge may open exactly one pending approval.
    enforce_jti_replay(&format!("txn-challenge:{iss}"), &claims)
        .map_err(|e| OAuth2Error::invalid_request(e.error_description.as_deref().unwrap_or("")))?;

    let txn = claims
        .get("txn")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            OAuth2Error::invalid_request("transaction_challenge is missing the txn claim")
        })?
        .to_string();

    let authorization_details = claims
        .get("authorization_details")
        .filter(|v| v.is_array())
        .cloned()
        .ok_or_else(|| {
            OAuth2Error::invalid_request(
                "transaction_challenge authorization_details must be a JSON array",
            )
        })?;

    let reason = claims
        .get("reason")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            OAuth2Error::invalid_request("transaction_challenge reason must be a string")
        })?
        .to_string();

    let reason_uri = claims
        .get("reason_uri")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();

    // The signed challenge is the delegation basis for any `act` it carries.
    // Normalize it so a malformed chain never reaches an issued token, and
    // hold it to the same depth limit as every other delegation path — a
    // registered resource must not be able to inject an unbounded chain.
    let act = match claims.get("act") {
        Some(value) => {
            let chain = DelegationActor::from_value(value).map_err(|e| {
                OAuth2Error::invalid_request(&format!("transaction_challenge act claim: {e}"))
            })?;
            chain
                .validate_chain(agent.max_delegation_depth)
                .map_err(|e| {
                    OAuth2Error::invalid_request(&format!("transaction_challenge act claim: {e}"))
                })?;
            Some(chain.to_value())
        }
        None => None,
    };

    let exp = claims.get("exp").and_then(Value::as_i64).ok_or_else(|| {
        OAuth2Error::invalid_request("transaction_challenge exp claim is not a number")
    })?;

    Ok(VerifiedChallenge {
        resource,
        txn,
        authorization_details,
        reason,
        reason_uri,
        act,
        exp,
    })
}

// ---------------------------------------------------------------------------
// Approval page
// ---------------------------------------------------------------------------

/// Return `reason_uri` only when it is an absolute `http`/`https` URL, so no
/// other scheme can ever reach an `href` on the approval page.
fn safe_reason_link(reason_uri: &str) -> Option<String> {
    let trimmed = reason_uri.trim();
    if trimmed.is_empty() {
        return None;
    }
    match url::Url::parse(trimmed) {
        Ok(url) if matches!(url.scheme(), "http" | "https") => Some(trimmed.to_string()),
        _ => None,
    }
}

fn render_approval_page(
    record: &TransactionAuthorization,
    client_name: &str,
    acting_agent: Option<&str>,
) -> String {
    let details = serde_json::to_string_pretty(&record.authorization_details_value())
        .unwrap_or_else(|_| record.authorization_details.clone());
    // The resource controls `reason_uri`, and this page renders inside the
    // user's authenticated session. HTML-escaping alone leaves `javascript:`
    // and `data:` URIs intact, so only http(s) links are rendered at all.
    let reason_block = match safe_reason_link(&record.reason_uri) {
        Some(uri) => format!(
            r#"<p><a href="{uri}" rel="noreferrer noopener">More about this request</a></p>"#,
            uri = html_escape(&uri)
        ),
        None => String::new(),
    };
    let actor_block = match acting_agent {
        Some(sub) => format!("<p>Acting agent: {}</p>", html_escape(sub)),
        None => String::new(),
    };

    format!(
        r#"<!DOCTYPE html>
<html>
<head><title>Approve Transaction</title></head>
<body>
  <h1>Approve this operation?</h1>
  <p>{client} is asking you to approve an operation at {resource}.</p>
  <p>{reason}</p>
  {reason_block}
  {actor_block}
  <h2>Requested authorization</h2>
  <pre>{details}</pre>
  <form method="post" action="/oauth/transaction_authorization/approve">
    <input type="hidden" name="transaction_authorization_id" value="{id}" />
    <button type="submit" name="action" value="approve">Approve</button>
    <button type="submit" name="action" value="deny">Deny</button>
  </form>
</body>
</html>"#,
        client = html_escape(client_name),
        resource = html_escape(&record.resource_uri),
        reason = html_escape(&record.reason),
        reason_block = reason_block,
        actor_block = actor_block,
        details = html_escape(&details),
        id = html_escape(&record.transaction_authorization_id),
    )
}

/// Load a pending approval and reject the states a human can no longer act on.
async fn load_actionable(
    storage: &DynStorage,
    transaction_authorization_id: &str,
) -> Result<TransactionAuthorization, OAuth2Error> {
    let record = storage
        .get_transaction_authorization(transaction_authorization_id)
        .await?
        .ok_or_else(|| OAuth2Error::invalid_request("Unknown transaction_authorization_id"))?;

    if record.is_expired() {
        return Err(OAuth2Error::invalid_request(
            "transaction authorization expired",
        ));
    }
    if record.used {
        return Err(OAuth2Error::invalid_request(
            "transaction authorization already used",
        ));
    }
    if record.approved || record.denied {
        return Err(OAuth2Error::invalid_request(
            "transaction authorization has already been decided",
        ));
    }
    Ok(record)
}

/// `GET /oauth/transaction_authorization/approve` — the human-facing approval
/// page. Requires an authenticated session, exactly like the device
/// verification page.
pub async fn approve_page(
    query: web::Query<ApproveQuery>,
    session: Session,
    client_actor: web::Data<Addr<ClientActor>>,
    storage: web::Data<DynStorage>,
    agent: Option<web::Data<AgentConfig>>,
) -> Result<HttpResponse, OAuth2Error> {
    require_tac_enabled(&agent_config(&agent))?;

    let user_id: Option<String> = session.get("user_id").unwrap_or(None);
    if user_id.is_none() {
        let return_to = format!(
            "/oauth/transaction_authorization/approve{}",
            query
                .transaction_authorization_id
                .as_ref()
                .map(|id| format!("?transaction_authorization_id={id}"))
                .unwrap_or_default()
        );
        session
            .insert("return_to", return_to)
            .map_err(|e| OAuth2Error::new("server_error", Some(&e.to_string())))?;
        return Ok(HttpResponse::Found()
            .append_header(("Location", "/auth/login"))
            .finish());
    }

    let id = query
        .transaction_authorization_id
        .as_deref()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| OAuth2Error::invalid_request("Missing transaction_authorization_id"))?;

    let record = load_actionable(storage.as_ref(), id).await?;

    // A missing client row must not break the page; fall back to the id.
    let client_name = client_actor
        .send(GetClient {
            client_id: record.client_id.clone(),
            span: tracing::Span::current(),
        })
        .await
        .ok()
        .and_then(|r| r.ok())
        .map(|c| c.name)
        .unwrap_or_else(|| record.client_id.clone());

    let act = record.act_value();
    let acting_agent = act
        .as_ref()
        .and_then(|a| a.get("sub"))
        .and_then(Value::as_str);

    Ok(HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(render_approval_page(&record, &client_name, acting_agent)))
}

/// `POST /oauth/transaction_authorization/approve` — record the human decision.
pub async fn approve_submit(
    form: web::Form<ApproveForm>,
    session: Session,
    storage: web::Data<DynStorage>,
    agent: Option<web::Data<AgentConfig>>,
) -> Result<HttpResponse, OAuth2Error> {
    require_tac_enabled(&agent_config(&agent))?;

    let user_id: Option<String> = session.get("user_id").unwrap_or(None);
    let user_id = user_id.ok_or_else(|| OAuth2Error::access_denied("Authentication required"))?;

    let record = load_actionable(storage.as_ref(), &form.transaction_authorization_id).await?;

    let approved = form.action.as_deref().unwrap_or("approve") != "deny";
    storage
        .settle_transaction_authorization(&record.transaction_authorization_id, &user_id, approved)
        .await?;

    tracing::info!(
        client_id = %record.client_id,
        transaction_authorization_id = %record.transaction_authorization_id,
        approved,
        "Transaction authorization settled by the end user"
    );

    let body = if approved {
        "<h1>Operation approved. You can return to the application.</h1>"
    } else {
        "<h1>Operation denied.</h1>"
    };
    Ok(HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(body))
}

// ---------------------------------------------------------------------------
// Polling grant
// ---------------------------------------------------------------------------

/// `grant_type=urn:ietf:params:oauth:grant-type:transaction-authorization` —
/// poll a pending approval and, once approved, issue a short-lived access
/// token carrying the challenge's `txn` and the approved
/// `authorization_details`.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn handle_transaction_authorization_grant(
    req: TokenRequest,
    cnf_claim: Option<Value>,
    token_actor: web::Data<TokenActorPool>,
    client_actor: web::Data<Addr<ClientActor>>,
    storage: web::Data<DynStorage>,
    metrics: web::Data<Metrics>,
    oidc_config: web::Data<OidcConfig>,
    agent: AgentConfig,
    jwks_cache: Option<web::Data<JwksCache>>,
    mtls_thumbprint: Option<&str>,
    mtls_subject_dn: Option<&str>,
) -> Result<HttpResponse, OAuth2Error> {
    require_tac_enabled(&agent)?;

    let transaction_authorization_id = req
        .transaction_authorization_id
        .clone()
        .ok_or_else(|| OAuth2Error::invalid_request("Missing transaction_authorization_id"))?;

    // --- Authenticate the polling client ---------------------------------
    let client = client_actor
        .send(GetClient {
            client_id: req.client_id.clone(),
            span: tracing::Span::current(),
        })
        .await
        .map_err(|e| OAuth2Error::new("server_error", Some(&e.to_string())))??;

    if client.is_public() {
        return Err(OAuth2Error::invalid_client(
            "Public clients cannot use transaction authorization",
        ));
    }
    let token_endpoint_url = format!("{}/oauth/token", oidc_config.issuer.trim_end_matches('/'));
    let resolved_jwks =
        resolve_client_jwks(&client, jwks_cache.as_ref().map(|d| d.as_ref())).await?;
    authenticate_confidential_client(
        &client,
        &req,
        &token_endpoint_url,
        &oidc_config.issuer,
        resolved_jwks.as_ref(),
        mtls_thumbprint,
        mtls_subject_dn,
    )?;

    if !client.supports_grant_type(GRANT_TRANSACTION_AUTHORIZATION) {
        return Err(OAuth2Error::unauthorized_client(
            "Client is not allowed to use the transaction-authorization grant",
        ));
    }

    // --- Poll the approval -------------------------------------------------
    let record = storage
        .get_transaction_authorization(&transaction_authorization_id)
        .await?
        .ok_or_else(|| OAuth2Error::invalid_grant("Invalid transaction_authorization_id"))?;

    if record.client_id != client.client_id {
        return Err(OAuth2Error::invalid_grant(
            "transaction_authorization_id does not belong to this client",
        ));
    }
    if record.used {
        return Err(OAuth2Error::invalid_grant(
            "transaction_authorization_id already used",
        ));
    }
    if record.is_expired() {
        return Err(OAuth2Error::new(
            "expired_token",
            Some("transaction authorization expired"),
        ));
    }
    if record.denied {
        return Err(OAuth2Error::access_denied(
            "End-user denied the transaction",
        ));
    }
    if !record.approved {
        return Err(OAuth2Error::new(
            "authorization_pending",
            Some("End-user approval is pending"),
        ));
    }

    let user_id = record.user_id.clone().ok_or_else(|| {
        OAuth2Error::invalid_grant("Approved transaction authorization is missing its approver")
    })?;

    // --- Issue the access token (never a refresh token) -------------------
    //
    // The approval is per-operation, so the token carries no scope: its
    // authority is exactly the approved `authorization_details`.
    let authorization_details = record.authorization_details_value();
    let resources = vec![record.resource_uri.clone()];
    let token = token_actor
        .route(&client.client_id)
        .send(CreateToken {
            user_id: Some(user_id),
            client_id: client.client_id.clone(),
            scope: String::new(),
            include_refresh: false,
            token_family: None,
            resources: resources.clone(),
            cnf: cnf_claim.clone(),
            authorization_details: Some(authorization_details.clone()),
            act: record.act_value(),
            txn: Some(record.txn.clone()),
            ttl_override_secs: Some(TOKEN_TTL_CAP_SECS),
            span: tracing::Span::current(),
        })
        .await
        .map_err(|e| OAuth2Error::new("server_error", Some(&e.to_string())))??;

    storage
        .mark_transaction_authorization_used(&record.transaction_authorization_id)
        .await?;

    metrics.oauth_token_issued_total.inc();

    let response = apply_dpop_token_type(TokenResponse::from(token), cnf_claim.as_ref());
    let mut body = serde_json::to_value(&response)
        .map_err(|e| OAuth2Error::new("server_error", Some(&e.to_string())))?;
    body["authorization_details"] = authorization_details;
    body["resource"] = Value::String(record.resource_uri.clone());

    Ok(no_store_headers(HttpResponse::Ok().json(body)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record() -> TransactionAuthorization {
        let mut r = TransactionAuthorization::new(
            "agent_client".to_string(),
            "https://rs.example".to_string(),
            "txn-1".to_string(),
            r#"[{"type":"payment","amount":"42.00"}]"#.to_string(),
            600,
        );
        r.reason = "Transfer 42.00 EUR".to_string();
        r
    }

    #[test]
    fn approval_page_shows_reason_and_details() {
        let html = render_approval_page(&record(), "Agent Client", None);
        assert!(html.contains("Transfer 42.00 EUR"));
        assert!(html.contains("Agent Client"));
        assert!(html.contains("&quot;payment&quot;"));
        assert!(html.contains("https://rs.example"));
        assert!(!html.contains("Acting agent"));
    }

    #[test]
    fn approval_page_escapes_resource_controlled_text() {
        let mut r = record();
        r.reason = r#"<script>alert(1)</script>"#.to_string();
        r.reason_uri = r#"https://rs.example/"><script>"#.to_string();
        let html = render_approval_page(&r, r#""><script>bad()</script>"#, None);
        assert!(!html.contains("<script>alert(1)</script>"));
        assert!(!html.contains("<script>bad()</script>"));
        assert!(!html.contains(r#"href="https://rs.example/"><"#));
        assert!(html.contains("&lt;script&gt;"));

        // Escaping leaves a `javascript:` URI intact, so the scheme check —
        // not the escaper — is what keeps it off the page.
        r.reason = "Transfer 42.00 EUR".to_string();
        r.reason_uri = "javascript:alert(1)".to_string();
        let html = render_approval_page(&r, "Agent Client", None);
        assert!(!html.contains(r#"href="javascript:"#));
        assert!(!html.contains("javascript:"));
        assert!(!html.contains("More about this request"));
    }

    #[test]
    fn only_http_reason_links_are_rendered() {
        assert_eq!(
            safe_reason_link("https://rs.example/tx/1"),
            Some("https://rs.example/tx/1".to_string())
        );
        assert_eq!(
            safe_reason_link("  http://rs.example/tx/1  "),
            Some("http://rs.example/tx/1".to_string())
        );
        for hostile in [
            "",
            "   ",
            "javascript:alert(1)",
            "JavaScript:alert(1)",
            "data:text/html,<script>alert(1)</script>",
            "/relative/path",
        ] {
            assert_eq!(safe_reason_link(hostile), None, "{hostile}");
        }
    }

    #[test]
    fn approval_page_names_the_acting_agent() {
        let html = render_approval_page(&record(), "Agent Client", Some("agent-7"));
        assert!(html.contains("Acting agent: agent-7"));
    }

    #[test]
    fn tac_flag_gates_every_entry_point() {
        let off = AgentConfig::default();
        assert!(require_tac_enabled(&off).is_err());
        let on = AgentConfig {
            tac_enabled: true,
            ..Default::default()
        };
        assert!(require_tac_enabled(&on).is_ok());
    }
}
