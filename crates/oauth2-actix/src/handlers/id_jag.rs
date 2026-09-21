//! Identity chaining / Identity Assertion Authorization Grant (ID-JAG).
//!
//! draft-ietf-oauth-identity-chaining-17 and
//! draft-ietf-oauth-identity-assertion-authz-grant-04 (issuing side).
//!
//! Reached from the RFC 8693 token-exchange arm when the client asks for
//! `requested_token_type = urn:ietf:params:oauth:token-type:id-jag`, or for
//! `...:token-type:jwt` with a single `audience` naming a configured chaining
//! target. What comes back is an *authorization grant* the client presents to
//! a second authorization server — not a usable access token. It is therefore
//! short-lived (5 minutes at most), never persisted, and handed over with
//! `token_type: "N_A"`.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::Utc;
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde::Serialize;
use serde_json::Value;
use uuid::Uuid;

use actix_web::HttpResponse;
use oauth2_config::AgentConfig;
use oauth2_core::models::actor::{Actor, ActorChainError, SUB_PROFILE_SERVICE};
use oauth2_core::models::key_set::{Algorithm as KeyAlgorithm, KeySet, SigningKey};
use oauth2_core::token_types;
use oauth2_core::OAuth2Error;

use crate::handlers::oauth::{no_store_headers, TokenRequest};
use crate::handlers::token_exchange::ExchangeContext;

/// JOSE `typ` of an identity assertion authorization grant
/// (draft-ietf-oauth-identity-assertion-authz-grant-04 §5.1).
const ID_JAG_TYP: &str = "oauth-id-jag+jwt";

/// Maximum assertion lifetime. The grant is redeemed immediately at the
/// downstream authorization server, so it never needs to outlive the request.
const MAX_LIFETIME_SECS: i64 = 300;

/// The identity-chaining trigger: a single `audience` value naming one of the
/// configured chaining targets.
pub(crate) fn is_chaining_request(req: &TokenRequest, config: &AgentConfig) -> bool {
    req.audience.len() == 1 && config.chaining_targets.contains(&req.audience[0])
}

/// Whether this exchange asks for an ID-JAG, either explicitly or via the
/// identity-chaining trigger. Consulted before the subject token is resolved,
/// because only this path accepts a refresh token as the subject.
pub(crate) fn is_id_jag_request(req: &TokenRequest, config: &AgentConfig) -> bool {
    match req.requested_token_type.as_deref() {
        Some(token_types::ID_JAG) => true,
        Some(token_types::JWT) => is_chaining_request(req, config),
        _ => false,
    }
}

/// The claim set of an identity assertion authorization grant.
#[derive(Serialize)]
struct IdJagClaims {
    iss: String,
    sub: String,
    aud: String,
    client_id: String,
    jti: String,
    iat: i64,
    exp: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    scope: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    resource: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    authorization_details: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    auth_time: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    acr: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    act: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cnf: Option<Value>,
}

pub(crate) async fn issue(ctx: &ExchangeContext) -> Result<HttpResponse, OAuth2Error> {
    if !ctx.config.id_jag_enabled {
        return Err(OAuth2Error::invalid_request(
            "ID-JAG issuance is not enabled",
        ));
    }

    // --- Target authorization server -----------------------------------------
    // Exactly one `audience` is required; anything else is unresolvable.
    let audience = match ctx.req.audience.as_slice() {
        [single] => single.clone(),
        [] => {
            return Err(OAuth2Error::invalid_request(
                "audience is required when requesting an ID-JAG",
            ))
        }
        _ => {
            return Err(OAuth2Error::invalid_request(
                "an ID-JAG names exactly one audience",
            ))
        }
    };
    if !ctx.config.chaining_targets.contains(&audience) {
        return Err(OAuth2Error::new(
            "invalid_target",
            Some("audience is not a configured identity-chaining target"),
        ));
    }

    // --- Subject -------------------------------------------------------------
    // The exchange algorithm has already narrowed scope and RAR against the
    // subject token and authorised any delegation; what is left is to shape
    // those facts into the assertion.
    let subject_claims = ctx
        .req
        .subject_token
        .as_deref()
        .and_then(jwt_payload)
        .unwrap_or(Value::Null);

    let sub = ctx
        .subject
        .user_id
        .clone()
        .unwrap_or_else(|| ctx.subject.sub.clone());

    let scope = ctx
        .req
        .scope
        .clone()
        .unwrap_or_else(|| ctx.subject.scope.clone());

    let authorization_details = match ctx.req.authorization_details.as_deref() {
        Some(raw) => serde_json::from_str::<Value>(raw).ok(),
        None => ctx.subject.authorization_details.clone(),
    };

    let resource = match ctx.req.resource.as_slice() {
        [] => None,
        [single] => Some(Value::String(single.clone())),
        many => Some(Value::from(many.to_vec())),
    };

    // OIDC Core §2: an ID token subject may carry the authentication context;
    // forward it so the downstream AS can apply its own step-up policy.
    let auth_time = subject_claims.get("auth_time").and_then(Value::as_i64);
    let acr = str_claim(&subject_claims, "acr");
    let email = match str_claim(&subject_claims, "email") {
        Some(email) => Some(email),
        None => match ctx.subject.user_id.as_deref() {
            Some(user_id) => ctx
                .storage
                .get_user_by_id(user_id)
                .await?
                .map(|user| user.email),
            None => None,
        },
    };

    // --- Delegation ----------------------------------------------------------
    // Mirrors the access-token path: an `act` chain only when an actor token
    // was presented and authorised, otherwise whatever the subject carried.
    let act = match ctx.actor.as_ref() {
        None => ctx.subject.act.clone(),
        Some(actor) => {
            let issuer = ctx.oidc_config.issuer.clone();
            let new_actor = Actor::new(actor.sub.clone(), issuer)
                .with_profile(actor.sub_profile.as_deref().unwrap_or(SUB_PROFILE_SERVICE));
            let chain = match ctx.subject.act.as_ref() {
                Some(existing) => {
                    let inner = Actor::from_value(existing).map_err(|e| {
                        OAuth2Error::invalid_grant(&format!(
                            "subject_token carries a malformed act claim: {e}"
                        ))
                    })?;
                    new_actor.with_inner(inner)
                }
                None => new_actor,
            };
            chain
                .validate_chain(ctx.config.max_delegation_depth)
                .map_err(|e| match e {
                    ActorChainError::DepthExceeded { .. } => {
                        OAuth2Error::invalid_request(&e.to_string())
                    }
                    other => OAuth2Error::invalid_grant(&other.to_string()),
                })?;
            Some(chain.to_value())
        }
    };

    // RFC 9449: a DPoP proof at this endpoint binds the assertion to the same
    // key, so the downstream AS can require proof of possession on redemption.
    let cnf = if ctx.dpop_present {
        ctx.cnf_claim.clone()
    } else {
        None
    };

    // --- Lifetime ------------------------------------------------------------
    let now = Utc::now().timestamp();
    let subject_remaining = subject_claims
        .get("exp")
        .and_then(Value::as_i64)
        .map(|exp| exp - now);
    let lifetime = match subject_remaining {
        Some(remaining) => remaining.min(MAX_LIFETIME_SECS),
        None => MAX_LIFETIME_SECS,
    };
    if lifetime <= 0 {
        return Err(OAuth2Error::invalid_grant("subject_token has expired"));
    }

    let claims = IdJagClaims {
        iss: ctx.oidc_config.issuer.clone(),
        sub,
        aud: audience,
        client_id: ctx.req.client_id.clone(),
        jti: Uuid::new_v4().to_string(),
        iat: now,
        exp: now + lifetime,
        scope: Some(scope.clone()).filter(|s| !s.is_empty()),
        resource,
        authorization_details: authorization_details.clone(),
        email,
        auth_time,
        acr,
        act,
        cnf,
    };

    // --- Signature -----------------------------------------------------------
    let signing_key = match ctx.keyset.as_ref() {
        Some(keyset) => {
            let keyset = keyset.read().await;
            pick_signing_key(&keyset)
        }
        None => None,
    };
    let assertion = encode_assertion(&claims, signing_key.as_ref(), &ctx.oidc_config.jwt_secret)?;

    ctx.metrics.oauth_token_issued_total.inc();

    // RFC 8693 §2.2.1: echo the token type that was asked for. The assertion
    // is not a bearer credential, so `token_type` is "N_A" (RFC 8693 §2.2.1).
    let issued_token_type = match ctx.req.requested_token_type.as_deref() {
        Some(token_types::ID_JAG) => token_types::ID_JAG,
        _ => token_types::JWT,
    };

    let mut body = serde_json::json!({
        "access_token": assertion,
        "issued_token_type": issued_token_type,
        "token_type": "N_A",
        "expires_in": lifetime,
        "scope": scope,
    });
    if let Some(details) = authorization_details {
        body["authorization_details"] = details;
    }

    Ok(no_store_headers(HttpResponse::Ok().json(body)))
}

/// Prefer the current RS256 key so the downstream authorization server can
/// verify the assertion from our JWKS; fall back to whatever key is current.
fn pick_signing_key(keyset: &KeySet) -> Option<SigningKey> {
    keyset
        .current_for_alg(KeyAlgorithm::RS256)
        .or_else(|| keyset.current())
        .cloned()
}

fn encode_assertion(
    claims: &IdJagClaims,
    key: Option<&SigningKey>,
    jwt_secret: &str,
) -> Result<String, OAuth2Error> {
    let (header, encoding_key) = match key {
        Some(key) => {
            let mut header = match key.algorithm {
                KeyAlgorithm::HS256 => Header::default(),
                KeyAlgorithm::RS256 => Header::new(Algorithm::RS256),
            };
            header.typ = Some(ID_JAG_TYP.to_string());
            header.kid = Some(key.kid.clone());
            let encoding_key = match key.algorithm {
                KeyAlgorithm::HS256 => EncodingKey::from_secret(&key.key_material),
                KeyAlgorithm::RS256 => EncodingKey::from_rsa_pem(&key.key_material)
                    .map_err(|e| OAuth2Error::new("server_error", Some(&e.to_string())))?,
            };
            (header, encoding_key)
        }
        None => (
            Header {
                typ: Some(ID_JAG_TYP.to_string()),
                ..Header::default()
            },
            EncodingKey::from_secret(jwt_secret.as_bytes()),
        ),
    };

    jsonwebtoken::encode(&header, claims, &encoding_key)
        .map_err(|e| OAuth2Error::new("server_error", Some(&e.to_string())))
}

/// Decode a JWT payload without verifying the signature. The caller has
/// already authenticated the token through the exchange's own resolution.
fn jwt_payload(token: &str) -> Option<Value> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return None;
    }
    let bytes = URL_SAFE_NO_PAD.decode(parts[1]).ok()?;
    serde_json::from_slice(&bytes).ok()
}

fn str_claim(claims: &Value, name: &str) -> Option<String> {
    claims
        .get(name)
        .and_then(Value::as_str)
        .map(str::to_string)
        .filter(|s| !s.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(targets: &[&str]) -> AgentConfig {
        AgentConfig {
            id_jag_enabled: true,
            chaining_targets: targets.iter().map(|t| t.to_string()).collect(),
            ..Default::default()
        }
    }

    fn request(requested_token_type: Option<&str>, audience: &[&str]) -> TokenRequest {
        TokenRequest {
            grant_type: token_types::GRANT_TOKEN_EXCHANGE.to_string(),
            code: None,
            redirect_uri: None,
            client_id: "c".to_string(),
            client_secret: None,
            refresh_token: None,
            username: None,
            password: None,
            scope: None,
            code_verifier: None,
            device_code: None,
            client_assertion_type: None,
            client_assertion: None,
            resource: Vec::new(),
            assertion: None,
            audience: audience.iter().map(|a| a.to_string()).collect(),
            subject_token: None,
            subject_token_type: None,
            actor_token: None,
            actor_token_type: None,
            requested_token_type: requested_token_type.map(str::to_string),
            authorization_details: None,
        }
    }

    #[test]
    fn id_jag_token_type_always_triggers_the_arm() {
        let req = request(Some(token_types::ID_JAG), &[]);
        assert!(is_id_jag_request(&req, &config(&[])));
    }

    #[test]
    fn jwt_token_type_triggers_only_for_a_configured_target() {
        let targets = config(&["https://as-b.example"]);
        assert!(is_id_jag_request(
            &request(Some(token_types::JWT), &["https://as-b.example"]),
            &targets
        ));
        assert!(!is_id_jag_request(
            &request(Some(token_types::JWT), &["https://other.example"]),
            &targets
        ));
        assert!(!is_id_jag_request(
            &request(Some(token_types::JWT), &[]),
            &targets
        ));
    }

    #[test]
    fn two_audiences_never_trigger_identity_chaining() {
        let targets = config(&["https://as-b.example", "https://as-c.example"]);
        assert!(!is_id_jag_request(
            &request(
                Some(token_types::JWT),
                &["https://as-b.example", "https://as-c.example"]
            ),
            &targets
        ));
    }

    #[test]
    fn a_plain_exchange_is_not_an_id_jag_request() {
        assert!(!is_id_jag_request(
            &request(None, &["https://as-b.example"]),
            &config(&["https://as-b.example"])
        ));
    }
}
