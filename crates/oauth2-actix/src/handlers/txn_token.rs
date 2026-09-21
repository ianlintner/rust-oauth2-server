//! Transaction Token (Txn-Token) issuance —
//! draft-ietf-oauth-transaction-tokens-11, with the A2A profile
//! (draft-liu-oauth-a2a-profile-00) and draft-araut actor/principal
//! compatibility.
//!
//! Reached from the RFC 8693 token-exchange arm when
//! `requested_token_type = urn:ietf:params:oauth:token-type:txn_token`.
//!
//! A transaction token is a short-lived, trust-domain-scoped assertion that
//! travels with one call chain: every workload that handles the request
//! exchanges the token it received for a *replacement* carrying the same
//! `txn` identifier and the same subject, narrowing scope as it goes. The
//! token is never persisted and never refreshable — its only authentication
//! is the signature and `exp`.

use actix_web::HttpResponse;
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

use oauth2_core::models::key_set::Algorithm as KeyAlgorithm;
use oauth2_core::token_types;
use oauth2_core::OAuth2Error;

use crate::handlers::oauth::{no_store_headers, validate_scope_subset};
use crate::handlers::token_exchange::ExchangeContext;

/// JOSE `typ` header value identifying a transaction token
/// (draft-ietf-oauth-transaction-tokens §5.1).
pub(crate) const TXN_TOKEN_TYP: &str = "txntoken+jwt";

/// The transaction token payload. Deliberately local to this module: the
/// claim set is specific to the txn-token profile and has nothing to share
/// with the access-token `Claims`.
#[derive(Serialize, Deserialize)]
struct TxnTokenClaims {
    iss: String,
    iat: i64,
    exp: i64,
    /// Always the trust domain — a txn token is valid nowhere else.
    aud: String,
    /// Stable identifier for the whole call chain.
    txn: String,
    sub: String,
    scope: String,
    /// Identifier of the workload that requested this token.
    req_wl: String,
    /// Transaction context: immutable for the lifetime of the transaction.
    #[serde(skip_serializing_if = "Option::is_none")]
    tctx: Option<Value>,
    /// Request context: may be replaced at every hop.
    #[serde(skip_serializing_if = "Option::is_none")]
    rctx: Option<Value>,
    /// A2A profile: the declared purpose of the transaction.
    #[serde(skip_serializing_if = "Option::is_none")]
    purp: Option<String>,
    /// RFC 8693 §4.1 delegation chain, carried over from the subject token.
    #[serde(skip_serializing_if = "Option::is_none")]
    act: Option<Value>,
    /// draft-araut compatibility: the outermost actor's `sub`.
    #[serde(skip_serializing_if = "Option::is_none")]
    actor: Option<String>,
    /// draft-araut compatibility: the identity being acted for.
    #[serde(skip_serializing_if = "Option::is_none")]
    principal: Option<String>,
}

pub(crate) async fn issue(ctx: &ExchangeContext) -> Result<HttpResponse, OAuth2Error> {
    if !ctx.config.txn_tokens_enabled {
        return Err(OAuth2Error::invalid_request(
            "transaction tokens are not enabled",
        ));
    }
    // A txn token's audience *is* the trust domain, so without one configured
    // there is nothing to issue it for.
    let trust_domain = ctx
        .config
        .trust_domain
        .as_deref()
        .map(str::trim)
        .filter(|domain| !domain.is_empty())
        .ok_or_else(|| {
            OAuth2Error::invalid_request("transaction tokens require a configured trust domain")
        })?;

    // draft-ietf-oauth-transaction-tokens §6.1: the requester is a workload,
    // authenticated by a key rather than by a shared secret. A secret that
    // leaks anywhere in the domain would otherwise mint tokens for any subject.
    match ctx.client.token_endpoint_auth_method.as_str() {
        "private_key_jwt" | "tls_client_auth" | "self_signed_tls_client_auth" => {}
        _ => {
            return Err(OAuth2Error::invalid_client(
                "transaction tokens require asymmetric client authentication",
            ))
        }
    }

    if ctx.req.audience.is_empty() {
        return Err(OAuth2Error::invalid_request(
            "audience is required for a transaction token request",
        ));
    }
    if ctx.req.audience.len() != 1 || ctx.req.audience[0] != trust_domain {
        return Err(OAuth2Error::new(
            "invalid_target",
            Some("audience must be the configured trust domain"),
        ));
    }

    let request_details = parse_json_object(ctx.req.request_details.as_deref(), "request_details")?;
    let request_context = parse_json_object(ctx.req.request_context.as_deref(), "request_context")?;

    // `Some` when this is a replacement: the claims of the txn token presented
    // as the subject (resolved and signature-checked by `resolve_token`).
    let replaced = ctx.subject.txn.as_ref();

    // A2A immutability: `tctx` is fixed when the transaction starts. A
    // replacement may restate it, but may not change it.
    let tctx = match replaced {
        None => request_details,
        Some(previous) => {
            let inherited = previous.get("tctx").cloned();
            if let Some(supplied) = request_details.as_ref() {
                if inherited.as_ref() != Some(supplied) {
                    return Err(OAuth2Error::invalid_request(
                        "request_details must not change across a transaction token replacement",
                    ));
                }
            }
            inherited
        }
    };
    // `rctx` describes the current hop, so a replacement may restate it and
    // inherits the previous value only when it says nothing.
    let rctx = match (request_context, replaced) {
        (Some(supplied), _) => Some(supplied),
        (None, Some(previous)) => previous.get("rctx").cloned(),
        (None, None) => None,
    };

    // One transaction, one identifier: preserved across every replacement.
    let txn = replaced
        .and_then(|previous| previous.get("txn").and_then(Value::as_str))
        .map(str::to_string)
        .unwrap_or_else(|| Uuid::new_v4().to_string());

    let sub = ctx.subject.sub.clone();
    let scope = match ctx.req.scope.as_deref() {
        Some(requested) => {
            validate_scope_subset(requested, &ctx.subject.scope)?;
            requested.to_string()
        }
        None => ctx.subject.scope.clone(),
    };

    let act = ctx.subject.act.clone();
    let purp = if ctx.config.a2a_profile_enabled {
        ctx.req.purp.clone()
    } else {
        None
    };
    // draft-araut names the two ends of the chain explicitly, which the A2A
    // profile mirrors. Both are only meaningful when there *is* a delegation.
    let actor = if ctx.config.a2a_profile_enabled {
        act.as_ref()
            .and_then(|act| act.get("sub").and_then(Value::as_str))
            .map(str::to_string)
    } else {
        None
    };
    let principal = actor.as_ref().map(|_| sub.clone());

    let now = chrono::Utc::now().timestamp();
    let expires_in = ctx.config.txn_token_ttl_secs;
    let claims = TxnTokenClaims {
        iss: ctx.oidc_config.issuer.clone(),
        iat: now,
        exp: now + expires_in as i64,
        aud: trust_domain.to_string(),
        txn,
        sub,
        scope,
        req_wl: ctx.client.client_id.clone(),
        tctx,
        rctx,
        purp,
        act,
        actor,
        principal,
    };

    let token = sign(ctx, &claims).await?;

    ctx.metrics.oauth_token_issued_total.inc();

    // draft-ietf-oauth-transaction-tokens §6.2: `token_type` is `N_A` — a txn
    // token is not presented as an HTTP credential — and there is no refresh
    // token, because a replacement is always requested from the subject token.
    Ok(no_store_headers(HttpResponse::Ok().json(
        serde_json::json!({
            "token_type": "N_A",
            "access_token": token,
            "issued_token_type": token_types::TXN_TOKEN,
            "expires_in": expires_in,
        }),
    )))
}

/// Sign the payload with the current RS256 key when the server has one,
/// falling back to the configured HS256 secret. Mirrors
/// `Claims::encode_with_key`, but stamps the txn-token `typ`.
async fn sign(ctx: &ExchangeContext, claims: &TxnTokenClaims) -> Result<String, OAuth2Error> {
    let keyset = match ctx.keyset.as_ref() {
        Some(keyset) => Some(keyset.read().await.clone()),
        None => None,
    };

    let (mut header, key) = match keyset
        .as_ref()
        .and_then(|keyset| keyset.current_for_alg(KeyAlgorithm::RS256))
    {
        Some(signing_key) => {
            let mut header = Header::new(Algorithm::RS256);
            header.kid = Some(signing_key.kid.clone());
            let key = EncodingKey::from_rsa_pem(&signing_key.key_material).map_err(|e| {
                OAuth2Error::new(
                    "server_error",
                    Some(&format!("transaction token signing key is unusable: {e}")),
                )
            })?;
            (header, key)
        }
        None => (
            Header::new(Algorithm::HS256),
            EncodingKey::from_secret(ctx.oidc_config.jwt_secret.as_bytes()),
        ),
    };
    header.typ = Some(TXN_TOKEN_TYP.to_string());

    jsonwebtoken::encode(&header, claims, &key).map_err(|e| {
        OAuth2Error::new(
            "server_error",
            Some(&format!("failed to sign transaction token: {e}")),
        )
    })
}

/// `request_details` / `request_context` are JSON objects carried in a form
/// value; anything else (an array, a scalar, malformed JSON) is a client error.
fn parse_json_object(raw: Option<&str>, name: &str) -> Result<Option<Value>, OAuth2Error> {
    let raw = match raw {
        None => return Ok(None),
        Some(raw) => raw,
    };
    let parsed: Value = serde_json::from_str(raw)
        .map_err(|_| OAuth2Error::invalid_request(&format!("{name} is not valid JSON")))?;
    if !parsed.is_object() {
        return Err(OAuth2Error::invalid_request(&format!(
            "{name} must be a JSON object"
        )));
    }
    Ok(Some(parsed))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_json_object_is_accepted() {
        assert_eq!(
            parse_json_object(Some(r#"{"a":1}"#), "request_details").expect("object"),
            Some(json!({ "a": 1 }))
        );
    }

    #[test]
    fn a_json_array_is_rejected() {
        let err = parse_json_object(Some("[1,2]"), "request_details").expect_err("must reject");
        assert_eq!(err.error, "invalid_request");
    }

    #[test]
    fn malformed_json_is_rejected() {
        let err = parse_json_object(Some("{"), "request_context").expect_err("must reject");
        assert_eq!(err.error, "invalid_request");
    }

    #[test]
    fn an_absent_value_stays_absent() {
        assert_eq!(
            parse_json_object(None, "request_details").expect("none"),
            None
        );
    }
}
