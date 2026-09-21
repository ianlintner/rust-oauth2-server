//! RFC 8693 — OAuth 2.0 Token Exchange, with actor (`act`) delegation chains.
//!
//! The grant takes a `subject_token` (the identity being acted for) and an
//! optional `actor_token` (the identity doing the acting) and mints a new
//! access token that is narrowed — never widened — in scope, audience and
//! `authorization_details` relative to the subject token.
//!
//! Delegation is only ever recorded when there is a validated basis for it:
//! the subject token's `may_act` claim (RFC 8693 §4.4) or the subject
//! client's `allowed_actors` registration. The resulting `act` chain is
//! depth-limited by `AgentConfig::max_delegation_depth`.

use std::collections::HashSet;
use std::sync::Arc;

use actix::Addr;
use actix_web::{web, HttpResponse};
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use serde_json::Value;
use tokio::sync::RwLock;

use oauth2_config::AgentConfig;
use oauth2_core::models::actor::{Actor, ActorChainError, SUB_PROFILE_SERVICE};
use oauth2_core::models::key_set::{Algorithm as KeyAlgorithm, KeySet};
use oauth2_core::token_types;
use oauth2_core::{Claims, IdTokenClaims, OAuth2Error, ProtectedResource};
use oauth2_observability::Metrics;
use oauth2_ports::DynStorage;

use crate::actors::{ClientActor, CreateToken, LookupToken, TokenActorPool, ValidateRefreshToken};
use crate::handlers::cimd::CimdFetcher;
use crate::handlers::client_resolver::{materialize_cimd_client, resolve_client};
use crate::handlers::jwks_cache::JwksCache;
use crate::handlers::oauth::{
    authenticate_confidential_client, no_store_headers, resolve_client_jwks, validate_scope_subset,
    TokenRequest,
};
use crate::handlers::wellknown::OidcConfig;

/// A security token that has been authenticated and reduced to the facts the
/// exchange algorithm needs. Built by [`resolve_token`].
pub(crate) struct ResolvedToken {
    /// The token's subject (`sub`).
    pub sub: String,
    /// The client the token was issued to, when known.
    pub client_id: Option<String>,
    /// The resource-owner this token represents, when it is a user token.
    pub user_id: Option<String>,
    pub scope: String,
    /// Effective audience: the resource indicators the token is bound to, or
    /// `[client_id]` when it carries no resource restriction.
    pub aud: Vec<String>,
    /// Existing `act` chain carried by the token, if any.
    pub act: Option<Value>,
    /// RFC 8693 §4.4 `may_act`: the party permitted to act for this subject.
    pub may_act: Option<Value>,
    pub sub_profile: Option<String>,
    pub authorization_details: Option<Value>,
    pub cnf: Option<Value>,
    /// `true` when this token is an OIDC ID token, which carries no scope of
    /// its own and therefore needs the request to name one explicitly.
    pub is_id_token: bool,
    /// Raw claims of a transaction-token subject (`None` otherwise).
    /// `ResolvedToken` cannot carry the txn-specific members
    /// (`txn`, `tctx`, `rctx`, `purp`, `req_wl`), so the replacement path in
    /// [`crate::handlers::txn_token`] reads them from here.
    pub txn: Option<Value>,
}

/// Everything the exchange algorithm operates on once the request has been
/// authenticated and both tokens resolved.
pub(crate) struct ExchangeContext {
    pub req: TokenRequest,
    pub client: oauth2_core::Client,
    pub cnf_claim: Option<Value>,
    pub dpop_present: bool,
    pub subject: ResolvedToken,
    pub actor: Option<ResolvedToken>,
    pub config: AgentConfig,
    pub storage: DynStorage,
    pub token_actor: web::Data<TokenActorPool>,
    pub metrics: web::Data<Metrics>,
    pub oidc_config: web::Data<OidcConfig>,
    pub keyset: Option<web::Data<Arc<RwLock<KeySet>>>>,
}

// ---------------------------------------------------------------------------
// Entry point: client authentication + token resolution (steps 1-3)
// ---------------------------------------------------------------------------

/// Dispatch target for `grant_type=urn:ietf:params:oauth:grant-type:token-exchange`.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn exchange(
    req: TokenRequest,
    cnf_claim: Option<Value>,
    dpop_present: bool,
    token_actor: web::Data<TokenActorPool>,
    client_actor: web::Data<Addr<ClientActor>>,
    storage: DynStorage,
    metrics: web::Data<Metrics>,
    oidc_config: web::Data<OidcConfig>,
    config: AgentConfig,
    keyset: Option<web::Data<Arc<RwLock<KeySet>>>>,
    jwks_cache: Option<web::Data<JwksCache>>,
    mtls_thumbprint: Option<&str>,
    mtls_subject_dn: Option<&str>,
    mtls_san_uri: Option<&str>,
    mtls_san_dns: Option<&str>,
    cimd: Option<web::Data<CimdFetcher>>,
) -> Result<HttpResponse, OAuth2Error> {
    // --- Step 1: authenticate the client making the exchange request. -------
    let client = resolve_client(
        &req.client_id,
        client_actor.get_ref(),
        cimd.as_ref().map(|d| d.get_ref()),
        &config,
    )
    .await?;

    if !client.supports_grant_type(token_types::GRANT_TOKEN_EXCHANGE) {
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
        &oidc_config.issuer,
        resolved_jwks.as_ref(),
        mtls_thumbprint,
        mtls_subject_dn,
        mtls_san_uri,
        mtls_san_dns,
    )?;

    // Client authentication succeeded; a CIMD client may now be persisted so
    // the tokens issued below satisfy the foreign key on `clients(client_id)`.
    materialize_cimd_client(&client, client_actor.get_ref(), &config).await?;

    // --- Step 2: resolve the subject token. ---------------------------------
    let subject_token = req
        .subject_token
        .clone()
        .ok_or_else(|| OAuth2Error::invalid_request("Missing subject_token"))?;
    let subject_token_type = req
        .subject_token_type
        .clone()
        .ok_or_else(|| OAuth2Error::invalid_request("Missing subject_token_type"))?;

    // draft-ietf-oauth-transaction-tokens §6: a transaction token is only
    // accepted as a subject when the request asks for another transaction
    // token (a *replacement*). Anything else would launder a token scoped to
    // the trust domain into a bearer credential for a resource server.
    if subject_token_type == token_types::TXN_TOKEN
        && req.requested_token_type.as_deref() != Some(token_types::TXN_TOKEN)
    {
        return Err(OAuth2Error::invalid_request(
            "a transaction token may only be exchanged for another transaction token",
        ));
    }

    // Read the keyset once; both token resolutions share the snapshot.
    let keyset_snapshot = match keyset.as_ref() {
        Some(ks) => Some(ks.read().await.clone()),
        None => None,
    };

    // draft-ietf-oauth-identity-chaining: only the ID-JAG path accepts a
    // refresh token as the subject; a plain access-token exchange must not.
    let allow_refresh_subject = crate::handlers::id_jag::is_id_jag_request(&req, &config);

    let subject = resolve_token(
        &subject_token,
        &subject_token_type,
        "subject",
        &token_actor,
        &req.client_id,
        &storage,
        &oidc_config,
        keyset_snapshot.as_ref(),
        allow_refresh_subject,
    )
    .await?;

    // RFC 8693 §2.1 + RFC 9449 §7 / RFC 8705 §3: a sender-constrained subject
    // token may only be exchanged by the holder of the key it is bound to.
    // Without this the exchange is a proof-of-possession → bearer downgrade.
    enforce_subject_proof_of_possession(&subject, cnf_claim.as_ref(), mtls_thumbprint)?;

    // --- Step 3: resolve the optional actor token. --------------------------
    let actor = match req.actor_token.clone() {
        None => None,
        Some(actor_token) => {
            let actor_token_type = req.actor_token_type.clone().ok_or_else(|| {
                OAuth2Error::invalid_request("Missing actor_token_type for actor_token")
            })?;
            let resolved = resolve_token(
                &actor_token,
                &actor_token_type,
                "actor",
                &token_actor,
                &req.client_id,
                &storage,
                &oidc_config,
                keyset_snapshot.as_ref(),
                false,
            )
            .await?;
            if resolved.client_id.as_deref() != Some(req.client_id.as_str()) {
                return Err(OAuth2Error::invalid_grant(
                    "actor token was not issued to this client",
                ));
            }
            Some(resolved)
        }
    };

    handle_token_exchange_grant(ExchangeContext {
        req,
        client,
        cnf_claim,
        dpop_present,
        subject,
        actor,
        config,
        storage,
        token_actor,
        metrics,
        oidc_config,
        keyset: keyset.clone(),
    })
    .await
}

/// A subject token carrying a `cnf` claim is sender-constrained: the caller
/// must demonstrate possession of the same key at this endpoint.
///
/// `presented_cnf` is the confirmation built from the request's DPoP proof
/// (`jkt`) or mTLS certificate (`x5t#S256`); `mtls_thumbprint` is consulted
/// separately because a request presenting both only surfaces `jkt` there.
fn enforce_subject_proof_of_possession(
    subject: &ResolvedToken,
    presented_cnf: Option<&Value>,
    mtls_thumbprint: Option<&str>,
) -> Result<(), OAuth2Error> {
    let subject_cnf = match subject.cnf.as_ref() {
        None => return Ok(()),
        Some(cnf) => cnf,
    };

    if let Some(expected) = subject_cnf.get("jkt").and_then(Value::as_str) {
        let presented = presented_cnf
            .and_then(|c| c.get("jkt"))
            .and_then(Value::as_str);
        if presented != Some(expected) {
            return Err(OAuth2Error::invalid_grant(
                "subject token is sender-constrained; matching DPoP proof required",
            ));
        }
    }

    if let Some(expected) = subject_cnf.get("x5t#S256").and_then(Value::as_str) {
        if mtls_thumbprint != Some(expected) {
            return Err(OAuth2Error::invalid_grant(
                "subject token is sender-constrained; matching client certificate required",
            ));
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Token resolution (RFC 8693 §3 token type identifiers)
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
pub(crate) async fn resolve_token(
    raw: &str,
    token_type: &str,
    which: &str,
    token_actor: &web::Data<TokenActorPool>,
    requesting_client_id: &str,
    storage: &DynStorage,
    oidc_config: &OidcConfig,
    keyset: Option<&KeySet>,
    allow_refresh: bool,
) -> Result<ResolvedToken, OAuth2Error> {
    match token_type {
        token_types::ACCESS_TOKEN => {
            let row = lookup(raw, token_actor, requesting_client_id)
                .await?
                .ok_or_else(|| {
                    OAuth2Error::invalid_grant(&format!("{which}_token not found or expired"))
                })?;
            if !row.is_valid() {
                return Err(OAuth2Error::invalid_grant(&format!(
                    "{which}_token is expired or revoked"
                )));
            }
            // The storage lookup already authenticated the token, so the
            // embedded claims (JWT mode) can be read without re-verifying the
            // signature. Opaque tokens have no payload — synthesize from the row.
            let claims = Claims::decode_unverified(raw);
            let row_aud = {
                let resources = row.resources();
                if resources.is_empty() {
                    vec![row.client_id.clone()]
                } else {
                    resources
                }
            };
            Ok(ResolvedToken {
                sub: claims.as_ref().map(|c| c.sub.clone()).unwrap_or_else(|| {
                    row.user_id.clone().unwrap_or_else(|| row.client_id.clone())
                }),
                client_id: Some(row.client_id.clone()),
                user_id: row.user_id.clone(),
                scope: row.scope.clone(),
                aud: claims
                    .as_ref()
                    .map(|c| c.aud.clone())
                    .filter(|a| !a.is_empty())
                    .unwrap_or(row_aud),
                act: claims
                    .as_ref()
                    .and_then(|c| c.act.clone())
                    .or_else(|| row.actor()),
                may_act: claims.as_ref().and_then(|c| c.may_act.clone()),
                sub_profile: claims.as_ref().and_then(|c| c.sub_profile.clone()),
                authorization_details: claims
                    .as_ref()
                    .and_then(|c| c.authorization_details.clone()),
                cnf: claims
                    .as_ref()
                    .and_then(|c| c.cnf.clone())
                    .or_else(|| row.cnf_value()),
                is_id_token: false,
                txn: None,
            })
        }
        token_types::JWT => {
            // RFC 9068 §2.1: access tokens carry `typ: "at+JWT"`. Refresh
            // tokens are the same `Claims` payload signed with the same key
            // and differ ONLY by this header, so without the check a revoked
            // or already-rotated refresh token could be exchanged for a fresh
            // access token.
            let header = jsonwebtoken::decode_header(raw).map_err(|_| {
                OAuth2Error::invalid_request(&format!("{which}_token header is malformed"))
            })?;
            if header.typ.as_deref() != Some("at+JWT") {
                return Err(OAuth2Error::invalid_request(&format!(
                    "{which}_token is not an access token"
                )));
            }

            let claims: Claims =
                verify_jwt(raw, &oidc_config.jwt_secret, keyset).map_err(|_| {
                    OAuth2Error::invalid_grant(&format!("{which}_token signature is not valid"))
                })?;
            // A JWT this server issued must still be on record and valid. The
            // lookup is by access token, so anything not stored as one (a
            // refresh token, a replayed copy of a deleted token) is refused.
            let row = lookup(raw, token_actor, requesting_client_id).await?;
            if claims.iss == oidc_config.issuer {
                let row = row.as_ref().ok_or_else(|| {
                    OAuth2Error::invalid_grant(&format!(
                        "{which}_token is not a known access token"
                    ))
                })?;
                if !row.is_valid() {
                    return Err(OAuth2Error::invalid_grant(&format!(
                        "{which}_token is expired or revoked"
                    )));
                }
            } else if let Some(row) = row {
                if !row.is_valid() {
                    return Err(OAuth2Error::invalid_grant(&format!(
                        "{which}_token is expired or revoked"
                    )));
                }
            }
            let client_id = claims.client_id.clone();
            let aud = if claims.aud.is_empty() {
                client_id.clone().into_iter().collect()
            } else {
                claims.aud.clone()
            };
            // `Claims::new` falls back to the client_id when there is no
            // resource owner, so a `sub` equal to the client is a client-only
            // token and must not be turned back into a `user_id` (there is no
            // matching `users` row for it).
            let user_id = match client_id.as_deref() {
                Some(cid) if cid == claims.sub => None,
                _ => Some(claims.sub.clone()),
            };
            Ok(ResolvedToken {
                sub: claims.sub.clone(),
                client_id,
                user_id,
                scope: claims.scope.clone(),
                aud,
                act: claims.act.clone(),
                may_act: claims.may_act.clone(),
                sub_profile: claims.sub_profile.clone(),
                authorization_details: claims.authorization_details.clone(),
                cnf: claims.cnf.clone(),
                is_id_token: false,
                txn: None,
            })
        }
        // RFC 8693 §3 lists `refresh_token`, but exchanging one for an access
        // token would turn a long-lived credential into a fresh grant without
        // rotation. It is therefore only accepted on the ID-JAG / identity
        // chaining path, and validated exactly as the refresh grant does.
        token_types::REFRESH_TOKEN if allow_refresh => {
            let row = token_actor
                .route(requesting_client_id)
                .send(ValidateRefreshToken {
                    refresh_token: raw.to_string(),
                    span: tracing::Span::current(),
                })
                .await
                .map_err(|e| OAuth2Error::new("server_error", Some(&e.to_string())))??;
            if row.client_id != requesting_client_id {
                return Err(OAuth2Error::invalid_grant(&format!(
                    "{which}_token was not issued to this client"
                )));
            }
            // The storage lookup already authenticated the token, so the
            // embedded claims can be read without re-verifying the signature.
            let claims = Claims::decode_unverified(raw);
            let row_aud = {
                let resources = row.resources();
                if resources.is_empty() {
                    vec![row.client_id.clone()]
                } else {
                    resources
                }
            };
            Ok(ResolvedToken {
                sub: claims.as_ref().map(|c| c.sub.clone()).unwrap_or_else(|| {
                    row.user_id.clone().unwrap_or_else(|| row.client_id.clone())
                }),
                client_id: Some(row.client_id.clone()),
                user_id: row.user_id.clone(),
                scope: row.scope.clone(),
                aud: claims
                    .as_ref()
                    .map(|c| c.aud.clone())
                    .filter(|a| !a.is_empty())
                    .unwrap_or(row_aud),
                act: claims
                    .as_ref()
                    .and_then(|c| c.act.clone())
                    .or_else(|| row.actor()),
                may_act: claims.as_ref().and_then(|c| c.may_act.clone()),
                sub_profile: claims.as_ref().and_then(|c| c.sub_profile.clone()),
                authorization_details: claims
                    .as_ref()
                    .and_then(|c| c.authorization_details.clone()),
                cnf: claims
                    .as_ref()
                    .and_then(|c| c.cnf.clone())
                    .or_else(|| row.cnf_value()),
                is_id_token: false,
                txn: None,
            })
        }
        token_types::ID_TOKEN => {
            // `IdTokenClaims` is a strict subset of the access/refresh token
            // `Claims` payload, so an access or refresh token would otherwise
            // deserialize here and bypass this arm's (deliberately absent)
            // revocation and `cnf` handling. Rule both out explicitly.
            let header = jsonwebtoken::decode_header(raw).map_err(|_| {
                OAuth2Error::invalid_request(&format!("{which}_token header is malformed"))
            })?;
            if header.typ.as_deref() == Some("at+JWT") {
                return Err(OAuth2Error::invalid_request(&format!(
                    "{which}_token is not an ID token"
                )));
            }
            // ID tokens are never stored in `tokens`; anything that is, is one
            // of our access or refresh tokens wearing the wrong type URN.
            let is_our_stored_token = storage.get_token_by_access_token(raw).await?.is_some()
                || storage.get_token_by_refresh_token(raw).await?.is_some();
            if is_our_stored_token {
                return Err(OAuth2Error::invalid_request(&format!(
                    "{which}_token is not an ID token"
                )));
            }

            let claims: IdTokenClaims =
                verify_jwt(raw, &oidc_config.jwt_secret, keyset).map_err(|_| {
                    OAuth2Error::invalid_grant(&format!("{which}_token is not a valid id_token"))
                })?;
            if claims.iss != oidc_config.issuer {
                return Err(OAuth2Error::invalid_grant(&format!(
                    "{which}_token was not issued by this authorization server"
                )));
            }
            // OIDC Core §2: an ID token's audience is the client it was issued
            // to, which must be the client presenting it here.
            if claims.aud != requesting_client_id {
                return Err(OAuth2Error::invalid_grant(&format!(
                    "{which}_token was not issued to this client"
                )));
            }
            Ok(ResolvedToken {
                sub: claims.sub.clone(),
                client_id: Some(claims.aud.clone()),
                user_id: Some(claims.sub.clone()),
                // An ID token authorizes nothing by itself; the request must
                // name the scope it wants (checked against the client only).
                scope: String::new(),
                aud: vec![claims.aud.clone()],
                act: None,
                may_act: None,
                sub_profile: None,
                authorization_details: None,
                cnf: None,
                is_id_token: true,
                txn: None,
            })
        }
        token_types::TXN_TOKEN => {
            // Only ever a *replacement* subject: a transaction token confers
            // no authority at a resource server, so it must not become an
            // actor token either.
            if which != "subject" {
                return Err(OAuth2Error::invalid_request(
                    "a transaction token cannot be used as an actor_token",
                ));
            }
            // Transaction tokens are never persisted, so the signature and
            // `exp` are the only authentication. Shared with introspection.
            let claims = crate::handlers::txn_token::verify_txn_token(
                raw,
                keyset,
                &oidc_config.jwt_secret,
                &oidc_config.issuer,
            )
            .map_err(|e| {
                OAuth2Error::new(
                    &e.error,
                    Some(&format!(
                        "{which}_token is not a valid transaction token: {}",
                        e.error_description.unwrap_or_default()
                    )),
                )
            })?;
            let aud = vec![claims.aud.clone()];
            let act = claims.act.clone();
            let scope = claims.scope.clone();
            let sub = claims.sub.clone();
            let raw_claims = serde_json::to_value(&claims)
                .map_err(|e| OAuth2Error::new("server_error", Some(&e.to_string())))?;

            Ok(ResolvedToken {
                sub,
                // A transaction token is bound to the trust domain, not to the
                // client it was issued to, so the cross-client guard in step 4
                // does not apply: any workload in the domain that authenticates
                // asymmetrically may request a replacement. Naming the caller
                // here makes that guard a no-op instead of a false refusal.
                client_id: Some(requesting_client_id.to_string()),
                user_id: None,
                scope,
                aud,
                act,
                may_act: None,
                sub_profile: None,
                authorization_details: None,
                cnf: None,
                is_id_token: false,
                txn: Some(raw_claims),
            })
        }
        other => Err(OAuth2Error::invalid_request(&format!(
            "Unsupported {which}_token_type '{other}'"
        ))),
    }
}

async fn lookup(
    raw: &str,
    token_actor: &web::Data<TokenActorPool>,
    routing_client_id: &str,
) -> Result<Option<oauth2_core::Token>, OAuth2Error> {
    token_actor
        .route(routing_client_id)
        .send(LookupToken {
            token: raw.to_string(),
            span: tracing::Span::current(),
        })
        .await
        .map_err(|e| OAuth2Error::new("server_error", Some(&e.to_string())))?
}

/// Verify a JWT issued by this authorization server, trying the active
/// [`KeySet`] first and falling back to the configured HS256 secret. `aud` is
/// deliberately not validated here: the exchange algorithm inspects the
/// audience itself.
pub(crate) fn verify_jwt<T: serde::de::DeserializeOwned>(
    raw: &str,
    jwt_secret: &str,
    keyset: Option<&KeySet>,
) -> Result<T, ()> {
    let header = jsonwebtoken::decode_header(raw).map_err(|_| ())?;

    let mut candidates: Vec<(DecodingKey, Algorithm)> = Vec::new();
    if let Some(ks) = keyset {
        let keys = match header.kid.as_ref().and_then(|kid| ks.find(kid)) {
            Some(key) => vec![key],
            None => ks.active_keys(),
        };
        for key in keys {
            let decoding = match key.algorithm {
                KeyAlgorithm::HS256 => Ok(DecodingKey::from_secret(&key.key_material)),
                KeyAlgorithm::RS256 => DecodingKey::from_rsa_pem(&key.key_material),
            };
            if let Ok(decoding) = decoding {
                let alg = match key.algorithm {
                    KeyAlgorithm::HS256 => Algorithm::HS256,
                    KeyAlgorithm::RS256 => Algorithm::RS256,
                };
                candidates.push((decoding, alg));
            }
        }
    }
    candidates.push((
        DecodingKey::from_secret(jwt_secret.as_bytes()),
        Algorithm::HS256,
    ));

    for (key, alg) in candidates {
        let mut validation = Validation::new(alg);
        validation.validate_aud = false;
        if let Ok(data) = decode::<T>(raw, &key, &validation) {
            return Ok(data.claims);
        }
    }
    Err(())
}

// ---------------------------------------------------------------------------
// The exchange itself (steps 4-13)
// ---------------------------------------------------------------------------

pub(crate) async fn handle_token_exchange_grant(
    ctx: ExchangeContext,
) -> Result<HttpResponse, OAuth2Error> {
    let issuer = ctx.oidc_config.issuer.clone();

    // --- Steps 4 + 5: delegation policy and `act` chain construction. -------
    let act_claim: Option<Value> = match ctx.actor.as_ref() {
        None => {
            // Without an actor token there is no delegation to record, but the
            // exchange still moves a token from one client to another, so the
            // issuing client must have authorized this client to do so.
            enforce_cross_client_exchange(&ctx).await?;
            ctx.subject.act.clone()
        }
        Some(actor) => {
            authorize_delegation(&ctx, actor).await?;

            let new_actor = Actor::new(actor.sub.clone(), issuer.clone())
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

    // The requested token type steers step 6 and is dispatched on at step 9.
    let requested_token_type = ctx
        .req
        .requested_token_type
        .clone()
        .unwrap_or_else(|| token_types::ACCESS_TOKEN.to_string());
    let is_txn_token = requested_token_type == token_types::TXN_TOKEN;

    // --- Step 6: requested resources / audiences. ---------------------------
    // A transaction token's `audience` names the trust domain, not a protected
    // resource: it is not a URL in general, it is not in the resource registry
    // and it is unrelated to the subject token's own audience. The txn arm
    // checks it against the configured trust domain itself, so it must not be
    // fed through the resource-indicator rules here.
    let resources = resolve_requested_resources(
        &ctx.req.resource,
        if is_txn_token { &[] } else { &ctx.req.audience },
        &ctx.subject.aud,
        ctx.subject.client_id.as_deref().unwrap_or_default(),
        &ctx.storage,
    )
    .await?;

    // --- Step 7: scope must stay a subset of the subject token's scope. -----
    let scope = if ctx.subject.is_id_token {
        // An ID token carries no scope, so there is nothing to narrow: the
        // request must state what it wants and the client ceiling below is
        // the only bound.
        ctx.req.scope.clone().ok_or_else(|| {
            OAuth2Error::invalid_request("scope is required when the subject is an ID token")
        })?
    } else {
        match ctx.req.scope {
            Some(ref requested) => {
                validate_scope_subset(requested, &ctx.subject.scope)?;
                requested.clone()
            }
            None => ctx.subject.scope.clone(),
        }
    };
    // …and within what the requesting client is itself registered for, as the
    // client_credentials grant already enforces.
    validate_scope_subset(&scope, &ctx.client.scope)?;

    // --- Step 8: RFC 9396 authorization_details must stay a subset. ---------
    let authorization_details = resolve_authorization_details(
        ctx.req.authorization_details.as_deref(),
        ctx.subject.authorization_details.as_ref(),
    )?;

    // --- Step 9: requested_token_type. --------------------------------------
    // draft-ietf-oauth-identity-chaining: `requested_token_type=...:jwt` with
    // a single `audience` naming a configured chaining target asks for a
    // delegated authorization grant, not a plain access token.
    if requested_token_type == token_types::JWT
        && crate::handlers::id_jag::is_chaining_request(&ctx.req, &ctx.config)
    {
        return crate::handlers::id_jag::issue(&ctx).await;
    }
    match requested_token_type.as_str() {
        token_types::ACCESS_TOKEN | token_types::JWT => {}
        token_types::ID_JAG => return crate::handlers::id_jag::issue(&ctx).await,
        token_types::TXN_TOKEN => return crate::handlers::txn_token::issue(&ctx).await,
        other => {
            return Err(OAuth2Error::invalid_request(&format!(
                "Unsupported requested_token_type '{other}'"
            )))
        }
    }

    // --- Step 10: confirmation (`cnf`) binding. -----------------------------
    // A proof presented at this endpoint rebinds the new token. Otherwise the
    // subject's binding is only inherited when the subject token belongs to
    // the client performing the exchange (never across a delegation hop).
    let cnf = match ctx.cnf_claim.clone() {
        Some(cnf) => Some(cnf),
        None if ctx.subject.client_id.as_deref() == Some(ctx.req.client_id.as_str()) => {
            ctx.subject.cnf.clone()
        }
        None => None,
    };

    // --- Step 11: mint the new token. ---------------------------------------
    let new_token = ctx
        .token_actor
        .route(&ctx.req.client_id)
        .send(CreateToken {
            user_id: ctx.subject.user_id.clone(),
            client_id: ctx.req.client_id.clone(),
            scope,
            include_refresh: false,
            token_family: None,
            resources,
            cnf: cnf.clone(),
            authorization_details,
            act: act_claim,
            ttl_override_secs: None,
            sub_profile: None,
            txn: None,
            span: tracing::Span::current(),
        })
        .await
        .map_err(|e| OAuth2Error::new("server_error", Some(&e.to_string())))??;

    // --- Step 13: metrics. ---------------------------------------------------
    ctx.metrics.oauth_token_issued_total.inc();

    // RFC 9449 §7.1: a DPoP-bound token is delivered as token_type "DPoP".
    let token_type_str = if cnf.as_ref().and_then(|c| c.get("jkt")).is_some() {
        "DPoP"
    } else {
        "Bearer"
    };

    // RFC 8693 §2.2.1: the response carries no `act` member — delegation is
    // expressed inside the issued token, not alongside it.
    Ok(no_store_headers(HttpResponse::Ok().json(
        serde_json::json!({
            "access_token": new_token.access_token,
            "issued_token_type": requested_token_type,
            "token_type": token_type_str,
            "expires_in": new_token.expires_in,
            "scope": new_token.scope,
        }),
    )))
}

/// Step 4 (no actor token): exchanging a token that was issued to a *different*
/// client requires that client's explicit opt-in via `allowed_actors`. Without
/// it, any client holding the grant could launder another client's token into
/// one of its own.
async fn enforce_cross_client_exchange(ctx: &ExchangeContext) -> Result<(), OAuth2Error> {
    let subject_client_id = match ctx.subject.client_id.as_deref() {
        // Same-client exchange (the common narrowing case) is always allowed.
        Some(id) if id == ctx.req.client_id => return Ok(()),
        Some(id) => id,
        None => {
            return Err(OAuth2Error::invalid_grant(
                "subject_token is not bound to a known client",
            ))
        }
    };

    let allowed = ctx
        .storage
        .get_client(subject_client_id)
        .await?
        .is_some_and(|issuing| issuing.allows_actor(&ctx.req.client_id));
    if allowed {
        return Ok(());
    }

    Err(OAuth2Error::invalid_grant(
        "client not authorized to exchange tokens issued to another client",
    ))
}

/// Step 4: an actor may act for the subject when the subject token names it in
/// `may_act`, or when the client the subject token was issued to has
/// registered it in `allowed_actors`.
async fn authorize_delegation(
    ctx: &ExchangeContext,
    actor: &ResolvedToken,
) -> Result<(), OAuth2Error> {
    let issuer = ctx.oidc_config.issuer.as_str();

    let may_act_allows = ctx
        .subject
        .may_act
        .as_ref()
        .and_then(Value::as_object)
        .map(|m| {
            let sub_matches = m.get("sub").and_then(Value::as_str) == Some(actor.sub.as_str());
            let iss_matches = match m.get("iss").and_then(Value::as_str) {
                None => true,
                Some(iss) => iss == issuer,
            };
            sub_matches && iss_matches
        })
        .unwrap_or(false);
    if may_act_allows {
        return Ok(());
    }

    if let Some(subject_client_id) = ctx.subject.client_id.as_deref() {
        let subject_client = ctx.storage.get_client(subject_client_id).await?;
        if let Some(subject_client) = subject_client {
            if subject_client.allows_actor(&ctx.req.client_id) {
                return Ok(());
            }
        }
    }

    Err(OAuth2Error::invalid_grant(
        "actor not authorized to act for subject",
    ))
}

/// Step 6: validate and narrow the requested `resource` / `audience` values
/// against the registry and the subject token's own audience.
///
/// Exposed for reuse by the other grants that accept resource indicators.
pub(crate) async fn resolve_requested_resources(
    resource: &[String],
    audience: &[String],
    subject_aud: &[String],
    subject_client_id: &str,
    storage: &DynStorage,
) -> Result<Vec<String>, OAuth2Error> {
    // The subject token carries no resource restriction when its audience is
    // exactly the client it was issued to (the `aud = client_id` default).
    let subject_unrestricted = subject_aud == [subject_client_id.to_string()];

    let mut requested: Vec<String> = Vec::new();
    let mut seen: HashSet<&str> = HashSet::new();
    for value in resource.iter().chain(audience.iter()) {
        if seen.insert(value.as_str()) {
            requested.push(value.clone());
        }
    }

    if requested.is_empty() {
        // Inherit the subject token's audience, dropping the client_id default.
        return Ok(if subject_unrestricted {
            Vec::new()
        } else {
            subject_aud.to_vec()
        });
    }

    for value in &requested {
        ProtectedResource::validate_uri(value)?;
    }

    // When a registry is configured, only registered resources may be targeted.
    let registry = storage.list_resources().await?;
    if !registry.is_empty() {
        for value in &requested {
            if !registry.iter().any(|r| r.resource_uri == *value) {
                return Err(OAuth2Error::new(
                    "invalid_target",
                    Some("requested resource is not a registered protected resource"),
                ));
            }
        }
    }

    if !subject_unrestricted {
        for value in &requested {
            if !subject_aud.iter().any(|a| a == value) {
                return Err(OAuth2Error::new(
                    "invalid_target",
                    Some("requested resource exceeds the subject token's audience"),
                ));
            }
        }
    }

    Ok(requested)
}

/// Step 8: the requested `authorization_details` must be a JSON array whose
/// every element carries a string `type` and is already present in the subject
/// token's own `authorization_details`.
fn resolve_authorization_details(
    requested: Option<&str>,
    subject: Option<&Value>,
) -> Result<Option<Value>, OAuth2Error> {
    let raw = match requested {
        None => return Ok(subject.cloned()),
        Some(raw) => raw,
    };

    let parsed: Value = serde_json::from_str(raw).map_err(|_| {
        OAuth2Error::new(
            "invalid_authorization_details",
            Some("authorization_details is not valid JSON"),
        )
    })?;
    let elements = parsed.as_array().ok_or_else(|| {
        OAuth2Error::new(
            "invalid_authorization_details",
            Some("authorization_details must be a JSON array"),
        )
    })?;

    let granted = subject.and_then(Value::as_array);
    for element in elements {
        if element.get("type").and_then(Value::as_str).is_none() {
            return Err(OAuth2Error::new(
                "invalid_authorization_details",
                Some("every authorization_details element requires a string `type`"),
            ));
        }
        let is_granted = granted.is_some_and(|g| g.iter().any(|granted| granted == element));
        if !is_granted {
            return Err(OAuth2Error::new(
                "invalid_authorization_details",
                Some("requested authorization_details exceed the subject token's grant"),
            ));
        }
    }

    Ok(Some(parsed))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn rar_defaults_to_the_subjects_grant() {
        let subject = json!([{ "type": "payment" }]);
        assert_eq!(
            resolve_authorization_details(None, Some(&subject)).expect("inherit"),
            Some(subject.clone())
        );
    }

    #[test]
    fn rar_rejects_an_element_without_a_type() {
        let subject = json!([{ "actions": ["read"] }]);
        let err = resolve_authorization_details(Some(r#"[{"actions":["read"]}]"#), Some(&subject))
            .expect_err("must reject");
        assert_eq!(err.error, "invalid_authorization_details");
    }

    #[test]
    fn rar_rejects_a_superset() {
        let subject = json!([{ "type": "payment" }]);
        let err = resolve_authorization_details(Some(r#"[{"type":"other"}]"#), Some(&subject))
            .expect_err("must reject");
        assert_eq!(err.error, "invalid_authorization_details");
    }

    #[test]
    fn rar_accepts_an_exact_subset() {
        let subject = json!([{ "type": "payment" }, { "type": "accounts" }]);
        let resolved =
            resolve_authorization_details(Some(r#"[{"type":"payment"}]"#), Some(&subject))
                .expect("subset");
        assert_eq!(resolved, Some(json!([{ "type": "payment" }])));
    }
}
