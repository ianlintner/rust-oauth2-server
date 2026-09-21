//! RFC 7523 §2.1 — JWT authorization grant, backed by the trusted-issuers
//! registry, plus acceptance of Identity Assertion Authorization Grants
//! (ID-JAG, `draft-ietf-oauth-identity-assertion-authz-grant-04`).
//!
//! An external identity provider signs an assertion about a subject; the
//! client presents it at the token endpoint under
//! `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer` together with its
//! own client credentials. The assertion's `iss` must name an enabled
//! [`TrustedIssuer`], whose `jwks_uri` supplies the verification key.
//!
//! An assertion carrying the JOSE header `typ: "oauth-id-jag+jwt"` is treated
//! as an ID-JAG: it additionally binds to the authenticated client, caps the
//! issued token's `scope` / `resource` / `authorization_details`, may demand
//! DPoP via `cnf.jkt`, and may carry a delegation (`act`) chain.

use actix::Addr;
use actix_web::{web, HttpResponse, Result};
use base64::{engine::general_purpose, Engine as _};
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use serde_json::Value;

use oauth2_config::AgentConfig;
use oauth2_core::{Actor as DelegationActor, OAuth2Error, TokenResponse, TrustedIssuer, User};
use oauth2_observability::Metrics;
use oauth2_ports::DynStorage;

use crate::actors::{ClientActor, CreateToken, GetClient, TokenActorPool};
use crate::handlers::jwks_cache::JwksCache;
use crate::handlers::oauth::{
    apply_dpop_token_type, authenticate_confidential_client, enforce_jti_replay, no_store_headers,
    resolve_client_jwks, validate_scope_subset, TokenRequest,
};
use crate::handlers::token_exchange::resolve_requested_resources;
use crate::handlers::wellknown::OidcConfig;

/// JOSE `typ` that marks an assertion as an Identity Assertion Authorization
/// Grant (ID-JAG).
const ID_JAG_TYP: &str = "oauth-id-jag+jwt";

/// Maximum clock skew tolerated when checking that `iat` is not in the future.
const IAT_SKEW_SECS: i64 = 60;

/// Signature algorithms accepted on an incoming assertion. Symmetric
/// algorithms are excluded on purpose: the verification key comes from the
/// issuer's public JWKS.
const ALLOWED_ALGS: [Algorithm; 3] = [Algorithm::RS256, Algorithm::ES256, Algorithm::PS256];

/// RFC 7523 §2.1 — exchange a JWT assertion from a trusted issuer for an
/// access token. Never issues a refresh token.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn handle_jwt_bearer_grant(
    req: TokenRequest,
    cnf_claim: Option<Value>,
    rar_details: Option<Value>,
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
    let assertion = req
        .assertion
        .clone()
        .ok_or_else(|| OAuth2Error::invalid_request("Missing assertion"))?;

    // --- 1. Authenticate the calling client ------------------------------
    //
    // Done before anything that touches the network (the JWKS fetch below),
    // so an unauthenticated caller cannot drive outbound requests.
    let client = client_actor
        .send(GetClient {
            client_id: req.client_id.clone(),
            span: tracing::Span::current(),
        })
        .await
        .map_err(|e| OAuth2Error::new("server_error", Some(&e.to_string())))??;

    if !client.supports_grant_type(oauth2_core::token_types::GRANT_JWT_BEARER) {
        return Err(OAuth2Error::unauthorized_client(
            "Client is not allowed to use the jwt-bearer grant",
        ));
    }
    if client.is_public() {
        return Err(OAuth2Error::invalid_client(
            "Public clients cannot use the jwt-bearer grant",
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

    // --- 2. Resolve the trusted issuer from the unverified `iss` ---------
    let header = jsonwebtoken::decode_header(&assertion)
        .map_err(|_| OAuth2Error::invalid_grant("Malformed assertion JWT header"))?;
    let unverified = decode_unverified_claims(&assertion)?;
    let iss = unverified
        .get("iss")
        .and_then(Value::as_str)
        .ok_or_else(|| OAuth2Error::invalid_grant("assertion is missing the iss claim"))?
        .to_string();

    let trusted = storage
        .get_trusted_issuer(&iss)
        .await?
        .filter(|ti| ti.enabled)
        .ok_or_else(|| OAuth2Error::invalid_grant("assertion iss is not a trusted issuer"))?;

    if !trusted.allows_client(&client.client_id) {
        return Err(OAuth2Error::invalid_grant(
            "client is not allowed to use this trusted issuer",
        ));
    }

    // --- 3. Verify the signature against the issuer's JWKS ---------------
    let claims = verify_assertion(
        &assertion,
        &header,
        &trusted,
        &iss,
        &oidc_config.issuer,
        &token_endpoint_url,
        jwks_cache.as_ref().map(|d| d.as_ref()),
    )
    .await?;

    // `iat` must not be in the future (beyond a small skew allowance).
    let iat = claims
        .get("iat")
        .and_then(Value::as_i64)
        .ok_or_else(|| OAuth2Error::invalid_grant("assertion iat claim is not a number"))?;
    if iat > chrono::Utc::now().timestamp() + IAT_SKEW_SECS {
        return Err(OAuth2Error::invalid_grant("assertion iat is in the future"));
    }

    // RFC 7523 §3: single-use `jti`. Namespaced by issuer because `jti`
    // uniqueness is the issuer's responsibility, not the presenting client's.
    // `invalid_client` from the shared guard is remapped: the client's own
    // credentials were fine, the *assertion* is what was replayed.
    enforce_jti_replay(&format!("jwt-bearer:{iss}"), &claims)
        .map_err(|e| OAuth2Error::invalid_grant(e.error_description.as_deref().unwrap_or("")))?;

    // --- 4. ID-JAG specifics ---------------------------------------------
    let is_id_jag = header.typ.as_deref() == Some(ID_JAG_TYP);
    let mut act: Option<Value> = None;
    let mut scope_ceiling: Option<String> = None;
    let mut resource_ceiling: Vec<String> = Vec::new();
    let mut assertion_rar: Option<Value> = None;

    if is_id_jag {
        if !agent.id_jag_enabled {
            return Err(OAuth2Error::invalid_grant(
                "ID-JAG assertions are not accepted by this authorization server",
            ));
        }

        let asserted_client = claims
            .get("client_id")
            .and_then(Value::as_str)
            .ok_or_else(|| OAuth2Error::invalid_grant("ID-JAG is missing the client_id claim"))?;
        if asserted_client != client.client_id {
            return Err(OAuth2Error::invalid_grant(
                "ID-JAG client_id does not match the authenticated client",
            ));
        }

        // A `cnf.jkt` in the assertion demands a matching DPoP proof, and the
        // issued token inherits that binding via `cnf_claim`.
        if let Some(expected_jkt) = claims.pointer("/cnf/jkt").and_then(Value::as_str) {
            let presented = cnf_claim
                .as_ref()
                .and_then(|c| c.get("jkt"))
                .and_then(Value::as_str);
            if presented != Some(expected_jkt) {
                return Err(OAuth2Error::invalid_grant(
                    "ID-JAG cnf.jkt requires a DPoP proof with a matching key thumbprint",
                ));
            }
        }

        if let Some(act_value) = claims.get("act") {
            let chain = DelegationActor::from_value(act_value)
                .map_err(|e| OAuth2Error::invalid_grant(&format!("ID-JAG act claim: {e}")))?;
            chain
                .validate_chain(agent.max_delegation_depth)
                .map_err(|e| OAuth2Error::invalid_request(&e.to_string()))?;
            act = Some(chain.to_value());
        }

        scope_ceiling = claims
            .get("scope")
            .and_then(Value::as_str)
            .map(str::to_string);
        resource_ceiling = string_or_array(claims.get("resource"));
        assertion_rar = claims.get("authorization_details").cloned();
    }

    // --- 5. Effective scope ----------------------------------------------
    let scope = match (req.scope.as_deref(), scope_ceiling.as_deref()) {
        // Requested scope must fit inside the ID-JAG's ceiling.
        (Some(requested), Some(ceiling)) => {
            validate_scope_subset(requested, ceiling)?;
            requested.to_string()
        }
        (Some(requested), None) => requested.to_string(),
        (None, Some(ceiling)) => ceiling.to_string(),
        (None, None) => client.scope.clone(),
    };
    // Every grant is additionally capped by what the client is registered for.
    validate_scope_subset(&scope, &client.scope)?;

    // --- 6. Effective resource -------------------------------------------
    // Shared with the token-exchange grant. That resolver reads
    // `subject_aud == [subject_client_id]` as "no audience restriction",
    // which is exactly what an assertion without a `resource` ceiling means
    // here, so the absent ceiling is encoded that way.
    let ceiling = if resource_ceiling.is_empty() {
        vec![client.client_id.clone()]
    } else {
        resource_ceiling
    };
    let resources = resolve_requested_resources(
        &req.resource,
        &[],
        &ceiling,
        &client.client_id,
        storage.as_ref(),
    )
    .await?;

    // --- 7. Effective authorization_details -------------------------------
    // The assertion is the ceiling; a request that restates it must match.
    let authorization_details = match (assertion_rar, rar_details) {
        (Some(asserted), Some(requested)) if asserted != requested => {
            return Err(OAuth2Error::new(
                "invalid_authorization_details",
                Some("authorization_details is not a subset of the assertion's"),
            ));
        }
        (Some(asserted), _) => Some(asserted),
        (None, requested) => requested,
    };

    // --- 8. Resolve the local subject -------------------------------------
    let user_id = resolve_subject(storage.as_ref(), &trusted, &claims).await?;

    // --- 9. Issue the access token (never a refresh token) ----------------
    let token = token_actor
        .route(&client.client_id)
        .send(CreateToken {
            user_id: Some(user_id),
            client_id: client.client_id.clone(),
            scope,
            include_refresh: false,
            token_family: None,
            resources: resources.clone(),
            cnf: cnf_claim.clone(),
            authorization_details: authorization_details.clone(),
            act,
            span: tracing::Span::current(),
        })
        .await
        .map_err(|e| OAuth2Error::new("server_error", Some(&e.to_string())))??;

    metrics.oauth_token_issued_total.inc();

    let response = apply_dpop_token_type(TokenResponse::from(token), cnf_claim.as_ref());
    let mut body = serde_json::to_value(&response)
        .map_err(|e| OAuth2Error::new("server_error", Some(&e.to_string())))?;
    if let Some(details) = authorization_details {
        body["authorization_details"] = details;
    }
    match resources.len() {
        0 => {}
        1 => body["resource"] = Value::String(resources[0].clone()),
        _ => body["resource"] = Value::Array(resources.into_iter().map(Value::String).collect()),
    }

    Ok(no_store_headers(HttpResponse::Ok().json(body)))
}

/// Base64url-decode a JWT's payload without verifying the signature. Used only
/// to learn which trusted issuer's key should verify it; every claim read here
/// is re-read from the *verified* claim set afterwards.
fn decode_unverified_claims(assertion: &str) -> Result<Value, OAuth2Error> {
    let segments: Vec<&str> = assertion.split('.').collect();
    if segments.len() != 3 {
        return Err(OAuth2Error::invalid_grant(
            "assertion is not a well-formed JWS Compact Serialization",
        ));
    }
    let bytes = general_purpose::URL_SAFE_NO_PAD
        .decode(segments[1])
        .map_err(|_| OAuth2Error::invalid_grant("assertion payload is not valid base64url"))?;
    serde_json::from_slice(&bytes)
        .map_err(|_| OAuth2Error::invalid_grant("assertion payload is not valid JSON"))
}

/// Fetch the issuer's JWKS, pick the key named by the JOSE header, and verify
/// the assertion's signature and registered claims.
async fn verify_assertion(
    assertion: &str,
    header: &jsonwebtoken::Header,
    trusted: &TrustedIssuer,
    iss: &str,
    our_issuer: &str,
    token_endpoint_url: &str,
    jwks_cache: Option<&JwksCache>,
) -> Result<Value, OAuth2Error> {
    if !ALLOWED_ALGS.contains(&header.alg) {
        return Err(OAuth2Error::invalid_grant(
            "assertion uses an unsupported signature algorithm",
        ));
    }

    let cache = jwks_cache.ok_or_else(|| {
        OAuth2Error::new(
            "server_error",
            Some("JWKS cache is not configured; cannot verify assertions"),
        )
    })?;
    let jwks = cache.fetch(trusted.jwks_uri.trim()).await.map_err(|e| {
        OAuth2Error::invalid_grant(&format!(
            "could not fetch the trusted issuer's JWKS: {}",
            e.error_description.as_deref().unwrap_or(&e.error)
        ))
    })?;
    let key = select_key(&jwks, header)?;

    // `aud` may name this AS (by issuer identifier or token endpoint URL) or
    // any audience the registry explicitly allows this issuer to target.
    let mut audiences = vec![our_issuer.to_string(), token_endpoint_url.to_string()];
    audiences.extend(trusted.allowed_audiences_vec());

    let mut validation = Validation::new(header.alg);
    validation.set_issuer(&[iss]);
    validation.set_audience(&audiences);
    validation.set_required_spec_claims(&["iss", "sub", "aud", "exp", "iat", "jti"]);

    let data = decode::<Value>(assertion, &key, &validation)
        .map_err(|e| OAuth2Error::invalid_grant(&format!("assertion validation failed: {e}")))?;
    Ok(data.claims)
}

/// Pick the verification key from a JWKS: by `kid` when the header names one,
/// otherwise the first key of the right type for the header's algorithm.
fn select_key(jwks: &Value, header: &jsonwebtoken::Header) -> Result<DecodingKey, OAuth2Error> {
    let keys = jwks
        .get("keys")
        .and_then(Value::as_array)
        .ok_or_else(|| OAuth2Error::invalid_grant("trusted issuer JWKS has no 'keys' array"))?;

    let wanted_kty = if header.alg == Algorithm::ES256 {
        "EC"
    } else {
        "RSA"
    };

    let key_json = match &header.kid {
        Some(kid) => keys
            .iter()
            .find(|k| k.get("kid").and_then(Value::as_str) == Some(kid))
            .ok_or_else(|| {
                OAuth2Error::invalid_grant("no key with the assertion's kid in the issuer JWKS")
            })?,
        None => keys
            .iter()
            .find(|k| k.get("kty").and_then(Value::as_str) == Some(wanted_kty))
            .ok_or_else(|| {
                OAuth2Error::invalid_grant("no usable key in the trusted issuer's JWKS")
            })?,
    };

    let component = |name: &str| -> Result<String, OAuth2Error> {
        key_json
            .get(name)
            .and_then(Value::as_str)
            .map(str::to_string)
            .ok_or_else(|| {
                OAuth2Error::invalid_grant(&format!("issuer JWKS key is missing '{name}'"))
            })
    };

    match key_json.get("kty").and_then(Value::as_str) {
        Some("RSA") => DecodingKey::from_rsa_components(&component("n")?, &component("e")?)
            .map_err(|_| OAuth2Error::invalid_grant("issuer JWKS RSA key is malformed")),
        Some("EC") => DecodingKey::from_ec_components(&component("x")?, &component("y")?)
            .map_err(|_| OAuth2Error::invalid_grant("issuer JWKS EC key is malformed")),
        _ => Err(OAuth2Error::invalid_grant(
            "issuer JWKS key type is not supported",
        )),
    }
}

/// Map the assertion's subject onto a local user id, just-in-time
/// provisioning one when the trusted issuer allows it.
async fn resolve_subject(
    storage: &DynStorage,
    trusted: &TrustedIssuer,
    claims: &Value,
) -> Result<String, OAuth2Error> {
    let sub = claims
        .get("sub")
        .and_then(Value::as_str)
        .ok_or_else(|| OAuth2Error::invalid_grant("assertion sub claim is not a string"))?;
    let email = claims
        .get("email")
        .and_then(Value::as_str)
        .unwrap_or_default();

    let is_email_mapping = trusted.subject_mapping == "email";
    let existing = if is_email_mapping {
        if email.is_empty() {
            return Err(OAuth2Error::invalid_grant(
                "trusted issuer maps subjects by email but the assertion has no email claim",
            ));
        }
        storage.get_user_by_email(email).await?
    } else {
        // Default (and the explicit `"sub"` setting): the `sub` claim is the
        // local user id.
        storage.get_user_by_id(sub).await?
    };

    if let Some(user) = existing {
        if !user.enabled {
            return Err(OAuth2Error::invalid_grant("subject user is disabled"));
        }
        return Ok(user.id);
    }

    // Email-mapped subjects are never provisioned: provisioning keys the new
    // row on `sub`, which says nothing about who owns the address, so an
    // unknown email is simply an unknown subject.
    if is_email_mapping {
        return Err(OAuth2Error::invalid_grant("unknown subject"));
    }

    if !trusted.jit_provision {
        return Err(OAuth2Error::invalid_grant(
            "assertion subject has no local user and the issuer does not allow provisioning",
        ));
    }

    let now = chrono::Utc::now();
    let user = User {
        id: sub.to_string(),
        username: sub.to_string(),
        password_hash: String::new(),
        email: email.to_string(),
        enabled: true,
        role: "user".to_string(),
        created_at: now,
        updated_at: now,
    };
    // `save_user` is a bare INSERT, so two concurrent first-use assertions for
    // the same subject — or a `sub` colliding with an existing local user id —
    // raise a unique-constraint error. Re-read once before giving up: a racing
    // request may have just created exactly the row we wanted. Either way this
    // is a grant failure, not a 500.
    if let Err(insert_err) = storage.save_user(&user).await {
        tracing::warn!(
            issuer = %trusted.issuer,
            subject = %sub,
            error = %insert_err.error,
            "RFC 7523: just-in-time user provisioning insert failed"
        );
        return match storage.get_user_by_id(sub).await {
            Ok(Some(raced)) if raced.enabled => Ok(raced.id),
            Ok(Some(_)) => Err(OAuth2Error::invalid_grant("subject user is disabled")),
            Ok(None) => Err(OAuth2Error::invalid_grant(
                "could not provision a local user for the assertion subject",
            )),
            // The re-read is part of recovering from a failed grant, so its
            // own failure is still a grant failure — never a 500.
            Err(reread_err) => {
                tracing::warn!(
                    issuer = %trusted.issuer,
                    subject = %sub,
                    error = %reread_err.error,
                    "RFC 7523: re-read after a failed provisioning insert also failed"
                );
                Err(OAuth2Error::invalid_grant(
                    "could not provision a local user for the assertion subject",
                ))
            }
        };
    }
    tracing::info!(
        issuer = %trusted.issuer,
        subject = %sub,
        "RFC 7523: just-in-time provisioned a user for a trusted-issuer assertion"
    );
    Ok(user.id)
}

/// Read a claim that may be either a single string or an array of strings.
fn string_or_array(value: Option<&Value>) -> Vec<String> {
    match value {
        Some(Value::String(s)) => vec![s.clone()],
        Some(Value::Array(items)) => items
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_string)
            .collect(),
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn decode_unverified_claims_rejects_a_non_jwt() {
        assert!(decode_unverified_claims("not-a-jwt").is_err());
        assert!(decode_unverified_claims("a.b").is_err());
        assert!(decode_unverified_claims("a.!!!.c").is_err());
    }

    #[test]
    fn decode_unverified_claims_reads_the_payload() {
        let payload = general_purpose::URL_SAFE_NO_PAD.encode(br#"{"iss":"https://idp.test"}"#);
        let claims = decode_unverified_claims(&format!("h.{payload}.s")).expect("payload");
        assert_eq!(claims["iss"], "https://idp.test");
    }

    #[test]
    fn string_or_array_accepts_both_shapes() {
        assert_eq!(string_or_array(None), Vec::<String>::new());
        assert_eq!(string_or_array(Some(&json!("a"))), vec!["a".to_string()]);
        assert_eq!(
            string_or_array(Some(&json!(["a", "b", 7]))),
            vec!["a".to_string(), "b".to_string()]
        );
    }

    #[test]
    fn select_key_requires_a_matching_kid() {
        let jwks = json!({ "keys": [{ "kty": "RSA", "kid": "one", "n": "AQAB", "e": "AQAB" }] });
        let mut header = jsonwebtoken::Header::new(Algorithm::RS256);
        header.kid = Some("two".to_string());
        let err = select_key(&jwks, &header).expect_err("kid mismatch");
        assert_eq!(err.error, "invalid_grant");
    }
}
