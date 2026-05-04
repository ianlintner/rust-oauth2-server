/// RFC 9449 DPoP Proof Validation
///
/// Provides full DPoP proof validation:
/// - `typ: "dpop+jwt"` header claim check
/// - JWT signature verification against embedded JWK (RS256 / ES256)
/// - `htm` (HTTP method) binding
/// - `htu` (HTTP URI, scheme+host+path, no query) binding
/// - `iat` freshness window (±5 minutes)
/// - `jti` replay prevention via `DpopReplayStore`
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use base64::{engine::general_purpose, Engine as _};
use oauth2_core::OAuth2Error;
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::handlers::dpop_nonce::DpopNonceIssuer;

/// In-memory DPoP proof replay store.
///
/// Keyed by `jti`; value is the expiry time (`iat` + acceptance window).
/// Entries are cleaned up lazily on each insertion.
#[derive(Clone, Default)]
pub struct DpopReplayStore(pub Arc<Mutex<HashMap<String, Instant>>>);

impl DpopReplayStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Check the `jti` and record it if fresh. Returns `Err` if already seen.
    pub fn check_and_insert(&self, jti: &str, expiry: Instant) -> Result<(), OAuth2Error> {
        let mut store = self.0.lock().map_err(|_| {
            OAuth2Error::new("server_error", Some("DPoP replay store lock poisoned"))
        })?;

        // Lazy cleanup: remove entries that have expired.
        let now = Instant::now();
        store.retain(|_, exp| *exp > now);

        if store.contains_key(jti) {
            return Err(OAuth2Error::new(
                "invalid_dpop_proof",
                Some("DPoP proof jti has already been used (replay)"),
            ));
        }
        store.insert(jti.to_string(), expiry);
        Ok(())
    }
}

/// Acceptance window for DPoP `iat` claim (±300 seconds per RFC 9449 §4.3).
const DPOP_IAT_SKEW_SECS: i64 = 300;

/// Maximum reasonable Host header length: 253 chars per RFC 1035 + room for `:port`.
const MAX_HOST_LEN: usize = 270;
/// Maximum reasonable URL path length for OAuth endpoints.
const MAX_PATH_LEN: usize = 2048;
/// Maximum reasonable URL scheme length (`https` is 5).
const MAX_SCHEME_LEN: usize = 16;

/// Build the request URL used as DPoP `htu` from `connection_info()` parts,
/// rejecting suspiciously large inputs to prevent uncontrolled-allocation issues
/// from a hostile reverse proxy or Host header.
///
/// Returns `Err(OAuth2Error::invalid_request(...))` if any component exceeds
/// its bound. The returned string is the concatenation `scheme://host{path}`.
pub fn build_request_url_bounded(
    scheme: &str,
    host: &str,
    path: &str,
) -> Result<String, OAuth2Error> {
    if scheme.len() > MAX_SCHEME_LEN {
        return Err(OAuth2Error::invalid_request("Request scheme is too long"));
    }
    if host.len() > MAX_HOST_LEN {
        return Err(OAuth2Error::invalid_request(
            "Request Host header is too long",
        ));
    }
    if path.len() > MAX_PATH_LEN {
        return Err(OAuth2Error::invalid_request("Request path is too long"));
    }
    // Fixed upper bound on the result size: scheme + "://" + host + path,
    // each of which has been validated above. Using a constant capacity
    // keeps the allocation size independent of any user-controlled length
    // (defends against `rust/uncontrolled-allocation-size`).
    const MAX_URL_LEN: usize = MAX_SCHEME_LEN + 3 + MAX_HOST_LEN + MAX_PATH_LEN;
    let mut out = String::with_capacity(MAX_URL_LEN);
    out.push_str(scheme);
    out.push_str("://");
    out.push_str(host);
    out.push_str(path);
    Ok(out)
}

#[derive(Debug, Deserialize)]
struct DpopClaims {
    htm: String,
    htu: String,
    iat: i64,
    jti: String,
    /// RFC 9449 §8.1 — server-issued nonce. Optional in the proof; only
    /// enforced when the client has `dpop_nonce_required = true`.
    #[serde(default)]
    nonce: Option<String>,
}

/// Outcome of a successful DPoP proof validation.
#[derive(Debug, Clone)]
pub struct DpopValidated {
    /// JWK Thumbprint (RFC 7638) of the proof's public key.
    pub jkt: String,
    /// `nonce` claim from the proof, if present.
    pub nonce: Option<String>,
}

/// RFC 9449 §§8, 9 — verify the proof's `nonce` against the server-issued
/// nonce issuer. Returns `error: use_dpop_nonce` when the nonce is missing
/// or stale (caller must include a fresh `DPoP-Nonce` response header) and
/// `error: invalid_dpop_proof` when the nonce is forged.
pub fn enforce_dpop_nonce(
    validated: &DpopValidated,
    issuer: &DpopNonceIssuer,
) -> Result<(), OAuth2Error> {
    let Some(nonce) = validated.nonce.as_deref() else {
        return Err(OAuth2Error::new(
            "use_dpop_nonce",
            Some("DPoP proof must include a server-issued nonce"),
        ));
    };
    match issuer.verify(nonce) {
        Ok(()) => Ok(()),
        Err(e) => {
            // Distinguish "stale/missing" from "forged" so callers know
            // whether to re-issue a nonce or to reject outright.
            let desc = e.error_description.as_deref().unwrap_or("");
            if desc.contains("expired") || desc.contains("not yet valid") {
                Err(OAuth2Error::new(
                    "use_dpop_nonce",
                    Some("DPoP nonce is expired; retry with a fresh nonce"),
                ))
            } else {
                Err(e)
            }
        }
    }
}

/// Fully validate a DPoP proof JWT per RFC 9449 §4.2 / §4.3.
///
/// Returns a [`DpopValidated`] carrying the JWK Thumbprint and the parsed
/// `nonce` claim (if any). Nonce **enforcement** is deferred to
/// [`enforce_dpop_nonce`] so the handler can look up the client's
/// per-client `dpop_nonce_required` policy first.
///
/// # Parameters
/// - `dpop_proof`: raw value of the `DPoP` HTTP header
/// - `method`: HTTP method of the current request (e.g. `"POST"`)
/// - `url`: full URL of the current request (query string is stripped for `htu` comparison)
/// - `replay_store`: DPoP-specific replay prevention store
pub fn validate_dpop_proof(
    dpop_proof: &str,
    method: &str,
    url: &str,
    replay_store: &DpopReplayStore,
) -> Result<DpopValidated, OAuth2Error> {
    // ── Step 1: decode the JOSE header ──────────────────────────────────────
    let header = jsonwebtoken::decode_header(dpop_proof).map_err(|_| {
        OAuth2Error::new("invalid_dpop_proof", Some("DPoP proof header is malformed"))
    })?;

    // ── Step 2: typ MUST be "dpop+jwt" ──────────────────────────────────────
    let typ = header.typ.as_deref().unwrap_or("");
    if !typ.eq_ignore_ascii_case("dpop+jwt") {
        return Err(OAuth2Error::new(
            "invalid_dpop_proof",
            Some("DPoP proof typ must be \"dpop+jwt\""),
        ));
    }

    // ── Step 3: extract embedded JWK ────────────────────────────────────────
    let jwk_obj = header.jwk.ok_or_else(|| {
        OAuth2Error::new(
            "invalid_dpop_proof",
            Some("DPoP proof missing 'jwk' header claim"),
        )
    })?;
    let jwk_str = serde_json::to_string(&jwk_obj)
        .map_err(|e| OAuth2Error::new("server_error", Some(&e.to_string())))?;
    let jwk_val: serde_json::Value = serde_json::from_str(&jwk_str)
        .map_err(|e| OAuth2Error::new("server_error", Some(&e.to_string())))?;

    // ── Step 4: compute JWK Thumbprint (RFC 7638) ───────────────────────────
    let jkt = compute_jkt(&jwk_val)?;

    // ── Step 5: verify JWT signature against embedded public key ────────────
    let claims = verify_dpop_signature(dpop_proof, &header.alg, &jwk_val)?;

    // ── Step 6: htm must match current HTTP method ──────────────────────────
    if !claims.htm.eq_ignore_ascii_case(method) {
        return Err(OAuth2Error::new(
            "invalid_dpop_proof",
            Some("DPoP proof htm does not match request method"),
        ));
    }

    // ── Step 7: htu must match current URI (no query string) ────────────────
    let expected_htu = strip_query(url);
    let proof_htu = strip_query(&claims.htu);
    if proof_htu != expected_htu {
        return Err(OAuth2Error::new(
            "invalid_dpop_proof",
            Some("DPoP proof htu does not match request URI"),
        ));
    }

    // ── Step 8: iat freshness check ─────────────────────────────────────────
    let now_secs = chrono::Utc::now().timestamp();
    let delta = now_secs - claims.iat;
    if !(-DPOP_IAT_SKEW_SECS..=DPOP_IAT_SKEW_SECS).contains(&delta) {
        return Err(OAuth2Error::new(
            "invalid_dpop_proof",
            Some("DPoP proof iat is outside the acceptance window"),
        ));
    }

    // ── Step 9: jti replay prevention ───────────────────────────────────────
    // Set expiry to iat + skew + some buffer so the store doesn't grow unbounded.
    let expiry = Instant::now() + Duration::from_secs((DPOP_IAT_SKEW_SECS * 2 + 60) as u64);
    replay_store.check_and_insert(&claims.jti, expiry)?;

    Ok(DpopValidated {
        jkt,
        nonce: claims.nonce,
    })
}

/// Compute the RFC 7638 JWK Thumbprint as a base64url-encoded SHA-256 hash.
fn compute_jkt(jwk: &serde_json::Value) -> Result<String, OAuth2Error> {
    let canonical = build_jwk_canonical(jwk)?;
    let hash = Sha256::digest(canonical.as_bytes());
    Ok(general_purpose::URL_SAFE_NO_PAD.encode(hash))
}

/// Build the RFC 7638 canonical JWK member set (alphabetically sorted, minimal fields).
fn build_jwk_canonical(jwk: &serde_json::Value) -> Result<String, OAuth2Error> {
    let kty = jwk
        .get("kty")
        .and_then(|v| v.as_str())
        .ok_or_else(|| OAuth2Error::new("invalid_dpop_proof", Some("JWK missing kty")))?;
    let obj = match kty {
        "EC" => {
            let crv = jwk.get("crv").ok_or_else(|| {
                OAuth2Error::new("invalid_dpop_proof", Some("EC JWK missing crv"))
            })?;
            let x = jwk
                .get("x")
                .ok_or_else(|| OAuth2Error::new("invalid_dpop_proof", Some("EC JWK missing x")))?;
            let y = jwk
                .get("y")
                .ok_or_else(|| OAuth2Error::new("invalid_dpop_proof", Some("EC JWK missing y")))?;
            serde_json::json!({ "crv": crv, "kty": kty, "x": x, "y": y })
        }
        "RSA" => {
            let e = jwk
                .get("e")
                .ok_or_else(|| OAuth2Error::new("invalid_dpop_proof", Some("RSA JWK missing e")))?;
            let n = jwk
                .get("n")
                .ok_or_else(|| OAuth2Error::new("invalid_dpop_proof", Some("RSA JWK missing n")))?;
            serde_json::json!({ "e": e, "kty": kty, "n": n })
        }
        "OKP" => {
            let crv = jwk.get("crv").ok_or_else(|| {
                OAuth2Error::new("invalid_dpop_proof", Some("OKP JWK missing crv"))
            })?;
            let x = jwk
                .get("x")
                .ok_or_else(|| OAuth2Error::new("invalid_dpop_proof", Some("OKP JWK missing x")))?;
            serde_json::json!({ "crv": crv, "kty": kty, "x": x })
        }
        _ => {
            return Err(OAuth2Error::new(
                "invalid_dpop_proof",
                Some("Unsupported JWK key type"),
            ))
        }
    };
    serde_json::to_string(&obj).map_err(|e| OAuth2Error::new("server_error", Some(&e.to_string())))
}

/// Verify the DPoP proof JWT signature and extract claims.
fn verify_dpop_signature(
    dpop_proof: &str,
    alg: &jsonwebtoken::Algorithm,
    jwk: &serde_json::Value,
) -> Result<DpopClaims, OAuth2Error> {
    use jsonwebtoken::{Algorithm, DecodingKey, Validation};

    let decoding_key = match alg {
        Algorithm::RS256
        | Algorithm::RS384
        | Algorithm::RS512
        | Algorithm::PS256
        | Algorithm::PS384
        | Algorithm::PS512 => {
            let n = jwk.get("n").and_then(|v| v.as_str()).ok_or_else(|| {
                OAuth2Error::new("invalid_dpop_proof", Some("RSA JWK missing 'n'"))
            })?;
            let e = jwk.get("e").and_then(|v| v.as_str()).ok_or_else(|| {
                OAuth2Error::new("invalid_dpop_proof", Some("RSA JWK missing 'e'"))
            })?;
            DecodingKey::from_rsa_components(n, e).map_err(|e| {
                OAuth2Error::new("invalid_dpop_proof", Some(&format!("Invalid RSA key: {e}")))
            })?
        }
        Algorithm::ES256 | Algorithm::ES384 => {
            let x = jwk.get("x").and_then(|v| v.as_str()).ok_or_else(|| {
                OAuth2Error::new("invalid_dpop_proof", Some("EC JWK missing 'x'"))
            })?;
            let y = jwk.get("y").and_then(|v| v.as_str()).ok_or_else(|| {
                OAuth2Error::new("invalid_dpop_proof", Some("EC JWK missing 'y'"))
            })?;
            DecodingKey::from_ec_components(x, y).map_err(|e| {
                OAuth2Error::new("invalid_dpop_proof", Some(&format!("Invalid EC key: {e}")))
            })?
        }
        _ => {
            return Err(OAuth2Error::new(
                "invalid_dpop_proof",
                Some("DPoP proof uses unsupported algorithm (only RS256/RS384/RS512/PS256/PS384/PS512/ES256/ES384 allowed)"),
            ));
        }
    };

    let mut validation = Validation::new(*alg);
    // DPoP proofs have no audience claim; disable aud validation.
    validation.set_audience(&[""]); // will be overridden below
    validation.validate_aud = false;
    // We check iat manually for the ±5 min window.
    validation.validate_exp = false;
    // No iss claim required in DPoP proofs — simply leave issuer validation disabled.
    // Required claims per RFC 9449 §4.2.
    validation.set_required_spec_claims(&["htm", "htu", "iat", "jti"]);

    let token_data = jsonwebtoken::decode::<DpopClaims>(dpop_proof, &decoding_key, &validation)
        .map_err(|e| {
            OAuth2Error::new(
                "invalid_dpop_proof",
                Some(&format!("DPoP proof signature invalid: {e}")),
            )
        })?;

    Ok(token_data.claims)
}

/// Strip the query string and fragment from a URL for `htu` comparison.
fn strip_query(url: &str) -> String {
    // Find first '?' or '#' and truncate there.
    let end = url.find('?').or_else(|| url.find('#')).unwrap_or(url.len());
    url[..end].trim_end_matches('/').to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_query_removes_query_string() {
        assert_eq!(
            strip_query("https://example.com/oauth/token?foo=bar"),
            "https://example.com/oauth/token"
        );
    }

    #[test]
    fn strip_query_leaves_plain_url() {
        assert_eq!(
            strip_query("https://example.com/oauth/token"),
            "https://example.com/oauth/token"
        );
    }

    #[test]
    fn dpop_replay_store_rejects_duplicate_jti() {
        let store = DpopReplayStore::new();
        let expiry = Instant::now() + Duration::from_secs(60);
        store.check_and_insert("test-jti", expiry).unwrap();
        let result = store.check_and_insert("test-jti", expiry);
        assert!(result.is_err());
    }

    #[test]
    fn dpop_replay_store_accepts_different_jti() {
        let store = DpopReplayStore::new();
        let expiry = Instant::now() + Duration::from_secs(60);
        store.check_and_insert("jti-1", expiry).unwrap();
        store.check_and_insert("jti-2", expiry).unwrap();
    }
}
