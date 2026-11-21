//! At-rest representation of credentials (storage format version 1).
//!
//! Two kinds of record, deliberately different:
//!
//! * **Bearer verifier** (`h1$<digest>`) — access/refresh tokens, authorization
//!   codes, device codes and registration access tokens. The value is high
//!   entropy and looked up by equality, so a domain-separated SHA-256 digest is
//!   stored instead of the value. It is *not recoverable*: nothing in the
//!   database can be replayed as a credential.
//! * **Client secret record** (`c1$<salt>$<verifier>$<sealed>`) — a salted
//!   verifier used for `client_secret_basic` / `client_secret_post`, plus the
//!   secret sealed with AES-256-GCM under a key derived from the server's JWT
//!   secret. The sealed part exists only because HMAC-based methods
//!   (`client_secret_jwt`, HS256 request objects) need the secret as key
//!   material; it is protected symmetric key material, not a verifier. When no
//!   key was configured at write time the sealed part is empty and those
//!   methods are unavailable for that client.
//!
//! Anything stored without the version prefix is a *legacy* (pre-cutover)
//! value. Verifiers never accept legacy values: see `docs/security/at-rest-hardening.md`.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use sha2::{Digest, Sha256};
use std::sync::OnceLock;
use subtle::ConstantTimeEq;

/// Prefix of a bearer verifier.
pub const BEARER_PREFIX: &str = "h1$";
/// Prefix of a client secret record.
pub const CLIENT_SECRET_PREFIX: &str = "c1$";

/// Value the cutover scripts write over legacy client secrets. Never valid.
pub const LEGACY_INVALIDATED_MARKER: &str = "legacy-invalidated";

static AT_REST_KEY: OnceLock<String> = OnceLock::new();

/// Install the process-wide secret that seals client secrets. First call wins;
/// returns `false` if a key was already installed. The server calls this once
/// at startup with the configured JWT secret.
pub fn init_at_rest_key(secret: &str) -> bool {
    AT_REST_KEY.set(secret.to_string()).is_ok()
}

fn digest(domain: &str, parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(domain.as_bytes());
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.ct_eq(b).into()
}

/// Deterministic verifier for a bearer value (used as the storage identifier).
pub fn hash_bearer(raw: &str) -> String {
    format!(
        "{BEARER_PREFIX}{}",
        URL_SAFE_NO_PAD.encode(digest("oauth2-at-rest:v1:bearer:", &[raw.as_bytes()]))
    )
}

/// `true` if `s` has the exact shape of a bearer verifier.
pub fn is_bearer_verifier(s: &str) -> bool {
    s.strip_prefix(BEARER_PREFIX)
        .is_some_and(|d| d.len() == 43 && URL_SAFE_NO_PAD.decode(d).is_ok())
}

/// Constant-time check of a presented bearer against a stored verifier.
/// A legacy (raw) stored value never matches.
pub fn verify_bearer(presented: &str, stored: &str) -> bool {
    is_bearer_verifier(stored) && ct_eq(hash_bearer(presented).as_bytes(), stored.as_bytes())
}

/// Identity for already-protected values, `hash_bearer` otherwise. Used only
/// for write-side idempotency (re-saving a record that was read back from
/// storage), never for authenticating a presented credential.
pub fn protect_bearer(value: &str) -> String {
    if value.is_empty() || is_bearer_verifier(value) {
        value.to_string()
    } else {
        hash_bearer(value)
    }
}

fn seal_key(secret: &str) -> String {
    format!("oauth2-at-rest:v1:client-secret-key:{secret}")
}

/// Build a client secret record from the raw secret.
pub fn seal_client_secret(raw: &str) -> String {
    let salt: [u8; 16] = *uuid::Uuid::new_v4().as_bytes();
    let verifier = digest("oauth2-at-rest:v1:client-secret:", &[&salt, raw.as_bytes()]);
    let sealed = AT_REST_KEY
        .get()
        .and_then(|k| {
            crate::models::key_set::encrypt_key_material(raw.as_bytes(), &seal_key(k)).ok()
        })
        .map(|b| URL_SAFE_NO_PAD.encode(b))
        .unwrap_or_default();
    format!(
        "{CLIENT_SECRET_PREFIX}{}${}${}",
        URL_SAFE_NO_PAD.encode(salt),
        URL_SAFE_NO_PAD.encode(verifier),
        sealed
    )
}

fn parse_client_secret(stored: &str) -> Option<(Vec<u8>, Vec<u8>, &str)> {
    let rest = stored.strip_prefix(CLIENT_SECRET_PREFIX)?;
    let mut it = rest.splitn(3, '$');
    let salt = URL_SAFE_NO_PAD.decode(it.next()?).ok()?;
    let verifier = URL_SAFE_NO_PAD.decode(it.next()?).ok()?;
    let sealed = it.next()?;
    (salt.len() == 16 && verifier.len() == 32).then_some((salt, verifier, sealed))
}

/// `true` if `s` is a well-formed client secret record.
pub fn is_client_secret_record(s: &str) -> bool {
    parse_client_secret(s).is_some()
}

/// Write-side idempotent protection (see [`protect_bearer`]).
pub fn protect_client_secret(value: &str) -> String {
    // The operator cutover marker must never be sealed into a usable secret.
    if value.is_empty() || value == LEGACY_INVALIDATED_MARKER || is_client_secret_record(value) {
        value.to_string()
    } else {
        seal_client_secret(value)
    }
}

/// Verify a presented client secret. Legacy (unprefixed) stored values never
/// match, and an empty presented secret never matches.
pub fn verify_client_secret(presented: &str, stored: &str) -> bool {
    if presented.is_empty() {
        return false;
    }
    match parse_client_secret(stored) {
        Some((salt, verifier, _)) => ct_eq(
            &digest(
                "oauth2-at-rest:v1:client-secret:",
                &[&salt, presented.as_bytes()],
            ),
            &verifier,
        ),
        None => false,
    }
}

/// Recover the HMAC key material from a client secret record, if it was
/// sealed and the configured key still matches.
pub fn client_secret_key(stored: &str) -> Option<Vec<u8>> {
    let (_, _, sealed) = parse_client_secret(stored)?;
    if sealed.is_empty() {
        return None;
    }
    let key = AT_REST_KEY.get()?;
    let bytes = URL_SAFE_NO_PAD.decode(sealed).ok()?;
    crate::models::key_set::decrypt_key_material(&bytes, &seal_key(key)).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bearer_roundtrip_and_legacy_boundary() {
        let h = hash_bearer("synthetic-token");
        assert!(is_bearer_verifier(&h));
        assert!(!h.contains("synthetic-token"));
        assert!(verify_bearer("synthetic-token", &h));
        assert!(!verify_bearer("other", &h));
        // A legacy raw value is never a match, even for itself.
        assert!(!verify_bearer("synthetic-token", "synthetic-token"));
        // Presenting the stored form does not authenticate.
        assert!(!verify_bearer(&h, &h));
        assert_eq!(protect_bearer(&h), h);
        assert_eq!(protect_bearer("synthetic-token"), h);
    }

    #[test]
    fn client_secret_record_verifies_and_rejects_legacy() {
        let rec = seal_client_secret("synthetic-secret");
        assert!(is_client_secret_record(&rec));
        assert!(!rec.contains("synthetic-secret"));
        assert!(verify_client_secret("synthetic-secret", &rec));
        assert!(!verify_client_secret("nope", &rec));
        assert!(!verify_client_secret("", &rec));
        assert!(!verify_client_secret(
            "synthetic-secret",
            "synthetic-secret"
        ));
        // Salted: two records of the same secret differ.
        assert_ne!(rec, seal_client_secret("synthetic-secret"));
        assert_eq!(protect_client_secret(&rec), rec);
    }

    #[test]
    fn sealed_key_recovered_only_with_key() {
        assert!(init_at_rest_key("unit-test-secret") || AT_REST_KEY.get().is_some());
        let rec = seal_client_secret("synthetic-secret");
        if AT_REST_KEY.get().map(String::as_str) == Some("unit-test-secret") {
            assert_eq!(client_secret_key(&rec).unwrap(), b"synthetic-secret");
        }
        assert!(client_secret_key("synthetic-secret").is_none());
    }
}
