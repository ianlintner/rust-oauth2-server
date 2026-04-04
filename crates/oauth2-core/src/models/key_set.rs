//! JWT signing key management with rotation support.
//!
//! `KeySet` holds multiple `SigningKey`s: one current per algorithm, plus
//! previously-rotated keys within their grace period. Tokens are signed with
//! the current key and can be validated against any active (non-expired) key.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Supported JWT signing algorithms.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Algorithm {
    HS256,
    RS256,
}

impl std::fmt::Display for Algorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Algorithm::HS256 => write!(f, "HS256"),
            Algorithm::RS256 => write!(f, "RS256"),
        }
    }
}

impl std::str::FromStr for Algorithm {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_uppercase().as_str() {
            "HS256" => Ok(Algorithm::HS256),
            "RS256" => Ok(Algorithm::RS256),
            other => Err(format!("Unknown algorithm: {other}")),
        }
    }
}

/// A single JWT signing key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigningKey {
    /// Unique key identifier (set in the JWT `kid` header).
    pub kid: String,
    /// Signing algorithm.
    pub algorithm: Algorithm,
    /// Raw key bytes: HMAC secret for HS256, PEM bytes for RS256.
    #[serde(skip_serializing)]
    pub key_material: Vec<u8>,
    /// Whether this key is the current signing key for its algorithm.
    pub is_current: bool,
    /// When this key was created.
    pub created_at: DateTime<Utc>,
    /// When this key expires (set during rotation for old keys).
    pub expires_at: Option<DateTime<Utc>>,
}

impl SigningKey {
    /// Whether this key is still active (not expired).
    pub fn is_active(&self) -> bool {
        match self.expires_at {
            Some(exp) => Utc::now() < exp,
            None => true,
        }
    }
}

/// A set of signing keys supporting rotation.
#[derive(Debug, Clone, Default)]
pub struct KeySet {
    keys: Vec<SigningKey>,
}

impl KeySet {
    pub fn new() -> Self {
        Self { keys: Vec::new() }
    }

    /// Create a KeySet from a list of keys.
    pub fn from_keys(keys: Vec<SigningKey>) -> Self {
        Self { keys }
    }

    /// The current signing key for a specific algorithm.
    pub fn current_for_alg(&self, alg: Algorithm) -> Option<&SigningKey> {
        self.keys
            .iter()
            .find(|k| k.is_current && k.algorithm == alg && k.is_active())
    }

    /// Find a key by its `kid`.
    pub fn find(&self, kid: &str) -> Option<&SigningKey> {
        self.keys.iter().find(|k| k.kid == kid && k.is_active())
    }

    /// All non-expired keys.
    pub fn active_keys(&self) -> Vec<&SigningKey> {
        self.keys.iter().filter(|k| k.is_active()).collect()
    }

    /// All keys (including expired), for persistence.
    pub fn all_keys(&self) -> &[SigningKey] {
        &self.keys
    }

    /// Add a key to the set.
    pub fn add(&mut self, key: SigningKey) {
        self.keys.push(key);
    }

    /// Rotate: insert a new key as current, mark old keys of the same
    /// algorithm as non-current with an expiration grace period.
    pub fn rotate(&mut self, new_key: SigningKey, grace_period: Duration) {
        let alg = new_key.algorithm;
        let expires_at = Utc::now() + chrono::Duration::from_std(grace_period).unwrap_or_default();

        for key in &mut self.keys {
            if key.algorithm == alg && key.is_current {
                key.is_current = false;
                key.expires_at = Some(expires_at);
            }
        }

        self.keys.push(new_key);
    }

    /// Remove expired keys. Returns the kids of pruned keys.
    pub fn prune_expired(&mut self) -> Vec<String> {
        let now = Utc::now();
        let mut pruned = Vec::new();
        self.keys.retain(|k| {
            if let Some(exp) = k.expires_at {
                if now >= exp {
                    pruned.push(k.kid.clone());
                    return false;
                }
            }
            true
        });
        pruned
    }
}

/// Encrypt key material using AES-256-GCM.
///
/// The JWT secret is used as the KEK (key-encryption-key).
/// Returns `nonce || ciphertext` as a single byte vector.
pub fn encrypt_key_material(plaintext: &[u8], jwt_secret: &str) -> Result<Vec<u8>, String> {
    use aes_gcm::{
        aead::{Aead, KeyInit, OsRng},
        AeadCore, Aes256Gcm,
    };

    // Derive a 32-byte key from the JWT secret via SHA-256
    let key_bytes = sha256_hash(jwt_secret.as_bytes());
    let cipher =
        Aes256Gcm::new_from_slice(&key_bytes).map_err(|e| format!("AES key init error: {e}"))?;

    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|e| format!("Encryption error: {e}"))?;

    // Prepend nonce (12 bytes) to ciphertext
    let mut result = nonce.to_vec();
    result.extend_from_slice(&ciphertext);
    Ok(result)
}

/// Decrypt key material encrypted with `encrypt_key_material`.
pub fn decrypt_key_material(encrypted: &[u8], jwt_secret: &str) -> Result<Vec<u8>, String> {
    use aes_gcm::{
        aead::{Aead, KeyInit},
        Aes256Gcm, Nonce,
    };

    if encrypted.len() < 13 {
        return Err("Encrypted data too short".into());
    }

    let key_bytes = sha256_hash(jwt_secret.as_bytes());
    let cipher =
        Aes256Gcm::new_from_slice(&key_bytes).map_err(|e| format!("AES key init error: {e}"))?;

    let (nonce_bytes, ciphertext) = encrypted.split_at(12);
    let nonce_arr: [u8; 12] = nonce_bytes
        .try_into()
        .map_err(|_| "Invalid nonce length".to_string())?;
    let nonce = Nonce::from(nonce_arr);

    cipher
        .decrypt(&nonce, ciphertext)
        .map_err(|e| format!("Decryption error: {e}"))
}

/// SHA-256 hash (used to derive AES key from JWT secret).
fn sha256_hash(data: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    result.into()
}

#[cfg(test)]
mod encryption_tests {
    use super::*;

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let plaintext = b"my-secret-key-material-here";
        let secret = "test-jwt-secret-that-is-long-enough-for-testing";

        let encrypted = encrypt_key_material(plaintext, secret).unwrap();
        assert_ne!(&encrypted, plaintext);

        let decrypted = decrypt_key_material(&encrypted, secret).unwrap();
        assert_eq!(&decrypted, plaintext);
    }

    #[test]
    fn wrong_secret_fails_to_decrypt() {
        let plaintext = b"sensitive-data";
        let encrypted =
            encrypt_key_material(plaintext, "correct-secret-for-test-purposes-1234").unwrap();
        let result = decrypt_key_material(&encrypted, "wrong-secret-for-testing-purposes-12345");
        assert!(result.is_err());
    }

    #[test]
    fn short_ciphertext_rejected() {
        let result = decrypt_key_material(&[0u8; 5], "any-secret");
        assert!(result.is_err());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration as ChronoDuration;

    fn make_key(kid: &str, alg: Algorithm, current: bool) -> SigningKey {
        SigningKey {
            kid: kid.to_string(),
            algorithm: alg,
            key_material: vec![1, 2, 3],
            is_current: current,
            created_at: Utc::now(),
            expires_at: None,
        }
    }

    #[test]
    fn current_for_alg_returns_active_current_key() {
        let mut ks = KeySet::new();
        ks.add(make_key("hs-1", Algorithm::HS256, true));
        ks.add(make_key("rs-1", Algorithm::RS256, false));
        assert_eq!(ks.current_for_alg(Algorithm::HS256).unwrap().kid, "hs-1");
        assert!(ks.current_for_alg(Algorithm::RS256).is_none());
    }

    #[test]
    fn current_for_alg_filters_by_algorithm() {
        let mut ks = KeySet::new();
        ks.add(make_key("hs-1", Algorithm::HS256, true));
        ks.add(make_key("rs-1", Algorithm::RS256, true));
        assert_eq!(ks.current_for_alg(Algorithm::RS256).unwrap().kid, "rs-1");
    }

    #[test]
    fn find_by_kid() {
        let mut ks = KeySet::new();
        ks.add(make_key("abc", Algorithm::HS256, false));
        assert!(ks.find("abc").is_some());
        assert!(ks.find("missing").is_none());
    }

    #[test]
    fn rotate_marks_old_key_non_current() {
        let mut ks = KeySet::new();
        ks.add(make_key("old", Algorithm::HS256, true));

        let new = SigningKey {
            kid: "new".into(),
            algorithm: Algorithm::HS256,
            key_material: vec![4, 5, 6],
            is_current: true,
            created_at: Utc::now(),
            expires_at: None,
        };
        ks.rotate(new, Duration::from_secs(3600));

        assert_eq!(ks.current_for_alg(Algorithm::HS256).unwrap().kid, "new");
        let old = ks.find("old").unwrap();
        assert!(!old.is_current);
        assert!(old.expires_at.is_some());
    }

    #[test]
    fn prune_expired_removes_old_keys() {
        let mut ks = KeySet::new();
        let mut expired_key = make_key("expired", Algorithm::HS256, false);
        expired_key.expires_at = Some(Utc::now() - ChronoDuration::hours(1));
        ks.add(expired_key);
        ks.add(make_key("current", Algorithm::HS256, true));

        let pruned = ks.prune_expired();
        assert_eq!(pruned, vec!["expired"]);
        assert_eq!(ks.active_keys().len(), 1);
    }

    #[test]
    fn active_keys_excludes_expired() {
        let mut ks = KeySet::new();
        ks.add(make_key("good", Algorithm::HS256, true));
        let mut bad = make_key("bad", Algorithm::RS256, false);
        bad.expires_at = Some(Utc::now() - ChronoDuration::seconds(1));
        ks.add(bad);

        let active = ks.active_keys();
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].kid, "good");
    }

    #[test]
    fn algorithm_display_and_parse() {
        assert_eq!(Algorithm::HS256.to_string(), "HS256");
        assert_eq!("rs256".parse::<Algorithm>().unwrap(), Algorithm::RS256);
        assert!("unknown".parse::<Algorithm>().is_err());
    }
}
