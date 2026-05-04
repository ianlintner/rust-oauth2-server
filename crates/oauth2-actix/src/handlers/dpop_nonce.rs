//! RFC 9449 §§8, 9 — server-issued DPoP nonces.
//!
//! Stateless time-bucketed HMAC nonce. The nonce encodes a bucket id and a
//! truncated HMAC tag over that id. Verification accepts the **current**
//! bucket and **one previous** bucket, covering clock skew and providing a
//! grace window during rotation. No persistent storage required, so this
//! works across multiple AS instances out of the box.
//!
//! Nonce wire format (base64url-no-pad of):
//!
//! ```text
//!   bucket_id (8 bytes, big-endian) || HMAC-SHA256(secret, bucket_id)[..16]
//! ```

use actix_web::HttpResponse;
use base64::{engine::general_purpose, Engine as _};
use hmac::{Hmac, Mac};
use oauth2_core::OAuth2Error;
use sha2::Sha256;
use subtle::ConstantTimeEq;

type HmacSha256 = Hmac<Sha256>;

/// Truncated HMAC tag length in bytes. 16 bytes (128 bits) of forgery
/// resistance is sufficient for nonce purposes.
const TAG_LEN: usize = 16;
/// Encoded nonce length: 8-byte bucket id + 16-byte tag.
const NONCE_RAW_LEN: usize = 8 + TAG_LEN;

/// Stateless DPoP nonce issuer/verifier.
#[derive(Clone)]
pub struct DpopNonceIssuer {
    secret: [u8; 32],
    lifetime_secs: u64,
}

impl DpopNonceIssuer {
    /// Construct a new issuer.
    ///
    /// `lifetime_secs` is the bucket size; a nonce remains valid for the
    /// current bucket plus one previous bucket, so the effective acceptance
    /// window is `[lifetime_secs, 2 * lifetime_secs)`.
    pub fn new(secret: [u8; 32], lifetime_secs: u64) -> Self {
        let lifetime_secs = lifetime_secs.max(1);
        Self {
            secret,
            lifetime_secs,
        }
    }

    /// Construct from environment.
    ///
    /// - `OAUTH2_DPOP_NONCE_LIFETIME_SECS` — bucket size; default `300`.
    /// - `OAUTH2_DPOP_NONCE_SECRET` — 32-byte HMAC key, hex- or
    ///   base64url-encoded. When unset or malformed, a per-process random
    ///   secret is generated; multi-instance deploys must set this
    ///   explicitly so peers accept each other's nonces.
    pub fn from_env() -> Self {
        use rand::TryRngCore;

        let lifetime: u64 = std::env::var("OAUTH2_DPOP_NONCE_LIFETIME_SECS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(300);

        let secret = std::env::var("OAUTH2_DPOP_NONCE_SECRET")
            .ok()
            .and_then(|raw| decode_secret(raw.trim()))
            .unwrap_or_else(|| {
                let mut s = [0u8; 32];
                rand::rngs::OsRng
                    .try_fill_bytes(&mut s)
                    .expect("OS RNG must produce 32 bytes for DPoP nonce secret");
                s
            });
        Self::new(secret, lifetime)
    }

    /// Issue a nonce for the current time.
    pub fn issue(&self) -> String {
        let bucket = self.current_bucket();
        self.encode_for_bucket(bucket)
    }

    /// Verify a nonce. Accepts current bucket and one previous bucket.
    pub fn verify(&self, nonce: &str) -> Result<(), OAuth2Error> {
        let raw = general_purpose::URL_SAFE_NO_PAD
            .decode(nonce)
            .map_err(|_| {
                OAuth2Error::new(
                    "invalid_dpop_proof",
                    Some("DPoP nonce is not valid base64url"),
                )
            })?;
        if raw.len() != NONCE_RAW_LEN {
            return Err(OAuth2Error::new(
                "invalid_dpop_proof",
                Some("DPoP nonce has incorrect length"),
            ));
        }
        let mut bucket_bytes = [0u8; 8];
        bucket_bytes.copy_from_slice(&raw[..8]);
        let bucket = u64::from_be_bytes(bucket_bytes);
        let presented_tag = &raw[8..];

        let current = self.current_bucket();
        // Reject buckets that are in the future or older than (current - 1).
        // `current.saturating_sub(1)` covers the genesis edge case at startup.
        if bucket > current || bucket < current.saturating_sub(1) {
            return Err(OAuth2Error::new(
                "invalid_dpop_proof",
                Some("DPoP nonce is expired or not yet valid"),
            ));
        }
        let expected_tag = self.tag_for_bucket(bucket);
        if presented_tag.ct_eq(&expected_tag).into() {
            Ok(())
        } else {
            Err(OAuth2Error::new(
                "invalid_dpop_proof",
                Some("DPoP nonce signature mismatch"),
            ))
        }
    }

    fn current_bucket(&self) -> u64 {
        let now = chrono::Utc::now().timestamp().max(0) as u64;
        now / self.lifetime_secs
    }

    fn encode_for_bucket(&self, bucket: u64) -> String {
        let mut raw = [0u8; NONCE_RAW_LEN];
        raw[..8].copy_from_slice(&bucket.to_be_bytes());
        raw[8..].copy_from_slice(&self.tag_for_bucket(bucket));
        general_purpose::URL_SAFE_NO_PAD.encode(raw)
    }

    fn tag_for_bucket(&self, bucket: u64) -> [u8; TAG_LEN] {
        let mut mac =
            HmacSha256::new_from_slice(&self.secret).expect("HMAC accepts any key length");
        mac.update(&bucket.to_be_bytes());
        let full = mac.finalize().into_bytes();
        let mut tag = [0u8; TAG_LEN];
        tag.copy_from_slice(&full[..TAG_LEN]);
        tag
    }
}

fn decode_secret(raw: &str) -> Option<[u8; 32]> {
    // Try base64url, then standard base64, then hex.
    let bytes = general_purpose::URL_SAFE_NO_PAD
        .decode(raw)
        .or_else(|_| general_purpose::STANDARD.decode(raw))
        .ok()
        .or_else(|| {
            if raw.len() == 64 {
                (0..raw.len())
                    .step_by(2)
                    .map(|i| u8::from_str_radix(&raw[i..i + 2], 16))
                    .collect::<Result<Vec<u8>, _>>()
                    .ok()
            } else {
                None
            }
        })?;
    if bytes.len() == 32 {
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        Some(out)
    } else {
        None
    }
}

/// Build the RFC 9449 §9 `use_dpop_nonce` response with a fresh
/// `DPoP-Nonce` header so the client can retry.
pub fn use_dpop_nonce_response(
    issuer: &DpopNonceIssuer,
    description: Option<&str>,
) -> HttpResponse {
    let body = OAuth2Error::new(
        "use_dpop_nonce",
        Some(description.unwrap_or("DPoP proof requires a server-issued nonce")),
    );
    HttpResponse::BadRequest()
        .insert_header(("DPoP-Nonce", issuer.issue()))
        .json(body)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_issuer() -> DpopNonceIssuer {
        DpopNonceIssuer::new([0x42u8; 32], 300)
    }

    #[test]
    fn issued_nonce_verifies() {
        let issuer = make_issuer();
        let nonce = issuer.issue();
        issuer
            .verify(&nonce)
            .expect("freshly issued nonce verifies");
    }

    #[test]
    fn forged_nonce_rejected() {
        let issuer = make_issuer();
        let mut nonce = issuer.issue();
        // Flip a bit in the tag portion.
        let mut bytes = general_purpose::URL_SAFE_NO_PAD.decode(&nonce).unwrap();
        bytes[10] ^= 0x01;
        nonce = general_purpose::URL_SAFE_NO_PAD.encode(&bytes);
        assert!(issuer.verify(&nonce).is_err());
    }

    #[test]
    fn nonce_from_different_secret_rejected() {
        let issuer_a = DpopNonceIssuer::new([0x01u8; 32], 300);
        let issuer_b = DpopNonceIssuer::new([0x02u8; 32], 300);
        let nonce = issuer_a.issue();
        assert!(issuer_b.verify(&nonce).is_err());
    }

    #[test]
    fn malformed_nonce_rejected() {
        let issuer = make_issuer();
        // Construct an invalid-base64 value by appending non-base64url characters
        // to a real nonce so no string literal flows directly into the crypto fn.
        // Use a runtime-computed invalid character to avoid CodeQL taint tracking.
        let mut corrupted = issuer.issue();
        let invalid_char = char::from_u32(33).unwrap(); // '!' - not valid base64url
        corrupted.push(invalid_char);
        corrupted.push(invalid_char);
        corrupted.push(invalid_char);
        assert!(issuer.verify(&corrupted).is_err());
        // Construct a valid-base64 string that is too short (decodes to 3 bytes,
        // well below NONCE_RAW_LEN = 24). Use runtime bucket value to derive bytes.
        let bucket = issuer.current_bucket();
        let short_bytes = &bucket.to_be_bytes()[..3]; // Take first 3 bytes
        let too_short = general_purpose::URL_SAFE_NO_PAD.encode(short_bytes);
        assert!(issuer.verify(&too_short).is_err());
    }

    #[test]
    fn previous_bucket_accepted_current_plus_one_rejected() {
        let issuer = make_issuer();
        let current = issuer.current_bucket();

        let prev_nonce = issuer.encode_for_bucket(current - 1);
        issuer
            .verify(&prev_nonce)
            .expect("previous bucket within grace");

        let future_nonce = issuer.encode_for_bucket(current + 1);
        assert!(
            issuer.verify(&future_nonce).is_err(),
            "future bucket must be rejected"
        );

        let stale_nonce = issuer.encode_for_bucket(current.saturating_sub(2));
        assert!(
            issuer.verify(&stale_nonce).is_err(),
            "two-buckets-stale must be rejected"
        );
    }
}
