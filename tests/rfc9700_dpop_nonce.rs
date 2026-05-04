//! RFC 9449 §§8, 9 — DPoP server-issued nonce enforcement.
//!
//! Closes Phase 6.2 enforcement gap. Per-client opt-in via
//! `Client.dpop_nonce_required`; when enabled the AS rejects DPoP proofs
//! lacking a valid nonce with `error: use_dpop_nonce` and an accompanying
//! `DPoP-Nonce` response header.

use actix_web::body::MessageBody;
use oauth2_actix::handlers::dpop::{enforce_dpop_nonce, DpopValidated};
use oauth2_actix::handlers::dpop_nonce::{use_dpop_nonce_response, DpopNonceIssuer};

fn issuer() -> DpopNonceIssuer {
    DpopNonceIssuer::new([0x55u8; 32], 300)
}

fn validated_with(nonce: Option<String>) -> DpopValidated {
    DpopValidated {
        jkt: "fake-jkt-thumbprint".to_string(),
        nonce,
    }
}

/// Vector 1: client with `dpop_nonce_required=true`, proof without `nonce`
/// → `use_dpop_nonce`.
#[test]
fn missing_nonce_returns_use_dpop_nonce() {
    let issuer = issuer();
    let validated = validated_with(None);
    let err = enforce_dpop_nonce(&validated, &issuer)
        .expect_err("missing nonce must be rejected when issuer is in use");
    assert_eq!(err.error, "use_dpop_nonce");
}

/// Vector 2: retry with the issued nonce → success.
#[test]
fn valid_nonce_accepted() {
    let issuer = issuer();
    let nonce = issuer.issue();
    let validated = validated_with(Some(nonce));
    enforce_dpop_nonce(&validated, &issuer).expect("freshly issued nonce verifies");
}

/// Vector 3: forged nonce (signature mismatch) → `invalid_dpop_proof`.
#[test]
fn forged_nonce_rejected_as_invalid_proof() {
    use base64::{engine::general_purpose, Engine as _};
    let issuer = issuer();
    let nonce = issuer.issue();
    let mut bytes = general_purpose::URL_SAFE_NO_PAD.decode(&nonce).unwrap();
    bytes[10] ^= 0x01; // flip a bit in the HMAC tag
    let forged = general_purpose::URL_SAFE_NO_PAD.encode(&bytes);
    let validated = validated_with(Some(forged));

    let err = enforce_dpop_nonce(&validated, &issuer).expect_err("forged nonce rejected");
    // `invalid_dpop_proof` (not `use_dpop_nonce`): we deliberately do NOT
    // hand out a fresh nonce when the client tampered with the value, to
    // avoid signaling that the secret is the only thing they're missing.
    assert_eq!(err.error, "invalid_dpop_proof");
}

/// Vector 4: nonce from a clearly stale bucket (3 lifetimes ago) →
/// `use_dpop_nonce` (so client retries with a fresh nonce).
#[test]
fn stale_nonce_returns_use_dpop_nonce() {
    let issuer = DpopNonceIssuer::new([0x77u8; 32], 1); // 1-second buckets
    let nonce = issuer.issue();
    // Sleep past the grace window: current + previous bucket only.
    std::thread::sleep(std::time::Duration::from_secs(3));
    let validated = validated_with(Some(nonce));

    let err = enforce_dpop_nonce(&validated, &issuer).expect_err("stale nonce rejected");
    assert_eq!(
        err.error, "use_dpop_nonce",
        "stale-but-correctly-signed nonce should re-issue, not look forged"
    );
}

/// Vector 5: `use_dpop_nonce_response` carries the `DPoP-Nonce` header
/// and a parseable JSON error body.
#[actix_web::test]
async fn use_dpop_nonce_response_includes_header_and_body() {
    let issuer = issuer();
    let resp = use_dpop_nonce_response(&issuer, Some("hint"));

    assert_eq!(resp.status(), actix_web::http::StatusCode::BAD_REQUEST);
    let header = resp
        .headers()
        .get("DPoP-Nonce")
        .expect("DPoP-Nonce header must be present");
    let nonce = header.to_str().unwrap().to_string();
    // The header value must verify against the same issuer.
    issuer
        .verify(&nonce)
        .expect("DPoP-Nonce header value must be a valid issued nonce");

    let body_bytes = resp
        .into_body()
        .try_into_bytes()
        .expect("body should be readable in-memory");
    let body: serde_json::Value = serde_json::from_slice(&body_bytes).expect("body must be JSON");
    assert_eq!(body["error"], "use_dpop_nonce");
    assert_eq!(body["error_description"], "hint");
}

/// Vector 6: previous-bucket nonce still verifies (grace window).
#[test]
fn previous_bucket_nonce_within_grace() {
    let issuer = DpopNonceIssuer::new([0x33u8; 32], 300);
    // Issuing right now puts us in the current bucket. The internal API
    // accepts current and current-1; we cover that path explicitly in
    // `dpop_nonce::tests::previous_bucket_accepted_current_plus_one_rejected`.
    // Here we just confirm the public path round-trips a fresh nonce.
    let nonce = issuer.issue();
    let validated = validated_with(Some(nonce));
    enforce_dpop_nonce(&validated, &issuer).expect("fresh nonce verifies");
}

/// `DpopNonceIssuer::from_env()` returns a working issuer even when no
/// env vars are set (per-process random secret path).
#[test]
fn from_env_default_works() {
    let issuer = DpopNonceIssuer::from_env();
    let nonce = issuer.issue();
    issuer.verify(&nonce).expect("from_env issuer round-trips");
}
