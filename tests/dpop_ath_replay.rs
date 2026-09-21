//! RFC 9449 §4.3 / §7.1 — DPoP `ath` claim validation and the storage-backed
//! `jti` replay store.
//!
//! * `ath` = base64url(SHA-256(ASCII access token)). It is REQUIRED whenever a
//!   DPoP proof accompanies an access token (introspection here); the token
//!   endpoint issues the token, so no `ath` is expected there.
//! * The `jti` replay store may be backed by `Storage` so replay detection
//!   survives a restart and works across instances.

use std::sync::OnceLock;
use std::time::Duration;

use actix::Actor;
use actix_web::{test, web, App};
use base64::{engine::general_purpose, Engine as _};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header as JwtHeader};
use oauth2_actix::actors::TokenActorPool;
use oauth2_actix::handlers::dpop::{compute_ath, validate_dpop_proof, DpopReplayStore};
use oauth2_actix::handlers::wellknown::OidcConfig;
use oauth2_core::Client;
use oauth2_observability::Metrics;
use rsa::pkcs1::EncodeRsaPrivateKey;
use rsa::traits::PublicKeyParts;
use rsa::{RsaPrivateKey, RsaPublicKey};
use serde_json::json;

/// RSA keypair used to sign DPoP proofs. Generated once per test binary —
/// 2048-bit key generation is expensive in debug builds.
fn signer() -> &'static (String, serde_json::Value) {
    static SIGNER: OnceLock<(String, serde_json::Value)> = OnceLock::new();
    SIGNER.get_or_init(|| {
        let mut rng = rand_core::OsRng;
        let private_key = RsaPrivateKey::new(&mut rng, 2048).expect("generate RSA key");
        let public_key = RsaPublicKey::from(&private_key);
        let pem = private_key
            .to_pkcs1_pem(rsa::pkcs1::LineEnding::LF)
            .expect("encode private key")
            .to_string();
        let jwk = json!({
            "kty": "RSA",
            "n": general_purpose::URL_SAFE_NO_PAD.encode(public_key.n().to_bytes_be()),
            "e": general_purpose::URL_SAFE_NO_PAD.encode(public_key.e().to_bytes_be()),
        });
        (pem, jwk)
    })
}

/// Build a signed DPoP proof JWT with the given claims.
fn dpop_proof(htm: &str, htu: &str, jti: &str, ath: Option<&str>) -> String {
    let (pem, jwk) = signer();
    let mut header = JwtHeader::new(Algorithm::RS256);
    header.typ = Some("dpop+jwt".to_string());
    header.jwk = Some(serde_json::from_value(jwk.clone()).expect("jwk header"));

    let mut claims = json!({
        "htm": htm,
        "htu": htu,
        "iat": chrono::Utc::now().timestamp(),
        "jti": jti,
    });
    if let Some(ath) = ath {
        claims["ath"] = json!(ath);
    }

    let key = EncodingKey::from_rsa_pem(pem.as_bytes()).expect("encoding key");
    encode(&header, &claims, &key).expect("sign DPoP proof")
}

const INTROSPECT_URL: &str = "http://auth.test/oauth/introspect";

// ---------------------------------------------------------------------------
// `ath` validation
// ---------------------------------------------------------------------------

/// RFC 9449 §4.3 step 12: when an access token accompanies the proof, `ath`
/// MUST hash to that exact token.
#[actix_web::test]
async fn ath_mismatch_is_rejected() {
    let store = DpopReplayStore::new();
    let proof = dpop_proof(
        "POST",
        INTROSPECT_URL,
        "ath-mismatch-1",
        Some(&compute_ath("some-other-token")),
    );

    let err = validate_dpop_proof(
        &proof,
        "POST",
        INTROSPECT_URL,
        &store,
        Some("the-presented-token"),
    )
    .await
    .expect_err("ath over a different token must be rejected");
    assert_eq!(err.error, "invalid_dpop_proof");
    assert!(err
        .error_description
        .as_ref()
        .expect("description")
        .contains("ath"));
}

/// RFC 9449 §7.1: `ath` is REQUIRED when the proof accompanies an access
/// token, so a proof without it must be rejected.
#[actix_web::test]
async fn missing_ath_is_rejected_when_expected() {
    let store = DpopReplayStore::new();
    let proof = dpop_proof("POST", INTROSPECT_URL, "ath-missing-1", None);

    let err = validate_dpop_proof(
        &proof,
        "POST",
        INTROSPECT_URL,
        &store,
        Some("the-presented-token"),
    )
    .await
    .expect_err("missing ath must be rejected when an access token is presented");
    assert_eq!(err.error, "invalid_dpop_proof");
}

/// Matching `ath` is accepted.
#[actix_web::test]
async fn matching_ath_is_accepted() {
    let store = DpopReplayStore::new();
    let token = "the-presented-token";
    let proof = dpop_proof(
        "POST",
        INTROSPECT_URL,
        "ath-match-1",
        Some(&compute_ath(token)),
    );

    validate_dpop_proof(&proof, "POST", INTROSPECT_URL, &store, Some(token))
        .await
        .expect("matching ath must be accepted");
}

/// Token endpoint: no access token is presented, so `ath` is not expected and
/// a proof without it stays valid (and one carrying `ath` is not scrutinized).
#[actix_web::test]
async fn token_endpoint_does_not_require_ath() {
    let store = DpopReplayStore::new();
    let url = "http://auth.test/oauth/token";

    let no_ath = dpop_proof("POST", url, "token-ep-1", None);
    validate_dpop_proof(&no_ath, "POST", url, &store, None)
        .await
        .expect("token endpoint proof without ath must be accepted");

    let with_ath = dpop_proof("POST", url, "token-ep-2", Some(&compute_ath("anything")));
    validate_dpop_proof(&with_ath, "POST", url, &store, None)
        .await
        .expect("token endpoint must not reject a proof that carries ath");
}

/// `compute_ath` is base64url (no padding) of SHA-256 over the ASCII token.
#[actix_web::test]
async fn compute_ath_matches_rfc_example_shape() {
    // Known SHA-256 of "abc" = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
    let expected = general_purpose::URL_SAFE_NO_PAD.encode(
        hex_to_bytes("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad").as_slice(),
    );
    assert_eq!(compute_ath("abc"), expected);
}

fn hex_to_bytes(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("hex"))
        .collect()
}

// ---------------------------------------------------------------------------
// Storage-backed replay store
// ---------------------------------------------------------------------------

/// Two independent `DpopReplayStore` instances sharing one `Storage` must
/// detect a replay across the instance boundary (a second server process /
/// worker must not accept a `jti` the first one already consumed).
#[actix_web::test]
async fn storage_backed_replay_is_detected_across_store_instances() {
    let storage = oauth2_storage_factory::create_storage("sqlite::memory:")
        .await
        .expect("create storage");
    storage.init().await.expect("init storage");

    let store_a = DpopReplayStore::with_storage(storage.clone());
    let store_b = DpopReplayStore::with_storage(storage.clone());

    store_a
        .check_and_insert("shared-jti", Duration::from_secs(600))
        .await
        .expect("first use of a jti is fresh");

    let err = store_b
        .check_and_insert("shared-jti", Duration::from_secs(600))
        .await
        .expect_err("a jti already recorded by another instance is a replay");
    assert_eq!(err.error, "invalid_dpop_proof");
    assert!(err
        .error_description
        .as_ref()
        .expect("description")
        .contains("replay"));

    // A different jti is unaffected.
    store_b
        .check_and_insert("other-jti", Duration::from_secs(600))
        .await
        .expect("unrelated jti is fresh");
}

/// In-memory stores stay independent (the pre-existing behaviour).
#[actix_web::test]
async fn in_memory_stores_are_independent() {
    let store_a = DpopReplayStore::new();
    let store_b = DpopReplayStore::new();

    store_a
        .check_and_insert("jti-x", Duration::from_secs(60))
        .await
        .expect("fresh");
    store_b
        .check_and_insert("jti-x", Duration::from_secs(60))
        .await
        .expect("independent in-memory store does not see the other's jti");
    store_a
        .check_and_insert("jti-x", Duration::from_secs(60))
        .await
        .expect_err("same store rejects the replay");
}

// ---------------------------------------------------------------------------
// HTTP: introspection of a DPoP-bound token
// ---------------------------------------------------------------------------

/// End-to-end: mint a DPoP-bound access token at the token endpoint (no `ath`
/// required there), then introspect it with proofs carrying a correct and an
/// incorrect `ath`.
#[actix_web::test]
async fn introspection_requires_matching_ath() {
    let storage = oauth2_storage_factory::create_storage("sqlite::memory:")
        .await
        .expect("create storage");
    storage.init().await.expect("init storage");

    let client = Client::new(
        "dpop_client".to_string(),
        "dpop_secret".to_string(),
        vec!["https://unused.example/cb".to_string()],
        vec!["client_credentials".to_string()],
        "read".to_string(),
        "DPoP test client".to_string(),
    );
    storage.save_client(&client).await.expect("save client");

    let jwt_secret = "test_jwt_secret".to_string();
    let metrics = Metrics::new().expect("metrics");
    let token_actor = oauth2_actix::actors::TokenActor::new(
        storage.clone(),
        jwt_secret.clone(),
        "http://localhost".to_string(),
    )
    .start();
    let token_pool = TokenActorPool::new(vec![token_actor]);
    let client_actor = oauth2_actix::actors::ClientActor::new(storage.clone()).start();
    let auth_actor = oauth2_actix::actors::AuthActor::new(storage.clone()).start();

    let oidc_config = OidcConfig {
        issuer: "http://localhost".to_string(),
        jwt_secret: jwt_secret.clone(),
        id_token_alg: "HS256".to_string(),
        id_token_kid: None,
        id_token_private_key_pem: None,
    };

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(token_pool))
            .app_data(web::Data::new(client_actor))
            .app_data(web::Data::new(auth_actor))
            .app_data(web::Data::new(storage.clone()))
            .app_data(web::Data::new(jwt_secret.clone()))
            .app_data(web::Data::new(false)) // stateless validation
            .app_data(web::Data::new(metrics))
            .app_data(web::Data::new(oidc_config))
            .app_data(web::Data::new(DpopReplayStore::new()))
            .service(
                web::scope("/oauth")
                    .route(
                        "/token",
                        web::post().to(oauth2_actix::handlers::oauth::token),
                    )
                    .route(
                        "/introspect",
                        web::post().to(oauth2_actix::handlers::token::introspect),
                    ),
            ),
    )
    .await;

    // ── Mint a DPoP-bound token: the proof carries no `ath`. ────────────────
    let token_proof = dpop_proof(
        "POST",
        "http://auth.test/oauth/token",
        "http-token-jti-1",
        None,
    );
    let basic = format!(
        "Basic {}",
        general_purpose::STANDARD.encode(b"dpop_client:dpop_secret")
    );
    let req = test::TestRequest::post()
        .uri("/oauth/token")
        .insert_header(("Host", "auth.test"))
        .insert_header(("Authorization", basic.clone()))
        .insert_header(("Content-Type", "application/x-www-form-urlencoded"))
        .insert_header(("DPoP", token_proof))
        .set_payload("grant_type=client_credentials&scope=read")
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(
        resp.status(),
        200,
        "token endpoint must accept a DPoP proof without ath"
    );
    let body: serde_json::Value = test::read_body_json(resp).await;
    let access_token = body["access_token"]
        .as_str()
        .expect("access_token")
        .to_string();

    // ── Introspect with the WRONG ath → inactive. ───────────────────────────
    let bad_proof = dpop_proof(
        "POST",
        INTROSPECT_URL,
        "http-introspect-jti-1",
        Some(&compute_ath("not-the-token")),
    );
    let req = test::TestRequest::post()
        .uri("/oauth/introspect")
        .insert_header(("Host", "auth.test"))
        .insert_header(("Authorization", basic.clone()))
        .insert_header(("Content-Type", "application/x-www-form-urlencoded"))
        .insert_header(("DPoP", bad_proof))
        .set_payload(format!("token={access_token}"))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(
        body["active"], false,
        "introspection with a mismatched ath must report the token inactive"
    );

    // ── Introspect with NO ath → inactive (ath is REQUIRED here). ───────────
    let no_ath_proof = dpop_proof("POST", INTROSPECT_URL, "http-introspect-jti-2", None);
    let req = test::TestRequest::post()
        .uri("/oauth/introspect")
        .insert_header(("Host", "auth.test"))
        .insert_header(("Authorization", basic.clone()))
        .insert_header(("Content-Type", "application/x-www-form-urlencoded"))
        .insert_header(("DPoP", no_ath_proof))
        .set_payload(format!("token={access_token}"))
        .to_request();
    let resp = test::call_service(&app, req).await;
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(
        body["active"], false,
        "introspection without ath must report the token inactive"
    );

    // ── Introspect with the CORRECT ath → active. ───────────────────────────
    let good_proof = dpop_proof(
        "POST",
        INTROSPECT_URL,
        "http-introspect-jti-3",
        Some(&compute_ath(&access_token)),
    );
    let req = test::TestRequest::post()
        .uri("/oauth/introspect")
        .insert_header(("Host", "auth.test"))
        .insert_header(("Authorization", basic))
        .insert_header(("Content-Type", "application/x-www-form-urlencoded"))
        .insert_header(("DPoP", good_proof))
        .set_payload(format!("token={access_token}"))
        .to_request();
    let resp = test::call_service(&app, req).await;
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(
        body["active"], true,
        "introspection with a matching ath must report the token active"
    );
}
