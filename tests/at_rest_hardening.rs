//! Storage format v1: credentials are persisted as verifiers, not raw values.
//! Synthetic, ephemeral records only.

use oauth2_core::at_rest::{self, BEARER_PREFIX, CLIENT_SECRET_PREFIX};
use oauth2_core::{AuthorizationCode, Client, DeviceAuthorization, Token};
use oauth2_ports::DynStorage;
use sqlx::Row;

async fn setup() -> (DynStorage, sqlx::SqlitePool, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let url = format!("sqlite:{}?mode=rwc", dir.path().join("t.db").display());
    let storage = oauth2_storage_factory::create_storage(&url).await.unwrap();
    storage.init().await.unwrap();
    let raw = sqlx::SqlitePool::connect(&url).await.unwrap();
    (storage, raw, dir)
}

fn client(id: &str, secret: &str) -> Client {
    Client::new(
        id.to_string(),
        secret.to_string(),
        vec!["https://example.test/cb".to_string()],
        vec!["authorization_code".to_string()],
        "read".to_string(),
        format!("synthetic {id}"),
    )
}

async fn column(raw: &sqlx::SqlitePool, sql: &str) -> Vec<String> {
    sqlx::query(sql)
        .fetch_all(raw)
        .await
        .unwrap()
        .iter()
        .map(|r| r.get::<String, _>(0))
        .collect()
}

#[actix_web::test]
async fn client_secret_is_stored_as_record_and_verifies() {
    let (storage, raw, _d) = setup().await;
    let mut c = client("c-hash", "synthetic-secret-value");
    c.registration_access_token = "synthetic-reg-token".to_string();
    storage.save_client(&c).await.unwrap();

    let secrets = column(&raw, "SELECT client_secret FROM clients").await;
    assert!(secrets[0].starts_with(CLIENT_SECRET_PREFIX));
    assert!(!secrets[0].contains("synthetic-secret-value"));
    let regs = column(&raw, "SELECT registration_access_token FROM clients").await;
    assert!(regs[0].starts_with(BEARER_PREFIX));
    assert!(!regs[0].contains("synthetic-reg-token"));

    let got = storage.get_client("c-hash").await.unwrap().unwrap();
    assert!(got.verify_secret("synthetic-secret-value"));
    assert!(!got.verify_secret("wrong"));
    // Re-saving a client read back from storage does not double-protect.
    storage.update_client(&got).await.unwrap();
    let got2 = storage.get_client("c-hash").await.unwrap().unwrap();
    assert!(got2.verify_secret("synthetic-secret-value"));
    assert!(at_rest::verify_bearer(
        "synthetic-reg-token",
        &got2.registration_access_token
    ));
}

#[actix_web::test]
async fn client_secret_rotation_replaces_verifier() {
    let (storage, raw, _d) = setup().await;
    storage
        .save_client(&client("c-rot", "old-secret"))
        .await
        .unwrap();
    storage
        .set_client_secret("c-rot", "new-secret")
        .await
        .unwrap();
    let got = storage.get_client("c-rot").await.unwrap().unwrap();
    assert!(got.verify_secret("new-secret"));
    assert!(!got.verify_secret("old-secret"));
    let secrets = column(&raw, "SELECT client_secret FROM clients").await;
    assert!(!secrets[0].contains("new-secret"));
}

#[actix_web::test]
async fn tokens_are_stored_hashed_and_lookups_use_raw_values() {
    let (storage, raw, _d) = setup().await;
    storage.save_client(&client("c1", "s")).await.unwrap();
    let t = Token::new(
        "synthetic-access".to_string(),
        Some("synthetic-refresh".to_string()),
        "c1".to_string(),
        None,
        "read".to_string(),
        3600,
        Some("fam".to_string()),
    );
    storage.save_token(&t).await.unwrap();

    let a = column(&raw, "SELECT access_token FROM tokens").await;
    let r = column(&raw, "SELECT refresh_token FROM tokens").await;
    assert!(a[0].starts_with(BEARER_PREFIX) && !a[0].contains("synthetic"));
    assert!(r[0].starts_with(BEARER_PREFIX) && !r[0].contains("synthetic"));

    let by_access = storage
        .get_token_by_access_token("synthetic-access")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(by_access.access_token, "synthetic-access");
    let by_refresh = storage
        .get_token_by_refresh_token("synthetic-refresh")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(by_refresh.id, t.id);

    // The stored verifier is not itself a credential.
    assert!(storage
        .get_token_by_access_token(&a[0])
        .await
        .unwrap()
        .is_none());
    assert!(storage
        .get_token_by_refresh_token(&r[0])
        .await
        .unwrap()
        .is_none());
}

#[actix_web::test]
async fn token_revocation_by_raw_value_hits_both_credentials() {
    let (storage, _raw, _d) = setup().await;
    storage.save_client(&client("c1", "s")).await.unwrap();
    let t = Token::new(
        "acc-rev".to_string(),
        Some("ref-rev".to_string()),
        "c1".to_string(),
        None,
        "read".to_string(),
        3600,
        None,
    );
    storage.save_token(&t).await.unwrap();
    storage.revoke_token("ref-rev").await.unwrap();
    let got = storage
        .get_token_by_access_token("acc-rev")
        .await
        .unwrap()
        .unwrap();
    assert!(got.revoked);
}

#[actix_web::test]
async fn legacy_plaintext_rows_are_not_accepted() {
    let (storage, raw, _d) = setup().await;
    // Simulate a pre-cutover row written directly (synthetic).
    storage.save_client(&client("c-legacy", "x")).await.unwrap();
    sqlx::query("UPDATE clients SET client_secret = 'legacy-plain' WHERE client_id = 'c-legacy'")
        .execute(&raw)
        .await
        .unwrap();
    let got = storage.get_client("c-legacy").await.unwrap().unwrap();
    assert!(!got.verify_secret("legacy-plain"));
    assert!(got.symmetric_key().is_none());

    let t = Token::new(
        "a".into(),
        Some("r".into()),
        "c-legacy".into(),
        None,
        "s".into(),
        60,
        None,
    );
    storage.save_token(&t).await.unwrap();
    sqlx::query("UPDATE tokens SET access_token = 'legacy-raw-access'")
        .execute(&raw)
        .await
        .unwrap();
    assert!(storage
        .get_token_by_access_token("legacy-raw-access")
        .await
        .unwrap()
        .is_none());
}

#[actix_web::test]
async fn authorization_and_device_codes_are_hashed() {
    let (storage, raw, _d) = setup().await;
    storage.save_client(&client("c1", "s")).await.unwrap();
    let user = oauth2_core::User::new("u1".into(), "$argon2id$x".into(), "u1@test.example".into());
    storage.save_user(&user).await.unwrap();
    let code = AuthorizationCode::new(
        "synthetic-code".into(),
        "c1".into(),
        user.id.clone(),
        "https://example.test/cb".into(),
        "read".into(),
        None,
        None,
        None,
        None,
        None,
        None,
    );
    storage.save_authorization_code(&code).await.unwrap();
    let stored = column(&raw, "SELECT code FROM authorization_codes").await;
    assert!(stored[0].starts_with(BEARER_PREFIX) && !stored[0].contains("synthetic"));
    let got = storage
        .get_authorization_code("synthetic-code")
        .await
        .unwrap()
        .unwrap();
    assert!(!got.used);
    storage
        .mark_authorization_code_used("synthetic-code")
        .await
        .unwrap();
    assert!(
        storage
            .get_authorization_code("synthetic-code")
            .await
            .unwrap()
            .unwrap()
            .used
    );
    assert!(storage
        .get_authorization_code(&stored[0])
        .await
        .unwrap()
        .is_none());

    let dev = DeviceAuthorization::new(
        "synthetic-device".into(),
        "ABCD-EFGH".into(),
        "c1".into(),
        "read".into(),
        600,
        5,
    );
    storage.save_device_authorization(&dev).await.unwrap();
    let stored = column(&raw, "SELECT device_code FROM device_authorizations").await;
    assert!(stored[0].starts_with(BEARER_PREFIX) && !stored[0].contains("synthetic"));
    assert!(storage
        .get_device_authorization_by_device_code("synthetic-device")
        .await
        .unwrap()
        .is_some());
    storage
        .mark_device_authorization_used("synthetic-device")
        .await
        .unwrap();
    assert!(
        storage
            .get_device_authorization_by_device_code("synthetic-device")
            .await
            .unwrap()
            .unwrap()
            .used
    );
}

#[test]
fn symmetric_key_material_is_sealed_and_recoverable_only_with_key() {
    at_rest::init_at_rest_key("synthetic-server-key");
    let rec = at_rest::seal_client_secret("synthetic-hmac-secret");
    assert!(!rec.contains("synthetic-hmac-secret"));
    assert!(at_rest::verify_client_secret("synthetic-hmac-secret", &rec));
    // Only assert recovery if this process owns the key (first init wins).
    if let Some(k) = oauth2_core::at_rest::client_secret_key(&rec) {
        assert_eq!(k, b"synthetic-hmac-secret");
    }
}

#[actix_web::test]
async fn refresh_rotation_evicts_warm_validation_cache() {
    use actix::Actor;
    use oauth2_actix::actors::token_actor::{RevokeToken, TokenActor, ValidateToken};

    let (storage, _raw, _d) = setup().await;
    storage.save_client(&client("c1", "s")).await.unwrap();
    let t = Token::new(
        "warm-access".to_string(),
        Some("warm-refresh".to_string()),
        "c1".to_string(),
        None,
        "read".to_string(),
        3600,
        None,
    );
    storage.save_token(&t).await.unwrap();
    let actor = TokenActor::new(
        storage.clone(),
        "synthetic-jwt-secret".into(),
        "http://localhost".into(),
    )
    .start();

    let validate = |raw: &str| ValidateToken {
        token: raw.to_string(),
        span: tracing::Span::none(),
    };
    // Warm the L1 cache with the raw access token.
    assert!(actor.send(validate("warm-access")).await.unwrap().is_ok());

    // Rotation path: the old token is loaded from storage (access token is a
    // verifier there) and revoked by that value.
    let old = storage
        .get_token_by_refresh_token("warm-refresh")
        .await
        .unwrap()
        .unwrap();
    assert!(at_rest::is_bearer_verifier(&old.access_token));
    actor
        .send(RevokeToken {
            token: old.access_token.clone(),
            span: tracing::Span::none(),
        })
        .await
        .unwrap()
        .unwrap();

    // Immediately invalid, not after cache TTL.
    let res = actor.send(validate("warm-access")).await.unwrap();
    assert!(res.map(|t| t.revoked).unwrap_or(true));
}

/// A stored verifier (`h1$…`) must never be accepted as a bearer, even when
/// the legitimate raw token has warmed the L1/L2 cache. Read/insert keys hash
/// unconditionally; only eviction maps a verifier back to the raw token's key.
#[actix_web::test]
async fn stored_verifier_is_not_accepted_as_bearer_when_cache_is_warm() {
    use actix::Actor;
    use oauth2_actix::actors::token_actor::{TokenActor, ValidateToken};

    let (storage, _raw, _d) = setup().await;
    storage.save_client(&client("c1", "s")).await.unwrap();
    let t = Token::new(
        "verifier-access".to_string(),
        Some("verifier-refresh".to_string()),
        "c1".to_string(),
        None,
        "read".to_string(),
        3600,
        None,
    );
    storage.save_token(&t).await.unwrap();
    let actor = TokenActor::new(
        storage.clone(),
        "synthetic-jwt-secret".into(),
        "http://localhost".into(),
    )
    .start();

    let validate = |raw: &str| ValidateToken {
        token: raw.to_string(),
        span: tracing::Span::none(),
    };

    // Read the verifier the way the database stores it.
    let stored = storage
        .get_token_by_refresh_token("verifier-refresh")
        .await
        .unwrap()
        .unwrap();
    let verifier = stored.access_token.clone();
    assert!(at_rest::is_bearer_verifier(&verifier));
    assert_ne!(verifier, "verifier-access");

    // Cold: the verifier is not a credential.
    assert!(actor.send(validate(&verifier)).await.unwrap().is_err());

    // Warm both caches with the legitimate raw token.
    assert!(actor
        .send(validate("verifier-access"))
        .await
        .unwrap()
        .is_ok());
    // Let the cache-insert message (sent back to the actor) land.
    let _ = actor.send(validate("verifier-access")).await.unwrap();

    // Warm: presenting the stored verifier must still fail.
    let res = actor.send(validate(&verifier)).await.unwrap();
    assert!(
        res.is_err(),
        "stored verifier was accepted as a bearer while the cache was warm"
    );
}

#[actix_web::test]
async fn legacy_client_secret_and_marker_stay_rejected_after_cache_warming() {
    use actix::Actor;
    use oauth2_actix::actors::{ClientActor, GetClient, ValidateClient};

    let (storage, raw, _d) = setup().await;
    storage.save_client(&client("c-warm", "x")).await.unwrap();
    storage.save_client(&client("c-mark", "x")).await.unwrap();
    sqlx::query("UPDATE clients SET client_secret = 'legacy-plain' WHERE client_id = 'c-warm'")
        .execute(&raw)
        .await
        .unwrap();
    sqlx::query(
        "UPDATE clients SET client_secret = 'legacy-invalidated' WHERE client_id = 'c-mark'",
    )
    .execute(&raw)
    .await
    .unwrap();

    let actor = ClientActor::new(storage).start();
    for (id, presented) in [("c-warm", "legacy-plain"), ("c-mark", "legacy-invalidated")] {
        // Run twice so the second pass is served from the warm cache.
        for _ in 0..2 {
            let fetched = actor
                .send(GetClient {
                    client_id: id.to_string(),
                    span: tracing::Span::none(),
                })
                .await
                .unwrap()
                .unwrap();
            assert!(!fetched.verify_secret(presented), "{id} verifies via cache");
            let valid = actor
                .send(ValidateClient {
                    client_id: id.to_string(),
                    client_secret: presented.to_string(),
                    span: tracing::Span::none(),
                })
                .await
                .unwrap();
            assert!(!matches!(valid, Ok(true)), "{id} accepted after warming");
        }
    }
}

#[test]
fn cutover_marker_is_never_sealed_into_a_secret() {
    let m = at_rest::LEGACY_INVALIDATED_MARKER;
    assert_eq!(at_rest::protect_client_secret(m), m);
    assert!(!at_rest::verify_client_secret(m, m));
}
