//! Phase 7 (agent / A2A OAuth) Task 12: identity chaining / ID-JAG issuing.
//!
//! draft-ietf-oauth-identity-chaining-17 and
//! draft-ietf-oauth-identity-assertion-authz-grant-04 (issuing side).
//!
//! The authorization server mints a short-lived *authorization grant* — not an
//! access token — that the client presents to a second authorization server.
//! It is signed like our other JWTs but carries `typ: "oauth-id-jag+jwt"`, is
//! never persisted, and is delivered with `token_type: "N_A"`.

use std::sync::OnceLock;

use actix::{Actor, Addr};
use actix_web::{test, web, App};
use base64::{engine::general_purpose, Engine as _};
use jsonwebtoken::{
    decode, decode_header, encode, Algorithm, DecodingKey, EncodingKey, Header as JwtHeader,
    Validation,
};
use serde_json::{json, Value};

use oauth2_actix::actors::{CreateToken, TokenActor, TokenActorPool};
use oauth2_actix::handlers::wellknown::OidcConfig;
use oauth2_config::{AgentConfig, Config};
use oauth2_core::models::key_set::{Algorithm as KeyAlgorithm, KeySet, SigningKey};
use oauth2_core::{Client, IdTokenClaims, Token, User};
use oauth2_observability::Metrics;
use oauth2_ports::DynStorage;
use rsa::pkcs1::{DecodeRsaPrivateKey, EncodeRsaPrivateKey, EncodeRsaPublicKey};
use rsa::traits::PublicKeyParts;
use rsa::{RsaPrivateKey, RsaPublicKey};

const TOKEN_EXCHANGE: &str = "urn:ietf:params:oauth:grant-type:token-exchange";
const ACCESS_TOKEN: &str = "urn:ietf:params:oauth:token-type:access_token";
const REFRESH_TOKEN: &str = "urn:ietf:params:oauth:token-type:refresh_token";
const ID_TOKEN: &str = "urn:ietf:params:oauth:token-type:id_token";
const JWT: &str = "urn:ietf:params:oauth:token-type:jwt";
const ID_JAG: &str = "urn:ietf:params:oauth:token-type:id-jag";
const ISSUER: &str = "http://localhost";
const JWT_SECRET: &str = "test_jwt_secret";
const HOST: &str = "auth.test";
const TARGET: &str = "https://as-b.example";

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

async fn storage() -> DynStorage {
    let storage = oauth2_storage_factory::create_storage("sqlite::memory:")
        .await
        .expect("create storage");
    storage.init().await.expect("init storage");
    storage
}

fn client(client_id: &str, grants: &[&str]) -> Client {
    Client::new(
        client_id.to_string(),
        format!("{client_id}_secret"),
        vec!["https://unused.example/cb".to_string()],
        grants.iter().map(|g| g.to_string()).collect(),
        "read write".to_string(),
        format!("{client_id} test client"),
    )
}

async fn save_user(storage: &DynStorage, id: &str) {
    let now = chrono::Utc::now();
    storage
        .save_user(&User {
            id: id.to_string(),
            username: id.to_string(),
            password_hash: "not_used".to_string(),
            email: format!("{id}@example.test"),
            enabled: true,
            role: "user".to_string(),
            created_at: now,
            updated_at: now,
        })
        .await
        .expect("save user");
}

fn fixture_actor(storage: &DynStorage) -> Addr<TokenActor> {
    TokenActor::new(storage.clone(), JWT_SECRET.to_string(), ISSUER.to_string()).start()
}

async fn mint(
    storage: &DynStorage,
    user_id: Option<&str>,
    client_id: &str,
    scope: &str,
    include_refresh: bool,
    authorization_details: Option<Value>,
) -> Token {
    fixture_actor(storage)
        .send(CreateToken {
            user_id: user_id.map(|u| u.to_string()),
            client_id: client_id.to_string(),
            scope: scope.to_string(),
            include_refresh,
            token_family: None,
            resources: Vec::new(),
            cnf: None,
            authorization_details,
            act: None,
            ttl_override_secs: None,
            sub_profile: None,
            span: tracing::Span::current(),
        })
        .await
        .expect("send CreateToken")
        .expect("create token")
}

/// Config with ID-JAG on and a single registered chaining target.
fn id_jag_config() -> AgentConfig {
    AgentConfig {
        id_jag_enabled: true,
        chaining_targets: vec![TARGET.to_string()],
        ..Default::default()
    }
}

macro_rules! oauth_app {
    ($storage:expr, $agent_config:expr) => {{
        let storage: DynStorage = $storage.clone();
        let jwt_secret = JWT_SECRET.to_string();
        let metrics = Metrics::new().expect("metrics");
        let token_pool = TokenActorPool::new(vec![TokenActor::new(
            storage.clone(),
            jwt_secret.clone(),
            ISSUER.to_string(),
        )
        .start()]);
        let client_actor = oauth2_actix::actors::ClientActor::new(storage.clone()).start();
        let auth_actor = oauth2_actix::actors::AuthActor::new(storage.clone()).start();
        let oidc_config = OidcConfig {
            issuer: ISSUER.to_string(),
            jwt_secret: jwt_secret.clone(),
            id_token_alg: "HS256".to_string(),
            id_token_kid: None,
            id_token_private_key_pem: None,
        };
        let mut config = Config::default();
        config.jwt.public_introspection = true;

        test::init_service(
            App::new()
                .app_data(web::Data::new(token_pool))
                .app_data(web::Data::new(client_actor))
                .app_data(web::Data::new(auth_actor))
                .app_data(web::Data::new(storage))
                .app_data(web::Data::new(jwt_secret))
                .app_data(web::Data::new(metrics))
                .app_data(web::Data::new(oidc_config))
                .app_data(web::Data::new(false)) // stateless_validation
                .app_data(web::Data::new(config))
                .app_data(web::Data::new($agent_config))
                .service(web::scope("/oauth").route(
                    "/token",
                    web::post().to(oauth2_actix::handlers::oauth::token),
                )),
        )
        .await
    }};
}

fn basic(client_id: &str) -> String {
    format!(
        "Basic {}",
        general_purpose::STANDARD.encode(format!("{client_id}:{client_id}_secret"))
    )
}

fn enc(value: &str) -> String {
    let mut out = String::with_capacity(value.len() * 3);
    for b in value.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

fn form(pairs: &[(&str, &str)]) -> String {
    pairs
        .iter()
        .map(|(k, v)| format!("{}={}", enc(k), enc(v)))
        .collect::<Vec<_>>()
        .join("&")
}

macro_rules! post_token {
    ($app:expr, $client_id:expr, $pairs:expr) => {{
        let req = test::TestRequest::post()
            .uri("/oauth/token")
            .insert_header(("Host", HOST))
            .insert_header(("Authorization", basic($client_id)))
            .insert_header(("Content-Type", "application/x-www-form-urlencoded"))
            .set_payload(form($pairs))
            .to_request();
        test::call_service(&$app, req).await
    }};
}

/// Decode an issued ID-JAG: header (for `typ` / `alg` / `kid`) plus the raw
/// claim set, verified against the HS256 fallback key.
fn decode_id_jag(token: &str) -> (JwtHeader, Value) {
    let header = decode_header(token).expect("decode id-jag header");
    let mut validation = Validation::new(Algorithm::HS256);
    validation.validate_aud = false;
    let data = decode::<Value>(
        token,
        &DecodingKey::from_secret(JWT_SECRET.as_bytes()),
        &validation,
    )
    .expect("id-jag must verify with the HS256 signing key");
    (header, data.claims)
}

// ---------------------------------------------------------------------------
// 1. Feature flag and audience validation
// ---------------------------------------------------------------------------

#[actix_web::test]
async fn id_jag_request_with_the_flag_off_is_invalid_request() {
    let storage = storage().await;
    storage
        .save_client(&client("tx_client", &[TOKEN_EXCHANGE]))
        .await
        .expect("save client");
    save_user(&storage, "alice").await;
    let subject = mint(&storage, Some("alice"), "tx_client", "read", false, None).await;

    // Targets configured, issuance disabled.
    let config = AgentConfig {
        id_jag_enabled: false,
        chaining_targets: vec![TARGET.to_string()],
        ..Default::default()
    };
    let app = oauth_app!(storage, config);
    let resp = post_token!(
        app,
        "tx_client",
        &[
            ("grant_type", TOKEN_EXCHANGE),
            ("subject_token", subject.access_token.as_str()),
            ("subject_token_type", ACCESS_TOKEN),
            ("requested_token_type", ID_JAG),
            ("audience", TARGET),
        ]
    );

    assert_eq!(resp.status(), 400);
    let body: Value = test::read_body_json(resp).await;
    assert_eq!(body["error"], "invalid_request", "body: {body}");
}

#[actix_web::test]
async fn audience_outside_the_chaining_targets_is_invalid_target() {
    let storage = storage().await;
    storage
        .save_client(&client("tx_client", &[TOKEN_EXCHANGE]))
        .await
        .expect("save client");
    save_user(&storage, "alice").await;
    let subject = mint(&storage, Some("alice"), "tx_client", "read", false, None).await;

    let app = oauth_app!(storage, id_jag_config());
    let resp = post_token!(
        app,
        "tx_client",
        &[
            ("grant_type", TOKEN_EXCHANGE),
            ("subject_token", subject.access_token.as_str()),
            ("subject_token_type", ACCESS_TOKEN),
            ("requested_token_type", ID_JAG),
            ("audience", "https://not-a-target.example"),
        ]
    );

    assert_eq!(resp.status(), 400);
    let body: Value = test::read_body_json(resp).await;
    assert_eq!(body["error"], "invalid_target", "body: {body}");
}

#[actix_web::test]
async fn id_jag_without_an_audience_is_invalid_request() {
    let storage = storage().await;
    storage
        .save_client(&client("tx_client", &[TOKEN_EXCHANGE]))
        .await
        .expect("save client");
    save_user(&storage, "alice").await;
    let subject = mint(&storage, Some("alice"), "tx_client", "read", false, None).await;

    let app = oauth_app!(storage, id_jag_config());
    let resp = post_token!(
        app,
        "tx_client",
        &[
            ("grant_type", TOKEN_EXCHANGE),
            ("subject_token", subject.access_token.as_str()),
            ("subject_token_type", ACCESS_TOKEN),
            ("requested_token_type", ID_JAG),
        ]
    );

    assert_eq!(resp.status(), 400);
    let body: Value = test::read_body_json(resp).await;
    assert_eq!(body["error"], "invalid_request", "body: {body}");
}

#[actix_web::test]
async fn more_than_one_audience_is_invalid_request() {
    let storage = storage().await;
    storage
        .save_client(&client("tx_client", &[TOKEN_EXCHANGE]))
        .await
        .expect("save client");
    save_user(&storage, "alice").await;
    let subject = mint(&storage, Some("alice"), "tx_client", "read", false, None).await;

    let config = AgentConfig {
        id_jag_enabled: true,
        chaining_targets: vec![TARGET.to_string(), "https://as-c.example".to_string()],
        ..Default::default()
    };
    let app = oauth_app!(storage, config);
    let resp = post_token!(
        app,
        "tx_client",
        &[
            ("grant_type", TOKEN_EXCHANGE),
            ("subject_token", subject.access_token.as_str()),
            ("subject_token_type", ACCESS_TOKEN),
            ("requested_token_type", ID_JAG),
            ("audience", TARGET),
            ("audience", "https://as-c.example"),
        ]
    );

    assert_eq!(resp.status(), 400);
    let body: Value = test::read_body_json(resp).await;
    assert_eq!(body["error"], "invalid_request", "body: {body}");
}

// ---------------------------------------------------------------------------
// 2. Happy path
// ---------------------------------------------------------------------------

#[actix_web::test]
async fn id_jag_is_minted_with_the_expected_header_and_claims() {
    let storage = storage().await;
    storage
        .save_client(&client("tx_client", &[TOKEN_EXCHANGE]))
        .await
        .expect("save client");
    save_user(&storage, "alice").await;
    let subject = mint(
        &storage,
        Some("alice"),
        "tx_client",
        "read write",
        false,
        None,
    )
    .await;

    let app = oauth_app!(storage, id_jag_config());
    let resp = post_token!(
        app,
        "tx_client",
        &[
            ("grant_type", TOKEN_EXCHANGE),
            ("subject_token", subject.access_token.as_str()),
            ("subject_token_type", ACCESS_TOKEN),
            ("requested_token_type", ID_JAG),
            ("audience", TARGET),
            ("scope", "read"),
        ]
    );

    assert_eq!(resp.status(), 200);
    let body: Value = test::read_body_json(resp).await;
    assert_eq!(body["issued_token_type"], ID_JAG, "body: {body}");
    assert_eq!(
        body["token_type"], "N_A",
        "an authorization grant is not a usable token: {body}"
    );
    assert_eq!(body["scope"], "read", "body: {body}");
    let expires_in = body["expires_in"].as_i64().expect("expires_in");
    assert!(
        expires_in > 0 && expires_in <= 300,
        "ID-JAG lifetime is capped at 300s, got {expires_in}"
    );

    let issued = body["access_token"].as_str().expect("access_token");
    let (header, claims) = decode_id_jag(issued);
    assert_eq!(header.typ.as_deref(), Some("oauth-id-jag+jwt"));
    assert_eq!(claims["iss"], ISSUER, "claims: {claims}");
    assert_eq!(claims["sub"], "alice", "claims: {claims}");
    assert_eq!(claims["aud"], TARGET, "claims: {claims}");
    assert_eq!(claims["client_id"], "tx_client", "claims: {claims}");
    assert_eq!(claims["scope"], "read", "claims: {claims}");
    assert_eq!(claims["email"], "alice@example.test", "claims: {claims}");
    assert!(
        claims["jti"].as_str().is_some_and(|j| !j.is_empty()),
        "claims: {claims}"
    );
    let now = chrono::Utc::now().timestamp();
    let exp = claims["exp"].as_i64().expect("exp");
    assert!(exp > now && exp <= now + 300, "claims: {claims}");
    assert!(claims["iat"].as_i64().is_some(), "claims: {claims}");
    assert!(
        claims.get("cnf").is_none(),
        "no DPoP proof was presented: {claims}"
    );
    assert!(
        claims.get("act").is_none(),
        "no actor token was presented: {claims}"
    );
}

/// The grant is an assertion, not an access token: nothing is persisted, so
/// the issued JWT is not resolvable as one of our tokens.
#[actix_web::test]
async fn id_jag_is_never_persisted_as_an_access_token() {
    let storage = storage().await;
    storage
        .save_client(&client("tx_client", &[TOKEN_EXCHANGE]))
        .await
        .expect("save client");
    save_user(&storage, "alice").await;
    let subject = mint(&storage, Some("alice"), "tx_client", "read", false, None).await;

    let app = oauth_app!(storage, id_jag_config());
    let resp = post_token!(
        app,
        "tx_client",
        &[
            ("grant_type", TOKEN_EXCHANGE),
            ("subject_token", subject.access_token.as_str()),
            ("subject_token_type", ACCESS_TOKEN),
            ("requested_token_type", ID_JAG),
            ("audience", TARGET),
        ]
    );
    assert_eq!(resp.status(), 200);
    let body: Value = test::read_body_json(resp).await;
    let issued = body["access_token"].as_str().expect("access_token");

    assert!(
        storage
            .get_token_by_access_token(issued)
            .await
            .expect("lookup")
            .is_none(),
        "the ID-JAG must not be stored as an access token"
    );
}

/// Identity chaining (draft-ietf-oauth-identity-chaining): the same assertion
/// is requested with `requested_token_type=...:jwt` plus a target audience,
/// and is echoed back as `...:jwt`.
#[actix_web::test]
async fn jwt_requested_type_with_a_chaining_target_issues_the_assertion() {
    let storage = storage().await;
    storage
        .save_client(&client("tx_client", &[TOKEN_EXCHANGE]))
        .await
        .expect("save client");
    save_user(&storage, "alice").await;
    let subject = mint(&storage, Some("alice"), "tx_client", "read", false, None).await;

    let app = oauth_app!(storage, id_jag_config());
    let resp = post_token!(
        app,
        "tx_client",
        &[
            ("grant_type", TOKEN_EXCHANGE),
            ("subject_token", subject.access_token.as_str()),
            ("subject_token_type", ACCESS_TOKEN),
            ("requested_token_type", JWT),
            ("audience", TARGET),
        ]
    );

    assert_eq!(resp.status(), 200);
    let body: Value = test::read_body_json(resp).await;
    assert_eq!(body["issued_token_type"], JWT, "body: {body}");
    assert_eq!(body["token_type"], "N_A", "body: {body}");

    let (header, claims) = decode_id_jag(body["access_token"].as_str().expect("access_token"));
    assert_eq!(header.typ.as_deref(), Some("oauth-id-jag+jwt"));
    assert_eq!(claims["aud"], TARGET, "claims: {claims}");
}

/// A plain `...:jwt` exchange with no chaining target still mints a normal
/// bearer access token — the chaining trigger must not swallow it.
#[actix_web::test]
async fn jwt_requested_type_without_a_chaining_target_still_mints_an_access_token() {
    let storage = storage().await;
    storage
        .save_client(&client("tx_client", &[TOKEN_EXCHANGE]))
        .await
        .expect("save client");
    save_user(&storage, "alice").await;
    let subject = mint(&storage, Some("alice"), "tx_client", "read", false, None).await;

    let app = oauth_app!(storage, id_jag_config());
    let resp = post_token!(
        app,
        "tx_client",
        &[
            ("grant_type", TOKEN_EXCHANGE),
            ("subject_token", subject.access_token.as_str()),
            ("subject_token_type", ACCESS_TOKEN),
            ("requested_token_type", JWT),
        ]
    );

    assert_eq!(resp.status(), 200);
    let body: Value = test::read_body_json(resp).await;
    assert_eq!(body["issued_token_type"], JWT, "body: {body}");
    assert_eq!(body["token_type"], "Bearer", "body: {body}");
}

// ---------------------------------------------------------------------------
// 3. Subject token types
// ---------------------------------------------------------------------------

#[actix_web::test]
async fn id_token_subject_carries_auth_time_and_acr_into_the_assertion() {
    let storage = storage().await;
    storage
        .save_client(&client("tx_client", &[TOKEN_EXCHANGE]))
        .await
        .expect("save client");
    save_user(&storage, "alice").await;

    let mut id_claims = IdTokenClaims::new(
        ISSUER,
        "alice".to_string(),
        "tx_client".to_string(),
        3600,
        None,
    );
    id_claims.acr = Some("urn:mace:incommon:iap:silver".to_string());
    id_claims.auth_time = Some(chrono::Utc::now().timestamp() - 30);
    id_claims.email = Some("alice@example.test".to_string());
    let subject = id_claims.encode(JWT_SECRET).expect("encode id_token");

    let app = oauth_app!(storage, id_jag_config());
    let resp = post_token!(
        app,
        "tx_client",
        &[
            ("grant_type", TOKEN_EXCHANGE),
            ("subject_token", subject.as_str()),
            ("subject_token_type", ID_TOKEN),
            ("requested_token_type", ID_JAG),
            ("audience", TARGET),
            ("scope", "read"),
        ]
    );

    assert_eq!(resp.status(), 200);
    let body: Value = test::read_body_json(resp).await;
    let (_, claims) = decode_id_jag(body["access_token"].as_str().expect("access_token"));
    assert_eq!(claims["sub"], "alice", "claims: {claims}");
    assert_eq!(
        claims["acr"], "urn:mace:incommon:iap:silver",
        "claims: {claims}"
    );
    assert_eq!(
        claims["auth_time"].as_i64(),
        id_claims.auth_time,
        "claims: {claims}"
    );
}

/// RFC 8693 §3 lists `refresh_token` as a subject token type. This server
/// accepts it only on the ID-JAG path.
#[actix_web::test]
async fn refresh_token_subject_is_accepted_for_id_jag() {
    let storage = storage().await;
    storage
        .save_client(&client("tx_client", &[TOKEN_EXCHANGE]))
        .await
        .expect("save client");
    save_user(&storage, "alice").await;
    let pair = mint(&storage, Some("alice"), "tx_client", "read", true, None).await;
    let refresh = pair.refresh_token.expect("refresh token");

    let app = oauth_app!(storage, id_jag_config());
    let resp = post_token!(
        app,
        "tx_client",
        &[
            ("grant_type", TOKEN_EXCHANGE),
            ("subject_token", refresh.as_str()),
            ("subject_token_type", REFRESH_TOKEN),
            ("requested_token_type", ID_JAG),
            ("audience", TARGET),
        ]
    );

    assert_eq!(resp.status(), 200);
    let body: Value = test::read_body_json(resp).await;
    let (_, claims) = decode_id_jag(body["access_token"].as_str().expect("access_token"));
    assert_eq!(claims["sub"], "alice", "claims: {claims}");
    assert_eq!(claims["aud"], TARGET, "claims: {claims}");
}

/// The same refresh token is still refused for a plain access-token exchange.
#[actix_web::test]
async fn refresh_token_subject_is_still_rejected_for_a_plain_exchange() {
    let storage = storage().await;
    storage
        .save_client(&client("tx_client", &[TOKEN_EXCHANGE]))
        .await
        .expect("save client");
    save_user(&storage, "alice").await;
    let pair = mint(&storage, Some("alice"), "tx_client", "read", true, None).await;
    let refresh = pair.refresh_token.expect("refresh token");

    let app = oauth_app!(storage, id_jag_config());
    let resp = post_token!(
        app,
        "tx_client",
        &[
            ("grant_type", TOKEN_EXCHANGE),
            ("subject_token", refresh.as_str()),
            ("subject_token_type", REFRESH_TOKEN),
        ]
    );

    assert_eq!(resp.status(), 400);
    let body: Value = test::read_body_json(resp).await;
    assert_eq!(body["error"], "invalid_request", "body: {body}");
}

/// A revoked refresh token must not be exchangeable for an assertion.
#[actix_web::test]
async fn revoked_refresh_token_subject_is_invalid_grant() {
    let storage = storage().await;
    storage
        .save_client(&client("tx_client", &[TOKEN_EXCHANGE]))
        .await
        .expect("save client");
    save_user(&storage, "alice").await;
    let pair = mint(&storage, Some("alice"), "tx_client", "read", true, None).await;
    let refresh = pair.refresh_token.clone().expect("refresh token");
    storage
        .revoke_token(&pair.access_token)
        .await
        .expect("revoke");

    let app = oauth_app!(storage, id_jag_config());
    let resp = post_token!(
        app,
        "tx_client",
        &[
            ("grant_type", TOKEN_EXCHANGE),
            ("subject_token", refresh.as_str()),
            ("subject_token_type", REFRESH_TOKEN),
            ("requested_token_type", ID_JAG),
            ("audience", TARGET),
        ]
    );

    assert_eq!(resp.status(), 400);
    let body: Value = test::read_body_json(resp).await;
    assert_eq!(body["error"], "invalid_grant", "body: {body}");
}

/// A refresh token issued to a different client cannot be used here.
#[actix_web::test]
async fn refresh_token_from_another_client_is_invalid_grant() {
    let storage = storage().await;
    storage
        .save_client(&client("tx_client", &[TOKEN_EXCHANGE]))
        .await
        .expect("save client");
    storage
        .save_client(&client("other_client", &["client_credentials"]))
        .await
        .expect("save other client");
    save_user(&storage, "alice").await;
    let pair = mint(&storage, Some("alice"), "other_client", "read", true, None).await;
    let refresh = pair.refresh_token.expect("refresh token");

    let app = oauth_app!(storage, id_jag_config());
    let resp = post_token!(
        app,
        "tx_client",
        &[
            ("grant_type", TOKEN_EXCHANGE),
            ("subject_token", refresh.as_str()),
            ("subject_token_type", REFRESH_TOKEN),
            ("requested_token_type", ID_JAG),
            ("audience", TARGET),
        ]
    );

    assert_eq!(resp.status(), 400);
    let body: Value = test::read_body_json(resp).await;
    assert_eq!(body["error"], "invalid_grant", "body: {body}");
}

// ---------------------------------------------------------------------------
// 4. Delegation (`act`) and RAR
// ---------------------------------------------------------------------------

#[actix_web::test]
async fn actor_token_is_recorded_in_the_act_claim() {
    let storage = storage().await;
    storage
        .save_client(&client("agent_client", &[TOKEN_EXCHANGE]))
        .await
        .expect("save agent client");
    let mut subject_client = client("sub_client", &["client_credentials"]);
    subject_client.allowed_actors = json!(["agent_client"]).to_string();
    storage
        .save_client(&subject_client)
        .await
        .expect("save subject client");
    save_user(&storage, "alice").await;

    let subject = mint(&storage, Some("alice"), "sub_client", "read", false, None).await;
    let actor = mint(&storage, None, "agent_client", "read", false, None).await;

    let app = oauth_app!(storage, id_jag_config());
    let resp = post_token!(
        app,
        "agent_client",
        &[
            ("grant_type", TOKEN_EXCHANGE),
            ("subject_token", subject.access_token.as_str()),
            ("subject_token_type", ACCESS_TOKEN),
            ("actor_token", actor.access_token.as_str()),
            ("actor_token_type", ACCESS_TOKEN),
            ("requested_token_type", ID_JAG),
            ("audience", TARGET),
        ]
    );

    assert_eq!(resp.status(), 200);
    let body: Value = test::read_body_json(resp).await;
    let (_, claims) = decode_id_jag(body["access_token"].as_str().expect("access_token"));
    assert_eq!(claims["act"]["sub"], "agent_client", "claims: {claims}");
    assert_eq!(claims["act"]["iss"], ISSUER, "claims: {claims}");
    assert_eq!(claims["act"]["sub_profile"], "service", "claims: {claims}");
    assert_eq!(claims["client_id"], "agent_client", "claims: {claims}");
}

#[actix_web::test]
async fn authorization_details_are_carried_into_the_assertion() {
    let storage = storage().await;
    storage
        .save_client(&client("tx_client", &[TOKEN_EXCHANGE]))
        .await
        .expect("save client");
    save_user(&storage, "alice").await;
    let rar = json!([{ "type": "payment", "amount": "10.00" }]);
    let subject = mint(
        &storage,
        Some("alice"),
        "tx_client",
        "read",
        false,
        Some(rar.clone()),
    )
    .await;

    let app = oauth_app!(storage, id_jag_config());
    let resp = post_token!(
        app,
        "tx_client",
        &[
            ("grant_type", TOKEN_EXCHANGE),
            ("subject_token", subject.access_token.as_str()),
            ("subject_token_type", ACCESS_TOKEN),
            ("requested_token_type", ID_JAG),
            ("audience", TARGET),
        ]
    );

    assert_eq!(resp.status(), 200);
    let body: Value = test::read_body_json(resp).await;
    assert_eq!(body["authorization_details"], rar, "body: {body}");
    let (_, claims) = decode_id_jag(body["access_token"].as_str().expect("access_token"));
    assert_eq!(claims["authorization_details"], rar, "claims: {claims}");
}

// ---------------------------------------------------------------------------
// 5. DPoP binding (RFC 9449)
// ---------------------------------------------------------------------------

fn signer() -> &'static (String, Value) {
    static SIGNER: OnceLock<(String, Value)> = OnceLock::new();
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

fn dpop_proof(htm: &str, htu: &str, jti: &str) -> String {
    let (pem, jwk) = signer();
    let mut header = JwtHeader::new(Algorithm::RS256);
    header.typ = Some("dpop+jwt".to_string());
    header.jwk = Some(serde_json::from_value(jwk.clone()).expect("jwk header"));

    let claims = json!({
        "htm": htm,
        "htu": htu,
        "iat": chrono::Utc::now().timestamp(),
        "jti": jti,
    });
    let key = EncodingKey::from_rsa_pem(pem.as_bytes()).expect("encoding key");
    encode(&header, &claims, &key).expect("sign DPoP proof")
}

#[actix_web::test]
async fn dpop_proof_binds_the_assertion_with_a_cnf_jkt() {
    let storage = storage().await;
    storage
        .save_client(&client("tx_client", &[TOKEN_EXCHANGE]))
        .await
        .expect("save client");
    save_user(&storage, "alice").await;
    let subject = mint(&storage, Some("alice"), "tx_client", "read", false, None).await;

    let app = oauth_app!(storage, id_jag_config());
    let proof = dpop_proof(
        "POST",
        &format!("http://{HOST}/oauth/token"),
        "id-jag-dpop-1",
    );
    let req = test::TestRequest::post()
        .uri("/oauth/token")
        .insert_header(("Host", HOST))
        .insert_header(("Authorization", basic("tx_client")))
        .insert_header(("Content-Type", "application/x-www-form-urlencoded"))
        .insert_header(("DPoP", proof))
        .set_payload(form(&[
            ("grant_type", TOKEN_EXCHANGE),
            ("subject_token", subject.access_token.as_str()),
            ("subject_token_type", ACCESS_TOKEN),
            ("requested_token_type", ID_JAG),
            ("audience", TARGET),
        ]))
        .to_request();
    let resp = test::call_service(&app, req).await;

    assert_eq!(resp.status(), 200);
    let body: Value = test::read_body_json(resp).await;
    assert_eq!(
        body["token_type"], "N_A",
        "an assertion is never delivered as a DPoP token: {body}"
    );
    let (_, claims) = decode_id_jag(body["access_token"].as_str().expect("access_token"));
    assert!(
        claims["cnf"]["jkt"].as_str().is_some_and(|j| !j.is_empty()),
        "claims: {claims}"
    );
}

// ---------------------------------------------------------------------------
// 6. Signing key selection
// ---------------------------------------------------------------------------

/// With a keyset configured the assertion is signed by the current RS256 key
/// so the downstream authorization server can verify it from our JWKS.
#[actix_web::test]
async fn a_configured_rs256_keyset_signs_the_assertion() {
    let storage = storage().await;
    storage
        .save_client(&client("tx_client", &[TOKEN_EXCHANGE]))
        .await
        .expect("save client");
    save_user(&storage, "alice").await;
    let subject = mint(&storage, Some("alice"), "tx_client", "read", false, None).await;

    let (private_pem, _) = signer();
    let public_pem =
        RsaPublicKey::from(&RsaPrivateKey::from_pkcs1_pem(private_pem).expect("parse private key"))
            .to_pkcs1_pem(rsa::pkcs1::LineEnding::LF)
            .expect("encode public key");
    let keyset = std::sync::Arc::new(tokio::sync::RwLock::new(KeySet::from_keys(vec![
        SigningKey {
            kid: "id-jag-rs256".to_string(),
            algorithm: KeyAlgorithm::RS256,
            key_material: private_pem.as_bytes().to_vec(),
            is_current: true,
            created_at: chrono::Utc::now(),
            expires_at: None,
        },
    ])));

    let jwt_secret = JWT_SECRET.to_string();
    let metrics = Metrics::new().expect("metrics");
    let token_pool = TokenActorPool::new(vec![TokenActor::new(
        storage.clone(),
        jwt_secret.clone(),
        ISSUER.to_string(),
    )
    .start()]);
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(token_pool))
            .app_data(web::Data::new(
                oauth2_actix::actors::ClientActor::new(storage.clone()).start(),
            ))
            .app_data(web::Data::new(
                oauth2_actix::actors::AuthActor::new(storage.clone()).start(),
            ))
            .app_data(web::Data::new(storage.clone()))
            .app_data(web::Data::new(jwt_secret.clone()))
            .app_data(web::Data::new(metrics))
            .app_data(web::Data::new(OidcConfig {
                issuer: ISSUER.to_string(),
                jwt_secret,
                id_token_alg: "HS256".to_string(),
                id_token_kid: None,
                id_token_private_key_pem: None,
            }))
            .app_data(web::Data::new(false))
            .app_data(web::Data::new(Config::default()))
            .app_data(web::Data::new(id_jag_config()))
            .app_data(web::Data::new(keyset))
            .service(web::scope("/oauth").route(
                "/token",
                web::post().to(oauth2_actix::handlers::oauth::token),
            )),
    )
    .await;

    let resp = post_token!(
        app,
        "tx_client",
        &[
            ("grant_type", TOKEN_EXCHANGE),
            ("subject_token", subject.access_token.as_str()),
            ("subject_token_type", ACCESS_TOKEN),
            ("requested_token_type", ID_JAG),
            ("audience", TARGET),
        ]
    );

    assert_eq!(resp.status(), 200);
    let body: Value = test::read_body_json(resp).await;
    let issued = body["access_token"].as_str().expect("access_token");

    let header = decode_header(issued).expect("header");
    assert_eq!(header.typ.as_deref(), Some("oauth-id-jag+jwt"));
    assert_eq!(header.alg, Algorithm::RS256);
    assert_eq!(header.kid.as_deref(), Some("id-jag-rs256"));

    let mut validation = Validation::new(Algorithm::RS256);
    validation.validate_aud = false;
    let claims = decode::<Value>(
        issued,
        &DecodingKey::from_rsa_pem(public_pem.as_bytes()).expect("decoding key"),
        &validation,
    )
    .expect("assertion must verify with the RS256 public key")
    .claims;
    assert_eq!(claims["aud"], TARGET, "claims: {claims}");
}
