//! Phase 7 (agent / A2A OAuth) Task 9: RFC 8693 token exchange with actor
//! delegation chains.
//!
//! Exercises the rewritten token-exchange grant end-to-end through the token
//! endpoint: subject/actor token typing, delegation authorisation (`may_act`
//! and `allowed_actors`), `act` chain construction and depth limiting,
//! resource/audience narrowing (RFC 8707 + RFC 8693 §2.1 `audience`), RAR
//! subsetting (RFC 9396) and DPoP rebinding (RFC 9449).

use std::sync::OnceLock;

use actix::{Actor, Addr};
use actix_web::{test, web, App};
use base64::{engine::general_purpose, Engine as _};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header as JwtHeader};
use serde_json::{json, Value};

use oauth2_actix::actors::{CreateToken, TokenActor, TokenActorPool};
use oauth2_actix::handlers::dpop::compute_ath;
use oauth2_actix::handlers::wellknown::OidcConfig;
use oauth2_config::{AgentConfig, Config};
use oauth2_core::{Claims, Client, ProtectedResource, Token, User};
use oauth2_observability::Metrics;
use oauth2_ports::DynStorage;
use rsa::pkcs1::EncodeRsaPrivateKey;
use rsa::traits::PublicKeyParts;
use rsa::{RsaPrivateKey, RsaPublicKey};

const TOKEN_EXCHANGE: &str = "urn:ietf:params:oauth:grant-type:token-exchange";
const ACCESS_TOKEN: &str = "urn:ietf:params:oauth:token-type:access_token";
const ISSUER: &str = "http://localhost";
const JWT_SECRET: &str = "test_jwt_secret";
const HOST: &str = "auth.test";

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

/// Mint a token through the real `CreateToken` path so it is both persisted
/// and (in JWT mode) carries the matching claims.
#[allow(clippy::too_many_arguments)]
async fn mint(
    storage: &DynStorage,
    user_id: Option<&str>,
    client_id: &str,
    scope: &str,
    resources: Vec<String>,
    authorization_details: Option<Value>,
) -> Token {
    fixture_actor(storage)
        .send(CreateToken {
            user_id: user_id.map(|u| u.to_string()),
            client_id: client_id.to_string(),
            scope: scope.to_string(),
            include_refresh: false,
            token_family: None,
            resources,
            cnf: None,
            authorization_details,
            act: None,
            span: tracing::Span::current(),
        })
        .await
        .expect("send CreateToken")
        .expect("create token")
}

/// Build an inline App exposing the token + introspection endpoints.
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
        .await
    }};
}

fn basic(client_id: &str) -> String {
    format!(
        "Basic {}",
        general_purpose::STANDARD.encode(format!("{client_id}:{client_id}_secret"))
    )
}

/// URL-encode a form value. Only the characters this test file actually uses
/// need escaping (`:` and `/` inside URNs / URIs, plus `&`, `=`, ` `).
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

/// Assemble an `application/x-www-form-urlencoded` body from raw pairs,
/// preserving repeated keys (needed for multi-valued `resource` / `audience`).
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

macro_rules! introspect {
    ($app:expr, $token:expr) => {{
        let req = test::TestRequest::post()
            .uri("/oauth/introspect")
            .insert_header(("Host", HOST))
            .set_form([("token", $token)])
            .to_request();
        let resp = test::call_service(&$app, req).await;
        assert_eq!(resp.status(), 200, "introspection must return 200");
        let body: Value = test::read_body_json(resp).await;
        body
    }};
}

// ---------------------------------------------------------------------------
// 1. Required parameters
// ---------------------------------------------------------------------------

#[actix_web::test]
async fn missing_subject_token_type_is_invalid_request() {
    let storage = storage().await;
    storage
        .save_client(&client("tx_client", &[TOKEN_EXCHANGE]))
        .await
        .expect("save client");
    save_user(&storage, "alice").await;
    let subject = mint(&storage, Some("alice"), "tx_client", "read", vec![], None).await;

    let app = oauth_app!(storage, AgentConfig::default());
    let resp = post_token!(
        app,
        "tx_client",
        &[
            ("grant_type", TOKEN_EXCHANGE),
            ("subject_token", subject.access_token.as_str()),
        ]
    );

    assert_eq!(resp.status(), 400);
    let body: Value = test::read_body_json(resp).await;
    assert_eq!(body["error"], "invalid_request", "body: {body}");
}

// ---------------------------------------------------------------------------
// 2. Plain exchange: scope narrowing, no `act` in the response
// ---------------------------------------------------------------------------

#[actix_web::test]
async fn access_token_subject_narrows_scope_and_omits_act() {
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
        vec![],
        None,
    )
    .await;

    let app = oauth_app!(storage, AgentConfig::default());
    let resp = post_token!(
        app,
        "tx_client",
        &[
            ("grant_type", TOKEN_EXCHANGE),
            ("subject_token", subject.access_token.as_str()),
            ("subject_token_type", ACCESS_TOKEN),
            ("scope", "read"),
        ]
    );

    assert_eq!(resp.status(), 200);
    let body: Value = test::read_body_json(resp).await;
    assert_eq!(body["issued_token_type"], ACCESS_TOKEN, "body: {body}");
    assert_eq!(body["token_type"], "Bearer");
    assert_eq!(body["scope"], "read");
    assert!(
        body.get("act").is_none(),
        "RFC 8693 §2.2.1 defines no `act` response member: {body}"
    );
}

/// A `...:token-type:jwt` subject token is verified by signature rather than by
/// storage lookup. A client-only token has `sub == client_id` and must not be
/// turned back into a `user_id` (there is no matching user row).
#[actix_web::test]
async fn jwt_subject_token_type_is_accepted_for_a_client_only_token() {
    let storage = storage().await;
    storage
        .save_client(&client("tx_client", &[TOKEN_EXCHANGE]))
        .await
        .expect("save client");
    let subject = mint(&storage, None, "tx_client", "read", vec![], None).await;

    let app = oauth_app!(storage, AgentConfig::default());
    let resp = post_token!(
        app,
        "tx_client",
        &[
            ("grant_type", TOKEN_EXCHANGE),
            ("subject_token", subject.access_token.as_str()),
            ("subject_token_type", "urn:ietf:params:oauth:token-type:jwt"),
        ]
    );

    assert_eq!(resp.status(), 200);
    let body: Value = test::read_body_json(resp).await;
    assert_eq!(body["scope"], "read", "body: {body}");
}

// ---------------------------------------------------------------------------
// 3. Actor token ownership
// ---------------------------------------------------------------------------

#[actix_web::test]
async fn actor_token_from_another_client_is_invalid_grant() {
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
    storage
        .save_client(&client("other_client", &["client_credentials"]))
        .await
        .expect("save other client");
    save_user(&storage, "alice").await;

    let subject = mint(&storage, Some("alice"), "sub_client", "read", vec![], None).await;
    // Actor token belongs to `other_client`, not the authenticating client.
    let actor = mint(&storage, None, "other_client", "read", vec![], None).await;

    let app = oauth_app!(storage, AgentConfig::default());
    let resp = post_token!(
        app,
        "agent_client",
        &[
            ("grant_type", TOKEN_EXCHANGE),
            ("subject_token", subject.access_token.as_str()),
            ("subject_token_type", ACCESS_TOKEN),
            ("actor_token", actor.access_token.as_str()),
            ("actor_token_type", ACCESS_TOKEN),
        ]
    );

    assert_eq!(resp.status(), 400);
    let body: Value = test::read_body_json(resp).await;
    assert_eq!(body["error"], "invalid_grant", "body: {body}");
}

// ---------------------------------------------------------------------------
// 4. Delegation authorised by the subject client's `allowed_actors`
// ---------------------------------------------------------------------------

#[actix_web::test]
async fn actor_allowed_via_allowed_actors_builds_act_claim() {
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

    let subject = mint(&storage, Some("alice"), "sub_client", "read", vec![], None).await;
    let actor = mint(&storage, None, "agent_client", "read", vec![], None).await;

    let app = oauth_app!(storage, AgentConfig::default());
    let resp = post_token!(
        app,
        "agent_client",
        &[
            ("grant_type", TOKEN_EXCHANGE),
            ("subject_token", subject.access_token.as_str()),
            ("subject_token_type", ACCESS_TOKEN),
            ("actor_token", actor.access_token.as_str()),
            ("actor_token_type", ACCESS_TOKEN),
        ]
    );

    assert_eq!(resp.status(), 200);
    let body: Value = test::read_body_json(resp).await;
    let issued = body["access_token"]
        .as_str()
        .expect("access_token")
        .to_string();

    let intro = introspect!(app, issued.as_str());
    assert_eq!(intro["active"], json!(true), "introspection: {intro}");
    assert_eq!(
        intro["act"]["sub"], "agent_client",
        "introspection: {intro}"
    );
    assert_eq!(intro["act"]["iss"], ISSUER);
    assert_eq!(intro["act"]["sub_profile"], "service");
}

// ---------------------------------------------------------------------------
// 5. Delegation authorised by the subject token's `may_act`
// ---------------------------------------------------------------------------

#[actix_web::test]
async fn actor_allowed_via_may_act_claim() {
    let storage = storage().await;
    storage
        .save_client(&client("agent_client", &[TOKEN_EXCHANGE]))
        .await
        .expect("save agent client");
    // No `allowed_actors`: only `may_act` can authorise the delegation.
    storage
        .save_client(&client("sub_client", &["client_credentials"]))
        .await
        .expect("save subject client");
    save_user(&storage, "alice").await;

    // Hand-crafted subject JWT carrying `may_act` (RFC 8693 §4.4).
    let mut claims = Claims::new(
        "alice".to_string(),
        "sub_client".to_string(),
        "read".to_string(),
        3600,
        ISSUER,
    );
    claims.may_act = Some(json!({ "sub": "agent_client", "iss": ISSUER }));
    let subject_jwt = claims.encode(JWT_SECRET).expect("encode subject jwt");
    let row = Token::new(
        subject_jwt.clone(),
        None,
        "sub_client".to_string(),
        Some("alice".to_string()),
        "read".to_string(),
        3600,
        None,
    );
    storage.save_token(&row).await.expect("save subject token");

    let actor = mint(&storage, None, "agent_client", "read", vec![], None).await;

    let app = oauth_app!(storage, AgentConfig::default());
    let resp = post_token!(
        app,
        "agent_client",
        &[
            ("grant_type", TOKEN_EXCHANGE),
            ("subject_token", subject_jwt.as_str()),
            ("subject_token_type", ACCESS_TOKEN),
            ("actor_token", actor.access_token.as_str()),
            ("actor_token_type", ACCESS_TOKEN),
        ]
    );

    assert_eq!(resp.status(), 200);
    let body: Value = test::read_body_json(resp).await;
    let issued = body["access_token"]
        .as_str()
        .expect("access_token")
        .to_string();
    let intro = introspect!(app, issued.as_str());
    assert_eq!(
        intro["act"]["sub"], "agent_client",
        "introspection: {intro}"
    );
}

// ---------------------------------------------------------------------------
// 6. Delegation chains and depth limiting
// ---------------------------------------------------------------------------

/// Set up two agents that may both act for `sub_client`, plus a subject token.
async fn nested_chain_fixture() -> (DynStorage, String, String, String) {
    let storage = storage().await;
    // The first hop re-issues the token to `agent_one`, which then becomes the
    // subject client of the second hop — so it must permit `agent_two` to act
    // for it.
    let mut agent_one = client("agent_one", &[TOKEN_EXCHANGE]);
    agent_one.allowed_actors = json!(["agent_two"]).to_string();
    storage
        .save_client(&agent_one)
        .await
        .expect("save agent one");
    storage
        .save_client(&client("agent_two", &[TOKEN_EXCHANGE]))
        .await
        .expect("save agent two");
    let mut subject_client = client("sub_client", &["client_credentials"]);
    subject_client.allowed_actors = json!(["agent_one", "agent_two"]).to_string();
    storage
        .save_client(&subject_client)
        .await
        .expect("save subject client");
    save_user(&storage, "alice").await;

    let subject = mint(&storage, Some("alice"), "sub_client", "read", vec![], None).await;
    let actor_one = mint(&storage, None, "agent_one", "read", vec![], None).await;
    let actor_two = mint(&storage, None, "agent_two", "read", vec![], None).await;

    (
        storage,
        subject.access_token,
        actor_one.access_token,
        actor_two.access_token,
    )
}

#[actix_web::test]
async fn nested_exchange_builds_a_two_level_actor_chain() {
    let (storage, subject, actor_one, actor_two) = nested_chain_fixture().await;
    let app = oauth_app!(storage, AgentConfig::default());

    let resp = post_token!(
        app,
        "agent_one",
        &[
            ("grant_type", TOKEN_EXCHANGE),
            ("subject_token", subject.as_str()),
            ("subject_token_type", ACCESS_TOKEN),
            ("actor_token", actor_one.as_str()),
            ("actor_token_type", ACCESS_TOKEN),
        ]
    );
    assert_eq!(resp.status(), 200);
    let body: Value = test::read_body_json(resp).await;
    let first = body["access_token"]
        .as_str()
        .expect("access_token")
        .to_string();

    let resp = post_token!(
        app,
        "agent_two",
        &[
            ("grant_type", TOKEN_EXCHANGE),
            ("subject_token", first.as_str()),
            ("subject_token_type", ACCESS_TOKEN),
            ("actor_token", actor_two.as_str()),
            ("actor_token_type", ACCESS_TOKEN),
        ]
    );
    assert_eq!(resp.status(), 200);
    let body: Value = test::read_body_json(resp).await;
    let second = body["access_token"]
        .as_str()
        .expect("access_token")
        .to_string();

    let intro = introspect!(app, second.as_str());
    assert_eq!(intro["act"]["sub"], "agent_two", "introspection: {intro}");
    assert_eq!(
        intro["act"]["act"]["sub"], "agent_one",
        "the previous actor must be nested one level deeper: {intro}"
    );
}

#[actix_web::test]
async fn delegation_depth_limit_rejects_the_second_hop() {
    let (storage, subject, actor_one, actor_two) = nested_chain_fixture().await;
    let agent_config = AgentConfig {
        max_delegation_depth: 1,
        ..AgentConfig::default()
    };
    let app = oauth_app!(storage, agent_config);

    let resp = post_token!(
        app,
        "agent_one",
        &[
            ("grant_type", TOKEN_EXCHANGE),
            ("subject_token", subject.as_str()),
            ("subject_token_type", ACCESS_TOKEN),
            ("actor_token", actor_one.as_str()),
            ("actor_token_type", ACCESS_TOKEN),
        ]
    );
    assert_eq!(
        resp.status(),
        200,
        "a single-level chain is within max depth 1"
    );
    let body: Value = test::read_body_json(resp).await;
    let first = body["access_token"]
        .as_str()
        .expect("access_token")
        .to_string();

    let resp = post_token!(
        app,
        "agent_two",
        &[
            ("grant_type", TOKEN_EXCHANGE),
            ("subject_token", first.as_str()),
            ("subject_token_type", ACCESS_TOKEN),
            ("actor_token", actor_two.as_str()),
            ("actor_token_type", ACCESS_TOKEN),
        ]
    );
    assert_eq!(resp.status(), 400);
    let body: Value = test::read_body_json(resp).await;
    assert_eq!(body["error"], "invalid_request", "body: {body}");
}

// ---------------------------------------------------------------------------
// 7-9. Resource / audience handling (RFC 8707 + RFC 8693 §2.1)
// ---------------------------------------------------------------------------

async fn register_resource(storage: &DynStorage, uri: &str) {
    storage
        .save_resource(&ProtectedResource::new(
            uri.to_string(),
            uri.to_string(),
            vec!["read".to_string(), "write".to_string()],
        ))
        .await
        .expect("save resource");
}

#[actix_web::test]
async fn registered_resource_becomes_the_audience() {
    let storage = storage().await;
    storage
        .save_client(&client("tx_client", &[TOKEN_EXCHANGE]))
        .await
        .expect("save client");
    save_user(&storage, "alice").await;
    register_resource(&storage, "https://api.example.test").await;
    let subject = mint(&storage, Some("alice"), "tx_client", "read", vec![], None).await;

    let app = oauth_app!(storage, AgentConfig::default());
    let resp = post_token!(
        app,
        "tx_client",
        &[
            ("grant_type", TOKEN_EXCHANGE),
            ("subject_token", subject.access_token.as_str()),
            ("subject_token_type", ACCESS_TOKEN),
            ("resource", "https://api.example.test"),
        ]
    );
    assert_eq!(resp.status(), 200);
    let body: Value = test::read_body_json(resp).await;
    let issued = body["access_token"]
        .as_str()
        .expect("access_token")
        .to_string();

    let intro = introspect!(app, issued.as_str());
    assert_eq!(
        intro["aud"], "https://api.example.test",
        "introspection: {intro}"
    );
}

#[actix_web::test]
async fn unregistered_resource_is_invalid_target() {
    let storage = storage().await;
    storage
        .save_client(&client("tx_client", &[TOKEN_EXCHANGE]))
        .await
        .expect("save client");
    save_user(&storage, "alice").await;
    register_resource(&storage, "https://api.example.test").await;
    let subject = mint(&storage, Some("alice"), "tx_client", "read", vec![], None).await;

    let app = oauth_app!(storage, AgentConfig::default());
    let resp = post_token!(
        app,
        "tx_client",
        &[
            ("grant_type", TOKEN_EXCHANGE),
            ("subject_token", subject.access_token.as_str()),
            ("subject_token_type", ACCESS_TOKEN),
            ("resource", "https://not-registered.test"),
        ]
    );
    assert_eq!(resp.status(), 400);
    let body: Value = test::read_body_json(resp).await;
    assert_eq!(body["error"], "invalid_target", "body: {body}");
}

#[actix_web::test]
async fn audience_widening_beyond_subject_aud_is_invalid_target() {
    let storage = storage().await;
    storage
        .save_client(&client("tx_client", &[TOKEN_EXCHANGE]))
        .await
        .expect("save client");
    save_user(&storage, "alice").await;
    register_resource(&storage, "https://api.one.test").await;
    register_resource(&storage, "https://api.two.test").await;

    // The subject token is already narrowed to api.one.
    let subject = mint(
        &storage,
        Some("alice"),
        "tx_client",
        "read",
        vec!["https://api.one.test".to_string()],
        None,
    )
    .await;

    let app = oauth_app!(storage, AgentConfig::default());
    let resp = post_token!(
        app,
        "tx_client",
        &[
            ("grant_type", TOKEN_EXCHANGE),
            ("subject_token", subject.access_token.as_str()),
            ("subject_token_type", ACCESS_TOKEN),
            ("audience", "https://api.two.test"),
        ]
    );
    assert_eq!(resp.status(), 400);
    let body: Value = test::read_body_json(resp).await;
    assert_eq!(body["error"], "invalid_target", "body: {body}");
}

// ---------------------------------------------------------------------------
// 10. RAR subsetting (RFC 9396)
// ---------------------------------------------------------------------------

fn subject_rar() -> Value {
    json!([
        { "type": "payment_initiation", "actions": ["read"] },
        { "type": "account_information" }
    ])
}

async fn rar_fixture() -> (DynStorage, String) {
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
        "read",
        vec![],
        Some(subject_rar()),
    )
    .await;
    (storage, subject.access_token)
}

#[actix_web::test]
async fn rar_subset_is_accepted() {
    let (storage, subject) = rar_fixture().await;
    let requested = json!([{ "type": "payment_initiation", "actions": ["read"] }]).to_string();

    let app = oauth_app!(storage, AgentConfig::default());
    let resp = post_token!(
        app,
        "tx_client",
        &[
            ("grant_type", TOKEN_EXCHANGE),
            ("subject_token", subject.as_str()),
            ("subject_token_type", ACCESS_TOKEN),
            ("authorization_details", requested.as_str()),
        ]
    );
    assert_eq!(resp.status(), 200);
}

#[actix_web::test]
async fn rar_superset_is_invalid_authorization_details() {
    let (storage, subject) = rar_fixture().await;
    let requested = json!([{ "type": "not_granted", "actions": ["write"] }]).to_string();

    let app = oauth_app!(storage, AgentConfig::default());
    let resp = post_token!(
        app,
        "tx_client",
        &[
            ("grant_type", TOKEN_EXCHANGE),
            ("subject_token", subject.as_str()),
            ("subject_token_type", ACCESS_TOKEN),
            ("authorization_details", requested.as_str()),
        ]
    );
    assert_eq!(resp.status(), 400);
    let body: Value = test::read_body_json(resp).await;
    assert_eq!(
        body["error"], "invalid_authorization_details",
        "body: {body}"
    );
}

// ---------------------------------------------------------------------------
// 11. Unsupported requested_token_type
// ---------------------------------------------------------------------------

#[actix_web::test]
async fn saml2_requested_token_type_is_invalid_request() {
    let storage = storage().await;
    storage
        .save_client(&client("tx_client", &[TOKEN_EXCHANGE]))
        .await
        .expect("save client");
    save_user(&storage, "alice").await;
    let subject = mint(&storage, Some("alice"), "tx_client", "read", vec![], None).await;

    let app = oauth_app!(storage, AgentConfig::default());
    let resp = post_token!(
        app,
        "tx_client",
        &[
            ("grant_type", TOKEN_EXCHANGE),
            ("subject_token", subject.access_token.as_str()),
            ("subject_token_type", ACCESS_TOKEN),
            (
                "requested_token_type",
                "urn:ietf:params:oauth:token-type:saml2"
            ),
        ]
    );
    assert_eq!(resp.status(), 400);
    let body: Value = test::read_body_json(resp).await;
    assert_eq!(body["error"], "invalid_request", "body: {body}");
}

// ---------------------------------------------------------------------------
// 12. DPoP rebinding at the exchange (RFC 9449)
// ---------------------------------------------------------------------------

/// RSA keypair used to sign DPoP proofs. Generated once per test binary —
/// 2048-bit key generation is expensive in debug builds.
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

#[actix_web::test]
async fn dpop_proof_at_exchange_rebinds_the_new_token() {
    let storage = storage().await;
    storage
        .save_client(&client("tx_client", &[TOKEN_EXCHANGE]))
        .await
        .expect("save client");
    save_user(&storage, "alice").await;
    let subject = mint(&storage, Some("alice"), "tx_client", "read", vec![], None).await;

    let app = oauth_app!(storage, AgentConfig::default());
    let proof = dpop_proof(
        "POST",
        &format!("http://{HOST}/oauth/token"),
        "tx-dpop-1",
        None,
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
        ]))
        .to_request();
    let resp = test::call_service(&app, req).await;

    assert_eq!(resp.status(), 200);
    let body: Value = test::read_body_json(resp).await;
    assert_eq!(body["token_type"], "DPoP", "body: {body}");
    let issued = body["access_token"]
        .as_str()
        .expect("access_token")
        .to_string();

    // Introspecting a DPoP-bound token requires a fresh proof carrying `ath`.
    let intro_proof = dpop_proof(
        "POST",
        &format!("http://{HOST}/oauth/introspect"),
        "tx-dpop-2",
        Some(&compute_ath(&issued)),
    );
    let req = test::TestRequest::post()
        .uri("/oauth/introspect")
        .insert_header(("Host", HOST))
        .insert_header(("DPoP", intro_proof))
        .set_form([("token", issued.as_str())])
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 200);
    let intro: Value = test::read_body_json(resp).await;
    assert_eq!(intro["active"], json!(true), "introspection: {intro}");
    assert!(
        intro["cnf"]["jkt"].is_string(),
        "the exchanged token must be DPoP-bound: {intro}"
    );
}
