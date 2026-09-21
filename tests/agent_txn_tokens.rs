//! Phase 7 (agent / A2A OAuth) Task 13: transaction tokens
//! (draft-ietf-oauth-transaction-tokens-11) with the A2A profile
//! (draft-liu-oauth-a2a-profile-00) and draft-araut actor/principal
//! compatibility.
//!
//! Exercises the `urn:ietf:params:oauth:token-type:txn_token`
//! `requested_token_type` arm of the token-exchange grant end-to-end:
//! feature gating, asymmetric client authentication, trust-domain audience,
//! the issued claim set, replacement semantics (`txn` preservation,
//! narrow-only scope, `tctx` immutability) and discovery.

use std::sync::OnceLock;

use actix::Actor as _;
use actix_web::{test, web, App};
use serde_json::{json, Value};

use oauth2_actix::actors::{CreateToken, TokenActor, TokenActorPool};
use oauth2_actix::handlers::wellknown::OidcConfig;
use oauth2_config::{AgentConfig, Config};
use oauth2_core::{Client, ProtectedResource, Token, User};
use oauth2_observability::Metrics;
use oauth2_ports::DynStorage;
use rsa::pkcs8::EncodePrivateKey;
use rsa::traits::PublicKeyParts;

const TOKEN_EXCHANGE: &str = "urn:ietf:params:oauth:grant-type:token-exchange";
const ACCESS_TOKEN: &str = "urn:ietf:params:oauth:token-type:access_token";
const TXN_TOKEN: &str = "urn:ietf:params:oauth:token-type:txn_token";
const ASSERTION_TYPE: &str = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
const ISSUER: &str = "http://localhost";
const JWT_SECRET: &str = "test_jwt_secret";
const HOST: &str = "auth.test";
const TRUST_DOMAIN: &str = "https://trust.example.test";
const CLIENT_KID: &str = "txn-test-kid";

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

/// One RSA keypair for every `private_key_jwt` client in this binary —
/// 2048-bit key generation is expensive in debug builds. Returns the PKCS#8
/// PEM and the matching JWKS document.
fn client_key() -> &'static (String, String) {
    static KEY: OnceLock<(String, String)> = OnceLock::new();
    KEY.get_or_init(|| {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
        let private_key =
            rsa::RsaPrivateKey::new(&mut rand_core::OsRng, 2048).expect("generate RSA key");
        let public_key = private_key.to_public_key();
        let jwks = json!({
            "keys": [{
                "kty": "RSA",
                "kid": CLIENT_KID,
                "use": "sig",
                "alg": "RS256",
                "n": URL_SAFE_NO_PAD.encode(public_key.n().to_bytes_be()),
                "e": URL_SAFE_NO_PAD.encode(public_key.e().to_bytes_be()),
            }]
        });
        let pem = private_key
            .to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)
            .expect("encode PEM")
            .to_string();
        (pem, jwks.to_string())
    })
}

fn base_client(client_id: &str, scope: &str) -> Client {
    Client::new(
        client_id.to_string(),
        format!("{client_id}_secret"),
        vec!["https://unused.example/cb".to_string()],
        vec![TOKEN_EXCHANGE.to_string()],
        scope.to_string(),
        format!("{client_id} workload"),
    )
}

/// A workload client authenticating with `private_key_jwt` — the only shape
/// the transaction-token endpoint accepts.
fn workload(client_id: &str, scope: &str) -> Client {
    let mut client = base_client(client_id, scope);
    client.token_endpoint_auth_method = "private_key_jwt".to_string();
    client.jwks = client_key().1.clone();
    client
}

/// A fresh client assertion. `jti` is unique per call because the server's
/// replay guard is process-wide for the whole test binary.
fn assertion(client_id: &str) -> String {
    let now = chrono::Utc::now().timestamp();
    let claims = json!({
        "iss": client_id,
        "sub": client_id,
        "aud": format!("{ISSUER}/oauth/token"),
        "exp": now + 300,
        "iat": now,
        "jti": uuid::Uuid::new_v4().to_string(),
    });
    let key = jsonwebtoken::EncodingKey::from_rsa_pem(client_key().0.as_bytes())
        .expect("encoding key from PEM");
    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
    header.kid = Some(CLIENT_KID.to_string());
    jsonwebtoken::encode(&header, &claims, &key).expect("encode client assertion")
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

/// Mint a subject access token through the real `CreateToken` path.
async fn mint(
    storage: &DynStorage,
    user_id: Option<&str>,
    client_id: &str,
    scope: &str,
    act: Option<Value>,
) -> Token {
    mint_for(storage, user_id, client_id, scope, act, vec![]).await
}

async fn mint_for(
    storage: &DynStorage,
    user_id: Option<&str>,
    client_id: &str,
    scope: &str,
    act: Option<Value>,
    resources: Vec<String>,
) -> Token {
    TokenActor::new(storage.clone(), JWT_SECRET.to_string(), ISSUER.to_string())
        .start()
        .send(CreateToken {
            user_id: user_id.map(|u| u.to_string()),
            client_id: client_id.to_string(),
            scope: scope.to_string(),
            include_refresh: false,
            token_family: None,
            resources,
            cnf: None,
            authorization_details: None,
            act,
            span: tracing::Span::current(),
        })
        .await
        .expect("send CreateToken")
        .expect("create token")
}

fn agent_config(enabled: bool, trust_domain: Option<&str>, a2a: bool) -> AgentConfig {
    AgentConfig {
        txn_tokens_enabled: enabled,
        trust_domain: trust_domain.map(|d| d.to_string()),
        a2a_profile_enabled: a2a,
        txn_token_ttl_secs: 300,
        ..AgentConfig::default()
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

/// URL-encode a form value.
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

/// POST to the token endpoint authenticating `client_id` with a fresh
/// `private_key_jwt` assertion.
macro_rules! post_pkj {
    ($app:expr, $client_id:expr, $pairs:expr) => {{
        let assertion = assertion($client_id);
        let mut pairs: Vec<(&str, &str)> = vec![
            ("client_id", $client_id),
            ("client_assertion_type", ASSERTION_TYPE),
            ("client_assertion", assertion.as_str()),
        ];
        pairs.extend_from_slice($pairs);
        let req = test::TestRequest::post()
            .uri("/oauth/token")
            .insert_header(("Host", HOST))
            .insert_header(("Content-Type", "application/x-www-form-urlencoded"))
            .set_payload(form(&pairs))
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

/// The form parameters of a first-hop transaction token request.
fn txn_request<'a>(subject: &'a str, subject_type: &'a str) -> Vec<(&'a str, &'a str)> {
    vec![
        ("grant_type", TOKEN_EXCHANGE),
        ("subject_token", subject),
        ("subject_token_type", subject_type),
        ("requested_token_type", TXN_TOKEN),
        ("audience", TRUST_DOMAIN),
    ]
}

/// Verify and decode an issued transaction token. The test server has no
/// keyset, so the token is HS256-signed with the configured secret.
fn decode_txn(token: &str) -> (jsonwebtoken::Header, Value) {
    let header = jsonwebtoken::decode_header(token).expect("decode header");
    let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::HS256);
    validation.validate_aud = false;
    let data = jsonwebtoken::decode::<Value>(
        token,
        &jsonwebtoken::DecodingKey::from_secret(JWT_SECRET.as_bytes()),
        &validation,
    )
    .expect("transaction token must verify against the server secret");
    (header, data.claims)
}

async fn body_of(resp: actix_web::dev::ServiceResponse) -> Value {
    test::read_body_json(resp).await
}

// ---------------------------------------------------------------------------
// 1. Feature gating
// ---------------------------------------------------------------------------

#[actix_web::test]
async fn txn_tokens_disabled_is_invalid_request() {
    let storage = storage().await;
    storage
        .save_client(&workload("wl_off", "read write"))
        .await
        .expect("save client");
    save_user(&storage, "alice").await;
    let subject = mint(&storage, Some("alice"), "wl_off", "read", None).await;

    let app = oauth_app!(storage, agent_config(false, Some(TRUST_DOMAIN), false));
    let resp = post_pkj!(
        app,
        "wl_off",
        &txn_request(subject.access_token.as_str(), ACCESS_TOKEN)
    );

    assert_eq!(resp.status(), 400);
    let body = body_of(resp).await;
    assert_eq!(body["error"], "invalid_request", "body: {body}");
}

#[actix_web::test]
async fn a_missing_trust_domain_is_invalid_request() {
    let storage = storage().await;
    storage
        .save_client(&workload("wl_no_domain", "read write"))
        .await
        .expect("save client");
    save_user(&storage, "alice").await;
    let subject = mint(&storage, Some("alice"), "wl_no_domain", "read", None).await;

    let app = oauth_app!(storage, agent_config(true, None, false));
    let resp = post_pkj!(
        app,
        "wl_no_domain",
        &txn_request(subject.access_token.as_str(), ACCESS_TOKEN)
    );

    assert_eq!(resp.status(), 400);
    let body = body_of(resp).await;
    assert_eq!(body["error"], "invalid_request", "body: {body}");
}

// ---------------------------------------------------------------------------
// 2. Client authentication
// ---------------------------------------------------------------------------

/// draft-ietf-oauth-transaction-tokens §6.1: a shared secret is not enough.
#[actix_web::test]
async fn a_secret_authenticated_client_is_invalid_client() {
    let storage = storage().await;
    storage
        .save_client(&base_client("wl_secret", "read write"))
        .await
        .expect("save client");
    save_user(&storage, "alice").await;
    let subject = mint(&storage, Some("alice"), "wl_secret", "read", None).await;

    let app = oauth_app!(storage, agent_config(true, Some(TRUST_DOMAIN), false));
    let mut pairs = vec![
        ("client_id", "wl_secret"),
        ("client_secret", "wl_secret_secret"),
    ];
    let request = txn_request(subject.access_token.as_str(), ACCESS_TOKEN);
    pairs.extend_from_slice(&request);
    let req = test::TestRequest::post()
        .uri("/oauth/token")
        .insert_header(("Host", HOST))
        .insert_header(("Content-Type", "application/x-www-form-urlencoded"))
        .set_payload(form(&pairs))
        .to_request();
    let resp = test::call_service(&app, req).await;

    assert_eq!(resp.status(), 401);
    let body = body_of(resp).await;
    assert_eq!(body["error"], "invalid_client", "body: {body}");
    assert!(
        body["error_description"]
            .as_str()
            .unwrap_or_default()
            .contains("asymmetric"),
        "body: {body}"
    );
}

// ---------------------------------------------------------------------------
// 3. Audience must be the trust domain
// ---------------------------------------------------------------------------

#[actix_web::test]
async fn an_audience_other_than_the_trust_domain_is_invalid_target() {
    let storage = storage().await;
    storage
        .save_client(&workload("wl_aud", "read write"))
        .await
        .expect("save client");
    save_user(&storage, "alice").await;
    let subject = mint(&storage, Some("alice"), "wl_aud", "read", None).await;

    let app = oauth_app!(storage, agent_config(true, Some(TRUST_DOMAIN), false));
    let resp = post_pkj!(
        app,
        "wl_aud",
        &[
            ("grant_type", TOKEN_EXCHANGE),
            ("subject_token", subject.access_token.as_str()),
            ("subject_token_type", ACCESS_TOKEN),
            ("requested_token_type", TXN_TOKEN),
            ("audience", "https://other.example.test"),
        ]
    );

    assert_eq!(resp.status(), 400);
    let body = body_of(resp).await;
    assert_eq!(body["error"], "invalid_target", "body: {body}");
}

#[actix_web::test]
async fn a_missing_audience_is_invalid_request() {
    let storage = storage().await;
    storage
        .save_client(&workload("wl_no_aud", "read write"))
        .await
        .expect("save client");
    save_user(&storage, "alice").await;
    let subject = mint(&storage, Some("alice"), "wl_no_aud", "read", None).await;

    let app = oauth_app!(storage, agent_config(true, Some(TRUST_DOMAIN), false));
    let resp = post_pkj!(
        app,
        "wl_no_aud",
        &[
            ("grant_type", TOKEN_EXCHANGE),
            ("subject_token", subject.access_token.as_str()),
            ("subject_token_type", ACCESS_TOKEN),
            ("requested_token_type", TXN_TOKEN),
        ]
    );

    assert_eq!(resp.status(), 400);
    let body = body_of(resp).await;
    assert_eq!(body["error"], "invalid_request", "body: {body}");
}

// ---------------------------------------------------------------------------
// 4. Happy path
// ---------------------------------------------------------------------------

#[actix_web::test]
async fn a_transaction_token_carries_the_profile_claim_set() {
    let storage = storage().await;
    storage
        .save_client(&workload("wl_happy", "read write"))
        .await
        .expect("save client");
    save_user(&storage, "alice").await;
    let subject = mint(&storage, Some("alice"), "wl_happy", "read write", None).await;

    let app = oauth_app!(storage, agent_config(true, Some(TRUST_DOMAIN), false));
    let mut request = txn_request(subject.access_token.as_str(), ACCESS_TOKEN);
    request.push(("scope", "read"));
    request.push(("request_details", r#"{"amount":42}"#));
    request.push(("request_context", r#"{"ip":"10.0.0.1"}"#));
    let resp = post_pkj!(app, "wl_happy", &request);

    assert_eq!(resp.status(), 200);
    let body = body_of(resp).await;
    assert_eq!(body["token_type"], "N_A", "body: {body}");
    assert_eq!(body["issued_token_type"], TXN_TOKEN, "body: {body}");
    assert_eq!(body["expires_in"], 300, "body: {body}");
    assert!(
        body.get("refresh_token").is_none(),
        "a transaction token is never refreshable: {body}"
    );

    let token = body["access_token"].as_str().expect("access_token");
    let (header, claims) = decode_txn(token);
    assert_eq!(header.typ.as_deref(), Some("txntoken+jwt"));
    assert_eq!(claims["iss"], ISSUER, "claims: {claims}");
    assert_eq!(claims["aud"], TRUST_DOMAIN, "claims: {claims}");
    assert_eq!(claims["sub"], "alice", "claims: {claims}");
    assert_eq!(claims["scope"], "read", "claims: {claims}");
    assert_eq!(claims["req_wl"], "wl_happy", "claims: {claims}");
    assert_eq!(claims["tctx"], json!({"amount": 42}), "claims: {claims}");
    assert_eq!(
        claims["rctx"],
        json!({"ip": "10.0.0.1"}),
        "claims: {claims}"
    );
    assert_eq!(
        claims["exp"].as_i64().expect("exp") - claims["iat"].as_i64().expect("iat"),
        300,
        "claims: {claims}"
    );
    uuid::Uuid::parse_str(claims["txn"].as_str().expect("txn")).expect("txn is a UUID");
    assert!(claims.get("purp").is_none(), "purp is A2A-only: {claims}");

    // Never persisted, but introspectable from its own signature.
    let intro = introspect!(app, token);
    assert_eq!(intro["active"], true, "intro: {intro}");
    assert_eq!(intro["token_type"], "N_A", "intro: {intro}");
    assert_eq!(intro["sub"], "alice", "intro: {intro}");
    assert_eq!(intro["aud"], TRUST_DOMAIN, "intro: {intro}");
    assert_eq!(intro["scope"], "read", "intro: {intro}");
    assert_eq!(intro["iss"], ISSUER, "intro: {intro}");
    assert_eq!(intro["txn"], claims["txn"], "intro: {intro}");
    assert_eq!(intro["req_wl"], "wl_happy", "intro: {intro}");
    assert_eq!(intro["exp"], claims["exp"], "intro: {intro}");
    assert_eq!(intro["iat"], claims["iat"], "intro: {intro}");
}

/// Without an explicit `scope` the token inherits the subject's.
#[actix_web::test]
async fn scope_defaults_to_the_subject_tokens_scope() {
    let storage = storage().await;
    storage
        .save_client(&workload("wl_inherit", "read write"))
        .await
        .expect("save client");
    save_user(&storage, "alice").await;
    let subject = mint(&storage, Some("alice"), "wl_inherit", "read write", None).await;

    let app = oauth_app!(storage, agent_config(true, Some(TRUST_DOMAIN), false));
    let resp = post_pkj!(
        app,
        "wl_inherit",
        &txn_request(subject.access_token.as_str(), ACCESS_TOKEN)
    );

    assert_eq!(resp.status(), 200);
    let body = body_of(resp).await;
    let (_, claims) = decode_txn(body["access_token"].as_str().expect("access_token"));
    assert_eq!(claims["scope"], "read write", "claims: {claims}");
}

#[actix_web::test]
async fn request_details_must_be_a_json_object() {
    let storage = storage().await;
    storage
        .save_client(&workload("wl_bad_details", "read write"))
        .await
        .expect("save client");
    save_user(&storage, "alice").await;
    let subject = mint(&storage, Some("alice"), "wl_bad_details", "read", None).await;

    let app = oauth_app!(storage, agent_config(true, Some(TRUST_DOMAIN), false));
    let mut request = txn_request(subject.access_token.as_str(), ACCESS_TOKEN);
    request.push(("request_details", "[1,2,3]"));
    let resp = post_pkj!(app, "wl_bad_details", &request);

    assert_eq!(resp.status(), 400);
    let body = body_of(resp).await;
    assert_eq!(body["error"], "invalid_request", "body: {body}");
}

// ---------------------------------------------------------------------------
// 5. Replacement
// ---------------------------------------------------------------------------

/// Issue a first-hop transaction token, evaluating to the raw JWT.
macro_rules! first_hop {
    ($app:expr, $client_id:expr, $subject:expr, $extra:expr) => {{
        let mut request = txn_request($subject, ACCESS_TOKEN);
        request.extend_from_slice($extra);
        let resp = post_pkj!($app, $client_id, &request);
        assert_eq!(resp.status(), 200, "first hop must succeed");
        let body = body_of(resp).await;
        body["access_token"]
            .as_str()
            .expect("access_token")
            .to_string()
    }};
}

#[actix_web::test]
async fn a_replacement_preserves_txn_sub_and_audience() {
    let storage = storage().await;
    storage
        .save_client(&workload("wl_one", "read write"))
        .await
        .expect("save client");
    storage
        .save_client(&workload("wl_two", "read write"))
        .await
        .expect("save client");
    save_user(&storage, "alice").await;
    let subject = mint(&storage, Some("alice"), "wl_one", "read write", None).await;

    let app = oauth_app!(storage, agent_config(true, Some(TRUST_DOMAIN), false));
    let first = first_hop!(app, "wl_one", subject.access_token.as_str(), &[]);
    let (_, first_claims) = decode_txn(&first);

    // The next workload in the chain narrows scope and gets a replacement.
    let mut request = txn_request(first.as_str(), TXN_TOKEN);
    request.push(("scope", "read"));
    let resp = post_pkj!(app, "wl_two", &request);

    assert_eq!(resp.status(), 200);
    let body = body_of(resp).await;
    let (header, claims) = decode_txn(body["access_token"].as_str().expect("access_token"));
    assert_eq!(header.typ.as_deref(), Some("txntoken+jwt"));
    assert_eq!(claims["txn"], first_claims["txn"], "claims: {claims}");
    assert_eq!(claims["sub"], "alice", "claims: {claims}");
    assert_eq!(claims["aud"], TRUST_DOMAIN, "claims: {claims}");
    assert_eq!(claims["scope"], "read", "claims: {claims}");
    assert_eq!(claims["req_wl"], "wl_two", "claims: {claims}");
}

#[actix_web::test]
async fn a_replacement_cannot_widen_scope() {
    let storage = storage().await;
    storage
        .save_client(&workload("wl_narrow", "read write"))
        .await
        .expect("save client");
    save_user(&storage, "alice").await;
    let subject = mint(&storage, Some("alice"), "wl_narrow", "read", None).await;

    let app = oauth_app!(storage, agent_config(true, Some(TRUST_DOMAIN), false));
    let first = first_hop!(app, "wl_narrow", subject.access_token.as_str(), &[]);

    let mut request = txn_request(first.as_str(), TXN_TOKEN);
    request.push(("scope", "read write"));
    let resp = post_pkj!(app, "wl_narrow", &request);

    assert_eq!(resp.status(), 400);
    let body = body_of(resp).await;
    assert_eq!(body["error"], "invalid_scope", "body: {body}");
}

/// A transaction token confers no authority at a resource server, so it must
/// never be exchanged for a plain access token.
#[actix_web::test]
async fn a_transaction_token_subject_cannot_yield_an_access_token() {
    let storage = storage().await;
    storage
        .save_client(&workload("wl_launder", "read write"))
        .await
        .expect("save client");
    save_user(&storage, "alice").await;
    let subject = mint(&storage, Some("alice"), "wl_launder", "read", None).await;

    let app = oauth_app!(storage, agent_config(true, Some(TRUST_DOMAIN), false));
    let first = first_hop!(app, "wl_launder", subject.access_token.as_str(), &[]);

    let resp = post_pkj!(
        app,
        "wl_launder",
        &[
            ("grant_type", TOKEN_EXCHANGE),
            ("subject_token", first.as_str()),
            ("subject_token_type", TXN_TOKEN),
        ]
    );

    assert_eq!(resp.status(), 400);
    let body = body_of(resp).await;
    assert_eq!(body["error"], "invalid_request", "body: {body}");
}

/// An access token wearing the txn-token type URN has the wrong `typ` header.
#[actix_web::test]
async fn an_access_token_is_not_accepted_as_a_transaction_token() {
    let storage = storage().await;
    storage
        .save_client(&workload("wl_typ", "read write"))
        .await
        .expect("save client");
    save_user(&storage, "alice").await;
    let subject = mint(&storage, Some("alice"), "wl_typ", "read", None).await;

    let app = oauth_app!(storage, agent_config(true, Some(TRUST_DOMAIN), false));
    let resp = post_pkj!(
        app,
        "wl_typ",
        &txn_request(subject.access_token.as_str(), TXN_TOKEN)
    );

    assert_eq!(resp.status(), 400);
    let body = body_of(resp).await;
    assert_eq!(body["error"], "invalid_request", "body: {body}");
}

// ---------------------------------------------------------------------------
// 6. A2A profile
// ---------------------------------------------------------------------------

#[actix_web::test]
async fn the_a2a_profile_sets_purp_actor_and_principal() {
    let storage = storage().await;
    storage
        .save_client(&workload("wl_a2a", "read write"))
        .await
        .expect("save client");
    save_user(&storage, "alice").await;
    let subject = mint(
        &storage,
        Some("alice"),
        "wl_a2a",
        "read",
        Some(json!({ "sub": "agent-7", "iss": ISSUER })),
    )
    .await;

    let app = oauth_app!(storage, agent_config(true, Some(TRUST_DOMAIN), true));
    let mut request = txn_request(subject.access_token.as_str(), ACCESS_TOKEN);
    request.push(("purp", "book_travel"));
    let resp = post_pkj!(app, "wl_a2a", &request);

    assert_eq!(resp.status(), 200);
    let body = body_of(resp).await;
    let (_, claims) = decode_txn(body["access_token"].as_str().expect("access_token"));
    assert_eq!(claims["purp"], "book_travel", "claims: {claims}");
    assert_eq!(claims["act"]["sub"], "agent-7", "claims: {claims}");
    assert_eq!(claims["actor"], "agent-7", "claims: {claims}");
    assert_eq!(claims["principal"], "alice", "claims: {claims}");
}

#[actix_web::test]
async fn purp_is_omitted_when_the_a2a_profile_is_off() {
    let storage = storage().await;
    storage
        .save_client(&workload("wl_no_a2a", "read write"))
        .await
        .expect("save client");
    save_user(&storage, "alice").await;
    let subject = mint(
        &storage,
        Some("alice"),
        "wl_no_a2a",
        "read",
        Some(json!({ "sub": "agent-7", "iss": ISSUER })),
    )
    .await;

    let app = oauth_app!(storage, agent_config(true, Some(TRUST_DOMAIN), false));
    let mut request = txn_request(subject.access_token.as_str(), ACCESS_TOKEN);
    request.push(("purp", "book_travel"));
    let resp = post_pkj!(app, "wl_no_a2a", &request);

    assert_eq!(resp.status(), 200);
    let body = body_of(resp).await;
    let (_, claims) = decode_txn(body["access_token"].as_str().expect("access_token"));
    assert!(claims.get("purp").is_none(), "claims: {claims}");
    assert!(claims.get("actor").is_none(), "claims: {claims}");
    assert!(claims.get("principal").is_none(), "claims: {claims}");
    // `act` still travels with the token — only the A2A aliases are gated.
    assert_eq!(claims["act"]["sub"], "agent-7", "claims: {claims}");
}

/// A2A immutability: `tctx` is fixed when the transaction starts.
#[actix_web::test]
async fn tctx_is_immutable_across_a_replacement() {
    let storage = storage().await;
    storage
        .save_client(&workload("wl_tctx", "read write"))
        .await
        .expect("save client");
    save_user(&storage, "alice").await;
    let subject = mint(&storage, Some("alice"), "wl_tctx", "read", None).await;

    let app = oauth_app!(storage, agent_config(true, Some(TRUST_DOMAIN), true));
    let first = first_hop!(
        app,
        "wl_tctx",
        subject.access_token.as_str(),
        &[("request_details", r#"{"amount":42}"#)]
    );

    // Changing it is refused …
    let mut changed = txn_request(first.as_str(), TXN_TOKEN);
    changed.push(("request_details", r#"{"amount":99}"#));
    let resp = post_pkj!(app, "wl_tctx", &changed);
    assert_eq!(resp.status(), 400);
    let body = body_of(resp).await;
    assert_eq!(body["error"], "invalid_request", "body: {body}");

    // … restating it verbatim is accepted, and `rctx` may still change.
    let mut restated = txn_request(first.as_str(), TXN_TOKEN);
    restated.push(("request_details", r#"{"amount":42}"#));
    restated.push(("request_context", r#"{"hop":2}"#));
    let resp = post_pkj!(app, "wl_tctx", &restated);
    assert_eq!(resp.status(), 200);
    let body = body_of(resp).await;
    let (_, claims) = decode_txn(body["access_token"].as_str().expect("access_token"));
    assert_eq!(claims["tctx"], json!({"amount": 42}), "claims: {claims}");
    assert_eq!(claims["rctx"], json!({"hop": 2}), "claims: {claims}");
}

// ---------------------------------------------------------------------------
// 7. The trust domain is not a resource indicator
// ---------------------------------------------------------------------------

/// A trust domain is an opaque identifier, not a URL: `example.com` is the
/// shape oauth2-config's own defaults use and must be accepted verbatim.
#[actix_web::test]
async fn a_non_url_trust_domain_is_accepted() {
    let storage = storage().await;
    storage
        .save_client(&workload("wl_bare", "read write"))
        .await
        .expect("save client");
    save_user(&storage, "alice").await;
    let subject = mint(&storage, Some("alice"), "wl_bare", "read", None).await;

    let app = oauth_app!(storage, agent_config(true, Some("example.com"), false));
    let resp = post_pkj!(
        app,
        "wl_bare",
        &[
            ("grant_type", TOKEN_EXCHANGE),
            ("subject_token", subject.access_token.as_str()),
            ("subject_token_type", ACCESS_TOKEN),
            ("requested_token_type", TXN_TOKEN),
            ("audience", "example.com"),
        ]
    );

    assert_eq!(resp.status(), 200);
    let body = body_of(resp).await;
    let (_, claims) = decode_txn(body["access_token"].as_str().expect("access_token"));
    assert_eq!(claims["aud"], "example.com", "claims: {claims}");
}

/// A subject token bound to a resource has `aud != client_id`. The trust
/// domain is unrelated to that audience and must not be checked against it.
#[actix_web::test]
async fn a_resource_bound_subject_token_can_obtain_a_txn_token() {
    let storage = storage().await;
    storage
        .save_client(&workload("wl_res", "read write"))
        .await
        .expect("save client");
    save_user(&storage, "alice").await;
    let subject = mint_for(
        &storage,
        Some("alice"),
        "wl_res",
        "read",
        None,
        vec!["https://api.example/v1".to_string()],
    )
    .await;

    let app = oauth_app!(storage, agent_config(true, Some(TRUST_DOMAIN), false));
    let resp = post_pkj!(
        app,
        "wl_res",
        &txn_request(subject.access_token.as_str(), ACCESS_TOKEN)
    );

    assert_eq!(resp.status(), 200);
    let body = body_of(resp).await;
    let (_, claims) = decode_txn(body["access_token"].as_str().expect("access_token"));
    assert_eq!(claims["aud"], TRUST_DOMAIN, "claims: {claims}");
}

/// A populated protected-resource registry constrains resource indicators,
/// not the trust domain.
#[actix_web::test]
async fn a_populated_resource_registry_does_not_block_txn_issuance() {
    let storage = storage().await;
    storage
        .save_resource(&ProtectedResource::new(
            "https://api.example/v1".to_string(),
            "Unrelated API".to_string(),
            vec!["read".to_string()],
        ))
        .await
        .expect("save resource");
    storage
        .save_client(&workload("wl_registry", "read write"))
        .await
        .expect("save client");
    save_user(&storage, "alice").await;
    let subject = mint(&storage, Some("alice"), "wl_registry", "read", None).await;

    let app = oauth_app!(storage, agent_config(true, Some(TRUST_DOMAIN), false));
    let resp = post_pkj!(
        app,
        "wl_registry",
        &txn_request(subject.access_token.as_str(), ACCESS_TOKEN)
    );

    assert_eq!(resp.status(), 200);
    let body = body_of(resp).await;
    let (_, claims) = decode_txn(body["access_token"].as_str().expect("access_token"));
    assert_eq!(claims["aud"], TRUST_DOMAIN, "claims: {claims}");
}

// ---------------------------------------------------------------------------
// 8. Introspection
// ---------------------------------------------------------------------------

/// Sign an arbitrary transaction-token payload with the server's HS256 secret.
fn forge_txn(claims: Value) -> String {
    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256);
    header.typ = Some("txntoken+jwt".to_string());
    jsonwebtoken::encode(
        &header,
        &claims,
        &jsonwebtoken::EncodingKey::from_secret(JWT_SECRET.as_bytes()),
    )
    .expect("sign forged txn token")
}

#[actix_web::test]
async fn an_expired_transaction_token_introspects_as_inactive() {
    let storage = storage().await;
    let app = oauth_app!(storage, agent_config(true, Some(TRUST_DOMAIN), false));

    let now = chrono::Utc::now().timestamp();
    let expired = forge_txn(json!({
        "iss": ISSUER,
        "iat": now - 600,
        "exp": now - 300,
        "aud": TRUST_DOMAIN,
        "txn": uuid::Uuid::new_v4().to_string(),
        "sub": "alice",
        "scope": "read",
        "req_wl": "wl_expired",
    }));

    let intro = introspect!(app, expired.as_str());
    assert_eq!(intro["active"], false, "intro: {intro}");
}

/// A token signed by someone else must not introspect as active, however
/// well-formed its payload is.
#[actix_web::test]
async fn a_foreign_transaction_token_introspects_as_inactive() {
    let storage = storage().await;
    let app = oauth_app!(storage, agent_config(true, Some(TRUST_DOMAIN), false));

    let now = chrono::Utc::now().timestamp();
    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256);
    header.typ = Some("txntoken+jwt".to_string());
    let foreign = jsonwebtoken::encode(
        &header,
        &json!({
            "iss": ISSUER,
            "iat": now,
            "exp": now + 300,
            "aud": TRUST_DOMAIN,
            "txn": uuid::Uuid::new_v4().to_string(),
            "sub": "alice",
            "scope": "read write",
            "req_wl": "wl_attacker",
        }),
        &jsonwebtoken::EncodingKey::from_secret(b"not-the-servers-secret"),
    )
    .expect("sign foreign token");

    let intro = introspect!(app, foreign.as_str());
    assert_eq!(intro["active"], false, "intro: {intro}");
}

/// With the feature off the txn branch is not taken at all, so the token
/// falls through to the ordinary (storage-backed) path and is inactive.
#[actix_web::test]
async fn introspection_ignores_txn_tokens_when_the_feature_is_off() {
    let storage = storage().await;
    let app = oauth_app!(storage, agent_config(false, Some(TRUST_DOMAIN), false));

    let now = chrono::Utc::now().timestamp();
    let token = forge_txn(json!({
        "iss": ISSUER,
        "iat": now,
        "exp": now + 300,
        "aud": TRUST_DOMAIN,
        "txn": uuid::Uuid::new_v4().to_string(),
        "sub": "alice",
        "scope": "read",
        "req_wl": "wl_off",
    }));

    let intro = introspect!(app, token.as_str());
    assert_eq!(intro["active"], false, "intro: {intro}");
}

// ---------------------------------------------------------------------------
// 9. Discovery
// ---------------------------------------------------------------------------

macro_rules! discovery_app {
    ($agent_config:expr) => {{
        let oidc_config = OidcConfig {
            issuer: ISSUER.to_string(),
            jwt_secret: JWT_SECRET.to_string(),
            id_token_alg: "HS256".to_string(),
            id_token_kid: None,
            id_token_private_key_pem: None,
        };
        test::init_service(
            App::new()
                .app_data(web::Data::new(oidc_config))
                .app_data(web::Data::new($agent_config))
                .route(
                    "/.well-known/openid-configuration",
                    web::get().to(oauth2_actix::handlers::wellknown::openid_configuration),
                ),
        )
        .await
    }};
}

async fn discovery(agent: AgentConfig) -> Value {
    let app = discovery_app!(agent);
    let req = test::TestRequest::get()
        .uri("/.well-known/openid-configuration")
        .insert_header(("Host", HOST))
        .to_request();
    test::read_body_json(test::call_service(&app, req).await).await
}

#[actix_web::test]
async fn discovery_advertises_transaction_tokens_only_when_enabled() {
    let enabled = discovery(agent_config(true, Some(TRUST_DOMAIN), false)).await;
    assert_eq!(
        enabled["transaction_token_supported"], true,
        "doc: {enabled}"
    );

    let disabled = discovery(agent_config(false, Some(TRUST_DOMAIN), false)).await;
    assert!(
        disabled.get("transaction_token_supported").is_none(),
        "doc: {disabled}"
    );
}
