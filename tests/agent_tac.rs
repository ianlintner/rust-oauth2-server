//! Task 15 (Phase 7 agent / A2A OAuth): Transaction Authorization Challenge
//! (`draft-rosomakho-oauth-txn-challenge-00`).
//!
//! Challenges are minted with a test RSA key whose public half is served as a
//! JWKS document from an in-process actix server bound to an ephemeral
//! loopback port; that URL is registered as the protected resource's
//! `txn_challenge_jwks_uri` so the production `JwksCache` fetches it for real.
//! (Same harness as `tests/agent_jwt_bearer_grant.rs`.)

use std::sync::OnceLock;

use actix::Actor;
use actix_session::{storage::CookieSessionStore, Session, SessionMiddleware};
use actix_web::{cookie::Key, test, web, App, HttpResponse, HttpServer};
use base64::{engine::general_purpose, Engine as _};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header as JwtHeader};
use rsa::pkcs1::EncodeRsaPrivateKey;
use rsa::traits::PublicKeyParts;
use rsa::{RsaPrivateKey, RsaPublicKey};
use serde_json::{json, Value};

use oauth2_actix::actors::TokenActorPool;
use oauth2_actix::handlers::jwks_cache::JwksCache;
use oauth2_actix::handlers::wellknown::OidcConfig;
use oauth2_config::AgentConfig;
use oauth2_core::{
    token_types::GRANT_TRANSACTION_AUTHORIZATION, Client, ProtectedResource,
    TransactionAuthorization, User,
};
use oauth2_observability::Metrics;
use oauth2_ports::DynStorage;

const ISSUER: &str = "http://localhost";
const RESOURCE_URI: &str = "https://payments.example";
const TEST_KID: &str = "tac-test-kid-1";
const USER_ID: &str = "user_123";

// ---------------------------------------------------------------------------
// Signing key + JWKS server
// ---------------------------------------------------------------------------

/// RSA keypair used to sign challenges. Generated once per test binary —
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
            "alg": "RS256",
            "use": "sig",
            "kid": TEST_KID,
            "n": general_purpose::URL_SAFE_NO_PAD.encode(public_key.n().to_bytes_be()),
            "e": general_purpose::URL_SAFE_NO_PAD.encode(public_key.e().to_bytes_be()),
        });
        (pem, jwk)
    })
}

/// A second keypair, used to produce challenges whose signature does not
/// verify against the published JWKS.
fn wrong_signer() -> &'static String {
    static WRONG: OnceLock<String> = OnceLock::new();
    WRONG.get_or_init(|| {
        let mut rng = rand_core::OsRng;
        let private_key = RsaPrivateKey::new(&mut rng, 2048).expect("generate RSA key");
        private_key
            .to_pkcs1_pem(rsa::pkcs1::LineEnding::LF)
            .expect("encode private key")
            .to_string()
    })
}

async fn serve_jwks() -> HttpResponse {
    let (_, jwk) = signer();
    HttpResponse::Ok().json(json!({ "keys": [jwk] }))
}

fn spawn_jwks_server() -> String {
    let server = HttpServer::new(|| App::new().default_service(web::to(serve_jwks)))
        .workers(1)
        .disable_signals()
        .bind(("127.0.0.1", 0))
        .expect("bind loopback");
    let port = server.addrs()[0].port();
    actix_web::rt::spawn(server.run());
    format!("http://127.0.0.1:{port}/jwks")
}

// ---------------------------------------------------------------------------
// Challenge minting
// ---------------------------------------------------------------------------

fn sign_challenge(claims: &Value, valid_sig: bool) -> String {
    let mut header = JwtHeader::new(Algorithm::RS256);
    header.kid = Some(TEST_KID.to_string());
    let pem = if valid_sig {
        &signer().0
    } else {
        wrong_signer()
    };
    let key = EncodingKey::from_rsa_pem(pem.as_bytes()).expect("encoding key");
    encode(&header, claims, &key).expect("sign challenge")
}

fn authorization_details() -> Value {
    json!([{
        "type": "payment_initiation",
        "actions": ["initiate"],
        "instructedAmount": { "currency": "EUR", "amount": "42.00" },
    }])
}

/// A complete, valid challenge claim set.
fn base_claims(jti: &str) -> Value {
    let now = chrono::Utc::now().timestamp();
    json!({
        "iss": RESOURCE_URI,
        "aud": ISSUER,
        "exp": now + 300,
        "iat": now,
        "jti": jti,
        "txn": "txn-abc-123",
        "authorization_details": authorization_details(),
        "reason": "Transfer 42.00 EUR to ACME Ltd",
        "reason_uri": "https://payments.example/tx/1",
    })
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

fn tac_client() -> Client {
    Client::new(
        "tac_client".to_string(),
        "tac_secret".to_string(),
        vec!["https://unused.example/cb".to_string()],
        vec![GRANT_TRANSACTION_AUTHORIZATION.to_string()],
        "read write".to_string(),
        "Payments Agent".to_string(),
    )
}

/// A unique file-backed SQLite database per test: `sqlite::memory:` creates a
/// fresh database per pooled connection, so a multi-connection pool can lose
/// writes when a later read lands on a different connection.
async fn setup(jwks_uri: Option<&str>) -> DynStorage {
    let tmp = tempfile::NamedTempFile::new().expect("tempfile");
    let url = format!("sqlite://{}", tmp.path().display());
    // Leak the guard so the file outlives the test — Drop removes it.
    std::mem::forget(tmp);
    let storage = oauth2_storage_factory::create_storage(&url)
        .await
        .expect("create storage");
    storage.init().await.expect("init storage");
    storage
        .save_client(&tac_client())
        .await
        .expect("save client");

    let now = chrono::Utc::now();
    storage
        .save_user(&User {
            id: USER_ID.to_string(),
            username: USER_ID.to_string(),
            password_hash: "not_used".to_string(),
            email: "user_123@example.test".to_string(),
            enabled: true,
            role: "user".to_string(),
            created_at: now,
            updated_at: now,
        })
        .await
        .expect("save user");

    if let Some(uri) = jwks_uri {
        let mut resource = ProtectedResource::new(
            RESOURCE_URI.to_string(),
            "Payments API".to_string(),
            vec!["payments".to_string()],
        );
        resource.txn_challenge_jwks_uri = uri.to_string();
        storage
            .save_resource(&resource)
            .await
            .expect("save resource");
    }

    storage
}

struct Deps {
    token_pool: TokenActorPool,
    client_actor: actix::Addr<oauth2_actix::actors::ClientActor>,
    auth_actor: actix::Addr<oauth2_actix::actors::AuthActor>,
    metrics: Metrics,
    oidc_config: OidcConfig,
    jwks_cache: JwksCache,
    agent_config: AgentConfig,
}

fn deps(storage: &DynStorage, tac_enabled: bool) -> Deps {
    let jwt_secret = "test_jwt_secret".to_string();
    let token_actor = oauth2_actix::actors::TokenActor::new(
        storage.clone(),
        jwt_secret.clone(),
        ISSUER.to_string(),
    )
    .start();
    Deps {
        token_pool: TokenActorPool::new(vec![token_actor]),
        client_actor: oauth2_actix::actors::ClientActor::new(storage.clone()).start(),
        auth_actor: oauth2_actix::actors::AuthActor::new(storage.clone()).start(),
        metrics: Metrics::new().expect("metrics"),
        oidc_config: OidcConfig {
            issuer: ISSUER.to_string(),
            jwt_secret,
            id_token_alg: "HS256".to_string(),
            id_token_kid: None,
            id_token_private_key_pem: None,
        },
        jwks_cache: JwksCache::new(),
        agent_config: AgentConfig {
            tac_enabled,
            ..Default::default()
        },
    }
}

fn basic_auth() -> String {
    format!(
        "Basic {}",
        general_purpose::STANDARD.encode(b"tac_client:tac_secret")
    )
}

fn enc(s: &str) -> String {
    percent_encoding::utf8_percent_encode(s, percent_encoding::NON_ALPHANUMERIC).to_string()
}

async fn test_set_session(session: Session) -> HttpResponse {
    session.insert("user_id", USER_ID).unwrap();
    session.insert("authenticated", true).unwrap();
    HttpResponse::Ok().finish()
}

/// Build the full app: challenge submission, approval page and token endpoint,
/// all sharing one storage handle, behind a session middleware so the approval
/// page can authenticate a user.
macro_rules! tac_app {
    ($storage:expr, $deps:expr) => {{
        let d = $deps;
        test::init_service(
            App::new()
                .wrap(SessionMiddleware::new(
                    CookieSessionStore::default(),
                    Key::generate(),
                ))
                .route("/test/login", web::get().to(test_set_session))
                .app_data(web::Data::new(d.token_pool))
                .app_data(web::Data::new(d.client_actor))
                .app_data(web::Data::new(d.auth_actor))
                .app_data(web::Data::new($storage.clone()))
                .app_data(web::Data::new(d.metrics))
                .app_data(web::Data::new(d.oidc_config))
                .app_data(web::Data::new(d.jwks_cache))
                .app_data(web::Data::new(d.agent_config))
                .service(
                    web::scope("/oauth")
                        .route(
                            "/transaction_authorization",
                            web::post().to(
                                oauth2_actix::handlers::transaction_authorization::transaction_authorization,
                            ),
                        )
                        .route(
                            "/transaction_authorization/approve",
                            web::get().to(
                                oauth2_actix::handlers::transaction_authorization::approve_page,
                            ),
                        )
                        .route(
                            "/transaction_authorization/approve",
                            web::post().to(
                                oauth2_actix::handlers::transaction_authorization::approve_submit,
                            ),
                        )
                        .route(
                            "/token",
                            web::post().to(oauth2_actix::handlers::oauth::token),
                        ),
                ),
        )
        .await
    }};
}

/// Submit a signed challenge as the test client.
macro_rules! submit {
    ($app:expr, $challenge:expr) => {{
        let req = test::TestRequest::post()
            .uri("/oauth/transaction_authorization")
            .insert_header(("Authorization", basic_auth()))
            .insert_header(("Content-Type", "application/x-www-form-urlencoded"))
            .set_payload(format!("transaction_challenge={}", enc($challenge)))
            .to_request();
        let resp = test::call_service(&$app, req).await;
        let status = resp.status();
        let body: Value = test::read_body_json(resp).await;
        (status, body)
    }};
}

/// Poll the token endpoint for a pending transaction authorization.
macro_rules! poll {
    ($app:expr, $id:expr) => {{
        let payload = format!(
            "grant_type={}&transaction_authorization_id={}",
            enc(GRANT_TRANSACTION_AUTHORIZATION),
            enc($id)
        );
        let req = test::TestRequest::post()
            .uri("/oauth/token")
            .insert_header(("Authorization", basic_auth()))
            .insert_header(("Content-Type", "application/x-www-form-urlencoded"))
            .set_payload(payload)
            .to_request();
        let resp = test::call_service(&$app, req).await;
        let status = resp.status();
        let body: Value = test::read_body_json(resp).await;
        (status, body)
    }};
}

/// Log in and return the session cookie.
macro_rules! login {
    ($app:expr) => {{
        let resp = test::call_service(
            &$app,
            test::TestRequest::get().uri("/test/login").to_request(),
        )
        .await;
        resp.response()
            .headers()
            .get(actix_web::http::header::SET_COOKIE)
            .and_then(|h| h.to_str().ok())
            .expect("session cookie should be set")
            .split(';')
            .next()
            .unwrap()
            .to_string()
    }};
}

/// Approve or deny through the human-facing form.
macro_rules! decide {
    ($app:expr, $cookie:expr, $id:expr, $action:expr) => {{
        let req = test::TestRequest::post()
            .uri("/oauth/transaction_authorization/approve")
            .insert_header(("Cookie", $cookie.to_string()))
            .insert_header(("Content-Type", "application/x-www-form-urlencoded"))
            .set_payload(format!(
                "transaction_authorization_id={}&action={}",
                enc($id),
                $action
            ))
            .to_request();
        test::call_service(&$app, req).await.status()
    }};
}

/// Decode a JWT access token without checking its audience.
fn decode_access_token(token: &str) -> Value {
    let mut validation = jsonwebtoken::Validation::new(Algorithm::HS256);
    validation.validate_aud = false;
    jsonwebtoken::decode::<Value>(
        token,
        &jsonwebtoken::DecodingKey::from_secret(b"test_jwt_secret"),
        &validation,
    )
    .expect("decode access token")
    .claims
}

// ---------------------------------------------------------------------------
// Submission validation
// ---------------------------------------------------------------------------

/// With `tac_enabled = false` the endpoint refuses every submission.
#[actix_web::test]
async fn submission_is_refused_when_the_flag_is_off() {
    let jwks_uri = spawn_jwks_server();
    let storage = setup(Some(&jwks_uri)).await;
    let app = tac_app!(storage, deps(&storage, false));

    let challenge = sign_challenge(&base_claims("flag-off-1"), true);
    let (status, body) = submit!(app, &challenge);

    assert_eq!(status, 400, "body: {body}");
    assert_eq!(body["error"], "invalid_request");
}

/// A challenge whose `iss` is not a registered protected resource is rejected.
#[actix_web::test]
async fn unknown_resource_issuer_is_rejected() {
    let jwks_uri = spawn_jwks_server();
    let storage = setup(Some(&jwks_uri)).await;
    let app = tac_app!(storage, deps(&storage, true));

    let mut claims = base_claims("unknown-iss-1");
    claims["iss"] = json!("https://not-registered.example");
    let challenge = sign_challenge(&claims, true);

    let (status, body) = submit!(app, &challenge);
    assert_eq!(status, 400, "body: {body}");
    assert_eq!(body["error"], "invalid_request");
}

/// A registered resource that publishes no `txn_challenge_jwks_uri` cannot
/// raise challenges at all.
#[actix_web::test]
async fn resource_without_challenge_jwks_is_rejected() {
    let storage = setup(None).await;
    let resource = ProtectedResource::new(
        RESOURCE_URI.to_string(),
        "Payments API".to_string(),
        vec!["payments".to_string()],
    );
    storage
        .save_resource(&resource)
        .await
        .expect("save resource");
    let app = tac_app!(storage, deps(&storage, true));

    let challenge = sign_challenge(&base_claims("no-jwks-1"), true);
    let (status, body) = submit!(app, &challenge);

    assert_eq!(status, 400, "body: {body}");
    assert_eq!(body["error"], "invalid_request");
}

/// A challenge signed by a key that is not in the resource's JWKS must fail.
#[actix_web::test]
async fn bad_signature_is_rejected() {
    let jwks_uri = spawn_jwks_server();
    let storage = setup(Some(&jwks_uri)).await;
    let app = tac_app!(storage, deps(&storage, true));

    let challenge = sign_challenge(&base_claims("bad-sig-1"), false);
    let (status, body) = submit!(app, &challenge);

    assert_eq!(status, 400, "body: {body}");
    assert_eq!(body["error"], "invalid_request");
}

/// `authorization_details` must be a JSON array.
#[actix_web::test]
async fn non_array_authorization_details_is_rejected() {
    let jwks_uri = spawn_jwks_server();
    let storage = setup(Some(&jwks_uri)).await;
    let app = tac_app!(storage, deps(&storage, true));

    let mut claims = base_claims("bad-rar-1");
    claims["authorization_details"] = json!({ "type": "payment_initiation" });
    let challenge = sign_challenge(&claims, true);

    let (status, body) = submit!(app, &challenge);
    assert_eq!(status, 400, "body: {body}");
    assert_eq!(body["error"], "invalid_request");
}

/// A `depth`-level `act` chain, outermost actor first.
fn nested_act(depth: usize) -> Value {
    let mut chain = json!({ "sub": "agent-0", "iss": "https://agent0.example" });
    for i in 1..depth {
        chain = json!({
            "sub": format!("agent-{i}"),
            "iss": format!("https://agent{i}.example"),
            "act": chain,
        });
    }
    chain
}

/// A resource must not be able to inject a delegation chain deeper than the
/// server's limit (default 4) into an issued token.
#[actix_web::test]
async fn deeply_nested_act_chain_is_rejected() {
    let jwks_uri = spawn_jwks_server();
    let storage = setup(Some(&jwks_uri)).await;
    let app = tac_app!(storage, deps(&storage, true));

    assert_eq!(AgentConfig::default().max_delegation_depth, 4);

    let mut claims = base_claims("deep-act-1");
    claims["act"] = nested_act(5);
    let challenge = sign_challenge(&claims, true);

    let (status, body) = submit!(app, &challenge);
    assert_eq!(status, 400, "body: {body}");
    assert_eq!(body["error"], "invalid_request");
}

/// An `act` chain within the limit survives challenge → approval page →
/// issued token.
#[actix_web::test]
async fn act_chain_flows_from_challenge_to_token() {
    let jwks_uri = spawn_jwks_server();
    let storage = setup(Some(&jwks_uri)).await;
    let app = tac_app!(storage, deps(&storage, true));

    let mut claims = base_claims("act-flow-1");
    claims["act"] = nested_act(1);
    let challenge = sign_challenge(&claims, true);

    let (status, body) = submit!(app, &challenge);
    assert_eq!(status, 200, "body: {body}");
    let id = body["transaction_authorization_id"]
        .as_str()
        .unwrap()
        .to_string();

    let cookie = login!(app);

    // The approving human is told which agent is acting.
    let req = test::TestRequest::get()
        .uri(&format!(
            "/oauth/transaction_authorization/approve?transaction_authorization_id={id}"
        ))
        .insert_header(("Cookie", cookie.clone()))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 200);
    let html = String::from_utf8(test::read_body(resp).await.to_vec()).expect("utf-8 body");
    assert!(html.contains("Acting agent: agent-0"), "html: {html}");

    assert_eq!(decide!(app, &cookie, &id, "approve"), 200);

    let (status, body) = poll!(app, &id);
    assert_eq!(status, 200, "body: {body}");
    let token_claims = decode_access_token(body["access_token"].as_str().expect("access_token"));
    assert_eq!(token_claims["act"]["sub"], "agent-0");
    assert_eq!(token_claims["act"]["iss"], "https://agent0.example");
    assert!(token_claims["act"]["act"].is_null());
}

/// The same challenge may not open two pending approvals (`jti` replay).
#[actix_web::test]
async fn replayed_challenge_jti_is_rejected() {
    let jwks_uri = spawn_jwks_server();
    let storage = setup(Some(&jwks_uri)).await;
    let app = tac_app!(storage, deps(&storage, true));

    let challenge = sign_challenge(&base_claims("replay-1"), true);
    let (status, body) = submit!(app, &challenge);
    assert_eq!(status, 200, "body: {body}");

    let (status, body) = submit!(app, &challenge);
    assert_eq!(status, 400, "body: {body}");
    assert_eq!(body["error"], "invalid_request");
}

// ---------------------------------------------------------------------------
// Approval page
// ---------------------------------------------------------------------------

/// Without a session the approval page bounces the user to the login form.
#[actix_web::test]
async fn approval_page_requires_a_session() {
    let jwks_uri = spawn_jwks_server();
    let storage = setup(Some(&jwks_uri)).await;
    let app = tac_app!(storage, deps(&storage, true));

    let challenge = sign_challenge(&base_claims("page-auth-1"), true);
    let (_, body) = submit!(app, &challenge);
    let id = body["transaction_authorization_id"].as_str().unwrap();

    let req = test::TestRequest::get()
        .uri(&format!(
            "/oauth/transaction_authorization/approve?transaction_authorization_id={id}"
        ))
        .to_request();
    let resp = test::call_service(&app, req).await;

    assert_eq!(resp.status(), 302);
    assert_eq!(
        resp.headers().get("Location").unwrap().to_str().unwrap(),
        "/auth/login"
    );
}

/// An unauthenticated POST cannot settle a pending approval either — the
/// redirect on the GET is a convenience, not the access control.
#[actix_web::test]
async fn approval_submit_requires_a_session() {
    let jwks_uri = spawn_jwks_server();
    let storage = setup(Some(&jwks_uri)).await;
    let app = tac_app!(storage, deps(&storage, true));

    let challenge = sign_challenge(&base_claims("submit-auth-1"), true);
    let (_, body) = submit!(app, &challenge);
    let id = body["transaction_authorization_id"]
        .as_str()
        .unwrap()
        .to_string();

    let req = test::TestRequest::post()
        .uri("/oauth/transaction_authorization/approve")
        .insert_header(("Content-Type", "application/x-www-form-urlencoded"))
        .set_payload(format!(
            "transaction_authorization_id={}&action=approve",
            enc(&id)
        ))
        .to_request();
    assert_eq!(test::call_service(&app, req).await.status(), 403);

    // The transaction is still pending, so the unauthenticated POST changed
    // nothing.
    let (status, body) = poll!(app, &id);
    assert_eq!(status, 400, "body: {body}");
    assert_eq!(body["error"], "authorization_pending");
}

/// The page shows the reason, the requesting client and the requested
/// authorization details.
#[actix_web::test]
async fn approval_page_shows_the_pending_operation() {
    let jwks_uri = spawn_jwks_server();
    let storage = setup(Some(&jwks_uri)).await;
    let app = tac_app!(storage, deps(&storage, true));

    let challenge = sign_challenge(&base_claims("page-render-1"), true);
    let (_, body) = submit!(app, &challenge);
    let id = body["transaction_authorization_id"].as_str().unwrap();
    let cookie = login!(app);

    let req = test::TestRequest::get()
        .uri(&format!(
            "/oauth/transaction_authorization/approve?transaction_authorization_id={id}"
        ))
        .insert_header(("Cookie", cookie))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 200);

    let html = String::from_utf8(test::read_body(resp).await.to_vec()).expect("utf-8 body");
    assert!(html.contains("Transfer 42.00 EUR to ACME Ltd"));
    assert!(html.contains("Payments Agent"));
    assert!(html.contains("payment_initiation"));
}

// ---------------------------------------------------------------------------
// Polling grant
// ---------------------------------------------------------------------------

/// submit → poll (pending) → approve → poll (token) → poll again (spent).
#[actix_web::test]
async fn approved_transaction_issues_a_token_carrying_txn() {
    let jwks_uri = spawn_jwks_server();
    let storage = setup(Some(&jwks_uri)).await;
    let app = tac_app!(storage, deps(&storage, true));

    let challenge = sign_challenge(&base_claims("happy-1"), true);
    let (status, body) = submit!(app, &challenge);
    assert_eq!(status, 200, "body: {body}");
    assert_eq!(body["interval"], 5);
    assert!(body["expires_in"].as_i64().unwrap() > 0);
    let id = body["transaction_authorization_id"]
        .as_str()
        .expect("handle")
        .to_string();

    // Nobody has approved yet.
    let (status, body) = poll!(app, &id);
    assert_eq!(status, 400, "body: {body}");
    assert_eq!(body["error"], "authorization_pending");

    // A human approves through an authenticated session.
    let cookie = login!(app);
    assert_eq!(decide!(app, &cookie, &id, "approve"), 200);

    let (status, body) = poll!(app, &id);
    assert_eq!(status, 200, "body: {body}");
    assert_eq!(body["authorization_details"], authorization_details());
    assert_eq!(body["resource"], RESOURCE_URI);
    assert!(body["refresh_token"].is_null());
    // The token is capped at the per-transaction ceiling.
    assert!(body["expires_in"].as_i64().unwrap() <= 300);

    let claims = decode_access_token(body["access_token"].as_str().expect("access_token"));
    assert_eq!(claims["txn"], "txn-abc-123");
    assert_eq!(claims["authorization_details"], authorization_details());
    assert_eq!(claims["aud"], RESOURCE_URI);
    assert_eq!(claims["sub"], USER_ID);

    // The handle is single-use.
    let (status, body) = poll!(app, &id);
    assert_eq!(status, 400, "body: {body}");
    assert_eq!(body["error"], "invalid_grant");
}

/// A denied transaction never yields a token.
#[actix_web::test]
async fn denied_transaction_returns_access_denied() {
    let jwks_uri = spawn_jwks_server();
    let storage = setup(Some(&jwks_uri)).await;
    let app = tac_app!(storage, deps(&storage, true));

    let challenge = sign_challenge(&base_claims("deny-1"), true);
    let (_, body) = submit!(app, &challenge);
    let id = body["transaction_authorization_id"]
        .as_str()
        .unwrap()
        .to_string();

    let cookie = login!(app);
    assert_eq!(decide!(app, &cookie, &id, "deny"), 200);

    let (status, body) = poll!(app, &id);
    assert_eq!(status, 403, "body: {body}");
    assert_eq!(body["error"], "access_denied");
}

/// Fail closed: an `action` the form did not offer is a denial, never a
/// silent approval.
#[actix_web::test]
async fn an_unrecognised_action_denies_the_transaction() {
    let jwks_uri = spawn_jwks_server();
    let storage = setup(Some(&jwks_uri)).await;
    let app = tac_app!(storage, deps(&storage, true));

    let challenge = sign_challenge(&base_claims("deny-2"), true);
    let (_, body) = submit!(app, &challenge);
    let id = body["transaction_authorization_id"]
        .as_str()
        .unwrap()
        .to_string();

    let cookie = login!(app);
    assert_eq!(decide!(app, &cookie, &id, "maybe"), 200);

    let (status, body) = poll!(app, &id);
    assert_eq!(status, 403, "body: {body}");
    assert_eq!(body["error"], "access_denied");
}

/// An approval that timed out before the client polled is `expired_token`.
#[actix_web::test]
async fn expired_transaction_returns_expired_token() {
    let storage = setup(None).await;
    let app = tac_app!(storage, deps(&storage, true));

    let mut record = TransactionAuthorization::new(
        "tac_client".to_string(),
        RESOURCE_URI.to_string(),
        "txn-expired".to_string(),
        authorization_details().to_string(),
        600,
    );
    record.approved = true;
    record.user_id = Some(USER_ID.to_string());
    record.expires_at = chrono::Utc::now() - chrono::Duration::seconds(1);
    storage
        .save_transaction_authorization(&record)
        .await
        .expect("save record");

    let (status, body) = poll!(app, &record.transaction_authorization_id);
    assert_eq!(status, 400, "body: {body}");
    assert_eq!(body["error"], "expired_token");
}

/// A handle belonging to another client is not redeemable.
#[actix_web::test]
async fn handle_from_another_client_is_rejected() {
    let storage = setup(None).await;
    let app = tac_app!(storage, deps(&storage, true));

    let mut record = TransactionAuthorization::new(
        "someone_else".to_string(),
        RESOURCE_URI.to_string(),
        "txn-other".to_string(),
        authorization_details().to_string(),
        600,
    );
    record.approved = true;
    record.user_id = Some(USER_ID.to_string());
    storage
        .save_transaction_authorization(&record)
        .await
        .expect("save record");

    let (status, body) = poll!(app, &record.transaction_authorization_id);
    assert_eq!(status, 400, "body: {body}");
    assert_eq!(body["error"], "invalid_grant");
}

/// An unknown handle is `invalid_grant`, not a 500.
#[actix_web::test]
async fn unknown_handle_is_invalid_grant() {
    let storage = setup(None).await;
    let app = tac_app!(storage, deps(&storage, true));

    let (status, body) = poll!(app, "no-such-handle");
    assert_eq!(status, 400, "body: {body}");
    assert_eq!(body["error"], "invalid_grant");
}
