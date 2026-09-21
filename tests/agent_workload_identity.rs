//! Task 16 (Phase 7 agent / A2A OAuth): workload identity polish.
//!
//! Covers:
//!   * RFC 8705 §2.1.2 SAN-based mTLS client authentication
//!     (`tls_client_auth_san_uri` / `tls_client_auth_san_dns`).
//!   * RFC 7591 §2.3 software statements signed by a trusted issuer.
//!   * The `sub_profile` claim on access tokens (`user` / `service` / `ai_agent`).
//!   * The AI-agent access-token TTL cap.
//!
//! Software statements are minted with a test RSA key whose public half is
//! served as a JWKS document from an in-process actix server bound to an
//! ephemeral loopback port, mirroring `tests/agent_jwt_bearer_grant.rs`.

use std::sync::OnceLock;

use actix::Actor;
use actix_web::{test, web, App, HttpResponse, HttpServer};
use base64::{engine::general_purpose, Engine as _};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header as JwtHeader};
use rsa::pkcs1::EncodeRsaPrivateKey;
use rsa::traits::PublicKeyParts;
use rsa::{RsaPrivateKey, RsaPublicKey};
use serde_json::{json, Value};

use oauth2_actix::actors::{CreateToken, TokenActorPool};
use oauth2_actix::handlers::jwks_cache::JwksCache;
use oauth2_actix::handlers::wellknown::OidcConfig;
use oauth2_config::AgentConfig;
use oauth2_core::models::actor::{SUB_PROFILE_AI_AGENT, SUB_PROFILE_SERVICE, SUB_PROFILE_USER};
use oauth2_core::{Claims, Client, TrustedIssuer};
use oauth2_observability::Metrics;
use oauth2_ports::DynStorage;

const ISSUER: &str = "http://localhost";
const JWT_SECRET: &str = "test_jwt_secret";
const TRUSTED_ISS: &str = "https://statements.example";
const TEST_KID: &str = "workload-kid-1";
const THUMBPRINT: &str = "dGVzdC10aHVtYnByaW50LXZhbHVl";
const SAN_URI: &str = "spiffe://example.test/ns/agents/sa/planner";
const SAN_DNS: &str = "planner.agents.example.test";

// ---------------------------------------------------------------------------
// Signing key + JWKS server
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
            "alg": "RS256",
            "use": "sig",
            "kid": TEST_KID,
            "n": general_purpose::URL_SAFE_NO_PAD.encode(public_key.n().to_bytes_be()),
            "e": general_purpose::URL_SAFE_NO_PAD.encode(public_key.e().to_bytes_be()),
        });
        (pem, jwk)
    })
}

/// A second keypair: produces statements whose signature does not verify
/// against the issuer's published JWKS.
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

fn sign_statement(claims: &Value, valid_sig: bool) -> String {
    let mut header = JwtHeader::new(Algorithm::RS256);
    header.kid = Some(TEST_KID.to_string());
    let pem = if valid_sig {
        &signer().0
    } else {
        wrong_signer()
    };
    let key = EncodingKey::from_rsa_pem(pem.as_bytes()).expect("encoding key");
    encode(&header, claims, &key).expect("sign software statement")
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/// A unique file-backed SQLite database per test. `sqlite::memory:` creates a
/// fresh database per pooled connection, so a multi-connection pool can lose
/// writes when a later read lands on a different connection — these tests
/// write a client (or a trusted issuer) and read it back through a handler.
async fn setup_storage() -> DynStorage {
    let tmp = tempfile::NamedTempFile::new().expect("tempfile");
    let url = format!("sqlite://{}", tmp.path().display());
    // Leak the guard so the file outlives the test — Drop removes it.
    std::mem::forget(tmp);
    let storage = oauth2_storage_factory::create_storage(&url)
        .await
        .expect("create storage");
    storage.init().await.expect("init storage");
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

fn deps(storage: &DynStorage, agent_config: AgentConfig) -> Deps {
    let token_actor = oauth2_actix::actors::TokenActor::new(
        storage.clone(),
        JWT_SECRET.to_string(),
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
            jwt_secret: JWT_SECRET.to_string(),
            id_token_alg: "HS256".to_string(),
            id_token_kid: None,
            id_token_private_key_pem: None,
        },
        jwks_cache: JwksCache::new(),
        agent_config,
    }
}

/// A confidential client that authenticates with a SAN-bound certificate.
fn san_client(client_id: &str, auth_method: &str, san: &str) -> Client {
    let mut client = Client::new(
        client_id.to_string(),
        String::new(),
        vec!["https://unused.example/cb".to_string()],
        vec!["client_credentials".to_string()],
        "read write".to_string(),
        "SAN mTLS test client".to_string(),
    );
    client.token_endpoint_auth_method = auth_method.to_string();
    client.tls_client_auth_san = san.to_string();
    client
}

/// POST the token endpoint with an inline App (per project convention).
macro_rules! post_token {
    ($storage:expr, $deps:expr, $body:expr, $headers:expr) => {{
        let d = $deps;
        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(d.token_pool))
                .app_data(web::Data::new(d.client_actor))
                .app_data(web::Data::new(d.auth_actor))
                .app_data(web::Data::new($storage.clone()))
                .app_data(web::Data::new(d.metrics))
                .app_data(web::Data::new(d.oidc_config))
                .app_data(web::Data::new(d.jwks_cache))
                .app_data(web::Data::new(d.agent_config))
                .service(web::scope("/oauth").route(
                    "/token",
                    web::post().to(oauth2_actix::handlers::oauth::token),
                )),
        )
        .await;

        let mut req = test::TestRequest::post()
            .uri("/oauth/token")
            .insert_header(("Content-Type", "application/x-www-form-urlencoded"));
        for (name, value) in $headers {
            req = req.insert_header((name, value));
        }
        let req = req.set_payload($body).to_request();

        let resp = test::call_service(&app, req).await;
        let status = resp.status();
        let body: Value = test::read_body_json(resp).await;
        (status, body)
    }};
}

fn cc_body(client_id: &str) -> String {
    format!("grant_type=client_credentials&client_id={client_id}&scope=read")
}

// ---------------------------------------------------------------------------
// RFC 8705 §2.1.2 — SAN-based mTLS client authentication
// ---------------------------------------------------------------------------

#[actix_web::test]
async fn san_uri_auth_succeeds_when_the_forwarded_san_matches() {
    let storage = setup_storage().await;
    storage
        .save_client(&san_client(
            "san_uri_ok",
            "tls_client_auth_san_uri",
            SAN_URI,
        ))
        .await
        .expect("save client");

    let (status, body) = post_token!(
        storage,
        deps(&storage, AgentConfig::default()),
        cc_body("san_uri_ok"),
        [
            ("X-Client-Cert-Thumbprint", THUMBPRINT),
            ("X-SSL-Client-SAN-URI", SAN_URI),
            ("X-SSL-Client-SAN-DNS", SAN_DNS),
        ]
    );

    assert_eq!(status, 200, "body: {body}");
    assert!(body.get("access_token").is_some(), "body: {body}");
}

#[actix_web::test]
async fn san_uri_auth_rejects_a_mismatched_san() {
    let storage = setup_storage().await;
    storage
        .save_client(&san_client(
            "san_uri_bad",
            "tls_client_auth_san_uri",
            SAN_URI,
        ))
        .await
        .expect("save client");

    let (status, body) = post_token!(
        storage,
        deps(&storage, AgentConfig::default()),
        cc_body("san_uri_bad"),
        [
            ("X-Client-Cert-Thumbprint", THUMBPRINT),
            (
                "X-SSL-Client-SAN-URI",
                "spiffe://example.test/ns/other/sa/x"
            ),
            ("X-SSL-Client-SAN-DNS", SAN_DNS),
        ]
    );

    assert_eq!(status, 401, "body: {body}");
    assert_eq!(body["error"], "invalid_client", "body: {body}");
}

/// The DNS SAN must not be accepted in place of the URI SAN: each auth method
/// reads exactly one header.
#[actix_web::test]
async fn san_uri_auth_does_not_fall_back_to_the_dns_header() {
    let storage = setup_storage().await;
    storage
        .save_client(&san_client(
            "san_uri_only",
            "tls_client_auth_san_uri",
            SAN_DNS,
        ))
        .await
        .expect("save client");

    let (status, body) = post_token!(
        storage,
        deps(&storage, AgentConfig::default()),
        cc_body("san_uri_only"),
        [
            ("X-Client-Cert-Thumbprint", THUMBPRINT),
            ("X-SSL-Client-SAN-DNS", SAN_DNS),
        ]
    );

    assert_eq!(status, 401, "body: {body}");
    assert_eq!(body["error"], "invalid_client", "body: {body}");
}

#[actix_web::test]
async fn san_dns_auth_succeeds_when_the_forwarded_san_matches() {
    let storage = setup_storage().await;
    storage
        .save_client(&san_client(
            "san_dns_ok",
            "tls_client_auth_san_dns",
            SAN_DNS,
        ))
        .await
        .expect("save client");

    let (status, body) = post_token!(
        storage,
        deps(&storage, AgentConfig::default()),
        cc_body("san_dns_ok"),
        [
            ("X-Client-Cert-Thumbprint", THUMBPRINT),
            ("X-SSL-Client-SAN-URI", SAN_URI),
            ("X-SSL-Client-SAN-DNS", SAN_DNS),
        ]
    );

    assert_eq!(status, 200, "body: {body}");
    assert!(body.get("access_token").is_some(), "body: {body}");
}

#[actix_web::test]
async fn san_dns_auth_rejects_a_mismatched_san() {
    let storage = setup_storage().await;
    storage
        .save_client(&san_client(
            "san_dns_bad",
            "tls_client_auth_san_dns",
            SAN_DNS,
        ))
        .await
        .expect("save client");

    let (status, body) = post_token!(
        storage,
        deps(&storage, AgentConfig::default()),
        cc_body("san_dns_bad"),
        [
            ("X-Client-Cert-Thumbprint", THUMBPRINT),
            ("X-SSL-Client-SAN-DNS", "impostor.agents.example.test"),
        ]
    );

    assert_eq!(status, 401, "body: {body}");
    assert_eq!(body["error"], "invalid_client", "body: {body}");
}

/// The certificate thumbprint header is still mandatory: a matching SAN alone
/// proves nothing, since only the proxy's mTLS termination vouches for it.
#[actix_web::test]
async fn san_auth_still_requires_the_certificate_thumbprint() {
    let storage = setup_storage().await;
    storage
        .save_client(&san_client(
            "san_no_thumb",
            "tls_client_auth_san_uri",
            SAN_URI,
        ))
        .await
        .expect("save client");

    let (status, body) = post_token!(
        storage,
        deps(&storage, AgentConfig::default()),
        cc_body("san_no_thumb"),
        [("X-SSL-Client-SAN-URI", SAN_URI)]
    );

    assert_eq!(status, 401, "body: {body}");
    assert_eq!(body["error"], "invalid_client", "body: {body}");
}

/// A client registered for SAN auth without a SAN has no binding at all, so it
/// must be refused rather than treated as "any certificate will do".
#[actix_web::test]
async fn san_auth_rejects_a_client_without_a_registered_san() {
    let storage = setup_storage().await;
    storage
        .save_client(&san_client("san_empty", "tls_client_auth_san_uri", ""))
        .await
        .expect("save client");

    let (status, body) = post_token!(
        storage,
        deps(&storage, AgentConfig::default()),
        cc_body("san_empty"),
        [
            ("X-Client-Cert-Thumbprint", THUMBPRINT),
            ("X-SSL-Client-SAN-URI", SAN_URI),
        ]
    );

    assert_eq!(status, 401, "body: {body}");
    assert_eq!(body["error"], "invalid_client", "body: {body}");
}

// ---------------------------------------------------------------------------
// RFC 8414 / RFC 8705 §5 — discovery metadata
// ---------------------------------------------------------------------------

#[actix_web::test]
async fn discovery_advertises_san_auth_methods_and_mtls_aliases() {
    let storage = setup_storage().await;
    let d = deps(&storage, AgentConfig::default());
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(d.token_pool))
            .app_data(web::Data::new(d.client_actor))
            .app_data(web::Data::new(d.auth_actor))
            .app_data(web::Data::new(d.metrics))
            .app_data(web::Data::new(d.oidc_config))
            .app_data(web::Data::new(d.agent_config))
            .route(
                "/.well-known/openid-configuration",
                web::get().to(oauth2_actix::handlers::wellknown::openid_configuration),
            ),
    )
    .await;

    let req = test::TestRequest::get()
        .uri("/.well-known/openid-configuration")
        .to_request();
    let body: Value = test::call_and_read_body_json(&app, req).await;

    let methods = body["token_endpoint_auth_methods_supported"]
        .as_array()
        .expect("auth methods array");
    assert!(
        methods.contains(&json!("tls_client_auth_san_uri")),
        "{body}"
    );
    assert!(
        methods.contains(&json!("tls_client_auth_san_dns")),
        "{body}"
    );

    let aliases = &body["mtls_endpoint_aliases"];
    assert_eq!(
        aliases["token_endpoint"],
        json!("http://localhost/oauth/token")
    );
    assert_eq!(
        aliases["introspection_endpoint"],
        json!("http://localhost/oauth/introspect")
    );
    assert_eq!(
        aliases["revocation_endpoint"],
        json!("http://localhost/oauth/revoke")
    );
}

// ---------------------------------------------------------------------------
// RFC 7591 §2.3 — software statements
// ---------------------------------------------------------------------------

/// Register the trusted issuer that signs software statements.
async fn setup_statement_issuer(storage: &DynStorage, jwks_uri: &str) {
    let trusted = TrustedIssuer::new(TRUSTED_ISS.to_string(), jwks_uri.to_string());
    storage
        .save_trusted_issuer(&trusted)
        .await
        .expect("save trusted issuer");
}

macro_rules! post_register {
    ($storage:expr, $deps:expr, $body:expr) => {{
        let d = $deps;
        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(d.client_actor))
                .app_data(web::Data::new($storage.clone()))
                .app_data(web::Data::new(d.jwks_cache))
                .route(
                    "/admin/clients/register",
                    web::post().to(oauth2_actix::handlers::client::register_client),
                ),
        )
        .await;

        let req = test::TestRequest::post()
            .uri("/admin/clients/register")
            .set_json($body)
            .to_request();
        let resp = test::call_service(&app, req).await;
        let status = resp.status();
        let body: Value = test::read_body_json(resp).await;
        (status, body)
    }};
}

#[actix_web::test]
async fn software_statement_claims_override_the_request_body() {
    let jwks_uri = spawn_jwks_server();
    let storage = setup_storage().await;
    setup_statement_issuer(&storage, &jwks_uri).await;

    let now = chrono::Utc::now().timestamp();
    let statement = sign_statement(
        &json!({
            "iss": TRUSTED_ISS,
            "iat": now,
            "exp": now + 300,
            "software_id": "agent:planner",
            "software_version": "4.2.0",
            "client_name": "Planner Agent (attested)",
            "redirect_uris": ["https://attested.example/cb"],
            "grant_types": ["client_credentials"],
            "scope": "read",
        }),
        true,
    );

    let (status, body) = post_register!(
        storage,
        deps(&storage, AgentConfig::default()),
        json!({
            "client_name": "Self-asserted name",
            "redirect_uris": ["https://self-asserted.example/cb"],
            "grant_types": ["authorization_code"],
            "scope": "read",
            "token_endpoint_auth_method": "client_secret_basic",
            "software_id": "not-an-agent",
            "software_statement": statement,
        })
    );

    assert_eq!(status, 201, "body: {body}");
    let client_id = body["client_id"].as_str().expect("client_id").to_string();

    let stored = storage
        .get_client(&client_id)
        .await
        .expect("lookup")
        .expect("client exists");
    assert_eq!(stored.name, "Planner Agent (attested)");
    assert_eq!(stored.software_id, "agent:planner");
    assert_eq!(stored.software_version, "4.2.0");
    assert_eq!(
        stored.get_redirect_uris(),
        vec!["https://attested.example/cb".to_string()]
    );
    assert_eq!(
        stored.get_grant_types(),
        vec!["client_credentials".to_string()]
    );
}

#[actix_web::test]
async fn software_statement_with_a_bad_signature_is_rejected() {
    let jwks_uri = spawn_jwks_server();
    let storage = setup_storage().await;
    setup_statement_issuer(&storage, &jwks_uri).await;

    let now = chrono::Utc::now().timestamp();
    let statement = sign_statement(
        &json!({
            "iss": TRUSTED_ISS,
            "iat": now,
            "exp": now + 300,
            "software_id": "agent:forged",
        }),
        false,
    );

    let (status, body) = post_register!(
        storage,
        deps(&storage, AgentConfig::default()),
        json!({
            "client_name": "Forged",
            "redirect_uris": ["https://forged.example/cb"],
            "grant_types": ["client_credentials"],
            "scope": "read",
            "token_endpoint_auth_method": "client_secret_basic",
            "software_statement": statement,
        })
    );

    assert_eq!(status, 400, "body: {body}");
    assert_eq!(body["error"], "invalid_software_statement", "body: {body}");
}

#[actix_web::test]
async fn software_statement_from_an_unknown_issuer_is_rejected() {
    let jwks_uri = spawn_jwks_server();
    let storage = setup_storage().await;
    setup_statement_issuer(&storage, &jwks_uri).await;

    let now = chrono::Utc::now().timestamp();
    let statement = sign_statement(
        &json!({
            "iss": "https://not-registered.example",
            "iat": now,
            "exp": now + 300,
            "software_id": "agent:stranger",
        }),
        true,
    );

    let (status, body) = post_register!(
        storage,
        deps(&storage, AgentConfig::default()),
        json!({
            "client_name": "Stranger",
            "redirect_uris": ["https://stranger.example/cb"],
            "grant_types": ["client_credentials"],
            "scope": "read",
            "token_endpoint_auth_method": "client_secret_basic",
            "software_statement": statement,
        })
    );

    assert_eq!(status, 400, "body: {body}");
    assert_eq!(body["error"], "invalid_software_statement", "body: {body}");
}

#[actix_web::test]
async fn software_statement_that_is_not_a_jwt_is_rejected() {
    let storage = setup_storage().await;

    let (status, body) = post_register!(
        storage,
        deps(&storage, AgentConfig::default()),
        json!({
            "client_name": "Garbage",
            "redirect_uris": ["https://garbage.example/cb"],
            "grant_types": ["client_credentials"],
            "scope": "read",
            "token_endpoint_auth_method": "client_secret_basic",
            "software_statement": "this-is-not-a-jwt",
        })
    );

    assert_eq!(status, 400, "body: {body}");
    assert_eq!(body["error"], "invalid_software_statement", "body: {body}");
}

/// A client registering for SAN auth must supply the SAN it will be matched on.
#[actix_web::test]
async fn registration_requires_a_san_for_san_auth_methods() {
    let storage = setup_storage().await;

    let (status, body) = post_register!(
        storage,
        deps(&storage, AgentConfig::default()),
        json!({
            "client_name": "No SAN",
            "redirect_uris": ["https://no-san.example/cb"],
            "grant_types": ["client_credentials"],
            "scope": "read",
            "token_endpoint_auth_method": "tls_client_auth_san_uri",
        })
    );

    assert_eq!(status, 400, "body: {body}");
    assert_eq!(body["error"], "invalid_request", "body: {body}");
}

#[actix_web::test]
async fn registration_stores_the_san_for_san_auth_methods() {
    let storage = setup_storage().await;

    let (status, body) = post_register!(
        storage,
        deps(&storage, AgentConfig::default()),
        json!({
            "client_name": "With SAN",
            "redirect_uris": ["https://with-san.example/cb"],
            "grant_types": ["client_credentials"],
            "scope": "read",
            "token_endpoint_auth_method": "tls_client_auth_san_uri",
            "tls_client_auth_san": SAN_URI,
        })
    );

    assert_eq!(status, 201, "body: {body}");
    let client_id = body["client_id"].as_str().expect("client_id").to_string();
    let stored = storage
        .get_client(&client_id)
        .await
        .expect("lookup")
        .expect("client exists");
    assert_eq!(stored.tls_client_auth_san, SAN_URI);
}

// ---------------------------------------------------------------------------
// `sub_profile` on access tokens
// ---------------------------------------------------------------------------

fn claims_of(body: &Value) -> Claims {
    let token = body["access_token"].as_str().expect("access_token");
    Claims::decode_unverified(token).expect("decode access token")
}

#[actix_web::test]
async fn client_credentials_token_carries_the_service_sub_profile() {
    let storage = setup_storage().await;
    storage
        .save_client(&san_client("plain_svc", "tls_client_auth_san_uri", SAN_URI))
        .await
        .expect("save client");

    let (status, body) = post_token!(
        storage,
        deps(&storage, AgentConfig::default()),
        cc_body("plain_svc"),
        [
            ("X-Client-Cert-Thumbprint", THUMBPRINT),
            ("X-SSL-Client-SAN-URI", SAN_URI),
        ]
    );

    assert_eq!(status, 200, "body: {body}");
    assert_eq!(
        claims_of(&body).sub_profile.as_deref(),
        Some(SUB_PROFILE_SERVICE)
    );
}

#[actix_web::test]
async fn agent_client_credentials_token_carries_the_ai_agent_sub_profile() {
    let storage = setup_storage().await;
    let mut client = san_client("agent_svc", "tls_client_auth_san_uri", SAN_URI);
    client.software_id = "agent:planner".to_string();
    storage.save_client(&client).await.expect("save client");

    let (status, body) = post_token!(
        storage,
        deps(&storage, AgentConfig::default()),
        cc_body("agent_svc"),
        [
            ("X-Client-Cert-Thumbprint", THUMBPRINT),
            ("X-SSL-Client-SAN-URI", SAN_URI),
        ]
    );

    assert_eq!(status, 200, "body: {body}");
    assert_eq!(
        claims_of(&body).sub_profile.as_deref(),
        Some(SUB_PROFILE_AI_AGENT)
    );
}

/// A client with a delegation allow-list is an agent even without an
/// `agent:`-prefixed `software_id`.
#[actix_web::test]
async fn allowed_actors_also_select_the_ai_agent_sub_profile() {
    let storage = setup_storage().await;
    let mut client = san_client("delegating_svc", "tls_client_auth_san_uri", SAN_URI);
    client.allowed_actors = json!(["some_other_client"]).to_string();
    storage.save_client(&client).await.expect("save client");

    let (status, body) = post_token!(
        storage,
        deps(&storage, AgentConfig::default()),
        cc_body("delegating_svc"),
        [
            ("X-Client-Cert-Thumbprint", THUMBPRINT),
            ("X-SSL-Client-SAN-URI", SAN_URI),
        ]
    );

    assert_eq!(status, 200, "body: {body}");
    assert_eq!(
        claims_of(&body).sub_profile.as_deref(),
        Some(SUB_PROFILE_AI_AGENT)
    );
}

#[actix_web::test]
async fn user_token_carries_the_user_sub_profile() {
    let storage = setup_storage().await;
    // The tokens table has FKs onto clients and users.
    storage
        .save_client(&san_client("some_client", "client_secret_basic", ""))
        .await
        .expect("save client");
    let user = oauth2_core::User::new(
        "user-42".to_string(),
        "hash".to_string(),
        "user42@example.test".to_string(),
    );
    storage.save_user(&user).await.expect("save user");

    let token_actor = oauth2_actix::actors::TokenActor::new(
        storage.clone(),
        JWT_SECRET.to_string(),
        ISSUER.to_string(),
    )
    .start();

    let token = token_actor
        .send(CreateToken {
            user_id: Some(user.id.clone()),
            client_id: "some_client".to_string(),
            scope: "read".to_string(),
            include_refresh: false,
            token_family: None,
            resources: vec![],
            cnf: None,
            authorization_details: None,
            act: None,
            ttl_override_secs: None,
            sub_profile: None,
            span: tracing::Span::current(),
        })
        .await
        .expect("mailbox")
        .expect("create token");

    let claims = Claims::decode_unverified(&token.access_token).expect("decode");
    assert_eq!(claims.sub_profile.as_deref(), Some(SUB_PROFILE_USER));
}

// ---------------------------------------------------------------------------
// AI-agent access-token TTL cap
// ---------------------------------------------------------------------------

#[actix_web::test]
async fn ai_agent_access_token_ttl_is_capped() {
    let storage = setup_storage().await;
    let mut client = san_client("capped_agent", "tls_client_auth_san_uri", SAN_URI);
    client.software_id = "agent:planner".to_string();
    storage.save_client(&client).await.expect("save client");

    let agent_config = AgentConfig {
        ai_agent_access_token_ttl_secs: Some(60),
        ..Default::default()
    };
    let (status, body) = post_token!(
        storage,
        deps(&storage, agent_config),
        cc_body("capped_agent"),
        [
            ("X-Client-Cert-Thumbprint", THUMBPRINT),
            ("X-SSL-Client-SAN-URI", SAN_URI),
        ]
    );

    assert_eq!(status, 200, "body: {body}");
    let claims = claims_of(&body);
    assert_eq!(claims.exp - claims.iat, 60, "body: {body}");
    assert_eq!(body["expires_in"], json!(60), "body: {body}");
}

/// The cap only shortens: a non-agent client keeps the default lifetime even
/// when the agent cap is configured.
#[actix_web::test]
async fn ttl_cap_does_not_apply_to_non_agent_clients() {
    let storage = setup_storage().await;
    storage
        .save_client(&san_client(
            "uncapped_svc",
            "tls_client_auth_san_uri",
            SAN_URI,
        ))
        .await
        .expect("save client");

    let agent_config = AgentConfig {
        ai_agent_access_token_ttl_secs: Some(60),
        ..Default::default()
    };
    let (status, body) = post_token!(
        storage,
        deps(&storage, agent_config),
        cc_body("uncapped_svc"),
        [
            ("X-Client-Cert-Thumbprint", THUMBPRINT),
            ("X-SSL-Client-SAN-URI", SAN_URI),
        ]
    );

    assert_eq!(status, 200, "body: {body}");
    let claims = claims_of(&body);
    assert_eq!(claims.exp - claims.iat, 3600, "body: {body}");
}
