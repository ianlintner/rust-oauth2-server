//! Task 10 (Phase 7 agent / A2A OAuth): RFC 7523 §2.1 JWT-bearer
//! authorization grant backed by the trusted-issuers registry, plus ID-JAG
//! (`draft-ietf-oauth-identity-assertion-authz-grant-04`) acceptance.
//!
//! Assertions are minted with a test RSA key whose public half is served as a
//! JWKS document from an in-process actix server bound to an ephemeral
//! loopback port; that URL is registered as the trusted issuer's `jwks_uri`
//! so the production `JwksCache` fetches it for real.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};

use actix::Actor;
use actix_web::{test, web, App, HttpResponse, HttpServer};
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
    token_types::GRANT_JWT_BEARER, AuthorizationCode, Client, OAuth2Error, ProtectedResource,
    Token, TrustedIssuer, User,
};
use oauth2_observability::Metrics;
use oauth2_ports::DynStorage;

const ISSUER: &str = "http://localhost";
const TOKEN_ENDPOINT: &str = "http://localhost/oauth/token";
const TRUSTED_ISS: &str = "https://idp.example";
const ID_JAG_TYP: &str = "oauth-id-jag+jwt";
const TEST_KID: &str = "test-kid-1";

// ---------------------------------------------------------------------------
// Signing key + JWKS server
// ---------------------------------------------------------------------------

/// RSA keypair used to sign assertions. Generated once per test binary —
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

/// A second keypair, used to produce assertions whose signature does not
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

/// Spawn an in-process JWKS endpoint on an ephemeral loopback port and return
/// its absolute URL. Mirrors the pattern used by the CIMD fetcher tests.
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
// Assertion minting
// ---------------------------------------------------------------------------

/// Sign `claims` with the trusted key (or the wrong key when `valid_sig` is
/// false), optionally stamping a JOSE `typ`.
fn sign_assertion(claims: &Value, typ: Option<&str>, valid_sig: bool) -> String {
    let mut header = JwtHeader::new(Algorithm::RS256);
    header.kid = Some(TEST_KID.to_string());
    if let Some(typ) = typ {
        header.typ = Some(typ.to_string());
    }
    let pem = if valid_sig {
        &signer().0
    } else {
        wrong_signer()
    };
    let key = EncodingKey::from_rsa_pem(pem.as_bytes()).expect("encoding key");
    encode(&header, claims, &key).expect("sign assertion")
}

/// Baseline RFC 7523 §3 claim set: every required claim present and valid.
fn base_claims(jti: &str) -> Value {
    let now = chrono::Utc::now().timestamp();
    json!({
        "iss": TRUSTED_ISS,
        "sub": "agent-subject-1",
        "aud": TOKEN_ENDPOINT,
        "exp": now + 300,
        "iat": now,
        "jti": jti,
        "email": "agent.subject.1@example.test",
    })
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/// A unique file-backed SQLite database per test. `sqlite::memory:` creates a
/// fresh database per pooled connection, so a multi-connection pool can lose
/// writes when a later read lands on a different connection — this test writes
/// a client, a trusted issuer and a user and then reads all three back through
/// the handler. See `tests/agent_trusted_issuers.rs` for the same reasoning.
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

fn agent_client() -> Client {
    Client::new(
        "agent_client".to_string(),
        "agent_secret".to_string(),
        vec!["https://unused.example/cb".to_string()],
        vec![GRANT_JWT_BEARER.to_string()],
        "read write".to_string(),
        "JWT bearer test client".to_string(),
    )
}

/// Register the client and a trusted issuer whose `jwks_uri` points at the
/// in-process JWKS server. Returns the storage handle.
async fn setup(jwks_uri: &str, customize: impl FnOnce(&mut TrustedIssuer)) -> DynStorage {
    let storage = setup_storage().await;
    storage
        .save_client(&agent_client())
        .await
        .expect("save client");

    let mut trusted = TrustedIssuer::new(TRUSTED_ISS.to_string(), jwks_uri.to_string());
    trusted.jit_provision = true;
    customize(&mut trusted);
    storage
        .save_trusted_issuer(&trusted)
        .await
        .expect("save trusted issuer");

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

fn deps(storage: &DynStorage, id_jag_enabled: bool) -> Deps {
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
            id_jag_enabled,
            ..Default::default()
        },
    }
}

fn basic_auth() -> String {
    format!(
        "Basic {}",
        general_purpose::STANDARD.encode(b"agent_client:agent_secret")
    )
}

/// Percent-encode a form value. `NON_ALPHANUMERIC` over-encodes, which is
/// always valid for `application/x-www-form-urlencoded`.
fn enc(s: &str) -> String {
    percent_encoding::utf8_percent_encode(s, percent_encoding::NON_ALPHANUMERIC).to_string()
}

fn form_body(assertion: &str, extra: &[(&str, &str)]) -> String {
    let mut parts = vec![
        format!("grant_type={}", enc(GRANT_JWT_BEARER)),
        format!("assertion={}", enc(assertion)),
    ];
    for (k, v) in extra {
        parts.push(format!("{}={}", enc(k), enc(v)));
    }
    parts.join("&")
}

// ---------------------------------------------------------------------------
// Test driver: build the App inline (per project convention) and POST.
// ---------------------------------------------------------------------------

macro_rules! post_token {
    ($storage:expr, $deps:expr, $body:expr, $dpop:expr) => {{
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
            .insert_header(("Authorization", basic_auth()))
            .insert_header(("Content-Type", "application/x-www-form-urlencoded"));
        if let Some(proof) = $dpop {
            req = req.insert_header(("DPoP", proof));
        }
        let req = req.set_payload($body).to_request();

        let resp = test::call_service(&app, req).await;
        let status = resp.status();
        let body: Value = test::read_body_json(resp).await;
        (status, body)
    }};
}

// ---------------------------------------------------------------------------
// RFC 7523 §3 validation
// ---------------------------------------------------------------------------

/// An `iss` that is not in the trusted-issuers registry must be rejected.
#[actix_web::test]
async fn unknown_issuer_is_rejected() {
    let jwks_uri = spawn_jwks_server();
    let storage = setup(&jwks_uri, |_| {}).await;

    let mut claims = base_claims("unknown-iss-1");
    claims["iss"] = json!("https://not-registered.example");
    let assertion = sign_assertion(&claims, None, true);

    let (status, body) = post_token!(
        storage,
        deps(&storage, false),
        form_body(&assertion, &[]),
        None::<String>
    );
    assert_eq!(status, 400, "body: {body}");
    assert_eq!(body["error"], "invalid_grant");
}

/// A disabled trusted issuer is treated exactly like an unknown one.
#[actix_web::test]
async fn disabled_issuer_is_rejected() {
    let jwks_uri = spawn_jwks_server();
    let storage = setup(&jwks_uri, |ti| ti.enabled = false).await;

    let assertion = sign_assertion(&base_claims("disabled-iss-1"), None, true);

    let (status, body) = post_token!(
        storage,
        deps(&storage, false),
        form_body(&assertion, &[]),
        None::<String>
    );
    assert_eq!(status, 400, "body: {body}");
    assert_eq!(body["error"], "invalid_grant");
}

/// An assertion signed by a key that is not in the issuer's JWKS must fail
/// signature verification.
#[actix_web::test]
async fn bad_signature_is_rejected() {
    let jwks_uri = spawn_jwks_server();
    let storage = setup(&jwks_uri, |_| {}).await;

    let assertion = sign_assertion(&base_claims("bad-sig-1"), None, false);

    let (status, body) = post_token!(
        storage,
        deps(&storage, false),
        form_body(&assertion, &[]),
        None::<String>
    );
    assert_eq!(status, 400, "body: {body}");
    assert_eq!(body["error"], "invalid_grant");
}

/// `aud` must name this AS (issuer or token endpoint) or an audience the
/// trusted issuer is explicitly allowed to target.
#[actix_web::test]
async fn audience_mismatch_is_rejected() {
    let jwks_uri = spawn_jwks_server();
    let storage = setup(&jwks_uri, |_| {}).await;

    let mut claims = base_claims("bad-aud-1");
    claims["aud"] = json!("https://someone-else.example/token");
    let assertion = sign_assertion(&claims, None, true);

    let (status, body) = post_token!(
        storage,
        deps(&storage, false),
        form_body(&assertion, &[]),
        None::<String>
    );
    assert_eq!(status, 400, "body: {body}");
    assert_eq!(body["error"], "invalid_grant");
}

/// An audience listed in `allowed_audiences` is accepted even though it is
/// neither our issuer nor our token endpoint.
#[actix_web::test]
async fn allowed_audience_from_registry_is_accepted() {
    let jwks_uri = spawn_jwks_server();
    let storage = setup(&jwks_uri, |ti| {
        ti.allowed_audiences =
            serde_json::to_string(&vec!["https://api.example/resource"]).unwrap();
    })
    .await;

    let mut claims = base_claims("allowed-aud-1");
    claims["aud"] = json!("https://api.example/resource");
    let assertion = sign_assertion(&claims, None, true);

    let (status, body) = post_token!(
        storage,
        deps(&storage, false),
        form_body(&assertion, &[]),
        None::<String>
    );
    assert_eq!(status, 200, "body: {body}");
}

/// A client outside the issuer's `allowed_client_ids` allowlist is rejected.
#[actix_web::test]
async fn client_outside_issuer_allowlist_is_rejected() {
    let jwks_uri = spawn_jwks_server();
    let storage = setup(&jwks_uri, |ti| {
        ti.allowed_client_ids = serde_json::to_string(&vec!["some-other-client"]).unwrap();
    })
    .await;

    let assertion = sign_assertion(&base_claims("allowlist-1"), None, true);

    let (status, body) = post_token!(
        storage,
        deps(&storage, false),
        form_body(&assertion, &[]),
        None::<String>
    );
    assert_eq!(status, 400, "body: {body}");
    assert_eq!(body["error"], "invalid_grant");
}

/// Replaying the same `(iss, jti)` pair inside the assertion's validity
/// window must be rejected (RFC 7523 §3).
#[actix_web::test]
async fn replayed_jti_is_rejected() {
    let jwks_uri = spawn_jwks_server();
    let storage = setup(&jwks_uri, |_| {}).await;

    let assertion = sign_assertion(&base_claims("replay-me-1"), None, true);

    let (status, body) = post_token!(
        storage,
        deps(&storage, false),
        form_body(&assertion, &[]),
        None::<String>
    );
    assert_eq!(status, 200, "first presentation must succeed; body: {body}");

    let (status, body) = post_token!(
        storage,
        deps(&storage, false),
        form_body(&assertion, &[]),
        None::<String>
    );
    assert_eq!(status, 400, "body: {body}");
    assert_eq!(body["error"], "invalid_grant");
}

// ---------------------------------------------------------------------------
// Subject resolution + token issuance
// ---------------------------------------------------------------------------

/// Happy path: `subject_mapping = "sub"` with `jit_provision = true` creates
/// the local user on the fly and issues an access token — and never a refresh
/// token (RFC 7523 §2.1 assertion grants are not refreshable here).
#[actix_web::test]
async fn sub_mapping_with_jit_provision_creates_user_and_issues_token() {
    let jwks_uri = spawn_jwks_server();
    let storage = setup(&jwks_uri, |_| {}).await;

    assert!(
        storage
            .get_user_by_id("agent-subject-1")
            .await
            .expect("get_user_by_id")
            .is_none(),
        "user must not exist before the grant"
    );

    let assertion = sign_assertion(&base_claims("happy-1"), None, true);

    let (status, body) = post_token!(
        storage,
        deps(&storage, false),
        form_body(&assertion, &[("scope", "read")]),
        None::<String>
    );
    assert_eq!(status, 200, "body: {body}");
    assert!(body["access_token"].is_string());
    assert_eq!(body["token_type"], "Bearer");
    assert_eq!(body["scope"], "read");
    assert!(
        body.get("refresh_token").is_none(),
        "a JWT-bearer grant must never issue a refresh token; body: {body}"
    );

    let user = storage
        .get_user_by_id("agent-subject-1")
        .await
        .expect("get_user_by_id")
        .expect("JIT-provisioned user must exist");
    assert_eq!(user.username, "agent-subject-1");
    assert_eq!(user.email, "agent.subject.1@example.test");
    assert_eq!(user.role, "user");
    assert!(user.enabled);
    assert!(user.password_hash.is_empty());
}

/// Without `jit_provision` an unknown subject cannot be mapped to a local
/// user, so the grant is refused.
#[actix_web::test]
async fn unknown_subject_without_jit_provision_is_rejected() {
    let jwks_uri = spawn_jwks_server();
    let storage = setup(&jwks_uri, |ti| ti.jit_provision = false).await;

    let assertion = sign_assertion(&base_claims("no-jit-1"), None, true);

    let (status, body) = post_token!(
        storage,
        deps(&storage, false),
        form_body(&assertion, &[]),
        None::<String>
    );
    assert_eq!(status, 400, "body: {body}");
    assert_eq!(body["error"], "invalid_grant");
}

/// `subject_mapping = "email"` resolves an existing local user by the
/// assertion's `email` claim.
#[actix_web::test]
async fn email_mapping_resolves_existing_user() {
    let jwks_uri = spawn_jwks_server();
    let storage = setup(&jwks_uri, |ti| {
        ti.subject_mapping = "email".to_string();
        ti.jit_provision = false;
    })
    .await;

    let now = chrono::Utc::now();
    let user = oauth2_core::User {
        id: "local-user-7".to_string(),
        username: "local7".to_string(),
        password_hash: String::new(),
        email: "agent.subject.1@example.test".to_string(),
        enabled: true,
        role: "user".to_string(),
        created_at: now,
        updated_at: now,
    };
    storage.save_user(&user).await.expect("save user");

    let assertion = sign_assertion(&base_claims("email-map-1"), None, true);

    let (status, body) = post_token!(
        storage,
        deps(&storage, false),
        form_body(&assertion, &[]),
        None::<String>
    );
    assert_eq!(status, 200, "body: {body}");
    assert!(body["access_token"].is_string());
}

/// `subject_mapping = "email"` never just-in-time provisions: keying a new row
/// on `sub` says nothing about who owns the address. An unknown email is an
/// unknown subject, and no user row may be created.
#[actix_web::test]
async fn email_mapping_never_jit_provisions() {
    let jwks_uri = spawn_jwks_server();
    // `jit_provision` is deliberately left on to prove the mapping, not the
    // flag, is what refuses to provision here.
    let storage = setup(&jwks_uri, |ti| {
        ti.subject_mapping = "email".to_string();
        ti.jit_provision = true;
    })
    .await;

    let assertion = sign_assertion(&base_claims("email-no-jit-1"), None, true);

    let (status, body) = post_token!(
        storage,
        deps(&storage, false),
        form_body(&assertion, &[]),
        None::<String>
    );
    assert_eq!(status, 400, "body: {body}");
    assert_eq!(body["error"], "invalid_grant");

    assert!(
        storage
            .get_user_by_email("agent.subject.1@example.test")
            .await
            .expect("get_user_by_email")
            .is_none(),
        "no user may be provisioned for an email-mapped subject"
    );
    assert!(
        storage
            .get_user_by_id("agent-subject-1")
            .await
            .expect("get_user_by_id")
            .is_none(),
        "no user may be provisioned for an email-mapped subject"
    );
}

/// When a local user already carries the `sub` as its id, the grant binds to
/// that user and leaves the row untouched — provisioning is never attempted,
/// so the bare INSERT can never collide.
#[actix_web::test]
async fn sub_mapping_reuses_an_existing_user_without_modifying_it() {
    let jwks_uri = spawn_jwks_server();
    let storage = setup(&jwks_uri, |_| {}).await;

    let now = chrono::Utc::now();
    let existing = oauth2_core::User {
        id: "agent-subject-1".to_string(),
        username: "already-here".to_string(),
        password_hash: "pre-existing-hash".to_string(),
        email: "already.here@example.test".to_string(),
        enabled: true,
        role: "admin".to_string(),
        created_at: now,
        updated_at: now,
    };
    storage.save_user(&existing).await.expect("save user");

    let assertion = sign_assertion(&base_claims("sub-existing-1"), None, true);

    let (status, body) = post_token!(
        storage,
        deps(&storage, false),
        form_body(&assertion, &[]),
        None::<String>
    );
    assert_eq!(status, 200, "body: {body}");

    // The token is bound to the existing user...
    let access_token = body["access_token"].as_str().expect("access_token");
    let stored = storage
        .get_token_by_access_token(access_token)
        .await
        .expect("get_token_by_access_token")
        .expect("issued token must be persisted");
    assert_eq!(stored.user_id.as_deref(), Some("agent-subject-1"));

    // ...and that user is completely unchanged.
    let after = storage
        .get_user_by_id("agent-subject-1")
        .await
        .expect("get_user_by_id")
        .expect("user still exists");
    assert_eq!(after.username, "already-here");
    assert_eq!(after.password_hash, "pre-existing-hash");
    assert_eq!(after.email, "already.here@example.test");
    assert_eq!(after.role, "admin");
}

// ---------------------------------------------------------------------------
// Failed-insert recovery (Storage wrapper that injects the failure)
// ---------------------------------------------------------------------------

/// A `Storage` decorator that forces `resolve_subject` down its
/// failed-insert/re-read recovery path. `Storage::save_user` is a bare INSERT
/// in every backend, so a subject whose row is created concurrently (or whose
/// `sub` collides with an existing user id) makes the insert fail; there is no
/// way to provoke that deterministically against real SQLite, hence this.
///
/// Every method delegates to `inner` except the two knobs. Follows the
/// `NonPersistingStorage` pattern in `tests/dpop_ath_replay.rs`.
struct FlakyStorage {
    inner: DynStorage,
    /// `save_user` fails as a unique-constraint violation would.
    fail_save_user: bool,
    /// The FIRST `get_user_by_id` answers `None` even when the row exists,
    /// modelling the lookup that happens before a concurrent writer commits.
    /// Every later call delegates.
    hide_first_user_lookup: AtomicBool,
}

impl FlakyStorage {
    fn wrap(inner: &DynStorage, fail_save_user: bool, hide_first_user_lookup: bool) -> DynStorage {
        Arc::new(Self {
            inner: inner.clone(),
            fail_save_user,
            hide_first_user_lookup: AtomicBool::new(hide_first_user_lookup),
        })
    }
}

#[async_trait::async_trait]
impl oauth2_ports::Storage for FlakyStorage {
    // --- the two knobs ---
    async fn save_user(&self, user: &User) -> Result<(), OAuth2Error> {
        if self.fail_save_user {
            return Err(OAuth2Error::new(
                "server_error",
                Some("simulated unique violation"),
            ));
        }
        self.inner.save_user(user).await
    }

    async fn get_user_by_id(&self, user_id: &str) -> Result<Option<User>, OAuth2Error> {
        if self.hide_first_user_lookup.swap(false, Ordering::SeqCst) {
            return Ok(None);
        }
        self.inner.get_user_by_id(user_id).await
    }

    // --- everything else delegates ---
    async fn init(&self) -> Result<(), OAuth2Error> {
        self.inner.init().await
    }
    async fn save_client(&self, client: &Client) -> Result<(), OAuth2Error> {
        self.inner.save_client(client).await
    }
    async fn get_client(&self, client_id: &str) -> Result<Option<Client>, OAuth2Error> {
        self.inner.get_client(client_id).await
    }
    async fn update_client(&self, client: &Client) -> Result<(), OAuth2Error> {
        self.inner.update_client(client).await
    }
    async fn delete_client(&self, client_id: &str) -> Result<(), OAuth2Error> {
        self.inner.delete_client(client_id).await
    }
    async fn get_user_by_username(&self, username: &str) -> Result<Option<User>, OAuth2Error> {
        self.inner.get_user_by_username(username).await
    }
    async fn get_user_by_email(&self, email: &str) -> Result<Option<User>, OAuth2Error> {
        self.inner.get_user_by_email(email).await
    }
    async fn save_token(&self, token: &Token) -> Result<(), OAuth2Error> {
        self.inner.save_token(token).await
    }
    async fn get_token_by_access_token(
        &self,
        access_token: &str,
    ) -> Result<Option<Token>, OAuth2Error> {
        self.inner.get_token_by_access_token(access_token).await
    }
    async fn get_token_by_refresh_token(
        &self,
        refresh_token: &str,
    ) -> Result<Option<Token>, OAuth2Error> {
        self.inner.get_token_by_refresh_token(refresh_token).await
    }
    async fn revoke_token(&self, token: &str) -> Result<(), OAuth2Error> {
        self.inner.revoke_token(token).await
    }
    async fn save_authorization_code(
        &self,
        auth_code: &AuthorizationCode,
    ) -> Result<(), OAuth2Error> {
        self.inner.save_authorization_code(auth_code).await
    }
    async fn get_authorization_code(
        &self,
        code: &str,
    ) -> Result<Option<AuthorizationCode>, OAuth2Error> {
        self.inner.get_authorization_code(code).await
    }
    async fn mark_authorization_code_used(&self, code: &str) -> Result<(), OAuth2Error> {
        self.inner.mark_authorization_code_used(code).await
    }
    async fn save_trusted_issuer(&self, trusted_issuer: &TrustedIssuer) -> Result<(), OAuth2Error> {
        self.inner.save_trusted_issuer(trusted_issuer).await
    }
    async fn get_trusted_issuer(&self, issuer: &str) -> Result<Option<TrustedIssuer>, OAuth2Error> {
        self.inner.get_trusted_issuer(issuer).await
    }
    async fn list_trusted_issuers(&self) -> Result<Vec<TrustedIssuer>, OAuth2Error> {
        self.inner.list_trusted_issuers().await
    }
    async fn save_resource(&self, r: &ProtectedResource) -> Result<(), OAuth2Error> {
        self.inner.save_resource(r).await
    }
    async fn get_resource_by_uri(
        &self,
        uri: &str,
    ) -> Result<Option<ProtectedResource>, OAuth2Error> {
        self.inner.get_resource_by_uri(uri).await
    }
    async fn list_resources(&self) -> Result<Vec<ProtectedResource>, OAuth2Error> {
        self.inner.list_resources().await
    }
}

/// The grant lost a race: its first lookup saw no user, its INSERT then
/// collided with the row the winner had just committed. Re-reading finds that
/// row, so the grant succeeds against it rather than returning a 500.
#[actix_web::test]
async fn sub_mapping_recovers_when_insert_races_with_concurrent_provisioning() {
    let jwks_uri = spawn_jwks_server();
    let inner = setup(&jwks_uri, |_| {}).await;

    // The "winner" of the race — written straight to the inner storage.
    let now = chrono::Utc::now();
    let winner = User {
        id: "agent-subject-1".to_string(),
        username: "race-winner".to_string(),
        password_hash: "winner-hash".to_string(),
        email: "race.winner@example.test".to_string(),
        enabled: true,
        role: "user".to_string(),
        created_at: now,
        updated_at: now,
    };
    inner.save_user(&winner).await.expect("save user");

    // Hide it from the first lookup, then fail the insert.
    let storage = FlakyStorage::wrap(&inner, true, true);

    let assertion = sign_assertion(&base_claims("race-recover-1"), None, true);

    let (status, body) = post_token!(
        storage,
        deps(&storage, false),
        form_body(&assertion, &[]),
        None::<String>
    );
    assert_eq!(
        status, 200,
        "a lost provisioning race must still issue a token; body: {body}"
    );

    let access_token = body["access_token"].as_str().expect("access_token");
    let stored = inner
        .get_token_by_access_token(access_token)
        .await
        .expect("get_token_by_access_token")
        .expect("issued token must be persisted");
    assert_eq!(stored.user_id.as_deref(), Some("agent-subject-1"));

    // The winner's row is untouched.
    let after = inner
        .get_user_by_id("agent-subject-1")
        .await
        .expect("get_user_by_id")
        .expect("user still exists");
    assert_eq!(after.username, "race-winner");
    assert_eq!(after.password_hash, "winner-hash");
    assert_eq!(after.email, "race.winner@example.test");
}

/// The insert failed for a reason other than a race — there is still no user
/// to bind to, so the grant fails closed with `invalid_grant`, never a 500.
#[actix_web::test]
async fn sub_mapping_returns_invalid_grant_when_insert_fails_and_user_absent() {
    let jwks_uri = spawn_jwks_server();
    let inner = setup(&jwks_uri, |_| {}).await;

    // No user anywhere; the insert simply fails.
    let storage = FlakyStorage::wrap(&inner, true, false);

    let assertion = sign_assertion(&base_claims("race-absent-1"), None, true);

    let (status, body) = post_token!(
        storage,
        deps(&storage, false),
        form_body(&assertion, &[]),
        None::<String>
    );
    assert_eq!(
        status, 400,
        "a failed insert must not surface as a 500; body: {body}"
    );
    assert_eq!(body["error"], "invalid_grant");

    assert!(
        inner
            .get_user_by_id("agent-subject-1")
            .await
            .expect("get_user_by_id")
            .is_none(),
        "no user row may exist after a failed provisioning insert"
    );
}

// ---------------------------------------------------------------------------
// ID-JAG acceptance
// ---------------------------------------------------------------------------

fn id_jag_claims(jti: &str) -> Value {
    let mut claims = base_claims(jti);
    claims["client_id"] = json!("agent_client");
    claims["scope"] = json!("read write");
    claims
}

/// An ID-JAG whose `client_id` claim names a different client than the one
/// that authenticated must be rejected (token/client binding).
#[actix_web::test]
async fn id_jag_client_id_mismatch_is_rejected() {
    let jwks_uri = spawn_jwks_server();
    let storage = setup(&jwks_uri, |_| {}).await;

    let mut claims = id_jag_claims("id-jag-mismatch-1");
    claims["client_id"] = json!("a-different-client");
    let assertion = sign_assertion(&claims, Some(ID_JAG_TYP), true);

    let (status, body) = post_token!(
        storage,
        deps(&storage, true),
        form_body(&assertion, &[]),
        None::<String>
    );
    assert_eq!(status, 400, "body: {body}");
    assert_eq!(body["error"], "invalid_grant");
    assert!(
        body["error_description"]
            .as_str()
            .expect("error_description")
            .contains("client_id"),
        "must be rejected for the client_id mismatch; body: {body}"
    );
}

/// An ID-JAG carrying `cnf.jkt` demands a matching DPoP proof on the token
/// request; with no proof at all the grant must fail.
#[actix_web::test]
async fn id_jag_with_cnf_jkt_and_no_dpop_is_rejected() {
    let jwks_uri = spawn_jwks_server();
    let storage = setup(&jwks_uri, |_| {}).await;

    let mut claims = id_jag_claims("id-jag-cnf-1");
    claims["cnf"] = json!({ "jkt": "some-key-thumbprint-value" });
    let assertion = sign_assertion(&claims, Some(ID_JAG_TYP), true);

    let (status, body) = post_token!(
        storage,
        deps(&storage, true),
        form_body(&assertion, &[]),
        None::<String>
    );
    assert_eq!(status, 400, "body: {body}");
    assert_eq!(body["error"], "invalid_grant");
    assert!(
        body["error_description"]
            .as_str()
            .expect("error_description")
            .contains("DPoP"),
        "must be rejected for the missing DPoP proof; body: {body}"
    );
}

/// ID-JAG acceptance is gated on `agent.id_jag_enabled`.
#[actix_web::test]
async fn id_jag_is_rejected_when_the_feature_is_disabled() {
    let jwks_uri = spawn_jwks_server();
    let storage = setup(&jwks_uri, |_| {}).await;

    let assertion = sign_assertion(&id_jag_claims("id-jag-off-1"), Some(ID_JAG_TYP), true);

    let (status, body) = post_token!(
        storage,
        deps(&storage, false),
        form_body(&assertion, &[]),
        None::<String>
    );
    assert_eq!(status, 400, "body: {body}");
    assert_eq!(body["error"], "invalid_grant");
}

/// The assertion's `scope` is a ceiling: the request may narrow it, and an
/// un-narrowed request inherits it.
#[actix_web::test]
async fn id_jag_scope_is_a_ceiling() {
    let jwks_uri = spawn_jwks_server();
    let storage = setup(&jwks_uri, |_| {}).await;

    // Inherit the assertion's scope when the request does not narrow it.
    let assertion = sign_assertion(&id_jag_claims("id-jag-scope-1"), Some(ID_JAG_TYP), true);
    let (status, body) = post_token!(
        storage,
        deps(&storage, true),
        form_body(&assertion, &[]),
        None::<String>
    );
    assert_eq!(status, 200, "body: {body}");
    assert_eq!(body["scope"], "read write");

    // Narrowing is allowed.
    let assertion = sign_assertion(&id_jag_claims("id-jag-scope-2"), Some(ID_JAG_TYP), true);
    let (status, body) = post_token!(
        storage,
        deps(&storage, true),
        form_body(&assertion, &[("scope", "read")]),
        None::<String>
    );
    assert_eq!(status, 200, "body: {body}");
    assert_eq!(body["scope"], "read");

    // Widening beyond the assertion's ceiling is not, even though the client
    // itself is registered for `read write`.
    let mut claims = id_jag_claims("id-jag-scope-3");
    claims["scope"] = json!("read");
    let assertion = sign_assertion(&claims, Some(ID_JAG_TYP), true);
    let (status, body) = post_token!(
        storage,
        deps(&storage, true),
        form_body(&assertion, &[("scope", "read write")]),
        None::<String>
    );
    assert_eq!(status, 400, "body: {body}");
    assert_eq!(body["error"], "invalid_scope");
}

/// A validated `act` chain on the ID-JAG is copied onto the issued token.
#[actix_web::test]
async fn id_jag_act_chain_is_copied_to_the_issued_token() {
    let jwks_uri = spawn_jwks_server();
    let storage = setup(&jwks_uri, |_| {}).await;

    let mut claims = id_jag_claims("id-jag-act-1");
    claims["act"] = json!({
        "sub": "agent-1",
        "iss": TRUSTED_ISS,
        "act": { "sub": "svc-1", "iss": TRUSTED_ISS }
    });
    let assertion = sign_assertion(&claims, Some(ID_JAG_TYP), true);

    let (status, body) = post_token!(
        storage,
        deps(&storage, true),
        form_body(&assertion, &[]),
        None::<String>
    );
    assert_eq!(status, 200, "body: {body}");

    let access_token = body["access_token"].as_str().expect("access_token");
    let stored = storage
        .get_token_by_access_token(access_token)
        .await
        .expect("get_token_by_access_token")
        .expect("issued token must be persisted");
    let act_json = stored.act.expect("issued token must carry an act claim");
    let act: Value = serde_json::from_str(&act_json).expect("act is JSON");
    assert_eq!(act["sub"], "agent-1");
    assert_eq!(act["act"]["sub"], "svc-1");
}

/// An `act` chain deeper than `max_delegation_depth` is refused.
#[actix_web::test]
async fn id_jag_act_chain_deeper_than_the_limit_is_rejected() {
    let jwks_uri = spawn_jwks_server();
    let storage = setup(&jwks_uri, |_| {}).await;

    // Five levels, against the default maximum of four.
    let mut act = json!({ "sub": "l0", "iss": TRUSTED_ISS });
    for i in 1..5 {
        act = json!({ "sub": format!("l{i}"), "iss": TRUSTED_ISS, "act": act });
    }
    let mut claims = id_jag_claims("id-jag-depth-1");
    claims["act"] = act;
    let assertion = sign_assertion(&claims, Some(ID_JAG_TYP), true);

    let mut d = deps(&storage, true);
    d.agent_config.max_delegation_depth = 4;
    let (status, body) = post_token!(storage, d, form_body(&assertion, &[]), None::<String>);
    assert_eq!(status, 400, "body: {body}");
    assert_eq!(body["error"], "invalid_request");
}

// ---------------------------------------------------------------------------
// Resource indicators (RFC 8707)
// ---------------------------------------------------------------------------

/// With an empty resource registry any well-formed `resource` is accepted and
/// echoed back on the response.
#[actix_web::test]
async fn requested_resource_is_echoed_when_the_registry_is_empty() {
    let jwks_uri = spawn_jwks_server();
    let storage = setup(&jwks_uri, |_| {}).await;

    let assertion = sign_assertion(&base_claims("resource-echo-1"), None, true);

    let (status, body) = post_token!(
        storage,
        deps(&storage, false),
        form_body(&assertion, &[("resource", "https://api.example/v1")]),
        None::<String>
    );
    assert_eq!(status, 200, "body: {body}");
    assert_eq!(body["resource"], "https://api.example/v1");
}

/// Once the registry has entries, an unregistered `resource` is `invalid_target`.
#[actix_web::test]
async fn unregistered_resource_is_invalid_target() {
    let jwks_uri = spawn_jwks_server();
    let storage = setup(&jwks_uri, |_| {}).await;
    storage
        .save_resource(&oauth2_core::ProtectedResource::new(
            "https://api.example/v1".to_string(),
            "API".to_string(),
            vec!["read".to_string()],
        ))
        .await
        .expect("save resource");

    let assertion = sign_assertion(&base_claims("resource-deny-1"), None, true);

    let (status, body) = post_token!(
        storage,
        deps(&storage, false),
        form_body(&assertion, &[("resource", "https://other.example/v1")]),
        None::<String>
    );
    assert_eq!(status, 400, "body: {body}");
    assert_eq!(body["error"], "invalid_target");
}

/// A malformed `resource` URI fails the RFC 8707 §2 shape check.
#[actix_web::test]
async fn malformed_resource_uri_is_invalid_target() {
    let jwks_uri = spawn_jwks_server();
    let storage = setup(&jwks_uri, |_| {}).await;

    let assertion = sign_assertion(&base_claims("resource-shape-1"), None, true);

    let (status, body) = post_token!(
        storage,
        deps(&storage, false),
        form_body(&assertion, &[("resource", "https://api.example/v1#frag")]),
        None::<String>
    );
    assert_eq!(status, 400, "body: {body}");
    assert_eq!(body["error"], "invalid_target");
}

/// An ID-JAG's `resource` claim is a ceiling the request may not step outside.
#[actix_web::test]
async fn id_jag_resource_is_a_ceiling() {
    let jwks_uri = spawn_jwks_server();
    let storage = setup(&jwks_uri, |_| {}).await;

    // Inherited when the request does not name one.
    let mut claims = id_jag_claims("id-jag-res-1");
    claims["resource"] = json!(["https://api.example/v1"]);
    let assertion = sign_assertion(&claims, Some(ID_JAG_TYP), true);
    let (status, body) = post_token!(
        storage,
        deps(&storage, true),
        form_body(&assertion, &[]),
        None::<String>
    );
    assert_eq!(status, 200, "body: {body}");
    assert_eq!(body["resource"], "https://api.example/v1");

    // A resource outside the assertion's list is refused.
    let mut claims = id_jag_claims("id-jag-res-2");
    claims["resource"] = json!(["https://api.example/v1"]);
    let assertion = sign_assertion(&claims, Some(ID_JAG_TYP), true);
    let (status, body) = post_token!(
        storage,
        deps(&storage, true),
        form_body(&assertion, &[("resource", "https://elsewhere.example/v1")]),
        None::<String>
    );
    assert_eq!(status, 400, "body: {body}");
    assert_eq!(body["error"], "invalid_target");
}

// ---------------------------------------------------------------------------
// Request shape
// ---------------------------------------------------------------------------

/// `assertion` is REQUIRED for this grant.
#[actix_web::test]
async fn missing_assertion_is_a_request_error() {
    let jwks_uri = spawn_jwks_server();
    let storage = setup(&jwks_uri, |_| {}).await;

    let body_str = format!("grant_type={}", enc(GRANT_JWT_BEARER));

    let (status, body) = post_token!(storage, deps(&storage, false), body_str, None::<String>);
    assert_eq!(status, 400, "body: {body}");
    assert_eq!(body["error"], "invalid_request");
}
