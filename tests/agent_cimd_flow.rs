//! Phase 7 (agent / A2A OAuth) Task 14: Client ID Metadata Documents (CIMD)
//! wired into the authorize / token flows.
//!
//! A CIMD client identifies itself with an HTTPS URL that the authorization
//! server dereferences instead of looking the client up in storage. These
//! tests serve metadata documents from an in-process HTTP server on loopback
//! and drive the real `/oauth/authorize` and `/oauth/token` handlers.

use std::sync::OnceLock;

use actix::Actor;
use actix_session::{storage::CookieSessionStore, Session, SessionMiddleware};
use actix_web::cookie::Key;
use actix_web::{test, web, App, HttpRequest, HttpResponse, HttpServer};
use base64::{engine::general_purpose, Engine as _};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header as JwtHeader};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use oauth2_actix::actors::{AuthActor, ClientActor, TokenActor, TokenActorPool};
use oauth2_actix::handlers::cimd::CimdFetcher;
use oauth2_actix::handlers::wellknown::OidcConfig;
use oauth2_config::AgentConfig;
use oauth2_core::User;
use oauth2_observability::Metrics;
use oauth2_ports::DynStorage;
use rsa::pkcs1::EncodeRsaPrivateKey;
use rsa::traits::PublicKeyParts;
use rsa::{RsaPrivateKey, RsaPublicKey};

const ISSUER: &str = "http://localhost";
const TOKEN_ENDPOINT: &str = "http://localhost/oauth/token";
const JWT_SECRET: &str = "test_jwt_secret";
const USER_ID: &str = "user_cimd";
const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const REDIRECT_URI: &str = "https://app.example/cb";
const CLIENT_NAME: &str = "Example MCP Client";
const TEST_KID: &str = "cimd-kid-1";

// ---------------------------------------------------------------------------
// Signing key (private_key_jwt CIMD client)
// ---------------------------------------------------------------------------

/// RSA keypair published in the `private_key_jwt` metadata document.
/// Generated once per test binary — 2048-bit generation is slow in debug.
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

/// Mint a `private_key_jwt` client assertion for `client_id`.
fn client_assertion(client_id: &str) -> String {
    let now = chrono::Utc::now().timestamp();
    let claims = json!({
        "iss": client_id,
        "sub": client_id,
        "aud": TOKEN_ENDPOINT,
        "exp": now + 300,
        "iat": now,
        "jti": uuid::Uuid::new_v4().to_string(),
    });
    let mut header = JwtHeader::new(Algorithm::RS256);
    header.kid = Some(TEST_KID.to_string());
    let key = EncodingKey::from_rsa_pem(signer().0.as_bytes()).expect("encoding key");
    encode(&header, &claims, &key).expect("sign client_assertion")
}

// ---------------------------------------------------------------------------
// In-process metadata server
// ---------------------------------------------------------------------------

/// Serve one metadata document per path. The document always declares the
/// exact URL it was fetched from, as the draft requires.
async fn metadata(req: HttpRequest) -> HttpResponse {
    let host = req.connection_info().host().to_string();
    let path = req.path().to_string();
    let client_id = format!("http://{host}{path}");

    match path.as_str() {
        // Public (token_endpoint_auth_method defaults to "none") agent.
        "/public-agent" => HttpResponse::Ok().json(json!({
            "client_id": client_id,
            "client_name": CLIENT_NAME,
            "redirect_uris": [REDIRECT_URI],
            "grant_types": ["authorization_code", "refresh_token"],
            "scope": "read write",
        })),
        // Metadata carrying a dangerous redirect URI scheme.
        "/evil-agent" => HttpResponse::Ok().json(json!({
            "client_id": client_id,
            "client_name": "Evil Agent",
            "redirect_uris": ["javascript:alert(1)"],
            "grant_types": ["authorization_code"],
            "scope": "read",
        })),
        // Confidential agent authenticating with keys from the document.
        "/pkjwt-agent" => HttpResponse::Ok().json(json!({
            "client_id": client_id,
            "client_name": "Key Agent",
            "redirect_uris": [REDIRECT_URI],
            "grant_types": ["client_credentials"],
            "token_endpoint_auth_method": "private_key_jwt",
            "scope": "read write",
            "jwks": { "keys": [signer().1.clone()] },
        })),
        _ => HttpResponse::NotFound().finish(),
    }
}

/// Spawn the metadata server on an ephemeral loopback port, returning its base URL.
fn spawn_metadata_server() -> String {
    let server = HttpServer::new(|| App::new().default_service(web::to(metadata)))
        .workers(1)
        .disable_signals()
        .bind(("127.0.0.1", 0))
        .expect("bind loopback");
    let port = server.addrs()[0].port();
    actix_web::rt::spawn(server.run());
    format!("http://127.0.0.1:{port}")
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

async fn storage() -> DynStorage {
    let storage = oauth2_storage_factory::create_storage("sqlite::memory:")
        .await
        .expect("create storage");
    storage.init().await.expect("init storage");
    let now = chrono::Utc::now();
    storage
        .save_user(&User {
            id: USER_ID.to_string(),
            username: USER_ID.to_string(),
            password_hash: "not_used".to_string(),
            email: format!("{USER_ID}@example.test"),
            enabled: true,
            role: "user".to_string(),
            created_at: now,
            updated_at: now,
        })
        .await
        .expect("save user");
    storage
}

fn agent_config(cimd_enabled: bool) -> AgentConfig {
    AgentConfig {
        cimd_enabled,
        cimd_allowed_hosts: vec![],
        cimd_denied_hosts: vec![],
        ..AgentConfig::default()
    }
}

fn fetcher() -> CimdFetcher {
    CimdFetcher::new(vec![], vec![]).allow_loopback_for_tests()
}

async fn test_login(session: Session) -> HttpResponse {
    session.insert("user_id", USER_ID).unwrap();
    session.insert("authenticated", true).unwrap();
    HttpResponse::Ok().finish()
}

fn session_cookie(
    resp: &actix_web::dev::ServiceResponse<impl actix_web::body::MessageBody>,
) -> String {
    resp.response()
        .headers()
        .get(actix_web::http::header::SET_COOKIE)
        .and_then(|h| h.to_str().ok())
        .expect("session cookie")
        .split(';')
        .next()
        .unwrap()
        .to_string()
}

fn location(resp: &actix_web::dev::ServiceResponse<impl actix_web::body::MessageBody>) -> String {
    resp.headers()
        .get(actix_web::http::header::LOCATION)
        .and_then(|h| h.to_str().ok())
        .expect("Location header")
        .to_string()
}

/// Read one query parameter out of a redirect URL. The authorize endpoint
/// only ever emits values that need no percent-decoding here.
fn query_param(url: &str, name: &str) -> Option<String> {
    url.split_once('?')?
        .1
        .split('&')
        .filter_map(|pair| pair.split_once('='))
        .find(|(k, _)| *k == name)
        .map(|(_, v)| v.to_string())
}

fn challenge() -> String {
    general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(VERIFIER.as_bytes()))
}

/// Build an inline `App` exposing authorize, token and the login page.
///
/// `$cimd` is an `Option<CimdFetcher>`; `None` leaves the handler's
/// `Option<web::Data<CimdFetcher>>` extractor empty.
macro_rules! cimd_app {
    ($storage:expr, $agent:expr, $cimd:expr) => {{
        let storage: DynStorage = $storage.clone();
        let metrics = Metrics::new().expect("metrics");
        let token_pool = TokenActorPool::new(vec![TokenActor::new(
            storage.clone(),
            JWT_SECRET.to_string(),
            ISSUER.to_string(),
        )
        .start()]);
        let oidc_config = OidcConfig {
            issuer: ISSUER.to_string(),
            jwt_secret: JWT_SECRET.to_string(),
            id_token_alg: "HS256".to_string(),
            id_token_kid: None,
            id_token_private_key_pem: None,
        };

        let mut builder = App::new()
            .wrap(SessionMiddleware::new(
                CookieSessionStore::default(),
                Key::generate(),
            ))
            .app_data(web::Data::new(token_pool))
            .app_data(web::Data::new(ClientActor::new(storage.clone()).start()))
            .app_data(web::Data::new(AuthActor::new(storage.clone()).start()))
            .app_data(web::Data::new(storage))
            .app_data(web::Data::new(JWT_SECRET.to_string()))
            .app_data(web::Data::new(metrics))
            .app_data(web::Data::new(oidc_config))
            .app_data(web::Data::new(false)) // stateless_validation
            .app_data(web::Data::new($agent));
        let cimd: Option<CimdFetcher> = $cimd;
        if let Some(cimd) = cimd {
            builder = builder.app_data(web::Data::new(cimd));
        }

        test::init_service(
            builder
                .route("/test/login", web::get().to(test_login))
                .route(
                    "/auth/login",
                    web::get().to(oauth2_actix::handlers::login::login_page),
                )
                .service(
                    web::scope("/oauth")
                        .route(
                            "/authorize",
                            web::get().to(oauth2_actix::handlers::oauth::authorize),
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

fn authorize_uri(client_id: &str, redirect_uri: &str) -> String {
    format!(
        "/oauth/authorize?response_type=code&client_id={}&redirect_uri={}&scope=read&state=xyz&code_challenge={}&code_challenge_method=S256",
        urlencoding(client_id),
        urlencoding(redirect_uri),
        challenge()
    )
}

fn urlencoding(value: &str) -> String {
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
        .map(|(k, v)| format!("{}={}", urlencoding(k), urlencoding(v)))
        .collect::<Vec<_>>()
        .join("&")
}

// ---------------------------------------------------------------------------
// authorize
// ---------------------------------------------------------------------------

#[actix_web::test]
async fn authorize_with_url_client_id_reaches_login() {
    let base = spawn_metadata_server();
    let client_id = format!("{base}/public-agent");
    let storage = storage().await;
    let app = cimd_app!(storage, agent_config(true), Some(fetcher()));

    let resp = test::call_service(
        &app,
        test::TestRequest::get()
            .uri(&authorize_uri(&client_id, REDIRECT_URI))
            .to_request(),
    )
    .await;

    assert_eq!(
        resp.status(),
        302,
        "unauthenticated CIMD authorize -> login"
    );
    assert_eq!(location(&resp), "/auth/login");

    // The login page names the client and the host its metadata came from.
    let cookie = session_cookie(&resp);
    let page = test::call_service(
        &app,
        test::TestRequest::get()
            .uri("/auth/login")
            .insert_header(("Cookie", cookie))
            .to_request(),
    )
    .await;
    assert_eq!(page.status(), 200);
    let body = String::from_utf8(test::read_body(page).await.to_vec()).expect("utf-8 body");
    assert!(
        body.contains(&format!("{CLIENT_NAME} (127.0.0.1)")),
        "login page must show the CIMD client name and host"
    );
}

#[actix_web::test]
async fn authorize_rejects_redirect_uri_absent_from_metadata() {
    let base = spawn_metadata_server();
    let client_id = format!("{base}/public-agent");
    let storage = storage().await;
    let app = cimd_app!(storage, agent_config(true), Some(fetcher()));

    let resp = test::call_service(
        &app,
        test::TestRequest::get()
            .uri(&authorize_uri(&client_id, "https://attacker.example/cb"))
            .to_request(),
    )
    .await;

    assert_eq!(resp.status(), 400, "redirect_uri not in the document");
}

#[actix_web::test]
async fn authorize_rejects_metadata_with_dangerous_redirect_scheme() {
    let base = spawn_metadata_server();
    let client_id = format!("{base}/evil-agent");
    let storage = storage().await;
    let app = cimd_app!(storage, agent_config(true), Some(fetcher()));

    let resp = test::call_service(
        &app,
        test::TestRequest::get()
            .uri(&authorize_uri(&client_id, "javascript:alert(1)"))
            .to_request(),
    )
    .await;

    assert_eq!(
        resp.status(),
        401,
        "metadata declaring a javascript: redirect_uri must be rejected"
    );
    let body: Value = test::read_body_json(resp).await;
    assert_eq!(body["error"], "invalid_client");
}

#[actix_web::test]
async fn url_client_id_is_rejected_when_cimd_is_disabled() {
    let storage = storage().await;
    let app = cimd_app!(storage, agent_config(false), None);

    let resp = test::call_service(
        &app,
        test::TestRequest::get()
            .uri(&authorize_uri("https://app.example/agent", REDIRECT_URI))
            .to_request(),
    )
    .await;

    assert_eq!(resp.status(), 401);
    let body: Value = test::read_body_json(resp).await;
    assert_eq!(body["error"], "invalid_client");
    assert_eq!(
        body["error_description"],
        "client_id metadata documents are not enabled"
    );
}

// ---------------------------------------------------------------------------
// authorize -> token
// ---------------------------------------------------------------------------

#[actix_web::test]
async fn authorization_code_flow_completes_for_cimd_client() {
    let base = spawn_metadata_server();
    let client_id = format!("{base}/public-agent");
    let storage = storage().await;
    let app = cimd_app!(storage, agent_config(true), Some(fetcher()));

    let login = test::call_service(
        &app,
        test::TestRequest::get().uri("/test/login").to_request(),
    )
    .await;
    let cookie = session_cookie(&login);

    let resp = test::call_service(
        &app,
        test::TestRequest::get()
            .uri(&authorize_uri(&client_id, REDIRECT_URI))
            .insert_header(("Cookie", cookie))
            .to_request(),
    )
    .await;
    assert_eq!(resp.status(), 302, "authenticated CIMD authorize -> code");

    let redirect = location(&resp);
    let code = query_param(&redirect, "code").expect("authorization code");

    // The public CIMD client redeems the code with PKCE and no secret.
    let token_resp = test::call_service(
        &app,
        test::TestRequest::post()
            .uri("/oauth/token")
            .insert_header(("Content-Type", "application/x-www-form-urlencoded"))
            .set_payload(form(&[
                ("grant_type", "authorization_code"),
                ("code", &code),
                ("redirect_uri", REDIRECT_URI),
                ("client_id", &client_id),
                ("code_verifier", VERIFIER),
            ]))
            .to_request(),
    )
    .await;

    assert_eq!(token_resp.status(), 200, "token exchange for CIMD client");
    let body: Value = test::read_body_json(token_resp).await;
    assert!(body["access_token"].is_string());
}

#[actix_web::test]
async fn private_key_jwt_cimd_client_authenticates_with_document_jwks() {
    let base = spawn_metadata_server();
    let client_id = format!("{base}/pkjwt-agent");
    let storage = storage().await;
    let app = cimd_app!(storage, agent_config(true), Some(fetcher()));

    let assertion = client_assertion(&client_id);
    let resp = test::call_service(
        &app,
        test::TestRequest::post()
            .uri("/oauth/token")
            .insert_header(("Content-Type", "application/x-www-form-urlencoded"))
            .set_payload(form(&[
                ("grant_type", "client_credentials"),
                ("client_id", &client_id),
                ("scope", "read"),
                (
                    "client_assertion_type",
                    "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                ),
                ("client_assertion", &assertion),
            ]))
            .to_request(),
    )
    .await;

    assert_eq!(
        resp.status(),
        200,
        "private_key_jwt CIMD client must authenticate with the document's jwks"
    );
    let body: Value = test::read_body_json(resp).await;
    assert!(body["access_token"].is_string());
}
