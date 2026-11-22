//! RFC 7662 §2.1 / RFC 7009 §2.1 — introspection and revocation must
//! authenticate the client using the method it registered for the token
//! endpoint (SEC-rust-oauth2-server-20261115-G6).

use actix::Actor;
use actix_web::{test, web, App};
use base64::{engine::general_purpose, Engine as _};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use oauth2_actix::actors::{CreateToken, TokenActorPool};
use oauth2_actix::handlers::wellknown::OidcConfig;
use oauth2_config::Config;
use oauth2_core::{Client, Token, User};
use oauth2_observability::Metrics;
use serde_json::json;
use std::sync::OnceLock;

const ISSUER: &str = "http://localhost";
const ASSERTION_TYPE: &str = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

fn basic(client_id: &str, secret: &str) -> String {
    format!(
        "Basic {}",
        general_purpose::STANDARD.encode(format!("{client_id}:{secret}"))
    )
}

fn key() -> &'static (String, String) {
    static KEY: OnceLock<(String, String)> = OnceLock::new();
    KEY.get_or_init(|| {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use rsa::pkcs8::EncodePrivateKey;
        use rsa::traits::PublicKeyParts;
        let private = rsa::RsaPrivateKey::new(&mut rand_core::OsRng, 2048).expect("rsa key");
        let public = private.to_public_key();
        let jwks = json!({
            "keys": [{
                "kty": "RSA",
                "kid": "g6-test-key",
                "use": "sig",
                "alg": "RS256",
                "n": URL_SAFE_NO_PAD.encode(public.n().to_bytes_be()),
                "e": URL_SAFE_NO_PAD.encode(public.e().to_bytes_be()),
            }]
        });
        let pem = private
            .to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)
            .expect("pem")
            .to_string();
        (pem, jwks.to_string())
    })
}

fn assertion(client_id: &str, audience: &str) -> String {
    let now = chrono::Utc::now().timestamp();
    let claims = json!({
        "iss": client_id,
        "sub": client_id,
        "aud": audience,
        "exp": now + 300,
        "iat": now,
        "jti": uuid::Uuid::new_v4().to_string(),
    });
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some("g6-test-key".to_string());
    encode(
        &header,
        &claims,
        &EncodingKey::from_rsa_pem(key().0.as_bytes()).expect("encoding key"),
    )
    .expect("sign assertion")
}

fn client(client_id: &str, method: &str, jwks: &str) -> Client {
    let mut c = Client::new(
        client_id.to_string(),
        format!("{client_id}_secret"),
        vec!["https://unused.example/cb".to_string()],
        vec!["client_credentials".to_string()],
        "read".to_string(),
        format!("{client_id} test client"),
    );
    c.token_endpoint_auth_method = method.to_string();
    c.jwks = jwks.to_string();
    c
}

async fn setup(
    clients: Vec<Client>,
    public_introspection: bool,
) -> (
    TokenActorPool,
    actix::Addr<oauth2_actix::actors::ClientActor>,
    String,
    Metrics,
    OidcConfig,
    Config,
) {
    let storage = oauth2_storage_factory::create_storage("sqlite::memory:")
        .await
        .expect("create storage");
    storage.init().await.expect("init storage");
    for c in clients {
        storage.save_client(&c).await.expect("save client");
    }
    let now = chrono::Utc::now();
    storage
        .save_user(&User {
            id: "user_g6".to_string(),
            username: "user_g6".to_string(),
            password_hash: "unused".to_string(),
            email: "user_g6@example.test".to_string(),
            enabled: true,
            role: "user".to_string(),
            created_at: now,
            updated_at: now,
        })
        .await
        .expect("save user");

    let jwt_secret = "test_jwt_secret".to_string();
    let metrics = Metrics::new().expect("metrics");
    let token_actor = oauth2_actix::actors::TokenActor::new(
        storage.clone(),
        jwt_secret.clone(),
        ISSUER.to_string(),
    )
    .start();
    let pool = TokenActorPool::new(vec![token_actor]);
    let client_actor = oauth2_actix::actors::ClientActor::new(storage.clone()).start();
    let oidc_config = OidcConfig {
        issuer: ISSUER.to_string(),
        jwt_secret: jwt_secret.clone(),
        id_token_alg: "HS256".to_string(),
        id_token_kid: None,
        id_token_private_key_pem: None,
    };
    let mut config = Config::default();
    config.jwt.public_introspection = public_introspection;
    (pool, client_actor, jwt_secret, metrics, oidc_config, config)
}

async fn issue(pool: &TokenActorPool, client_id: &str) -> Token {
    pool.route(client_id)
        .send(CreateToken {
            user_id: Some("user_g6".to_string()),
            client_id: client_id.to_string(),
            scope: "read".to_string(),
            include_refresh: false,
            token_family: None,
            resources: Vec::new(),
            cnf: None,
            authorization_details: None,
            act: None,
            ttl_override_secs: None,
            sub_profile: None,
            txn: None,
            span: tracing::Span::current(),
        })
        .await
        .expect("send create token")
        .expect("create token")
}

macro_rules! app {
    ($pool:expr, $client_actor:expr, $jwt_secret:expr, $metrics:expr, $oidc:expr, $config:expr) => {
        test::init_service(
            App::new()
                .app_data(web::Data::new($pool))
                .app_data(web::Data::new($client_actor))
                .app_data(web::Data::new($jwt_secret))
                .app_data(web::Data::new($metrics))
                .app_data(web::Data::new($oidc))
                .app_data(web::Data::new($config))
                .app_data(web::Data::new(false))
                .service(
                    web::scope("/oauth")
                        .route(
                            "/introspect",
                            web::post().to(oauth2_actix::handlers::token::introspect),
                        )
                        .route(
                            "/revoke",
                            web::post().to(oauth2_actix::handlers::token::revoke),
                        ),
                ),
        )
        .await
    };
}

#[actix_web::test]
async fn introspect_rejects_empty_form_secret_for_public_client() {
    let c = client("public_g6", "none", "");
    let (pool, client_actor, jwt_secret, metrics, oidc, config) = setup(vec![c], false).await;
    let token = issue(&pool, "public_g6").await;
    let app = app!(pool, client_actor, jwt_secret, metrics, oidc, config);

    let req = test::TestRequest::post()
        .uri("/oauth/introspect")
        .set_form([
            ("token", token.access_token.as_str()),
            ("client_id", "public_g6"),
            ("client_secret", ""),
        ])
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 401);
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["error"], "invalid_client");
}

#[actix_web::test]
async fn introspect_accepts_authenticated_caller_with_client_secret() {
    let c = client("conf_g6", "client_secret_basic", "");
    let (pool, client_actor, jwt_secret, metrics, oidc, config) = setup(vec![c], false).await;
    let token = issue(&pool, "conf_g6").await;
    let app = app!(pool, client_actor, jwt_secret, metrics, oidc, config);

    let req = test::TestRequest::post()
        .uri("/oauth/introspect")
        .insert_header(("Authorization", basic("conf_g6", "conf_g6_secret")))
        .set_form([("token", token.access_token.as_str())])
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["active"], true);
}

#[actix_web::test]
async fn introspect_requires_registered_auth_method() {
    let c = client("pkjwt_g6", "private_key_jwt", &key().1);
    let (pool, client_actor, jwt_secret, metrics, oidc, config) = setup(vec![c], false).await;
    let token = issue(&pool, "pkjwt_g6").await;
    let app = app!(pool, client_actor, jwt_secret, metrics, oidc, config);

    // Shared secret must not work for a client registered for private_key_jwt.
    let req = test::TestRequest::post()
        .uri("/oauth/introspect")
        .insert_header(("Authorization", basic("pkjwt_g6", "pkjwt_g6_secret")))
        .set_form([("token", token.access_token.as_str())])
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 401);
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["error"], "invalid_client");

    // The registered method (a valid client assertion) must work. The
    // introspection endpoint is an OAuth endpoint, so its `aud` is the token
    // endpoint URL as on the token endpoint itself.
    let req = test::TestRequest::post()
        .uri("/oauth/introspect")
        .set_form([
            ("token", token.access_token.as_str()),
            ("client_id", "pkjwt_g6"),
            ("client_assertion_type", ASSERTION_TYPE),
            (
                "client_assertion",
                assertion("pkjwt_g6", &format!("{ISSUER}/oauth/token")).as_str(),
            ),
        ])
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["active"], true);
}

#[actix_web::test]
async fn revoke_requires_registered_auth_method() {
    let c = client("pkjwt_revoke_g6", "private_key_jwt", &key().1);
    let (pool, client_actor, jwt_secret, metrics, oidc, config) = setup(vec![c], false).await;
    let token = issue(&pool, "pkjwt_revoke_g6").await;
    let app = app!(pool, client_actor, jwt_secret, metrics, oidc, config);

    let req = test::TestRequest::post()
        .uri("/oauth/revoke")
        .insert_header((
            "Authorization",
            basic("pkjwt_revoke_g6", "pkjwt_revoke_g6_secret"),
        ))
        .set_form([("token", token.access_token.as_str())])
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 401);
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["error"], "invalid_client");

    let req = test::TestRequest::post()
        .uri("/oauth/revoke")
        .set_form([
            ("token", token.access_token.as_str()),
            ("client_id", "pkjwt_revoke_g6"),
            ("client_assertion_type", ASSERTION_TYPE),
            (
                "client_assertion",
                assertion("pkjwt_revoke_g6", &format!("{ISSUER}/oauth/token")).as_str(),
            ),
        ])
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 200);
}

#[actix_web::test]
async fn public_client_can_still_revoke_own_token() {
    let c = client("public_revoke_g6", "none", "");
    let (pool, client_actor, jwt_secret, metrics, oidc, _config) = setup(vec![c], false).await;
    let token = issue(&pool, "public_revoke_g6").await;

    // Revoke with client_id alone: RFC 7009 §2.1 permits public clients.
    {
        let app = app!(
            pool.clone(),
            client_actor.clone(),
            jwt_secret.clone(),
            metrics.clone(),
            oidc.clone(),
            Config::default()
        );
        let req = test::TestRequest::post()
            .uri("/oauth/revoke")
            .set_form([
                ("token", token.access_token.as_str()),
                ("client_id", "public_revoke_g6"),
            ])
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);
    }

    // Confirm the token is inactive via anonymous introspection with
    // public_introspection enabled.
    let mut config = Config::default();
    config.jwt.public_introspection = true;
    let app = app!(pool, client_actor, jwt_secret, metrics, oidc, config);
    let req = test::TestRequest::post()
        .uri("/oauth/introspect")
        .set_form([("token", token.access_token.as_str())])
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["active"], false, "revoked token must be inactive");
}
