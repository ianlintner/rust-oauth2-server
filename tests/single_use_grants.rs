//! Single-use grant consumption under concurrency (RFC 6749 §4.1.2,
//! RFC 9700 §2.1.5 / §4.14.2): authorization codes and refresh tokens are
//! consumed by one atomic conditional storage write, so at most one of any
//! number of concurrent requests succeeds.

use actix::Actor;
use actix_web::{test, web, App};
use std::sync::Arc;
use tokio::sync::RwLock;

use oauth2_actix::actors::TokenActorPool;
use oauth2_actix::handlers::wellknown::OidcConfig;
use oauth2_core::{
    AuthorizationCode, Client, IntrospectionResponse, OAuth2Error, TokenResponse, User,
};
use oauth2_observability::Metrics;
use oauth2_ports::DynStorage;

const ISSUER: &str = "http://localhost";
const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const REDIRECT: &str = "https://client.example/callback";
const SECRET: &str = "test-only-secret";

fn s256(verifier: &str) -> String {
    use base64::{engine::general_purpose, Engine as _};
    use sha2::{Digest, Sha256};
    general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

fn basic_auth_header(client_id: &str, client_secret: &str) -> String {
    use base64::{engine::general_purpose, Engine as _};
    format!(
        "Basic {}",
        general_purpose::STANDARD.encode(format!("{client_id}:{client_secret}"))
    )
}

struct Ctx {
    storage: DynStorage,
    token_actor: TokenActorPool,
    client_actor: actix::Addr<oauth2_actix::actors::ClientActor>,
    auth_actor: actix::Addr<oauth2_actix::actors::AuthActor>,
    jwt_secret: String,
    metrics: Metrics,
    oidc_config: OidcConfig,
    _db: tempfile::NamedTempFile,
}

/// File-backed SQLite so concurrent requests really race on separate pooled
/// connections (an in-memory database would serialize them).
async fn setup(grants: &[&str]) -> Ctx {
    let db = tempfile::NamedTempFile::new().expect("tempfile");
    let url = format!("sqlite://{}", db.path().display());
    let storage = oauth2_storage_factory::create_storage(&url)
        .await
        .expect("create storage");
    storage.init().await.expect("init");

    let client = Client::new(
        "client-a".to_string(),
        SECRET.to_string(),
        vec![REDIRECT.to_string()],
        grants.iter().map(|g| g.to_string()).collect(),
        "read".to_string(),
        "test".to_string(),
    );
    storage.save_client(&client).await.expect("save client");

    let now = chrono::Utc::now();
    storage
        .save_user(&User {
            id: "user_rfc".to_string(),
            username: "user_rfc".to_string(),
            password_hash: "unused".to_string(),
            email: "user_rfc@example.test".to_string(),
            enabled: true,
            role: "user".to_string(),
            created_at: now,
            updated_at: now,
        })
        .await
        .expect("save user");

    let jwt_secret = "rfc_test_jwt_secret_at_least_32_chars".to_string();
    let token_actor = oauth2_actix::actors::TokenActor::new(
        storage.clone(),
        jwt_secret.clone(),
        ISSUER.to_string(),
    )
    .start();
    Ctx {
        token_actor: TokenActorPool::new(vec![token_actor]),
        client_actor: oauth2_actix::actors::ClientActor::new(storage.clone()).start(),
        auth_actor: oauth2_actix::actors::AuthActor::new(storage.clone()).start(),
        metrics: Metrics::new().expect("metrics"),
        oidc_config: OidcConfig {
            issuer: ISSUER.to_string(),
            jwt_secret: jwt_secret.clone(),
            id_token_alg: "HS256".to_string(),
            id_token_kid: None,
            id_token_private_key_pem: None,
        },
        jwt_secret,
        storage,
        _db: db,
    }
}

async fn save_code(storage: &DynStorage, code: &str) {
    let mut ac = AuthorizationCode::new(
        code.to_string(),
        "client-a".to_string(),
        "user_rfc".to_string(),
        REDIRECT.to_string(),
        "read".to_string(),
        Some(s256(VERIFIER)),
        Some("S256".to_string()),
        None,
        None,
        None,
        None,
    );
    ac.token_family = Some(uuid::Uuid::new_v4().to_string());
    storage
        .save_authorization_code(&ac)
        .await
        .expect("save code");
}

macro_rules! app {
    ($ctx:expr) => {{
        let keyset = Arc::new(RwLock::new(oauth2_core::models::key_set::KeySet::default()));
        test::init_service(
            App::new()
                .app_data(web::Data::new($ctx.token_actor.clone()))
                .app_data(web::Data::new($ctx.client_actor.clone()))
                .app_data(web::Data::new($ctx.auth_actor.clone()))
                .app_data(web::Data::new($ctx.jwt_secret.clone()))
                .app_data(web::Data::new($ctx.metrics.clone()))
                .app_data(web::Data::new($ctx.oidc_config.clone()))
                .app_data(web::Data::new(keyset))
                .app_data(web::Data::new(false))
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

macro_rules! token_req {
    ($form:expr) => {
        test::TestRequest::post()
            .uri("/oauth/token")
            .insert_header(("authorization", basic_auth_header("client-a", SECRET)))
            .set_form($form)
            .to_request()
    };
}

macro_rules! is_active {
    ($app:expr, $token:expr) => {{
        let resp = test::call_service(
            &$app,
            test::TestRequest::post()
                .uri("/oauth/introspect")
                .insert_header(("authorization", basic_auth_header("client-a", SECRET)))
                .set_form([("token", $token)])
                .to_request(),
        )
        .await;
        assert_eq!(resp.status(), 200);
        let body: IntrospectionResponse = test::read_body_json(resp).await;
        body.active
    }};
}

fn code_form(code: &str) -> [(&str, &str); 4] {
    [
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", REDIRECT),
        ("code_verifier", VERIFIER),
    ]
}

#[actix_web::test]
async fn mark_authorization_code_used_reports_already_used() {
    let ctx = setup(&["authorization_code"]).await;
    save_code(&ctx.storage, "code-unit").await;
    assert!(ctx
        .storage
        .mark_authorization_code_used("code-unit")
        .await
        .unwrap());
    assert!(!ctx
        .storage
        .mark_authorization_code_used("code-unit")
        .await
        .unwrap());
    assert!(!ctx
        .storage
        .mark_authorization_code_used("missing")
        .await
        .unwrap());
}

#[actix_web::test]
async fn authorization_code_concurrent_redemption_yields_one_token() {
    for iteration in 0..20 {
        let ctx = setup(&["authorization_code", "refresh_token"]).await;
        let code = format!("code-race-{iteration}");
        save_code(&ctx.storage, &code).await;
        let app = app!(ctx);

        let responses = futures::future::join_all(
            (0..10).map(|_| test::call_service(&app, token_req!(&code_form(&code)))),
        )
        .await;

        let mut ok = 0;
        for resp in responses {
            if resp.status() == 200 {
                ok += 1;
            } else {
                assert_eq!(resp.status(), 400, "iteration {iteration}");
                let err: OAuth2Error = test::read_body_json(resp).await;
                assert_eq!(err.error, "invalid_grant");
            }
        }
        assert_eq!(ok, 1, "iteration {iteration}: exactly one redemption");
    }
}

#[actix_web::test]
async fn code_replay_revokes_access_token_for_client_without_refresh_grant() {
    let ctx = setup(&["authorization_code"]).await;
    save_code(&ctx.storage, "code-norefresh").await;
    let app = app!(ctx);

    let first = test::call_service(&app, token_req!(&code_form("code-norefresh"))).await;
    assert_eq!(first.status(), 200);
    let body: TokenResponse = test::read_body_json(first).await;
    assert!(body.refresh_token.is_none());
    assert!(is_active!(app, &body.access_token));

    let second = test::call_service(&app, token_req!(&code_form("code-norefresh"))).await;
    assert_eq!(second.status(), 400);
    let err: OAuth2Error = test::read_body_json(second).await;
    assert_eq!(err.error, "invalid_grant");

    assert!(
        !is_active!(app, &body.access_token),
        "replay must revoke the access token issued from the code"
    );
}

#[actix_web::test]
async fn refresh_token_concurrent_use_yields_one_pair_and_revokes_family() {
    for iteration in 0..10 {
        let ctx = setup(&["authorization_code", "refresh_token"]).await;
        let code = format!("code-refresh-{iteration}");
        save_code(&ctx.storage, &code).await;
        let app = app!(ctx);

        let first = test::call_service(&app, token_req!(&code_form(&code))).await;
        assert_eq!(first.status(), 200);
        let initial: TokenResponse = test::read_body_json(first).await;
        let refresh = initial.refresh_token.expect("refresh token");

        let responses = futures::future::join_all((0..10).map(|_| {
            test::call_service(
                &app,
                token_req!(&[
                    ("grant_type", "refresh_token"),
                    ("refresh_token", refresh.as_str()),
                ]),
            )
        }))
        .await;

        let mut ok = 0;
        let mut issued: Vec<TokenResponse> = Vec::new();
        for resp in responses {
            if resp.status() == 200 {
                ok += 1;
                issued.push(test::read_body_json(resp).await);
            } else {
                assert_eq!(resp.status(), 400, "iteration {iteration}");
                let err: OAuth2Error = test::read_body_json(resp).await;
                assert_eq!(err.error, "invalid_grant");
            }
        }
        assert!(
            ok <= 1,
            "iteration {iteration}: at most one new pair, got {ok}"
        );

        assert!(!is_active!(app, &initial.access_token));
        // Ten requests, at most one winner: any loser revokes the whole
        // family, including the winner's freshly minted pair.
        for t in &issued {
            assert!(
                !is_active!(app, &t.access_token),
                "iteration {iteration}: family must be revoked after concurrent reuse"
            );
        }
    }
}
