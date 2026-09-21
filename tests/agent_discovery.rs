//! Phase 7 (agent / A2A OAuth) discovery tests.
//!
//! Covers: `openid_configuration` advertising agent capabilities gated on
//! `oauth2_config::AgentConfig` flags, and the per-resource RFC 9728
//! Protected Resource Metadata endpoint (`GET
//! /.well-known/oauth-protected-resource/{id}`).

use actix_web::{test, web, App};
use serde_json::Value;

use oauth2_actix::handlers::wellknown::OidcConfig;
use oauth2_config::AgentConfig;
use oauth2_core::token_types::{GRANT_JWT_BEARER, GRANT_TRANSACTION_AUTHORIZATION, ID_JAG, JWT};
use oauth2_core::ProtectedResource;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn oidc_config() -> OidcConfig {
    OidcConfig {
        issuer: "https://auth.example.test".to_string(),
        jwt_secret: "test_jwt_secret".to_string(),
        id_token_alg: "HS256".to_string(),
        id_token_kid: None,
        id_token_private_key_pem: None,
    }
}

/// All Phase 7 agent/A2A flags off (the documented default).
fn agent_config_all_off() -> AgentConfig {
    AgentConfig {
        max_delegation_depth: 4,
        trust_domain: None,
        cimd_enabled: false,
        cimd_allowed_hosts: vec![],
        cimd_denied_hosts: vec![],
        cimd_max_clients: 1000,
        obo_enabled: false,
        a2a_profile_enabled: false,
        txn_token_ttl_secs: 300,
        txn_tokens_enabled: false,
        tac_enabled: false,
        id_jag_enabled: false,
        chaining_targets: vec![],
        ai_agent_access_token_ttl_secs: None,
    }
}

macro_rules! discovery_app {
    ($oidc_config:expr, $agent_config:expr) => {
        test::init_service(
            App::new()
                .app_data(web::Data::new($oidc_config))
                .app_data(web::Data::new($agent_config))
                .service(web::scope("/.well-known").route(
                    "/openid-configuration",
                    web::get().to(oauth2_actix::handlers::wellknown::openid_configuration),
                )),
        )
        .await
    };
}

async fn discovery_body(oidc_config: OidcConfig, agent_config: AgentConfig) -> Value {
    let app = discovery_app!(oidc_config, agent_config);
    let req = test::TestRequest::get()
        .uri("/.well-known/openid-configuration")
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 200, "discovery endpoint must return 200");
    test::read_body_json(resp).await
}

/// Discovery body built with storage attached (for `authorization_details_types_supported`
/// union tests) and a given agent config.
async fn discovery_body_with_storage(
    oidc_config: OidcConfig,
    agent_config: AgentConfig,
    storage: oauth2_ports::DynStorage,
) -> Value {
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(oidc_config))
            .app_data(web::Data::new(agent_config))
            .app_data(web::Data::new(storage))
            .service(web::scope("/.well-known").route(
                "/openid-configuration",
                web::get().to(oauth2_actix::handlers::wellknown::openid_configuration),
            )),
    )
    .await;
    let req = test::TestRequest::get()
        .uri("/.well-known/openid-configuration")
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 200, "discovery endpoint must return 200");
    test::read_body_json(resp).await
}

macro_rules! prm_app {
    ($oidc_config:expr, $storage:expr) => {
        test::init_service(
            App::new()
                .app_data(web::Data::new($oidc_config))
                .app_data(web::Data::new($storage))
                .service(web::scope("/.well-known").route(
                    "/oauth-protected-resource/{id}",
                    web::get().to(
                        oauth2_actix::handlers::wellknown::protected_resource_metadata_for_resource,
                    ),
                )),
        )
        .await
    };
}

// ---------------------------------------------------------------------------
// Discovery: flags off -> agent fields absent
// ---------------------------------------------------------------------------

#[actix_web::test]
async fn agent_flags_off_client_id_metadata_document_supported_absent() {
    let body = discovery_body(oidc_config(), agent_config_all_off()).await;
    assert!(
        body.get("client_id_metadata_document_supported").is_none(),
        "client_id_metadata_document_supported must be absent when cimd_enabled is false"
    );
}

#[actix_web::test]
async fn agent_flags_off_identity_chaining_types_absent() {
    let body = discovery_body(oidc_config(), agent_config_all_off()).await;
    assert!(
        body.get("identity_chaining_requested_token_types_supported")
            .is_none(),
        "identity_chaining_requested_token_types_supported must be absent when id_jag_enabled is false"
    );
}

#[actix_web::test]
async fn agent_flags_off_authorization_grant_profiles_absent() {
    let body = discovery_body(oidc_config(), agent_config_all_off()).await;
    assert!(
        body.get("authorization_grant_profiles_supported").is_none(),
        "authorization_grant_profiles_supported must be absent when id_jag_enabled is false"
    );
}

#[actix_web::test]
async fn agent_flags_off_transaction_authorization_endpoint_absent() {
    let body = discovery_body(oidc_config(), agent_config_all_off()).await;
    assert!(
        body.get("transaction_authorization_endpoint").is_none(),
        "transaction_authorization_endpoint must be absent when tac_enabled is false"
    );
}

#[actix_web::test]
async fn agent_flags_off_requested_actor_parameter_absent() {
    let body = discovery_body(oidc_config(), agent_config_all_off()).await;
    assert!(
        body.get("requested_actor_parameter_supported").is_none(),
        "requested_actor_parameter_supported must be absent when obo_enabled is false"
    );
}

#[actix_web::test]
async fn agent_flags_off_grant_types_supported_excludes_transaction_authorization() {
    let body = discovery_body(oidc_config(), agent_config_all_off()).await;
    let grants = body["grant_types_supported"]
        .as_array()
        .expect("grant_types_supported must be an array");
    assert!(
        !grants
            .iter()
            .any(|v| v.as_str() == Some(GRANT_TRANSACTION_AUTHORIZATION)),
        "grant_types_supported must not include the transaction-authorization grant when tac_enabled is false"
    );
}

// ---------------------------------------------------------------------------
// Discovery: grant_types_supported always includes GRANT_JWT_BEARER
// ---------------------------------------------------------------------------

#[actix_web::test]
async fn grant_types_supported_always_includes_jwt_bearer() {
    let body = discovery_body(oidc_config(), agent_config_all_off()).await;
    let grants = body["grant_types_supported"]
        .as_array()
        .expect("grant_types_supported must be an array");
    assert!(
        grants.iter().any(|v| v.as_str() == Some(GRANT_JWT_BEARER)),
        "grant_types_supported must always include {}",
        GRANT_JWT_BEARER
    );
}

// ---------------------------------------------------------------------------
// Discovery: each flag on -> exact expected values
// ---------------------------------------------------------------------------

#[actix_web::test]
async fn cimd_enabled_advertises_client_id_metadata_document_supported() {
    let mut agent = agent_config_all_off();
    agent.cimd_enabled = true;
    let body = discovery_body(oidc_config(), agent).await;
    assert_eq!(
        body["client_id_metadata_document_supported"].as_bool(),
        Some(true)
    );
}

#[actix_web::test]
async fn id_jag_enabled_advertises_identity_chaining_types() {
    let mut agent = agent_config_all_off();
    agent.id_jag_enabled = true;
    let body = discovery_body(oidc_config(), agent).await;
    let types = body["identity_chaining_requested_token_types_supported"]
        .as_array()
        .expect("identity_chaining_requested_token_types_supported must be an array");
    let type_strs: Vec<&str> = types.iter().filter_map(|v| v.as_str()).collect();
    assert_eq!(type_strs, vec![JWT, ID_JAG]);
}

#[actix_web::test]
async fn id_jag_enabled_advertises_authorization_grant_profiles() {
    let mut agent = agent_config_all_off();
    agent.id_jag_enabled = true;
    let body = discovery_body(oidc_config(), agent).await;
    let profiles = body["authorization_grant_profiles_supported"]
        .as_array()
        .expect("authorization_grant_profiles_supported must be an array");
    let profile_strs: Vec<&str> = profiles.iter().filter_map(|v| v.as_str()).collect();
    assert_eq!(
        profile_strs,
        vec!["urn:ietf:params:oauth:grant-profile:id-jag"]
    );
}

#[actix_web::test]
async fn tac_enabled_advertises_transaction_authorization_endpoint() {
    let mut agent = agent_config_all_off();
    agent.tac_enabled = true;
    let body = discovery_body(oidc_config(), agent).await;
    assert_eq!(
        body["transaction_authorization_endpoint"].as_str(),
        Some("https://auth.example.test/oauth/transaction_authorization")
    );
}

#[actix_web::test]
async fn tac_enabled_adds_transaction_authorization_grant_type() {
    let mut agent = agent_config_all_off();
    agent.tac_enabled = true;
    let body = discovery_body(oidc_config(), agent).await;
    let grants = body["grant_types_supported"]
        .as_array()
        .expect("grant_types_supported must be an array");
    assert!(grants
        .iter()
        .any(|v| v.as_str() == Some(GRANT_TRANSACTION_AUTHORIZATION)));
}

#[actix_web::test]
async fn obo_enabled_advertises_requested_actor_parameter_supported() {
    let mut agent = agent_config_all_off();
    agent.obo_enabled = true;
    let body = discovery_body(oidc_config(), agent).await;
    assert_eq!(
        body["requested_actor_parameter_supported"].as_bool(),
        Some(true)
    );
}

// ---------------------------------------------------------------------------
// Discovery: authorization_details_types_supported union with registered resources
// ---------------------------------------------------------------------------

#[actix_web::test]
async fn authorization_details_types_supported_includes_openid_with_no_storage() {
    let body = discovery_body(oidc_config(), agent_config_all_off()).await;
    let types = body["authorization_details_types_supported"]
        .as_array()
        .expect("authorization_details_types_supported must be an array");
    let type_strs: Vec<&str> = types.iter().filter_map(|v| v.as_str()).collect();
    assert_eq!(type_strs, vec!["openid"]);
}

#[actix_web::test]
async fn authorization_details_types_supported_unions_registered_resource_types() {
    let storage = oauth2_storage_factory::create_storage("sqlite::memory:")
        .await
        .expect("create storage");
    storage.init().await.expect("init storage");

    let mut resource = ProtectedResource::new(
        "https://api.example.test".to_string(),
        "Example API".to_string(),
        vec!["read".to_string()],
    );
    resource.authorization_details_types =
        serde_json::to_string(&vec!["payment_initiation", "account_information"]).unwrap();
    storage
        .save_resource(&resource)
        .await
        .expect("save resource");

    let body = discovery_body_with_storage(oidc_config(), agent_config_all_off(), storage).await;
    let types = body["authorization_details_types_supported"]
        .as_array()
        .expect("authorization_details_types_supported must be an array");
    let type_strs: Vec<&str> = types.iter().filter_map(|v| v.as_str()).collect();
    assert!(type_strs.contains(&"openid"));
    assert!(type_strs.contains(&"payment_initiation"));
    assert!(type_strs.contains(&"account_information"));
}

// ---------------------------------------------------------------------------
// Per-resource Protected Resource Metadata (RFC 9728)
// ---------------------------------------------------------------------------

#[actix_web::test]
async fn per_resource_prm_returns_200_with_rfc9728_fields() {
    let storage = oauth2_storage_factory::create_storage("sqlite::memory:")
        .await
        .expect("create storage");
    storage.init().await.expect("init storage");

    let mut resource = ProtectedResource::new(
        "https://api.example.test".to_string(),
        "Example API".to_string(),
        vec!["read".to_string(), "write".to_string()],
    );
    resource.authorization_details_types =
        serde_json::to_string(&vec!["payment_initiation"]).unwrap();
    storage
        .save_resource(&resource)
        .await
        .expect("save resource");

    let app = prm_app!(oidc_config(), storage);
    let req = test::TestRequest::get()
        .uri(&format!(
            "/.well-known/oauth-protected-resource/{}",
            resource.id
        ))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 200);

    let body: Value = test::read_body_json(resp).await;
    assert_eq!(body["resource"].as_str(), Some("https://api.example.test"));
    assert_eq!(
        body["authorization_servers"].as_array().unwrap(),
        &vec![Value::String("https://auth.example.test".to_string())]
    );
    let scopes: Vec<&str> = body["scopes_supported"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|v| v.as_str())
        .collect();
    assert_eq!(scopes, vec!["read", "write"]);
    assert_eq!(
        body["bearer_methods_supported"].as_array().unwrap(),
        &vec![Value::String("header".to_string())]
    );
    assert!(body["dpop_signing_alg_values_supported"]
        .as_array()
        .unwrap()
        .iter()
        .any(|v| v.as_str() == Some("ES256")));
    assert_eq!(
        body["tls_client_certificate_bound_access_tokens"].as_bool(),
        Some(true)
    );
    let details_types: Vec<&str> = body["authorization_details_types_supported"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|v| v.as_str())
        .collect();
    assert_eq!(details_types, vec!["payment_initiation"]);
    assert_eq!(body["resource_name"].as_str(), Some("Example API"));
    // txn_challenge_jwks_uri was left empty -> fields must be absent.
    assert!(body.get("txn_challenge_jwks_uri").is_none());
    assert!(body
        .get("txn_challenge_signing_alg_values_supported")
        .is_none());
}

#[actix_web::test]
async fn per_resource_prm_includes_txn_challenge_fields_when_configured() {
    let storage = oauth2_storage_factory::create_storage("sqlite::memory:")
        .await
        .expect("create storage");
    storage.init().await.expect("init storage");

    let mut resource = ProtectedResource::new(
        "https://api.example.test".to_string(),
        "Example API".to_string(),
        vec!["read".to_string()],
    );
    resource.txn_challenge_jwks_uri = "https://api.example.test/jwks.json".to_string();
    storage
        .save_resource(&resource)
        .await
        .expect("save resource");

    let app = prm_app!(oidc_config(), storage);
    let req = test::TestRequest::get()
        .uri(&format!(
            "/.well-known/oauth-protected-resource/{}",
            resource.id
        ))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 200);

    let body: Value = test::read_body_json(resp).await;
    assert_eq!(
        body["txn_challenge_jwks_uri"].as_str(),
        Some("https://api.example.test/jwks.json")
    );
    let algs: Vec<&str> = body["txn_challenge_signing_alg_values_supported"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|v| v.as_str())
        .collect();
    assert_eq!(algs, vec!["RS256", "ES256"]);
}

#[actix_web::test]
async fn per_resource_prm_returns_404_not_found_for_unknown_id() {
    let storage = oauth2_storage_factory::create_storage("sqlite::memory:")
        .await
        .expect("create storage");
    storage.init().await.expect("init storage");

    let app = prm_app!(oidc_config(), storage);
    let req = test::TestRequest::get()
        .uri("/.well-known/oauth-protected-resource/does-not-exist")
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 404);

    let body: Value = test::read_body_json(resp).await;
    assert_eq!(body, serde_json::json!({"error": "not_found"}));
}
