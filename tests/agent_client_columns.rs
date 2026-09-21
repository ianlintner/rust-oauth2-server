//! Phase 7 (agent/A2A OAuth) storage plumbing tests for `clients.allowed_actors`
//! (V25) and `authorization_codes.requested_actor` (V26).

use oauth2_core::{AuthorizationCode, Client, User};
use oauth2_ports::DynStorage;

async fn setup_storage() -> DynStorage {
    let storage = oauth2_storage_factory::create_storage("sqlite::memory:")
        .await
        .expect("create storage");
    storage.init().await.expect("init");
    storage
}

fn make_client(suffix: &str) -> Client {
    Client::new(
        format!("client-{suffix}"),
        "secret".to_string(),
        vec!["https://example.com/cb".to_string()],
        vec!["authorization_code".to_string()],
        "read".to_string(),
        format!("Test Client {suffix}"),
    )
}

fn make_user(suffix: &str) -> User {
    User::new(
        format!("user_{suffix}"),
        "$argon2id$seed".to_string(),
        format!("user_{suffix}@test.example"),
    )
}

#[actix_web::test]
async fn client_allowed_actors_round_trips_and_allows_actor_checks_work() {
    let storage = setup_storage().await;

    let mut client = make_client("allowed-actors");
    client.allowed_actors = serde_json::to_string(&vec!["agent-a".to_string()]).unwrap();
    storage.save_client(&client).await.expect("save client");

    let reloaded = storage
        .get_client(&client.client_id)
        .await
        .expect("get client")
        .expect("client present");

    assert_eq!(reloaded.allowed_actors, r#"["agent-a"]"#);
    assert!(reloaded.allows_actor("agent-a"));
    assert!(!reloaded.allows_actor("agent-b"));
}

#[actix_web::test]
async fn client_default_allowed_actors_is_empty_array_and_allows_nothing() {
    let storage = setup_storage().await;

    let client = make_client("default-allowed-actors");
    storage.save_client(&client).await.expect("save client");

    let reloaded = storage
        .get_client(&client.client_id)
        .await
        .expect("get client")
        .expect("client present");

    assert_eq!(reloaded.allowed_actors, "[]");
    assert!(!reloaded.allows_actor("agent-a"));
}

#[actix_web::test]
async fn client_allows_actor_returns_false_on_invalid_json() {
    let mut client = make_client("invalid-json");
    client.allowed_actors = "not-json".to_string();
    assert!(!client.allows_actor("agent-a"));
}

#[actix_web::test]
async fn authorization_code_requested_actor_round_trips() {
    let storage = setup_storage().await;

    let mut client = make_client("auth-code-actor");
    storage.save_client(&client).await.expect("save client");
    client.allowed_actors = serde_json::to_string(&vec!["agent-a".to_string()]).unwrap();

    let user = make_user("auth-code-actor");
    storage.save_user(&user).await.expect("save user");

    let mut auth_code = AuthorizationCode::new(
        "test-code-123".to_string(),
        client.client_id.clone(),
        user.id.clone(),
        "https://example.com/cb".to_string(),
        "read".to_string(),
        None,
        None,
        None,
        None,
        None,
        None,
    );
    auth_code.requested_actor = Some("agent-a".to_string());

    storage
        .save_authorization_code(&auth_code)
        .await
        .expect("save authorization code");

    let reloaded = storage
        .get_authorization_code(&auth_code.code)
        .await
        .expect("get authorization code")
        .expect("authorization code present");

    assert_eq!(reloaded.requested_actor, Some("agent-a".to_string()));
}

#[actix_web::test]
async fn authorization_code_requested_actor_defaults_to_none() {
    let storage = setup_storage().await;

    let client = make_client("auth-code-no-actor");
    storage.save_client(&client).await.expect("save client");

    let user = make_user("auth-code-no-actor");
    storage.save_user(&user).await.expect("save user");

    let auth_code = AuthorizationCode::new(
        "test-code-456".to_string(),
        client.client_id.clone(),
        user.id.clone(),
        "https://example.com/cb".to_string(),
        "read".to_string(),
        None,
        None,
        None,
        None,
        None,
        None,
    );

    storage
        .save_authorization_code(&auth_code)
        .await
        .expect("save authorization code");

    let reloaded = storage
        .get_authorization_code(&auth_code.code)
        .await
        .expect("get authorization code")
        .expect("authorization code present");

    assert_eq!(reloaded.requested_actor, None);
}
