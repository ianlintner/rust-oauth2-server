#![cfg(feature = "mongo")]

use std::time::Duration;

use rust_oauth2_server::{
    models::{AuthorizationCode, Client, Token, User},
    storage::{mongo::MongoStorage, Storage},
};
use testcontainers::clients::Cli;
use testcontainers_modules::mongo::Mongo as TcMongo;

// Basic CRUD contract tests for the MongoDB storage backend.
// Skips automatically unless RUN_TESTCONTAINERS=1 is set to avoid requiring Docker everywhere.
#[tokio::test]
async fn mongo_storage_roundtrip_smoke_test() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::var("RUN_TESTCONTAINERS").as_deref() != Ok("1") {
        eprintln!("skipping mongo_storage test (set RUN_TESTCONTAINERS=1 to run)");
        return Ok(());
    }

    let docker = Cli::default();

    // NOTE: MongoDB starts quickly, but we still do a retry loop before asserting readiness.
    let node = docker.run(TcMongo);
    let port = node.get_host_port_ipv4(27017);

    let uri = format!("mongodb://127.0.0.1:{}/oauth2_test", port);

    // Wait for MongoDB to accept connections.
    let storage = {
        let mut last_err: Option<String> = None;
        let mut storage: Option<MongoStorage> = None;

        for _ in 0..30 {
            match MongoStorage::new(&uri).await {
                Ok(s) => {
                    if let Err(e) = s.healthcheck().await {
                        last_err = Some(e.to_string());
                    } else {
                        storage = Some(s);
                        break;
                    }
                }
                Err(e) => last_err = Some(e.to_string()),
            }

            tokio::time::sleep(Duration::from_millis(300)).await;
        }

        storage.ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::Other,
                format!(
                "failed to connect to mongo testcontainer after retries: {}",
                last_err.unwrap_or_else(|| "unknown".to_string())
                ),
            )
        })?
    };

    storage.init().await.expect("mongo init should succeed");

    // Client roundtrip
    let client = Client::new(
        "client_1".to_string(),
        "secret".to_string(),
        vec!["http://localhost/cb".to_string()],
        vec!["client_credentials".to_string()],
        "read".to_string(),
        "test client".to_string(),
    );

    storage
        .save_client(&client)
        .await
        .expect("save_client should succeed");
    let fetched = storage
        .get_client("client_1")
        .await
        .expect("get_client should succeed")
        .expect("client should exist");
    assert_eq!(fetched.client_id, client.client_id);

    // Enforce uniqueness (best-effort contract parity with SQL UNIQUE constraints)
    let dup = storage.save_client(&client).await;
    assert!(dup.is_err(), "saving the same client_id twice should fail");

    // User roundtrip (exercise otherwise-unused trait methods)
    let user = User::new(
        "user_1".to_string(),
        "password_hash".to_string(),
        "user_1@example.com".to_string(),
    );
    storage
        .save_user(&user)
        .await
        .expect("save_user should succeed");
    let fetched_user = storage
        .get_user_by_username("user_1")
        .await
        .expect("get_user_by_username should succeed")
        .expect("user should exist");
    assert_eq!(fetched_user.username, user.username);

    // Token roundtrip + revoke
    let token = Token::new(
        "access_token_1".to_string(),
        Some("refresh_token_1".to_string()),
        client.client_id.clone(),
        None,
        "read".to_string(),
        3600,
    );

    storage
        .save_token(&token)
        .await
        .expect("save_token should succeed");
    let fetched_token = storage
        .get_token_by_access_token("access_token_1")
        .await
        .expect("get_token_by_access_token should succeed")
        .expect("token should exist");
    assert!(!fetched_token.revoked);

    storage
        .revoke_token("access_token_1")
        .await
        .expect("revoke_token should succeed");
    let revoked_token = storage
        .get_token_by_access_token("access_token_1")
        .await
        .expect("get_token_by_access_token should succeed")
        .expect("token should still exist");
    assert!(revoked_token.revoked);

    // Authorization code roundtrip + mark used
    let code = AuthorizationCode::new(
        "code_1".to_string(),
        client.client_id.clone(),
        "user_1".to_string(),
        "http://localhost/cb".to_string(),
        "read".to_string(),
        None,
        None,
    );

    storage
        .save_authorization_code(&code)
        .await
        .expect("save_authorization_code should succeed");
    let fetched_code = storage
        .get_authorization_code("code_1")
        .await
        .expect("get_authorization_code should succeed")
        .expect("auth code should exist");
    assert!(!fetched_code.used);

    storage
        .mark_authorization_code_used("code_1")
        .await
        .expect("mark_authorization_code_used should succeed");
    let used_code = storage
        .get_authorization_code("code_1")
        .await
        .expect("get_authorization_code should succeed")
        .expect("auth code should exist");
    assert!(used_code.used);

    Ok(())
}
