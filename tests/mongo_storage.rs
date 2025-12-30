#![cfg(feature = "mongo")]

use std::time::Duration;

use rust_oauth2_server::storage::{mongo::MongoStorage, Storage};
use testcontainers::{core::IntoContainerPort, runners::AsyncRunner};
use testcontainers_modules::mongo::Mongo as TcMongo;

mod common;

// Basic CRUD contract tests for the MongoDB storage backend.
// Skips automatically unless RUN_TESTCONTAINERS=1 is set to avoid requiring Docker everywhere.
#[tokio::test]
async fn mongo_storage_roundtrip_smoke_test() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::var("RUN_TESTCONTAINERS").as_deref() != Ok("1") {
        eprintln!("skipping mongo_storage test (set RUN_TESTCONTAINERS=1 to run)");
        return Ok(());
    }

    // NOTE: MongoDB starts quickly, but we still do a retry loop before asserting readiness.
    let node = TcMongo::default().start().await?;
    let host = node.get_host().await?;
    let port = node.get_host_port_ipv4(27017.tcp()).await?;

    let uri = format!("mongodb://{host}:{port}/oauth2_test");

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
            std::io::Error::other(format!(
                "failed to connect to mongo testcontainer after retries: {}",
                last_err.unwrap_or_else(|| "unknown".to_string())
            ))
        })?
    };

    storage.init().await.expect("mongo init should succeed");

    common::run_storage_contract(&storage).await
}
