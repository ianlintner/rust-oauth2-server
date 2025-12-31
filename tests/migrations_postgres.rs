use sqlx::{postgres::PgPoolOptions, Executor};
use std::{fs, path::PathBuf, time::Duration};
use testcontainers::{core::IntoContainerPort, runners::AsyncRunner};
use testcontainers_modules::postgres::Postgres as TcPostgres;

use oauth2_core::Token;
use uuid::Uuid;

// This test spins up a disposable Postgres via Testcontainers, applies our SQLx migrations,
// and verifies the schema is valid. Skips automatically unless RUN_TESTCONTAINERS=1 is set
// to avoid breaking environments without Docker (e.g., CI without privileges).
#[tokio::test]
async fn migrations_apply_successfully_on_postgres() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::var("RUN_TESTCONTAINERS").as_deref() != Ok("1") {
        eprintln!("skipping migrations_postgres test (set RUN_TESTCONTAINERS=1 to run)");
        return Ok(());
    }

    let node = TcPostgres::default().start().await?;
    let host = node.get_host().await?;
    let port = node.get_host_port_ipv4(5432.tcp()).await?;
    let url = format!("postgres://postgres:postgres@{host}:{port}/postgres");

    // Wait for Postgres to accept connections
    let pool = {
        let mut last_err = None;
        let mut last_pool = None;

        for _ in 0..20 {
            match PgPoolOptions::new().max_connections(5).connect(&url).await {
                Ok(pool) => {
                    last_pool = Some(pool);
                    break;
                }
                Err(e) => {
                    last_err = Some(e);
                    tokio::time::sleep(Duration::from_millis(500)).await;
                }
            }
        }

        last_pool.ok_or_else(|| {
            last_err.unwrap_or_else(|| sqlx::Error::Configuration("unknown error".into()))
        })?
    };

    // Apply Flyway-style migrations manually to avoid sqlx filename parsing expectations
    let mut entries: Vec<PathBuf> = fs::read_dir("./migrations/sql")?
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.extension().and_then(|s| s.to_str()) == Some("sql"))
        .collect();

    entries.sort();

    for path in entries {
        let sql = fs::read_to_string(&path)?;
        pool.execute(sql.as_str()).await?;
    }

    // Simple sanity check
    pool.execute("SELECT 1").await?;

    // Regression check: ensure we can decode a Token row from Postgres.
    // This protects against Rust/SQL type mismatches (e.g., INT4 vs i64) that only show up at runtime.
    let client_row_id = Uuid::new_v4().to_string();
    sqlx::query(
        r#"
        INSERT INTO clients (id, client_id, client_secret, redirect_uris, grant_types, scope, name, created_at, updated_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, now(), now())
        ON CONFLICT (client_id) DO NOTHING
        "#,
    )
    .bind(&client_row_id)
    .bind("test_client_id")
    .bind("test_client_secret")
    .bind("[]")
    .bind("[\"client_credentials\"]")
    .bind("read")
    .bind("test")
    .execute(&pool)
    .await?;

    let token_row_id = Uuid::new_v4().to_string();
    sqlx::query(
        r#"
        INSERT INTO tokens (
            id,
            access_token,
            refresh_token,
            token_type,
            expires_in,
            scope,
            client_id,
            user_id,
            created_at,
            expires_at,
            revoked
        )
        VALUES ($1, $2, NULL, $3, $4, $5, $6, NULL, now(), now() + interval '1 hour', FALSE)
        ON CONFLICT (access_token) DO NOTHING
        "#,
    )
    .bind(&token_row_id)
    .bind("test_access_token")
    .bind("Bearer")
    .bind(3600_i32)
    .bind("read")
    .bind("test_client_id")
    .execute(&pool)
    .await?;

    let token: Token = sqlx::query_as("SELECT * FROM tokens WHERE access_token = $1")
        .bind("test_access_token")
        .fetch_one(&pool)
        .await?;

    assert_eq!(token.access_token, "test_access_token");
    assert_eq!(token.expires_in, 3600);
    assert!(token.is_valid());

    Ok(())
}
