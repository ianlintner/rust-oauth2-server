use sqlx::{postgres::PgPoolOptions, Executor, Postgres};
use std::time::Duration;
use testcontainers::{clients::Cli, images::postgres::Postgres as TcPostgres};

// This test spins up a disposable Postgres via Testcontainers, applies our SQLx migrations,
// and verifies the schema is valid. Skips automatically unless RUN_TESTCONTAINERS=1 is set
// to avoid breaking environments without Docker (e.g., CI without privileges).
#[tokio::test]
async fn migrations_apply_successfully_on_postgres() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::var("RUN_TESTCONTAINERS").as_deref() != Ok("1") {
        eprintln!("skipping migrations_postgres test (set RUN_TESTCONTAINERS=1 to run)");
        return Ok(());
    }

    let docker = Cli::default();
    let node = docker.run(TcPostgres::default());
    let port = node.get_host_port_ipv4(5432);
    let url = format!("postgres://postgres:postgres@127.0.0.1:{}/postgres", port);

    // Wait for Postgres to accept connections
    let pool = {
        let mut last_err = None;
        for _ in 0..20 {
            match PgPoolOptions::new().max_connections(5).connect(&url).await {
                Ok(pool) => {
                    last_err = None;
                    break pool;
                }
                Err(e) => {
                    last_err = Some(e);
                    tokio::time::sleep(Duration::from_millis(500)).await;
                }
            }
        }
        .ok_or_else(|| {
            last_err.unwrap_or_else(|| sqlx::Error::Configuration("unknown error".into()))
        })?
    };

    // Apply migrations from the repository
    sqlx::migrate!("./migrations/sql").run(&pool).await?;

    // Simple sanity check
    pool.execute("SELECT 1").await?;

    Ok(())
}
