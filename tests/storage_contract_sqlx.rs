mod common;

use oauth2_ports::Storage;
use oauth2_storage_sqlx::SqlxStorage;

/// Contract tests for the default SQLx backend.
///
/// Uses a temporary SQLite file DB (not `:memory:`) so the SQLx pool can use multiple
/// connections safely.
#[tokio::test]
async fn sqlx_storage_contract() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let db_path = dir.path().join("oauth2_test.db");

    // Prefer the URL form for absolute paths.
    // The `mode=rwc` flag ensures the file is created if missing.
    let url = format!("sqlite://{}?mode=rwc", db_path.display());

    let storage = SqlxStorage::new(&url).await?;
    storage
        .init()
        .await
        .map_err(|e| std::io::Error::other(e.to_string()))?;

    common::run_storage_contract(&storage).await
}

/// Databases bootstrapped before the late `authorization_codes` columns
/// existed must be upgraded in place by `init()` (`CREATE TABLE IF NOT EXISTS`
/// never alters an existing table).
#[tokio::test]
async fn sqlx_init_upgrades_legacy_authorization_codes() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let db_path = dir.path().join("legacy.db");
    let url = format!("sqlite://{}?mode=rwc", db_path.display());

    let storage = SqlxStorage::new(&url).await?;
    storage
        .init()
        .await
        .map_err(|e| std::io::Error::other(e.to_string()))?;

    // Simulate a pre-V22 database: strip the newest columns.
    let pool = sqlx::SqlitePool::connect(&url).await?;
    for column in ["dpop_jkt", "token_family", "claims_request"] {
        sqlx::query(&format!(
            "ALTER TABLE authorization_codes DROP COLUMN {column}"
        ))
        .execute(&pool)
        .await?;
    }
    pool.close().await;

    // Re-running init must restore them, and the full contract must pass.
    storage
        .init()
        .await
        .map_err(|e| std::io::Error::other(e.to_string()))?;
    common::run_storage_contract(&storage).await
}
