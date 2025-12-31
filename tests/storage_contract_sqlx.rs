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
