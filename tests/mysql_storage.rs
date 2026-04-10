mod common;

use oauth2_ports::Storage;
use oauth2_storage_sqlx::SqlxStorage;

/// Contract tests for the MySQL SQLx backend.
///
/// Skips automatically unless `OAUTH2_MYSQL_TEST_URL` is set so local dev and CI
/// without MySQL stay green.
#[tokio::test]
async fn mysql_storage_contract() -> Result<(), Box<dyn std::error::Error>> {
    let database_url = match std::env::var("OAUTH2_MYSQL_TEST_URL") {
        Ok(url) if !url.is_empty() => url,
        _ => {
            eprintln!(
                "skipping mysql_storage test (set OAUTH2_MYSQL_TEST_URL to run, e.g. mysql://user:pass@localhost:3306/oauth2_test)"
            );
            return Ok(());
        }
    };

    let storage = SqlxStorage::new(&database_url).await?;
    storage
        .init()
        .await
        .map_err(|e| std::io::Error::other(e.to_string()))?;

    common::run_storage_contract(&storage).await
}
