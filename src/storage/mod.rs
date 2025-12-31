use std::sync::Arc;

use crate::models::OAuth2Error;

pub use oauth2_ports::{DynStorage, Storage};

mod observed;
pub use observed::ObservedStorage;

/// Backward-compatible module path for the SQLx adapter.
pub mod sqlx {
    pub use oauth2_storage_sqlx::SqlxStorage;
}

#[cfg(feature = "mongo")]
pub mod mongo {
    pub use oauth2_storage_mongo::MongoStorage;
}

/// Create a storage backend based on URL scheme.
///
/// Supported:
/// - `postgres://...` and `sqlite:...` -> SQLx backend
/// - `mongodb://...` and `mongodb+srv://...` -> Mongo backend (requires `--features mongo`)
pub async fn create_storage(database_url: &str) -> Result<DynStorage, OAuth2Error> {
    if database_url.starts_with("mongodb://") || database_url.starts_with("mongodb+srv://") {
        #[cfg(feature = "mongo")]
        {
            let storage = mongo::MongoStorage::new(database_url).await?;
            let inner: DynStorage = Arc::new(storage);
            let observed = observed::ObservedStorage::new(inner, "mongodb".to_string());
            return Ok(Arc::new(observed));
        }

        #[cfg(not(feature = "mongo"))]
        {
            return Err(OAuth2Error::new(
                "server_error",
                Some("MongoDB backend requested but the binary was built without the `mongo` feature"),
            ));
        }
    }

    // Default to SQLx backend for sqlite/postgres.
    let storage = oauth2_storage_sqlx::SqlxStorage::new(database_url).await?;
    let db_system =
        if database_url.starts_with("postgres://") || database_url.starts_with("postgresql://") {
            "postgresql"
        } else if database_url.starts_with("sqlite:") || database_url.starts_with("sqlite://") {
            "sqlite"
        } else {
            "sql"
        };

    let inner: DynStorage = Arc::new(storage);
    let observed = observed::ObservedStorage::new(inner, db_system.to_string());
    Ok(Arc::new(observed))
}
