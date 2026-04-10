//! Storage backend selection for the OAuth2 server.
//!
//! This crate centralizes URL-based backend selection (SQLx vs Mongo) and wraps
//! the chosen implementation with `ObservedStorage` for tracing.

use std::sync::Arc;

use oauth2_core::OAuth2Error;

pub use oauth2_observability::ObservedStorage;
pub use oauth2_ports::{DynStorage, Storage};

/// Backward-compatible module path for the SQLx adapter.
#[cfg(feature = "sqlx")]
pub mod sqlx {
    pub use oauth2_storage_sqlx::PoolConfig;
    pub use oauth2_storage_sqlx::SqlxStorage;
}

/// Backward-compatible module path for the Mongo adapter.
#[cfg(feature = "mongo")]
pub mod mongo {
    pub use oauth2_storage_mongo::MongoStorage;
}

/// Backward-compatible module path for the Cosmos DB adapter.
#[cfg(feature = "cosmosdb")]
pub mod cosmosdb {
    pub use oauth2_storage_cosmosdb::CosmosDbStorage;
}

/// Backward-compatible module path for the Cassandra adapter.
#[cfg(feature = "cassandra")]
pub mod cassandra {
    pub use oauth2_storage_cassandra::CassandraStorage;
}

/// Create a storage backend based on URL scheme.
///
/// Supported:
/// - `postgres://...`, `mysql://...`, and `sqlite:...` -> SQLx backend
/// - `mongodb://...` and `mongodb+srv://...` -> Mongo backend (requires `--features mongo`)
/// - `cosmosdb://...` -> Cosmos DB backend (requires `--features cosmosdb`)
/// - `cassandra://...` -> Cassandra backend (requires `--features cassandra`)
pub async fn create_storage(database_url: &str) -> Result<DynStorage, OAuth2Error> {
    create_storage_with_pool_config(database_url, None, None).await
}

/// Create a storage backend with explicit pool configuration.
#[cfg(feature = "sqlx")]
pub async fn create_storage_with_pool_config(
    database_url: &str,
    pool_config: Option<oauth2_storage_sqlx::PoolConfig>,
    read_url: Option<&str>,
) -> Result<DynStorage, OAuth2Error> {
    let is_mongo =
        database_url.starts_with("mongodb://") || database_url.starts_with("mongodb+srv://");
    let is_cosmos = database_url.starts_with("cosmosdb://");
    let is_cassandra = database_url.starts_with("cassandra://");

    if is_mongo {
        #[cfg(feature = "mongo")]
        {
            let storage = mongo::MongoStorage::new(database_url).await?;
            let inner: DynStorage = Arc::new(storage);
            let observed = ObservedStorage::new(inner, "mongodb".to_string());
            Ok(Arc::new(observed))
        }

        #[cfg(not(feature = "mongo"))]
        {
            Err(OAuth2Error::new(
                "server_error",
                Some(
                    "MongoDB backend requested but the binary was built without the `mongo` feature",
                ),
            ))
        }
    } else if is_cosmos {
        #[cfg(feature = "cosmosdb")]
        {
            let storage = cosmosdb::CosmosDbStorage::new(database_url).await?;
            let inner: DynStorage = Arc::new(storage);
            let observed = ObservedStorage::new(inner, "cosmosdb".to_string());
            Ok(Arc::new(observed))
        }

        #[cfg(not(feature = "cosmosdb"))]
        {
            Err(OAuth2Error::new(
                "server_error",
                Some(
                    "Cosmos DB backend requested but the binary was built without the `cosmosdb` feature",
                ),
            ))
        }
    } else if is_cassandra {
        #[cfg(feature = "cassandra")]
        {
            let storage = cassandra::CassandraStorage::new(database_url).await?;
            let inner: DynStorage = Arc::new(storage);
            let observed = ObservedStorage::new(inner, "cassandra".to_string());
            Ok(Arc::new(observed))
        }

        #[cfg(not(feature = "cassandra"))]
        {
            Err(OAuth2Error::new(
                "server_error",
                Some(
                    "Cassandra backend requested but the binary was built without the `cassandra` feature",
                ),
            ))
        }
    } else {
        let storage = match (pool_config, read_url) {
            (Some(pc), Some(ru)) => {
                oauth2_storage_sqlx::SqlxStorage::with_read_replica(database_url, ru, pc).await?
            }
            (Some(pc), None) => {
                oauth2_storage_sqlx::SqlxStorage::with_pool_config(database_url, pc).await?
            }
            (None, _) => oauth2_storage_sqlx::SqlxStorage::new(database_url).await?,
        };
        let db_system = if database_url.starts_with("postgres://")
            || database_url.starts_with("postgresql://")
        {
            "postgresql"
        } else if database_url.starts_with("mysql://") || database_url.starts_with("mariadb://") {
            "mysql"
        } else if database_url.starts_with("sqlite:") || database_url.starts_with("sqlite://") {
            "sqlite"
        } else {
            "sql"
        };

        let inner: DynStorage = Arc::new(storage);
        let observed = ObservedStorage::new(inner, db_system.to_string());
        Ok(Arc::new(observed))
    }
}

/// Create a storage backend with explicit pool configuration.
///
/// When built without the `sqlx` feature the pool-config and read-url
/// parameters are accepted for API compatibility but ignored.
#[cfg(not(feature = "sqlx"))]
pub async fn create_storage_with_pool_config(
    database_url: &str,
    _pool_config: Option<()>,
    _read_url: Option<&str>,
) -> Result<DynStorage, OAuth2Error> {
    let is_mongo =
        database_url.starts_with("mongodb://") || database_url.starts_with("mongodb+srv://");
    let is_cosmos = database_url.starts_with("cosmosdb://");
    let is_cassandra = database_url.starts_with("cassandra://");

    if is_mongo {
        #[cfg(feature = "mongo")]
        {
            let storage = mongo::MongoStorage::new(database_url).await?;
            let inner: DynStorage = Arc::new(storage);
            let observed = ObservedStorage::new(inner, "mongodb".to_string());
            Ok(Arc::new(observed))
        }

        #[cfg(not(feature = "mongo"))]
        {
            Err(OAuth2Error::new(
                "server_error",
                Some(
                    "MongoDB backend requested but the binary was built without the `mongo` feature",
                ),
            ))
        }
    } else if is_cosmos {
        #[cfg(feature = "cosmosdb")]
        {
            let storage = cosmosdb::CosmosDbStorage::new(database_url).await?;
            let inner: DynStorage = Arc::new(storage);
            let observed = ObservedStorage::new(inner, "cosmosdb".to_string());
            Ok(Arc::new(observed))
        }

        #[cfg(not(feature = "cosmosdb"))]
        {
            Err(OAuth2Error::new(
                "server_error",
                Some(
                    "Cosmos DB backend requested but the binary was built without the `cosmosdb` feature",
                ),
            ))
        }
    } else if is_cassandra {
        #[cfg(feature = "cassandra")]
        {
            let storage = cassandra::CassandraStorage::new(database_url).await?;
            let inner: DynStorage = Arc::new(storage);
            let observed = ObservedStorage::new(inner, "cassandra".to_string());
            Ok(Arc::new(observed))
        }

        #[cfg(not(feature = "cassandra"))]
        {
            Err(OAuth2Error::new(
                "server_error",
                Some(
                    "Cassandra backend requested but the binary was built without the `cassandra` feature",
                ),
            ))
        }
    } else {
        Err(OAuth2Error::new(
            "server_error",
            Some(
                "SQL backend requested but the binary was built without SQL support (feature `sqlx` disabled)",
            ),
        ))
    }
}
