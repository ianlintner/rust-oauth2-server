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

/// Derive OpenTelemetry semconv-friendly `db.name` and `net.peer.name` values
/// from a database URL. Best-effort and parameter-less: unrecognized shapes
/// return `None` so that `ObservedStorage` falls back to empty strings rather
/// than emitting misleading attributes.
///
/// - `postgres://user:pw@host:5432/mydb` → (`"mydb"`, `"host"`)
/// - `postgresql://host/mydb?sslmode=require` → (`"mydb"`, `"host"`)
/// - `sqlite::memory:` → (`":memory:"`, `None`) — peer is meaningless in-process
/// - `sqlite:///var/lib/app.db` → (`"app.db"`, `None`)
/// - `mongodb://host:27017/admin` → (`"admin"`, `"host"`)
fn derive_db_span_attrs(database_url: &str) -> (Option<String>, Option<String>) {
    // sqlite — no network peer, db.name is the file name or ":memory:".
    if let Some(rest) = database_url
        .strip_prefix("sqlite://")
        .or_else(|| database_url.strip_prefix("sqlite:"))
    {
        // sqlite::memory: (after stripping "sqlite:" leaves ":memory:")
        // sqlite://:memory: (after stripping "sqlite://" leaves ":memory:")
        if rest == ":memory:" || rest.is_empty() {
            return (Some(":memory:".to_string()), None);
        }
        // Strip leading slashes from absolute-path forms like "sqlite:///tmp/foo.db".
        let path = rest.trim_start_matches('/');
        // Drop any query string.
        let path = path.split('?').next().unwrap_or(path);
        let file = std::path::Path::new(path)
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or(path)
            .to_string();
        return (Some(file), None);
    }

    // postgres / postgresql / mongodb — parse user:pw@host:port/db?query.
    let (_scheme, rest) = match database_url.split_once("://") {
        Some((s, r)) => (s, r),
        None => return (None, None),
    };

    // Strip userinfo before '@'.
    let after_auth = rest.rsplit_once('@').map(|(_, r)| r).unwrap_or(rest);

    // Separate host[:port]/path?query.
    let (hostport, path_and_query) = match after_auth.split_once('/') {
        Some((hp, pq)) => (hp, pq),
        None => (after_auth, ""),
    };

    let host = hostport.split(':').next().unwrap_or("").to_string();
    let host = if host.is_empty() { None } else { Some(host) };

    let db_name = path_and_query
        .split('?')
        .next()
        .map(|s| s.trim_end_matches('/'))
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string());

    (db_name, host)
}

/// Create a storage backend based on URL scheme.
///
/// Supported:
/// - `postgres://...` and `sqlite:...` -> SQLx backend
/// - `mongodb://...` -> Mongo backend (requires `--features mongo`)
/// - `mongodb+srv://...` currently returns an error because the MongoDB DNS
///   resolver feature is disabled pending upstream hickory-proto fixes
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

    if is_mongo {
        #[cfg(feature = "mongo")]
        {
            let storage = mongo::MongoStorage::new(database_url).await?;
            let inner: DynStorage = Arc::new(storage);
            let (db_name, peer) = derive_db_span_attrs(database_url);
            let observed = ObservedStorage::new(inner, "mongodb".to_string(), db_name, peer);
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
        } else if database_url.starts_with("sqlite:") || database_url.starts_with("sqlite://") {
            "sqlite"
        } else {
            "sql"
        };

        let inner: DynStorage = Arc::new(storage);
        let (db_name, peer) = derive_db_span_attrs(database_url);
        let observed = ObservedStorage::new(inner, db_system.to_string(), db_name, peer);
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

    if is_mongo {
        #[cfg(feature = "mongo")]
        {
            let storage = mongo::MongoStorage::new(database_url).await?;
            let inner: DynStorage = Arc::new(storage);
            let (db_name, peer) = derive_db_span_attrs(database_url);
            let observed = ObservedStorage::new(inner, "mongodb".to_string(), db_name, peer);
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
    } else {
        Err(OAuth2Error::new(
            "server_error",
            Some(
                "SQL backend requested but the binary was built without SQL support (feature `sqlx` disabled)",
            ),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::derive_db_span_attrs;

    #[test]
    fn postgres_url_with_userinfo() {
        let (db, peer) = derive_db_span_attrs("postgres://user:pw@db.internal:5432/oauth2");
        assert_eq!(db.as_deref(), Some("oauth2"));
        assert_eq!(peer.as_deref(), Some("db.internal"));
    }

    #[test]
    fn postgresql_url_no_userinfo_with_query() {
        let (db, peer) = derive_db_span_attrs("postgresql://pg/app?sslmode=require");
        assert_eq!(db.as_deref(), Some("app"));
        assert_eq!(peer.as_deref(), Some("pg"));
    }

    #[test]
    fn sqlite_memory() {
        let (db, peer) = derive_db_span_attrs("sqlite::memory:");
        assert_eq!(db.as_deref(), Some(":memory:"));
        assert!(peer.is_none());
    }

    #[test]
    fn sqlite_file() {
        let (db, peer) = derive_db_span_attrs("sqlite:///var/lib/oauth2.db");
        assert_eq!(db.as_deref(), Some("oauth2.db"));
        assert!(peer.is_none());
    }

    #[test]
    fn mongodb_url() {
        let (db, peer) = derive_db_span_attrs("mongodb://mongo.svc:27017/admin");
        assert_eq!(db.as_deref(), Some("admin"));
        assert_eq!(peer.as_deref(), Some("mongo.svc"));
    }

    #[test]
    fn unknown_scheme_returns_none() {
        let (db, peer) = derive_db_span_attrs("gibberish");
        assert!(db.is_none());
        assert!(peer.is_none());
    }
}
