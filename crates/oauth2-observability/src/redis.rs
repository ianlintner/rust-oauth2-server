//! Traced wrapper around `redis::aio::ConnectionManager` that emits an
//! OpenTelemetry-semconv span (`redis.command`) for each Redis command.
//!
//! Spans carry:
//!   - `db.system = "redis"`
//!   - `db.operation = "<COMMAND>"` (e.g. `GET`, `SET`, `LPUSH`)
//!   - `db.redis.database_index` — the numeric DB index from the URL
//!   - `net.peer.name` — `host:port` from the URL
//!   - `otel.kind = "client"`
//!
//! Key values are deliberately *not* recorded (PII / high-cardinality risk).
//!
//! Enabled via the `redis` feature on `oauth2-observability`. The wrapper uses
//! `tracing` only — `otel` merely controls whether those spans are exported
//! via OTLP. This module is compiled out entirely when `redis` is not enabled
//! so that callers who don't need Redis do not pull the `redis` crate in.

use redis::aio::ConnectionManager;
use redis::{AsyncCommands, FromRedisValue, RedisResult, Script, ToRedisArgs};
use tracing::{field, info_span, Instrument};

use crate::telemetry::annotate_span_with_trace_ids;

/// Thin wrapper around `redis::aio::ConnectionManager` that records an
/// OTel-semconv span for every Redis command.
///
/// Wraps, not replaces — the inner `ConnectionManager` is cheaply clonable
/// and any helper that still needs the raw type can call [`Self::inner_clone`].
#[derive(Clone)]
pub struct TracedRedis {
    inner: ConnectionManager,
    db_index: i64,
    peer: String,
}

impl TracedRedis {
    /// Wrap a connection manager with the given peer (`host:port`) and DB index.
    pub fn new(inner: ConnectionManager, peer: String, db_index: i64) -> Self {
        Self {
            inner,
            db_index,
            peer,
        }
    }

    /// Wrap a connection manager, parsing the `peer` and `db_index` from the
    /// Redis URL it was built from. Malformed URLs degrade gracefully: `peer`
    /// becomes empty and `db_index` becomes `0`.
    pub fn from_url(inner: ConnectionManager, redis_url: &str) -> Self {
        let (peer, db_index) = parse_peer_and_db(redis_url);
        Self::new(inner, peer, db_index)
    }

    /// Borrow the underlying connection manager (useful for callers that need
    /// to invoke a command this wrapper does not yet expose). Use sparingly:
    /// commands issued through the raw handle are not traced.
    pub fn inner_clone(&self) -> ConnectionManager {
        self.inner.clone()
    }

    fn span(&self, operation: &'static str) -> tracing::Span {
        let span = info_span!(
            "redis.command",
            trace_id = field::Empty,
            span_id = field::Empty,
            "db.system" = "redis",
            "db.operation" = operation,
            "db.redis.database_index" = self.db_index,
            "net.peer.name" = %self.peer,
            "otel.kind" = "client",
        );
        annotate_span_with_trace_ids(&span);
        span
    }

    /// `GET key`.
    pub async fn get<K, V>(&mut self, key: K) -> RedisResult<V>
    where
        K: ToRedisArgs + Send + Sync,
        V: FromRedisValue,
    {
        let span = self.span("GET");
        async { self.inner.get(key).await }.instrument(span).await
    }

    /// `SET key value EX seconds` — value with TTL. Matches the existing cache
    /// call sites, which always pair SET with an `EX` expiry.
    pub async fn set_ex<K, V>(&mut self, key: K, value: V, seconds: u64) -> RedisResult<()>
    where
        K: ToRedisArgs + Send + Sync,
        V: ToRedisArgs + Send + Sync,
    {
        let span = self.span("SET");
        async {
            redis::cmd("SET")
                .arg(key)
                .arg(value)
                .arg("EX")
                .arg(seconds)
                .query_async(&mut self.inner)
                .await
        }
        .instrument(span)
        .await
    }

    /// `DEL key`.
    pub async fn del<K>(&mut self, key: K) -> RedisResult<()>
    where
        K: ToRedisArgs + Send + Sync,
    {
        let span = self.span("DEL");
        async {
            redis::cmd("DEL")
                .arg(key)
                .query_async(&mut self.inner)
                .await
        }
        .instrument(span)
        .await
    }

    /// `LPUSH key value`.
    pub async fn lpush<K, V>(&mut self, key: K, value: V) -> RedisResult<()>
    where
        K: ToRedisArgs + Send + Sync,
        V: ToRedisArgs + Send + Sync,
    {
        let span = self.span("LPUSH");
        async { self.inner.lpush(key, value).await }
            .instrument(span)
            .await
    }

    /// `LTRIM key start stop`.
    pub async fn ltrim<K>(&mut self, key: K, start: isize, stop: isize) -> RedisResult<()>
    where
        K: ToRedisArgs + Send + Sync,
    {
        let span = self.span("LTRIM");
        async { self.inner.ltrim(key, start, stop).await }
            .instrument(span)
            .await
    }

    /// `EXPIRE key seconds`.
    pub async fn expire<K>(&mut self, key: K, seconds: i64) -> RedisResult<()>
    where
        K: ToRedisArgs + Send + Sync,
    {
        let span = self.span("EXPIRE");
        async { self.inner.expire(key, seconds).await }
            .instrument(span)
            .await
    }

    /// `LRANGE key start stop`.
    pub async fn lrange<K, V>(&mut self, key: K, start: isize, stop: isize) -> RedisResult<V>
    where
        K: ToRedisArgs + Send + Sync,
        V: FromRedisValue,
    {
        let span = self.span("LRANGE");
        async { self.inner.lrange(key, start, stop).await }
            .instrument(span)
            .await
    }

    /// Invoke a pre-built Lua [`Script`] (atomic INCR+EXPIRE pattern in the
    /// Redis rate limiter). Recorded as `db.operation = "EVALSHA"` — the
    /// `redis` crate's `Script::invoke_async` uses `EVALSHA` with a fallback
    /// to `EVAL` on `NOSCRIPT`.
    pub async fn script_invoke<V>(
        &mut self,
        invocation: &redis::ScriptInvocation<'_>,
    ) -> RedisResult<V>
    where
        V: FromRedisValue,
    {
        let span = self.span("EVALSHA");
        async { invocation.invoke_async(&mut self.inner).await }
            .instrument(span)
            .await
    }

    /// Convenience: clone the connection manager and prepare a traced handle
    /// keyed at the same peer/db — useful when code that still uses the raw
    /// type needs a short-lived traced handle.
    pub fn fork(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            db_index: self.db_index,
            peer: self.peer.clone(),
        }
    }

    /// Exposed so rate-limit callers (which build a [`Script`] once and reuse
    /// it) can construct the invocation without re-importing `redis`.
    pub fn script(source: &str) -> Script {
        Script::new(source)
    }
}

/// Parse `redis://[user[:pass]@]host[:port][/db]` into (`host:port`, `db`).
/// On failure returns empty peer / db `0`.
fn parse_peer_and_db(url: &str) -> (String, i64) {
    // Strip scheme.
    let after_scheme = url.split_once("://").map(|(_, rest)| rest).unwrap_or(url);

    // Drop optional `user:pass@` userinfo.
    let host_and_rest = after_scheme
        .split_once('@')
        .map(|(_, rest)| rest)
        .unwrap_or(after_scheme);

    // Split host/port from path.
    let (hostport, path) = match host_and_rest.split_once('/') {
        Some((hp, p)) => (hp, p),
        None => (host_and_rest, ""),
    };

    // Default the port to 6379 if none was given — keeps `net.peer.name`
    // useful in service graphs even for minimal URLs.
    let peer = if hostport.is_empty() {
        String::new()
    } else if hostport.contains(':') {
        hostport.to_string()
    } else {
        format!("{hostport}:6379")
    };

    // Strip any `?query` off the path before parsing the DB index.
    let db_part = path.split_once('?').map(|(p, _)| p).unwrap_or(path);
    let db_index = db_part.parse::<i64>().unwrap_or(0);

    (peer, db_index)
}

#[cfg(test)]
mod tests {
    use super::parse_peer_and_db;

    #[test]
    fn parses_host_and_port() {
        assert_eq!(
            parse_peer_and_db("redis://example.com:6380/2"),
            ("example.com:6380".to_string(), 2)
        );
    }

    #[test]
    fn defaults_port_when_missing() {
        assert_eq!(
            parse_peer_and_db("redis://cache/0"),
            ("cache:6379".to_string(), 0)
        );
    }

    #[test]
    fn strips_userinfo() {
        assert_eq!(
            parse_peer_and_db("redis://default:secret@cache.internal:6380/3"),
            ("cache.internal:6380".to_string(), 3)
        );
    }

    #[test]
    fn tolerates_missing_db() {
        assert_eq!(
            parse_peer_and_db("redis://cache.internal:6380"),
            ("cache.internal:6380".to_string(), 0)
        );
    }

    #[test]
    fn tolerates_garbage() {
        assert_eq!(
            parse_peer_and_db("not-a-url"),
            ("not-a-url:6379".to_string(), 0)
        );
    }
}
