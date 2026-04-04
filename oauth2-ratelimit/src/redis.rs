//! Redis-backed rate limiter using atomic Lua script.
//!
//! Enabled via the `redis-backend` feature flag.

use std::time::{Duration, SystemTime};

use redis::aio::ConnectionManager;

use crate::{RateLimitError, RateLimitResult, RateLimiter};

/// Rate limiter using Redis as the backend store.
///
/// Uses a fixed-window counter per key with an atomic Lua script.
/// Key format: `ratelimit:{key}`, TTL = `window_secs`.
pub struct RedisRateLimiter {
    conn: ConnectionManager,
    max_requests: u32,
    window_secs: u64,
}

impl RedisRateLimiter {
    /// Create a new Redis rate limiter.
    ///
    /// Establishes a connection pool to the given Redis URL.
    pub async fn new(
        redis_url: &str,
        max_requests: u32,
        window_secs: u64,
    ) -> Result<Self, RateLimitError> {
        let client = redis::Client::open(redis_url)
            .map_err(|e| RateLimitError::Backend(format!("Redis connection error: {e}")))?;
        let conn = ConnectionManager::new(client)
            .await
            .map_err(|e| RateLimitError::Backend(format!("Redis connection manager error: {e}")))?;
        Ok(Self {
            conn,
            max_requests,
            window_secs,
        })
    }
}

#[async_trait::async_trait]
impl RateLimiter for RedisRateLimiter {
    async fn check(&self, key: &str) -> Result<RateLimitResult, RateLimitError> {
        let redis_key = format!("ratelimit:{key}");
        let mut conn = self.conn.clone();

        // Atomic INCR + EXPIRE via Lua script to avoid race conditions.
        // If the process crashes between INCR and EXPIRE, the key would
        // persist forever with no TTL, permanently blocking that client.
        // We also handle pre-existing keys without TTL (e.g. leftover from
        // a prior bug or manual Redis writes) by checking TTL inside the script.
        let script = redis::Script::new(
            r"local count = redis.call('INCR', KEYS[1])
if count == 1 then
    redis.call('EXPIRE', KEYS[1], ARGV[1])
end
local ttl = redis.call('TTL', KEYS[1])
if ttl < 0 then
    redis.call('EXPIRE', KEYS[1], ARGV[1])
    ttl = tonumber(ARGV[1])
end
return {count, ttl}",
        );
        let (count, ttl): (u32, i64) = script
            .key(&redis_key)
            .arg(self.window_secs as i64)
            .invoke_async(&mut conn)
            .await
            .map_err(|e| RateLimitError::Backend(format!("Redis Lua script error: {e}")))?;

        let reset_at = SystemTime::now() + Duration::from_secs(ttl.max(0) as u64);
        let allowed = count <= self.max_requests;
        let remaining = if allowed {
            self.max_requests - count
        } else {
            0
        };
        let retry_after = if allowed {
            None
        } else {
            Some(Duration::from_secs(ttl.max(1) as u64))
        };

        Ok(RateLimitResult {
            allowed,
            remaining,
            limit: self.max_requests,
            reset_at,
            retry_after,
        })
    }
}
