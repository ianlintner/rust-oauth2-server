use std::time::Instant;

/// A single token bucket for one key (e.g. one IP address).
///
/// Tokens refill at a constant rate. Each request consumes one token.
/// When the bucket is empty, requests are rejected.
pub struct TokenBucket {
    tokens: f64,
    last_refill: Instant,
    max_tokens: u32,
    refill_rate: f64,
}

impl TokenBucket {
    /// Create a new bucket at full capacity.
    ///
    /// `refill_rate` = `max_tokens / window_secs` tokens per second.
    pub fn new(max_tokens: u32, window_secs: u64) -> Self {
        if max_tokens == 0 {
            tracing::warn!(
                "TokenBucket created with max_tokens=0; clamping to 1 to avoid division-by-zero"
            );
        }
        if window_secs == 0 {
            tracing::warn!("TokenBucket created with window_secs=0; defaulting to 1 second");
        }
        let tokens = max_tokens.max(1); // clamp to minimum 1 token
        let window = window_secs.max(1); // clamp to minimum 1 second
        Self {
            tokens: tokens as f64,
            last_refill: Instant::now(),
            max_tokens: tokens,
            refill_rate: tokens as f64 / window as f64,
        }
    }

    /// Try to consume one token. Returns `(allowed, remaining)`.
    pub fn try_consume(&mut self) -> (bool, u32) {
        self.refill();
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            (true, self.tokens.floor() as u32)
        } else {
            (false, 0)
        }
    }

    /// Seconds until at least one token is available.
    pub fn seconds_until_refill(&self) -> f64 {
        if self.tokens >= 1.0 {
            0.0
        } else {
            (1.0 - self.tokens) / self.refill_rate
        }
    }

    /// The window duration in seconds (derived from capacity / rate).
    pub fn window_secs(&self) -> u64 {
        (self.max_tokens as f64 / self.refill_rate).ceil() as u64
    }

    fn refill(&mut self) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.refill_rate).min(self.max_tokens as f64);
        self.last_refill = now;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_bucket_is_full() {
        let bucket = TokenBucket::new(10, 60);
        assert_eq!(bucket.max_tokens, 10);
        assert!((bucket.tokens - 10.0).abs() < f64::EPSILON);
    }

    #[test]
    fn consume_reduces_tokens() {
        let mut bucket = TokenBucket::new(5, 60);
        let (allowed, remaining) = bucket.try_consume();
        assert!(allowed);
        assert_eq!(remaining, 4);
    }

    #[test]
    fn exhaust_bucket_rejects() {
        let mut bucket = TokenBucket::new(2, 60);
        assert!(bucket.try_consume().0); // 1 remaining
        assert!(bucket.try_consume().0); // 0 remaining
        let (allowed, remaining) = bucket.try_consume();
        assert!(!allowed);
        assert_eq!(remaining, 0);
    }

    #[test]
    fn seconds_until_refill_positive_when_empty() {
        let mut bucket = TokenBucket::new(2, 60);
        bucket.try_consume();
        bucket.try_consume();
        bucket.try_consume(); // rejected
        let wait = bucket.seconds_until_refill();
        assert!(wait > 0.0);
        assert!(wait <= 30.0); // refill_rate = 2/60 => ~30s per token
    }

    #[test]
    fn window_secs_roundtrip() {
        let bucket = TokenBucket::new(100, 60);
        assert_eq!(bucket.window_secs(), 60);
    }

    #[test]
    fn zero_window_secs_clamped_to_one() {
        let mut bucket = TokenBucket::new(2, 0);
        // refill_rate should be 2/1 = 2.0, not Infinity
        assert!(bucket.try_consume().0);
        assert!(bucket.try_consume().0);
        assert!(!bucket.try_consume().0); // should reject, not silently allow
    }

    #[test]
    fn zero_max_tokens_clamped_to_one() {
        let mut bucket = TokenBucket::new(0, 60);
        // max_tokens should be clamped to 1, not 0
        assert_eq!(bucket.max_tokens, 1);
        assert!(bucket.try_consume().0);
        assert!(!bucket.try_consume().0);
        // seconds_until_refill should not be Infinity or NaN
        let wait = bucket.seconds_until_refill();
        assert!(wait.is_finite());
        assert!(wait > 0.0);
    }
}
