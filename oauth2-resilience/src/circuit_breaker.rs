//! Circuit breaker implementation.
//!
//! Prevents cascading failures by fast-failing requests when error rates
//! are too high.  The circuit transitions between three states:
//!
//! * **Closed** – normal operation; failures are counted.
//! * **Open**   – fast-fail all requests; a recovery timer is running.
//! * **HalfOpen** – a limited probe window: successes close the circuit,
//!   failures re-open it immediately.

use std::sync::atomic::{AtomicU32, AtomicU8, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Public state of the circuit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitState {
    /// Normal operation.
    Closed,
    /// Fast-failing all requests.
    Open,
    /// Probing for recovery.
    HalfOpen,
}

impl CircuitState {
    /// Numeric encoding stored in the atomic (0 = Closed, 1 = Open, 2 = HalfOpen).
    fn from_u8(v: u8) -> Self {
        match v {
            1 => Self::Open,
            2 => Self::HalfOpen,
            _ => Self::Closed,
        }
    }

    fn as_u8(self) -> u8 {
        match self {
            Self::Closed => 0,
            Self::Open => 1,
            Self::HalfOpen => 2,
        }
    }

    /// Numeric value suitable for a Prometheus gauge
    /// (0 = Closed, 1 = Open, 2 = HalfOpen).
    pub fn as_gauge_value(self) -> f64 {
        match self {
            Self::Closed => 0.0,
            Self::Open => 1.0,
            Self::HalfOpen => 2.0,
        }
    }
}

/// Configuration for a circuit breaker.
#[derive(Debug, Clone)]
pub struct CircuitBreakerConfig {
    /// Number of consecutive failures before the circuit opens.
    pub failure_threshold: u32,
    /// Number of consecutive successes in half-open state before the circuit closes.
    pub success_threshold: u32,
    /// How long the circuit stays open before moving to half-open.
    pub open_duration: Duration,
    /// Maximum number of concurrent probes allowed in half-open state.
    pub half_open_max_probes: u32,
}

impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        Self {
            failure_threshold: 5,
            success_threshold: 2,
            open_duration: Duration::from_secs(30),
            half_open_max_probes: 3,
        }
    }
}

/// Thread-safe circuit breaker.
///
/// Clone cheaply — all clones share the same underlying state.
#[derive(Clone)]
pub struct CircuitBreaker {
    inner: Arc<CircuitBreakerInner>,
}

struct CircuitBreakerInner {
    /// Encoded as u8; see [`CircuitState::from_u8`].
    state: AtomicU8,
    /// Consecutive failure count (reset on success or open→half-open).
    failure_count: AtomicU32,
    /// Consecutive success count in half-open (reset on state change).
    success_count: AtomicU32,
    /// Number of in-flight probes in half-open state.
    probe_count: AtomicU32,
    /// Total trips (open transitions) since creation.
    total_trips: AtomicU32,
    /// When the circuit was opened (protected by the transition mutex).
    opened_at: Mutex<Option<Instant>>,
    config: CircuitBreakerConfig,
    /// Optional name for log messages.
    name: String,
}

impl CircuitBreaker {
    /// Create a new circuit breaker with the given configuration.
    pub fn new(name: impl Into<String>, config: CircuitBreakerConfig) -> Self {
        Self {
            inner: Arc::new(CircuitBreakerInner {
                state: AtomicU8::new(CircuitState::Closed.as_u8()),
                failure_count: AtomicU32::new(0),
                success_count: AtomicU32::new(0),
                probe_count: AtomicU32::new(0),
                total_trips: AtomicU32::new(0),
                opened_at: Mutex::new(None),
                config,
                name: name.into(),
            }),
        }
    }

    /// Create a circuit breaker with default settings.
    pub fn with_defaults(name: impl Into<String>) -> Self {
        Self::new(name, CircuitBreakerConfig::default())
    }

    /// Returns the current observable state.
    pub fn state(&self) -> CircuitState {
        self.check_transition();
        CircuitState::from_u8(self.inner.state.load(Ordering::Acquire))
    }

    /// Total number of times the circuit has tripped open.
    pub fn total_trips(&self) -> u32 {
        self.inner.total_trips.load(Ordering::Relaxed)
    }

    /// The configured open duration (used for deriving `Retry-After` headers).
    pub fn open_duration(&self) -> Duration {
        self.inner.config.open_duration
    }

    /// Returns `true` if the request is allowed through.
    ///
    /// Call [`record_success`] or [`record_failure`] after the operation
    /// completes so the circuit breaker can track outcomes and release the
    /// probe slot.
    pub fn allow_request(&self) -> bool {
        self.check_transition();
        let state = CircuitState::from_u8(self.inner.state.load(Ordering::Acquire));
        match state {
            CircuitState::Closed => true,
            CircuitState::Open => false,
            CircuitState::HalfOpen => {
                // Use a CAS loop so a rejected call never consumes a slot.
                loop {
                    let current = self.inner.probe_count.load(Ordering::Acquire);
                    if current >= self.inner.config.half_open_max_probes {
                        return false;
                    }
                    if self
                        .inner
                        .probe_count
                        .compare_exchange_weak(
                            current,
                            current + 1,
                            Ordering::AcqRel,
                            Ordering::Relaxed,
                        )
                        .is_ok()
                    {
                        return true;
                    }
                }
            }
        }
    }

    /// Record a successful operation.
    pub fn record_success(&self) {
        let state = CircuitState::from_u8(self.inner.state.load(Ordering::Acquire));
        match state {
            CircuitState::Closed => {
                self.inner.failure_count.store(0, Ordering::Release);
            }
            CircuitState::HalfOpen => {
                // Release the probe slot.
                self.inner.probe_count.fetch_sub(1, Ordering::AcqRel);
                let successes = self.inner.success_count.fetch_add(1, Ordering::AcqRel) + 1;
                if successes >= self.inner.config.success_threshold {
                    self.transition_to(CircuitState::Closed);
                }
            }
            CircuitState::Open => {} // ignore
        }
    }

    /// Record a failed operation.
    pub fn record_failure(&self) {
        let state = CircuitState::from_u8(self.inner.state.load(Ordering::Acquire));
        match state {
            CircuitState::Closed => {
                let failures = self.inner.failure_count.fetch_add(1, Ordering::AcqRel) + 1;
                if failures >= self.inner.config.failure_threshold {
                    self.transition_to(CircuitState::Open);
                }
            }
            CircuitState::HalfOpen => {
                // Release the probe slot, then re-open immediately.
                self.inner.probe_count.fetch_sub(1, Ordering::AcqRel);
                self.transition_to(CircuitState::Open);
            }
            CircuitState::Open => {} // already open
        }
    }

    // --- private helpers ---

    /// Check whether the open-duration timer has expired and transition to
    /// half-open if so.
    fn check_transition(&self) {
        if CircuitState::from_u8(self.inner.state.load(Ordering::Acquire)) != CircuitState::Open {
            return;
        }
        let opened_at = {
            let guard = self
                .inner
                .opened_at
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            *guard
        };
        if let Some(opened) = opened_at {
            if opened.elapsed() >= self.inner.config.open_duration {
                self.transition_to(CircuitState::HalfOpen);
            }
        }
    }

    fn transition_to(&self, new_state: CircuitState) {
        let old = CircuitState::from_u8(self.inner.state.swap(new_state.as_u8(), Ordering::AcqRel));

        if old == new_state {
            return;
        }

        tracing::warn!(
            circuit = %self.inner.name,
            from = ?old,
            to = ?new_state,
            "Circuit breaker state transition"
        );

        match new_state {
            CircuitState::Open => {
                *self
                    .inner
                    .opened_at
                    .lock()
                    .unwrap_or_else(|e| e.into_inner()) = Some(Instant::now());
                self.inner.failure_count.store(0, Ordering::Release);
                self.inner.success_count.store(0, Ordering::Release);
                self.inner.probe_count.store(0, Ordering::Release);
                self.inner.total_trips.fetch_add(1, Ordering::AcqRel);
            }
            CircuitState::HalfOpen => {
                self.inner.success_count.store(0, Ordering::Release);
                self.inner.probe_count.store(0, Ordering::Release);
            }
            CircuitState::Closed => {
                self.inner.failure_count.store(0, Ordering::Release);
                self.inner.success_count.store(0, Ordering::Release);
                self.inner.probe_count.store(0, Ordering::Release);
                *self
                    .inner
                    .opened_at
                    .lock()
                    .unwrap_or_else(|e| e.into_inner()) = None;
                tracing::info!(circuit = %self.inner.name, "Circuit breaker closed — service recovered");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fast_cfg() -> CircuitBreakerConfig {
        CircuitBreakerConfig {
            failure_threshold: 3,
            success_threshold: 2,
            open_duration: Duration::from_millis(50),
            half_open_max_probes: 2,
        }
    }

    #[test]
    fn starts_closed() {
        let cb = CircuitBreaker::new("test", fast_cfg());
        assert_eq!(cb.state(), CircuitState::Closed);
        assert!(cb.allow_request());
    }

    #[test]
    fn opens_after_failure_threshold() {
        let cb = CircuitBreaker::new("test", fast_cfg());
        for _ in 0..3 {
            cb.record_failure();
        }
        assert_eq!(cb.state(), CircuitState::Open);
        assert!(!cb.allow_request());
        assert_eq!(cb.total_trips(), 1);
    }

    #[test]
    fn success_resets_failure_count() {
        let cb = CircuitBreaker::new("test", fast_cfg());
        cb.record_failure();
        cb.record_failure();
        cb.record_success(); // resets to 0
        cb.record_failure();
        cb.record_failure();
        // only 2 failures since last success → still closed
        assert_eq!(cb.state(), CircuitState::Closed);
    }

    #[tokio::test]
    async fn transitions_to_half_open_after_timeout() {
        let cb = CircuitBreaker::new("test", fast_cfg());
        for _ in 0..3 {
            cb.record_failure();
        }
        assert_eq!(cb.state(), CircuitState::Open);

        tokio::time::sleep(Duration::from_millis(100)).await;
        // Next call to state() or allow_request() triggers transition check.
        assert_eq!(cb.state(), CircuitState::HalfOpen);
    }

    #[tokio::test]
    async fn closes_after_enough_successes_in_half_open() {
        let cb = CircuitBreaker::new("test", fast_cfg());
        for _ in 0..3 {
            cb.record_failure();
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(cb.state(), CircuitState::HalfOpen);

        cb.record_success();
        assert_eq!(cb.state(), CircuitState::HalfOpen);
        cb.record_success(); // threshold = 2
        assert_eq!(cb.state(), CircuitState::Closed);
    }

    #[tokio::test]
    async fn re_opens_on_failure_in_half_open() {
        let cb = CircuitBreaker::new("test", fast_cfg());
        for _ in 0..3 {
            cb.record_failure();
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(cb.state(), CircuitState::HalfOpen);

        cb.record_failure(); // re-open immediately
        assert_eq!(cb.state(), CircuitState::Open);
    }

    #[tokio::test]
    async fn half_open_limits_probe_count() {
        let cfg = CircuitBreakerConfig {
            failure_threshold: 1,
            success_threshold: 5,
            open_duration: Duration::from_millis(50),
            half_open_max_probes: 2,
        };
        let cb = CircuitBreaker::new("test", cfg);
        cb.record_failure();
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(cb.state(), CircuitState::HalfOpen);

        assert!(cb.allow_request()); // probe 0
        assert!(cb.allow_request()); // probe 1
        assert!(!cb.allow_request()); // probe 2 >= max_probes=2 → rejected
    }

    #[tokio::test]
    async fn probe_slot_released_on_success() {
        let cfg = CircuitBreakerConfig {
            failure_threshold: 1,
            success_threshold: 5,
            open_duration: Duration::from_millis(50),
            half_open_max_probes: 1,
        };
        let cb = CircuitBreaker::new("test", cfg);
        cb.record_failure();
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(cb.state(), CircuitState::HalfOpen);

        // Take the only probe slot.
        assert!(cb.allow_request());
        assert!(!cb.allow_request()); // full

        // Completing the probe frees the slot.
        cb.record_success();
        assert!(cb.allow_request()); // slot available again
    }

    #[tokio::test]
    async fn probe_slot_released_on_failure() {
        let cfg = CircuitBreakerConfig {
            failure_threshold: 1,
            success_threshold: 5,
            open_duration: Duration::from_millis(50),
            half_open_max_probes: 1,
        };
        let cb = CircuitBreaker::new("test", cfg);
        cb.record_failure();
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(cb.state(), CircuitState::HalfOpen);

        // Take the only probe slot.
        assert!(cb.allow_request());
        assert!(!cb.allow_request()); // full

        // Failure re-opens (and releases the slot via transition reset).
        cb.record_failure();
        assert_eq!(cb.state(), CircuitState::Open);
    }

    #[tokio::test]
    async fn rejected_probe_does_not_consume_slot() {
        let cfg = CircuitBreakerConfig {
            failure_threshold: 1,
            success_threshold: 5,
            open_duration: Duration::from_millis(50),
            half_open_max_probes: 1,
        };
        let cb = CircuitBreaker::new("test", cfg);
        cb.record_failure();
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(cb.state(), CircuitState::HalfOpen);

        // Take the only slot.
        assert!(cb.allow_request());

        // The rejected call should NOT consume a slot.
        assert!(!cb.allow_request());

        // Complete the first probe — slot freed.
        cb.record_success();

        // Now we should be able to probe again (if rejected had consumed a slot
        // this would fail).
        assert!(cb.allow_request());
    }
}
