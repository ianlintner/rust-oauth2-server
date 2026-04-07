//! Back-pressure via a bounded concurrency semaphore.
//!
//! When all permits are taken the request is rejected immediately (503) rather
//! than queued — this is intentional: queuing under load hides latency and
//! can lead to memory exhaustion.

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// An RAII guard that holds a semaphore permit.
///
/// When dropped the permit is automatically returned to the pool.
pub struct ConcurrencyPermit(#[allow(dead_code)] OwnedSemaphorePermit);

/// Bounded concurrency limiter.
///
/// Clone cheaply — all clones share the same underlying semaphore.
#[derive(Clone)]
pub struct ConcurrencyLimiter {
    inner: Arc<ConcurrencyLimiterInner>,
}

struct ConcurrencyLimiterInner {
    semaphore: Arc<Semaphore>,
    max_concurrent: u32,
    rejected_total: AtomicU32,
}

impl ConcurrencyLimiter {
    /// Create a new limiter allowing at most `max_concurrent` simultaneous
    /// requests.
    pub fn new(max_concurrent: u32) -> Self {
        let max = max_concurrent.max(1);
        Self {
            inner: Arc::new(ConcurrencyLimiterInner {
                semaphore: Arc::new(Semaphore::new(max as usize)),
                max_concurrent: max,
                rejected_total: AtomicU32::new(0),
            }),
        }
    }

    /// Maximum simultaneous requests this limiter allows.
    pub fn max_concurrent(&self) -> u32 {
        self.inner.max_concurrent
    }

    /// Current number of available (free) permits.
    pub fn available_permits(&self) -> u32 {
        self.inner.semaphore.available_permits() as u32
    }

    /// Current number of in-flight requests.
    pub fn in_flight(&self) -> u32 {
        self.inner
            .max_concurrent
            .saturating_sub(self.available_permits())
    }

    /// Total requests rejected (all-time, since creation).
    pub fn rejected_total(&self) -> u32 {
        self.inner.rejected_total.load(Ordering::Relaxed)
    }

    /// Try to acquire a permit without blocking.
    ///
    /// Returns `Some(permit)` on success or `None` when at capacity.
    /// The permit is released when it is dropped.
    pub fn try_acquire(&self) -> Option<ConcurrencyPermit> {
        match self.inner.semaphore.clone().try_acquire_owned() {
            Ok(permit) => Some(ConcurrencyPermit(permit)),
            Err(_) => {
                self.inner.rejected_total.fetch_add(1, Ordering::Relaxed);
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_up_to_max_concurrent() {
        let lim = ConcurrencyLimiter::new(3);
        let _p1 = lim.try_acquire().expect("permit 1");
        let _p2 = lim.try_acquire().expect("permit 2");
        let _p3 = lim.try_acquire().expect("permit 3");
        assert!(
            lim.try_acquire().is_none(),
            "should be rejected at capacity"
        );
    }

    #[test]
    fn permit_released_on_drop() {
        let lim = ConcurrencyLimiter::new(1);
        {
            let _p = lim.try_acquire().expect("permit");
            assert!(lim.try_acquire().is_none());
        }
        // After the permit is dropped the slot is free again.
        assert!(lim.try_acquire().is_some());
    }

    #[test]
    fn rejected_total_increments() {
        let lim = ConcurrencyLimiter::new(1);
        let _p = lim.try_acquire().expect("permit");
        lim.try_acquire(); // rejected
        lim.try_acquire(); // rejected
        assert_eq!(lim.rejected_total(), 2);
    }

    #[test]
    fn in_flight_is_correct() {
        let lim = ConcurrencyLimiter::new(4);
        let _p1 = lim.try_acquire().unwrap();
        let _p2 = lim.try_acquire().unwrap();
        assert_eq!(lim.in_flight(), 2);
        assert_eq!(lim.available_permits(), 2);
    }

    #[test]
    fn cloned_shares_semaphore() {
        let lim = ConcurrencyLimiter::new(2);
        let clone = lim.clone();
        let _p = lim.try_acquire().unwrap();
        // Clone sees the same semaphore.
        let _p2 = clone.try_acquire().unwrap();
        assert!(lim.try_acquire().is_none());
    }
}
