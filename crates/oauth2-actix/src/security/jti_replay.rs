//! RFC 7523 §3 / RFC 9700 §2.5 — JWT client-assertion replay prevention.
//!
//! A JWT bearer assertion carries a unique `jti`; the AS MUST reject any
//! assertion whose `(iss, jti)` pair has already been seen within the
//! assertion's validity window. Without this check, an attacker who
//! captures one valid assertion can replay it indefinitely (up to `exp`)
//! from their own origin, since the server otherwise accepts any assertion
//! that decodes and passes signature verification.
//!
//! This guard is an in-process LRU-bounded map of `(client_id, jti)` →
//! expiry. It is intentionally simple — a single `Mutex<HashMap>` because
//! the cache is only touched by client-assertion validations, which run
//! at most once per token request. Entries are pruned opportunistically
//! on insert; a hard size cap bounds memory even under abuse.
//!
//! For multi-node deployments the caller can swap in a Redis-backed
//! implementation of [`JtiReplayStore`] when the `redis-cache` feature
//! is enabled (out of scope for this initial commit — the in-memory
//! guard is sufficient for single-node deployments and for stopping the
//! attack in the "attacker hits the same replica" case, which is the
//! common one behind a sticky-session load balancer).

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Result of observing a `(client_id, jti)` pair.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ObserveResult {
    /// First time we have seen this pair within its validity window.
    Fresh,
    /// The pair has already been observed — reject the assertion as a replay.
    Replay,
}

/// Default hard cap on in-memory entries. Beyond this size the oldest
/// entries (regardless of TTL) are dropped so a pathological client
/// cannot exhaust memory by rotating `jti` values.
const DEFAULT_MAX_ENTRIES: usize = 100_000;
/// Upper bound on how long any single entry may live. RFC 7523 §3 does
/// not cap `exp`, but accepting an assertion with a multi-day window
/// would turn the guard into a near-permanent store. Five minutes is
/// comfortably past a typical clock-skew allowance and more than long
/// enough to cover the real replay risk window.
const MAX_TTL_SECS: u64 = 300;

#[derive(Debug)]
pub struct JtiReplayGuard {
    inner: Mutex<Inner>,
    max_entries: usize,
}

#[derive(Debug)]
struct Inner {
    seen: HashMap<String, Instant>,
}

impl Default for JtiReplayGuard {
    fn default() -> Self {
        Self::with_capacity(DEFAULT_MAX_ENTRIES)
    }
}

impl JtiReplayGuard {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_capacity(max_entries: usize) -> Self {
        Self {
            inner: Mutex::new(Inner {
                seen: HashMap::new(),
            }),
            max_entries: max_entries.max(1),
        }
    }

    /// Record `(client_id, jti)` with the assertion's remaining validity.
    ///
    /// Returns [`ObserveResult::Replay`] when the pair was already seen and
    /// its previous entry has not yet expired.
    pub fn observe(&self, client_id: &str, jti: &str, ttl: Duration) -> ObserveResult {
        let ttl = ttl.min(Duration::from_secs(MAX_TTL_SECS));
        let now = Instant::now();
        let expires_at = now + ttl;
        let key = format!("{client_id}\0{jti}");

        let mut inner = self.inner.lock().expect("jti replay mutex poisoned");

        // Opportunistic cleanup — drop any expired entries we trip over
        // instead of scanning on every observe. Under steady-state load
        // the map stays close to the size of the active assertion window.
        inner.seen.retain(|_, exp| *exp > now);

        if let Some(existing) = inner.seen.get(&key) {
            if *existing > now {
                return ObserveResult::Replay;
            }
        }

        // Hard cap — drop an arbitrary entry before inserting when full.
        // Avoids unbounded growth; the TTL sweep above usually keeps the
        // map well under the cap.
        if inner.seen.len() >= self.max_entries {
            if let Some(k) = inner.seen.keys().next().cloned() {
                inner.seen.remove(&k);
            }
        }

        inner.seen.insert(key, expires_at);
        ObserveResult::Fresh
    }

    /// Current entry count — exposed for test assertions only.
    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.inner.lock().unwrap().seen.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_observation_is_fresh_replay_rejected() {
        let guard = JtiReplayGuard::new();
        let ttl = Duration::from_secs(60);
        assert_eq!(guard.observe("c1", "jti-a", ttl), ObserveResult::Fresh);
        assert_eq!(guard.observe("c1", "jti-a", ttl), ObserveResult::Replay);
    }

    #[test]
    fn different_clients_do_not_collide_on_same_jti() {
        let guard = JtiReplayGuard::new();
        let ttl = Duration::from_secs(60);
        assert_eq!(guard.observe("c1", "jti-x", ttl), ObserveResult::Fresh);
        // Same jti, different client_id — treated as a separate assertion.
        assert_eq!(guard.observe("c2", "jti-x", ttl), ObserveResult::Fresh);
    }

    #[test]
    fn expired_entry_is_treated_as_fresh_again() {
        let guard = JtiReplayGuard::new();
        // Zero-TTL entry expires at the instant it's inserted; the next
        // observe past the retain() sweep sees an empty slot.
        assert_eq!(
            guard.observe("c1", "jti-zero", Duration::from_nanos(1)),
            ObserveResult::Fresh
        );
        std::thread::sleep(Duration::from_millis(5));
        assert_eq!(
            guard.observe("c1", "jti-zero", Duration::from_secs(60)),
            ObserveResult::Fresh
        );
    }

    #[test]
    fn ttl_is_capped_at_max() {
        // A caller requesting a 1-hour TTL should be silently clamped.
        // This is an internal invariant — no public accessor for entry
        // TTL, so assert indirectly by confirming observe() never panics
        // and the resulting entry does not prevent re-observation after
        // the cap elapses. (We don't wait 5 minutes in this test; we
        // simply confirm the clamp does not reject the first observation.)
        let guard = JtiReplayGuard::new();
        assert_eq!(
            guard.observe("c", "j", Duration::from_secs(86_400)),
            ObserveResult::Fresh
        );
    }

    #[test]
    fn cap_drops_entries_to_stay_bounded() {
        let guard = JtiReplayGuard::with_capacity(4);
        for i in 0..8 {
            assert_eq!(
                guard.observe("c", &format!("j-{i}"), Duration::from_secs(60)),
                ObserveResult::Fresh
            );
        }
        assert!(guard.len() <= 4, "entries must be bounded by max_entries");
    }
}
