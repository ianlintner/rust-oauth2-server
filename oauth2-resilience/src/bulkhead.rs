//! Bulkhead pattern — named, independent concurrency pools.
//!
//! A bulkhead isolates different parts of the system so that a surge in one
//! area (e.g. the `/oauth/token` endpoint) cannot starve another (e.g.
//! `/admin`).

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use crate::back_pressure::{ConcurrencyLimiter, ConcurrencyPermit};

/// Configuration for a single bulkhead partition.
#[derive(Debug, Clone)]
pub struct BulkheadConfig {
    /// Human-readable name (also used as the key in metrics labels).
    pub name: String,
    /// URL path prefix this bulkhead covers (e.g. `"/oauth"`).
    pub path_prefix: String,
    /// Maximum simultaneous requests allowed through this bulkhead.
    pub max_concurrent: u32,
}

/// Registry of named bulkheads, each with its own concurrency limit.
///
/// Clone cheaply — all clones share the same underlying state.
#[derive(Clone)]
pub struct BulkheadRegistry {
    inner: Arc<RwLock<BulkheadRegistryInner>>,
}

struct BulkheadRegistryInner {
    /// Ordered list so the first matching prefix wins.
    bulkheads: Vec<(String, ConcurrencyLimiter)>,
    /// Prefix → name map for metrics labels.
    prefix_to_name: HashMap<String, String>,
}

impl BulkheadRegistry {
    /// Build a registry from a list of configurations.
    ///
    /// Entries are checked in order; the first matching `path_prefix` wins.
    pub fn from_configs(configs: Vec<BulkheadConfig>) -> Self {
        let mut bulkheads = Vec::with_capacity(configs.len());
        let mut prefix_to_name = HashMap::new();

        for cfg in configs {
            prefix_to_name.insert(cfg.path_prefix.clone(), cfg.name.clone());
            bulkheads.push((cfg.path_prefix, ConcurrencyLimiter::new(cfg.max_concurrent)));
        }

        Self {
            inner: Arc::new(RwLock::new(BulkheadRegistryInner {
                bulkheads,
                prefix_to_name,
            })),
        }
    }

    /// Try to acquire a permit for the given request path.
    ///
    /// Returns `(name, Some(permit))` when allowed, or
    /// `(name, None)` when the bulkhead is at capacity.
    /// Returns `("none", None)` when no bulkhead matches the path.
    pub fn try_acquire(&self, path: &str) -> (&'static str, Option<ConcurrencyPermit>) {
        // Collect matching prefix and limiter while holding the read lock,
        // then drop the lock before acquiring the permit (which may allocate).
        let found: Option<(String, ConcurrencyLimiter)> = {
            let inner = self.inner.read().unwrap_or_else(|e| e.into_inner());
            inner
                .bulkheads
                .iter()
                .find(|(prefix, _)| path.starts_with(prefix.as_str()))
                .map(|(prefix, limiter)| (prefix.clone(), limiter.clone()))
        };

        match found {
            Some((prefix, limiter)) => {
                let permit = limiter.try_acquire();
                let name = self.interned_name(&prefix);
                (name, permit)
            }
            None => ("none", None),
        }
    }

    /// Returns all bulkhead snapshots (name, in_flight, max, rejected_total).
    pub fn snapshots(&self) -> Vec<BulkheadSnapshot> {
        let inner = self.inner.read().unwrap_or_else(|e| e.into_inner());
        inner
            .bulkheads
            .iter()
            .map(|(prefix, limiter)| {
                let name = inner
                    .prefix_to_name
                    .get(prefix)
                    .cloned()
                    .unwrap_or_else(|| prefix.clone());
                BulkheadSnapshot {
                    name,
                    in_flight: limiter.in_flight(),
                    max_concurrent: limiter.max_concurrent(),
                    rejected_total: limiter.rejected_total(),
                }
            })
            .collect()
    }

    /// Intern a bulkhead name to produce a `&'static str`.
    ///
    /// Once a name is interned it lives for the lifetime of the process.
    fn interned_name(&self, prefix: &str) -> &'static str {
        // We build a small append-only table of leaked strings.
        // The table is keyed by prefix.  Because the registry itself is
        // long-lived (typically the whole process lifetime) this is safe.
        //
        // Acquire RwLock first, then the INTERNED mutex — never the other
        // way around — to avoid a deadlock with `try_acquire` which also
        // holds the RwLock.
        use std::collections::HashMap;
        use std::sync::OnceLock;
        static INTERNED: OnceLock<std::sync::Mutex<HashMap<String, &'static str>>> =
            OnceLock::new();

        // 1. Look up the human-readable name while holding the RwLock.
        let name: String = {
            let inner = self.inner.read().unwrap_or_else(|e| e.into_inner());
            inner
                .prefix_to_name
                .get(prefix)
                .cloned()
                .unwrap_or_else(|| prefix.to_string())
            // RwLock guard dropped here.
        };

        // 2. Intern the name — now no other lock is held.
        let map = INTERNED.get_or_init(|| std::sync::Mutex::new(HashMap::new()));
        let mut guard = map.lock().unwrap_or_else(|e| e.into_inner());
        guard
            .entry(name.clone())
            .or_insert_with(|| Box::leak(name.into_boxed_str()))
    }
}

/// Point-in-time snapshot of a single bulkhead's state.
#[derive(Debug, Clone)]
pub struct BulkheadSnapshot {
    pub name: String,
    pub in_flight: u32,
    pub max_concurrent: u32,
    pub rejected_total: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_registry() -> BulkheadRegistry {
        BulkheadRegistry::from_configs(vec![
            BulkheadConfig {
                name: "oauth".to_string(),
                path_prefix: "/oauth".to_string(),
                max_concurrent: 2,
            },
            BulkheadConfig {
                name: "admin".to_string(),
                path_prefix: "/admin".to_string(),
                max_concurrent: 1,
            },
        ])
    }

    #[test]
    fn acquires_for_matching_prefix() {
        let reg = make_registry();
        let (name, permit) = reg.try_acquire("/oauth/token");
        assert_eq!(name, "oauth");
        assert!(permit.is_some());
    }

    #[test]
    fn rejects_when_bulkhead_full() {
        let reg = make_registry();
        let (_n, p1) = reg.try_acquire("/oauth/token");
        let (_n, p2) = reg.try_acquire("/oauth/authorize");
        assert!(p1.is_some());
        assert!(p2.is_some());
        // Third request should be rejected.
        let (_n, p3) = reg.try_acquire("/oauth/token");
        assert!(p3.is_none());
    }

    #[test]
    fn separate_bulkheads_are_independent() {
        let reg = make_registry();
        // Fill oauth bulkhead.
        let (_n, _p1) = reg.try_acquire("/oauth/token");
        let (_n, _p2) = reg.try_acquire("/oauth/token");
        // Admin bulkhead is unaffected.
        let (_n, p_admin) = reg.try_acquire("/admin/api");
        assert!(p_admin.is_some());
    }

    #[test]
    fn unmatched_path_returns_none_name() {
        let reg = make_registry();
        let (name, permit) = reg.try_acquire("/health");
        assert_eq!(name, "none");
        // No bulkhead matches → permit is None (no pool to acquire from).
        assert!(permit.is_none());
    }

    #[test]
    fn permit_released_frees_slot() {
        let reg = make_registry();
        {
            let (_n, _p1) = reg.try_acquire("/admin/x");
            // At capacity (max=1).
            let (_n, p2) = reg.try_acquire("/admin/x");
            assert!(p2.is_none());
        }
        // Permit dropped → slot freed.
        let (_n, p3) = reg.try_acquire("/admin/x");
        assert!(p3.is_some());
    }

    #[test]
    fn snapshots_contain_all_bulkheads() {
        let reg = make_registry();
        let snaps = reg.snapshots();
        assert_eq!(snaps.len(), 2);
        let names: Vec<_> = snaps.iter().map(|s| s.name.as_str()).collect();
        assert!(names.contains(&"oauth"));
        assert!(names.contains(&"admin"));
    }
}
