//! Server resilience patterns for the OAuth2 server.
//!
//! Provides three complementary patterns:
//!
//! * **[`circuit_breaker`]** — stop forwarding requests to a dependency that
//!   is failing and automatically recover once it stabilises.
//! * **[`back_pressure`]** — bounded concurrency semaphore: reject requests
//!   immediately when the server is at capacity instead of queueing them.
//! * **[`bulkhead`]** — per-route-group concurrency isolation so a traffic
//!   surge in one area cannot exhaust capacity in another.

pub mod back_pressure;
pub mod bulkhead;
pub mod circuit_breaker;

pub use back_pressure::{ConcurrencyLimiter, ConcurrencyPermit};
pub use bulkhead::{BulkheadConfig, BulkheadRegistry, BulkheadSnapshot};
pub use circuit_breaker::{CircuitBreaker, CircuitBreakerConfig, CircuitState};
