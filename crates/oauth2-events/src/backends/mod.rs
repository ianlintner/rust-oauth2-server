//! Optional eventing backends.
//!
//! These are behind Cargo features so the default build stays lightweight:
//! - `events-redis`
//! - `events-kafka`
//! - `events-rabbit`

#[cfg(feature = "events-redis")]
pub mod redis_streams;

#[cfg(feature = "events-kafka")]
pub mod kafka;

#[cfg(feature = "events-rabbit")]
pub mod rabbit;

#[cfg(feature = "events-redis")]
pub use redis_streams::*;

#[cfg(feature = "events-kafka")]
pub use kafka::*;

#[cfg(feature = "events-rabbit")]
pub use rabbit::*;
