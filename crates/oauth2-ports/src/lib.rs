//! Integration ports for the OAuth2 server.
//!
//! Implement these traits in your own crate to plug in custom persistence or other
//! infrastructure without forking.

pub mod storage;

pub use storage::*;
