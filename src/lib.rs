//! Root crate library stub.
//!
//! This repository has been split into a Cargo workspace of reusable crates under `crates/`.
//! The root package is intentionally kept minimal.
//!
//! Use these crates directly instead of `rust_oauth2_server::*`:
//! - `oauth2-server` (server assembly)
//! - `oauth2-actix` (HTTP handlers/actors/middleware)
//! - `oauth2-core` (domain types)
//! - `oauth2-ports` (traits like `Storage`)
//! - `oauth2-storage-sqlx`, `oauth2-storage-mongo` (adapters)
//! - `oauth2-storage-factory` (backend selection)
//! - `oauth2-openapi` (OpenAPI generation)

pub use oauth2_server;
