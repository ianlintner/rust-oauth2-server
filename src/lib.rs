//! Library exports.
//!
//! Historically, this project kept most modules only in the binary crate (`main.rs`).
//! Exporting modules here allows:
//! - Reuse from additional binaries (e.g. OpenAPI exporters)
//! - Cleaner integration tests
//! - Single source of truth for types used by utoipa/OpenAPI generation

/// Reusable, framework-agnostic domain types.
pub use oauth2_core as core;

/// Integration ports (traits) for plugging in custom adapters (e.g., storage/DAO).
pub use oauth2_ports as ports;

pub mod actors;
pub mod config;
pub mod db;
pub mod events;
pub mod handlers;
pub mod metrics;
pub mod middleware;
pub mod models;
pub mod openapi;
pub mod services;
pub mod storage;
pub mod telemetry;
