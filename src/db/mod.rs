//! Backwards-compatibility module.
//!
//! The codebase now uses `crate::storage` for modular backend persistence.
//! This module remains as a thin shim so existing code (and older docs/tests)
//! that reference `crate::db::Database` continue to compile.

#[allow(dead_code)]
pub type Database = crate::storage::sqlx::SqlxStorage;
