//! Actix-web HTTP surface for the OAuth2 server.
//!
//! This crate intentionally contains framework-specific code (Actix handlers and actors).
//! Domain types live in `oauth2-core`, while storage is abstracted behind `oauth2-ports`.

pub mod actors;
pub mod handlers;
