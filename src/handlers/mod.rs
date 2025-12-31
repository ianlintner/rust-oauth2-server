// Compatibility facade.
//
// Most HTTP handlers were extracted to `oauth2-actix`.
// Social-login handlers live in `oauth2-social-login`.

pub mod admin;
pub mod client;
pub mod events;
pub mod oauth;
pub mod token;
pub mod wellknown;

/// Social login handlers.
pub mod auth;
