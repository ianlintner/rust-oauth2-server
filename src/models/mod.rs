// Compatibility facade.
//
// Domain types live in the extracted `oauth2-core` crate so downstream users can depend
// on them without pulling in the whole server.
pub use oauth2_core::*;

// App-specific types (depend on server config/env) stay in this crate.
pub mod social;
pub use social::*;
