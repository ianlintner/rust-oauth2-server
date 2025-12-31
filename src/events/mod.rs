// Compatibility facade.
//
// The eventing subsystem was extracted into the `oauth2-events` crate so downstream
// consumers can depend on it without pulling in the entire server.
//
// Keep the public API stable: `rust_oauth2_server::events::*` continues to work.
pub use oauth2_events::*;
