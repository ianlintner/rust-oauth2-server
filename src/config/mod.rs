// Compatibility facade.
//
// The configuration loader/types were extracted into the `oauth2-config` crate so:
// - downstream users can reuse config parsing without pulling in the whole server
// - the root crate can stay as a thin re-export/compatibility layer
pub use oauth2_config::*;
