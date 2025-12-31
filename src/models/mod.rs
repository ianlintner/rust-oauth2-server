// Compatibility facade.
//
// Domain types live in the extracted `oauth2-core` crate so downstream users can depend
// on them without pulling in the whole server.
pub use oauth2_core::*;

// App-specific types.
//
// Social-login types were extracted to `oauth2-social-login` and `oauth2-config`.
pub use oauth2_config::ProviderConfig;
pub use oauth2_social_login::{SocialLoginConfig, SocialUserInfo};

// Compatibility module path.
//
// Historically these lived under `rust_oauth2_server::models::social::*`.
pub mod social;
