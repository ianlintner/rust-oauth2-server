// Compatibility facade.
//
// Social login service was extracted to `oauth2-social-login`.
pub use oauth2_social_login::SocialLoginService;

// Compatibility module path.
//
// Historically these lived under `rust_oauth2_server::services::social_login::*`.
pub mod social_login;
