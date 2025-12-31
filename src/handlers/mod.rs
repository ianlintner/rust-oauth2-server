// Compatibility facade.
//
// Most HTTP handlers were extracted to `oauth2-actix`.
// We keep `auth` local for now because it depends on server-specific social-login config.

pub mod admin {
	pub use oauth2_actix::handlers::admin::*;
}

pub mod client {
	pub use oauth2_actix::handlers::client::*;
}

pub mod events {
	pub use oauth2_actix::handlers::events::*;
}

pub mod oauth {
	pub use oauth2_actix::handlers::oauth::*;
}

pub mod token {
	pub use oauth2_actix::handlers::token::*;
}

pub mod wellknown {
	pub use oauth2_actix::handlers::wellknown::*;
}

pub mod auth;
