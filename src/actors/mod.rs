// Compatibility facade.
//
// The Actix actor implementations were extracted to `oauth2-actix` so downstream
// users can compose their own server binaries without depending on this crate.

pub use oauth2_actix::actors::*;

pub mod auth_actor {
	pub use oauth2_actix::actors::auth_actor::*;
}

pub mod client_actor {
	pub use oauth2_actix::actors::client_actor::*;
}

pub mod token_actor {
	pub use oauth2_actix::actors::token_actor::*;
}
