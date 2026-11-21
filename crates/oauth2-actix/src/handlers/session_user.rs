//! Re-check a session's user against storage.
//!
//! The session is a signed cookie, so it cannot be revoked server-side and
//! keeps carrying `user_id` / `role` for its whole lifetime. Anything that
//! acts on a session's behalf must therefore confirm the user record still
//! exists and is enabled, and take the role from that record.

use oauth2_core::{OAuth2Error, User};
use oauth2_ports::DynStorage;

/// The user for `user_id` when the record exists and is enabled.
///
/// `Ok(None)` means the session no longer identifies a usable user.
pub(crate) async fn load_active_user(
    storage: &DynStorage,
    user_id: &str,
) -> Result<Option<User>, OAuth2Error> {
    Ok(storage
        .get_user_by_id(user_id)
        .await?
        .filter(|user| user.enabled))
}

/// Fail with `access_denied` unless `user_id` names an enabled user.
pub(crate) async fn require_active_user(
    storage: &DynStorage,
    user_id: &str,
) -> Result<User, OAuth2Error> {
    load_active_user(storage, user_id)
        .await?
        .ok_or_else(|| OAuth2Error::access_denied("Authentication required"))
}
