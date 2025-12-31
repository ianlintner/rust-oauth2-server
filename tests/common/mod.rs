use oauth2_core::{AuthorizationCode, Client, Token, User};
use oauth2_ports::Storage;

/// A minimal contract test suite that every `Storage` backend must satisfy.
///
/// This keeps backend parity honest (SQLx, Mongo, and any future backends).
pub async fn run_storage_contract(storage: &dyn Storage) -> Result<(), Box<dyn std::error::Error>> {
    // Client roundtrip
    let client = Client::new(
        "client_1".to_string(),
        "secret".to_string(),
        vec!["http://localhost/cb".to_string()],
        vec!["client_credentials".to_string()],
        "read".to_string(),
        "test client".to_string(),
    );

    storage
        .save_client(&client)
        .await
        .map_err(|e| std::io::Error::other(e.to_string()))?;

    let fetched = storage
        .get_client("client_1")
        .await
        .map_err(|e| std::io::Error::other(e.to_string()))?
        .ok_or_else(|| std::io::Error::other("client should exist"))?;

    assert_eq!(fetched.client_id, client.client_id);

    // Uniqueness parity: saving the same client_id twice should fail.
    let dup = storage.save_client(&client).await;
    assert!(dup.is_err(), "saving the same client_id twice should fail");

    // User roundtrip
    let user = User::new(
        "user_1".to_string(),
        "password_hash".to_string(),
        "user_1@example.com".to_string(),
    );

    storage
        .save_user(&user)
        .await
        .map_err(|e| std::io::Error::other(e.to_string()))?;

    let fetched_user = storage
        .get_user_by_username("user_1")
        .await
        .map_err(|e| std::io::Error::other(e.to_string()))?
        .ok_or_else(|| std::io::Error::other("user should exist"))?;

    assert_eq!(fetched_user.username, user.username);

    // Token roundtrip + revoke
    let token = Token::new(
        "access_token_1".to_string(),
        Some("refresh_token_1".to_string()),
        client.client_id.clone(),
        None,
        "read".to_string(),
        3600,
    );

    storage
        .save_token(&token)
        .await
        .map_err(|e| std::io::Error::other(e.to_string()))?;

    let fetched_token = storage
        .get_token_by_access_token("access_token_1")
        .await
        .map_err(|e| std::io::Error::other(e.to_string()))?
        .ok_or_else(|| std::io::Error::other("token should exist"))?;

    assert!(!fetched_token.revoked);

    storage
        .revoke_token("access_token_1")
        .await
        .map_err(|e| std::io::Error::other(e.to_string()))?;

    let revoked_token = storage
        .get_token_by_access_token("access_token_1")
        .await
        .map_err(|e| std::io::Error::other(e.to_string()))?
        .ok_or_else(|| std::io::Error::other("token should still exist"))?;

    assert!(revoked_token.revoked);

    // Authorization code roundtrip + mark used
    let code = AuthorizationCode::new(
        "code_1".to_string(),
        client.client_id.clone(),
        user.id.clone(),
        "http://localhost/cb".to_string(),
        "read".to_string(),
        None,
        None,
    );

    storage
        .save_authorization_code(&code)
        .await
        .map_err(|e| std::io::Error::other(e.to_string()))?;

    let fetched_code = storage
        .get_authorization_code("code_1")
        .await
        .map_err(|e| std::io::Error::other(e.to_string()))?
        .ok_or_else(|| std::io::Error::other("auth code should exist"))?;

    assert!(!fetched_code.used);

    storage
        .mark_authorization_code_used("code_1")
        .await
        .map_err(|e| std::io::Error::other(e.to_string()))?;

    let used_code = storage
        .get_authorization_code("code_1")
        .await
        .map_err(|e| std::io::Error::other(e.to_string()))?
        .ok_or_else(|| std::io::Error::other("auth code should exist"))?;

    assert!(used_code.used);

    Ok(())
}
