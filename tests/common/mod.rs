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
        None,
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

    // Parity check: multiple tokens with no refresh token should be allowed.
    // (SQL UNIQUE allows multiple NULLs; Mongo requires omitting the field to match that behavior.)
    let no_refresh_1 = Token::new(
        "access_token_no_refresh_1".to_string(),
        None,
        client.client_id.clone(),
        None,
        "read".to_string(),
        3600,
        None,
    );

    storage
        .save_token(&no_refresh_1)
        .await
        .map_err(|e| std::io::Error::other(e.to_string()))?;

    let no_refresh_2 = Token::new(
        "access_token_no_refresh_2".to_string(),
        None,
        client.client_id.clone(),
        None,
        "read".to_string(),
        3600,
        None,
    );

    storage
        .save_token(&no_refresh_2)
        .await
        .map_err(|e| std::io::Error::other(e.to_string()))?;

    // Uniqueness parity: saving the same access_token twice should fail.
    let dup_access = storage.save_token(&no_refresh_2).await;
    assert!(
        dup_access.is_err(),
        "saving the same access_token twice should fail"
    );

    // Admin revocation uses the storage ID, never an access/refresh token value.
    for id in [
        "missing-token-id",
        &token.access_token,
        &no_refresh_1.access_token,
    ] {
        let count = storage
            .revoke_token_by_id(id)
            .await
            .map_err(|e| std::io::Error::other(e.to_string()))?;
        assert_eq!(count, 0);
    }
    let count = storage
        .revoke_token_by_id(&no_refresh_1.id)
        .await
        .map_err(|e| std::io::Error::other(e.to_string()))?;
    assert_eq!(count, 1);
    let count = storage
        .revoke_token_by_id(&no_refresh_1.id)
        .await
        .map_err(|e| std::io::Error::other(e.to_string()))?;
    assert_eq!(count, 0, "already-revoked tokens are not counted again");

    for (token, revoked) in [(&no_refresh_1, true), (&no_refresh_2, false)] {
        let fetched = storage
            .get_token_by_access_token(&token.access_token)
            .await
            .map_err(|e| std::io::Error::other(e.to_string()))?
            .ok_or_else(|| std::io::Error::other("token should still exist"))?;
        assert_eq!(fetched.revoked, revoked);
    }

    // Authorization code roundtrip + mark used
    let code = AuthorizationCode::new(
        "code_1".to_string(),
        client.client_id.clone(),
        user.id.clone(),
        "http://localhost/cb".to_string(),
        "read".to_string(),
        None,
        None,
        None, // nonce
        None, // resource
        None, // authorization_details
        None, // claims_request
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

    // RFC 9449 §10: dpop_jkt binding persists (None by default, Some when set).
    assert_eq!(fetched_code.dpop_jkt, None);
    let mut bound_code = AuthorizationCode::new(
        "code_dpop".to_string(),
        client.client_id.clone(),
        user.id.clone(),
        "http://localhost/cb".to_string(),
        "read".to_string(),
        None,
        None,
        None,
        None,
        None,
        None,
    );
    bound_code.dpop_jkt = Some("0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I".to_string());
    storage
        .save_authorization_code(&bound_code)
        .await
        .map_err(|e| std::io::Error::other(e.to_string()))?;
    let fetched_bound = storage
        .get_authorization_code("code_dpop")
        .await
        .map_err(|e| std::io::Error::other(e.to_string()))?
        .ok_or_else(|| std::io::Error::other("dpop-bound auth code should exist"))?;
    assert_eq!(
        fetched_bound.dpop_jkt.as_deref(),
        Some("0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I")
    );

    Ok(())
}
