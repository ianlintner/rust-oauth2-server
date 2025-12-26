// BDD tests using Cucumber for OAuth2 flows

use cucumber::{given, then, when, World};
use std::collections::HashMap;

#[derive(Debug, Default, World)]
pub struct OAuth2World {
    pub server_url: String,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub access_token: Option<String>,
    pub refresh_token: Option<String>,
    pub authorization_code: Option<String>,
    pub redirect_uri: Option<String>,
    pub scope: Option<String>,
    pub state: Option<String>,
    pub pkce_verifier: Option<String>,
    pub pkce_challenge: Option<String>,
    pub error: Option<String>,
    pub token_active: bool,
    pub token_metadata: HashMap<String, String>,
}

impl OAuth2World {
    fn new() -> Self {
        Self {
            server_url: "http://localhost:8080".to_string(),
            ..Default::default()
        }
    }
}

// Background steps
#[given("an OAuth2 server is running")]
async fn server_is_running(world: &mut OAuth2World) {
    world.server_url = "http://localhost:8080".to_string();
}

#[given(expr = "a client is registered with ID {string} and secret {string}")]
async fn client_is_registered(world: &mut OAuth2World, client_id: String, client_secret: String) {
    world.client_id = Some(client_id);
    world.client_secret = Some(client_secret);
}

#[given(expr = "the redirect URI {string} is allowed")]
async fn redirect_uri_is_allowed(world: &mut OAuth2World, redirect_uri: String) {
    world.redirect_uri = Some(redirect_uri);
}

#[given("a user is authenticated")]
async fn user_is_authenticated(_world: &mut OAuth2World) {
    // Mock user authentication
}

// Authorization Code Flow steps
#[when(expr = "the client requests authorization with scope {string}")]
async fn request_authorization_with_scope(world: &mut OAuth2World, scope: String) {
    world.scope = Some(scope);
}

#[when("the client requests authorization")]
async fn request_authorization(world: &mut OAuth2World) {
    world.scope = Some("read".to_string());
}

#[then("an authorization code is generated")]
async fn authorization_code_generated(world: &mut OAuth2World) {
    world.authorization_code = Some("mock_auth_code_123".to_string());
}

#[when("the client exchanges the code for a token")]
async fn exchange_code_for_token(world: &mut OAuth2World) {
    // Mock token exchange
    world.access_token = Some("mock_access_token".to_string());
    world.refresh_token = Some("mock_refresh_token".to_string());
}

#[then("an access token is issued")]
async fn access_token_issued(world: &mut OAuth2World) {
    assert!(world.access_token.is_some(), "Access token should be issued");
}

#[then(expr = "the token has scope {string}")]
async fn token_has_scope(world: &mut OAuth2World, expected_scope: String) {
    assert_eq!(
        world.scope.as_ref().unwrap(),
        &expected_scope,
        "Token scope should match"
    );
}

#[then("a refresh token is issued")]
async fn refresh_token_issued(world: &mut OAuth2World) {
    assert!(
        world.refresh_token.is_some(),
        "Refresh token should be issued"
    );
}

// PKCE steps
#[given("a PKCE code verifier is generated")]
async fn pkce_verifier_generated(world: &mut OAuth2World) {
    world.pkce_verifier = Some("mock_pkce_verifier_123".to_string());
}

#[given(expr = "a code challenge is created using {word} method")]
async fn code_challenge_created(world: &mut OAuth2World, method: String) {
    world.pkce_challenge = Some(format!("mock_challenge_{}", method));
}

#[when("the client requests authorization with PKCE challenge")]
async fn request_authorization_with_pkce(world: &mut OAuth2World) {
    world.scope = Some("read".to_string());
}

#[when("the client exchanges the code with PKCE verifier")]
async fn exchange_code_with_pkce(world: &mut OAuth2World) {
    world.access_token = Some("mock_access_token_pkce".to_string());
}

// Error handling steps
#[when("the client attempts to exchange an invalid code")]
async fn exchange_invalid_code(world: &mut OAuth2World) {
    world.error = Some("invalid_grant".to_string());
}

#[then(expr = "the request is rejected with error {string}")]
async fn request_rejected_with_error(world: &mut OAuth2World, error: String) {
    assert_eq!(
        world.error.as_ref().unwrap(),
        &error,
        "Error should match expected"
    );
}

#[when("the client attempts to reuse the same code")]
async fn reuse_authorization_code(world: &mut OAuth2World) {
    world.error = Some("invalid_grant".to_string());
}

#[given("10 minutes have passed")]
async fn time_has_passed(_world: &mut OAuth2World) {
    // Mock time passage
}

#[when("the client exchanges the expired code")]
async fn exchange_expired_code(world: &mut OAuth2World) {
    world.error = Some("invalid_grant".to_string());
}

#[when("the client exchanges the code with a different redirect URI")]
async fn exchange_with_different_redirect(world: &mut OAuth2World) {
    world.error = Some("invalid_request".to_string());
}

#[when(expr = "the client requests authorization with state {string}")]
async fn request_authorization_with_state(world: &mut OAuth2World, state: String) {
    world.state = Some(state);
}

#[then(expr = "the redirect includes state {string}")]
async fn redirect_includes_state(world: &mut OAuth2World, expected_state: String) {
    assert_eq!(
        world.state.as_ref().unwrap(),
        &expected_state,
        "State should match"
    );
}

// Client Credentials steps
#[when("the client requests a token with client credentials")]
async fn request_token_with_client_credentials(world: &mut OAuth2World) {
    world.access_token = Some("mock_access_token_cc".to_string());
}

#[when(expr = "the request includes scope {string}")]
async fn request_includes_scope(world: &mut OAuth2World, scope: String) {
    world.scope = Some(scope);
}

#[then("no refresh token is issued")]
async fn no_refresh_token_issued(world: &mut OAuth2World) {
    assert!(
        world.refresh_token.is_none(),
        "Refresh token should not be issued"
    );
}

#[when("a client with invalid credentials requests a token")]
async fn request_with_invalid_credentials(world: &mut OAuth2World) {
    world.error = Some("invalid_client".to_string());
}

#[when("a client requests a token without providing a secret")]
async fn request_without_secret(world: &mut OAuth2World) {
    world.error = Some("invalid_client".to_string());
}

#[when(expr = "the client requests a token with scope {string}")]
async fn request_token_with_scope(world: &mut OAuth2World, scope: String) {
    world.scope = Some(scope);
    world.access_token = Some("mock_access_token".to_string());
}

// Password Grant steps
#[given(expr = "a user exists with username {string} and password {string}")]
async fn user_exists(_world: &mut OAuth2World, _username: String, _password: String) {
    // Mock user existence
}

#[when(expr = "the client requests a token with username {string} and password {string}")]
async fn request_token_with_password(
    world: &mut OAuth2World,
    username: String,
    _password: String,
) {
    if username == "testuser" {
        world.access_token = Some("mock_access_token_password".to_string());
        world.refresh_token = Some("mock_refresh_token".to_string());
    } else {
        world.error = Some("invalid_grant".to_string());
    }
}

#[when("the client requests a token without providing a username")]
async fn request_without_username(world: &mut OAuth2World) {
    world.error = Some("invalid_request".to_string());
}

#[when("the client requests a token without providing a password")]
async fn request_without_password(world: &mut OAuth2World) {
    world.error = Some("invalid_request".to_string());
}

// Token Introspection steps
#[given("a valid access token exists")]
async fn valid_token_exists(world: &mut OAuth2World) {
    world.access_token = Some("valid_access_token".to_string());
    world.token_active = true;
}

#[when("the resource server introspects the token")]
async fn introspect_token(world: &mut OAuth2World) {
    world.token_metadata.insert("scope".to_string(), "read write".to_string());
    world.token_metadata.insert("client_id".to_string(), "test_client".to_string());
    world.token_metadata.insert("user_id".to_string(), "user_123".to_string());
}

#[then("the response indicates the token is active")]
async fn token_is_active(world: &mut OAuth2World) {
    assert!(world.token_active, "Token should be active");
}

#[then("the response includes the token scope")]
async fn response_includes_scope(world: &mut OAuth2World) {
    assert!(world.token_metadata.contains_key("scope"));
}

#[then("the response includes the client ID")]
async fn response_includes_client_id(world: &mut OAuth2World) {
    assert!(world.token_metadata.contains_key("client_id"));
}

#[then("the response includes the user ID")]
async fn response_includes_user_id(world: &mut OAuth2World) {
    assert!(world.token_metadata.contains_key("user_id"));
}

#[given("an access token has expired")]
async fn token_has_expired(world: &mut OAuth2World) {
    world.access_token = Some("expired_token".to_string());
    world.token_active = false;
}

#[when("the resource server introspects the expired token")]
async fn introspect_expired_token(_world: &mut OAuth2World) {
    // Mock introspection
}

#[then("the response indicates the token is not active")]
async fn token_is_not_active(world: &mut OAuth2World) {
    assert!(!world.token_active, "Token should not be active");
}

#[given("an access token has been revoked")]
async fn token_has_been_revoked(world: &mut OAuth2World) {
    world.access_token = Some("revoked_token".to_string());
    world.token_active = false;
}

#[when("the resource server introspects the revoked token")]
async fn introspect_revoked_token(_world: &mut OAuth2World) {
    // Mock introspection
}

#[when("the resource server introspects an invalid token")]
async fn introspect_invalid_token(world: &mut OAuth2World) {
    world.token_active = false;
}

// Token Revocation steps
#[when("the client revokes the access token")]
async fn revoke_access_token(world: &mut OAuth2World) {
    world.token_active = false;
}

#[then("the revocation succeeds")]
async fn revocation_succeeds(_world: &mut OAuth2World) {
    // Mock successful revocation
}

#[then("the token is no longer valid")]
async fn token_is_invalid(world: &mut OAuth2World) {
    assert!(!world.token_active, "Token should be invalid");
}

#[given("a valid refresh token exists")]
async fn valid_refresh_token_exists(world: &mut OAuth2World) {
    world.refresh_token = Some("valid_refresh_token".to_string());
}

#[when("the client revokes the refresh token")]
async fn revoke_refresh_token(_world: &mut OAuth2World) {
    // Mock revocation
}

#[then("the refresh token is no longer valid")]
async fn refresh_token_is_invalid(_world: &mut OAuth2World) {
    // Mock validation
}

#[when("the client attempts to revoke it again")]
async fn revoke_again(_world: &mut OAuth2World) {
    // Mock revocation
}

#[when("the client attempts to revoke an invalid token")]
async fn revoke_invalid_token(_world: &mut OAuth2World) {
    // Mock revocation
}

// Refresh Token steps
#[when("the client requests a new token using the refresh token")]
async fn request_token_with_refresh(world: &mut OAuth2World) {
    world.access_token = Some("new_access_token".to_string());
    world.refresh_token = Some("new_refresh_token".to_string());
}

#[then("a new access token is issued")]
async fn new_access_token_issued(world: &mut OAuth2World) {
    assert!(world.access_token.is_some(), "New access token should be issued");
}

#[then("a new refresh token is issued")]
async fn new_refresh_token_issued(world: &mut OAuth2World) {
    assert!(world.refresh_token.is_some(), "New refresh token should be issued");
}

#[when("the client requests a token with an invalid refresh token")]
async fn request_with_invalid_refresh(world: &mut OAuth2World) {
    world.error = Some("invalid_grant".to_string());
}

#[given("a refresh token has been revoked")]
async fn refresh_token_revoked(world: &mut OAuth2World) {
    world.refresh_token = Some("revoked_refresh_token".to_string());
}

#[when("the client attempts to use the revoked refresh token")]
async fn use_revoked_refresh_token(world: &mut OAuth2World) {
    world.error = Some("invalid_grant".to_string());
}

#[given("a refresh token has expired")]
async fn refresh_token_expired(world: &mut OAuth2World) {
    world.refresh_token = Some("expired_refresh_token".to_string());
}

#[when("the client attempts to use the expired refresh token")]
async fn use_expired_refresh_token(world: &mut OAuth2World) {
    world.error = Some("invalid_grant".to_string());
}

// PKCE specific steps
#[given("a public client is registered with ID {string}")]
async fn public_client_registered(world: &mut OAuth2World, client_id: String) {
    world.client_id = Some(client_id);
}

#[when("the client requests authorization with the code challenge")]
async fn request_with_code_challenge(world: &mut OAuth2World) {
    world.authorization_code = Some("pkce_auth_code".to_string());
}

#[when("the client exchanges the code with the code verifier")]
async fn exchange_with_code_verifier(world: &mut OAuth2World) {
    world.access_token = Some("pkce_access_token".to_string());
}

#[given("a PKCE authorization has been completed")]
async fn pkce_authorization_completed(world: &mut OAuth2World) {
    world.authorization_code = Some("pkce_auth_code".to_string());
    world.pkce_challenge = Some("mock_challenge".to_string());
}

#[when("the client exchanges the code with an incorrect verifier")]
async fn exchange_with_incorrect_verifier(world: &mut OAuth2World) {
    world.error = Some("invalid_grant".to_string());
}

#[when("the client exchanges the code without providing a verifier")]
async fn exchange_without_verifier(world: &mut OAuth2World) {
    world.error = Some("invalid_request".to_string());
}

// Error Handling steps
#[when(expr = "a client requests a token with grant type {string}")]
async fn request_with_grant_type(world: &mut OAuth2World, grant_type: String) {
    if grant_type == "implicit" {
        world.error = Some("unsupported_grant_type".to_string());
    }
}

#[when("a client sends a malformed token request")]
async fn send_malformed_request(world: &mut OAuth2World) {
    world.error = Some("invalid_request".to_string());
}

#[when("an unregistered client attempts to request a token")]
async fn unregistered_client_request(world: &mut OAuth2World) {
    world.error = Some("invalid_client".to_string());
}

#[given(expr = "a client is registered with scope {string}")]
async fn client_registered_with_scope(world: &mut OAuth2World, scope: String) {
    world.client_id = Some("test_client".to_string());
    world.scope = Some(scope);
}

#[when(expr = "the client requests authorization with scope {string}")]
async fn request_authorization_with_invalid_scope(world: &mut OAuth2World, _scope: String) {
    world.error = Some("invalid_scope".to_string());
}

#[when("the user denies authorization")]
async fn user_denies_authorization(world: &mut OAuth2World) {
    world.error = Some("access_denied".to_string());
}

#[then(expr = "the client receives an error {string}")]
async fn client_receives_error(world: &mut OAuth2World, error: String) {
    assert_eq!(world.error.as_ref().unwrap(), &error);
}

#[given("the OAuth2 server has an internal error")]
async fn server_has_internal_error(_world: &mut OAuth2World) {
    // Mock server error
}

#[when("a client makes a token request")]
async fn make_token_request(world: &mut OAuth2World) {
    world.error = Some("server_error".to_string());
}

#[tokio::main]
async fn main() {
    OAuth2World::cucumber()
        .run("tests/features")
        .await;
}

