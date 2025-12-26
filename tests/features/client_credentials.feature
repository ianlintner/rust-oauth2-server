Feature: Client Credentials Flow
  As an OAuth2 client
  I want to obtain access tokens using client credentials
  So that I can access protected resources on behalf of the client

  Background:
    Given an OAuth2 server is running
    And a client is registered with ID "test_client" and secret "test_secret"

  Scenario: Successful client credentials flow
    When the client requests a token with client credentials
    And the request includes scope "read"
    Then an access token is issued
    And the token has scope "read"
    And no refresh token is issued

  Scenario: Invalid client credentials
    When a client with invalid credentials requests a token
    Then the request is rejected with error "invalid_client"

  Scenario: Missing client secret
    When a client requests a token without providing a secret
    Then the request is rejected with error "invalid_client"

  Scenario: Client credentials with multiple scopes
    When the client requests a token with scope "read write admin"
    Then an access token is issued
    And the token has scope "read write admin"
