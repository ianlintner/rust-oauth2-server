Feature: Authorization Code Flow
  As an OAuth2 client
  I want to obtain access tokens using authorization code flow
  So that I can access protected resources on behalf of a user

  Background:
    Given an OAuth2 server is running
    And a client is registered with ID "test_client" and secret "test_secret"
    And the redirect URI "http://localhost:3000/callback" is allowed

  Scenario: Successful authorization code flow
    Given a user is authenticated
    When the client requests authorization with scope "read write"
    Then an authorization code is generated
    When the client exchanges the code for a token
    Then an access token is issued
    And the token has scope "read write"
    And a refresh token is issued

  Scenario: Authorization with PKCE
    Given a user is authenticated
    And a PKCE code verifier is generated
    When the client requests authorization with PKCE challenge
    Then an authorization code is generated
    When the client exchanges the code with PKCE verifier
    Then an access token is issued

  Scenario: Invalid authorization code
    When the client attempts to exchange an invalid code
    Then the request is rejected with error "invalid_grant"

  Scenario: Authorization code used twice
    Given a user is authenticated
    When the client requests authorization
    And an authorization code is generated
    And the client exchanges the code for a token
    When the client attempts to reuse the same code
    Then the request is rejected with error "invalid_grant"

  Scenario: Expired authorization code
    Given a user is authenticated
    When the client requests authorization
    And an authorization code is generated
    And 10 minutes have passed
    When the client exchanges the expired code
    Then the request is rejected with error "invalid_grant"

  Scenario: Mismatched redirect URI
    Given a user is authenticated
    When the client requests authorization
    And an authorization code is generated
    When the client exchanges the code with a different redirect URI
    Then the request is rejected with error "invalid_request"

  Scenario: Authorization with state parameter
    Given a user is authenticated
    When the client requests authorization with state "xyz123"
    Then the redirect includes state "xyz123"
