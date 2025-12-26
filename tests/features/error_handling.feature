Feature: OAuth2 Error Handling
  As an OAuth2 client
  I want to receive appropriate error responses
  So that I can handle different error conditions correctly

  Background:
    Given an OAuth2 server is running

  Scenario: Unsupported grant type
    When a client requests a token with grant type "implicit"
    Then the request is rejected with error "unsupported_grant_type"

  Scenario: Invalid request format
    When a client sends a malformed token request
    Then the request is rejected with error "invalid_request"

  Scenario: Unauthorized client
    When an unregistered client attempts to request a token
    Then the request is rejected with error "invalid_client"

  Scenario: Invalid scope
    Given a client is registered with scope "read"
    When the client requests authorization with scope "admin"
    Then the request is rejected with error "invalid_scope"

  Scenario: Access denied by user
    Given a user is authenticated
    When the user denies authorization
    Then the client receives an error "access_denied"

  Scenario: Server error
    Given the OAuth2 server has an internal error
    When a client makes a token request
    Then the request is rejected with error "server_error"
