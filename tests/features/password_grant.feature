Feature: Resource Owner Password Credentials Flow
  As an OAuth2 client
  I want to obtain access tokens using user credentials
  So that I can access protected resources on behalf of a user

  Background:
    Given an OAuth2 server is running
    And a client is registered with ID "test_client" and secret "test_secret"
    And a user exists with username "testuser" and password "testpass"

  Scenario: Successful password grant
    When the client requests a token with username "testuser" and password "testpass"
    Then an access token is issued
    And a refresh token is issued

  Scenario: Invalid username or password
    When the client requests a token with username "testuser" and password "wrongpass"
    Then the request is rejected with error "invalid_grant"

  Scenario: Missing username
    When the client requests a token without providing a username
    Then the request is rejected with error "invalid_request"

  Scenario: Missing password
    When the client requests a token without providing a password
    Then the request is rejected with error "invalid_request"

  Scenario: Password grant with scope
    When the client requests a token with username "testuser" and password "testpass"
    And the request includes scope "read write"
    Then an access token is issued
    And the token has scope "read write"
