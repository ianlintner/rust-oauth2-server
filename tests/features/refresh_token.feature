Feature: Refresh Token Flow
  As an OAuth2 client
  I want to obtain new access tokens using refresh tokens
  So that I can maintain access without requiring user interaction

  Background:
    Given an OAuth2 server is running
    And a client is registered with ID "test_client" and secret "test_secret"

  Scenario: Refresh access token successfully
    Given a valid refresh token exists
    When the client requests a new token using the refresh token
    Then a new access token is issued
    And a new refresh token is issued

  Scenario: Refresh with invalid refresh token
    When the client requests a token with an invalid refresh token
    Then the request is rejected with error "invalid_grant"

  Scenario: Refresh with revoked refresh token
    Given a refresh token has been revoked
    When the client attempts to use the revoked refresh token
    Then the request is rejected with error "invalid_grant"

  Scenario: Refresh token used after expiration
    Given a refresh token has expired
    When the client attempts to use the expired refresh token
    Then the request is rejected with error "invalid_grant"
