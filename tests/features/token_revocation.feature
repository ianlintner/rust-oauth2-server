Feature: Token Revocation
  As an OAuth2 client or resource owner
  I want to revoke access tokens
  So that I can invalidate access when needed

  Background:
    Given an OAuth2 server is running
    And a valid access token exists

  Scenario: Revoke active access token
    When the client revokes the access token
    Then the revocation succeeds
    And the token is no longer valid

  Scenario: Revoke refresh token
    Given a valid refresh token exists
    When the client revokes the refresh token
    Then the revocation succeeds
    And the refresh token is no longer valid

  Scenario: Revoke already revoked token
    Given an access token has been revoked
    When the client attempts to revoke it again
    Then the revocation succeeds

  Scenario: Revoke invalid token
    When the client attempts to revoke an invalid token
    Then the revocation succeeds
