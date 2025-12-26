Feature: Token Introspection
  As an OAuth2 resource server
  I want to validate access tokens
  So that I can determine if they are active and get token metadata

  Background:
    Given an OAuth2 server is running
    And a valid access token exists

  Scenario: Introspect active token
    When the resource server introspects the token
    Then the response indicates the token is active
    And the response includes the token scope
    And the response includes the client ID
    And the response includes the user ID

  Scenario: Introspect expired token
    Given an access token has expired
    When the resource server introspects the expired token
    Then the response indicates the token is not active

  Scenario: Introspect revoked token
    Given an access token has been revoked
    When the resource server introspects the revoked token
    Then the response indicates the token is not active

  Scenario: Introspect invalid token
    When the resource server introspects an invalid token
    Then the response indicates the token is not active
