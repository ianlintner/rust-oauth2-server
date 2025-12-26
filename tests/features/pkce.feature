Feature: PKCE (Proof Key for Code Exchange)
  As a public OAuth2 client
  I want to use PKCE for authorization code flow
  So that I can securely obtain access tokens without client secrets

  Background:
    Given an OAuth2 server is running
    And a public client is registered with ID "public_client"

  Scenario: PKCE with S256 challenge method
    Given a PKCE code verifier is generated
    And a code challenge is created using S256 method
    When the client requests authorization with the code challenge
    Then an authorization code is generated
    When the client exchanges the code with the code verifier
    Then an access token is issued

  Scenario: PKCE with plain challenge method
    Given a PKCE code verifier is generated
    And a code challenge is created using plain method
    When the client requests authorization with the code challenge
    Then an authorization code is generated
    When the client exchanges the code with the code verifier
    Then an access token is issued

  Scenario: PKCE with invalid verifier
    Given a PKCE authorization has been completed
    When the client exchanges the code with an incorrect verifier
    Then the request is rejected with error "invalid_grant"

  Scenario: PKCE without code verifier
    Given a PKCE authorization has been completed
    When the client exchanges the code without providing a verifier
    Then the request is rejected with error "invalid_request"
