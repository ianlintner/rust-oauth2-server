# OAuth2 Test Flow Skill

**Purpose**: Test the complete OAuth2 authorization code + PKCE flow end-to-end to verify correct implementation.

**When to Use**:
- After implementing or modifying OAuth2 flows
- When debugging authorization issues
- Before deploying changes to production
- During RFC compliance validation

## Parameters

- `client_type`: Type of client to test (confidential, public)
- `scope`: OAuth2 scopes to request (e.g., "read write", "openid profile")
- `issuer`: Issuer URL for the OAuth2 server (default: "http://localhost:8080")

## Prerequisites

- OAuth2 server running locally or accessible
- Test client registered with appropriate redirect URIs
- Database initialized with migrations

## Prompt

Test the OAuth2 authorization code + PKCE flow with the following configuration:
- Client type: {{client_type}}
- Requested scope: {{scope}}
- Issuer: {{issuer}}

Please perform these steps:

1. **Setup Phase**:
   - Start the OAuth2 server if not already running: `cargo run`
   - Verify server health: `curl {{issuer}}/health`
   - Register a test client if needed via `/admin/clients/register`

2. **Authorization Phase**:
   - Generate PKCE code verifier and challenge (S256)
   - Construct authorization URL with required parameters:
     - `response_type=code`
     - `client_id=<test_client_id>`
     - `redirect_uri=<registered_redirect>`
     - `scope={{scope}}`
     - `state=<random_state>`
     - `code_challenge=<pkce_challenge>`
     - `code_challenge_method=S256`
   - Visit the authorization URL in a browser or test client
   - Complete authentication if required
   - Verify redirect includes `code` and `state` parameters
   - Verify redirect includes `iss` parameter (RFC 9207)

3. **Token Exchange Phase**:
   - Exchange authorization code for tokens using POST to `/oauth/token`:
     - `grant_type=authorization_code`
     - `code=<auth_code>`
     - `redirect_uri=<same_redirect>`
     - `code_verifier=<pkce_verifier>`
     - `client_id=<client_id>`
     - For confidential clients: include `client_secret`
   - Verify response contains:
     - `access_token`
     - `token_type=Bearer`
     - `expires_in`
     - `scope`
     - `id_token` (if openid scope requested)

4. **Token Validation Phase**:
   - Decode the JWT access token
   - Verify JOSE header contains `typ: "at+JWT"` (RFC 9068)
   - Verify claims contain:
     - `iss`: {{issuer}}
     - `sub`: User identifier
     - `aud`: Client ID
     - `exp`: Expiration timestamp
     - `iat`: Issued at timestamp
     - `nbf`: Not before timestamp
     - `jti`: JWT ID
     - `scope`: Requested scope
   - Verify token signature using server's public key

5. **Introspection Phase**:
   - Call introspection endpoint POST `/oauth/introspect`:
     - `token=<access_token>`
     - Include client authentication
   - Verify response includes:
     - `active: true`
     - `client_id`
     - `username`
     - `scope`
     - `exp`, `iat`, `nbf`, `iss`, `aud`, `jti` (RFC 7662 §2.2)

6. **Resource Access Phase**:
   - Call UserInfo endpoint GET `/.well-known/userinfo` with:
     - `Authorization: Bearer <access_token>`
   - Verify response contains user claims

7. **Cleanup Phase**:
   - Revoke the token POST `/oauth/revoke`:
     - `token=<access_token>`
     - Include client authentication
   - Verify introspection now returns `active: false`

## Success Criteria

- [ ] Server health check returns 200
- [ ] Authorization redirect includes code, state, and iss parameters
- [ ] Token exchange returns valid access_token
- [ ] JWT header contains `typ: "at+JWT"`
- [ ] JWT claims contain all required fields (iss, sub, aud, exp, iat, nbf, jti, scope)
- [ ] Token signature validates successfully
- [ ] Introspection returns active token with all required fields
- [ ] UserInfo endpoint returns user claims
- [ ] Token revocation succeeds
- [ ] Introspection after revocation shows inactive token

## Common Issues

1. **PKCE validation failure**: Ensure code_verifier matches code_challenge (S256 hash)
2. **Missing iss parameter**: Check RFC 9207 implementation in authorize handler
3. **Invalid JWT typ**: Verify Claims::encode() sets typ: "at+JWT"
4. **Introspection missing fields**: Check IntrospectionResponse includes nbf, jti, aud, iss
5. **Public client secret required**: Verify Client::is_public() checks token_endpoint_auth_method

## Related Resources

- [OAuth 2.0 Flow Documentation](../docs/usage/oauth2-oidc.md)
- [RFC 6749 - OAuth 2.0](https://tools.ietf.org/html/rfc6749)
- [RFC 7636 - PKCE](https://tools.ietf.org/html/rfc7636)
- [RFC 9068 - JWT Access Tokens](https://tools.ietf.org/html/rfc9068)
- [RFC 9207 - Issuer Identification](https://tools.ietf.org/html/rfc9207)
- [Test Examples](../tests/rfc_compliance.rs)
- [Development Agent](../.github/agents/development.md)

## Example Usage

### Testing Confidential Client

```
Use the oauth2-test-flow skill with:
- client_type: confidential
- scope: openid profile email
- issuer: http://localhost:8080
```

### Testing Public Client

```
Use the oauth2-test-flow skill with:
- client_type: public
- scope: read write
- issuer: https://auth.example.com
```

## Validation Script

For automated validation, run:

```bash
cargo test --test rfc_compliance -- oauth2_authorization_code_with_pkce
```

## Notes

- This skill follows the test patterns in `tests/rfc_compliance.rs`
- Always verify RFC 9068 and RFC 9207 compliance
- Public clients must use PKCE and skip client_secret
- All tokens must include proper issuer identification
