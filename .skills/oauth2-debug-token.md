# OAuth2 Debug Token Skill

**Purpose**: Debug JWT token validation issues, claim mismatches, and signature problems.

**When to Use**:
- Token validation fails in production
- Claims don't match expected values
- Signature verification errors
- Token expired or not yet valid issues
- Missing required claims (RFC compliance)

## Parameters

- `token`: The JWT access token to debug
- `expected_issuer`: Expected issuer URL
- `expected_audience`: Expected audience (client_id)
- `check_rfc_compliance`: Whether to validate RFC 9068/7662 compliance (default: true)

## Prerequisites

- OAuth2 server running and accessible
- JWT token to debug (access_token or id_token)
- Knowledge of expected token claims
- Access to server's JWKS endpoint

## Prompt

Debug the following JWT token and identify any issues:
- Token: {{token}}
- Expected issuer: {{expected_issuer}}
- Expected audience: {{expected_audience}}
- Check RFC compliance: {{check_rfc_compliance}}

Please perform these comprehensive debugging steps:

1. **Token Structure Analysis**:
   - Verify token is properly formatted (3 base64url parts: header.payload.signature)
   - Decode the token without verification to inspect contents
   - Use: `echo "{{token}}" | cut -d'.' -f1-2 | base64 -d`
   - Or use online JWT debugger: jwt.io (caution: never paste production tokens there)

2. **JOSE Header Inspection**:
   - Decode header (first part of JWT)
   - Verify required fields:
     - `alg`: Algorithm (should be RS256, HS256, etc., NOT none)
     - `typ`: **Must be "at+JWT" for access tokens** (RFC 9068)
     - `kid`: Key ID (for finding correct public key)
   - Common issues:
     - Missing `typ: "at+JWT"` → Check Claims::encode() implementation
     - Missing `kid` → Check key rotation setup
     - `alg: "none"` → Security vulnerability!

3. **Claims Payload Inspection**:
   - Decode payload (second part of JWT)
   - Verify standard claims:
     - `iss`: Issuer URL (should match {{expected_issuer}})
     - `sub`: Subject (user identifier)
     - `aud`: Audience (should match {{expected_audience}})
     - `exp`: Expiration (Unix timestamp, must be future)
     - `iat`: Issued at (Unix timestamp, should be past)
     - `nbf`: Not before (Unix timestamp, should be past or now)
     - `jti`: JWT ID (unique identifier for token)
     - `scope`: OAuth2 scopes (space-separated string)
   - Check timestamps:
     ```bash
     # Convert Unix timestamp to human-readable
     date -d @<timestamp>

     # Compare with current time
     date +%s  # Current Unix timestamp
     ```

4. **RFC Compliance Check** (if check_rfc_compliance=true):
   - **RFC 9068 - JWT Access Token Profile**:
     - JOSE header has `typ: "at+JWT"`
     - Payload has `iss`, `sub`, `aud`, `exp`, `iat`
     - `aud` contains client_id
     - `scope` claim present with OAuth2 scopes
   - **RFC 7662 - Token Introspection**:
     - Introspection response includes `nbf`, `jti`, `aud`, `iss`
   - **RFC 9207 - Authorization Server Issuer Identification**:
     - `iss` claim matches server's issuer URL exactly

5. **Signature Verification**:
   - Fetch server's JWKS (JSON Web Key Set):
     ```bash
     curl {{expected_issuer}}/.well-known/jwks.json
     ```
   - Find key matching `kid` from token header
   - Verify signature using public key:
     - For HS256: Use shared JWT secret
     - For RS256: Use public key from JWKS
   - Use jsonwebtoken crate or similar:
     ```rust
     use jsonwebtoken::{decode, Validation, DecodingKey};

     let validation = Validation::new(Algorithm::RS256);
     let result = decode::<Claims>(token, &decoding_key, &validation);
     ```

6. **Time Validation**:
   - Check current time vs token timestamps:
     ```
     Current time: <now>
     Token iat (issued): <iat> → <human_readable>
     Token nbf (not before): <nbf> → <human_readable>
     Token exp (expires): <exp> → <human_readable>

     Token age: <now - iat> seconds
     Time until expiry: <exp - now> seconds
     ```
   - Verify token is not expired: `now < exp`
   - Verify token is valid now: `now >= nbf`
   - Check for clock skew issues (add 60s tolerance)

7. **Introspection Cross-Check**:
   - Call introspection endpoint to verify server's view:
     ```bash
     curl -X POST {{expected_issuer}}/oauth/introspect \
       -H "Content-Type: application/x-www-form-urlencoded" \
       -u "client_id:client_secret" \
       -d "token={{token}}"
     ```
   - Compare introspection response with decoded claims
   - Check `active` field (should be true for valid tokens)

8. **Database Cross-Check**:
   - Query tokens table for this token:
     ```sql
     SELECT token_type, scope, expires_at, revoked
     FROM tokens
     WHERE access_token = '{{token}}';
     ```
   - Verify token exists and not revoked
   - Check expiration matches JWT `exp` claim

## Success Criteria

- [ ] Token structure is valid (3 parts, base64url encoded)
- [ ] JOSE header contains `typ: "at+JWT"`
- [ ] All required claims present (iss, sub, aud, exp, iat, nbf, jti, scope)
- [ ] Issuer matches expected value
- [ ] Audience matches expected value
- [ ] Token not expired (exp > now)
- [ ] Token valid now (nbf <= now)
- [ ] Signature verifies successfully
- [ ] Introspection returns active: true
- [ ] Database shows token as active and not revoked

## Common Issues & Solutions

### 1. Token Expired
**Symptom**: `exp` claim is in the past
**Solution**:
- Request new token
- Check token TTL configuration
- Implement token refresh flow

### 2. Missing `typ: "at+JWT"` Header
**Symptom**: JOSE header missing `typ` or has wrong value
**Solution**:
- Check Claims::encode() in `crates/oauth2-core/src/models/token.rs:125`
- Verify jsonwebtoken crate usage sets header.typ
- This was fixed in Phase 1.A - ensure code is up to date

### 3. Wrong Issuer
**Symptom**: `iss` claim doesn't match server URL
**Solution**:
- Check OAUTH2_ISSUER environment variable
- Verify TokenActor::new() receives correct issuer
- Check all 5 call sites (4 tests + lib.rs)
- Issuer threading fixed in Phase 1.C

### 4. Missing nbf, jti in Introspection
**Symptom**: Introspection response missing RFC 7662 required fields
**Solution**:
- Check IntrospectionResponse struct in `crates/oauth2-core/src/models/token.rs`
- Verify serialization includes nbf, jti, aud, iss
- This was fixed in Phase 1.A

### 5. Signature Verification Failed
**Symptom**: Signature doesn't verify with server's public key
**Solution**:
- Check JWKS endpoint returns correct keys
- Verify `kid` in header matches key in JWKS
- Ensure JWT_SECRET is correct for HS256
- Check for key rotation issues

### 6. Clock Skew Issues
**Symptom**: Token fails validation due to time mismatch
**Solution**:
- Add 60-120 second leeway to validation
- Check server time synchronization (NTP)
- Verify all servers use UTC

## Related Resources

- [JWT Debugging Guide](../docs/troubleshooting/jwt-issues.md)
- [RFC 9068 - JWT Access Token Profile](https://tools.ietf.org/html/rfc9068)
- [RFC 7662 - Token Introspection](https://tools.ietf.org/html/rfc7662)
- [RFC 7519 - JWT](https://tools.ietf.org/html/rfc7519)
- [Claims Implementation](../crates/oauth2-core/src/models/token.rs)
- [Token Actor](../crates/oauth2-actix/src/actors/token_actor.rs)
- [Security Agent](../.github/agents/security.md)

## Example Usage

### Debug Expired Token

```
Use the oauth2-debug-token skill with:
- token: eyJhbGciOiJSUzI1NiIsInR5cCI6ImF0K0pXVCJ9...
- expected_issuer: http://localhost:8080
- expected_audience: my-client-id
- check_rfc_compliance: true
```

### Debug Signature Issue

```
Debug this token that's failing signature verification:
- Token: eyJhbGciOiJSUzI1NiIsInR5cCI6ImF0K0pXVCJ9...
- Expected issuer: https://auth.example.com
- Expected audience: web-app-client
```

## Automated Testing

Run token validation tests:

```bash
# RFC compliance tests (includes token validation)
cargo test --test rfc_compliance

# Security tests (includes token verification)
cargo test --test security_http

# Specific token tests
cargo test token_validation
```

## Notes

- Never log full tokens in production (security risk)
- Use token introspection rather than decoding in production code
- JWT.io is useful for development but never paste production tokens
- Token debugging is covered in CLAUDE.md §JWT Token Details
- All token issues should reference RFC sections for compliance
