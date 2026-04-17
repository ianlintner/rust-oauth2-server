# RFC Compliance Check Skill

**Purpose**: Verify OAuth2 and OIDC implementation complies with relevant RFCs (6749, 7636, 7662, 9068, 9207, etc.)

**When to Use**:
- Before deploying new OAuth2/OIDC features
- After modifying token generation or validation
- During security audits
- When investigating compliance issues
- Before cutting a release

## Parameters

- `rfc_number`: Specific RFC to check (optional, checks all if not specified)
- `feature`: Specific feature to test (e.g., "pkce", "introspection", "jwt_profile")
- `issuer`: Server issuer URL (default: http://localhost:8080)

## Prerequisites

- OAuth2 server running locally
- Test database initialized
- RFC compliance test suite available
- Understanding of OAuth2/OIDC specifications

## Prompt

Check RFC compliance for:
- RFC: {{rfc_number}} (or "all" for comprehensive check)
- Feature: {{feature}}
- Issuer: {{issuer}}

Please perform these verification steps:

1. **Setup Test Environment**:
   - Start OAuth2 server: `cargo run`
   - Verify health: `curl {{issuer}}/health`
   - Check test database is clean: `rm -f /tmp/oauth2_test.db`

2. **Run RFC Compliance Tests**:
   ```bash
   # Run all RFC compliance tests
   cargo test --test rfc_compliance --verbose

   # Run specific RFC test
   cargo test --test rfc_compliance {{feature}}

   # Run with detailed output
   RUST_LOG=debug cargo test --test rfc_compliance -- --nocapture
   ```

3. **RFC-Specific Checks**:

   **RFC 6749 - OAuth 2.0 Framework**:
   - [ ] Authorization endpoint returns code + state
   - [ ] Token endpoint validates grant_type
   - [ ] Client authentication works correctly
   - [ ] Scope handling is proper
   - [ ] Error responses follow spec format

   **RFC 7636 - PKCE**:
   - [ ] code_challenge required for public clients
   - [ ] code_challenge_method supports S256
   - [ ] code_verifier validation works
   - [ ] PKCE prevents authorization code interception

   **RFC 7662 - Token Introspection**:
   - [ ] Introspection endpoint exists at /oauth/introspect
   - [ ] Response includes: active, scope, client_id, username, token_type, exp, iat
   - [ ] **Response includes nbf, jti, aud, iss** (§2.2 compliance)
   - [ ] Revoked tokens return active: false
   - [ ] Client authentication required

   **RFC 9068 - JWT Access Token Profile**:
   - [ ] JOSE header contains **typ: "at+JWT"**
   - [ ] Claims include: iss, sub, aud, exp, iat, jti
   - [ ] Scope claim present and properly formatted
   - [ ] Audience claim contains client_id
   - [ ] Token signature validates

   **RFC 9207 - Authorization Server Issuer Identification**:
   - [ ] Authorization response includes **iss parameter**
   - [ ] iss parameter matches server issuer exactly
   - [ ] Clients can validate iss before token exchange

   **RFC 7009 - Token Revocation**:
   - [ ] Revocation endpoint exists at /oauth/revoke
   - [ ] Accepts token and token_type_hint
   - [ ] Returns 200 for successful revocation
   - [ ] Revoked tokens fail introspection

   **RFC 8414 - Authorization Server Metadata**:
   - [ ] Discovery endpoint at /.well-known/oauth-authorization-server
   - [ ] Returns required metadata fields
   - [ ] Endpoint URLs are absolute

   **OIDC Core**:
   - [ ] Discovery at /.well-known/openid-configuration
   - [ ] JWKS endpoint at /.well-known/jwks.json
   - [ ] UserInfo endpoint at /.well-known/userinfo
   - [ ] ID tokens properly formatted
   - [ ] prompt parameter handling (none, login)
   - [ ] max_age parameter enforcement

4. **Manual Verification Steps**:

   **Check JWT Token Format**:
   ```bash
   # Get a token
   TOKEN=$(curl -X POST {{issuer}}/oauth/token \
     -d "grant_type=client_credentials&client_id=test&client_secret=secret" \
     | jq -r .access_token)

   # Decode header
   echo $TOKEN | cut -d'.' -f1 | base64 -d | jq

   # Should see: {"typ":"at+JWT","alg":"RS256",...}
   ```

   **Check Introspection Response**:
   ```bash
   curl -X POST {{issuer}}/oauth/introspect \
     -u "client_id:secret" \
     -d "token=$TOKEN" | jq

   # Verify includes: nbf, jti, aud, iss
   ```

   **Check Authorization Response**:
   ```bash
   # Visit authorization URL and check redirect
   # Redirect should include: code, state, iss parameters
   ```

5. **Review Test Results**:
   - Check all tests pass: `test result: ok`
   - Review any failures with detailed output
   - Cross-reference failures with RFC sections
   - Check CLAUDE.md for known issues or invariants

6. **Document Findings**:
   - List any RFC violations discovered
   - Note which phase/chunk would fix them (see docs/oauth2-spec-audit.md)
   - Create GitHub issue if new violations found
   - Update CLAUDE.md if invariants changed

## Success Criteria

- [ ] All RFC compliance tests pass
- [ ] JWT tokens include typ: "at+JWT" header
- [ ] Authorization responses include iss parameter
- [ ] Introspection responses include nbf, jti, aud, iss
- [ ] PKCE validation works for public clients
- [ ] Discovery endpoints return proper metadata
- [ ] Token signatures validate correctly
- [ ] Revoked tokens show as inactive
- [ ] No RFC violations in token generation
- [ ] No RFC violations in endpoint responses

## Common Issues & Fixes

### Issue: Tests fail with "missing app_data"
**Fix**: Check that all handlers have required app_data injected
- See CLAUDE.md §app_data Required by Each Handler
- Update tests/rfc_compliance.rs with new app_data types

### Issue: JWT missing typ: "at+JWT"
**Fix**: Update Claims::encode() to set header.typ
- Location: crates/oauth2-core/src/models/token.rs:125
- This was fixed in Phase 1.A

### Issue: Authorization response missing iss
**Fix**: Add iss parameter to redirect in authorize handler
- Location: crates/oauth2-actix/src/handlers/oauth.rs
- This was fixed in Phase 1.A

### Issue: Introspection missing nbf, jti, aud, iss
**Fix**: Update IntrospectionResponse struct
- Location: crates/oauth2-core/src/models/token.rs
- Add fields to struct and serialization
- This was fixed in Phase 1.A

### Issue: Public client requires client_secret
**Fix**: Check Client::is_public() implementation
- Location: crates/oauth2-core/src/models/client.rs
- Returns true when token_endpoint_auth_method == "none"
- Migration V12 added this column
- This was fixed in Phase 1.B

## Related Resources

- [OAuth2 Spec Audit](../docs/oauth2-spec-audit.md) - Authoritative roadmap
- [CLAUDE.md](../CLAUDE.md) - RFC compliance section
- [RFC Compliance Tests](../tests/rfc_compliance.rs)
- [Security Tests](../tests/security_http.rs)
- [RFC 6749](https://tools.ietf.org/html/rfc6749)
- [RFC 7636 (PKCE)](https://tools.ietf.org/html/rfc7636)
- [RFC 7662 (Introspection)](https://tools.ietf.org/html/rfc7662)
- [RFC 9068 (JWT Profile)](https://tools.ietf.org/html/rfc9068)
- [RFC 9207 (Issuer ID)](https://tools.ietf.org/html/rfc9207)

## Example Usage

### Check All RFCs

```
Use the rfc-compliance-check skill to verify all OAuth2/OIDC RFCs
with issuer http://localhost:8080
```

### Check Specific Feature

```
Use the rfc-compliance-check skill with:
- feature: pkce
- issuer: http://localhost:8080
```

### Check Specific RFC

```
Use the rfc-compliance-check skill with:
- rfc_number: 9068
- feature: jwt_profile
- issuer: https://auth.example.com
```

## Phase 1 Compliance Status

All Phase 1 items are **DONE** per CLAUDE.md:

| Chunk | Status |
|-------|--------|
| 1.A: typ: "at+JWT", iss parameter, RFC 7662 fields | ✅ Done |
| 1.B: Public clients, token_endpoint_auth_method=none | ✅ Done |
| 1.C: Issuer threading, UserInfo claims | ✅ Done |
| 1.D: prompt=none/login, max_age | ✅ Done |
| 1.E: id_token_hint validation, cascade revocation | ✅ Done |
| 1.F: Discovery doc cleanup | ✅ Done |

## CI Integration

RFC compliance tests run automatically in CI:

```yaml
# .github/workflows/ci.yml
- name: Run tests
  run: cargo test --verbose --all-features --locked
```

This includes tests/rfc_compliance.rs along with all other tests.

## Notes

- See docs/oauth2-spec-audit.md for complete RFC tracking
- Phase 1 (all chunks) completed on branch claude/oauth2-spec-audit-UheZ5
- Future phases will address additional RFCs and optional features
- RFC compliance is a moving target - specs evolve
- Always cite specific RFC sections when reporting violations
