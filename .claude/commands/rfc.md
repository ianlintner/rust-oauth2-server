Check RFC compliance for OAuth2 and OIDC implementations.

## What to Check

**All RFCs** (comprehensive):
```bash
cargo test --test rfc_compliance --verbose
```

**Specific RFC**:
- RFC 6749: OAuth 2.0 Core
- RFC 7636: PKCE
- RFC 7662: Token Introspection
- RFC 9068: JWT Access Token Profile
- RFC 9207: Authorization Server Issuer Identification
- RFC 8414: Authorization Server Metadata
- OIDC Core: OpenID Connect

**Specific Feature**:
- `pkce`: PKCE implementation
- `jwt_profile`: JWT access token format
- `introspection`: Token introspection
- `issuer_identification`: Issuer parameter in responses

Use the rfc-compliance-check skill for detailed validation.

Which RFC or feature would you like to check?
