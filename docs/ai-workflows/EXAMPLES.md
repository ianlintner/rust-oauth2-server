# AI-Assisted Development Examples

This document provides practical examples of using AI tooling with rust-oauth2-server.

## Prerequisites

- Claude Code CLI or Claude Desktop with MCP configured
- Local development environment set up
- OAuth2 server accessible at http://localhost:8080

## Example 1: Testing OAuth2 Flow

### Scenario
You've implemented a new feature and want to verify the OAuth2 authorization code + PKCE flow works correctly.

### Using Skills

**Prompt:**
```
Use the oauth2-test-flow skill to test with:
- client_type: public
- scope: openid profile email
- issuer: http://localhost:8080
```

**What the AI Does:**
1. Starts the OAuth2 server (if needed)
2. Registers a test client
3. Generates PKCE challenge and verifier
4. Constructs authorization URL
5. Simulates authorization flow
6. Exchanges code for token
7. Validates JWT structure and claims
8. Checks RFC 9068 and RFC 9207 compliance
9. Introspects the token
10. Tests UserInfo endpoint
11. Revokes the token
12. Reports results

**Expected Output:**
```
✓ Server health check passed
✓ Authorization redirect includes code, state, and iss
✓ Token exchange successful
✓ JWT header contains typ: "at+JWT"
✓ All required claims present
✓ Token signature valid
✓ Introspection shows active token with all RFC 7662 fields
✓ UserInfo returns user claims
✓ Token revocation successful

All tests passed! OAuth2 flow is compliant with RFCs 6749, 7636, 9068, and 9207.
```

## Example 2: Debugging Token Validation Failure

### Scenario
A client reports tokens are failing validation with "invalid signature" errors.

### Using Skills

**Prompt:**
```
Use the oauth2-debug-token skill to debug this token:
eyJhbGciOiJSUzI1NiIsInR5cCI6ImF0K0pXVCIsImtpZCI6ImtleTEifQ...

Expected issuer: https://auth.example.com
Expected audience: web-client-123
```

**What the AI Does:**
1. Decodes token structure (header.payload.signature)
2. Inspects JOSE header for typ, alg, kid
3. Decodes payload claims
4. Checks all required claims (iss, sub, aud, exp, iat, nbf, jti, scope)
5. Validates timestamps (expiry, not-before)
6. Fetches JWKS from server
7. Verifies signature with public key
8. Calls introspection endpoint
9. Cross-checks with database
10. Reports findings

**Expected Output:**
```
Token Analysis:
✓ Structure: Valid (3 parts)
✓ JOSE Header: typ: "at+JWT", alg: "RS256", kid: "key1"
✓ Claims: All required fields present
✓ Issuer: https://auth.example.com ✓
✓ Audience: web-client-123 ✓
✗ Expiration: Token expired (exp: 2026-04-16 15:00:00, now: 2026-04-17 15:00:00)
✓ Not Before: Valid
✓ Signature: Verification successful

Issue Found: Token is expired
Solution: Request a new token or implement token refresh flow
```

## Example 3: Adding a New OAuth2 Endpoint

### Scenario
You need to implement the device authorization endpoint (RFC 8628).

### Using Skills

**Prompt:**
```
Use the add-endpoint skill to create:
- endpoint_path: /oauth/device_authorization
- http_method: POST
- handler_name: device_authorization
- purpose: RFC 8628 device authorization grant initiation
- authentication_required: false
```

**What the AI Does:**
1. Reviews existing OAuth2 handlers for patterns
2. Creates handler function in `crates/oauth2-actix/src/handlers/device.rs`
3. Defines DeviceAuthorizationRequest and Response types
4. Registers route in `crates/oauth2-server/src/lib.rs`
5. Adds required app_data dependencies
6. Creates unit tests in handler module
7. Creates integration tests following RFC testing pattern
8. Updates OpenAPI specification
9. Writes documentation
10. Runs CI gate checks

**Expected Output:**
```
Created Files:
- crates/oauth2-actix/src/handlers/device.rs (new)
- tests/device_flow.rs (updated)
- docs/usage/device-flow.md (new)

Modified Files:
- crates/oauth2-server/src/lib.rs (route registration)
- crates/oauth2-openapi/src/spec.rs (API spec)

CI Gate:
✓ cargo fmt --all -- --check
✓ cargo clippy --all-targets --all-features -- -D warnings
✓ cargo test --verbose --all-features --locked

All checks passed! Device authorization endpoint is ready.
```

## Example 4: Creating a Database Migration

### Scenario
You need to add a `refresh_token_rotation` boolean column to the clients table.

### Using Skills

**Prompt:**
```
Use the db-migration skill to:
- migration_description: add_refresh_token_rotation_to_clients
- migration_type: add_column
- target_table: clients
- backwards_compatible: true
```

**What the AI Does:**
1. Determines next migration version (V13)
2. Creates `migrations/sql/V13__add_refresh_token_rotation_to_clients.sql`
3. Writes SQL with DEFAULT value for backwards compatibility
4. Updates `crates/oauth2-storage-sqlx/src/sqlx.rs`:
   - Adds field to Client struct
   - Updates save_client() query
   - Updates load_client() query
5. Updates `crates/oauth2-core/src/models/client.rs` if needed
6. Tests migration locally
7. Runs full test suite
8. Updates documentation

**Expected Output:**
```
Created: migrations/sql/V13__add_refresh_token_rotation_to_clients.sql

Migration SQL:
ALTER TABLE clients
ADD COLUMN refresh_token_rotation BOOLEAN DEFAULT false NOT NULL;

Modified Files:
- crates/oauth2-storage-sqlx/src/sqlx.rs
- crates/oauth2-core/src/models/client.rs

Migration Applied Successfully:
✓ SQLite: Column added
✓ PostgreSQL: Column added
✓ All tests pass
✓ Backwards compatible

Ready to commit!
```

## Example 5: Deploying to Kubernetes

### Scenario
You need to deploy a new version to staging for testing.

### Using Skills

**Prompt:**
```
Use the deploy-k8s skill to:
- environment: staging
- action: update
- image_tag: v0.0.11
```

**What the AI Does:**
1. Verifies kubectl access to staging cluster
2. Checks current deployment status
3. Verifies image exists in registry
4. Updates kustomization.yaml with new image tag
5. Builds Kustomize manifests
6. Applies changes to cluster
7. Watches rollout progress
8. Runs post-deployment health checks
9. Tests OAuth2 endpoints
10. Monitors logs for errors

**Expected Output:**
```
Pre-deployment:
✓ kubectl connected to staging cluster
✓ Current version: v0.0.10, replicas: 2, all healthy
✓ Image verified: ianlintner068/oauth2-server:v0.0.11

Deployment:
✓ Kustomization updated
✓ Manifests applied
✓ Rollout started...
  - oauth2-server-7d4f8b5c-xk9mp: Running
  - oauth2-server-7d4f8b5c-pm2ln: Running
✓ Rollout complete (45s)

Post-deployment:
✓ Health: {"status":"healthy","version":"0.0.11"}
✓ Readiness: {"ready":true}
✓ Token endpoint: Responding
✓ Discovery: Responding

Deployment successful! Staging now running v0.0.11.
```

## Example 6: Checking RFC Compliance

### Scenario
Before releasing, verify all OAuth2/OIDC RFCs are still compliant.

### Using Slash Commands

**Prompt:**
```
/rfc
```

**Follow-up Prompt:**
```
Run all RFC compliance tests
```

**What the AI Does:**
1. Executes `cargo test --test rfc_compliance --verbose`
2. Parses test results
3. Groups by RFC (6749, 7636, 7662, 9068, 9207, etc.)
4. Reports pass/fail for each
5. Shows detailed output for any failures
6. References relevant RFC sections

**Expected Output:**
```
RFC Compliance Test Results:

RFC 6749 (OAuth 2.0 Core):
✓ Authorization endpoint (3 tests)
✓ Token endpoint (5 tests)
✓ Error responses (2 tests)

RFC 7636 (PKCE):
✓ Code challenge validation (2 tests)
✓ Public client enforcement (1 test)

RFC 7662 (Token Introspection):
✓ Active token response (1 test)
✓ Required fields present (nbf, jti, aud, iss) (1 test)

RFC 9068 (JWT Access Token Profile):
✓ JOSE header typ: "at+JWT" (1 test)
✓ Required claims (1 test)

RFC 9207 (Issuer Identification):
✓ Authorization response iss parameter (1 test)

Total: 18 tests, 18 passed, 0 failed

All RFCs compliant! ✓
```

## Example 7: Running Security Checks

### Scenario
Before merging a PR, run comprehensive security checks.

### Using Slash Commands

**Prompt:**
```
/security
```

**Follow-up Prompt:**
```
Run all security checks including dependency audit, security tests, and clippy
```

**What the AI Does:**
1. Runs `cargo audit` for vulnerable dependencies
2. Runs `cargo test --test security_http` for security tests
3. Runs `cargo clippy` with security lints
4. Checks for hardcoded secrets
5. Reviews recent code changes for security issues
6. Reports findings with severity

**Expected Output:**
```
Security Check Results:

Dependency Audit (cargo audit):
✓ No known vulnerabilities in dependencies
  Audited 247 crates

Security Tests (tests/security_http.rs):
✓ Client authentication (3 tests)
✓ PKCE validation (2 tests)
✓ Token validation (4 tests)
✓ Input sanitization (2 tests)
✓ Rate limiting (1 test)

Clippy Security Lints:
✓ No security warnings

Secret Scanning:
✓ No hardcoded secrets found

Summary: All security checks passed ✓
```

## Example 8: Using MCP Server

### Scenario
You want to register an OAuth2 client and get a token via AI assistant.

### Using MCP Tools

**In Claude Desktop (with MCP configured):**

**Prompt 1:**
```
Register a new OAuth2 client called "Test App" with redirect URI http://localhost:3000/callback
```

**Claude's Action:**
- Calls `register_client` MCP tool
- Stores client_id and client_secret

**Prompt 2:**
```
Get an access token for the Test App client with scope "read write"
```

**Claude's Action:**
- Calls `get_token` MCP tool with stored credentials
- Returns access token

**Prompt 3:**
```
Introspect this token to verify it's active
```

**Claude's Action:**
- Calls `introspect_token` MCP tool
- Shows token metadata

## Best Practices

### 1. Use Skills for Complex Workflows
- Multi-step operations
- Need validation at each step
- RFC compliance checking

### 2. Use Slash Commands for Quick Operations
- Running tests
- Checking status
- Quick validations

### 3. Use MCP Server for OAuth2 Operations
- Token operations
- Client management
- Server queries

### 4. Combine Tools
```
Example: "Use oauth2-test-flow skill, then run /rfc to verify compliance"
```

### 5. Reference Agent Instructions
```
Example: "Following the Development Agent guidelines, add a new endpoint..."
```

## Troubleshooting

### Skill Not Found
- Verify `.skills/` directory exists
- Check skill filename matches exactly
- Review `.skills/README.md` for available skills

### Slash Command Not Working
- Verify `.claude/commands/` directory exists
- Check command filename matches (e.g., `test.md` for `/test`)
- Ensure Claude Code is using the project directory

### MCP Server Connection Failed
- Verify server is running: `cd mcp-server && npm start`
- Check OAUTH2_BASE_URL in `.env`
- Verify Claude Desktop MCP configuration
- Check OAuth2 server is accessible

### CI Gate Failures
- Run `/ci` to see specific failures
- Format: `cargo fmt --all`
- Fix clippy warnings: `cargo clippy --fix`
- Run tests: `cargo test`

## Next Steps

1. Review [CLAUDE.md](https://github.com/ianlintner/rust-oauth2-server/blob/main/CLAUDE.md) for agent memory and guidelines
2. Explore [.skills/](../.skills/) directory for available skills
3. Try [.claude/commands/](../.claude/commands/) slash commands
4. Configure MCP server: [mcp-server/README.md](https://github.com/ianlintner/rust-oauth2-server/blob/main/mcp-server/README.md)
5. Read specialized agent instructions in [.github/agents/](../.github/agents/)

## Contributing New Examples

To add examples:
1. Document the scenario clearly
2. Show exact prompts used
3. Describe AI actions step-by-step
4. Include expected output
5. Note any gotchas or tips
6. Submit PR with example added to this file
