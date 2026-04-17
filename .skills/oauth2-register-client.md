# OAuth2 Register Client Skill

**Purpose**: Register a new OAuth2 client with proper configuration for specific use cases.

**When to Use**:
- Setting up a new application integration
- Creating test clients for development
- Configuring social login providers
- Enabling new grant types or scopes

## Parameters

- `client_name`: Human-readable client name
- `client_type`: Client type (confidential, public)
- `grant_types`: Comma-separated grant types (authorization_code, client_credentials, refresh_token)
- `redirect_uris`: Comma-separated redirect URIs
- `scope`: Space-separated OAuth2 scopes
- `description`: Optional client description

## Prerequisites

- OAuth2 server running and accessible
- Admin authentication (session cookie or API token)
- Understanding of OAuth2 client types and grant types

## Prompt

Register a new OAuth2 client with the following configuration:
- Client name: {{client_name}}
- Client type: {{client_type}}
- Grant types: {{grant_types}}
- Redirect URIs: {{redirect_uris}}
- Scope: {{scope}}
- Description: {{description}}

Please perform these steps:

1. **Preparation Phase**:
   - Verify server is running: `curl http://localhost:8080/health`
   - Determine client type requirements:
     - **Confidential**: Can securely store client_secret (backend services)
     - **Public**: Cannot store secrets (SPAs, mobile apps, must use PKCE)
   - Validate redirect URIs match client application URLs
   - Ensure grant types align with client type and use case

2. **Registration Phase**:
   - Prepare registration request payload:
   ```json
   {
     "client_name": "{{client_name}}",
     "redirect_uris": [{{redirect_uris}}],
     "grant_types": [{{grant_types}}],
     "token_endpoint_auth_method": "{{auth_method}}",
     "scope": "{{scope}}",
     "response_types": ["code"],
     "application_type": "web",
     "client_uri": "",
     "logo_uri": "",
     "contacts": [],
     "tos_uri": "",
     "policy_uri": "",
     "jwks_uri": "",
     "jwks": null,
     "software_id": "",
     "software_version": ""
   }
   ```

   - Set `token_endpoint_auth_method`:
     - Confidential clients: `"client_secret_basic"` or `"client_secret_post"`
     - Public clients: `"none"`

   - Make registration request:
   ```bash
   curl -X POST http://localhost:8080/admin/clients/register \
     -H "Content-Type: application/json" \
     -b "session_cookie=<admin_session>" \
     -d '<registration_json>'
   ```

3. **Validation Phase**:
   - Verify response includes:
     - `client_id`: Unique client identifier
     - `client_secret`: Secret for confidential clients (store securely!)
     - `client_id_issued_at`: Registration timestamp
     - Confirmed grant_types, redirect_uris, scope
   - Save client credentials securely
   - For public clients, verify no client_secret in response

4. **Configuration Phase**:
   - Document the client configuration:
     - Client ID
     - Client secret (if confidential)
     - Redirect URIs
     - Allowed grant types
     - Scope
   - Configure the client application with these values
   - Set up PKCE if public client

5. **Testing Phase**:
   - Test client authentication:
     - For confidential clients: Test client_credentials grant
     ```bash
     curl -X POST http://localhost:8080/oauth/token \
       -H "Content-Type: application/x-www-form-urlencoded" \
       -d "grant_type=client_credentials&client_id=<id>&client_secret=<secret>&scope={{scope}}"
     ```
     - For public clients: Test authorization_code with PKCE
   - Verify token response is valid
   - Test token introspection

## Success Criteria

- [ ] Client registered successfully with unique client_id
- [ ] Client type correctly set (confidential with secret, or public without)
- [ ] Grant types match intended use case
- [ ] Redirect URIs are valid and match client application
- [ ] Scope is properly configured
- [ ] token_endpoint_auth_method matches client type
- [ ] Client credentials stored securely
- [ ] Test token request succeeds
- [ ] Token introspection returns valid client information

## Common Issues

1. **Public client receives client_secret**: Verify token_endpoint_auth_method is "none"
2. **Redirect URI mismatch**: Ensure exact match including protocol, domain, port, path
3. **Invalid grant type**: Check grant_types are supported and appropriate for client type
4. **Scope not available**: Verify requested scopes are defined in server configuration
5. **Registration fails with 403**: Ensure admin authentication is valid

## Related Resources

- [Admin API Documentation](../docs/usage/admin-api.md)
- [Client Registration RFC 7591](https://tools.ietf.org/html/rfc7591)
- [OAuth 2.0 Client Types](https://tools.ietf.org/html/rfc6749#section-2.1)
- [PKCE RFC 7636](https://tools.ietf.org/html/rfc7636)
- [Client Model](../crates/oauth2-core/src/models/client.rs)
- [Registration Handler](../crates/oauth2-actix/src/handlers/client.rs)

## Example Usage

### Registering a Web Application (Confidential)

```
Use the oauth2-register-client skill with:
- client_name: My Web App
- client_type: confidential
- grant_types: authorization_code,refresh_token
- redirect_uris: https://myapp.com/callback
- scope: openid profile email read write
- description: Main web application
```

### Registering a Single-Page App (Public)

```
Use the oauth2-register-client skill with:
- client_name: My SPA
- client_type: public
- grant_types: authorization_code
- redirect_uris: http://localhost:3000/callback
- scope: read write
- description: Development SPA client
```

### Registering a Service Account (Confidential)

```
Use the oauth2-register-client skill with:
- client_name: Background Service
- client_type: confidential
- grant_types: client_credentials
- redirect_uris: (none needed)
- scope: api.read api.write
- description: Background processing service
```

## Using MCP Server

If using the MCP server, you can register clients via AI assistant:

```
Register a new OAuth2 client called "My App" with redirect URI
https://myapp.com/callback and authorization_code grant type.
```

The MCP server will call the `register_client` tool automatically.

## Security Considerations

1. **Store client_secret securely**: Never commit to version control
2. **Use HTTPS redirect URIs in production**: Prevent token leakage
3. **Limit scope to minimum required**: Principle of least privilege
4. **Rotate secrets periodically**: Especially for long-lived clients
5. **Public clients must use PKCE**: Mitigate authorization code interception
6. **Validate redirect URIs strictly**: Prevent open redirect attacks

## Notes

- Public clients (token_endpoint_auth_method=none) added in Phase 1.B
- All clients default to token_endpoint_auth_method="client_secret_basic"
- Migration V12 added token_endpoint_auth_method column to clients table
- Client validation enforced during registration and token requests
