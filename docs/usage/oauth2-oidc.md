# OAuth & OIDC

This server is an OAuth2 authorization server with a practical OIDC surface: discovery, JWKS, and UserInfo. This page covers the endpoints and behaviors you actually need when integrating a client.

## What is supported

| Capability                | Status                              | Notes                                                                                             |
| ------------------------- | ----------------------------------- | ------------------------------------------------------------------------------------------------- |
| Authorization Code + PKCE | Shipped                             | PKCE with `S256` is required for the browser flow.                                                |
| Client Credentials        | Shipped                             | Best path for service-to-service access.                                                          |
| Device Authorization      | Shipped                             | RFC 8628 — headless devices and limited-input screens.                                            |
| Token introspection       | Shipped                             | `POST /oauth/introspect`. JSON or signed JWT (`Accept: application/token-introspection+jwt`).     |
| Token revocation          | Shipped                             | `POST /oauth/revoke`.                                                                             |
| Pushed Authorization Requests (PAR) | Shipped                   | `POST /oauth/par` — RFC 9126.                                                                     |
| OIDC logout               | Shipped                             | `GET /oauth/logout` with `id_token_hint` validation.                                              |
| Discovery                 | Shipped                             | `GET /.well-known/openid-configuration`.                                                          |
| JWKS                      | Shipped                             | `GET /.well-known/jwks.json`. Returns RSA public keys when RS256 signing is configured.           |
| UserInfo                  | Shipped                             | `GET` or `POST /oauth/userinfo`. Returns real claims from storage.                                |
| Protected Resource Metadata | Shipped                           | `GET /.well-known/oauth-protected-resource` — RFC 9728.                                           |
| Dynamic Client Registration | Shipped                           | `POST /connect/register` — RFC 7591. Read/update/delete via RFC 7592.                             |
| Opaque access tokens      | Shipped                             | Set `OAUTH2_ACCESS_TOKENS_OPAQUE=true` to issue reference tokens instead of JWTs.                 |
| Refresh token grant       | Implemented but disabled by default | Requests are rejected with `unsupported_grant_type` unless your deployment explicitly enables it. |
| Password grant            | Implemented but disabled by default | Not recommended; requests are rejected by default.                                                |

## Endpoint map

| Endpoint                                | Method        | Purpose                                                     |
| --------------------------------------- | ------------- | ----------------------------------------------------------- |
| `/oauth/authorize`                      | `GET`         | Start Authorization Code + PKCE flow.                       |
| `/oauth/token`                          | `POST`        | Exchange code or client credentials for tokens.             |
| `/oauth/introspect`                     | `POST`        | Validate a token and return metadata (JSON or JWT).         |
| `/oauth/revoke`                         | `POST`        | Revoke an access or refresh token.                          |
| `/oauth/par`                            | `POST`        | Push authorization request and get a `request_uri`.         |
| `/oauth/userinfo`                       | `GET`, `POST` | Return claims for the authenticated subject.                |
| `/oauth/logout`                         | `GET`         | RP-initiated logout; honours `id_token_hint`.               |
| `/oauth/device_authorization`           | `POST`        | Start a Device Authorization flow (RFC 8628).               |
| `/oauth/device/verify`                  | `GET`, `POST` | Browser UI for device user-code entry and approval.         |
| `/connect/register`                     | `POST`        | RFC 7591 dynamic client registration.                       |
| `/connect/register/{client_id}`         | `GET`, `PUT`, `DELETE` | RFC 7592 client configuration management.          |
| `/.well-known/openid-configuration`     | `GET`         | Discovery document for clients and proxies.                 |
| `/.well-known/oauth-authorization-server` | `GET`       | Alias for the OIDC discovery document (RFC 8414).           |
| `/.well-known/jwks.json`                | `GET`         | Public signing keys for RS256 id tokens.                    |
| `/.well-known/oauth-protected-resource` | `GET`         | Protected resource metadata (RFC 9728).                     |

## Authorization Code + PKCE

Use this for browser, mobile, and interactive applications.

Required query parameters:

- `response_type=code`
- `client_id`
- `redirect_uri`
- `code_challenge`
- `code_challenge_method=S256`
- `state` strongly recommended

Example authorization request:

```text
http://localhost:8080/oauth/authorize?response_type=code&client_id=YOUR_CLIENT_ID&redirect_uri=http://localhost:3000/callback&scope=openid%20profile%20read&state=csrf-token&code_challenge=CODE_CHALLENGE&code_challenge_method=S256
```

Exchange the returned code:

```bash
curl -X POST http://localhost:8080/oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code" \
  -d "code=AUTH_CODE" \
  -d "client_id=YOUR_CLIENT_ID" \
  -d "client_secret=YOUR_CLIENT_SECRET" \
  -d "redirect_uri=http://localhost:3000/callback" \
  -d "code_verifier=CODE_VERIFIER"
```

!!! note
`redirect_uri` is optional for OAuth 2.1-style clients, but if you send it, it must exactly match the value used during authorization.

## Client Credentials

Use this for server-to-server access where there is no end user in the loop.

```bash
curl -X POST http://localhost:8080/oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&client_id=YOUR_CLIENT_ID&client_secret=YOUR_CLIENT_SECRET&scope=read"
```

## Introspection and revocation

Both endpoints require client authentication by default. Two methods are supported:

| Method                | How to use it                                                                   |
| --------------------- | ------------------------------------------------------------------------------- |
| `client_secret_post`  | Send `client_id` and `client_secret` as form fields (shown in the examples) |
| `client_secret_basic` | Send credentials as an HTTP Basic `Authorization` header                        |

The discovery document at `/.well-known/openid-configuration` advertises the supported methods in `introspection_endpoint_auth_methods_supported` and `revocation_endpoint_auth_methods_supported`.

Validate a token (`client_secret_post`):

```bash
curl -X POST http://localhost:8080/oauth/introspect \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "token=ACCESS_TOKEN" \
  -d "client_id=YOUR_CLIENT_ID" \
  -d "client_secret=YOUR_CLIENT_SECRET"
```

Or with HTTP Basic auth (`client_secret_basic`):

```bash
curl -X POST http://localhost:8080/oauth/introspect \
  -u "YOUR_CLIENT_ID:YOUR_CLIENT_SECRET" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "token=ACCESS_TOKEN"
```

### JWT introspection response (RFC 9701)

Add `Accept: application/token-introspection+jwt` to receive the introspection response as a signed JWT instead of plain JSON. The response carries `Content-Type: application/token-introspection+jwt` and the JOSE header `typ: "token-introspection+jwt"`.

```bash
curl -X POST http://localhost:8080/oauth/introspect \
  -u "YOUR_CLIENT_ID:YOUR_CLIENT_SECRET" \
  -H "Accept: application/token-introspection+jwt" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "token=ACCESS_TOKEN"
```

Revoke a token (`client_secret_post`):

```bash
curl -X POST http://localhost:8080/oauth/revoke \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "token=ACCESS_TOKEN" \
  -d "client_id=YOUR_CLIENT_ID" \
  -d "client_secret=YOUR_CLIENT_SECRET"
```

Or with HTTP Basic auth (`client_secret_basic`):

```bash
curl -X POST http://localhost:8080/oauth/revoke \
  -u "YOUR_CLIENT_ID:YOUR_CLIENT_SECRET" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "token=ACCESS_TOKEN"
```

!!! note
    If your deployment intentionally allows unauthenticated introspection, set `OAUTH2_PUBLIC_INTROSPECTION=true`. When enabled, the discovery document adds `none` to the list of supported auth methods. This is not recommended for production.

## Device Authorization Grant (RFC 8628)

Use this for headless devices and applications with limited input capabilities (smart TVs, CLIs, IoT devices).

Start a device flow:

```bash
curl -X POST http://localhost:8080/oauth/device_authorization \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "client_id=YOUR_CLIENT_ID&scope=read"
```

The response includes `device_code`, `user_code`, `verification_uri`, `verification_uri_complete`, `expires_in`, and `interval`. Direct the user to `verification_uri` to enter `user_code`, or to `verification_uri_complete` directly.

The device polls for the token:

```bash
curl -X POST http://localhost:8080/oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=urn:ietf:params:oauth:grant-type:device_code" \
  -d "device_code=DEVICE_CODE" \
  -d "client_id=YOUR_CLIENT_ID"
```

Poll at the rate indicated by `interval`. Expect `authorization_pending` until the user approves, then a token response.

## Pushed Authorization Requests (PAR — RFC 9126)

Push authorization parameters before the redirect to prevent tampering. Use for high-security flows (FAPI, enterprise deployments).

Push the request:

```bash
curl -X POST http://localhost:8080/oauth/par \
  -u "YOUR_CLIENT_ID:YOUR_CLIENT_SECRET" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "response_type=code" \
  -d "client_id=YOUR_CLIENT_ID" \
  -d "redirect_uri=https://yourapp.example/callback" \
  -d "scope=openid profile" \
  -d "code_challenge=CODE_CHALLENGE" \
  -d "code_challenge_method=S256"
```

The response returns `request_uri` (valid for 60 seconds) and `expires_in`. Use the `request_uri` in the authorization redirect:

```text
http://localhost:8080/oauth/authorize?request_uri=REQUEST_URI&client_id=YOUR_CLIENT_ID
```

## Dynamic Client Registration (RFC 7591 / RFC 7592)

Register a client programmatically without admin involvement.

Register a new client:

```bash
curl -X POST http://localhost:8080/connect/register \
  -H "Content-Type: application/json" \
  -d '{
    "client_name": "My App",
    "redirect_uris": ["https://myapp.example/callback"],
    "grant_types": ["authorization_code", "refresh_token"],
    "response_types": ["code"],
    "scope": "openid profile email",
    "token_endpoint_auth_method": "client_secret_basic"
  }'
```

The response includes `client_id`, `client_secret` (for confidential clients), and `registration_access_token`. Store the `registration_access_token` — it is required for later management calls.

Read your registration:

```bash
curl http://localhost:8080/connect/register/YOUR_CLIENT_ID \
  -H "Authorization: Bearer REGISTRATION_ACCESS_TOKEN"
```

Update your registration:

```bash
curl -X PUT http://localhost:8080/connect/register/YOUR_CLIENT_ID \
  -H "Authorization: Bearer REGISTRATION_ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"client_name": "My Updated App", ...}'
```

Delete your registration:

```bash
curl -X DELETE http://localhost:8080/connect/register/YOUR_CLIENT_ID \
  -H "Authorization: Bearer REGISTRATION_ACCESS_TOKEN"
```

## Opaque access tokens

By default, access tokens are JWTs. To issue opaque (reference-style) tokens that require introspection to validate, set:

```dotenv
OAUTH2_ACCESS_TOKENS_OPAQUE=true
```

Resource servers must then call `/oauth/introspect` for every token validation instead of validating the JWT locally.

## Discovery, JWKS, and UserInfo

The discovery document advertises the live endpoint names used by the server:

- `authorization_endpoint`
- `token_endpoint`
- `token_introspection_endpoint`
- `token_revocation_endpoint`
- `userinfo_endpoint`
- `jwks_uri`
- `registration_endpoint`

Fetch discovery:

```bash
curl http://localhost:8080/.well-known/openid-configuration
```

Fetch JWKS:

```bash
curl http://localhost:8080/.well-known/jwks.json
```

Call UserInfo with a bearer token:

```bash
curl http://localhost:8080/oauth/userinfo \
  -H "Authorization: Bearer ACCESS_TOKEN"
```

## Registration is admin-scoped

Dynamic client registration for this project is intentionally an admin workflow, not an anonymous public registration endpoint.

- Route: `POST /admin/clients/register`
- Authentication: admin session required

See [Admin & API](admin-api.md) for the admin workflow.

## Integration checklist

Before wiring a client against this server, confirm:

- your `redirect_uri` exactly matches the registered value
- you are using PKCE for Authorization Code
- your public issuer/base URL is correct behind a proxy (`OAUTH2_SERVER_PUBLIC_BASE_URL`, alias `OAUTH2_PUBLIC_URL`)
- your chosen scopes exist in your client registration
- you are not depending on refresh/password grants unless you have intentionally enabled them
- if you need opaque tokens, set `OAUTH2_ACCESS_TOKENS_OPAQUE=true` and configure resource servers to call `/oauth/introspect`

## Related pages

- [Quickstart](../getting-started/quickstart.md)
- [Configuration](../getting-started/configuration.md)
- [Admin & API](admin-api.md)
- [Integrations](integrations.md)
