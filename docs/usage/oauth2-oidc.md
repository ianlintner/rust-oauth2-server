# OAuth & OIDC

This server is an OAuth2 authorization server with a practical OIDC surface: discovery, JWKS, and UserInfo. This page covers the endpoints and behaviors you actually need when integrating a client.

## What is supported

| Capability                | Status                              | Notes                                                                                             |
| ------------------------- | ----------------------------------- | ------------------------------------------------------------------------------------------------- |
| Authorization Code + PKCE | Shipped                             | PKCE with `S256` is required for the browser flow.                                                |
| Client Credentials        | Shipped                             | Best path for service-to-service access.                                                          |
| Token introspection       | Shipped                             | `POST /oauth/introspect`.                                                                         |
| Token revocation          | Shipped                             | `POST /oauth/revoke`.                                                                             |
| Discovery                 | Shipped                             | `GET /.well-known/openid-configuration`.                                                          |
| JWKS                      | Shipped                             | `GET /.well-known/jwks.json`. Returns RSA public keys when RS256 signing is configured.           |
| UserInfo                  | Shipped                             | `GET` or `POST /oauth/userinfo`.                                                                  |
| Refresh token grant       | Implemented but disabled by default | Requests are rejected with `unsupported_grant_type` unless your deployment explicitly enables it. |
| Password grant            | Implemented but disabled by default | Not recommended; requests are rejected by default.                                                |

## Endpoint map

| Endpoint                            | Method        | Purpose                                         |
| ----------------------------------- | ------------- | ----------------------------------------------- |
| `/oauth/authorize`                  | `GET`         | Start Authorization Code + PKCE flow.           |
| `/oauth/token`                      | `POST`        | Exchange code or client credentials for tokens. |
| `/oauth/introspect`                 | `POST`        | Validate a token and return metadata.           |
| `/oauth/revoke`                     | `POST`        | Revoke an access or refresh token.              |
| `/oauth/userinfo`                   | `GET`, `POST` | Return claims for the authenticated subject.    |
| `/.well-known/openid-configuration` | `GET`         | Discovery document for clients and proxies.     |
| `/.well-known/jwks.json`            | `GET`         | Public signing keys for RS256 id tokens.        |

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

## Related pages

- [Quickstart](../getting-started/quickstart.md)
- [Configuration](../getting-started/configuration.md)
- [Admin & API](admin-api.md)
- [Integrations](integrations.md)
