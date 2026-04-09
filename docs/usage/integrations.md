# Integrations

Beyond the core OAuth endpoints, this repo exposes three integration surfaces that matter in practice:

1. social login providers
2. the eventing subsystem
3. the standalone MCP wrapper under `mcp-server/`

## Social login

| Provider  | Status          | Routes                                              |
| --------- | --------------- | --------------------------------------------------- |
| Google    | Shipped         | `/auth/login/google`, `/auth/callback/google`       |
| Microsoft | Shipped         | `/auth/login/microsoft`, `/auth/callback/microsoft` |
| Azure AD  | Shipped         | `/auth/login/azure`, `/auth/callback/azure`         |
| GitHub    | Shipped         | `/auth/login/github`, `/auth/callback/github`       |
| Okta      | Not implemented | `/auth/login/okta` returns HTTP `503`               |
| Auth0     | Not implemented | `/auth/login/auth0` returns HTTP `503`              |

Minimum setup is just provider credentials plus a redirect URI. The exact variable names live in `.env.example` and `application.conf.example`.

!!! note
`/auth/login/azure` uses the same Microsoft identity platform client as the Microsoft flow. It prefers dedicated `OAUTH2_AZURE_*` settings and falls back to `OAUTH2_MICROSOFT_*` when Azure-specific settings are unset.

Example for Google:

```bash
export OAUTH2_GOOGLE_CLIENT_ID=your-client-id
export OAUTH2_GOOGLE_CLIENT_SECRET=your-client-secret
export OAUTH2_GOOGLE_REDIRECT_URI=http://localhost:8080/auth/callback/google
```

## Eventing

The server can emit auth events and accept external event envelopes.

Runtime defaults:

- `OAUTH2_EVENTS_ENABLED=true`
- `OAUTH2_EVENTS_BACKEND=in_memory`
- `OAUTH2_EVENTS_FILTER_MODE=allow_all`
- health probe: `GET /events/health`
- external ingest: `POST /events/ingest`

### Event ingest authentication

By default, `POST /events/ingest` requires a bearer token. Configure the shared
secret with `OAUTH2_EVENTS_INGEST_BEARER_TOKEN` and include it in the
`Authorization` header:

```bash
curl -X POST http://localhost:8080/events/ingest \
  -H "Authorization: Bearer YOUR_INGEST_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{ "event": { ... } }'
```

If the token is missing or does not match, the endpoint returns HTTP `401`.
If the token variable is not configured at all, the endpoint returns HTTP `503`.

To allow unauthenticated callers (not recommended for production), set
`OAUTH2_EVENTS_PUBLIC_INGEST=true`.

Feature-gated broker backends:

| Backend       | Build requirement          |
| ------------- | -------------------------- |
| Redis Streams | `--features events-redis`  |
| Kafka         | `--features events-kafka`  |
| RabbitMQ      | `--features events-rabbit` |

Example Redis Streams path:

```bash
cargo run --features events-redis
```

```bash
export OAUTH2_EVENTS_BACKEND=redis
export OAUTH2_EVENTS_REDIS_URL=redis://127.0.0.1:6379
export OAUTH2_EVENTS_REDIS_STREAM=oauth2_events
```

## MCP server

The repository includes a separate Node.js stdio server in `mcp-server/`.

### What it exposes

| Tool                | Purpose                                 |
| ------------------- | --------------------------------------- |
| `register_client`   | Calls the admin client-registration API |
| `get_token`         | Client credentials token request        |
| `exchange_code`     | Authorization code token exchange       |
| `refresh_token`     | Refresh-token request                   |
| `introspect_token`  | Token introspection                     |
| `revoke_token`      | Token revocation                        |
| `get_health`        | Health probe                            |
| `get_readiness`     | Readiness probe                         |
| `get_metrics`       | Metrics fetch                           |
| `get_openid_config` | Discovery fetch                         |

### Important limitations

- the wrapper is **not** browser/session aware
- `register_client` targets the admin-protected endpoint `POST /admin/clients/register`
- `refresh_token` exists as a tool, but default server configs still reject the refresh grant unless you explicitly enable it
- it does **not** provide general user CRUD or admin-dashboard automation

Quick setup:

```bash
cd mcp-server
npm install
cp .env.example .env
npm start
```

Then point your MCP client at `mcp-server/src/index.js` with `OAUTH2_BASE_URL` set to the running server. The fuller repo-local guide lives in `mcp-server/README.md`.

Use the published copy here: [the MCP server README](https://github.com/ianlintner/rust-oauth2-server/blob/main/mcp-server/README.md).

## Source of truth

When you are unsure whether an integration is real or aspirational, check these files first:

- `crates/oauth2-server/src/lib.rs` for registered routes
- `.env.example` and `application.conf.example` for config keys
- `mcp-server/src/index.js` for exposed MCP tools
- `crates/oauth2-events/` for event backend support

## Useful examples

- [Eventing example](../examples/eventing.md)
- [Service-to-service example](../examples/service-to-service.md)

## Related pages

- [OAuth & OIDC](oauth2-oidc.md)
- [Configuration](../getting-started/configuration.md)
- [Admin & API](admin-api.md)
