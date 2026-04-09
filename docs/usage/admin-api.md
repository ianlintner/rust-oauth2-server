# Admin & API

This page covers the operator-facing HTTP surface: the admin UI, JSON admin API, health endpoints, and the generated OpenAPI docs.

## Admin authentication

All `/admin/*` routes are protected by `AdminGuard`.

- unauthenticated requests are redirected to `/auth/login`
- only admin users should use the admin UI and admin JSON API
- the seed admin account is configured with `OAUTH2_SEED_USERNAME`, `OAUTH2_SEED_PASSWORD`, and `OAUTH2_SEED_EMAIL`

## UI routes

| Route                    | Method        | Purpose                           |
| ------------------------ | ------------- | --------------------------------- |
| `/`                      | `GET`         | Redirects to `/profile`.          |
| `/profile`               | `GET`         | Authenticated user landing page.  |
| `/auth/login`            | `GET`, `POST` | Login page and login form submit. |
| `/auth/logout`           | `POST`        | End the current session.          |
| `/admin`                 | `GET`         | Admin dashboard shell.            |
| `/admin/clients`         | `GET`         | Admin clients view.               |
| `/admin/tokens`          | `GET`         | Admin tokens view.                |
| `/admin/users`           | `GET`         | Admin users view.                 |
| `/swagger-ui`            | `GET`         | Interactive OpenAPI UI.           |
| `/api-docs/openapi.json` | `GET`         | Raw OpenAPI document.             |

## Admin JSON endpoints

| Route                           | Method   | Purpose                      |
| ------------------------------- | -------- | ---------------------------- |
| `/admin/clients/register`       | `POST`   | Register a client.           |
| `/admin/api/dashboard`          | `GET`    | Dashboard totals.            |
| `/admin/api/clients`            | `GET`    | List clients.                |
| `/admin/api/tokens`             | `GET`    | List tokens.                 |
| `/admin/api/users`              | `GET`    | List users.                  |
| `/admin/api/tokens/{id}/revoke` | `POST`   | Revoke a token by id.        |
| `/admin/api/keys`               | `GET`    | List JWT signing keys.       |
| `/admin/api/keys/rotate`        | `POST`   | Rotate JWT signing keys.     |
| `/admin/api/clients/{id}`       | `DELETE` | Placeholder delete endpoint. |

!!! warning
`DELETE /admin/api/clients/{id}` currently returns a success response without performing a real delete. Treat it as a placeholder until the backend implementation lands.

## Register a client

Log in first, then submit the registration request with your session cookie:

```bash
curl -X POST http://localhost:8080/admin/clients/register \
  -H "Content-Type: application/json" \
  -b cookie.jar \
  -d '{
    "client_name": "My Application",
    "redirect_uris": ["http://localhost:3000/callback"],
    "grant_types": ["authorization_code", "client_credentials"],
    "scope": "openid profile read write"
  }'
```

## Health and operations endpoints

| Route            | Method | Purpose                                                     |
| ---------------- | ------ | ----------------------------------------------------------- |
| `/health`        | `GET`  | Liveness-style check. Returns service status and timestamp. |
| `/ready`         | `GET`  | Readiness check. Confirms storage health.                   |
| `/metrics`       | `GET`  | Prometheus metrics.                                         |
| `/events/health` | `GET`  | Event subsystem status when eventing is enabled.            |
| `/events/ingest` | `POST` | Accept externally produced event envelopes. Requires a bearer token by default (see [Integrations](integrations.md#event-ingest-authentication)). |

Example readiness response:

```json
{
  "status": "ready",
  "checks": {
    "database": "ok"
  }
}
```

## OpenAPI is the reference for payload shapes

The fastest way to confirm request and response formats is to use the generated API docs:

- browser: `http://localhost:8080/swagger-ui`
- JSON: `http://localhost:8080/api-docs/openapi.json`

That JSON is generated from code and should be treated as the canonical API contract.

## What belongs where

Use these rules to stay sane:

- use the admin UI and admin JSON endpoints for client and key management
- use `/oauth/*` for OAuth client flows
- use `/health`, `/ready`, `/metrics`, and `/events/health` for operations and monitoring
- use Swagger / OpenAPI for exact request-body and response schema details

## Related pages

- [OAuth & OIDC](oauth2-oidc.md)
- [Integrations](integrations.md)
- [Observability](../operations/observability.md)
- [Runbooks](../operations/runbooks.md)
