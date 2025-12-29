# Example Resource Server (Introspection)

This is a tiny example "resource server" used for the KIND E2E cookbook/tests.

It exposes:

- `GET /public` (no auth)
- `GET /protected` (requires `Authorization: Bearer <token>` and validates via
  `POST /oauth/introspect`)
- `GET /health`, `GET /ready`

## Configuration

Environment variables:

- `PORT` (default: `8080`)
- `OAUTH2_INTROSPECT_URL` (default: `http://oauth2-server/oauth/introspect`)
- `OAUTH2_CLIENT_ID` (required)
- `OAUTH2_CLIENT_SECRET` (required)
- `REQUIRED_SCOPE` (optional, e.g. `read`)

## Intended usage

In Kubernetes, the E2E runner will:

1. Deploy the OAuth2 server + this resource server
2. Register a test client against the OAuth2 server
3. Patch the resource server deployment with the generated client credentials
4. Call `/protected` with/without the token to verify service-to-service auth
