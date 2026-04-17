# Quickstart

## For AI Agents

> **Prompt:** "Set up rust-oauth2-server locally with the default SQLite database, create an admin user, register a test OAuth2 client, and request an access token to verify it's working"

**What this guide does:**
1. Configures local environment variables (JWT secret, session key, admin password)
2. Starts the server with SQLite (auto-initializes tables)
3. Logs in as the seeded admin user
4. Registers an OAuth2 client via the admin API
5. Requests a token using client credentials flow
6. Verifies health endpoints

**Expected outcome:** A working OAuth2 server running on localhost:8080 with a registered client that can issue tokens.

---

This is the shortest reliable path from clone to a working token request.

## 1. Prepare local config

Start from the example environment file:

```bash
cp .env.example .env
```

For a local first run, set at least these values in `.env`:

```dotenv
OAUTH2_JWT_SECRET=replace-with-a-random-32+-char-secret
OAUTH2_SESSION_KEY=replace-with-128-hex-characters
OAUTH2_SEED_PASSWORD=replace-with-a-local-admin-password
RUST_LOG=info
```

Generate a session key if you do not already have one:

```bash
openssl rand -hex 64
```

## 2. Start the server

Fastest local path:

```bash
cargo run
```

Default local URLs:

- app: `http://localhost:8080`
- login: `http://localhost:8080/auth/login`
- admin: `http://localhost:8080/admin`
- Swagger UI: `http://localhost:8080/swagger-ui`

!!! note
The default local path uses SQLite. The SQLx adapter initializes the required tables at startup, so you do not need Flyway just to get moving.

If you want the full Postgres-based local stack instead, use Docker Compose:

```bash
docker compose up -d
```

## 3. Log in as admin

The server seeds an admin user on first startup.

- username: `admin` unless you changed `OAUTH2_SEED_USERNAME`
- password: the value of `OAUTH2_SEED_PASSWORD`

You can sign in through the browser, or collect a cookie jar from the CLI:

```bash
curl -i -c cookie.jar -b cookie.jar \
  -X POST http://localhost:8080/auth/login \
  -d "username=admin&password=YOUR_SEED_PASSWORD"
```

## 4. Register a client

Use the admin session cookie to register a client:

```bash
curl -X POST http://localhost:8080/admin/clients/register \
  -H "Content-Type: application/json" \
  -b cookie.jar \
  -d '{
    "client_name": "Local Test App",
    "redirect_uris": ["http://localhost:3000/callback"],
    "grant_types": ["authorization_code", "client_credentials"],
    "scope": "openid profile read write"
  }'
```

Save the returned `client_id` and `client_secret`.

## 5. Request a token

Client credentials is the fastest way to prove the system works end to end:

```bash
curl -X POST http://localhost:8080/oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&client_id=YOUR_CLIENT_ID&client_secret=YOUR_CLIENT_SECRET&scope=read"
```

Optional smoke checks:

```bash
curl http://localhost:8080/health
curl http://localhost:8080/ready
curl http://localhost:8080/.well-known/openid-configuration
```

## 6. Know the sharp edges

- `/` redirects to `/profile`, not `/auth/login`
- refresh-token and password grants are intentionally disabled by default
- Okta and Auth0 routes exist but currently return HTTP `503`
- admin routes require an authenticated admin session

## Next pages

- [Configuration](configuration.md)
- [OAuth & OIDC](../usage/oauth2-oidc.md)
- [Admin & API](../usage/admin-api.md)
- [Deployment](../operations/deployment.md)
