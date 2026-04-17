# Extending

## For AI Agents

> **Prompt:** "Add a new custom storage backend using CouchDB to the rust-oauth2-server"

**Common extension tasks:**

| Task | Prompt Example |
|------|----------------|
| Add storage backend | "Implement a DynamoDB storage backend for the OAuth2 server" |
| Add middleware | "Add custom rate limiting middleware that reads limits from a database" |
| Add event backend | "Add support for AWS SQS as an event backend" |
| Add OAuth grant | "Implement a custom OAuth2 grant type for device authentication" |
| Add admin endpoint | "Add a new admin API endpoint to export client configurations" |
| Custom metrics | "Add custom Prometheus metrics for tracking authorization success rates" |

**Extension points:**
- Storage: Implement `oauth2_ports::Storage` trait
- Middleware: Add to `crates/oauth2-actix/src/middleware/`
- Events: Extend `crates/oauth2-events/`
- Handlers: Add routes in `crates/oauth2-actix/src/handlers/`

**Key warning:** Adding `web::Data<T>` to a handler requires updating all test setups in `tests/security_http.rs`

---

This page is for contributors who want to add behavior without forking the entire project into a ball of sadness.

## Add a custom storage backend

The intended extension seam is `oauth2_ports::Storage`.

General approach:

1. create a new crate or adapter that implements the storage trait
2. wire it into backend selection in `oauth2-storage-factory`
3. add tests for create, read, revoke, auth-code, and user flows
4. document the new connection string or feature flag in `.env.example` and `application.conf.example`

If you only need SQLx or Mongo, prefer improving the existing adapters rather than inventing a parallel abstraction tower.

## Add middleware or request policy

Most cross-cutting behavior belongs in one of these places:

- `crates/oauth2-actix/src/middleware/` for HTTP middleware
- `oauth2-ratelimit/` for throttling behavior
- `oauth2-resilience/` for back-pressure, bulkheads, and circuit breaking
- `crates/oauth2-observability/` for tracing and metrics

When adding route-level or middleware-level app state, remember this repo pitfall:

!!! warning
If you add a new `web::Data<T>` dependency to a handler, update every matching app setup in `tests/security_http.rs`.

## Add an event backend or plugin

Auth events are emitted through `crates/oauth2-events/`.

Good extension pattern:

1. implement the plugin or publisher in `oauth2-events`
2. gate external infrastructure dependencies behind a cargo feature
3. add config keys to `application.conf.example`
4. add runtime wiring in `crates/oauth2-server/src/lib.rs`

The existing Redis, Kafka, and RabbitMQ backends are the reference pattern.

## Add or finish a social provider

Social login lives in `crates/oauth2-social-login/` and the `/auth/login/*` route wiring in `crates/oauth2-server/src/lib.rs`.

Today:

- Google, Microsoft, GitHub, and Azure routes are wired
- Okta and Auth0 are not fully implemented

If you finish a provider, update all three of these surfaces together:

- route registration
- runtime config docs (`.env.example`, `application.conf.example`)
- user-facing docs in `docs/usage/integrations.md` and `README.md`

## Extend the MCP server

The MCP server is a separate Node.js app.

To add a tool:

1. update the tool list and schema in `mcp-server/src/index.js`
2. implement the underlying HTTP call in the client wrapper
3. update [the repo-local MCP guide](https://github.com/ianlintner/rust-oauth2-server/blob/main/mcp-server/README.md)
4. keep tool descriptions aligned with the actual route and auth model

## Keep docs from drifting again

When behavior changes, update the code-backed sources first:

- OpenAPI routes or handler behavior
- `.env.example`
- `application.conf.example`
- the smallest relevant page under `docs/`

Avoid duplicating large configuration tables across multiple pages.

Also keep the doc surface small:

- update the smallest relevant page
- prefer repo-local deep guides (`k8s/README.md`, `mcp-server/README.md`, `DOCKERHUB.md`, `benchmarks/README.md`) for specialist detail
- delete stale duplicate pages instead of preserving them “just in case”

## Related pages

- [Architecture](architecture.md)
- [Testing](testing.md)
- [Contributing](contributing.md)
