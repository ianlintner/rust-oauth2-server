# Architecture

## For AI Agents

> **Prompt:** "Explain the architecture of rust-oauth2-server, including the workspace structure, actor model, storage layer, and request flow"

**Common architecture tasks:**

| Task | Prompt Example |
|------|----------------|
| Understand workspace | "Show me the Cargo workspace structure and explain what each crate does" |
| Trace request flow | "Walk me through what happens when a client requests an access token" |
| Storage layer | "Explain how the storage abstraction works and how to add a new backend" |
| Actor system | "Describe the Actix actors used in the OAuth2 server and their responsibilities" |
| Add feature | "I want to add a new OAuth2 grant type - which crates and files do I need to modify?" |
| Feature flags | "Show me all available feature flags and what they enable" |

**Key architectural patterns:**
- Cargo workspace with domain-driven crate separation
- Actix actors for hot paths (TokenActor, ClientActor, AuthActor)
- Storage trait abstraction (`oauth2-ports`) with multiple backends
- Middleware pipeline for resilience, rate limiting, and observability
- Feature flags for optional dependencies (Redis, MongoDB, event buses)

---

This repo is a Cargo workspace, not a single giant crate pretending to be a plan.

## Workspace map

| Path                            | Role                                               |
| ------------------------------- | -------------------------------------------------- |
| `crates/oauth2-core`            | framework-agnostic domain models and shared types  |
| `crates/oauth2-ports`           | storage and integration traits                     |
| `crates/oauth2-config`          | HOCON and environment-backed config parsing        |
| `crates/oauth2-actix`           | HTTP handlers, middleware, and actors              |
| `crates/oauth2-server`          | server assembly and route registration             |
| `crates/oauth2-openapi`         | generated OpenAPI document wiring                  |
| `crates/oauth2-observability`   | metrics, tracing, and telemetry helpers            |
| `crates/oauth2-events`          | event types, plugins, and Actix event bus          |
| `crates/oauth2-social-login`    | provider flows and callbacks                       |
| `crates/oauth2-storage-sqlx`    | SQLite/Postgres storage adapter                    |
| `crates/oauth2-storage-mongo`   | MongoDB storage adapter                            |
| `crates/oauth2-storage-factory` | backend selection and observed storage wrapping    |
| `oauth2-ratelimit`              | in-memory and Redis-backed rate limiting           |
| `oauth2-resilience`             | concurrency limits, bulkheads, and circuit breaker |
| `mcp-server/`                   | standalone Node.js MCP server                      |

## Request path

At a high level, an HTTP request flows through:

1. resilience middleware
2. rate limiting
3. sessions
4. tracing and logging
5. metrics
6. route handler
7. actor or storage operation
8. JSON or HTML response

The concrete route wiring lives in `crates/oauth2-server/src/lib.rs`.

## Runtime characteristics

### Actors

The server uses Actix actors for the hot OAuth paths:

- `TokenActor` or `TokenActorPool`
- `ClientActor`
- `AuthActor`
- `EventActor` when eventing is enabled

### Storage

Default runtime behavior is SQLx-backed storage. The backend is selected from the database URL and feature flags:

- `sqlite:` and `postgresql:` use SQLx
- `mongodb:` requires `--features mongo`

### Feature flags

| Feature            | Purpose                                      |
| ------------------ | -------------------------------------------- |
| `sqlx`             | SQLx-backed storage (default)                |
| `mongo`            | MongoDB backend                              |
| `events-redis`     | Redis Streams event backend                  |
| `events-kafka`     | Kafka event backend                          |
| `events-rabbit`    | RabbitMQ event backend                       |
| `redis-cache`      | Redis L2 cache for actors                    |
| `redis-rate-limit` | Redis-backed rate limiting                   |
| `distributed`      | convenience bundle for clustered deployments |

## Security-relevant behavior

A few architectural choices matter for operators and contributors:

- startup fails on insecure JWT secrets and default seed passwords unless `OAUTH2_ALLOW_INSECURE_DEFAULTS=1`
- `/admin/*` routes are protected by `AdminGuard`
- CORS is fail-closed unless allowed origins are configured
- the root route redirects to `/profile`, not `/auth/login`
- Okta and Auth0 routes exist but currently return HTTP 503
- access tokens are JWTs by default; set `OAUTH2_ACCESS_TOKENS_OPAQUE=true` to issue opaque reference tokens
- introspection and revocation require client authentication by default (`OAUTH2_PUBLIC_INTROSPECTION=false`)

## Where to look before changing behavior

| Change                     | Start here                                                          |
| -------------------------- | ------------------------------------------------------------------- |
| routes or middleware order | `crates/oauth2-server/src/lib.rs`                                   |
| OAuth request handling     | `crates/oauth2-actix/src/handlers/`                                 |
| config keys or defaults    | `crates/oauth2-config/`, `.env.example`, `application.conf.example` |
| metrics or telemetry       | `crates/oauth2-observability/`                                      |
| storage behavior           | `crates/oauth2-storage-*`                                           |
| admin UI shell             | `templates/`                                                        |
| MCP tools                  | `mcp-server/src/index.js`                                           |

## Related pages

- [Extending](extending.md)
- [Testing](testing.md)
- [Contributing](contributing.md)
