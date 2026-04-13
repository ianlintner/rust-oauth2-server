# Configuration

Use this page for the settings you are actually likely to touch. When you need exact keys, defaults, or comments, use `.env.example` and `application.conf.example` as the canonical contract.

## Source of truth

Check these first when docs and runtime behavior disagree:

- `.env.example`
- `application.conf.example`
- `crates/oauth2-config/`
- `crates/oauth2-server/src/lib.rs`

Runtime precedence is:

1. environment variables
2. `application.conf`
3. built-in defaults

## Minimum local config

For a useful local run, these are the only values most people need to set:

| Variable               | Why it matters                                                         |
| ---------------------- | ---------------------------------------------------------------------- |
| `OAUTH2_DATABASE_URL`  | Defaults to SQLite and is fine for local work.                         |
| `OAUTH2_JWT_SECRET`    | Required for token signing; startup fails on insecure defaults.        |
| `OAUTH2_SESSION_KEY`   | Keeps sessions stable across restarts. Use a 128-character hex string. |
| `OAUTH2_SEED_PASSWORD` | Password for the seeded admin account.                                 |
| `RUST_LOG`             | Runtime log level.                                                     |

Example:

```dotenv
OAUTH2_DATABASE_URL=sqlite:oauth2.db
OAUTH2_JWT_SECRET=replace-with-a-random-32+-char-secret
OAUTH2_SESSION_KEY=replace-with-128-hex-characters
OAUTH2_SEED_PASSWORD=replace-with-a-local-admin-password
RUST_LOG=info
```

Generate a session key with:

```bash
openssl rand -hex 64
```

## Database pool tuning

These settings control the SQLx connection pool when using SQLite or PostgreSQL:

| Variable                              | Default | Purpose                                  |
| ------------------------------------- | ------- | ---------------------------------------- |
| `OAUTH2_DATABASE_MAX_CONNECTIONS`     | `50`    | Maximum number of connections in the pool |
| `OAUTH2_DATABASE_MIN_CONNECTIONS`     | `1`     | Minimum idle connections to keep open    |
| `OAUTH2_DATABASE_ACQUIRE_TIMEOUT_SECS`| `30`    | Seconds to wait when acquiring a connection |
| `OAUTH2_DATABASE_IDLE_TIMEOUT_SECS`   | `600`   | Seconds before an idle connection is closed |
| `OAUTH2_DATABASE_READ_URL`            | —       | Optional read-replica URL for read traffic |

## URL, proxy, and browser settings

These matter when the bind address is not the same as the public address clients use.

| Variable                            | Use it when                                                          |
| ----------------------------------- | -------------------------------------------------------------------- |
| `OAUTH2_SERVER_PUBLIC_BASE_URL`     | the externally visible issuer/base URL differs from the bind address |
| `OAUTH2_SERVER_TRUST_PROXY_HEADERS` | the server sits behind a trusted reverse proxy                       |
| `OAUTH2_ALLOWED_ORIGINS`            | browsers call the server cross-origin                                |
| `OAUTH2_SERVER_WORKERS`             | you want to pin Actix worker count                                   |

The runtime also accepts `OAUTH2_PUBLIC_URL` as an alias for the public base URL.

## Security-sensitive settings

These are worth calling out because startup and auth flows depend on them.

| Variable                          | Notes                                                       |
| --------------------------------- | ----------------------------------------------------------- |
| `OAUTH2_JWT_SECRET`               | Must be strong and must not use the insecure default.       |
| `OAUTH2_SESSION_KEY`              | Persistent 64-byte key encoded as 128 hex characters.       |
| `OAUTH2_SEED_USERNAME`            | Optional; defaults to `admin`.                              |
| `OAUTH2_SEED_EMAIL`               | Optional; defaults to `admin@example.com`.                  |
| `OAUTH2_SEED_PASSWORD`            | Required in normal mode; the server aborts on `changeme`.   |
| `OAUTH2_ALLOW_INSECURE_DEFAULTS`  | Development-only escape hatch. Never set in production.     |
| `OAUTH2_JWT_STATELESS_VALIDATION` | Skips DB-backed introspection checks for higher throughput. |
| `OAUTH2_ACCESS_TOKENS_OPAQUE`    | Issue opaque (reference-style) access tokens instead of JWTs. Default `false`. |
| `OAUTH2_PUBLIC_INTROSPECTION`     | Allows unauthenticated callers to use introspection. Default `false`. |

## Social login

Implemented provider flows today:

- Google
- Microsoft
- Azure
- GitHub

Important caveats:

- `/auth/login/azure` and `/auth/callback/azure` prefer `OAUTH2_AZURE_*` settings and fall back to `OAUTH2_MICROSOFT_*` when Azure-specific config is unset.
- Okta and Auth0 config fields exist, but those routes currently return HTTP `503`.

Example Microsoft setup:

```bash
export OAUTH2_MICROSOFT_CLIENT_ID=your-client-id
export OAUTH2_MICROSOFT_CLIENT_SECRET=your-client-secret
export OAUTH2_MICROSOFT_REDIRECT_URI=http://localhost:8080/auth/callback/microsoft
export OAUTH2_MICROSOFT_TENANT_ID=common
```

## OIDC signing

If you want RS256 id tokens and a populated JWKS endpoint, configure:

| Variable                          | Purpose                                                                 |
| --------------------------------- | ----------------------------------------------------------------------- |
| `OAUTH2_ID_TOKEN_PRIVATE_KEY_PEM` | RSA private key PEM; literal newlines and `\n`-escaped values both work |
| `OAUTH2_ID_TOKEN_KID`             | Key id published through JWKS                                           |
| `OAUTH2_ID_TOKEN_ALG`             | Usually `RS256`; defaults to `RS256` when a private key is present      |

If these are not set, id tokens fall back to HS256 using `OAUTH2_JWT_SECRET`.

## Eventing, caching, and traffic control

Runtime defaults:

- `OAUTH2_EVENTS_ENABLED=true`
- `OAUTH2_EVENTS_BACKEND=in_memory`
- `OAUTH2_EVENTS_FILTER_MODE=allow_all`

Event ingest authentication:

| Variable                          | Purpose                                                                                |
| --------------------------------- | -------------------------------------------------------------------------------------- |
| `OAUTH2_EVENTS_PUBLIC_INGEST`     | Allow unauthenticated callers to `POST /events/ingest`. Default `false`.               |
| `OAUTH2_EVENTS_INGEST_BEARER_TOKEN` | Shared bearer token required when `OAUTH2_EVENTS_PUBLIC_INGEST=false`. Callers send `Authorization: Bearer <token>`. |

Feature-gated broker backends:

| Backend       | Build requirement          |
| ------------- | -------------------------- |
| Redis Streams | `--features events-redis`  |
| Kafka         | `--features events-kafka`  |
| RabbitMQ      | `--features events-rabbit` |

Cluster and performance knobs:

| Variable                    | What it controls                                     |
| --------------------------- | ---------------------------------------------------- |
| `OAUTH2_DATABASE_READ_URL`  | Optional read replica for geographically local reads |
| `OAUTH2_CACHE_REDIS_URL`    | Redis L2 cache (requires `redis-cache`)              |
| `OAUTH2_TOKEN_ACTOR_SHARDS` | Per-process token actor shard count                  |
| `OAUTH2_RATE_LIMIT_*`       | In-memory or Redis-backed request throttling         |
| `OAUTH2_RESILIENCE_*`       | Back-pressure and circuit-breaker middleware         |

For the bundled clustered profile, build with:

```bash
cargo build --release --features distributed
```

## HOCON vs env files

Use environment variables when:

- you deploy with containers or Kubernetes
- secrets come from a secret manager
- you want a twelve-factor-style setup

Use `application.conf` when:

- you want a checked-in local baseline
- you prefer grouped config over a long env file
- you are mixing defaults with a few environment overrides

## Related pages

- [Quickstart](quickstart.md)
- [OAuth & OIDC](../usage/oauth2-oidc.md)
- [Deployment](../operations/deployment.md)
