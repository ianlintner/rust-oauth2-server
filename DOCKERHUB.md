# Rust OAuth2 Server (Docker Image)

A production-ready OAuth2 authorization server built with Rust + Actix-web.

This page is written for **Docker Hub users** who want to run the server **without compiling**.

> Image name used in examples: `ianlintner068/oauth2-server`
>
> If you publish under a different namespace/name, replace it everywhere below.

## Quick start (SQLite, no extra containers)

This runs the server with an embedded SQLite database stored in a Docker volume.

- UI login page: `http://localhost:8080/auth/login`
- Swagger UI: `http://localhost:8080/swagger-ui`
- Health: `http://localhost:8080/health`

### 1) Generate secrets

In production you **must** set a JWT secret and (strongly recommended) a persistent session key.

- `OAUTH2_JWT_SECRET`: minimum 32 characters (64+ recommended)
- `OAUTH2_SESSION_KEY`: **128 hex characters** (64 bytes) recommended

Examples:

- JWT secret (hex, 32 bytes): `openssl rand -hex 32`
- Session key (hex, 64 bytes): `openssl rand -hex 64`

### 2) Run the container

```bash
docker run --rm -p 8080:8080 \
  -e OAUTH2_SERVER_HOST=0.0.0.0 \
  -e OAUTH2_SERVER_PORT=8080 \
  -e OAUTH2_DATABASE_URL=sqlite:/app/data/oauth2.db \
  -e OAUTH2_JWT_SECRET="$(openssl rand -hex 32)" \
  -e OAUTH2_SESSION_KEY="$(openssl rand -hex 64)" \
  -e RUST_LOG=info \
  -v oauth2_data:/app/data \
  --name rust-oauth2-server \
  ianlintner068/oauth2-server:latest
```

The first start will create `/app/data/oauth2.db` automatically.

## Docker Compose (SQLite)

```yaml
services:
  oauth2:
    image: ianlintner068/oauth2-server:latest
    ports:
      - "8080:8080"
    environment:
      OAUTH2_SERVER_HOST: 0.0.0.0
      OAUTH2_SERVER_PORT: 8080
      OAUTH2_DATABASE_URL: sqlite:/app/data/oauth2.db
      OAUTH2_JWT_SECRET: ${OAUTH2_JWT_SECRET}
      OAUTH2_SESSION_KEY: ${OAUTH2_SESSION_KEY}
      RUST_LOG: info
    volumes:
      - oauth2_data:/app/data

volumes:
  oauth2_data:
```

## Environment variables (most common)

| Variable              |       Required | Example                      | Notes                                                                                          |
| --------------------- | -------------: | ---------------------------- | ---------------------------------------------------------------------------------------------- |
| `OAUTH2_SERVER_HOST`  |    Recommended | `0.0.0.0`                    | Bind to all interfaces inside the container                                                    |
| `OAUTH2_SERVER_PORT`  |       Optional | `8080`                       | Defaults to 8080                                                                               |
| `OAUTH2_DATABASE_URL` |    Recommended | `sqlite:/app/data/oauth2.db` | Also supports Postgres URLs                                                                    |
| `OAUTH2_JWT_SECRET`   | **Yes (prod)** | (see above)                  | Must be at least 32 chars; do not use defaults in production                                   |
| `OAUTH2_SESSION_KEY`  | **Yes (prod)** | `openssl rand -hex 64`       | Must be **hex**; should be **64 bytes** (128 hex chars). Without it, sessions reset on restart |
| `RUST_LOG`            |       Optional | `info` / `debug`             | Rust logging level                                                                             |

## Useful endpoints

- Login UI: `GET /auth/login`
- OAuth endpoints:
  - `GET /oauth/authorize`
  - `POST /oauth/token`
  - `POST /oauth/introspect`
  - `POST /oauth/revoke`
- OpenID discovery: `GET /.well-known/openid-configuration`
- Swagger UI: `GET /swagger-ui`
- OpenAPI JSON: `GET /api-docs/openapi.json`
- Health: `GET /health`
- Readiness: `GET /ready`
- Prometheus metrics: `GET /metrics`

## Configuration via `application.conf` (optional)

By default, the container reads configuration from environment variables.

If you prefer a config file, mount one to `/app/application.conf`:

```bash
docker run --rm -p 8080:8080 \
  -v "$PWD/application.conf:/app/application.conf:ro" \
  -e OAUTH2_JWT_SECRET="$(openssl rand -hex 32)" \
  ianlintner068/oauth2-server:latest
```

The `application.conf` format is HOCON and supports environment substitution.

## PostgreSQL (production setup)

The Postgres backend is supported, but the schema is expected to be created by **Flyway migrations**.

### Recommended (no compile, but you’ll clone for migrations)

Use the repository’s `docker-compose.yml` (it includes Postgres + Flyway migrations).

To run the **prebuilt** image, change the `oauth2_server` service from `build: .` to:

- `image: ianlintner/rust-oauth2-server:latest`

Repository: https://github.com/ianlintner/rust-oauth2-server

## Notes & troubleshooting

- **JWT secret warnings**: if you don’t set `OAUTH2_JWT_SECRET`, the server will start with an insecure default intended only for testing.
- **Session key format**: `OAUTH2_SESSION_KEY` must be hex. Use `openssl rand -hex 64`.
- **SQLite persistence**: mount `/app/data` (or another directory) and point `OAUTH2_DATABASE_URL` at that path.
- **MongoDB**: Mongo support is feature-gated in the Rust build.
  - Default image (no Mongo): `:latest` (or `:<version>`)
  - Mongo-enabled image: `:latest-mongo` (or `:<version>-mongo`)
  - Mongo-only image (no SQLx/SQL support): `:latest-mongo-only` (or `:<version>-mongo-only`)

## MongoDB (prebuilt image)

Use the mongo-enabled tag and point `OAUTH2_DATABASE_URL` at a MongoDB connection string.

If you specifically want a build with **no SQLx/SQL support compiled in**, use the `*-mongo-only` tag.

### Docker Compose (MongoDB)

```yaml
services:
  mongo:
    image: mongo:7
    ports:
      - "27017:27017"
    volumes:
      - mongo_data:/data/db

  oauth2:
    image: ianlintner068/oauth2-server:latest-mongo
    ports:
      - "8080:8080"
    environment:
      OAUTH2_SERVER_HOST: 0.0.0.0
      OAUTH2_SERVER_PORT: 8080
      OAUTH2_DATABASE_URL: mongodb://mongo:27017/oauth2
      OAUTH2_JWT_SECRET: ${OAUTH2_JWT_SECRET}
      OAUTH2_SESSION_KEY: ${OAUTH2_SESSION_KEY}
      RUST_LOG: info
    depends_on:
      - mongo

volumes:
  mongo_data:
```

## Source

- GitHub: https://github.com/ianlintner/rust-oauth2-server

## License

Dual-licensed under Apache-2.0 and MIT.
