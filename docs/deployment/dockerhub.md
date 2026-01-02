# Docker Hub Image (Prebuilt)

This page documents how to run the **prebuilt** Rust OAuth2 Server container image from Docker Hub.

If you’re looking for “clone + build”, see [Docker](docker.md).

> **Goal:** run the server without compiling Rust.

## Image

Examples below use:

- `ianlintner068/oauth2-server:latest`

Mongo-enabled prebuilt image:

- `ianlintner068/oauth2-server:latest-mongo`

Mongo-only (no SQLx/SQL support compiled in):

- `ianlintner068/oauth2-server:latest-mongo-only`

If you publish under a different name, substitute accordingly.

## Quick start (SQLite)

SQLite is the simplest way to run the server as a single container.

### Run

```bash
docker run --rm -p 8080:8080 \
  -e OAUTH2_SERVER_HOST=0.0.0.0 \
  -e OAUTH2_DATABASE_URL=sqlite:/app/data/oauth2.db \
  -e OAUTH2_JWT_SECRET="$(openssl rand -hex 32)" \
  -e OAUTH2_SESSION_KEY="$(openssl rand -hex 64)" \
  -v oauth2_data:/app/data \
  ianlintner068/oauth2-server:latest
```

### Verify

- Login UI: `http://localhost:8080/auth/login`
- Swagger UI: `http://localhost:8080/swagger-ui`
- Health: `http://localhost:8080/health`
- Metrics: `http://localhost:8080/metrics`

## Required production settings

### `OAUTH2_JWT_SECRET`

The server will warn (and be insecure) if you don’t provide a JWT signing secret.

- Minimum: 32 characters
- Recommended: 64+ random characters

Generate example:

```bash
openssl rand -hex 32
```

### `OAUTH2_SESSION_KEY`

In production you should set a persistent session key so sessions don’t reset on container restart.

- Must be **hex**
- Should be **64 bytes** = **128 hex characters**

Generate example:

```bash
openssl rand -hex 64
```

## Docker Compose example (SQLite)

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

## PostgreSQL

Postgres is supported, but the server expects the schema to be created by **Flyway migrations**.

If you want Postgres with migrations and _still no compiling_, use the repository’s compose stack (Postgres + Flyway) and point the server service at the Docker Hub image.

Repository: https://github.com/ianlintner/rust-oauth2-server

## MongoDB (prebuilt)

Mongo support is feature-gated in the Rust build. Use the `*-mongo` image tag when you want to run against MongoDB.

### Docker Compose example (MongoDB)

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

## Optional: config file (`application.conf`)

The container defaults to environment-variable configuration.

If you prefer HOCON config, mount a file at `/app/application.conf`:

```bash
docker run --rm -p 8080:8080 \
  -v "$PWD/application.conf:/app/application.conf:ro" \
  -e OAUTH2_JWT_SECRET="$(openssl rand -hex 32)" \
  ianlintner/rust-oauth2-server:latest
```

## Full Docker Hub page content

The Docker Hub listing typically uses a README-like description. The repository contains `DOCKERHUB.md` with copy/paste-ready content.
