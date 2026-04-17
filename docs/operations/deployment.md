# Deployment

## For AI Agents

> **Prompt:** "Deploy rust-oauth2-server to Kubernetes using the production overlay with PostgreSQL backend and proper secrets configuration"

**Common deployment tasks:**

| Task | Prompt Example |
|------|----------------|
| Local development | "Run the OAuth2 server locally with all dependencies using Docker Compose" |
| Kubernetes dev | "Deploy to Kubernetes dev environment with the dev overlay" |
| Kubernetes production | "Deploy to production Kubernetes with the production overlay, including proper secrets and PostgreSQL" |
| Distributed setup | "Deploy with distributed profile (Redis cache, rate limiting, event bus)" |
| Docker only | "Build and run the OAuth2 server as a Docker container with environment configuration" |

**Key files for deployment:**
- `k8s/overlays/production/` - Production Kubernetes manifests
- `k8s/overlays/production-distributed/` - HA distributed setup
- `docker-compose.yml` - Local multi-service setup
- `.env.example` - Environment variable reference

---

This page is intentionally opinionated: start with the smallest thing that works, then scale up only when you need to.

## Pick a runtime path

| Goal                                             | Recommended path                                                 |
| ------------------------------------------------ | ---------------------------------------------------------------- |
| Run locally with the fewest moving parts         | `cargo run` + SQLite                                             |
| Run locally with Postgres and the full app stack | `docker compose up -d`                                           |
| Run a packaged image without compiling           | Docker Hub image                                                 |
| Deploy to Kubernetes                             | `k8s/overlays/*` with Kustomize                                  |
| Run the clustered profile                        | `k8s/overlays/production-distributed` + `--features distributed` |

## Local development

Fastest path:

```bash
cp .env.example .env
# edit OAUTH2_JWT_SECRET, OAUTH2_SESSION_KEY, and OAUTH2_SEED_PASSWORD
cargo run
```

That default path uses SQLite. The SQLx storage layer will initialize the required tables at startup.

If you want the full local stack instead:

```bash
docker compose up -d
```

Useful local URLs:

- app: `http://localhost:8080`
- login: `http://localhost:8080/auth/login`
- admin: `http://localhost:8080/admin`
- Swagger UI: `http://localhost:8080/swagger-ui`
- metrics: `http://localhost:8080/metrics`

## Docker image paths

Build locally:

```bash
docker build -t rust-oauth2-server:local .
```

Run locally:

```bash
docker run --rm -p 8080:8080 --env-file .env rust-oauth2-server:local
```

If you want a prebuilt image instead of compiling, use the published image documented in `DOCKERHUB.md`.

Repo-local deep guide: [DOCKERHUB.md](https://github.com/ianlintner/rust-oauth2-server/blob/main/DOCKERHUB.md)

## Kubernetes

The Kubernetes manifests live under `k8s/` and are organized as:

- `k8s/base/` for shared resources
- `k8s/components/` for optional building blocks
- `k8s/overlays/` for environment-specific deployments

Standard overlays:

- `k8s/overlays/dev`
- `k8s/overlays/staging`
- `k8s/overlays/production`
- `k8s/overlays/production-distributed`

Deploy an overlay:

```bash
kubectl apply -k k8s/overlays/production -n oauth2-server
```

For the full manifest-level guide, use [the Kubernetes README](https://github.com/ianlintner/rust-oauth2-server/blob/main/k8s/README.md).

!!! note
This repo ships Kustomize overlays and raw manifests. It does **not** currently ship Helm charts.

## Distributed profile

The distributed runtime is opt-in at build time.

Build the binary or image with:

```bash
cargo build --release --features distributed
```

That convenience feature enables:

- `redis-cache`
- `redis-rate-limit`
- `events-redis`

The matching Kustomize profile is `k8s/overlays/production-distributed`, which layers in:

- `components/distributed-ha`
- `components/redis`
- `components/pgbouncer`
- `components/postgres-tuning`

## Production checklist

Before you call a deployment production-ready, confirm:

- `OAUTH2_JWT_SECRET` is strong and not the default
- `OAUTH2_SESSION_KEY` is set to a persistent 64-byte hex key
- `OAUTH2_SEED_PASSWORD` is not `changeme`
- `OAUTH2_SERVER_PUBLIC_BASE_URL` matches the externally visible URL
- `OAUTH2_ALLOWED_ORIGINS` is explicitly set if browsers call the server cross-origin
- database backups and rollback steps are documented
- `/health`, `/ready`, `/metrics`, and `/events/health` are monitored
- OpenTelemetry export is wired if you care about traces

## When to use Flyway

- for Postgres and packaged deployments, use `./scripts/migrate.sh` or the Kubernetes Flyway job
- for the default local SQLite path, startup initialization is usually enough to get moving quickly

## Related pages

- [Quickstart](../getting-started/quickstart.md)
- [Configuration](../getting-started/configuration.md)
- [Observability](observability.md)
- [Runbooks](runbooks.md)
