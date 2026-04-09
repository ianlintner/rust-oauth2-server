# Project Summary - Rust OAuth2 Server

## What this repo is

A Rust + Actix OAuth2/OIDC server assembled from a Cargo workspace.

Core facts:

- `src/main.rs` is a thin delegating binary that calls `oauth2_server::run()`
- default local storage is SQLite
- Postgres is supported through SQLx
- MongoDB is optional behind `--features mongo`
- rate limiting, resilience middleware, and eventing are shipped
- Kustomize overlays are shipped; Helm charts are not

## Canonical docs set

The repository deliberately keeps a smaller docs surface now. The canonical pages are:

- `README.md`
- `docs/index.md`
- `docs/getting-started/quickstart.md`
- `docs/getting-started/configuration.md`
- `docs/usage/oauth2-oidc.md`
- `docs/usage/admin-api.md`
- `docs/usage/integrations.md`
- `docs/operations/deployment.md`
- `docs/operations/observability.md`
- `docs/operations/runbooks.md`
- `docs/development/architecture.md`
- `docs/development/extending.md`
- `docs/development/testing.md`
- `docs/development/contributing.md`

## Source of truth

When docs and assumptions disagree, check these files first:

- `.env.example`
- `application.conf.example`
- `crates/oauth2-server/src/lib.rs`
- generated Swagger / OpenAPI output
- `mcp-server/src/index.js`

## Behavior that commonly drifts in docs

- refresh-token and password grants exist in code paths but are disabled by default
- Google, Microsoft, GitHub, and Azure social login routes are wired; Okta/Auth0 currently return `503`
- rate limiting is implemented and configurable
- the root route redirects to `/profile`
- admin routes live under `/admin/*` and are protected by `AdminGuard`
- `POST /oauth/introspect` and `POST /oauth/revoke` require client authentication by default (`client_secret_post` or `client_secret_basic`); set `OAUTH2_PUBLIC_INTROSPECTION=true` only for deployments that intentionally expose public introspection
- `POST /events/ingest` requires a bearer token by default (`OAUTH2_EVENTS_INGEST_BEARER_TOKEN`); set `OAUTH2_EVENTS_PUBLIC_INGEST=true` to allow unauthenticated callers (not recommended for production)

## Contributor gate

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --verbose --all-features --locked
```

If you need a longer narrative, use the docs site. This file exists to keep future summaries from drifting into fan fiction.

## Repo-local deep guides

These stay outside the main docs nav on purpose:

- `k8s/README.md`
- `DOCKERHUB.md`
- `mcp-server/README.md`
- `benchmarks/README.md`
- `SECURITY.md`
