
# Rust OAuth2 Server

[![Build Status](https://github.com/ianlintner/rust-oauth2-server/actions/workflows/ci.yml/badge.svg)](https://github.com/ianlintner/rust-oauth2-server/actions/workflows/ci.yml)
<br/>
<p align="center"><img width="256" alt="rustoauth2" src="https://github.com/user-attachments/assets/0a009caa-a37a-4c87-88d3-373229e01e0b" /></p>
<br/>
Self-Hosted OAuth2 and OIDC in Rust with Actix, an admin UI, generated OpenAPI, eventing, and kubernetes-ready deployment assets.

## For AI Agents

This project is fully equipped for AI-assisted development with **Skills**, **Slash Commands**, **MCP Server**, and specialized **Agent Instructions**.

### Quick Start Prompts

> **Setup:** "Set up the rust-oauth2-server locally with SQLite, then register a test client and request an access token"

> **Test Flow:** "Use the oauth2-test-flow skill to verify authorization code + PKCE flow"

> **Deploy:** "Use the deploy-k8s skill to deploy to staging environment"

> **Debug:** "Use the oauth2-debug-token skill to debug this JWT token: eyJ..."

> **Troubleshoot:** "The server is returning 500 errors on token endpoint - help me debug this"

### AI Tooling

**Skills** (`.skills/`) - Reusable AI workflows for complex tasks:
- `oauth2-test-flow` - Test complete OAuth2 flows
- `oauth2-register-client` - Register new OAuth2 clients
- `oauth2-debug-token` - Debug JWT token issues
- `rfc-compliance-check` - Verify RFC compliance
- `db-migration` - Create database migrations
- `deploy-k8s` - Deploy to Kubernetes
- `add-endpoint` - Add new HTTP endpoints

**Slash Commands** (`.claude/commands/`) - Quick access to common operations:
- `/test` - Run tests with filters
- `/ci` - Run CI gate checks
- `/deploy` - Deploy to environment
- `/rfc` - Check RFC compliance
- `/security` - Run security scans
- `/migrate` - Create migration
- `/docs` - Generate documentation
- `/benchmark` - Run performance tests

**MCP Server** (`mcp-server/`) - OAuth2 operations via Model Context Protocol:
- Token operations (get, exchange, refresh, introspect, revoke)
- Client registration
- Server health and metrics
- OIDC discovery

**Agent Instructions** (`.github/agents/`) - Specialized domain expertise:
- `development.md` - Coding guidelines and patterns
- `operations.md` - Deployment and ops procedures
- `database.md` - Database management
- `security.md` - Security best practices

### Core Documentation

- [`CLAUDE.md`](CLAUDE.md) - **Start here**: Agent memory, behavioral guidelines, and project context
- [`AGENTIC_QUICKSTART.md`](AGENTIC_QUICKSTART.md) - Quick start for AI-assisted development
- [`docs/AI_TOOLING_ENHANCEMENTS.md`](docs/AI_TOOLING_ENHANCEMENTS.md) - AI tooling enhancement plan
- [`.github/copilot-instructions.md`](.github/copilot-instructions.md) - Copilot-specific instructions

## Start in 60 seconds

```bash
cp .env.example .env
# set OAUTH2_JWT_SECRET, OAUTH2_SESSION_KEY, and OAUTH2_SEED_PASSWORD
cargo run
```

Then open:

- app: `http://localhost:8080`
- login: `http://localhost:8080/auth/login`
- admin: `http://localhost:8080/admin`
- Swagger UI: `http://localhost:8080/swagger-ui`

The default local path uses SQLite. If you want Postgres plus the supporting services, use `docker compose up -d` instead.

## What actually ships

- OAuth2: Authorization Code + PKCE, Client Credentials, introspection, revocation
- OIDC: discovery, JWKS, UserInfo
- Admin surface: HTML dashboard plus JSON admin API
- Operations: `/health`, `/ready`, `/metrics`, OpenTelemetry export
- Runtime controls: rate limiting, eventing, resilience middleware, Redis-backed distributed profile
- Deployment assets: Docker, Docker Compose, Kustomize overlays under `k8s/`

Important reality checks:

- refresh-token and password grants are present in code paths but disabled by default
- Google, Microsoft, GitHub, and Azure login flows are wired; `/auth/login/azure` prefers `OAUTH2_AZURE_*` config and falls back to Microsoft if unset; Okta/Auth0 currently return `503`
- the repo ships Kustomize manifests, not Helm charts

## Docs by job

- run it locally: [`docs/getting-started/quickstart.md`](docs/getting-started/quickstart.md)
- configure it: [`docs/getting-started/configuration.md`](docs/getting-started/configuration.md)
- integrate a client: [`docs/usage/oauth2-oidc.md`](docs/usage/oauth2-oidc.md)
- manage/administer it: [`docs/usage/admin-api.md`](docs/usage/admin-api.md)
- deploy and operate it: [`docs/operations/deployment.md`](docs/operations/deployment.md), [`docs/operations/observability.md`](docs/operations/observability.md), [`docs/operations/runbooks.md`](docs/operations/runbooks.md)
- extend the workspace: [`docs/development/architecture.md`](docs/development/architecture.md), [`docs/development/extending.md`](docs/development/extending.md)
- contribute safely: [`docs/development/testing.md`](docs/development/testing.md), [`docs/development/contributing.md`](docs/development/contributing.md)

Deep repo-local guides intentionally live outside the docs-site nav:

- Kubernetes: [`k8s/README.md`](k8s/README.md)
- prebuilt container image: [`DOCKERHUB.md`](DOCKERHUB.md)
- MCP wrapper: [`mcp-server/README.md`](mcp-server/README.md)
- benchmark harness: [`benchmarks/README.md`](benchmarks/README.md)

## Workspace shape

The server is a Cargo workspace, not a single monolith:

- `crates/oauth2-core` — domain types
- `crates/oauth2-ports` — storage/integration traits
- `crates/oauth2-actix` — handlers, middleware, actors
- `crates/oauth2-server` — runtime assembly and route wiring
- `crates/oauth2-events` / `oauth2-ratelimit` / `oauth2-resilience` — operational behavior
- `mcp-server/` — separate Node.js MCP wrapper

If you are changing behavior, the main source-of-truth files are:

- `.env.example`
- `application.conf.example`
- `crates/oauth2-server/src/lib.rs`
- `mcp-server/src/index.js`

## Contributor gate

Before considering any change done, run the same local gates CI expects:

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --verbose --all-features --locked
```

If you changed docs, also run:

```bash
python3 -m mkdocs build --strict
```

