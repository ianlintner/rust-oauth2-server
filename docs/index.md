# Rust OAuth2 Server

<div class="hero" markdown>

# Self-hosted OAuth2 and OIDC without the docs maze

Run it locally, deploy it with Docker or Kubernetes, inspect it with metrics and traces, and extend it as a real Cargo workspace instead of reverse-engineering a README novella.

[Run locally](getting-started/quickstart.md){ .md-button .md-button--primary }
[Deploy it](operations/deployment.md){ .md-button }
[Extend it](development/extending.md){ .md-button }

</div>

## For AI Agents

If you're an AI assistant helping a user with this OAuth2 server, here are common tasks phrased as natural language prompts:

| User Need | Example Prompt |
|-----------|----------------|
| **First-time setup** | "Set up rust-oauth2-server locally using SQLite, create the admin user, and verify it's working" |
| **Client registration** | "Register a new OAuth2 client with redirect URI http://localhost:3000/callback and authorization_code grant" |
| **Token requests** | "Get an access token using client credentials grant for client ID abc123" |
| **Kubernetes deployment** | "Deploy the OAuth2 server to Kubernetes using the production overlay with PostgreSQL" |
| **Debugging** | "The /oauth/token endpoint is returning errors - check logs and configuration" |
| **Integration** | "Help me integrate this OAuth2 server with my React app using PKCE flow" |
| **Add features** | "Add a new OAuth2 scope called 'admin:write' and update the authorization logic" |

**Key agent resources:**
- [CLAUDE.md](https://github.com/ianlintner/rust-oauth2-server/blob/main/CLAUDE.md) - Complete agent memory file
- [AGENTIC_QUICKSTART.md](https://github.com/ianlintner/rust-oauth2-server/blob/main/AGENTIC_QUICKSTART.md) - Agent-focused quickstart
- [.github/agents/](https://github.com/ianlintner/rust-oauth2-server/tree/main/.github/agents) - Specialized agent instructions

## Start with the job you have today

<div class="grid cards" markdown>

- **Run it locally**

---

Start the server with SQLite and `cargo run`, then log in as the seeded admin user.

[Quickstart](getting-started/quickstart.md)

- **Integrate a client**

---

Use Authorization Code + PKCE, Client Credentials, discovery, JWKS, and UserInfo without guesswork.

[OAuth & OIDC](usage/oauth2-oidc.md)

- **Operate it**

---

Use the health, readiness, metrics, and eventing endpoints that are actually wired in code.

[Observability](operations/observability.md)

- **Change the system**

---

Follow the workspace layout, feature flags, test matrix, and extension seams.

[Architecture](development/architecture.md)

</div>

## What ships today

| Area                    | Current state                                                           | Notes                                                                                          |
| ----------------------- | ----------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------- |
| OAuth2 flows            | <span class="status-pill status-pill--good">Shipped</span>              | Authorization Code + PKCE, Client Credentials, introspection, revocation                       |
| OIDC surface            | <span class="status-pill status-pill--good">Shipped</span>              | Discovery, JWKS, UserInfo                                                                      |
| Admin UI and JSON API   | <span class="status-pill status-pill--good">Shipped</span>              | Admin session required                                                                         |
| Eventing                | <span class="status-pill status-pill--good">Shipped</span>              | In-memory and console at runtime; broker backends are feature-gated                            |
| Distributed runtime     | <span class="status-pill status-pill--warn">Feature-gated</span>        | Build with `--features distributed`                                                            |
| Social login            | <span class="status-pill status-pill--warn">Mixed</span>                | Google, Microsoft, GitHub ship; `/auth/login/azure` aliases Microsoft; Okta/Auth0 return `503` |
| Refresh/password grants | <span class="status-pill status-pill--muted">Disabled by default</span> | Present in code paths, intentionally rejected by default                                       |

## Source of truth

To keep this site short and keep drift down, treat these files as canonical:

- API shapes: `/swagger-ui` and `/api-docs/openapi.json`
- runtime config keys: `.env.example` and `application.conf.example`
- route registration and actual behavior: `crates/oauth2-server/src/lib.rs`
- Kubernetes topology: `k8s/`
- performance results: `benchmarks/results/comparison-report.md`
- MCP tool surface: `mcp-server/src/index.js`

## If you only read four pages

1. [Quickstart](getting-started/quickstart.md)
2. [Configuration](getting-started/configuration.md)
3. [Admin & API](usage/admin-api.md)
4. [Deployment](operations/deployment.md)

That gets most users from clone to working deployment without spelunking.

## Need the repo-local deep guides?

Use these when you want the implementation-adjacent detail without stuffing the docs nav with specialist pages:

- [Kubernetes manifests and overlays](https://github.com/ianlintner/rust-oauth2-server/blob/main/k8s/README.md)
- [Prebuilt Docker image guide](https://github.com/ianlintner/rust-oauth2-server/blob/main/DOCKERHUB.md)
- [MCP server guide](https://github.com/ianlintner/rust-oauth2-server/blob/main/mcp-server/README.md)
- [Benchmark harness](https://github.com/ianlintner/rust-oauth2-server/blob/main/benchmarks/README.md)
