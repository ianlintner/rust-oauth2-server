# Quick Start Guide for Agentic AI Development

This guide helps you get started with the OAuth2 Server in an AI-assisted development environment with GitHub Copilot and other AI agents.

## Overview

The OAuth2 Server project is fully equipped for modern agentic AI development with:

- 💡 **Skills** (`.skills/`) - 7 reusable AI workflows for complex tasks
- ⚡ **Slash Commands** (`.claude/commands/`) - 8 quick-access operations
- 🤖 **MCP Server** (`mcp-server/`) - OAuth2 operations via Model Context Protocol
- 📚 **Agent Instructions** (`.github/agents/`) - 9 specialized domain guides
- 🧠 **Agent Memory** (`CLAUDE.md`) - Behavioral guidelines and project context
- ☸️ **Kubernetes** manifests for production deployment
- 🔄 **CI/CD** with E2E testing
- 📖 **Comprehensive Documentation** with runbooks

## For AI Assistants

### Skills - Reusable AI Workflows

**Location**: `.skills/` directory

Skills are structured prompts for complex, multi-step tasks.

**Available Skills:**
- **oauth2-test-flow** - Test OAuth2 flows end-to-end
- **oauth2-register-client** - Register OAuth2 clients
- **oauth2-debug-token** - Debug JWT token issues
- **rfc-compliance-check** - Verify RFC compliance
- **db-migration** - Create database migrations
- **deploy-k8s** - Deploy to Kubernetes
- **add-endpoint** - Add new HTTP endpoints

**Usage**: `"Use the oauth2-test-flow skill to test authorization code + PKCE"`

### Slash Commands - Quick Operations

**Location**: `.claude/commands/` directory

**Available Commands:**
- `/test` - Run tests with filters
- `/ci` - Run CI gate checks
- `/deploy` - Deploy to environment
- `/rfc` - Check RFC compliance
- `/security` - Run security scans
- `/migrate` - Create migration
- `/docs` - Generate documentation
- `/benchmark` - Run benchmarks

### Agent Instructions - Specialized Expertise

**Location**: `.github/agents/` directory

1. **Development** ([`development.md`](.github/agents/development.md)) - Coding guidelines
2. **Operations** ([`operations.md`](.github/agents/operations.md)) - Deployment procedures
3. **Database** ([`database.md`](.github/agents/database.md)) - Database operations
4. **Security** ([`security.md`](.github/agents/security.md)) - Security practices
5. **Maintainer Agents** - Autonomous maintenance (caretaker integration)

### MCP Server - OAuth2 Operations

**Location**: `mcp-server/` directory

**Setup:**
```bash
cd mcp-server
npm install
cp .env.example .env
npm start
```

**Tools**: Token operations, client registration, health/metrics, OIDC discovery

See [`mcp-server/README.md`](mcp-server/README.md) for configuration.

### Agent Memory - CLAUDE.md

**Location**: `CLAUDE.md` (root directory)

**Read this first** - Contains behavioral guidelines, project context, RFC compliance, common pitfalls, and CI requirements.

## For Developers

### First Time Setup

1. **Clone and Build**

   ```bash
   git clone https://github.com/ianlintner/rust_oauth2_server.git
   cd rust_oauth2_server
   cargo build
   ```

2. **Run Database Migrations**

   ```bash
   ./scripts/migrate.sh
   ```

3. **Start the Server**

   ```bash
   export OAUTH2_JWT_SECRET="your-secret-key-at-least-32-characters-long"
   cargo run
   ```

4. **Verify Installation**
   ```bash
   curl http://localhost:8080/health
   ```

### Development Workflow

1. **Create a Feature Branch**

   ```bash
   git checkout -b feature/my-feature
   ```

2. **Make Changes**
   - Follow guidelines in [Development Agent](.github/agents/development.md)
   - Use AI assistance for coding patterns
   - Run tests frequently: `cargo test`

3. **Lint and Format**

   ```bash
   cargo fmt
   cargo clippy
   ```

4. **Commit and Push**

   ```bash
   git add .
   git commit -m "Description of changes"
   git push origin feature/my-feature
   ```

5. **Create Pull Request**
   - CI/CD will run automatically
   - E2E tests validate K8s deployments
   - Security scans check for vulnerabilities

## For Operations

### Local Testing with K8s

For repeatable end-to-end testing that matches CI (KIND + Postgres + Flyway + real HTTP calls), use the script:

```bash
./scripts/e2e_kind.sh
```

Notes:

- Uses `kubectl port-forward` to avoid host port conflicts.
- Builds the container image via `Dockerfile` (Linux build) so it works on macOS.
- Cleans up the namespace and cluster by default (set `--keep-cluster` / `--keep-namespace` to debug).

1. **Install KIND**

   ```bash
   curl -Lo ./kind https://kind.sigs.k8s.io/dl/v0.20.0/kind-linux-amd64
   chmod +x ./kind
   sudo mv ./kind /usr/local/bin/kind
   ```

2. **Create Cluster**

   ```bash
   kind create cluster --name oauth2-test
   ```

3. **Build and Load Image**

   ```bash
   docker build -t docker.io/ianlintner068/oauth2-server:test .
   kind load docker-image docker.io/ianlintner068/oauth2-server:test --name oauth2-test
   ```

4. **Deploy**

   ```bash
   kubectl apply -k k8s/base
   ```

5. **Test**
   ```bash
   kubectl port-forward -n oauth2-server svc/oauth2-server 8080:80
   curl http://localhost:8080/health
   ```

### Production Deployment

See [Kubernetes README](k8s/README.md) and [Operations Runbooks](docs/operations/runbooks.md).

## Common Tasks

### Register a New OAuth2 Client

**Using API:**

```bash
curl -X POST http://localhost:8080/admin/clients/register \
  -H "Content-Type: application/json" \
  -b "session_cookie=YOUR_ADMIN_SESSION" \
  -d '{
    "client_name": "My Application",
    "redirect_uris": ["http://localhost:3000/callback"],
    "grant_types": ["authorization_code", "refresh_token"],
    "scope": "read write"
  }'
```

**Using MCP Server (via AI):**

> "Register a new OAuth2 client called 'My Application' with redirect URI http://localhost:3000/callback"

### Get Access Token

**Using API:**

```bash
curl -X POST http://localhost:8080/oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&client_id=CLIENT_ID&client_secret=CLIENT_SECRET&scope=read"
```

**Using MCP Server (via AI):**

> "Get an access token for client ID abc123 with scope read"

### Check Server Health

**Using API:**

```bash
curl http://localhost:8080/health | jq
curl http://localhost:8080/metrics
```

**Using MCP Server (via AI):**

> "Check the health status of the OAuth2 server"

**Using K8s:**

```bash
kubectl get pods -n oauth2-server
kubectl logs -f deployment/oauth2-server -n oauth2-server
```

### Deploy to Kubernetes

**Development:**

```bash
kubectl apply -k k8s/overlays/dev
```

**Staging:**

```bash
kubectl apply -k k8s/overlays/staging
```

**Production:**

```bash
kubectl apply -k k8s/overlays/production
```

## Project Structure

```
rust_oauth2_server/
├── .github/
│   ├── agents/              # Agent instruction files
│   │   ├── development.md   # Development guidelines
│   │   ├── operations.md    # Operations procedures
│   │   ├── database.md      # Database operations
│   │   └── security.md      # Security practices
│   └── workflows/           # CI/CD pipelines
│       ├── ci.yml           # Main CI pipeline
│       └── e2e-kind.yml     # E2E tests with KIND
├── docs/                    # Documentation
│   ├── api/                 # API reference
│   ├── architecture/        # Architecture docs
│   ├── flows/               # OAuth2 flow guides
│   ├── getting-started/     # Getting started guides
│   ├── deployment/          # Deployment guides
│   └── operations/          # Operational runbooks
├── k8s/                     # Kubernetes manifests
│   ├── base/                # Base resources
│   └── overlays/            # Environment-specific overlays
│       ├── dev/
│       ├── staging/
│       └── production/
├── mcp-server/              # MCP server for AI integration
│   ├── src/
│   │   └── index.js         # Main MCP server
│   ├── package.json
│   └── README.md
├── migrations/              # Database migrations
│   └── sql/                 # Flyway SQL migrations
├── src/                     # Rust source code
│   ├── actors/              # Actor implementations
│   ├── handlers/            # HTTP handlers
│   ├── models/              # Data models
│   ├── services/            # Business logic
│   └── main.rs              # Entry point
├── tests/                   # Tests
│   ├── features/            # BDD feature files
│   ├── bdd.rs               # BDD test runner
│   └── integration.rs       # Integration tests
├── Cargo.toml               # Rust dependencies
├── Dockerfile               # Container image
├── docker-compose.yml       # Docker Compose config
└── README.md                # Main documentation
```

## Troubleshooting

### Build Errors

```bash
# Clean and rebuild
cargo clean
cargo build

# Update dependencies
cargo update
```

### Database Connection Issues

```bash
# Check database URL
echo $OAUTH2_DATABASE_URL

# Test connection (PostgreSQL)
psql $OAUTH2_DATABASE_URL -c "SELECT 1;"

# Run migrations
./scripts/migrate.sh
```

### K8s Deployment Issues

```bash
# Check pod status
kubectl get pods -n oauth2-server
kubectl describe pod <pod-name> -n oauth2-server

# Check logs
kubectl logs -f deployment/oauth2-server -n oauth2-server

# Check events
kubectl get events -n oauth2-server --sort-by='.lastTimestamp'
```

### MCP Server Issues

```bash
# Check configuration
cat mcp-server/.env

# Test server URL
curl $OAUTH2_BASE_URL/health

# Check MCP server logs
npm start
```

## Resources

### Documentation

- [Main README](README.md) - Project overview
- [Quickstart](docs/getting-started/quickstart.md) - Fastest local setup path
- [OAuth & OIDC](docs/usage/oauth2-oidc.md) - Client integration reference
- [K8s Guide](k8s/README.md) - Kubernetes deployment
- [MCP Server](mcp-server/README.md) - AI integration
- [Runbooks](docs/operations/runbooks.md) - Operational procedures

### Agent Instructions

- [Development](.github/agents/development.md) - Coding guidelines
- [Operations](.github/agents/operations.md) - Deployment & ops
- [Database](.github/agents/database.md) - Database management
- [Security](.github/agents/security.md) - Security best practices

### External Resources

- [OAuth 2.0 RFC 6749](https://tools.ietf.org/html/rfc6749)
- [Rust Documentation](https://doc.rust-lang.org/)
- [Actix Web](https://actix.rs/)
- [Kubernetes](https://kubernetes.io/docs/)
- [Model Context Protocol](https://modelcontextprotocol.io/)

## Getting Help

1. **Documentation**: Check the `docs/` directory
2. **Agent Instructions**: Reference specialized agent guides
3. **Runbooks**: Follow step-by-step procedures
4. **Issues**: Create a GitHub issue
5. **Discussions**: Use GitHub Discussions
6. **Security**: See [SECURITY.md](SECURITY.md)

## Contributing

See [Development Agent](.github/agents/development.md) for:

- Coding standards
- Testing guidelines
- Pull request process
- Code review checklist

---

**Ready to get started?** Pick a task from the list above and use the appropriate agent instructions for guidance!
