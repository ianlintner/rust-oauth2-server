# Configuration Guide

This comprehensive guide covers all configuration options available for the Rust OAuth2 Server.

## Configuration Methods

The server supports multiple configuration methods:

1. **Environment Variables** (Recommended for production)
2. **`.env` File** (Recommended for development)
3. **Configuration File** (Alternative method)

## Environment Variables

All configuration options can be set via environment variables with the `OAUTH2_` prefix.

### Server Configuration

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `OAUTH2_SERVER_HOST` | String | `127.0.0.1` | Server bind address |
| `OAUTH2_SERVER_PORT` | Integer | `8080` | Server port |
| `OAUTH2_SERVER_WORKERS` | Integer | CPU cores | Number of worker threads |

**Example:**
```bash
export OAUTH2_SERVER_HOST=0.0.0.0
export OAUTH2_SERVER_PORT=8080
export OAUTH2_SERVER_WORKERS=4
```

### Database Configuration

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `OAUTH2_DATABASE_URL` | String | `sqlite:oauth2.db` | Database connection URL |
| `OAUTH2_DATABASE_MAX_CONNECTIONS` | Integer | `10` | Maximum database connections |
| `OAUTH2_DATABASE_MIN_CONNECTIONS` | Integer | `1` | Minimum database connections |
| `OAUTH2_DATABASE_CONNECT_TIMEOUT` | Integer | `30` | Connection timeout (seconds) |

**Supported Databases:**

=== "SQLite"
    ```bash
    export OAUTH2_DATABASE_URL=sqlite:oauth2.db
    # Or with absolute path
    export OAUTH2_DATABASE_URL=sqlite:/path/to/oauth2.db
    ```

=== "PostgreSQL"
    ```bash
    export OAUTH2_DATABASE_URL=postgresql://username:password@localhost:5432/oauth2_db
    # With SSL
    export OAUTH2_DATABASE_URL=postgresql://username:password@localhost:5432/oauth2_db?sslmode=require
    ```

### JWT Configuration

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `OAUTH2_JWT_SECRET` | String | **Required** | Secret key for signing JWT tokens |
| `OAUTH2_JWT_ALGORITHM` | String | `HS256` | JWT signing algorithm |
| `OAUTH2_JWT_ISSUER` | String | `rust_oauth2_server` | Token issuer identifier |

!!! danger "Security Critical"
    The `OAUTH2_JWT_SECRET` must be:
    - At least 32 characters long (64+ recommended)
    - Cryptographically random
    - Kept secret and never committed to version control
    - Rotated periodically in production

**Generating a secure JWT secret:**
```bash
# Using openssl
openssl rand -hex 32

# Using /dev/urandom
cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 64 | head -n 1
```

**Example:**
```bash
export OAUTH2_JWT_SECRET="a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6"
```

### Token Expiration

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `OAUTH2_ACCESS_TOKEN_EXPIRATION` | Integer | `3600` | Access token lifetime (seconds) |
| `OAUTH2_REFRESH_TOKEN_EXPIRATION` | Integer | `2592000` | Refresh token lifetime (seconds, 30 days) |
| `OAUTH2_AUTHORIZATION_CODE_EXPIRATION` | Integer | `600` | Authorization code lifetime (seconds, 10 minutes) |

**Example:**
```bash
# Access token valid for 1 hour
export OAUTH2_ACCESS_TOKEN_EXPIRATION=3600

# Refresh token valid for 30 days
export OAUTH2_REFRESH_TOKEN_EXPIRATION=2592000

# Authorization code valid for 10 minutes
export OAUTH2_AUTHORIZATION_CODE_EXPIRATION=600
```

### Session Configuration

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `OAUTH2_SESSION_KEY` | String | Auto-generated | Session encryption key (min 64 chars) |
| `OAUTH2_SESSION_TIMEOUT` | Integer | `3600` | Session timeout (seconds) |
| `OAUTH2_SESSION_SECURE` | Boolean | `false` | Require HTTPS for cookies |

!!! warning "Production Requirement"
    In production, `OAUTH2_SESSION_KEY` must be set to a persistent value. Auto-generated keys will invalidate all sessions on server restart.

**Example:**
```bash
export OAUTH2_SESSION_KEY="your-persistent-session-key-at-least-64-characters-long-abc123"
export OAUTH2_SESSION_TIMEOUT=7200
export OAUTH2_SESSION_SECURE=true
```

### Social Login Configuration

#### Google OAuth2

| Variable | Type | Required | Description |
|----------|------|----------|-------------|
| `OAUTH2_GOOGLE_CLIENT_ID` | String | Yes | Google OAuth2 client ID |
| `OAUTH2_GOOGLE_CLIENT_SECRET` | String | Yes | Google OAuth2 client secret |
| `OAUTH2_GOOGLE_REDIRECT_URI` | String | Yes | Callback URL for Google |

#### Microsoft/Azure AD

| Variable | Type | Required | Description |
|----------|------|----------|-------------|
| `OAUTH2_MICROSOFT_CLIENT_ID` | String | Yes | Microsoft client ID |
| `OAUTH2_MICROSOFT_CLIENT_SECRET` | String | Yes | Microsoft client secret |
| `OAUTH2_MICROSOFT_REDIRECT_URI` | String | Yes | Callback URL for Microsoft |
| `OAUTH2_MICROSOFT_TENANT_ID` | String | No | Azure AD tenant ID (default: `common`) |

#### GitHub

| Variable | Type | Required | Description |
|----------|------|----------|-------------|
| `OAUTH2_GITHUB_CLIENT_ID` | String | Yes | GitHub OAuth app client ID |
| `OAUTH2_GITHUB_CLIENT_SECRET` | String | Yes | GitHub OAuth app client secret |
| `OAUTH2_GITHUB_REDIRECT_URI` | String | Yes | Callback URL for GitHub |

#### Okta

| Variable | Type | Required | Description |
|----------|------|----------|-------------|
| `OAUTH2_OKTA_CLIENT_ID` | String | Yes | Okta client ID |
| `OAUTH2_OKTA_CLIENT_SECRET` | String | Yes | Okta client secret |
| `OAUTH2_OKTA_REDIRECT_URI` | String | Yes | Callback URL for Okta |
| `OAUTH2_OKTA_DOMAIN` | String | Yes | Okta domain (e.g., dev-123.okta.com) |

#### Auth0

| Variable | Type | Required | Description |
|----------|------|----------|-------------|
| `OAUTH2_AUTH0_CLIENT_ID` | String | Yes | Auth0 client ID |
| `OAUTH2_AUTH0_CLIENT_SECRET` | String | Yes | Auth0 client secret |
| `OAUTH2_AUTH0_REDIRECT_URI` | String | Yes | Callback URL for Auth0 |
| `OAUTH2_AUTH0_DOMAIN` | String | Yes | Auth0 domain (e.g., tenant.auth0.com) |

**Complete Social Login Example:**
```bash
# Google
export OAUTH2_GOOGLE_CLIENT_ID="123456-abc.apps.googleusercontent.com"
export OAUTH2_GOOGLE_CLIENT_SECRET="GOCSPX-abc123def456"
export OAUTH2_GOOGLE_REDIRECT_URI="http://localhost:8080/auth/callback/google"

# Microsoft
export OAUTH2_MICROSOFT_CLIENT_ID="12345678-1234-1234-1234-123456789abc"
export OAUTH2_MICROSOFT_CLIENT_SECRET="abc~123.def456"
export OAUTH2_MICROSOFT_REDIRECT_URI="http://localhost:8080/auth/callback/microsoft"
export OAUTH2_MICROSOFT_TENANT_ID="common"

# GitHub
export OAUTH2_GITHUB_CLIENT_ID="Iv1.a1b2c3d4e5f6g7h8"
export OAUTH2_GITHUB_CLIENT_SECRET="1a2b3c4d5e6f7g8h9i0j1k2l3m4n5o6p7q8r9s0t"
export OAUTH2_GITHUB_REDIRECT_URI="http://localhost:8080/auth/callback/github"
```

See [Social Login Setup Guide](social-login-setup.md) for detailed provider configuration.

### OpenTelemetry Configuration

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `OAUTH2_OTLP_ENDPOINT` | String | `http://localhost:4317` | OTLP gRPC endpoint |
| `OAUTH2_OTLP_PROTOCOL` | String | `grpc` | Protocol (grpc or http/protobuf) |
| `OAUTH2_OTLP_TRACES_ENABLED` | Boolean | `true` | Enable trace export |
| `OAUTH2_OTLP_METRICS_ENABLED` | Boolean | `true` | Enable metrics export |

**Example:**
```bash
export OAUTH2_OTLP_ENDPOINT=http://jaeger:4317
export OAUTH2_OTLP_PROTOCOL=grpc
export OAUTH2_OTLP_TRACES_ENABLED=true
```

### Logging Configuration

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `RUST_LOG` | String | `info` | Log level filter |
| `OAUTH2_LOG_FORMAT` | String | `json` | Log format (json or pretty) |

**Log Levels:**
- `error` - Error messages only
- `warn` - Warnings and errors
- `info` - Informational messages (recommended)
- `debug` - Debug information
- `trace` - Very verbose logging

**Example:**
```bash
# Production: JSON formatted info logs
export RUST_LOG=info
export OAUTH2_LOG_FORMAT=json

# Development: Pretty printed debug logs
export RUST_LOG=debug,sqlx=warn
export OAUTH2_LOG_FORMAT=pretty
```

### CORS Configuration

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `OAUTH2_CORS_ALLOWED_ORIGINS` | String | `*` | Comma-separated list of allowed origins |
| `OAUTH2_CORS_ALLOWED_METHODS` | String | `GET,POST,PUT,DELETE,OPTIONS` | Allowed HTTP methods |
| `OAUTH2_CORS_ALLOWED_HEADERS` | String | `*` | Allowed headers |
| `OAUTH2_CORS_MAX_AGE` | Integer | `3600` | Preflight cache duration (seconds) |

**Example:**
```bash
export OAUTH2_CORS_ALLOWED_ORIGINS="https://app.example.com,https://admin.example.com"
export OAUTH2_CORS_ALLOWED_METHODS="GET,POST,OPTIONS"
export OAUTH2_CORS_MAX_AGE=7200
```

## Configuration File Example

Create a complete `.env` file for your environment:

### Development Configuration

```bash
# .env.development
# Server
OAUTH2_SERVER_HOST=127.0.0.1
OAUTH2_SERVER_PORT=8080

# Database
OAUTH2_DATABASE_URL=sqlite:oauth2.db

# JWT
OAUTH2_JWT_SECRET=dev-secret-key-change-in-production-minimum-32-chars

# Session
OAUTH2_SESSION_KEY=dev-session-key-must-be-at-least-64-characters-for-security-123456

# Tokens
OAUTH2_ACCESS_TOKEN_EXPIRATION=3600
OAUTH2_REFRESH_TOKEN_EXPIRATION=2592000

# Logging
RUST_LOG=debug,sqlx=warn
OAUTH2_LOG_FORMAT=pretty

# OpenTelemetry
OAUTH2_OTLP_ENDPOINT=http://localhost:4317
```

### Production Configuration

```bash
# .env.production
# Server
OAUTH2_SERVER_HOST=0.0.0.0
OAUTH2_SERVER_PORT=8080
OAUTH2_SERVER_WORKERS=8

# Database (PostgreSQL)
OAUTH2_DATABASE_URL=postgresql://oauth2_user:strong_password@postgres:5432/oauth2_db?sslmode=require
OAUTH2_DATABASE_MAX_CONNECTIONS=20
OAUTH2_DATABASE_MIN_CONNECTIONS=5

# JWT (Use secret management service)
OAUTH2_JWT_SECRET=${SECRET_JWT_KEY}

# Session (Use secret management service)
OAUTH2_SESSION_KEY=${SECRET_SESSION_KEY}
OAUTH2_SESSION_TIMEOUT=7200
OAUTH2_SESSION_SECURE=true

# Tokens
OAUTH2_ACCESS_TOKEN_EXPIRATION=1800
OAUTH2_REFRESH_TOKEN_EXPIRATION=604800

# Logging
RUST_LOG=info,actix_web=warn
OAUTH2_LOG_FORMAT=json

# OpenTelemetry
OAUTH2_OTLP_ENDPOINT=http://otel-collector:4317

# CORS
OAUTH2_CORS_ALLOWED_ORIGINS=https://app.example.com,https://admin.example.com
OAUTH2_CORS_MAX_AGE=7200

# Social Login (from secret management)
OAUTH2_GOOGLE_CLIENT_ID=${SECRET_GOOGLE_CLIENT_ID}
OAUTH2_GOOGLE_CLIENT_SECRET=${SECRET_GOOGLE_CLIENT_SECRET}
OAUTH2_GOOGLE_REDIRECT_URI=https://oauth.example.com/auth/callback/google
```

## Docker Configuration

### Using Environment Variables

```yaml
# docker-compose.yml
version: '3.8'

services:
  oauth2_server:
    image: rust_oauth2_server:latest
    ports:
      - "8080:8080"
    environment:
      OAUTH2_SERVER_HOST: 0.0.0.0
      OAUTH2_SERVER_PORT: 8080
      OAUTH2_DATABASE_URL: postgresql://oauth2:password@postgres:5432/oauth2_db
      OAUTH2_JWT_SECRET: ${JWT_SECRET}
      OAUTH2_SESSION_KEY: ${SESSION_KEY}
    depends_on:
      - postgres
  
  postgres:
    image: postgres:16-alpine
    environment:
      POSTGRES_DB: oauth2_db
      POSTGRES_USER: oauth2
      POSTGRES_PASSWORD: password
    volumes:
      - postgres_data:/var/lib/postgresql/data

volumes:
  postgres_data:
```

### Using .env File

```yaml
# docker-compose.yml
version: '3.8'

services:
  oauth2_server:
    image: rust_oauth2_server:latest
    ports:
      - "8080:8080"
    env_file:
      - .env.production
```

## Kubernetes Configuration

### ConfigMap

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: oauth2-config
data:
  OAUTH2_SERVER_HOST: "0.0.0.0"
  OAUTH2_SERVER_PORT: "8080"
  OAUTH2_DATABASE_URL: "postgresql://oauth2:password@postgres:5432/oauth2_db"
  OAUTH2_LOG_FORMAT: "json"
  RUST_LOG: "info"
```

### Secret

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: oauth2-secrets
type: Opaque
stringData:
  OAUTH2_JWT_SECRET: "your-jwt-secret-here"
  OAUTH2_SESSION_KEY: "your-session-key-here"
  OAUTH2_GOOGLE_CLIENT_SECRET: "google-secret-here"
```

### Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: oauth2-server
spec:
  replicas: 3
  template:
    spec:
      containers:
      - name: oauth2-server
        image: rust_oauth2_server:latest
        envFrom:
        - configMapRef:
            name: oauth2-config
        - secretRef:
            name: oauth2-secrets
        ports:
        - containerPort: 8080
```

## Configuration Validation

The server validates critical configuration at startup:

### Production Checklist

The server warns if production requirements aren't met:

- ✅ JWT secret is at least 32 characters
- ✅ Session key is at least 64 characters
- ✅ Database URL is configured
- ✅ HTTPS is enabled for sessions (in production)
- ✅ Secure cookie settings are enabled

**View validation results:**
```bash
# Start server and check logs
cargo run 2>&1 | grep -i "configuration\|warning"
```

## Advanced Configuration

### Custom Token Claims

Customize JWT token claims by modifying the configuration:

```bash
export OAUTH2_JWT_ISSUER=https://oauth.example.com
export OAUTH2_JWT_AUDIENCE=https://api.example.com
```

### Database Connection Pooling

Fine-tune database performance:

```bash
export OAUTH2_DATABASE_MAX_CONNECTIONS=50
export OAUTH2_DATABASE_MIN_CONNECTIONS=10
export OAUTH2_DATABASE_CONNECT_TIMEOUT=30
export OAUTH2_DATABASE_IDLE_TIMEOUT=600
```

### Rate Limiting (Planned)

```bash
export OAUTH2_RATE_LIMIT_ENABLED=true
export OAUTH2_RATE_LIMIT_REQUESTS_PER_MINUTE=60
export OAUTH2_RATE_LIMIT_BURST=10
```

## Troubleshooting

### Configuration Not Loading

1. Check environment variable names (must start with `OAUTH2_`)
2. Verify `.env` file is in the correct directory
3. Check for syntax errors in `.env` file
4. Ensure no spaces around `=` in `.env` file

### Database Connection Failures

1. Verify database URL format
2. Check network connectivity
3. Verify credentials
4. Check firewall rules

### JWT Token Issues

1. Ensure JWT secret is set and long enough
2. Verify secret hasn't changed (invalidates existing tokens)
3. Check token expiration settings

## Best Practices

1. **Never commit secrets to version control**
   - Use `.gitignore` for `.env` files
   - Use secret management services in production

2. **Use strong secrets**
   - Generate cryptographically random secrets
   - Use minimum recommended lengths
   - Rotate secrets periodically

3. **Environment-specific configuration**
   - Separate dev, staging, and production configs
   - Use different secrets for each environment
   - Document required variables

4. **Database configuration**
   - Use PostgreSQL in production
   - Configure appropriate connection pools
   - Enable SSL for database connections

5. **Monitoring and logging**
   - Use JSON logs in production
   - Configure appropriate log levels
   - Enable OpenTelemetry tracing

## Next Steps

- [Quick Start Guide](quickstart.md) - Start using the OAuth2 server
- [Social Login Setup](social-login-setup.md) - Configure social providers
- [Production Deployment](../deployment/production.md) - Deploy to production
- [Security Best Practices](../deployment/production.md#security) - Secure your deployment
