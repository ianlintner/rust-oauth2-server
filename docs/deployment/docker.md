# Docker Deployment

This guide covers deploying the Rust OAuth2 Server using Docker and Docker Compose.

## Quick Start

The fastest way to get started with Docker:

```bash
# Clone the repository
git clone https://github.com/ianlintner/rust_oauth2.git
cd rust_oauth2

# Start with Docker Compose
docker-compose up -d
```

The server will be available at `http://localhost:8080`.

## Docker Architecture

```mermaid
graph TB
    subgraph "Docker Compose Stack"
        subgraph "OAuth2 Service"
            OAuth2[OAuth2 Server Container]
        end
        
        subgraph "Database Service"
            DB[(PostgreSQL Container)]
        end
        
        subgraph "Observability"
            Jaeger[Jaeger Container]
            Prometheus[Prometheus Container]
        end
        
        subgraph "Networks"
            AppNet[app-network]
        end
    end
    
    OAuth2 --> DB
    OAuth2 --> Jaeger
    Prometheus --> OAuth2
    
    AppNet -.-> OAuth2
    AppNet -.-> DB
    AppNet -.-> Jaeger
    AppNet -.-> Prometheus
    
    style OAuth2 fill:#ff9800,color:#fff
    style DB fill:#f3e5f5
    style Jaeger fill:#fff9c4
    style Prometheus fill:#e8f5e9
```

## Building the Docker Image

### Using the Provided Dockerfile

```bash
# Build the image
docker build -t rust_oauth2_server:latest .

# Run the container
docker run -d \
  -p 8080:8080 \
  -e OAUTH2_DATABASE_URL=sqlite:oauth2.db \
  -e OAUTH2_JWT_SECRET=your-secret-key \
  --name oauth2_server \
  rust_oauth2_server:latest
```

### Multi-Stage Dockerfile

The project includes an optimized multi-stage Dockerfile:

```dockerfile
# Stage 1: Build
FROM rust:1.75-slim as builder

WORKDIR /app

# Copy manifests
COPY Cargo.toml Cargo.lock ./

# Copy source code
COPY src ./src
COPY migrations ./migrations
COPY templates ./templates
COPY static ./static

# Build release
RUN cargo build --release

# Stage 2: Runtime
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy binary from builder
COPY --from=builder /app/target/release/rust_oauth2_server .

# Copy runtime assets
COPY templates ./templates
COPY static ./static
COPY migrations ./migrations

# Expose port
EXPOSE 8080

# Run the server
CMD ["./rust_oauth2_server"]
```

## Docker Compose Setup

### Basic Configuration

Create `docker-compose.yml`:

```yaml
version: '3.8'

services:
  oauth2_server:
    build: .
    ports:
      - "8080:8080"
    environment:
      OAUTH2_SERVER_HOST: 0.0.0.0
      OAUTH2_SERVER_PORT: 8080
      OAUTH2_DATABASE_URL: postgresql://oauth2:password@postgres:5432/oauth2_db
      OAUTH2_JWT_SECRET: ${JWT_SECRET:-change-this-in-production}
      OAUTH2_SESSION_KEY: ${SESSION_KEY:-change-this-in-production-must-be-64-chars}
      RUST_LOG: info
    depends_on:
      postgres:
        condition: service_healthy
    networks:
      - app-network
    restart: unless-stopped
  
  postgres:
    image: postgres:16-alpine
    environment:
      POSTGRES_DB: oauth2_db
      POSTGRES_USER: oauth2
      POSTGRES_PASSWORD: password
    volumes:
      - postgres_data:/var/lib/postgresql/data
    networks:
      - app-network
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U oauth2"]
      interval: 5s
      timeout: 5s
      retries: 5
    restart: unless-stopped

networks:
  app-network:
    driver: bridge

volumes:
  postgres_data:
```

### With Observability Stack

Complete setup with monitoring:

```yaml
version: '3.8'

services:
  oauth2_server:
    build: .
    ports:
      - "8080:8080"
    environment:
      OAUTH2_SERVER_HOST: 0.0.0.0
      OAUTH2_SERVER_PORT: 8080
      OAUTH2_DATABASE_URL: postgresql://oauth2:password@postgres:5432/oauth2_db
      OAUTH2_JWT_SECRET: ${JWT_SECRET}
      OAUTH2_SESSION_KEY: ${SESSION_KEY}
      OAUTH2_OTLP_ENDPOINT: http://jaeger:4317
      RUST_LOG: info
    depends_on:
      - postgres
      - jaeger
    networks:
      - app-network
    restart: unless-stopped
  
  postgres:
    image: postgres:16-alpine
    environment:
      POSTGRES_DB: oauth2_db
      POSTGRES_USER: oauth2
      POSTGRES_PASSWORD: password
    volumes:
      - postgres_data:/var/lib/postgresql/data
    networks:
      - app-network
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U oauth2"]
      interval: 5s
      timeout: 5s
      retries: 5
    restart: unless-stopped
  
  jaeger:
    image: jaegertracing/all-in-one:latest
    ports:
      - "16686:16686"  # Jaeger UI
      - "4317:4317"    # OTLP gRPC
    environment:
      COLLECTOR_OTLP_ENABLED: "true"
    networks:
      - app-network
    restart: unless-stopped
  
  prometheus:
    image: prom/prometheus:latest
    ports:
      - "9090:9090"
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml
      - prometheus_data:/prometheus
    command:
      - '--config.file=/etc/prometheus/prometheus.yml'
      - '--storage.tsdb.path=/prometheus'
    networks:
      - app-network
    restart: unless-stopped
  
  grafana:
    image: grafana/grafana:latest
    ports:
      - "3000:3000"
    environment:
      GF_SECURITY_ADMIN_PASSWORD: admin
    volumes:
      - grafana_data:/var/lib/grafana
    networks:
      - app-network
    restart: unless-stopped

networks:
  app-network:
    driver: bridge

volumes:
  postgres_data:
  prometheus_data:
  grafana_data:
```

### Prometheus Configuration

Create `prometheus.yml`:

```yaml
global:
  scrape_interval: 15s
  evaluation_interval: 15s

scrape_configs:
  - job_name: 'oauth2_server'
    static_configs:
      - targets: ['oauth2_server:8080']
    metrics_path: '/metrics'
```

## Environment Variables

Create `.env` file for Docker Compose:

```bash
# Server Configuration
OAUTH2_SERVER_HOST=0.0.0.0
OAUTH2_SERVER_PORT=8080

# Database
OAUTH2_DATABASE_URL=postgresql://oauth2:password@postgres:5432/oauth2_db

# Security (IMPORTANT: Change these!)
JWT_SECRET=your-secure-random-secret-minimum-32-characters
SESSION_KEY=your-secure-session-key-must-be-at-least-64-characters

# Token Expiration
OAUTH2_ACCESS_TOKEN_EXPIRATION=3600
OAUTH2_REFRESH_TOKEN_EXPIRATION=2592000

# Observability
OAUTH2_OTLP_ENDPOINT=http://jaeger:4317
RUST_LOG=info

# Social Login (Optional)
# OAUTH2_GOOGLE_CLIENT_ID=
# OAUTH2_GOOGLE_CLIENT_SECRET=
```

## Database Migrations

### Automatic Migrations

Run migrations automatically on startup:

```yaml
services:
  oauth2_server:
    # ...
    entrypoint: ["/bin/sh", "-c"]
    command:
      - |
        # Run migrations
        flyway migrate
        # Start server
        ./rust_oauth2_server
```

### Using Init Container

```yaml
services:
  migration:
    image: flyway/flyway:10-alpine
    command: migrate
    volumes:
      - ./migrations/sql:/flyway/sql
      - ./flyway.conf:/flyway/conf/flyway.conf
    networks:
      - app-network
    depends_on:
      postgres:
        condition: service_healthy
  
  oauth2_server:
    # ...
    depends_on:
      - migration
      - postgres
```

## Docker Commands

### Build

```bash
# Build image
docker-compose build

# Build without cache
docker-compose build --no-cache

# Build specific service
docker-compose build oauth2_server
```

### Run

```bash
# Start all services
docker-compose up -d

# Start specific service
docker-compose up -d oauth2_server

# View logs
docker-compose logs -f oauth2_server

# View all logs
docker-compose logs -f
```

### Stop

```bash
# Stop all services
docker-compose down

# Stop and remove volumes
docker-compose down -v

# Stop specific service
docker-compose stop oauth2_server
```

### Restart

```bash
# Restart all services
docker-compose restart

# Restart specific service
docker-compose restart oauth2_server
```

### Status

```bash
# View running containers
docker-compose ps

# View resource usage
docker-compose stats
```

## Health Checks

Add health checks to your services:

```yaml
services:
  oauth2_server:
    # ...
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8080/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s
```

## Volume Management

### Backup Database

```bash
# Backup PostgreSQL
docker-compose exec postgres pg_dump -U oauth2 oauth2_db > backup.sql

# Restore from backup
docker-compose exec -T postgres psql -U oauth2 oauth2_db < backup.sql
```

### Persistent Data

Volumes ensure data persists across container restarts:

```yaml
volumes:
  postgres_data:
    driver: local
  
  # Or use named volume with specific driver
  postgres_data:
    driver: local
    driver_opts:
      type: none
      device: /path/to/data
      o: bind
```

## Networking

### Expose Ports

```yaml
services:
  oauth2_server:
    ports:
      - "8080:8080"        # host:container
      - "127.0.0.1:8080:8080"  # bind to localhost only
```

### Custom Network

```yaml
networks:
  frontend:
    driver: bridge
  backend:
    driver: bridge

services:
  oauth2_server:
    networks:
      - frontend
      - backend
  
  postgres:
    networks:
      - backend
```

## Security

### Run as Non-Root User

Update Dockerfile:

```dockerfile
# Create non-root user
RUN useradd -m -u 1000 oauth2user

# Change ownership
RUN chown -R oauth2user:oauth2user /app

# Switch to non-root user
USER oauth2user

CMD ["./rust_oauth2_server"]
```

### Secrets Management

Use Docker secrets:

```yaml
version: '3.8'

services:
  oauth2_server:
    secrets:
      - jwt_secret
      - session_key
    environment:
      OAUTH2_JWT_SECRET_FILE: /run/secrets/jwt_secret
      OAUTH2_SESSION_KEY_FILE: /run/secrets/session_key

secrets:
  jwt_secret:
    file: ./secrets/jwt_secret.txt
  session_key:
    file: ./secrets/session_key.txt
```

## Production Deployment

### Use HTTPS

Behind a reverse proxy (Nginx/Traefik):

```yaml
services:
  nginx:
    image: nginx:alpine
    ports:
      - "443:443"
      - "80:80"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf
      - ./certs:/etc/nginx/certs
    depends_on:
      - oauth2_server
    networks:
      - app-network
  
  oauth2_server:
    # No ports exposed directly
    expose:
      - "8080"
    networks:
      - app-network
```

### Resource Limits

```yaml
services:
  oauth2_server:
    deploy:
      resources:
        limits:
          cpus: '2'
          memory: 2G
        reservations:
          cpus: '0.5'
          memory: 512M
```

### Restart Policy

```yaml
services:
  oauth2_server:
    restart: unless-stopped
    # or
    restart: always
    # or
    restart: on-failure:3
```

## Monitoring

### Docker Stats

```bash
# View resource usage
docker stats oauth2_server

# Continuous monitoring
watch docker stats
```

### Container Logs

```bash
# Follow logs
docker-compose logs -f oauth2_server

# Last 100 lines
docker-compose logs --tail=100 oauth2_server

# Logs since 1 hour ago
docker-compose logs --since 1h oauth2_server
```

## Troubleshooting

### Container Won't Start

```bash
# Check logs
docker-compose logs oauth2_server

# Inspect container
docker inspect oauth2_server

# Check configuration
docker-compose config
```

### Database Connection Issues

```bash
# Check if database is running
docker-compose ps postgres

# Test connection
docker-compose exec oauth2_server nc -zv postgres 5432

# View database logs
docker-compose logs postgres
```

### Permission Issues

```bash
# Check file ownership
docker-compose exec oauth2_server ls -la

# Fix permissions
sudo chown -R 1000:1000 ./data
```

## Next Steps

- [Kubernetes Deployment](kubernetes.md) - Deploy to Kubernetes
- [Production Guide](production.md) - Production best practices
- [Monitoring Setup](../observability/metrics.md) - Set up monitoring
- [Configuration Guide](../getting-started/configuration.md) - Advanced configuration
