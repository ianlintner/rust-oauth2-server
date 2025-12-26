# Production Deployment Guide

This guide covers best practices for deploying the Rust OAuth2 Server in production environments.

## Pre-Deployment Checklist

- [ ] Security configuration reviewed
- [ ] Database properly configured (PostgreSQL recommended)
- [ ] HTTPS/TLS certificates configured
- [ ] Environment variables set securely
- [ ] Database migrations tested
- [ ] Backup strategy defined
- [ ] Monitoring and alerting configured
- [ ] Load testing completed
- [ ] Disaster recovery plan documented
- [ ] Security audit performed

## Architecture Overview

### Production Architecture

```mermaid
graph TB
    Internet[Internet] --> CDN[CDN/CloudFront]
    CDN --> WAF[Web Application Firewall]
    WAF --> LB[Load Balancer]
    
    LB --> OAuth1[OAuth2 Server 1]
    LB --> OAuth2[OAuth2 Server 2]
    LB --> OAuth3[OAuth2 Server 3]
    
    OAuth1 & OAuth2 & OAuth3 --> DBPrimary[(PostgreSQL Primary)]
    DBPrimary --> DBReplica1[(Replica 1)]
    DBPrimary --> DBReplica2[(Replica 2)]
    
    OAuth1 & OAuth2 & OAuth3 --> Redis[(Redis Cache)]
    
    OAuth1 & OAuth2 & OAuth3 --> OTLP[OTLP Collector]
    OTLP --> Jaeger[Jaeger]
    
    Prometheus[Prometheus] --> OAuth1 & OAuth2 & OAuth3
    
    style WAF fill:#f44336,color:#fff
    style LB fill:#ff9800,color:#fff
    style DBPrimary fill:#4caf50,color:#fff
    style Redis fill:#e91e63,color:#fff
```

## Security Configuration

### 1. HTTPS/TLS

**Always use HTTPS in production.**

#### Using Nginx Reverse Proxy

```nginx
server {
    listen 443 ssl http2;
    server_name oauth.yourdomain.com;
    
    # SSL certificates
    ssl_certificate /etc/nginx/certs/fullchain.pem;
    ssl_certificate_key /etc/nginx/certs/privkey.pem;
    
    # SSL configuration
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384';
    ssl_prefer_server_ciphers on;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;
    
    # Security headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    
    # Proxy to OAuth2 server
    location / {
        proxy_pass http://oauth2_backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # Timeouts
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
    }
    
    # Health check endpoint (no auth required)
    location /health {
        proxy_pass http://oauth2_backend;
        access_log off;
    }
}

upstream oauth2_backend {
    least_conn;
    server oauth2_1:8080 max_fails=3 fail_timeout=30s;
    server oauth2_2:8080 max_fails=3 fail_timeout=30s;
    server oauth2_3:8080 max_fails=3 fail_timeout=30s;
    
    keepalive 32;
}

# Redirect HTTP to HTTPS
server {
    listen 80;
    server_name oauth.yourdomain.com;
    return 301 https://$server_name$request_uri;
}
```

### 2. Secret Management

**Never store secrets in code or environment variables directly.**

#### AWS Secrets Manager

```bash
# Store secrets
aws secretsmanager create-secret \
  --name oauth2/jwt-secret \
  --secret-string "your-jwt-secret"

aws secretsmanager create-secret \
  --name oauth2/session-key \
  --secret-string "your-session-key"

# Retrieve in application startup script
export OAUTH2_JWT_SECRET=$(aws secretsmanager get-secret-value \
  --secret-id oauth2/jwt-secret \
  --query SecretString \
  --output text)
```

#### HashiCorp Vault

```bash
# Store secrets
vault kv put secret/oauth2/config \
  jwt_secret="your-jwt-secret" \
  session_key="your-session-key"

# Retrieve
vault kv get -field=jwt_secret secret/oauth2/config
```

### 3. Database Security

```bash
# Use SSL for database connections
export OAUTH2_DATABASE_URL="postgresql://user:pass@host:5432/db?sslmode=require"

# Encrypt data at rest
# Enable in PostgreSQL config
ssl = on
ssl_cert_file = '/path/to/server.crt'
ssl_key_file = '/path/to/server.key'
```

### 4. Network Security

```bash
# Firewall rules (example using ufw)
ufw default deny incoming
ufw default allow outgoing
ufw allow 443/tcp  # HTTPS
ufw allow 22/tcp   # SSH (from specific IPs only)
ufw enable

# Security groups (AWS example)
# Allow inbound 443 from anywhere
# Allow inbound 8080 only from load balancer
# Allow inbound 5432 only from application servers
```

## Database Configuration

### PostgreSQL Production Setup

```sql
-- Create database and user
CREATE DATABASE oauth2_db;
CREATE USER oauth2_user WITH ENCRYPTED PASSWORD 'strong-password';
GRANT ALL PRIVILEGES ON DATABASE oauth2_db TO oauth2_user;

-- Performance tuning
ALTER SYSTEM SET shared_buffers = '256MB';
ALTER SYSTEM SET effective_cache_size = '1GB';
ALTER SYSTEM SET maintenance_work_mem = '64MB';
ALTER SYSTEM SET checkpoint_completion_target = 0.9;
ALTER SYSTEM SET wal_buffers = '16MB';
ALTER SYSTEM SET default_statistics_target = 100;
ALTER SYSTEM SET random_page_cost = 1.1;
ALTER SYSTEM SET effective_io_concurrency = 200;
ALTER SYSTEM SET work_mem = '4MB';
ALTER SYSTEM SET max_connections = 200;

-- Reload configuration
SELECT pg_reload_conf();
```

### Connection Pooling

```bash
# Environment variables
export OAUTH2_DATABASE_MAX_CONNECTIONS=50
export OAUTH2_DATABASE_MIN_CONNECTIONS=10
export OAUTH2_DATABASE_CONNECT_TIMEOUT=30
export OAUTH2_DATABASE_IDLE_TIMEOUT=600
```

### Database Backup

```bash
#!/bin/bash
# Automated backup script

DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_DIR="/backups/oauth2"
DB_NAME="oauth2_db"

# Create backup
pg_dump -h localhost -U oauth2_user $DB_NAME | \
  gzip > "$BACKUP_DIR/backup_$DATE.sql.gz"

# Upload to S3
aws s3 cp "$BACKUP_DIR/backup_$DATE.sql.gz" \
  s3://your-bucket/oauth2-backups/

# Keep only last 30 days
find $BACKUP_DIR -name "backup_*.sql.gz" -mtime +30 -delete

# Schedule with cron
# 0 2 * * * /path/to/backup.sh
```

## High Availability

### Load Balancing

#### HAProxy Configuration

```conf
global
    log /dev/log local0
    maxconn 4096
    
defaults
    log global
    mode http
    option httplog
    option dontlognull
    timeout connect 5000
    timeout client 50000
    timeout server 50000
    
frontend oauth2_frontend
    bind *:443 ssl crt /etc/ssl/certs/oauth2.pem
    default_backend oauth2_servers
    
    # Health check
    acl is_health path /health
    use_backend health_backend if is_health
    
backend oauth2_servers
    balance roundrobin
    option httpchk GET /health
    http-check expect status 200
    
    server oauth2_1 10.0.1.10:8080 check
    server oauth2_2 10.0.1.11:8080 check
    server oauth2_3 10.0.1.12:8080 check
    
backend health_backend
    server oauth2_1 10.0.1.10:8080
```

### Database Replication

#### PostgreSQL Streaming Replication

**Primary Server:**

```sql
-- postgresql.conf
wal_level = replica
max_wal_senders = 3
wal_keep_size = 64

-- pg_hba.conf
host replication replicator 10.0.1.0/24 md5
```

**Replica Server:**

```conf
# recovery.conf (PostgreSQL < 12) or postgresql.conf (>= 12)
primary_conninfo = 'host=primary_ip port=5432 user=replicator password=pass'
promote_trigger_file = '/tmp/promote_replica'
```

## Performance Optimization

### Server Configuration

```bash
# Optimal worker count
export OAUTH2_SERVER_WORKERS=8  # Number of CPU cores

# Database connection pool
export OAUTH2_DATABASE_MAX_CONNECTIONS=50
export OAUTH2_DATABASE_MIN_CONNECTIONS=10

# Token expiration (balance security vs performance)
export OAUTH2_ACCESS_TOKEN_EXPIRATION=1800  # 30 minutes
export OAUTH2_REFRESH_TOKEN_EXPIRATION=604800  # 7 days
```

### Caching Strategy

#### Redis for Session Storage

```yaml
# docker-compose.yml
services:
  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    volumes:
      - redis_data:/data
    command: redis-server --appendonly yes
```

### Application-Level Caching

```rust
// Token validation caching
use cached::proc_macro::cached;

#[cached(time = 300)]  // Cache for 5 minutes
async fn validate_token(token: String) -> Result<bool, Error> {
    // Validation logic
}
```

## Monitoring and Alerting

### Prometheus Alerts

Create `alerts.yml`:

```yaml
groups:
  - name: oauth2_alerts
    rules:
      - alert: HighErrorRate
        expr: rate(oauth2_server_http_requests_total{status="5xx"}[5m]) > 0.05
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "High error rate detected"
          description: "Error rate is {{ $value }} requests/sec"
      
      - alert: HighLatency
        expr: histogram_quantile(0.95, rate(oauth2_server_http_request_duration_seconds_bucket[5m])) > 1
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High request latency"
          description: "P95 latency is {{ $value }}s"
      
      - alert: DatabaseConnectionPoolExhausted
        expr: oauth2_server_db_connections_active >= oauth2_server_db_connections_max * 0.9
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Database connection pool near capacity"
      
      - alert: TokenRevocationRateHigh
        expr: rate(oauth2_server_oauth_token_revoked_total[5m]) > 10
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High token revocation rate"
```

### Grafana Dashboard

Import the provided dashboard JSON or create custom dashboards monitoring:

- Request rate and latency
- Error rates
- Token issuance rate
- Database performance
- Resource utilization

## Scaling Strategy

### Horizontal Scaling

```bash
# Add more instances
docker-compose up -d --scale oauth2_server=5

# Kubernetes
kubectl scale deployment oauth2-server --replicas=5
```

### Vertical Scaling

```yaml
# Docker resource limits
services:
  oauth2_server:
    deploy:
      resources:
        limits:
          cpus: '4'
          memory: 4G
        reservations:
          cpus: '2'
          memory: 2G
```

### Auto-scaling (Kubernetes)

```yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: oauth2-hpa
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: oauth2-server
  minReplicas: 3
  maxReplicas: 10
  metrics:
    - type: Resource
      resource:
        name: cpu
        target:
          type: Utilization
          averageUtilization: 70
    - type: Resource
      resource:
        name: memory
        target:
          type: Utilization
          averageUtilization: 80
```

## Disaster Recovery

### Backup Strategy

```bash
# Daily database backups
# Weekly full system backups
# Monthly archival to cold storage
# Test restoration quarterly

# Backup checklist:
# - Database dumps
# - Configuration files
# - TLS certificates
# - Application logs
# - Metrics data
```

### Recovery Procedures

```bash
# 1. Restore database
gunzip < backup_20240101_120000.sql.gz | \
  psql -h localhost -U oauth2_user oauth2_db

# 2. Verify data integrity
psql -h localhost -U oauth2_user oauth2_db -c "
  SELECT COUNT(*) FROM clients;
  SELECT COUNT(*) FROM tokens;
"

# 3. Start application
docker-compose up -d

# 4. Verify health
curl https://oauth.yourdomain.com/health

# 5. Monitor logs
docker-compose logs -f
```

## Compliance

### GDPR Compliance

```sql
-- Right to erasure (Article 17)
CREATE OR REPLACE FUNCTION delete_user_data(user_id TEXT)
RETURNS VOID AS $$
BEGIN
    DELETE FROM tokens WHERE user_id = user_id;
    DELETE FROM authorization_codes WHERE user_id = user_id;
    DELETE FROM users WHERE id = user_id;
END;
$$ LANGUAGE plpgsql;

-- Data export (Article 20)
CREATE OR REPLACE FUNCTION export_user_data(user_id TEXT)
RETURNS JSON AS $$
    SELECT json_build_object(
        'user', (SELECT row_to_json(u) FROM users u WHERE id = user_id),
        'tokens', (SELECT json_agg(t) FROM tokens t WHERE t.user_id = user_id),
        'auth_codes', (SELECT json_agg(a) FROM authorization_codes a WHERE a.user_id = user_id)
    );
$$ LANGUAGE sql;
```

### Audit Logging

```rust
// Log all authentication events
async fn log_auth_event(event: AuthEvent) {
    tracing::info!(
        event_type = %event.event_type,
        user_id = %event.user_id,
        client_id = %event.client_id,
        ip_address = %event.ip_address,
        timestamp = %event.timestamp,
        "Authentication event"
    );
}
```

## Security Best Practices

1. **Regular Updates**: Keep dependencies and system packages updated
2. **Penetration Testing**: Conduct regular security audits
3. **Rate Limiting**: Implement aggressive rate limiting
4. **DDoS Protection**: Use CloudFlare or AWS Shield
5. **Intrusion Detection**: Monitor for suspicious activity
6. **Least Privilege**: Run services with minimal permissions
7. **Network Segmentation**: Isolate database and application tiers
8. **Secret Rotation**: Rotate secrets regularly
9. **Security Headers**: Implement all recommended security headers
10. **WAF**: Use Web Application Firewall

## Troubleshooting Production Issues

### High CPU Usage

```bash
# Check process CPU
top -p $(pgrep -f oauth2_server)

# Profile application
perf record -F 99 -p $(pgrep -f oauth2_server) -g -- sleep 30
perf report
```

### Memory Leaks

```bash
# Monitor memory usage
watch -n 1 'ps aux | grep oauth2_server'

# Check for leaks
valgrind --leak-check=full ./oauth2_server
```

### Database Performance

```sql
-- Slow query log
ALTER SYSTEM SET log_min_duration_statement = 1000;  -- 1 second

-- Find slow queries
SELECT query, mean_exec_time, calls
FROM pg_stat_statements
ORDER BY mean_exec_time DESC
LIMIT 10;

-- Check indexes
SELECT schemaname, tablename, indexname, idx_scan
FROM pg_stat_user_indexes
ORDER BY idx_scan;
```

## Maintenance Windows

```bash
# Schedule regular maintenance
# - Security updates: Weekly
# - Database maintenance: Monthly
# - Certificate renewal: Quarterly
# - Load testing: Quarterly
# - Disaster recovery drill: Semi-annually
```

## Next Steps

- [Docker Deployment](docker.md) - Containerized deployment
- [Kubernetes Deployment](kubernetes.md) - K8s setup
- [Monitoring](../observability/metrics.md) - Set up monitoring
- [Configuration](../getting-started/configuration.md) - Advanced configuration
