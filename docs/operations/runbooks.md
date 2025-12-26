# Operational Runbooks

This directory contains operational runbooks for common tasks and procedures when managing the OAuth2 Server.

## Runbook Index

### Deployment
- [Initial Deployment](#initial-deployment)
- [Update Deployment](#update-deployment)
- [Rollback Deployment](#rollback-deployment)

### Database
- [Database Backup](#database-backup)
- [Database Restore](#database-restore)
- [Run Database Migrations](#run-database-migrations)
- [Database Performance Tuning](#database-performance-tuning)

### Monitoring
- [Check Server Health](#check-server-health)
- [View Application Logs](#view-application-logs)
- [Monitor Metrics](#monitor-metrics)
- [Set Up Alerts](#set-up-alerts)

### Troubleshooting
- [Pod Not Starting](#pod-not-starting)
- [High Error Rate](#high-error-rate)
- [Database Connection Issues](#database-connection-issues)
- [Performance Degradation](#performance-degradation)

### Security
- [Rotate JWT Secret](#rotate-jwt-secret)
- [Rotate Database Password](#rotate-database-password)
- [Revoke All Tokens](#revoke-all-tokens)
- [Security Incident Response](#security-incident-response)

---

## Initial Deployment

### Prerequisites
- Kubernetes cluster (1.24+)
- kubectl configured
- Docker images built and pushed
- Secrets configured

### Steps

1. **Create namespace**
   ```bash
   kubectl apply -f k8s/base/namespace.yaml
   ```

2. **Configure secrets**
   ```bash
   # Generate JWT secret
   JWT_SECRET=$(openssl rand -base64 32)
   
   # Create secret
   kubectl create secret generic oauth2-server-secret \
     --from-literal=OAUTH2_JWT_SECRET="$JWT_SECRET" \
     --from-literal=POSTGRES_PASSWORD="$(openssl rand -base64 20)" \
     -n oauth2-server
   ```

3. **Deploy PostgreSQL**
   ```bash
   kubectl apply -k k8s/overlays/production
   kubectl wait --for=condition=ready pod/postgres-0 -n oauth2-server --timeout=300s
   ```

4. **Run migrations**
   ```bash
   kubectl apply -f k8s/base/flyway-migration-job.yaml
   kubectl logs -f job/flyway-migration -n oauth2-server
   ```

5. **Deploy application**
   ```bash
   kubectl apply -k k8s/overlays/production
   kubectl wait --for=condition=ready pod -l app=oauth2-server -n oauth2-server --timeout=300s
   ```

6. **Verify deployment**
   ```bash
   kubectl get all -n oauth2-server
   curl -f https://oauth.example.com/health
   ```

### Rollback
If deployment fails:
```bash
kubectl delete -k k8s/overlays/production
kubectl delete namespace oauth2-server
```

---

## Update Deployment

### Prerequisites
- New Docker image built and pushed
- Tested in staging environment

### Steps

1. **Update image tag**
   ```bash
   cd k8s/overlays/production
   kustomize edit set image gabby.azurecr.io/oauth2-server:v1.1.0
   ```

2. **Apply update**
   ```bash
   kubectl apply -k k8s/overlays/production
   ```

3. **Monitor rollout**
   ```bash
   kubectl rollout status deployment/oauth2-server -n oauth2-server
   ```

4. **Verify new pods**
   ```bash
   kubectl get pods -n oauth2-server
   kubectl logs -f deployment/oauth2-server -n oauth2-server
   ```

5. **Health check**
   ```bash
   curl -f https://oauth.example.com/health
   ```

### Rollback
If issues occur:
```bash
kubectl rollout undo deployment/oauth2-server -n oauth2-server
kubectl rollout status deployment/oauth2-server -n oauth2-server
```

---

## Rollback Deployment

### When to Rollback
- High error rate (>5%)
- Failed health checks
- Database connection issues
- Performance degradation

### Steps

1. **View rollout history**
   ```bash
   kubectl rollout history deployment/oauth2-server -n oauth2-server
   ```

2. **Rollback to previous version**
   ```bash
   kubectl rollout undo deployment/oauth2-server -n oauth2-server
   ```

3. **Or rollback to specific revision**
   ```bash
   kubectl rollout undo deployment/oauth2-server --to-revision=5 -n oauth2-server
   ```

4. **Monitor rollback**
   ```bash
   kubectl rollout status deployment/oauth2-server -n oauth2-server
   ```

5. **Verify health**
   ```bash
   kubectl logs -f deployment/oauth2-server -n oauth2-server
   curl -f https://oauth.example.com/health
   ```

---

## Database Backup

### Schedule
- **Daily**: Automated backup at 2 AM UTC
- **Before major changes**: Manual backup
- **Monthly**: Full database dump to cold storage

### Manual Backup

1. **Create backup**
   ```bash
   kubectl exec -n oauth2-server postgres-0 -- \
     pg_dump -U oauth2_user -F c oauth2 > backup-$(date +%Y%m%d-%H%M).dump
   ```

2. **Verify backup**
   ```bash
   pg_restore --list backup-$(date +%Y%m%d-%H%M).dump | head -20
   ```

3. **Upload to S3 (if configured)**
   ```bash
   aws s3 cp backup-$(date +%Y%m%d-%H%M).dump \
     s3://oauth2-backups/$(date +%Y/%m/%d)/
   ```

4. **Test restore (on staging)**
   ```bash
   # On staging database
   pg_restore -U oauth2_user -d oauth2_staging backup-$(date +%Y%m%d-%H%M).dump
   ```

### Automated Backup Script

```bash
#!/bin/bash
# /opt/scripts/backup-oauth2-db.sh

DATE=$(date +%Y%m%d-%H%M)
BACKUP_FILE="/backups/oauth2-$DATE.dump"
S3_BUCKET="s3://oauth2-backups"

# Create backup
kubectl exec -n oauth2-server postgres-0 -- \
  pg_dump -U oauth2_user -F c oauth2 > "$BACKUP_FILE"

# Upload to S3
aws s3 cp "$BACKUP_FILE" "$S3_BUCKET/$(date +%Y/%m/%d)/"

# Keep local backups for 7 days
find /backups -name "oauth2-*.dump" -mtime +7 -delete

# Verify
if [ $? -eq 0 ]; then
  echo "Backup successful: $BACKUP_FILE"
else
  echo "Backup failed!" >&2
  exit 1
fi
```

---

## Database Restore

### Prerequisites
- Valid backup file
- Database accessible
- Application pods scaled to 0

### Steps

1. **Scale down application**
   ```bash
   kubectl scale deployment oauth2-server --replicas=0 -n oauth2-server
   kubectl wait --for=delete pod -l app=oauth2-server -n oauth2-server --timeout=60s
   ```

2. **Download backup from S3 (if needed)**
   ```bash
   aws s3 cp s3://oauth2-backups/2024/01/15/backup-20240115-1400.dump .
   ```

3. **Restore database**
   ```bash
   kubectl exec -i -n oauth2-server postgres-0 -- \
     pg_restore -U oauth2_user -d oauth2 -c < backup-20240115-1400.dump
   ```

4. **Verify restoration**
   ```bash
   kubectl exec -it postgres-0 -n oauth2-server -- \
     psql -U oauth2_user -d oauth2 -c "\dt"
   
   # Check record counts
   kubectl exec -it postgres-0 -n oauth2-server -- \
     psql -U oauth2_user -d oauth2 -c "
       SELECT 'clients' as table, COUNT(*) FROM clients
       UNION ALL
       SELECT 'tokens', COUNT(*) FROM tokens
       UNION ALL
       SELECT 'users', COUNT(*) FROM users;
     "
   ```

5. **Scale up application**
   ```bash
   kubectl scale deployment oauth2-server --replicas=2 -n oauth2-server
   kubectl wait --for=condition=ready pod -l app=oauth2-server -n oauth2-server --timeout=300s
   ```

6. **Verify application**
   ```bash
   curl -f https://oauth.example.com/health
   curl -f https://oauth.example.com/metrics
   ```

---

## Run Database Migrations

### Prerequisites
- Migration files in `migrations/sql/`
- Database accessible
- Tested in development/staging

### Steps

1. **Create ConfigMap with migrations**
   ```bash
   kubectl create configmap flyway-migrations \
     --from-file=migrations/sql/ \
     -n oauth2-server \
     --dry-run=client -o yaml | kubectl apply -f -
   ```

2. **Apply migration job**
   ```bash
   # Delete old job if exists
   kubectl delete job flyway-migration -n oauth2-server --ignore-not-found
   
   # Apply new job
   kubectl apply -f k8s/base/flyway-migration-job.yaml
   ```

3. **Monitor migration**
   ```bash
   kubectl logs -f job/flyway-migration -n oauth2-server
   ```

4. **Verify migration**
   ```bash
   kubectl exec -it postgres-0 -n oauth2-server -- \
     psql -U oauth2_user -d oauth2 -c "
       SELECT installed_rank, version, description, installed_on, success 
       FROM flyway_schema_history 
       ORDER BY installed_rank DESC 
       LIMIT 5;
     "
   ```

5. **Test application**
   ```bash
   kubectl logs -f deployment/oauth2-server -n oauth2-server
   curl -f https://oauth.example.com/health
   ```

### Rollback Migration

If migration fails:

1. **Check migration status**
   ```bash
   kubectl logs job/flyway-migration -n oauth2-server
   ```

2. **Manually revert changes**
   ```bash
   kubectl exec -it postgres-0 -n oauth2-server -- \
     psql -U oauth2_user -d oauth2
   
   # Run rollback SQL
   ```

3. **Restore from backup if needed**
   ```bash
   # See "Database Restore" runbook
   ```

---

## Check Server Health

### Quick Health Check

```bash
# Health endpoint
curl -f https://oauth.example.com/health | jq

# Readiness endpoint
curl -f https://oauth.example.com/ready | jq

# Kubernetes pod status
kubectl get pods -n oauth2-server

# Recent logs
kubectl logs -n oauth2-server -l app=oauth2-server --tail=20
```

### Detailed Health Check

```bash
# Application metrics
curl -s https://oauth.example.com/metrics | grep oauth2_server

# Database connectivity
kubectl exec -it postgres-0 -n oauth2-server -- \
  pg_isready -U oauth2_user

# Pod resource usage
kubectl top pods -n oauth2-server

# Check for errors in logs
kubectl logs -n oauth2-server -l app=oauth2-server --since=1h | grep -i error

# HPA status
kubectl get hpa -n oauth2-server

# Service endpoints
kubectl get endpoints -n oauth2-server
```

---

## View Application Logs

### Real-time Logs

```bash
# All pods
kubectl logs -f -n oauth2-server -l app=oauth2-server

# Specific pod
kubectl logs -f -n oauth2-server oauth2-server-abc123-xyz

# Last 100 lines
kubectl logs -n oauth2-server -l app=oauth2-server --tail=100

# Since 1 hour ago
kubectl logs -n oauth2-server -l app=oauth2-server --since=1h

# Previous pod (after crash)
kubectl logs -p -n oauth2-server oauth2-server-abc123-xyz
```

### Log Analysis

```bash
# Count errors
kubectl logs -n oauth2-server -l app=oauth2-server | grep -c ERROR

# Find authentication failures
kubectl logs -n oauth2-server -l app=oauth2-server | grep "401\|403"

# Find slow queries
kubectl logs -n oauth2-server -l app=oauth2-server | grep "query took"

# Export logs for analysis
kubectl logs -n oauth2-server -l app=oauth2-server --tail=10000 > oauth2-logs.txt
```

---

## Monitor Metrics

### Prometheus Queries

Access Prometheus and run these queries:

```promql
# Request rate
rate(oauth2_server_http_requests_total[5m])

# Error rate percentage
100 * (
  rate(oauth2_server_http_requests_total{status=~"5.."}[5m]) /
  rate(oauth2_server_http_requests_total[5m])
)

# Token issuance rate
rate(oauth2_server_oauth_token_issued_total[5m])

# Active tokens
oauth2_server_oauth_active_tokens

# P95 response time
histogram_quantile(0.95, 
  rate(oauth2_server_http_request_duration_seconds_bucket[5m]))

# Database query latency
histogram_quantile(0.95,
  rate(oauth2_server_db_query_duration_seconds_bucket[5m]))
```

### Key Metrics to Monitor

| Metric | Threshold | Action |
|--------|-----------|--------|
| Error rate | > 5% | Investigate logs |
| Response time (P95) | > 500ms | Check database |
| Active tokens | > 100,000 | Consider cleanup |
| Database CPU | > 80% | Scale or optimize |
| Memory usage | > 80% | Scale pods |

---

## Set Up Alerts

### Alertmanager Rules

```yaml
groups:
  - name: oauth2_server
    interval: 30s
    rules:
      - alert: HighErrorRate
        expr: |
          100 * (
            rate(oauth2_server_http_requests_total{status=~"5.."}[5m]) /
            rate(oauth2_server_http_requests_total[5m])
          ) > 5
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "High error rate detected"
          description: "Error rate is {{ $value }}%"
      
      - alert: HighResponseTime
        expr: |
          histogram_quantile(0.95,
            rate(oauth2_server_http_request_duration_seconds_bucket[5m])
          ) > 0.5
        for: 10m
        labels:
          severity: warning
        annotations:
          summary: "High response time"
          description: "P95 response time is {{ $value }}s"
      
      - alert: DatabaseDown
        expr: up{job="oauth2-database"} == 0
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "Database is down"
      
      - alert: PodRestartLoop
        expr: rate(kube_pod_container_status_restarts_total{namespace="oauth2-server"}[15m]) > 0
        labels:
          severity: warning
        annotations:
          summary: "Pod is restarting frequently"
```

---

## Additional Runbooks

For more specific scenarios, see:

- **[Operations Agent](.github/agents/operations.md)** - Comprehensive operational procedures
- **[Database Agent](.github/agents/database.md)** - Database-specific operations
- **[Security Agent](.github/agents/security.md)** - Security incident response

---

## Support

- **Documentation**: `/docs` directory
- **Issues**: GitHub Issues
- **Discussions**: GitHub Discussions
- **Security**: See [SECURITY.md](../SECURITY.md)
