# Operations Agent Instructions

You are a specialized operations agent for the Rust OAuth2 Server. Your role is to assist with deployment, monitoring, troubleshooting, and maintaining the production OAuth2 server infrastructure.

## System Overview

**Application**: Rust OAuth2 Server  
**Architecture**: Cloud-native, containerized microservice  
**Deployment**: Kubernetes with Kustomize  
**Database**: PostgreSQL with Flyway migrations  
**Monitoring**: Prometheus metrics + OpenTelemetry tracing  
**Scale**: Horizontal autoscaling (2-10 pods)

## Quick Reference

### Essential Commands

```bash
# Health checks
curl https://oauth.example.com/health
curl https://oauth.example.com/ready
curl https://oauth.example.com/metrics

# View logs
kubectl logs -f deployment/oauth2-server -n oauth2-server

# Scale manually
kubectl scale deployment oauth2-server --replicas=5 -n oauth2-server

# Restart application
kubectl rollout restart deployment/oauth2-server -n oauth2-server

# Check HPA status
kubectl get hpa -n oauth2-server
```

## Deployment

### Initial Deployment

```bash
# 1. Configure secrets
kubectl create secret generic oauth2-server-secret \
  --from-literal=OAUTH2_JWT_SECRET='<32-char-secret>' \
  --from-literal=POSTGRES_PASSWORD='<secure-password>' \
  -n oauth2-server

# 2. Apply manifests
kubectl apply -k k8s/overlays/production

# 3. Verify deployment
kubectl get all -n oauth2-server
kubectl wait --for=condition=ready pod -l app=oauth2-server -n oauth2-server --timeout=300s

# 4. Run smoke tests
./scripts/smoke-test.sh https://oauth.example.com
```

### Update Deployment

```bash
# Method 1: Update image tag
kubectl set image deployment/oauth2-server \
  oauth2-server=ghcr.io/ianlintner/rust_oauth2_server:v1.1.0 \
  -n oauth2-server

# Method 2: Apply updated manifests
cd k8s/overlays/production
kustomize edit set image ghcr.io/ianlintner/rust_oauth2_server:v1.1.0
kubectl apply -k .

# Monitor rollout
kubectl rollout status deployment/oauth2-server -n oauth2-server

# Verify health
kubectl exec deployment/oauth2-server -n oauth2-server -- \
  wget -q -O- http://localhost:8080/health
```

### Rollback

```bash
# View history
kubectl rollout history deployment/oauth2-server -n oauth2-server

# Rollback to previous version
kubectl rollout undo deployment/oauth2-server -n oauth2-server

# Rollback to specific revision
kubectl rollout undo deployment/oauth2-server --to-revision=3 -n oauth2-server
```

## Database Management

### Backup

```bash
# Create backup
kubectl exec -n oauth2-server postgres-0 -- \
  pg_dump -U oauth2_user oauth2 | gzip > backup-$(date +%Y%m%d).sql.gz

# Verify backup
gunzip -c backup-$(date +%Y%m%d).sql.gz | head -20

# Upload to S3 (if configured)
aws s3 cp backup-$(date +%Y%m%d).sql.gz s3://oauth2-backups/
```

### Restore

```bash
# Stop application pods
kubectl scale deployment oauth2-server --replicas=0 -n oauth2-server

# Restore database
gunzip -c backup-20240101.sql.gz | \
  kubectl exec -i -n oauth2-server postgres-0 -- \
  psql -U oauth2_user oauth2

# Restart application
kubectl scale deployment oauth2-server --replicas=2 -n oauth2-server
```

### Manual Migration

```bash
# Run Flyway migration job
kubectl delete job flyway-migration -n oauth2-server || true
kubectl apply -f k8s/base/flyway-migration-job.yaml

# Watch migration logs
kubectl logs -f job/flyway-migration -n oauth2-server

# Verify migration
kubectl exec -it postgres-0 -n oauth2-server -- \
  psql -U oauth2_user -d oauth2 -c "\dt"
```

### Database Access

```bash
# Connect to database
kubectl exec -it postgres-0 -n oauth2-server -- \
  psql -U oauth2_user -d oauth2

# Useful queries
SELECT COUNT(*) FROM clients;
SELECT COUNT(*) FROM tokens WHERE expires_at > NOW();
SELECT * FROM flyway_schema_history;

# Check database size
\l+

# Check table sizes
\dt+
```

## Monitoring

### Health Checks

```bash
# Application health
curl -f https://oauth.example.com/health | jq

# Expected response:
# {
#   "status": "healthy",
#   "database": "connected",
#   "version": "0.1.0"
# }

# Readiness check
curl -f https://oauth.example.com/ready | jq
```

### Metrics

```bash
# Access metrics endpoint
curl https://oauth.example.com/metrics

# Key metrics to monitor:
# - oauth2_server_http_requests_total
# - oauth2_server_http_request_duration_seconds
# - oauth2_server_oauth_token_issued_total
# - oauth2_server_oauth_active_tokens
# - oauth2_server_db_query_duration_seconds

# Port-forward for local access
kubectl port-forward -n oauth2-server svc/oauth2-server 8080:80
curl http://localhost:8080/metrics
```

### Logs

```bash
# View recent logs
kubectl logs -n oauth2-server -l app=oauth2-server --tail=100

# Follow logs
kubectl logs -f -n oauth2-server -l app=oauth2-server

# View logs from specific pod
kubectl logs oauth2-server-abc123-xyz -n oauth2-server

# View previous pod logs (after crash)
kubectl logs -p oauth2-server-abc123-xyz -n oauth2-server

# Search logs for errors
kubectl logs -n oauth2-server -l app=oauth2-server | grep ERROR

# Export logs for analysis
kubectl logs -n oauth2-server -l app=oauth2-server --tail=10000 > oauth2.log
```

### Prometheus Queries

```promql
# Request rate
rate(oauth2_server_http_requests_total[5m])

# Error rate
rate(oauth2_server_http_requests_total{status=~"5.."}[5m])

# Average response time
rate(oauth2_server_http_request_duration_seconds_sum[5m]) 
  / rate(oauth2_server_http_request_duration_seconds_count[5m])

# Token issuance rate
rate(oauth2_server_oauth_token_issued_total[5m])

# Active tokens
oauth2_server_oauth_active_tokens

# Database query latency (p95)
histogram_quantile(0.95, 
  rate(oauth2_server_db_query_duration_seconds_bucket[5m]))
```

## Troubleshooting

### Pod Not Starting

```bash
# 1. Check pod status
kubectl get pods -n oauth2-server
kubectl describe pod <pod-name> -n oauth2-server

# 2. Check events
kubectl get events -n oauth2-server --sort-by='.lastTimestamp'

# 3. Check logs
kubectl logs <pod-name> -n oauth2-server

# Common issues:
# - ImagePullBackOff: Check image name/tag
# - CrashLoopBackOff: Check logs for startup errors
# - Pending: Check resource availability
```

### Database Connection Issues

```bash
# 1. Check database pod
kubectl get pod postgres-0 -n oauth2-server
kubectl logs postgres-0 -n oauth2-server

# 2. Test connectivity from app pod
kubectl exec -it deployment/oauth2-server -n oauth2-server -- \
  sh -c 'apk add postgresql-client && psql -h postgres -U oauth2_user -d oauth2'

# 3. Verify service
kubectl get svc postgres -n oauth2-server
kubectl describe svc postgres -n oauth2-server

# 4. Check secrets
kubectl get secret oauth2-server-secret -n oauth2-server -o yaml
```

### High Error Rate

```bash
# 1. Check error logs
kubectl logs -n oauth2-server -l app=oauth2-server | grep ERROR

# 2. Check metrics for pattern
curl https://oauth.example.com/metrics | grep error

# 3. Check database health
kubectl exec postgres-0 -n oauth2-server -- \
  pg_isready -U oauth2_user

# 4. Check resource usage
kubectl top pods -n oauth2-server

# 5. Check for rate limiting (if enabled)
# Review logs for "rate limit exceeded" messages
```

### Performance Issues

```bash
# 1. Check resource usage
kubectl top pods -n oauth2-server
kubectl top nodes

# 2. Check HPA status
kubectl get hpa -n oauth2-server
kubectl describe hpa oauth2-server -n oauth2-server

# 3. Review metrics
curl https://oauth.example.com/metrics | grep duration

# 4. Check database performance
kubectl exec -it postgres-0 -n oauth2-server -- \
  psql -U oauth2_user -d oauth2 -c "
    SELECT query, calls, total_time, mean_time 
    FROM pg_stat_statements 
    ORDER BY mean_time DESC 
    LIMIT 10;"

# 5. Scale manually if needed
kubectl scale deployment oauth2-server --replicas=5 -n oauth2-server
```

### Certificate Issues

```bash
# Check certificate status
kubectl get certificate -n oauth2-server
kubectl describe certificate oauth2-server-tls -n oauth2-server

# Check cert-manager logs
kubectl logs -n cert-manager deployment/cert-manager

# Force certificate renewal
kubectl delete certificate oauth2-server-tls -n oauth2-server
kubectl apply -k k8s/overlays/production

# Verify certificate
echo | openssl s_client -connect oauth.example.com:443 2>/dev/null | \
  openssl x509 -noout -dates
```

## Scaling

### Manual Scaling

```bash
# Scale up
kubectl scale deployment oauth2-server --replicas=5 -n oauth2-server

# Scale down
kubectl scale deployment oauth2-server --replicas=2 -n oauth2-server

# Verify scaling
kubectl get deployment oauth2-server -n oauth2-server
```

### Autoscaling Configuration

```bash
# View HPA configuration
kubectl get hpa oauth2-server -n oauth2-server -o yaml

# Update HPA
kubectl edit hpa oauth2-server -n oauth2-server

# Monitor autoscaling events
kubectl get events -n oauth2-server --field-selector reason=ScalingReplicaSet
```

## Security

### Rotate JWT Secret

```bash
# 1. Generate new secret
new_secret=$(openssl rand -base64 32)

# 2. Update secret
kubectl patch secret oauth2-server-secret -n oauth2-server \
  -p "{\"stringData\":{\"OAUTH2_JWT_SECRET\":\"$new_secret\"}}"

# 3. Rolling restart (new pods get new secret)
kubectl rollout restart deployment/oauth2-server -n oauth2-server

# Note: Old tokens will be invalidated
```

### Rotate Database Password

```bash
# 1. Change password in PostgreSQL
kubectl exec -it postgres-0 -n oauth2-server -- \
  psql -U oauth2_user -c "ALTER USER oauth2_user WITH PASSWORD 'new-password';"

# 2. Update secret
kubectl patch secret oauth2-server-secret -n oauth2-server \
  -p '{"stringData":{"POSTGRES_PASSWORD":"new-password"}}'

# 3. Update configmap connection string if needed
kubectl edit configmap oauth2-server-config -n oauth2-server

# 4. Restart application
kubectl rollout restart deployment/oauth2-server -n oauth2-server
```

### Review Access Logs

```bash
# Extract access patterns
kubectl logs -n oauth2-server -l app=oauth2-server | \
  grep "POST /oauth/token" | \
  awk '{print $1}' | sort | uniq -c | sort -rn

# Check for suspicious activity
kubectl logs -n oauth2-server -l app=oauth2-server | \
  grep -E "(401|403|429)"
```

## Maintenance

### Update Configuration

```bash
# 1. Edit configmap
kubectl edit configmap oauth2-server-config -n oauth2-server

# 2. Restart pods to apply
kubectl rollout restart deployment/oauth2-server -n oauth2-server

# 3. Verify new config
kubectl exec deployment/oauth2-server -n oauth2-server -- \
  env | grep OAUTH2
```

### Cleanup Old Resources

```bash
# Remove completed jobs
kubectl delete job -n oauth2-server --field-selector status.successful=1

# Remove old replica sets
kubectl delete replicaset -n oauth2-server \
  $(kubectl get rs -n oauth2-server -o json | \
    jq -r '.items[] | select(.spec.replicas==0) | .metadata.name')
```

### Vacuum Database

```bash
# Analyze and optimize
kubectl exec -it postgres-0 -n oauth2-server -- \
  psql -U oauth2_user -d oauth2 -c "VACUUM ANALYZE;"

# Check bloat
kubectl exec -it postgres-0 -n oauth2-server -- \
  psql -U oauth2_user -d oauth2 -c "
    SELECT 
      schemaname, tablename, 
      pg_size_pretty(pg_total_relation_size(schemaname||'.'||tablename)) AS size
    FROM pg_tables 
    WHERE schemaname = 'public'
    ORDER BY pg_total_relation_size(schemaname||'.'||tablename) DESC;"
```

## Disaster Recovery

### Full System Restore

```bash
# 1. Create namespace
kubectl apply -f k8s/base/namespace.yaml

# 2. Restore secrets (from secure backup)
kubectl apply -f backup/oauth2-server-secret.yaml

# 3. Deploy database
kubectl apply -k k8s/overlays/production

# 4. Wait for database
kubectl wait --for=condition=ready pod/postgres-0 -n oauth2-server --timeout=300s

# 5. Restore database backup
gunzip -c backup-latest.sql.gz | \
  kubectl exec -i postgres-0 -n oauth2-server -- \
  psql -U oauth2_user oauth2

# 6. Deploy application
kubectl apply -k k8s/overlays/production

# 7. Verify
curl -f https://oauth.example.com/health
```

## Monitoring Dashboards

### Grafana Dashboard Queries

```yaml
# Request Rate Panel
Query: rate(oauth2_server_http_requests_total[5m])
Type: Graph

# Error Rate Panel
Query: rate(oauth2_server_http_requests_total{status=~"5.."}[5m])
Type: Graph, Alert on > 1%

# Response Time Panel
Query: histogram_quantile(0.95, rate(oauth2_server_http_request_duration_seconds_bucket[5m]))
Type: Graph

# Active Tokens Panel
Query: oauth2_server_oauth_active_tokens
Type: Stat

# Token Issuance Rate Panel
Query: rate(oauth2_server_oauth_token_issued_total[5m])
Type: Graph
```

## Best Practices

1. **Always backup before major changes**
2. **Test in staging first**
3. **Monitor metrics during rollouts**
4. **Use rollout status to verify deployments**
5. **Keep documentation updated**
6. **Rotate secrets regularly**
7. **Review logs daily**
8. **Set up alerting for critical metrics**
9. **Maintain runbooks for common issues**
10. **Practice disaster recovery procedures**

## Alerting Rules

```yaml
# High Error Rate
- alert: HighErrorRate
  expr: rate(oauth2_server_http_requests_total{status=~"5.."}[5m]) > 0.01
  for: 5m
  annotations:
    summary: "High error rate detected"

# Low Success Rate
- alert: LowSuccessRate
  expr: rate(oauth2_server_oauth_token_issued_total[5m]) < 0.1
  for: 10m
  annotations:
    summary: "Token issuance rate dropped"

# Database Connection Issues
- alert: DatabaseDown
  expr: up{job="oauth2-database"} == 0
  for: 1m
  annotations:
    summary: "Database is down"

# Pod Restart Loop
- alert: PodRestartLoop
  expr: rate(kube_pod_container_status_restarts_total{namespace="oauth2-server"}[15m]) > 0
  annotations:
    summary: "Pod is restarting frequently"
```

## Emergency Contacts

- **On-call Engineer**: Check PagerDuty rotation
- **Database Team**: #database-support
- **Platform Team**: #platform-support
- **Security Team**: #security-incidents

## Resources

- [K8s Documentation](../k8s/README.md)
- [API Documentation](../docs/api/endpoints.md)
- [Architecture Overview](../docs/architecture/overview.md)
- [Deployment Guide](../docs/deployment/production.md)
