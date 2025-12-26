# Kubernetes Deployment

This directory contains Kubernetes manifests for deploying the OAuth2 Server using Kustomize.

## Directory Structure

```
k8s/
├── base/                      # Base Kubernetes resources
│   ├── namespace.yaml         # Namespace definition
│   ├── configmap.yaml         # Configuration settings
│   ├── secret.yaml            # Sensitive data (JWT secret, DB credentials)
│   ├── postgres-pvc.yaml      # PostgreSQL persistent volume claim
│   ├── postgres-statefulset.yaml  # PostgreSQL database
│   ├── postgres-service.yaml # PostgreSQL service
│   ├── flyway-migration-job.yaml  # Database migration job
│   ├── deployment.yaml        # OAuth2 server deployment
│   ├── service.yaml           # OAuth2 server service
│   ├── ingress.yaml           # Ingress configuration
│   ├── hpa.yaml               # Horizontal Pod Autoscaler
│   ├── rbac.yaml              # Role-Based Access Control
│   └── kustomization.yaml     # Kustomize base configuration
└── overlays/                  # Environment-specific overlays
    ├── dev/                   # Development environment
    ├── staging/               # Staging environment
    └── production/            # Production environment
```

## Prerequisites

- Kubernetes cluster (v1.24+)
- kubectl CLI tool
- kustomize (v4.5.7+ or kubectl with built-in kustomize)
- Ingress controller (e.g., nginx-ingress)
- cert-manager (for TLS certificates)
- Storage class for persistent volumes

## Quick Start

### 1. Install Required Tools

```bash
# Install kubectl
# See: https://kubernetes.io/docs/tasks/tools/

# Install kustomize (optional, kubectl has it built-in)
curl -s "https://raw.githubusercontent.com/kubernetes-sigs/kustomize/master/hack/install_kustomize.sh" | bash
```

### 2. Configure Secrets

Edit `base/secret.yaml` with your production values:

```bash
# Generate a secure JWT secret (32+ characters)
openssl rand -base64 32

# Update secret.yaml with your values
kubectl create secret generic oauth2-server-secret \
  --from-literal=OAUTH2_JWT_SECRET='your-secure-jwt-secret' \
  --from-literal=POSTGRES_USER='oauth2_user' \
  --from-literal=POSTGRES_PASSWORD='your-secure-password' \
  --from-literal=POSTGRES_DB='oauth2' \
  --dry-run=client -o yaml > base/secret.yaml
```

### 3. Deploy to Development

```bash
# Apply development overlay
kubectl apply -k overlays/dev

# Verify deployment
kubectl get all -n oauth2-server-dev

# Check logs
kubectl logs -f deployment/dev-oauth2-server -n oauth2-server-dev
```

### 4. Deploy to Staging

```bash
kubectl apply -k overlays/staging
kubectl get all -n oauth2-server-staging
```

### 5. Deploy to Production

```bash
kubectl apply -k overlays/production
kubectl get all -n oauth2-server
```

## Configuration

### Environment Variables

Edit `base/configmap.yaml` to modify configuration:

```yaml
data:
  OAUTH2_SERVER_HOST: "0.0.0.0"
  OAUTH2_SERVER_PORT: "8080"
  OAUTH2_DATABASE_URL: "postgresql://oauth2_user:oauth2_password@postgres:5432/oauth2"
  RUST_LOG: "info"
```

### Ingress Configuration

Edit `base/ingress.yaml` to configure your domain:

```yaml
spec:
  tls:
    - hosts:
        - oauth.your-domain.com  # Change this
      secretName: oauth2-server-tls
  rules:
    - host: oauth.your-domain.com  # Change this
```

### Resource Limits

Adjust resource requests and limits in `base/deployment.yaml`:

```yaml
resources:
  requests:
    memory: "256Mi"
    cpu: "250m"
  limits:
    memory: "512Mi"
    cpu: "500m"
```

### Horizontal Pod Autoscaling

Configure autoscaling in `base/hpa.yaml`:

```yaml
spec:
  minReplicas: 2
  maxReplicas: 10
  metrics:
    - type: Resource
      resource:
        name: cpu
        target:
          type: Utilization
          averageUtilization: 70
```

## Database Setup

### PostgreSQL

The deployment includes a PostgreSQL StatefulSet with persistent storage.

#### Backup Database

```bash
kubectl exec -n oauth2-server postgres-0 -- pg_dump \
  -U oauth2_user oauth2 > backup.sql
```

#### Restore Database

```bash
kubectl exec -i -n oauth2-server postgres-0 -- psql \
  -U oauth2_user oauth2 < backup.sql
```

#### Connect to Database

```bash
kubectl exec -it -n oauth2-server postgres-0 -- psql \
  -U oauth2_user -d oauth2
```

### Migrations

Database migrations are handled by Flyway automatically on deployment.

To manually run migrations:

```bash
kubectl apply -f base/flyway-migration-job.yaml
kubectl logs job/flyway-migration -n oauth2-server
```

## Monitoring

### Health Checks

```bash
# Check health endpoint
kubectl exec -n oauth2-server deployment/oauth2-server -- \
  wget -q -O- http://localhost:8080/health

# Check readiness
kubectl exec -n oauth2-server deployment/oauth2-server -- \
  wget -q -O- http://localhost:8080/ready
```

### Metrics

Access Prometheus metrics:

```bash
kubectl port-forward -n oauth2-server \
  deployment/oauth2-server 8080:8080

# Access metrics at http://localhost:8080/metrics
```

### Logs

```bash
# View server logs
kubectl logs -f deployment/oauth2-server -n oauth2-server

# View all pod logs
kubectl logs -f -l app=oauth2-server -n oauth2-server

# View previous pod logs
kubectl logs -p deployment/oauth2-server -n oauth2-server
```

## Scaling

### Manual Scaling

```bash
# Scale replicas
kubectl scale deployment oauth2-server --replicas=5 -n oauth2-server

# Verify scaling
kubectl get deployment oauth2-server -n oauth2-server
```

### Horizontal Pod Autoscaler

The HPA automatically scales based on CPU and memory usage:

```bash
# Check HPA status
kubectl get hpa -n oauth2-server

# Describe HPA
kubectl describe hpa oauth2-server -n oauth2-server
```

## Troubleshooting

### Pod Not Starting

```bash
# Check pod status
kubectl get pods -n oauth2-server

# Describe pod for events
kubectl describe pod <pod-name> -n oauth2-server

# Check logs
kubectl logs <pod-name> -n oauth2-server
```

### Database Connection Issues

```bash
# Test database connectivity
kubectl run -it --rm debug --image=postgres:15-alpine \
  --restart=Never -n oauth2-server -- \
  psql -h postgres -U oauth2_user -d oauth2

# Check database pod status
kubectl get pod postgres-0 -n oauth2-server
kubectl logs postgres-0 -n oauth2-server
```

### Ingress Issues

```bash
# Check ingress status
kubectl get ingress -n oauth2-server
kubectl describe ingress oauth2-server -n oauth2-server

# Check ingress controller logs
kubectl logs -n ingress-nginx deployment/ingress-nginx-controller
```

### Certificate Issues

```bash
# Check certificate status (if using cert-manager)
kubectl get certificate -n oauth2-server
kubectl describe certificate oauth2-server-tls -n oauth2-server

# Check cert-manager logs
kubectl logs -n cert-manager deployment/cert-manager
```

## Updating

### Update Configuration

```bash
# Edit configmap
kubectl edit configmap oauth2-server-config -n oauth2-server

# Restart pods to apply changes
kubectl rollout restart deployment/oauth2-server -n oauth2-server
```

### Update Application

```bash
# Update image tag in kustomization.yaml
# Then apply
kubectl apply -k overlays/production

# Or use kubectl set image
kubectl set image deployment/oauth2-server \
  oauth2-server=ghcr.io/ianlintner/rust_oauth2_server:v1.1.0 \
  -n oauth2-server

# Check rollout status
kubectl rollout status deployment/oauth2-server -n oauth2-server
```

### Rollback

```bash
# View rollout history
kubectl rollout history deployment/oauth2-server -n oauth2-server

# Rollback to previous version
kubectl rollout undo deployment/oauth2-server -n oauth2-server

# Rollback to specific revision
kubectl rollout undo deployment/oauth2-server --to-revision=2 \
  -n oauth2-server
```

## Cleanup

### Delete Development Environment

```bash
kubectl delete -k overlays/dev
```

### Delete Staging Environment

```bash
kubectl delete -k overlays/staging
```

### Delete Production Environment

```bash
# Be careful with production!
kubectl delete -k overlays/production
```

### Delete Everything

```bash
kubectl delete namespace oauth2-server
kubectl delete namespace oauth2-server-dev
kubectl delete namespace oauth2-server-staging
```

## Security Best Practices

1. **Secrets Management**
   - Never commit real secrets to version control
   - Use external secret management (e.g., HashiCorp Vault, AWS Secrets Manager)
   - Rotate secrets regularly

2. **Network Policies**
   - Implement network policies to restrict pod-to-pod communication
   - Only allow necessary ingress/egress traffic

3. **RBAC**
   - Follow principle of least privilege
   - Use service accounts with minimal permissions

4. **TLS**
   - Always use TLS in production
   - Configure cert-manager for automatic certificate renewal

5. **Image Security**
   - Use specific image tags, not `latest`
   - Scan images for vulnerabilities
   - Use private registry for production

## Production Checklist

- [ ] Update secret.yaml with secure values
- [ ] Configure ingress with your domain
- [ ] Set up TLS certificates
- [ ] Configure resource limits appropriately
- [ ] Set up monitoring and alerting
- [ ] Configure backup strategy for database
- [ ] Test disaster recovery procedures
- [ ] Set up log aggregation
- [ ] Configure network policies
- [ ] Review and harden RBAC policies
- [ ] Set up external secrets management
- [ ] Configure database replication (if needed)
- [ ] Test autoscaling behavior
- [ ] Document runbooks for common operations

## References

- [Kubernetes Documentation](https://kubernetes.io/docs/)
- [Kustomize Documentation](https://kustomize.io/)
- [OAuth2 Server Documentation](../docs/)
- [cert-manager Documentation](https://cert-manager.io/docs/)
