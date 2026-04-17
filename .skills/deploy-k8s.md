# Deploy to Kubernetes Skill

**Purpose**: Deploy the OAuth2 server to Kubernetes using Kustomize overlays for different environments.

**When to Use**:
- Deploying to dev/staging/production
- Updating existing deployment with new version
- Rolling back to previous version
- Scaling deployment
- Applying configuration changes

## Parameters

- `environment`: Target environment (dev, staging, production)
- `action`: Deployment action (deploy, update, rollback, scale, status)
- `image_tag`: Container image tag (e.g., "v0.0.10", "latest", "test")
- `replicas`: Number of replicas (optional, for scaling)

## Prerequisites

- kubectl installed and configured
- Access to target Kubernetes cluster
- Container image built and pushed to registry
- Kustomize overlays configured
- Database initialized with migrations

## Prompt

Deploy the OAuth2 server with:
- Environment: {{environment}}
- Action: {{action}}
- Image tag: {{image_tag}}
- Replicas: {{replicas}} (if scaling)

Please perform these deployment steps:

1. **Pre-deployment Checks**:
   - Verify kubectl access:
     ```bash
     kubectl cluster-info
     kubectl get nodes
     ```
   - Check current deployment status:
     ```bash
     kubectl get deployments -n oauth2-server
     kubectl get pods -n oauth2-server
     ```
   - Verify image exists:
     ```bash
     docker pull ianlintner068/oauth2-server:{{image_tag}}
     ```

2. **Environment Selection**:
   - Review overlay configuration:
     ```bash
     cat k8s/overlays/{{environment}}/kustomization.yaml
     ```
   - Verify environment-specific settings:
     - Resource limits and requests
     - Replica count
     - Storage class
     - Ingress configuration
     - Secret references

3. **Build Kustomize Manifests**:
   ```bash
   # Preview what will be applied
   kubectl kustomize k8s/overlays/{{environment}}

   # Save to file for review
   kubectl kustomize k8s/overlays/{{environment}} > /tmp/deploy-{{environment}}.yaml

   # Review the manifest
   less /tmp/deploy-{{environment}}.yaml
   ```

4. **Execute Deployment Action**:

   **Deploy (Initial Deployment)**:
   ```bash
   # Create namespace if needed
   kubectl create namespace oauth2-server --dry-run=client -o yaml | kubectl apply -f -

   # Apply base + overlay
   kubectl apply -k k8s/overlays/{{environment}}

   # Wait for rollout
   kubectl rollout status deployment/oauth2-server -n oauth2-server --timeout=5m
   ```

   **Update (New Version)**:
   ```bash
   # Update image tag in overlay
   cd k8s/overlays/{{environment}}
   kustomize edit set image ianlintner068/oauth2-server:{{image_tag}}

   # Apply changes
   kubectl apply -k .

   # Watch rollout
   kubectl rollout status deployment/oauth2-server -n oauth2-server
   ```

   **Rollback (Previous Version)**:
   ```bash
   # View rollout history
   kubectl rollout history deployment/oauth2-server -n oauth2-server

   # Rollback to previous
   kubectl rollout undo deployment/oauth2-server -n oauth2-server

   # Rollback to specific revision
   kubectl rollout undo deployment/oauth2-server -n oauth2-server --to-revision={{revision}}
   ```

   **Scale (Adjust Replicas)**:
   ```bash
   # Scale deployment
   kubectl scale deployment/oauth2-server -n oauth2-server --replicas={{replicas}}

   # Or update kustomization.yaml and apply
   ```

   **Status (Check Health)**:
   ```bash
   # Get deployment status
   kubectl get deployment oauth2-server -n oauth2-server -o wide

   # Get pod status
   kubectl get pods -n oauth2-server -l app=oauth2-server -o wide

   # Check pod logs
   kubectl logs -f deployment/oauth2-server -n oauth2-server
   ```

5. **Database Migration** (if needed):
   ```bash
   # Run Flyway migration job
   kubectl apply -f k8s/base/jobs/flyway-migration.yaml

   # Wait for completion
   kubectl wait --for=condition=complete job/flyway-migration -n oauth2-server --timeout=5m

   # Check migration logs
   kubectl logs job/flyway-migration -n oauth2-server
   ```

6. **Post-deployment Validation**:
   - Check pod health:
     ```bash
     kubectl get pods -n oauth2-server
     # All pods should be Running with 1/1 READY
     ```
   - Test health endpoint:
     ```bash
     # Port forward for testing
     kubectl port-forward -n oauth2-server svc/oauth2-server 8080:80

     # Test endpoints
     curl http://localhost:8080/health
     curl http://localhost:8080/ready
     curl http://localhost:8080/metrics
     ```
   - Test OAuth2 flows:
     ```bash
     # Get discovery document
     curl http://localhost:8080/.well-known/oauth-authorization-server

     # Test token endpoint (with valid client)
     curl -X POST http://localhost:8080/oauth/token \
       -d "grant_type=client_credentials&client_id=test&client_secret=secret"
     ```

7. **Monitor Deployment**:
   - Check pod logs:
     ```bash
     kubectl logs -f -l app=oauth2-server -n oauth2-server
     ```
   - Watch events:
     ```bash
     kubectl get events -n oauth2-server --sort-by='.lastTimestamp'
     ```
   - Check metrics:
     ```bash
     kubectl top pods -n oauth2-server
     ```

8. **Troubleshooting** (if issues occur):
   - Describe deployment:
     ```bash
     kubectl describe deployment oauth2-server -n oauth2-server
     ```
   - Describe pods:
     ```bash
     kubectl describe pods -l app=oauth2-server -n oauth2-server
     ```
   - Check pod logs:
     ```bash
     kubectl logs -l app=oauth2-server -n oauth2-server --tail=100
     ```
   - Get previous pod logs (if crashed):
     ```bash
     kubectl logs -l app=oauth2-server -n oauth2-server --previous
     ```

## Success Criteria

- [ ] kubectl can access target cluster
- [ ] Namespace oauth2-server exists
- [ ] Kustomize manifests build successfully
- [ ] Deployment applied without errors
- [ ] Pods reach Running state
- [ ] Health check returns 200
- [ ] Readiness check returns 200
- [ ] OAuth2 endpoints respond correctly
- [ ] Database connection successful
- [ ] No errors in pod logs
- [ ] Metrics endpoint accessible

## Common Issues & Solutions

### Issue: ImagePullBackOff
**Symptoms**: Pods stuck in ImagePullBackOff state
**Solutions**:
- Verify image exists: `docker pull ianlintner068/oauth2-server:{{image_tag}}`
- Check image pull secret if using private registry
- Verify image name and tag in kustomization.yaml

### Issue: CrashLoopBackOff
**Symptoms**: Pods repeatedly crashing
**Solutions**:
- Check logs: `kubectl logs -l app=oauth2-server -n oauth2-server --previous`
- Common causes:
  - Database connection failure (check DATABASE_URL secret)
  - Missing JWT_SECRET
  - Invalid configuration
  - Database migrations not applied

### Issue: Pods Pending
**Symptoms**: Pods stuck in Pending state
**Solutions**:
- Check node resources: `kubectl describe nodes`
- Check events: `kubectl get events -n oauth2-server`
- Verify persistent volume claims bound
- Check resource requests vs available resources

### Issue: Service Not Accessible
**Symptoms**: Can't reach OAuth2 endpoints
**Solutions**:
- Verify service exists: `kubectl get svc -n oauth2-server`
- Check ingress configuration: `kubectl get ingress -n oauth2-server`
- Test with port-forward: `kubectl port-forward svc/oauth2-server 8080:80 -n oauth2-server`
- Verify network policies allow traffic

### Issue: Database Connection Fails
**Symptoms**: Logs show database connection errors
**Solutions**:
- Verify PostgreSQL pod running: `kubectl get pods -l app=postgres -n oauth2-server`
- Check database secret: `kubectl get secret db-credentials -n oauth2-server -o yaml`
- Test database connection from oauth2-server pod:
  ```bash
  kubectl exec -it deployment/oauth2-server -n oauth2-server -- sh
  # Inside pod: test DATABASE_URL connection
  ```

## Related Resources

- [Kubernetes Documentation](../k8s/README.md)
- [Operations Agent](../.github/agents/operations.md)
- [Deployment Guide](../docs/operations/deployment.md)
- [Runbooks](../docs/operations/runbooks.md)
- [Observability](../docs/operations/observability.md)
- [Kustomize Documentation](https://kustomize.io/)

## Example Usage

### Deploy to Development

```
Use the deploy-k8s skill with:
- environment: dev
- action: deploy
- image_tag: latest
```

### Update Staging with New Version

```
Use the deploy-k8s skill with:
- environment: staging
- action: update
- image_tag: v0.0.10
```

### Scale Production

```
Use the deploy-k8s skill with:
- environment: production
- action: scale
- replicas: 3
```

### Rollback Production

```
Use the deploy-k8s skill with:
- environment: production
- action: rollback
```

### Check Status

```
Use the deploy-k8s skill with:
- environment: production
- action: status
```

## Environment-Specific Configurations

### Development (k8s/overlays/dev/)
- 1 replica
- Reduced resource limits
- SQLite or PostgreSQL
- NodePort service
- Permissive network policies

### Staging (k8s/overlays/staging/)
- 2 replicas
- Moderate resource limits
- PostgreSQL required
- LoadBalancer or Ingress
- Staging secrets

### Production (k8s/overlays/production/)
- 3+ replicas
- Full resource limits
- PostgreSQL with HA
- Ingress with TLS
- Production secrets
- HPA (Horizontal Pod Autoscaler)
- Network policies enforced

## CI/CD Integration

The E2E workflow tests Kubernetes deployment:

```yaml
# .github/workflows/e2e-kind.yml
- name: Create KIND cluster
- name: Build and load image
- name: Deploy to KIND
- name: Run E2E tests
```

This validates deployment on every PR.

## Notes

- See k8s/README.md for complete Kubernetes documentation
- Operations Agent has detailed deployment procedures and troubleshooting
- Always test deployments in dev/staging before production
- Use blue-green or canary deployments for zero-downtime updates
- Monitor metrics and logs after every deployment
- Keep database backups before applying migrations
