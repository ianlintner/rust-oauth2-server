Deploy the OAuth2 server to Kubernetes.

## Select Environment

- **dev**: Development environment with minimal resources
- **staging**: Staging environment for pre-production testing
- **production**: Production environment with HA and full resources

## Select Action

- **deploy**: Initial deployment to environment
- **update**: Update existing deployment with new image
- **rollback**: Rollback to previous version
- **scale**: Change number of replicas
- **status**: Check current deployment status

Please specify:
1. Environment (dev/staging/production)
2. Action (deploy/update/rollback/scale/status)
3. Image tag (if deploying/updating)
4. Replica count (if scaling)

Use the deploy-k8s skill for detailed deployment steps.
