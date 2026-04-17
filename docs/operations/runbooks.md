# Operational Runbooks

## For AI Agents

> **Prompt:** "The OAuth2 server is down in production - help me diagnose and fix the issue using the runbooks"

**Common operational scenarios:**

| Scenario | Prompt Example |
|----------|----------------|
| Service health check | "Check if the OAuth2 server is healthy and ready" |
| High latency | "The token endpoint is slow - help diagnose the performance issue" |
| Failed deployment | "The latest deployment failed - help me roll back safely" |
| Database issues | "The readiness check is failing - troubleshoot database connectivity" |
| Token errors | "Users are getting 'invalid_token' errors - diagnose the issue" |
| Storage full | "The database is running out of space - help me clean up old tokens" |
| Memory leak | "The server memory usage is growing - help identify the leak" |
| Rate limit tuning | "Too many rate limit rejections - adjust the thresholds" |

**First-response checklist:**
```bash
curl http://localhost:8080/health     # Basic liveness
curl http://localhost:8080/ready      # Storage connectivity
curl http://localhost:8080/metrics    # Current metrics
kubectl get pods -n oauth2-server     # Pod status
kubectl logs -n oauth2-server -l app=oauth2-server     # Recent logs
```

**Quick actions:**
- Roll back: `kubectl rollout undo deployment/oauth2-server -n oauth2-server`
- Restart: `kubectl rollout restart deployment/oauth2-server -n oauth2-server`
- Scale: `kubectl scale deployment/oauth2-server --replicas=3 -n oauth2-server`

---

This page is the first-response sheet, not an operations novel. Use it when the service is unhealthy, slow, or freshly deployed and suspicious.

## First five minutes

Start here before guessing:

```bash
curl -fsS http://localhost:8080/health
curl -fsS http://localhost:8080/ready
curl -fsS http://localhost:8080/metrics | head
kubectl get pods -n oauth2-server
kubectl logs -n oauth2-server -l app=oauth2-server --tail=100
```

If `/ready` fails, treat it as a storage or config problem first. If `/health` is green but latency is bad, use metrics and recent deploy history before touching the database.

## Roll back a bad deploy

### Kubernetes

```bash
kubectl rollout history deployment/oauth2-server -n oauth2-server
kubectl rollout undo deployment/oauth2-server -n oauth2-server
kubectl rollout status deployment/oauth2-server -n oauth2-server
```

### Docker Compose

```bash
docker compose ps
docker compose logs --tail=100 oauth2-server
docker compose down
docker compose up -d
```

Roll back fast when a deploy correlates with new `5xx`, readiness failures, or broken admin login.

## Readiness failing

Work this list in order:

1. verify `OAUTH2_DATABASE_URL` and any secret-backed env vars
2. check migration status (`./scripts/migrate.sh` locally, Flyway job in Kubernetes)
3. inspect database logs
4. confirm the app can resolve the database hostname

Useful checks:

```bash
kubectl logs postgres-0 -n oauth2-server --tail=100
kubectl get job -n oauth2-server
kubectl describe pod -n oauth2-server <pod-name>
```

## High `5xx` or latency

Use data before heroics:

1. compare request rate and latency in `/metrics`
2. check recent config or image changes
3. inspect database saturation and connection pressure
4. if eventing is enabled, confirm `/events/health` is not degraded

Focus on:

- request error rate
- request latency percentiles
- database query latency
- rate-limit rejection spikes
- restart counts and rollout events

## Eventing health failing

If `GET /events/health` is unhappy:

1. confirm the configured backend matches the build features
2. verify backend URLs (`OAUTH2_EVENTS_*`)
3. look for fallback warnings in logs

The safe default remains `in_memory`, so a broker failure usually means degraded integration behavior rather than total server death.

## Admin or auth login failures

Check these first:

- seed admin credentials (`OAUTH2_SEED_USERNAME`, `OAUTH2_SEED_PASSWORD`)
- session key stability (`OAUTH2_SESSION_KEY`)
- externally visible URL and proxy headers (`OAUTH2_SERVER_PUBLIC_BASE_URL`, `OAUTH2_SERVER_TRUST_PROXY_HEADERS`)
- social provider configuration for the specific `/auth/login/{provider}` route

Remember that Okta and Auth0 routes currently return `503` by design.

## Rotate signing material

There are two different operations:

- **JWT secret rotation**: rotate `OAUTH2_JWT_SECRET`, redeploy, and expect existing HS256-signed tokens to stop validating
- **keyset rotation**: use `POST /admin/api/keys/rotate` when you are using managed signing keys and an authenticated admin session

After rotation, verify:

```bash
curl -fsS http://localhost:8080/.well-known/jwks.json
curl -fsS http://localhost:8080/health
```

## Revoke everything fast

There is no single “revoke all” endpoint. Your practical options are:

1. rotate JWT secret or signing keys
2. restart with new session and admin credentials if compromise is broader
3. document the incident and the cutoff timestamp

## Backups and restore

Database backup strategy is deployment-specific, so this page does not pretend every team uses the same S3 bucket and cron job.

Use your platform-native Postgres backup process, and verify restores on a non-production environment. For Kubernetes-specific mechanics, use [the Kubernetes README](https://github.com/ianlintner/rust-oauth2-server/blob/main/k8s/README.md).

## Related pages

- [Deployment](deployment.md)
- [Observability](observability.md)
- [Security policy](https://github.com/ianlintner/rust-oauth2-server/blob/main/SECURITY.md)
