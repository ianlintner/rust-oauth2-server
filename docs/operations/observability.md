# Observability

## For AI Agents

> **Prompt:** "Set up observability for the rust-oauth2-server with Prometheus metrics, health checks, and OpenTelemetry tracing"

**Common observability tasks:**

| Task | Prompt Example |
|------|----------------|
| Check health | "Verify the OAuth2 server is healthy and responding" |
| View metrics | "Show me the current Prometheus metrics from the server" |
| Set up monitoring | "Configure Prometheus to scrape metrics from the OAuth2 server" |
| Enable tracing | "Enable OpenTelemetry tracing and export to Jaeger" |
| Debug performance | "Check the metrics for slow token endpoint responses" |
| Monitor rate limits | "Show metrics for rate limit rejections and current usage" |
| Event health | "Check the health status of the event backend" |

**Key endpoints:**
- Health check: `GET /health` - Basic liveness probe
- Readiness check: `GET /ready` - Storage readiness (for K8s)
- Metrics: `GET /metrics` - Prometheus format metrics
- Event health: `GET /events/health` - Event backend status

**What's monitored:**
- HTTP request volume, latency, and status codes
- Token operations (issuance, introspection, revocation)
- Actor performance and message processing
- Cache hit/miss rates (when Redis cache enabled)
- Rate limiting rejections
- Circuit breaker states and resilience metrics

---

The observability surface is intentionally small and code-backed:

- liveness: `/health`
- readiness: `/ready`
- metrics: `/metrics`
- eventing health: `/events/health`
- traces: OpenTelemetry export

## Endpoints

| Endpoint         | Purpose                     | Typical use                    |
| ---------------- | --------------------------- | ------------------------------ |
| `/health`        | basic process health        | load balancer or uptime probe  |
| `/ready`         | storage readiness           | Kubernetes readiness probe     |
| `/metrics`       | Prometheus text endpoint    | scrape target                  |
| `/events/health` | event backend/plugin health | eventing triage                |
| `/swagger-ui`    | generated API surface       | validation and operator checks |

Example health response:

```json
{
  "status": "healthy",
  "service": "oauth2_server",
  "timestamp": "2026-04-07T12:34:56Z"
}
```

## Metrics

The server exposes Prometheus metrics for:

- HTTP request volume and latency
- token issuance and revocation
- actor- and route-level behavior
- cache efficiency when cache features are enabled
- rate-limit rejections when rate limiting is enabled
- resilience middleware state (circuit breaker transitions, back-pressure rejections, bulkhead utilization) when `OAUTH2_RESILIENCE_ENABLED=true`

Use `/metrics` directly for raw output, or wire the bundled observability stack.

## Local observability stack

Bring up the bundled observability services:

```bash
docker compose -f docker-compose.observability.yml up -d
```

Common local endpoints:

- Grafana: `http://localhost:3000`
- Prometheus: `http://localhost:9090`
- Jaeger: `http://localhost:16686`

To export traces from the server locally:

```bash
export OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4317
cargo run
```

!!! note
The repo still supports `OAUTH2_OTLP_ENDPOINT` as a compatibility alias in `.env.example`, but standard `OTEL_*` variables are the preferred long-term path.

## What to watch first

If you are operating this service, start with these checks:

1. `/ready` — confirms the storage layer is alive
2. `5xx` rate from `/metrics`
3. request latency percentiles
4. event backend health when eventing is enabled
5. deployment rollouts and recent config changes

## Dashboards and SLO assets

The repo includes ready-to-edit assets under:

- `observability/grafana/`
- `observability/prometheus/`
- `observability/otel/`
- `observability/slo/`

These are the best place to continue if you want dashboards or alert rules rather than prose.

## Benchmarks and performance reports

Performance comparisons are generated into:

- `benchmarks/results/comparison-report.md`
- `benchmarks/results/comparison-data.csv`

The benchmark harness guide lives in the repo-local `benchmarks/README.md` file.

Use the published copy here: [benchmarks/README.md](https://github.com/ianlintner/rust-oauth2-server/blob/main/benchmarks/README.md).

## Related pages

- [Deployment](deployment.md)
- [Runbooks](runbooks.md)
- [Testing](../development/testing.md)
