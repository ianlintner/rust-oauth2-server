# Metrics

The server exposes Prometheus-compatible metrics at:

- `GET /metrics`

## What you get

Metrics cover:

- HTTP request counts and latency histograms
- OAuth2 token issuance and revocation counters
- Database query counts and latency histograms

In addition, the repo contains **generated SLO recording + alerting rules** (see [SLOs](slos.md)).

See the full list in the project README under **Metrics**.

## Prometheus scrape config

Example `prometheus.yml` snippet:

```yaml
scrape_configs:
  - job_name: oauth2-server
    static_configs:
      - targets: ["localhost:8080"]
```

## Kubernetes

In Kubernetes, you can scrape the service (or pod) via a ServiceMonitor depending on your Prometheus operator setup.

## Troubleshooting

- If `/metrics` is empty, ensure the server started successfully and is receiving traffic.
- For latency spikes, correlate metrics with traces (see [Tracing](tracing.md)).
