# Observability (Local)

This folder contains **local** observability configuration for:

- Prometheus (metrics scrape + rule files)
- Grafana (provisioned datasource + dashboards)
- OpenTelemetry Collector (OTLP receiver)
- Jaeger (trace storage + UI)

## What you get

- **Metrics**: the OAuth2 server exposes Prometheus metrics at `GET /metrics`.
- **Traces**: the OAuth2 server exports OTLP spans when `OTEL_EXPORTER_OTLP_ENDPOINT` (or `OAUTH2_OTLP_ENDPOINT`) is set.
- **SLOs**: Prometheus SLO recording + alerting rules generated from a Sloth spec.

## Ports

- Grafana: http://localhost:3000 (admin / admin)
- Prometheus: http://localhost:9090
- Jaeger UI: http://localhost:16686

## Notes

- The repo keeps using Prometheus for metrics exposition.
- Traces can go directly to Jaeger (`OAUTH2_OTLP_ENDPOINT=http://jaeger:4317`) or via the collector (`OTEL_EXPORTER_OTLP_ENDPOINT=http://otel_collector:4317`).

### SLO rule generation (Sloth)

SLOs are defined in `observability/slo/sloth/` and turned into Prometheus rule files in `observability/prometheus/rules/`.

To regenerate:

- `./scripts/generate_slo_rules.sh`

Prometheus loads all `*.yml` under `/etc/prometheus/rules` (see `observability/prometheus/prometheus.yml`).
