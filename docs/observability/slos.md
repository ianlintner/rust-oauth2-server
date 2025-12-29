````markdown
# SLOs (Service Level Objectives)

This project treats SLOs as **first-class configuration**.

- SLO definitions live in `observability/slo/sloth/` (human-edited)
- Prometheus recording + alerting rules are **generated** into `observability/prometheus/rules/` (machine-generated)

We use [Sloth](https://github.com/slok/sloth) to generate multi-window, multi-burn-rate alerting rules.

## Current SLOs

The initial SLOs focus on the most critical endpoint: `POST /oauth/token`.

- **Token availability** (30d): objective **99.9%**
  - *Error* = HTTP **5xx** responses
- **Token latency (500ms)** (30d): objective **99%**
  - *Error* = requests slower than **0.5s**
  - Excludes `5xx` from the latency SLI so “the server is broken” doesn’t also count as “the server is slow”

The spec is defined in:

- `observability/slo/sloth/oauth2-server.yml`

## How SLO rules are generated

Run:

```bash
./scripts/generate_slo_rules.sh
```

This script:

1. Validates the Sloth spec.
2. Generates Prometheus rules into:

   - `observability/prometheus/rules/oauth2_server_slos.yml`

The generated file is meant to be committed, so Prometheus can load SLO rules without running Sloth continuously.

### Requirements

- Docker (the script runs `ghcr.io/slok/sloth` in a container)

## How Prometheus loads SLO rules

The local Prometheus configuration includes:

```yaml
rule_files:
  - /etc/prometheus/rules/*.yml
```

And `docker-compose.observability.yml` mounts the repo rule directory:

- `./observability/prometheus/rules` → `/etc/prometheus/rules`

So once you regenerate the rules and restart Prometheus, they’ll be picked up.

## Metric labels used by SLOs

SLOs rely on the labeled HTTP metrics:

- `oauth2_server_http_requests_total_by_route{route,method,status}`
- `oauth2_server_http_request_duration_seconds_by_route_bucket{route,method,status,le}`
- `oauth2_server_http_request_duration_seconds_by_route_count{route,method,status}`

The `route` label comes from Actix route patterns (`match_pattern()`), so for the token endpoint it should match:

- `route="/oauth/token"`

## Next steps (easy additions)

Typical follow-up SLO candidates:

- `GET /oauth/authorize` availability
- Introspection/revocation endpoints (if enabled)
- Admin endpoints (if used in production)

````
