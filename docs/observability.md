# Observability Runbook

This runbook covers the OpenTelemetry (OTEL) pipeline for `rust_oauth2_server`.
It is written for operators deploying the server and for developers who need to
verify traces during local or staging work. It deliberately does not discuss
Prometheus `/metrics` scraping, which is documented separately under
`k8s/components/observability/` and the Grafana dashboards under
`k8s/components/observability/assets/grafana/`.

## 1. Overview

The server emits traces and metrics via the OpenTelemetry Protocol (OTLP) to a
single, canonical target: an in-cluster **OpenTelemetry Collector**. The
application does not know about any specific backend. Fan-out, tail sampling,
redaction, and vendor-specific exporters all live in the collector.

```
┌────────────────────┐     OTLP/gRPC 4317     ┌────────────────────┐
│ oauth2-server pods │ ─────────────────────▶ │ otel-collector     │
│ (tracing SDK)      │                        │ (batch, tail-sample│
└────────────────────┘                        │  exporters fan-out)│
                                              └────────┬───────────┘
                                                       │
                                ┌──────────────────────┼──────────────────────┐
                                ▼                      ▼                      ▼
                         ┌────────────┐         ┌──────────────┐        ┌─────────────┐
                         │  Tempo     │         │  Datadog     │        │  Jaeger     │
                         │ (storage)  │         │ (opt-in)     │        │ (local dev) │
                         └────────────┘         └──────────────┘        └─────────────┘
```

What is emitted:

- Traces for every HTTP request hitting the actix root span, plus child spans
  for DB queries, Redis commands, outbound HTTP calls made via `reqwest`, and
  event-bus publishes (Kafka, RabbitMQ, Redis Streams).
- Metrics — the OTLP metrics pipeline is enabled alongside traces; scraping
  Prometheus `/metrics` remains the primary path and is unchanged.

What is **not** emitted from the application:

- No direct Jaeger, Zipkin, Datadog, or New Relic exporter lives in the Rust
  workspace. Routing to a specific vendor always goes through the collector.

## 2. Enabling the feature

The `otel` Cargo feature is part of the workspace default feature set. Every
default build — including the release CI pipeline and the Docker image — ships
with the OpenTelemetry SDK compiled in. Traces only emit when
`OTEL_EXPORTER_OTLP_ENDPOINT` (or the legacy `OAUTH2_OTLP_ENDPOINT`) is set at
runtime; with no endpoint configured the SDK is a zero-cost no-op.

Local build (tracing included automatically):

```bash
cargo build --release
```

For a production image, pass the storage backend feature
(see `~/.claude/projects/.../memory/feedback_docker_build_mongo.md` for the
rationale on the MongoDB backend). The `otel` feature comes along for free via
the default set:

```bash
docker build \
  --build-arg CARGO_FEATURES=mongo \
  -t docker.io/ianlintner068/oauth2-server:<tag> \
  .
```

Opting **out** of tracing (smaller binary, no OTEL dependencies compiled in) is
available for teams that need a minimal build:

```bash
cargo build --release --no-default-features --features sqlx        # or mongo
```

The release CI pipeline (`.github/scripts/build_release_binaries.sh`) builds
the `default`, `mongo`, and `mongo-only` variants; all three include `otel`
after the default-feature flip. Non-OTEL variants are not published from CI —
users who need them should run the `--no-default-features` build locally.

## 3. Required environment variables

The server recognises both the standard OpenTelemetry env vars and a legacy
alias. The canonical block lives in `.env.example`:

```
OTEL_EXPORTER_OTLP_ENDPOINT=             # empty = telemetry disabled
OAUTH2_OTLP_ENDPOINT=                    # legacy alias, still honored
OTEL_EXPORTER_OTLP_PROTOCOL=grpc         # grpc | http/protobuf
OTEL_SERVICE_NAME=oauth2_server
OTEL_PROPAGATORS=tracecontext,baggage
OTEL_TRACES_SAMPLER=parentbased_always_on
POD_NAMESPACE=                           # Downward API in-cluster
IMAGE_SHA=                               # injected by CI
DEPLOYMENT_ENVIRONMENT=dev
RUST_LOG=info
```

Leaving `OTEL_EXPORTER_OTLP_ENDPOINT` unset disables the OTLP pipeline
cleanly — the server continues running and emits structured JSON logs only.

## 4. Resource attributes

The following resource attributes are set on every span and metric:

| Attribute                | Source                                                            |
| ------------------------ | ----------------------------------------------------------------- |
| `service.name`           | `OTEL_SERVICE_NAME` or the `app.kubernetes.io/name` pod label     |
| `service.namespace`      | `POD_NAMESPACE` via Kubernetes Downward API                       |
| `service.version`        | `IMAGE_SHA` injected by CI at deploy time                         |
| `deployment.environment` | Set per overlay (`dev`, `staging`, `prod`)                        |

In Kubernetes these are wired through the Downward API plus a CI-populated
placeholder. The production overlay (`k8s/overlays/production`) contains the
canonical patch:

```yaml
env:
  - name: OTEL_SERVICE_NAME
    valueFrom:
      fieldRef:
        fieldPath: "metadata.labels['app.kubernetes.io/name']"
  - name: OTEL_RESOURCE_ATTRIBUTES
    value: "service.namespace=$(POD_NAMESPACE),deployment.environment=prod,service.version=$(IMAGE_SHA)"
  - name: POD_NAMESPACE
    valueFrom:
      fieldRef:
        fieldPath: metadata.namespace
  - name: IMAGE_SHA
    value: "sha-REPLACE_AT_DEPLOY"   # CI overwrites before apply
```

## 5. Sampling

The SDK is configured for `parentbased_always_on`. That is a deliberate choice,
not an accident: we want complete traces when something is already being
sampled upstream (Istio, oauth2-proxy) and we want the collector — not the app
— to make the cost/keep decision.

Tail sampling happens at the collector. The collector decides to keep a trace
based on its outcome (errors, latency, slow DB spans) rather than dropping
spans at the source. This keeps the application hot path cheap and preserves
the full context of interesting traces.

## 6. What is traced

| Area                    | Span name pattern                        | Notes                                                                 |
| ----------------------- | ---------------------------------------- | --------------------------------------------------------------------- |
| HTTP entrypoints        | `actix_web.request` (root)               | Added by the actix tracing layer; includes `http.*` semconv.          |
| SQL (SQLite, PostgreSQL)| `db.query <statement-prefix>`            | `db.system`, `db.statement`, `db.name` attributes (Wave 1.1).         |
| MongoDB                 | `db.mongodb.<command>`                   | `db.system=mongodb`, `db.operation` (Wave 1.2).                       |
| Redis (cache, rate limit)| `redis.<command>`                       | `db.system=redis`, `db.operation` (Wave 1.3).                         |
| Outbound HTTP (reqwest) | `HTTP <method> <host>`                   | W3C context injected on outgoing requests (Wave 1.4, social-login).   |
| Event bus publish       | `event.publish <backend>`                | Kafka/RabbitMQ headers, Redis Streams via envelope field (Wave 1.5).  |

## 7. Log to trace linking

The JSON log formatter attaches `trace_id` and `span_id` to every log line when
a span is active. That makes it easy to click from a log entry in Loki/ELK/
Datadog straight into the matching trace in Tempo/Jaeger.

If you see logs without these fields, either the `otel` feature is not
compiled in, or `OTEL_EXPORTER_OTLP_ENDPOINT` is empty, in which case the
tracing subscriber never attaches the OTEL layer.

## 8. Routing to Datadog without a rebuild (Path A)

The application has no vendor-specific exporter and is not going to gain one.
To route traces to Datadog:

1. Keep the application unchanged.
2. Add a `datadog` exporter to the collector pipeline.

Sample collector snippet (drop into the existing
`k8s/components/observability/otel/otel-collector.yml`):

```yaml
exporters:
  datadog:
    api:
      site: datadoghq.com
      key: ${env:DD_API_KEY}

service:
  pipelines:
    traces:
      receivers: [otlp]
      processors: [batch]
      exporters: [otlp/jaeger, datadog]
```

`DD_API_KEY` should come from a Kubernetes Secret mounted on the collector
Pod. The application pods never see it. This is what "Path A" means in the
OTEL rollout plan: switch vendors by editing the collector, not by rebuilding
and redeploying the server.

## 9. Verifying traces land in Tempo

Local or KIND (the `e2e-kind-observability` overlay wires the full stack):

```bash
# Port-forward the collector and Tempo (adjust svc names if different).
kubectl -n default port-forward svc/otel-collector 4317:4317 &
kubectl -n default port-forward svc/tempo 3200:3200 &

# Exercise the server so it emits a trace.
curl -sS http://localhost:8080/.well-known/openid-configuration > /dev/null

# Query Tempo by service name.
curl -sS "http://localhost:3200/api/search?q=%7Bresource.service.name%3D%22oauth2-server%22%7D" | jq .
```

A successful run returns a non-empty `traces` array. Drill in with
`/api/traces/<traceID>` or use the Grafana Explore UI.

### Local smoke test

Reproduce the trace shape the `tests/otel_trace_propagation.rs` integration
test asserts (root HTTP span → `actor.token.create` → `db.query`
`db.system=sqlite`) against a real collector on your workstation:

```bash
# 1. Start a single-node Tempo with OTLP/gRPC and the Tempo query API exposed.
docker run --rm -p 4317:4317 -p 3200:3200 \
  grafana/tempo:latest -config.file=/etc/tempo/tempo.yaml

# 2. Point the server at it. Add to `.env` or export inline:
export OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4317

# 3. Run the server with OTEL enabled.
cargo run

# 4. In a second shell, exercise the `/token` path with a seeded client.
curl -sS -X POST http://localhost:8080/oauth/token \
  -d grant_type=client_credentials \
  -d client_id=demo-client -d client_secret=demo-secret -d scope=read

# 5. Search Tempo for the trace the server just emitted.
curl -sS 'http://localhost:3200/api/search?q=%7Bresource.service.name%3D%22oauth2_server%22%7D&limit=5' \
  | jq '.traces[0]'
```

Inside the returned trace you should see the same parent/child shape the
integration test asserts on. When running against the repo's Docker Compose
observability stack, replace `localhost` with the collector/Tempo service
hostnames defined there.

### Production (AKS "bigboy")

The production cluster is applied via raw `kubectl` rather than Flux or Argo,
so the production overlays in this repo are authoritative reference material
but are not auto-synced. When changing the OTEL env block in
`k8s/overlays/production/observability-patch.yaml`, also copy the new block
into whatever manifest is applied against the `bigboy` context to keep the two
in sync.

## 10. Anti-patterns

Do **not**:

- Import a vendor-specific OTEL exporter into the Rust workspace.
  Routing changes belong in the collector.
- Point the server directly at Tempo, Jaeger, or Zipkin. Always go via the
  collector so tail sampling, retries, and batching apply.
- Put PII in span attributes. User IDs, client IDs, and trace/span IDs only;
  no email addresses, no passwords, no tokens, no request bodies.
- Set `OTEL_TRACES_SAMPLER=always_off` in production as a way to silence
  volume. Silence it at the collector with tail sampling instead; the
  application still needs to emit so the collector can decide.
- Disable propagation (`OTEL_PROPAGATORS=none`) to "simplify". That breaks
  cross-service correlation with Istio, oauth2-proxy, and any downstream
  service that honours W3C context.
- Build release images without `otel` and then wonder why traces do not appear.
  Verify with `cargo tree | grep opentelemetry` first (default build includes OTEL).
