#!/usr/bin/env bash
set -euo pipefail

# Bring up KIND + oauth2-server + in-cluster observability (Prometheus/Grafana/Jaeger/OTEL).
#
# This is intended for local dev/demo usage where you want a single command to:
# - create or reuse a KIND cluster
# - build + load the oauth2-server image
# - apply the kustomize overlay that includes observability
# - start port-forwards for Grafana + Jaeger UIs
#
# Exit behavior:
# - By default this DOES NOT delete the cluster/namespace.
# - Ctrl-C will stop port-forwards and exit.

CLUSTER_NAME="${CLUSTER_NAME:-oauth2-observability}"
NAMESPACE="${NAMESPACE:-oauth2-server}"
IMAGE_REF="${IMAGE_REF:-docker.io/ianlintner068/oauth2-server:test}"
KUSTOMIZE_DIR="${KUSTOMIZE_DIR:-k8s/overlays/e2e-kind-observability}"

SKIP_IMAGE_BUILD="${SKIP_IMAGE_BUILD:-0}"
RECREATE_CLUSTER="${RECREATE_CLUSTER:-1}"
RECREATE_NAMESPACE="${RECREATE_NAMESPACE:-1}"

GRAFANA_PORT="${GRAFANA_PORT:-}"
JAEGER_PORT="${JAEGER_PORT:-}"
APP_PORT="${APP_PORT:-}"

_usage() {
  cat <<'USAGE'
Usage: scripts/kind_up_observability.sh

Environment overrides:
  CLUSTER_NAME (default: oauth2-observability)
  NAMESPACE    (default: oauth2-server)
  IMAGE_REF    (default: docker.io/ianlintner068/oauth2-server:test)
  KUSTOMIZE_DIR (default: k8s/overlays/e2e-kind-observability)

  SKIP_IMAGE_BUILD=1    Skip docker build (requires IMAGE_REF to exist locally)
  RECREATE_CLUSTER=0    Reuse existing cluster instead of deleting/recreating
  RECREATE_NAMESPACE=0  Reuse existing namespace resources

  GRAFANA_PORT=XXXX  Fixed local port for Grafana port-forward (default: choose free port)
  JAEGER_PORT=XXXX   Fixed local port for Jaeger UI port-forward (default: choose free port)
  APP_PORT=XXXX      Fixed local port for oauth2-server port-forward (default: choose free port)

Notes:
- This command will block (keep port-forwards running) until Ctrl-C.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help)
      _usage
      exit 0
      ;;
    *)
      echo "Unknown arg: $1" >&2
      _usage >&2
      exit 2
      ;;
  esac
done

_require() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "Missing required command: $1" >&2
    exit 1
  }
}

_require docker
_require kind
_require kubectl
_require kustomize
_require python3

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

_free_port() {
  python3 - <<'PY'
import socket
s = socket.socket()
s.bind(('127.0.0.1', 0))
print(s.getsockname()[1])
s.close()
PY
}

PF_GRAFANA_PID=""
PF_JAEGER_PID=""
PF_APP_PID=""

_cleanup() {
  set +e
  for pid in "${PF_GRAFANA_PID}" "${PF_JAEGER_PID}" "${PF_APP_PID}"; do
    if [[ -n "${pid}" ]]; then
      kill "${pid}" >/dev/null 2>&1 || true
      wait "${pid}" >/dev/null 2>&1 || true
    fi
  done
}
trap _cleanup EXIT INT TERM

echo "==> Syncing in-cluster observability assets"
# Keep kustomize component assets in sync (dashboards/rules).
# This does NOT require Sloth; it just copies committed files.
"${ROOT_DIR}/scripts/sync_incluster_observability_assets.sh" >/dev/null

# (Optional) regenerate SLO rules if Docker is available (it is, since KIND uses it).
# If this fails, we still continue with the last committed rules.
if [[ -f "${ROOT_DIR}/scripts/generate_slo_rules.sh" ]]; then
  echo "==> (Optional) Regenerating SLO rules via Sloth"
  if ! "${ROOT_DIR}/scripts/generate_slo_rules.sh" >/dev/null 2>&1; then
    echo "    (Skipping: failed to regenerate SLO rules; using committed rules)"
  fi
fi

echo "==> Ensuring KIND cluster (${CLUSTER_NAME})"
if kind get clusters | grep -qx "${CLUSTER_NAME}"; then
  if [[ "${RECREATE_CLUSTER}" == "1" ]]; then
    echo "Cluster exists; deleting for repeatability (RECREATE_CLUSTER=1)"
    kind delete cluster --name "${CLUSTER_NAME}" >/dev/null
    kind create cluster --name "${CLUSTER_NAME}" >/dev/null
  else
    echo "Reusing existing cluster (RECREATE_CLUSTER=0)"
  fi
else
  kind create cluster --name "${CLUSTER_NAME}" >/dev/null
fi

if [[ "${SKIP_IMAGE_BUILD}" == "1" ]]; then
  echo "==> Skipping image build (SKIP_IMAGE_BUILD=1); verifying image exists: ${IMAGE_REF}"
  docker image inspect "${IMAGE_REF}" >/dev/null 2>&1 || {
    echo "Image not found locally: ${IMAGE_REF}" >&2
    exit 1
  }
else
  echo "==> Building oauth2-server image (${IMAGE_REF})"
  docker build -t "${IMAGE_REF}" -f Dockerfile . >/dev/null
fi

echo "==> Loading image into KIND"
kind load docker-image "${IMAGE_REF}" --name "${CLUSTER_NAME}" >/dev/null

echo "==> Applying kustomize overlay (${KUSTOMIZE_DIR})"
if [[ "${RECREATE_NAMESPACE}" == "1" ]]; then
  kubectl delete namespace "${NAMESPACE}" --ignore-not-found >/dev/null 2>&1 || true
fi

# The overlay sets namespace: oauth2-server, but we still ensure it exists to avoid races.
kubectl get namespace "${NAMESPACE}" >/dev/null 2>&1 || kubectl create namespace "${NAMESPACE}" >/dev/null

kustomize build "${KUSTOMIZE_DIR}" | kubectl apply -f - >/dev/null

# Ensure migration job is fresh for each run.
kubectl delete job flyway-migration -n "${NAMESPACE}" --ignore-not-found >/dev/null 2>&1 || true
kustomize build "${KUSTOMIZE_DIR}" | kubectl apply -f - >/dev/null

echo "==> Waiting for Postgres readiness"
kubectl wait --for=condition=ready pod -l app=postgres -n "${NAMESPACE}" --timeout=180s >/dev/null

echo "==> Waiting for Flyway migrations"
kubectl wait --for=condition=complete job/flyway-migration -n "${NAMESPACE}" --timeout=360s >/dev/null

echo "==> Waiting for oauth2-server rollout"
kubectl rollout status deployment/oauth2-server -n "${NAMESPACE}" --timeout=240s >/dev/null

echo "==> Waiting for Grafana + Jaeger rollouts"
kubectl rollout status deployment/grafana -n "${NAMESPACE}" --timeout=240s >/dev/null
kubectl rollout status deployment/jaeger -n "${NAMESPACE}" --timeout=240s >/dev/null

if [[ -z "${GRAFANA_PORT}" ]]; then
  GRAFANA_PORT="$(_free_port)"
fi
if [[ -z "${JAEGER_PORT}" ]]; then
  JAEGER_PORT="$(_free_port)"
fi
if [[ -z "${APP_PORT}" ]]; then
  APP_PORT="$(_free_port)"
fi

echo "==> Starting port-forwards"
# Log files help debug local port-forward flakiness.
kubectl -n "${NAMESPACE}" port-forward svc/grafana "${GRAFANA_PORT}:3000" >/tmp/grafana-port-forward.log 2>&1 &
PF_GRAFANA_PID=$!

kubectl -n "${NAMESPACE}" port-forward svc/jaeger "${JAEGER_PORT}:16686" >/tmp/jaeger-port-forward.log 2>&1 &
PF_JAEGER_PID=$!

kubectl -n "${NAMESPACE}" port-forward svc/oauth2-server "${APP_PORT}:80" >/tmp/oauth2-port-forward.log 2>&1 &
PF_APP_PID=$!

# Give port-forward a moment to bind.
sleep 1

echo ""
echo "✅ KIND cluster is up with in-cluster observability"
echo ""
echo "Grafana:  http://127.0.0.1:${GRAFANA_PORT}   (admin/admin)"
echo "Jaeger:   http://127.0.0.1:${JAEGER_PORT}"
echo "OAuth2:   http://127.0.0.1:${APP_PORT}"
echo ""
echo "Tip: generate demo traffic for dashboards/SLOs:"
echo "  make kind-observability-traffic"
echo ""
echo "This process will keep running to hold the port-forwards open. Ctrl-C to stop."

# Block forever while port-forwards are alive.
wait
