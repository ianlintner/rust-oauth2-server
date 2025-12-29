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
REGENERATE_SLO_RULES="${REGENERATE_SLO_RULES:-0}"
HOLD_OPEN="${HOLD_OPEN:-1}"

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
  REGENERATE_SLO_RULES=1 Regenerate SLO rules via Sloth (default: 0 / use committed rules)
  HOLD_OPEN=0           Exit after printing URLs (default: 1 / keep port-forwards running)

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

_diag() {
  echo "\n--- Diagnostics (namespace=${NAMESPACE})" >&2
  kubectl get all -n "${NAMESPACE}" -o wide >&2 || true
  echo "\n--- Recent events" >&2
  kubectl get events -n "${NAMESPACE}" --sort-by=.lastTimestamp >&2 | tail -100 || true
  echo "\n--- Pods describe" >&2
  kubectl describe pods -n "${NAMESPACE}" >&2 || true
  echo "\n--- Jaeger logs" >&2
  kubectl logs deployment/jaeger -n "${NAMESPACE}" --tail=200 >&2 || true
  echo "\n--- Grafana logs" >&2
  kubectl logs deployment/grafana -n "${NAMESPACE}" --tail=200 >&2 || true
}

_remove_stale_kind_nodes() {
  # If a previous KIND delete left containers behind, they can block cluster recreation.
  # We identify nodes via the standard label KIND sets on Docker containers.
  local nodes
  nodes=$(docker ps -a --filter "label=io.x-k8s.kind.cluster=${CLUSTER_NAME}" --format '{{.ID}}' || true)
  if [[ -n "${nodes}" ]]; then
    echo "Found stale KIND node containers; removing..." >&2
    # shellcheck disable=SC2086
    docker rm -f ${nodes} >/dev/null 2>&1 || true
  fi
}

_ensure_kind_cluster() {
  echo "==> Ensuring KIND cluster (${CLUSTER_NAME})"
  if kind get clusters | grep -qx "${CLUSTER_NAME}"; then
    if [[ "${RECREATE_CLUSTER}" == "1" ]]; then
      echo "Cluster exists; deleting for repeatability (RECREATE_CLUSTER=1)"
      kind delete cluster --name "${CLUSTER_NAME}" >/dev/null 2>&1 || true
    else
      echo "Reusing existing cluster (RECREATE_CLUSTER=0)"
      return 0
    fi
  fi

  # KIND sometimes errors with "node(s) already exist" if Docker containers were left behind.
  if ! kind create cluster --name "${CLUSTER_NAME}" >/dev/null 2>&1; then
    echo "kind create cluster failed; attempting to remove stale node containers and retry..." >&2
    _remove_stale_kind_nodes
    kind delete cluster --name "${CLUSTER_NAME}" >/dev/null 2>&1 || true
    kind create cluster --name "${CLUSTER_NAME}" >/dev/null
  fi
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

if [[ "${REGENERATE_SLO_RULES}" == "1" ]] && [[ -f "${ROOT_DIR}/scripts/generate_slo_rules.sh" ]]; then
  echo "==> Regenerating SLO rules via Sloth (REGENERATE_SLO_RULES=1)"
  if ! "${ROOT_DIR}/scripts/generate_slo_rules.sh" >/dev/null 2>&1; then
    echo "    (Warning: failed to regenerate SLO rules; using committed rules)" >&2
  fi
fi

_ensure_kind_cluster

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
if ! kubectl rollout status deployment/grafana -n "${NAMESPACE}" --timeout=240s >/dev/null; then
  echo "Grafana did not become ready in time." >&2
  _diag
  exit 1
fi
if ! kubectl rollout status deployment/jaeger -n "${NAMESPACE}" --timeout=240s >/dev/null; then
  echo "Jaeger did not become ready in time." >&2
  _diag
  exit 1
fi

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

if [[ "${HOLD_OPEN}" == "1" ]]; then
  # Block forever while port-forwards are alive.
  wait
fi

echo "HOLD_OPEN=0 set; exiting now (port-forwards will be stopped)."
