#!/usr/bin/env bash
set -euo pipefail

CONFIG_NAME="${1:?Usage: deploy-config.sh <config-name>}"
CLUSTER_NAME="${CLUSTER_NAME:-oauth2-security}"
NAMESPACE="${NAMESPACE:-security-scan}"
IMAGE_REF="${IMAGE_REF:-docker.io/example/oauth2-server:test}"
PORT="${PORT:-}"
SKIP_IMAGE_BUILD="${SKIP_IMAGE_BUILD:-0}"
NS_DELETE_TIMEOUT="${NS_DELETE_TIMEOUT:-120}"  # seconds to wait for namespace Terminating → gone

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "$ROOT_DIR"

KUSTOMIZE_DIR="tests/security-scan/configs/${CONFIG_NAME}"
if [[ ! -d "${KUSTOMIZE_DIR}" ]]; then
  echo "Config not found: ${KUSTOMIZE_DIR}" >&2
  exit 1
fi

KUBECONFIG="${KUBECONFIG:-${ROOT_DIR}/.kube/kind-kubeconfig}"
export KUBECONFIG

_kubectl() {
  kubectl --kubeconfig "${KUBECONFIG}" --context "kind-${CLUSTER_NAME}" "$@"
}

_free_port() {
  python3 -c "import socket; s=socket.socket(); s.bind(('127.0.0.1',0)); print(s.getsockname()[1]); s.close()"
}

# Create cluster if needed
if ! kind get clusters 2>/dev/null | grep -qx "${CLUSTER_NAME}"; then
  echo "==> Creating KinD cluster (${CLUSTER_NAME})" >&2
  mkdir -p "$(dirname "${KUBECONFIG}")"
  kind create cluster --name "${CLUSTER_NAME}" --kubeconfig "${KUBECONFIG}" >&2
fi

kubectl --kubeconfig "${KUBECONFIG}" config use-context "kind-${CLUSTER_NAME}" >/dev/null

# Wait for cluster
for _ in {1..30}; do
  _kubectl cluster-info >/dev/null 2>&1 && break
  sleep 1
done

_kubectl wait --for=condition=Ready nodes --all --timeout=180s >/dev/null 2>&1
_kubectl wait --for=condition=Ready pod -n kube-system -l k8s-app=kube-dns --timeout=180s >/dev/null 2>&1

# Build and load image
if [[ "${SKIP_IMAGE_BUILD}" != "1" ]]; then
  echo "==> Building image (${IMAGE_REF})" >&2
  docker build -t "${IMAGE_REF}" -f Dockerfile . 2>&1 | tail -5 >&2
fi
kind load docker-image "${IMAGE_REF}" --name "${CLUSTER_NAME}" >/dev/null 2>&1 || true

# Clean namespace — wait for full deletion before recreating to avoid Terminating races
_kubectl delete namespace "${NAMESPACE}" --ignore-not-found 2>/dev/null || true
_ns_wait_iters=$(( NS_DELETE_TIMEOUT / 2 ))
for _ in $(seq 1 "${_ns_wait_iters}"); do
  _kubectl get namespace "${NAMESPACE}" >/dev/null 2>&1 || break
  sleep 2
done
_kubectl create namespace "${NAMESPACE}" >&2

# Deploy
echo "==> Deploying config: ${CONFIG_NAME}" >&2
kustomize build "${KUSTOMIZE_DIR}" | _kubectl apply -n "${NAMESPACE}" -f - >&2
_kubectl delete job flyway-migration -n "${NAMESPACE}" --ignore-not-found >/dev/null 2>&1 || true
kustomize build "${KUSTOMIZE_DIR}" | _kubectl apply -n "${NAMESPACE}" -f - >&2

# Wait for postgres
echo "==> Waiting for Postgres" >&2
_kubectl rollout status statefulset/postgres -n "${NAMESPACE}" --timeout=240s >&2

# Wait for migration
echo "==> Waiting for migrations" >&2
if ! _kubectl wait --for=condition=complete job/flyway-migration -n "${NAMESPACE}" --timeout=360s >&2; then
  echo "Migration failed" >&2
  _kubectl logs -n "${NAMESPACE}" -l job-name=flyway-migration -c flyway --tail=100 >&2 || true
  exit 1
fi

# Restart deployment for clean start
_kubectl rollout restart deployment/oauth2-server -n "${NAMESPACE}" >&2
echo "==> Waiting for oauth2-server" >&2
if ! _kubectl rollout status deployment/oauth2-server -n "${NAMESPACE}" --timeout=240s >&2; then
  echo "Deployment failed" >&2
  _kubectl describe pods -n "${NAMESPACE}" >&2 || true
  _kubectl logs deployment/oauth2-server -n "${NAMESPACE}" --tail=100 >&2 || true
  # For edge-empty config, deployment failure IS the expected finding
  if [[ "${CONFIG_NAME}" == "edge-empty" ]]; then
    echo '{"config":"edge-empty","status":"startup_failed","base_url":""}'
    exit 0
  fi
  exit 1
fi

# Port forward
if [[ -z "${PORT}" ]]; then
  PORT="$(_free_port)"
fi
BASE_URL="http://127.0.0.1:${PORT}"

_kubectl -n "${NAMESPACE}" port-forward svc/oauth2-server "${PORT}:80" >/tmp/security-scan-pf.log 2>&1 &
PF_PID=$!

healthy=0
for _ in {1..60}; do
  if curl -fsS "${BASE_URL}/health" >/dev/null 2>&1; then
    healthy=1
    break
  fi
  sleep 1
done

if [[ "$healthy" -eq 0 ]]; then
  echo "Health check timed out for config ${CONFIG_NAME}" >&2
  kill "$PF_PID" 2>/dev/null || true
  echo '{"config":"'"${CONFIG_NAME}"'","status":"unhealthy","base_url":"'"${BASE_URL}"'","port":'"${PORT}"',"pf_pid":'"${PF_PID}"'}'
  exit 1
fi

echo '{"config":"'"${CONFIG_NAME}"'","status":"ready","base_url":"'"${BASE_URL}"'","port":'"${PORT}"',"pf_pid":'"${PF_PID}"'}'
