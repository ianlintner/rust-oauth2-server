#!/usr/bin/env bash
set -euo pipefail

# Local (and CI-compatible) E2E runner using KIND + Kubernetes manifests.
#
# Design goals:
# - Repeatable: starts from a clean namespace and cleans up on exit
# - No repo mutation: does not rewrite k8s/base files
# - macOS-friendly: builds the container image via Dockerfile (Linux build)
# - Low-flake: generous waits + diagnostics on failure

CLUSTER_NAME="${CLUSTER_NAME:-oauth2-test}"
NAMESPACE="${NAMESPACE:-oauth2-server}"
IMAGE_REF="${IMAGE_REF:-docker.io/ianlintner068/oauth2-server:test}"
KUSTOMIZE_DIR="${KUSTOMIZE_DIR:-k8s/overlays/e2e-kind}"
KEEP_CLUSTER="${KEEP_CLUSTER:-0}"
KEEP_NAMESPACE="${KEEP_NAMESPACE:-0}"
SKIP_IMAGE_BUILD="${SKIP_IMAGE_BUILD:-0}"
PORT="${PORT:-}"

_usage() {
  cat <<'USAGE'
Usage: scripts/e2e_kind.sh [--keep-cluster] [--keep-namespace] [--cluster NAME] [--namespace NAME] [--image IMAGE]

Environment overrides:
  CLUSTER_NAME   (default: oauth2-test)
  NAMESPACE      (default: oauth2-server)
  IMAGE_REF      (default: docker.io/ianlintner068/oauth2-server:test)
  KUSTOMIZE_DIR  (default: k8s/overlays/e2e-kind)
  KEEP_CLUSTER   (default: 0)
  KEEP_NAMESPACE (default: 0)
  SKIP_IMAGE_BUILD (default: 0)
  PORT (optional: fixed local port for port-forward)

Notes:
- This script uses kubectl port-forward (no NodePort host port conflicts).
- It tags the locally-built image as IMAGE_REF and loads it into KIND.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --keep-cluster)
      KEEP_CLUSTER=1
      shift
      ;;
    --keep-namespace)
      KEEP_NAMESPACE=1
      shift
      ;;
    --cluster)
      CLUSTER_NAME="$2"
      shift 2
      ;;
    --namespace)
      NAMESPACE="$2"
      shift 2
      ;;
    --image)
      IMAGE_REF="$2"
      shift 2
      ;;
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
_require jq
_require curl

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

# Ensure kubectl always targets the KIND cluster explicitly.
# If kubectl has no current context, it falls back to http://localhost:8080.
# Using a dedicated kubeconfig avoids accidental cross-step/context issues in CI.
KUBECONFIG="${KUBECONFIG:-${ROOT_DIR}/.kube/kind-kubeconfig}"
export KUBECONFIG

_kubectl() {
  kubectl --kubeconfig "${KUBECONFIG}" --context "kind-${CLUSTER_NAME}" "$@"
}

PORT_FWD_PID=""

_cleanup() {
  set +e

  if [[ -n "${PORT_FWD_PID}" ]]; then
    kill "${PORT_FWD_PID}" >/dev/null 2>&1 || true
    wait "${PORT_FWD_PID}" >/dev/null 2>&1 || true
  fi

  if [[ "${KEEP_NAMESPACE}" != "1" ]]; then
    _kubectl delete namespace "${NAMESPACE}" --ignore-not-found >/dev/null 2>&1 || true
  fi

  if [[ "${KEEP_CLUSTER}" != "1" ]]; then
    kind delete cluster --name "${CLUSTER_NAME}" >/dev/null 2>&1 || true
  fi
}

trap _cleanup EXIT INT TERM

_free_port() {
  # Uses Python to ask the OS for an available ephemeral port.
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
  _kubectl get all -n "${NAMESPACE}" -o wide >&2 || true
  echo "\n--- Pods describe" >&2
  _kubectl describe pods -n "${NAMESPACE}" >&2 || true
  echo "\n--- Nodes" >&2
  _kubectl get nodes -o wide >&2 || true
  echo "\n--- kube-system pods" >&2
  _kubectl get pods -n kube-system -o wide >&2 || true
  echo "\n--- Flyway job logs" >&2
  local pods
  pods=$(_kubectl get pods -n "${NAMESPACE}" -l job-name=flyway-migration -o jsonpath='{.items[*].metadata.name}' 2>/dev/null || true)
  for pod in $pods; do
    echo "--- describe pod/${pod}" >&2
    _kubectl describe pod "$pod" -n "${NAMESPACE}" >&2 || true
    echo "--- logs pod/${pod} (init: wait-for-postgres)" >&2
    _kubectl logs "$pod" -n "${NAMESPACE}" -c wait-for-postgres --tail=200 >&2 || true
    echo "--- logs pod/${pod} (container: flyway)" >&2
    _kubectl logs "$pod" -n "${NAMESPACE}" -c flyway --tail=400 >&2 || true
    echo "--- logs pod/${pod} (container: flyway, previous)" >&2
    _kubectl logs "$pod" -n "${NAMESPACE}" -c flyway --previous --tail=400 >&2 || true
  done
  echo "\n--- oauth2-server logs" >&2
  _kubectl logs deployment/oauth2-server -n "${NAMESPACE}" -c oauth2-server --tail=300 >&2 || true
}

_wait_for_cluster_ready() {
  echo "==> Waiting for KIND node readiness" >&2

  # Wait for nodes to report Ready (clears the NotReady taint that blocks scheduling).
  if ! _kubectl wait --for=condition=Ready nodes --all --timeout=180s >/dev/null 2>&1; then
    echo "KIND nodes did not become Ready in time." >&2
    _kubectl get nodes -o wide >&2 || true
    _kubectl describe nodes >&2 || true
    exit 1
  fi

  # CoreDNS is required for most in-cluster name resolution; wait for it to avoid downstream flakes.
  if ! _kubectl wait --for=condition=Ready pod -n kube-system -l k8s-app=kube-dns --timeout=180s >/dev/null 2>&1; then
    echo "CoreDNS did not become ready in time." >&2
    _kubectl get pods -n kube-system -o wide >&2 || true
    _kubectl describe pods -n kube-system >&2 || true
    exit 1
  fi
}

echo "==> Ensuring a clean KIND cluster (${CLUSTER_NAME})"
if kind get clusters | grep -qx "${CLUSTER_NAME}"; then
  echo "Cluster already exists; deleting for repeatability..."
  kind delete cluster --name "${CLUSTER_NAME}"
fi

mkdir -p "$(dirname "${KUBECONFIG}")"
kind create cluster --name "${CLUSTER_NAME}" --kubeconfig "${KUBECONFIG}"

echo "==> Verifying kubectl context (kind-${CLUSTER_NAME})"
kubectl --kubeconfig "${KUBECONFIG}" config use-context "kind-${CLUSTER_NAME}" >/dev/null

# Give the API server a moment and fail fast with a helpful message if kubeconfig/context is wrong.
for _ in {1..30}; do
  if _kubectl cluster-info >/dev/null 2>&1; then
    break
  fi
  sleep 1
done
if ! _kubectl cluster-info >/dev/null 2>&1; then
  echo "kubectl cannot reach the KIND API server (context=kind-${CLUSTER_NAME})." >&2
  echo "KUBECONFIG=${KUBECONFIG}" >&2
  kubectl --kubeconfig "${KUBECONFIG}" config get-contexts >&2 || true
  kind get clusters >&2 || true
  exit 1
fi

_wait_for_cluster_ready

if [[ "${SKIP_IMAGE_BUILD}" == "1" ]]; then
  echo "==> Skipping image build (SKIP_IMAGE_BUILD=1); verifying image exists: ${IMAGE_REF}"
  if ! docker image inspect "${IMAGE_REF}" >/dev/null 2>&1; then
    echo "Image not found locally: ${IMAGE_REF}" >&2
    echo "Either build it first (e.g. via CI Docker build step) or unset SKIP_IMAGE_BUILD." >&2
    exit 1
  fi
else
  echo "==> Building container image (${IMAGE_REF}) using Dockerfile"
  # Build inside Docker so the resulting binary matches the Linux node OS.
  docker build -t "${IMAGE_REF}" -f Dockerfile .
fi

echo "==> Loading image into KIND"
kind load docker-image "${IMAGE_REF}" --name "${CLUSTER_NAME}"

echo "==> Resetting namespace (${NAMESPACE})"
_kubectl delete namespace "${NAMESPACE}" --ignore-not-found || true
_kubectl create namespace "${NAMESPACE}"

echo "==> Deploying manifests via kustomize (${KUSTOMIZE_DIR})"
kustomize build "${KUSTOMIZE_DIR}" | _kubectl apply -n "${NAMESPACE}" -f -

# Ensure migration job is fresh for each run.
_kubectl delete job flyway-migration -n "${NAMESPACE}" --ignore-not-found || true
kustomize build "${KUSTOMIZE_DIR}" | _kubectl apply -n "${NAMESPACE}" -f -

echo "==> Waiting for Postgres readiness"
if ! _kubectl rollout status statefulset/postgres -n "${NAMESPACE}" --timeout=240s; then
  echo "Postgres did not become ready in time." >&2
  _diag
  exit 1
fi

echo "==> Waiting for Flyway migrations"
if ! _kubectl wait --for=condition=complete job/flyway-migration -n "${NAMESPACE}" --timeout=360s; then
  echo "Flyway migration job did not complete in time." >&2
  _diag
  exit 1
fi

echo "==> Waiting for OAuth2 server rollout"
if ! _kubectl rollout status deployment/oauth2-server -n "${NAMESPACE}" --timeout=240s; then
  echo "OAuth2 server did not become ready in time." >&2
  _diag
  exit 1
fi

if [[ -z "${PORT}" ]]; then
  PORT="$(_free_port)"
fi
BASE_URL="http://127.0.0.1:${PORT}"

echo "==> Port-forwarding svc/oauth2-server ${PORT}:80"
_kubectl -n "${NAMESPACE}" port-forward svc/oauth2-server "${PORT}:80" >/tmp/oauth2-port-forward.log 2>&1 &
PORT_FWD_PID=$!

echo "==> Waiting for /health"
for _ in {1..60}; do
  if curl -fsS "${BASE_URL}/health" >/dev/null 2>&1; then
    break
  fi
  sleep 1
  if ! kill -0 "${PORT_FWD_PID}" >/dev/null 2>&1; then
    echo "port-forward exited unexpectedly. Log:" >&2
    tail -200 /tmp/oauth2-port-forward.log >&2 || true
    _diag
    exit 1
  fi
done

curl -fsS "${BASE_URL}/health" >/dev/null
curl -fsS "${BASE_URL}/ready" >/dev/null
curl -fsS "${BASE_URL}/.well-known/openid-configuration" >/dev/null

echo "==> Registering test client"
client_json=$(curl -fsS -X POST "${BASE_URL}/clients/register" \
  -H "Content-Type: application/json" \
  -d '{
    "client_name": "Test Client",
    "redirect_uris": ["http://localhost:3000/callback"],
    "grant_types": ["client_credentials"],
    "scope": "read write"
  }')

echo "$client_json" > /tmp/e2e-client.json
client_id=$(echo "$client_json" | jq -r '.client_id')
client_secret=$(echo "$client_json" | jq -r '.client_secret')

if [[ -z "${client_id}" || "${client_id}" == "null" || -z "${client_secret}" || "${client_secret}" == "null" ]]; then
  echo "Client registration failed: ${client_json}" >&2
  _diag
  exit 1
fi

echo "==> Requesting access token"
token_json=$(curl -fsS -X POST "${BASE_URL}/oauth/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&client_id=${client_id}&client_secret=${client_secret}&scope=read")

echo "$token_json" > /tmp/e2e-token.json
access_token=$(echo "$token_json" | jq -r '.access_token')

if [[ -z "${access_token}" || "${access_token}" == "null" ]]; then
  echo "Token response invalid: ${token_json}" >&2
  _diag
  exit 1
fi

echo "==> Introspecting token"
introspect_json=$(curl -fsS -X POST "${BASE_URL}/oauth/introspect" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "token=${access_token}&client_id=${client_id}&client_secret=${client_secret}")

echo "$introspect_json" > /tmp/e2e-introspect.json
active=$(echo "$introspect_json" | jq -r '.active')

if [[ "${active}" != "true" ]]; then
  echo "Introspection returned inactive: ${introspect_json}" >&2
  _diag
  exit 1
fi

echo "==> Checking /metrics (smoke)"
curl -fsS "${BASE_URL}/metrics" | head -20 >/dev/null

echo "\n✅ E2E OK (cluster=${CLUSTER_NAME}, namespace=${NAMESPACE}, base_url=${BASE_URL})"

if [[ "${KEEP_CLUSTER}" == "1" ]]; then
  echo "(Keeping cluster due to --keep-cluster / KEEP_CLUSTER=1)"
fi
if [[ "${KEEP_NAMESPACE}" == "1" ]]; then
  echo "(Keeping namespace due to --keep-namespace / KEEP_NAMESPACE=1)"
fi
