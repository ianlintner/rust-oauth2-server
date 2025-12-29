#!/usr/bin/env bash
set -euo pipefail

# Extended KIND E2E runner.
#
# Adds a "resource server" deployment that validates Bearer tokens using RFC7662 introspection.
# This covers a practical service-to-service pattern:
#   Service A -> obtains token (client_credentials)
#   Service B -> validates token (introspection) + enforces scope

CLUSTER_NAME="${CLUSTER_NAME:-oauth2-test}"
NAMESPACE="${NAMESPACE:-oauth2-server}"
IMAGE_REF="${IMAGE_REF:-docker.io/ianlintner068/oauth2-server:test}"
KUSTOMIZE_DIR="${KUSTOMIZE_DIR:-k8s/overlays/e2e-kind-extended}"
KEEP_CLUSTER="${KEEP_CLUSTER:-0}"
KEEP_NAMESPACE="${KEEP_NAMESPACE:-0}"
SKIP_IMAGE_BUILD="${SKIP_IMAGE_BUILD:-0}"
PORT="${PORT:-}"

RESOURCE_IMAGE_REF="${RESOURCE_IMAGE_REF:-docker.io/ianlintner068/oauth2-resource-server:test}"
RESOURCE_CONTEXT_DIR="${RESOURCE_CONTEXT_DIR:-examples/resource-server-node}"
RESOURCE_PORT="${RESOURCE_PORT:-}"

_usage() {
  cat <<'USAGE'
Usage: scripts/e2e_kind_extended.sh [--keep-cluster] [--keep-namespace] [--cluster NAME] [--namespace NAME] [--image IMAGE]

Environment overrides:
  CLUSTER_NAME   (default: oauth2-test)
  NAMESPACE      (default: oauth2-server)
  IMAGE_REF      (default: docker.io/ianlintner068/oauth2-server:test)
  KUSTOMIZE_DIR  (default: k8s/overlays/e2e-kind-extended)
  KEEP_CLUSTER   (default: 0)
  KEEP_NAMESPACE (default: 0)
  SKIP_IMAGE_BUILD (default: 0)
  PORT (optional: fixed local port for oauth2-server port-forward)

Resource server overrides:
  RESOURCE_IMAGE_REF (default: docker.io/ianlintner068/oauth2-resource-server:test)
  RESOURCE_CONTEXT_DIR (default: examples/resource-server-node)
  RESOURCE_PORT (optional: fixed local port for resource-server port-forward)
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
_require python3

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

PORT_FWD_PID=""
RS_PORT_FWD_PID=""

_cleanup() {
  set +e

  if [[ -n "${RS_PORT_FWD_PID}" ]]; then
    kill "${RS_PORT_FWD_PID}" >/dev/null 2>&1 || true
    wait "${RS_PORT_FWD_PID}" >/dev/null 2>&1 || true
  fi
  if [[ -n "${PORT_FWD_PID}" ]]; then
    kill "${PORT_FWD_PID}" >/dev/null 2>&1 || true
    wait "${PORT_FWD_PID}" >/dev/null 2>&1 || true
  fi

  if [[ "${KEEP_NAMESPACE}" != "1" ]]; then
    kubectl delete namespace "${NAMESPACE}" --ignore-not-found >/dev/null 2>&1 || true
  fi

  if [[ "${KEEP_CLUSTER}" != "1" ]]; then
    kind delete cluster --name "${CLUSTER_NAME}" >/dev/null 2>&1 || true
  fi
}

trap _cleanup EXIT INT TERM

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
  echo "\n--- Pods describe" >&2
  kubectl describe pods -n "${NAMESPACE}" >&2 || true
  echo "\n--- Flyway job logs" >&2
  local pods
  pods=$(kubectl get pods -n "${NAMESPACE}" -l job-name=flyway-migration -o jsonpath='{.items[*].metadata.name}' 2>/dev/null || true)
  for pod in $pods; do
    echo "--- describe pod/${pod}" >&2
    kubectl describe pod "$pod" -n "${NAMESPACE}" >&2 || true
    echo "--- logs pod/${pod} (init: wait-for-postgres)" >&2
    kubectl logs "$pod" -n "${NAMESPACE}" -c wait-for-postgres --tail=200 >&2 || true
    echo "--- logs pod/${pod} (container: flyway)" >&2
    kubectl logs "$pod" -n "${NAMESPACE}" -c flyway --tail=400 >&2 || true
  done
  echo "\n--- oauth2-server logs" >&2
  kubectl logs deployment/oauth2-server -n "${NAMESPACE}" -c oauth2-server --tail=300 >&2 || true
  echo "\n--- resource-server logs" >&2
  kubectl logs deployment/resource-server -n "${NAMESPACE}" -c resource-server --tail=200 >&2 || true
}

echo "==> Ensuring a clean KIND cluster (${CLUSTER_NAME})"
if kind get clusters | grep -qx "${CLUSTER_NAME}"; then
  echo "Cluster already exists; deleting for repeatability..."
  kind delete cluster --name "${CLUSTER_NAME}"
fi

kind create cluster --name "${CLUSTER_NAME}"

if [[ "${SKIP_IMAGE_BUILD}" == "1" ]]; then
  echo "==> Skipping oauth2-server image build (SKIP_IMAGE_BUILD=1); verifying image exists: ${IMAGE_REF}"
  if ! docker image inspect "${IMAGE_REF}" >/dev/null 2>&1; then
    echo "Image not found locally: ${IMAGE_REF}" >&2
    exit 1
  fi
else
  echo "==> Building oauth2-server container image (${IMAGE_REF}) using Dockerfile"
  docker build -t "${IMAGE_REF}" -f Dockerfile .
fi

echo "==> Building resource-server image (${RESOURCE_IMAGE_REF})"
docker build -t "${RESOURCE_IMAGE_REF}" "${RESOURCE_CONTEXT_DIR}"

echo "==> Loading images into KIND"
kind load docker-image "${IMAGE_REF}" --name "${CLUSTER_NAME}"
kind load docker-image "${RESOURCE_IMAGE_REF}" --name "${CLUSTER_NAME}"

echo "==> Resetting namespace (${NAMESPACE})"
kubectl delete namespace "${NAMESPACE}" --ignore-not-found || true
kubectl create namespace "${NAMESPACE}"

echo "==> Deploying manifests via kustomize (${KUSTOMIZE_DIR})"
kustomize build "${KUSTOMIZE_DIR}" | kubectl apply -n "${NAMESPACE}" -f -

# Ensure migration job is fresh for each run.
kubectl delete job flyway-migration -n "${NAMESPACE}" --ignore-not-found || true
kustomize build "${KUSTOMIZE_DIR}" | kubectl apply -n "${NAMESPACE}" -f -

echo "==> Waiting for Postgres readiness"
kubectl wait --for=condition=ready pod -l app=postgres -n "${NAMESPACE}" --timeout=180s

echo "==> Waiting for Flyway migrations"
if ! kubectl wait --for=condition=complete job/flyway-migration -n "${NAMESPACE}" --timeout=360s; then
  echo "Flyway migration job did not complete in time." >&2
  _diag
  exit 1
fi

echo "==> Waiting for oauth2-server rollout"
if ! kubectl rollout status deployment/oauth2-server -n "${NAMESPACE}" --timeout=240s; then
  echo "OAuth2 server did not become ready in time." >&2
  _diag
  exit 1
fi

echo "==> Waiting for resource-server rollout (initial)"
if ! kubectl rollout status deployment/resource-server -n "${NAMESPACE}" --timeout=180s; then
  echo "resource-server did not become ready in time." >&2
  _diag
  exit 1
fi

if [[ -z "${PORT}" ]]; then
  PORT="$(_free_port)"
fi
BASE_URL="http://127.0.0.1:${PORT}"

if [[ -z "${RESOURCE_PORT}" ]]; then
  RESOURCE_PORT="$(_free_port)"
fi
RS_URL="http://127.0.0.1:${RESOURCE_PORT}"

echo "==> Port-forwarding svc/oauth2-server ${PORT}:80"
kubectl -n "${NAMESPACE}" port-forward svc/oauth2-server "${PORT}:80" >/tmp/oauth2-port-forward.log 2>&1 &
PORT_FWD_PID=$!

echo "==> Port-forwarding svc/resource-server ${RESOURCE_PORT}:80"
kubectl -n "${NAMESPACE}" port-forward svc/resource-server "${RESOURCE_PORT}:80" >/tmp/resource-server-port-forward.log 2>&1 &
RS_PORT_FWD_PID=$!

echo "==> Waiting for oauth2-server /health"
for _ in {1..60}; do
  if curl -fsS "${BASE_URL}/health" >/dev/null 2>&1; then
    break
  fi
  sleep 1
  if ! kill -0 "${PORT_FWD_PID}" >/dev/null 2>&1; then
    echo "oauth2-server port-forward exited unexpectedly. Log:" >&2
    tail -200 /tmp/oauth2-port-forward.log >&2 || true
    _diag
    exit 1
  fi
done

curl -fsS "${BASE_URL}/ready" >/dev/null
curl -fsS "${BASE_URL}/.well-known/openid-configuration" >/dev/null

echo "==> Waiting for resource-server /ready"
for _ in {1..60}; do
  if curl -fsS "${RS_URL}/ready" >/dev/null 2>&1; then
    break
  fi
  sleep 1
  if ! kill -0 "${RS_PORT_FWD_PID}" >/dev/null 2>&1; then
    echo "resource-server port-forward exited unexpectedly. Log:" >&2
    tail -200 /tmp/resource-server-port-forward.log >&2 || true
    _diag
    exit 1
  fi
done

curl -fsS "${RS_URL}/public" >/dev/null

echo "==> Registering test client (client_credentials)"
client_json=$(curl -fsS -X POST "${BASE_URL}/clients/register" \
  -H "Content-Type: application/json" \
  -d '{
    "client_name": "E2E Service Client",
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

echo "==> Patching resource-server introspection credentials"
kubectl -n "${NAMESPACE}" set env deployment/resource-server \
  "OAUTH2_CLIENT_ID=${client_id}" \
  "OAUTH2_CLIENT_SECRET=${client_secret}" >/dev/null

if ! kubectl rollout status deployment/resource-server -n "${NAMESPACE}" --timeout=180s; then
  echo "resource-server did not become ready after env patch." >&2
  _diag
  exit 1
fi

echo "==> Requesting access token (scope=read)"
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

echo "==> Verifying resource-server rejects missing token"
code=$(curl -s -o /dev/null -w '%{http_code}' "${RS_URL}/protected")
if [[ "${code}" != "401" ]]; then
  echo "Expected 401 from resource-server without token, got ${code}" >&2
  _diag
  exit 1
fi

echo "==> Verifying resource-server accepts valid token"
code=$(curl -s -o /dev/null -w '%{http_code}' "${RS_URL}/protected" -H "Authorization: Bearer ${access_token}")
if [[ "${code}" != "200" ]]; then
  echo "Expected 200 from resource-server with token, got ${code}" >&2
  echo "resource-server response:" >&2
  curl -fsS "${RS_URL}/protected" -H "Authorization: Bearer ${access_token}" >&2 || true
  _diag
  exit 1
fi

echo "==> Revoking access token"
# RFC7009: expects 200 OK even if the token is unknown; we still verify via protected call.
curl -fsS -X POST "${BASE_URL}/oauth/revoke" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "token=${access_token}&client_id=${client_id}&client_secret=${client_secret}" >/dev/null

sleep 1

echo "==> Verifying resource-server rejects revoked token"
code=$(curl -s -o /dev/null -w '%{http_code}' "${RS_URL}/protected" -H "Authorization: Bearer ${access_token}")
if [[ "${code}" != "401" ]]; then
  echo "Expected 401 from resource-server with revoked token, got ${code}" >&2
  echo "resource-server response:" >&2
  curl -fsS "${RS_URL}/protected" -H "Authorization: Bearer ${access_token}" >&2 || true
  _diag
  exit 1
fi

echo "==> Checking /metrics (smoke)"
curl -fsS "${BASE_URL}/metrics" | head -20 >/dev/null

echo "\n✅ Extended E2E OK (cluster=${CLUSTER_NAME}, namespace=${NAMESPACE}, base_url=${BASE_URL}, resource_url=${RS_URL})"

if [[ "${KEEP_CLUSTER}" == "1" ]]; then
  echo "(Keeping cluster due to --keep-cluster / KEEP_CLUSTER=1)"
fi
if [[ "${KEEP_NAMESPACE}" == "1" ]]; then
  echo "(Keeping namespace due to --keep-namespace / KEEP_NAMESPACE=1)"
fi
