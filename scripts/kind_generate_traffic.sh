#!/usr/bin/env bash
set -euo pipefail

# Generate synthetic traffic *inside* a KIND cluster to produce demo metrics/traces.
#
# This creates a Kubernetes Job that runs several load streams against the in-cluster service:
# - POST /oauth/token (client_credentials) with a valid client -> 200s
# - POST /oauth/token with an invalid secret -> 401s
# - GET  /health and /ready -> 200s
#
# Defaults assume you've applied migrations that insert the dev client:
#   client_id=default_client
#   client_secret=INSECURE_DEFAULT_SECRET_REGENERATE_FOR_PRODUCTION
# (see migrations/sql/V5__insert_default_data.sql)

NAMESPACE="oauth2-server"
SERVICE_NAME="oauth2-server"
DURATION="5m"        # hey -z duration format, e.g. 30s, 5m, 1h
QPS_SUCCESS="5"      # requests/sec for successful token requests
CONCURRENCY_SUCCESS="5"
QPS_INVALID="1"      # requests/sec for invalid token requests
CONCURRENCY_INVALID="1"
QPS_HEALTH="1"       # requests/sec for health/ready checks
CONCURRENCY_HEALTH="1"
JOB_NAME=""
DETACH="false"
CLEANUP="true"

usage() {
  cat <<'USAGE'
Usage: ./scripts/kind_generate_traffic.sh [options]

Options:
  --namespace <ns>         Kubernetes namespace (default: oauth2-server)
  --service <name>         Service name (default: oauth2-server)
  --duration <dur>         Test duration (default: 5m). Format: 30s, 5m, 1h

  --qps-success <n>        QPS for successful POST /oauth/token (default: 5)
  --concurrency-success <n>

  --qps-invalid <n>        QPS for invalid-secret POST /oauth/token (default: 1)
  --concurrency-invalid <n>

  --qps-health <n>         QPS for GET /health and /ready (default: 1)
  --concurrency-health <n>

  --job-name <name>        Override generated job name
  --detach                Don't wait for completion / stream logs
  --no-cleanup            Don't delete the Job when finished

Examples:
  ./scripts/kind_generate_traffic.sh
  ./scripts/kind_generate_traffic.sh --duration 15m --qps-success 20 --concurrency-success 10
  ./scripts/kind_generate_traffic.sh --detach --no-cleanup
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --namespace) NAMESPACE="$2"; shift 2;;
    --service) SERVICE_NAME="$2"; shift 2;;
    --duration) DURATION="$2"; shift 2;;

    --qps-success) QPS_SUCCESS="$2"; shift 2;;
    --concurrency-success) CONCURRENCY_SUCCESS="$2"; shift 2;;

    --qps-invalid) QPS_INVALID="$2"; shift 2;;
    --concurrency-invalid) CONCURRENCY_INVALID="$2"; shift 2;;

    --qps-health) QPS_HEALTH="$2"; shift 2;;
    --concurrency-health) CONCURRENCY_HEALTH="$2"; shift 2;;

    --job-name) JOB_NAME="$2"; shift 2;;
    --detach) DETACH="true"; shift 1;;
    --no-cleanup) CLEANUP="false"; shift 1;;

    -h|--help) usage; exit 0;;
    *) echo "Unknown arg: $1" >&2; usage; exit 2;;
  esac
done

if ! command -v kubectl >/dev/null 2>&1; then
  echo "kubectl is required" >&2
  exit 1
fi

_duration_to_seconds() {
  local v="$1"
  if [[ "${v}" =~ ^[0-9]+$ ]]; then
    echo "${v}"
    return 0
  fi
  if [[ "${v}" =~ ^([0-9]+)([smh])$ ]]; then
    local n="${BASH_REMATCH[1]}"
    local u="${BASH_REMATCH[2]}"
    case "${u}" in
      s) echo "${n}";;
      m) echo "$((n * 60))";;
      h) echo "$((n * 3600))";;
    esac
    return 0
  fi
  echo "Invalid --duration '${v}'. Expected: 30s, 5m, 1h" >&2
  return 1
}

_require_positive_int() {
  local name="$1"
  local value="$2"
  if ! [[ "${value}" =~ ^[0-9]+$ ]] || [[ "${value}" -le 0 ]]; then
    echo "Invalid ${name}: '${value}' (must be a positive integer)" >&2
    exit 2
  fi
}

_require_positive_int "--qps-success" "${QPS_SUCCESS}"
_require_positive_int "--concurrency-success" "${CONCURRENCY_SUCCESS}"
_require_positive_int "--qps-invalid" "${QPS_INVALID}"
_require_positive_int "--concurrency-invalid" "${CONCURRENCY_INVALID}"
_require_positive_int "--qps-health" "${QPS_HEALTH}"
_require_positive_int "--concurrency-health" "${CONCURRENCY_HEALTH}"

DURATION_SECONDS="$(_duration_to_seconds "${DURATION}")"

# Pick a predictable-but-unique name.
if [[ -z "${JOB_NAME}" ]]; then
  JOB_NAME="oauth2-traffic-$(date +%Y%m%d%H%M%S)"
fi

BASE_URL="http://${SERVICE_NAME}.${NAMESPACE}.svc.cluster.local"
TOKEN_URL="${BASE_URL}/oauth/token"
HEALTH_URL="${BASE_URL}/health"
READY_URL="${BASE_URL}/ready"

CLIENT_ID="default_client"
CLIENT_SECRET="INSECURE_DEFAULT_SECRET_REGENERATE_FOR_PRODUCTION"

TOKEN_BODY_SUCCESS="grant_type=client_credentials&client_id=${CLIENT_ID}&client_secret=${CLIENT_SECRET}&scope=read"
TOKEN_BODY_INVALID="grant_type=client_credentials&client_id=${CLIENT_ID}&client_secret=WRONG_SECRET&scope=read"

echo "==> Creating traffic Job ${JOB_NAME} in namespace ${NAMESPACE}"
echo "    Target: ${BASE_URL}"

# Ensure namespace exists (no-op if already there).
kubectl get namespace "${NAMESPACE}" >/dev/null 2>&1 || kubectl create namespace "${NAMESPACE}" >/dev/null

# Best-effort cleanup if a Job with same name already exists.
kubectl -n "${NAMESPACE}" delete job "${JOB_NAME}" --ignore-not-found >/dev/null

cat <<EOF | kubectl apply -n "${NAMESPACE}" -f -
apiVersion: batch/v1
kind: Job
metadata:
  name: ${JOB_NAME}
  labels:
    app: oauth2-traffic
spec:
  backoffLimit: 0
  template:
    metadata:
      labels:
        app: oauth2-traffic
    spec:
      restartPolicy: Never
      containers:
        - name: token-success
          image: curlimages/curl:8.10.1
          command: ["/bin/sh","-c"]
          env:
            - name: DURATION_SECONDS
              value: "${DURATION_SECONDS}"
            - name: QPS
              value: "${QPS_SUCCESS}"
            - name: CONCURRENCY
              value: "${CONCURRENCY_SUCCESS}"
            - name: URL
              value: "${TOKEN_URL}"
            - name: METHOD
              value: "POST"
            - name: CONTENT_TYPE
              value: "application/x-www-form-urlencoded"
            - name: BODY
              value: "${TOKEN_BODY_SUCCESS}"
          args:
            - |
              set -euo pipefail
              : "${DURATION_SECONDS:?}" "${QPS:?}" "${CONCURRENCY:?}" "${URL:?}"
              if [ "${QPS}" -le 0 ] || [ "${CONCURRENCY}" -le 0 ]; then
                echo "QPS and CONCURRENCY must be > 0" >&2
                exit 2
              fi
              END=$(( $(date +%s) + DURATION_SECONDS ))
              # Each worker sends ~QPS/CONCURRENCY requests/sec
              SLEEP_S=$(awk -v c="${CONCURRENCY}" -v q="${QPS}" 'BEGIN { printf "%.4f", (c / q) }')
              export END SLEEP_S URL METHOD CONTENT_TYPE BODY
              echo "Starting load: method=${METHOD} url=${URL} duration=${DURATION_SECONDS}s qps=${QPS} concurrency=${CONCURRENCY} sleep=${SLEEP_S}s"
              seq 1 "${CONCURRENCY}" | xargs -n1 -P"${CONCURRENCY}" sh -c '
                while [ "$(date +%s)" -lt "${END}" ]; do
                  curl -sS -o /dev/null \
                    --connect-timeout 2 --max-time 5 \
                    -X "${METHOD}" \
                    -H "Content-Type: ${CONTENT_TYPE}" \
                    --data "${BODY}" \
                    "${URL}" || true
                  sleep "${SLEEP_S}" || true
                done
              '
        - name: token-invalid
          image: curlimages/curl:8.10.1
          command: ["/bin/sh","-c"]
          env:
            - name: DURATION_SECONDS
              value: "${DURATION_SECONDS}"
            - name: QPS
              value: "${QPS_INVALID}"
            - name: CONCURRENCY
              value: "${CONCURRENCY_INVALID}"
            - name: URL
              value: "${TOKEN_URL}"
            - name: METHOD
              value: "POST"
            - name: CONTENT_TYPE
              value: "application/x-www-form-urlencoded"
            - name: BODY
              value: "${TOKEN_BODY_INVALID}"
          args:
            - |
              set -euo pipefail
              : "${DURATION_SECONDS:?}" "${QPS:?}" "${CONCURRENCY:?}" "${URL:?}"
              END=$(( $(date +%s) + DURATION_SECONDS ))
              SLEEP_S=$(awk -v c="${CONCURRENCY}" -v q="${QPS}" 'BEGIN { printf "%.4f", (c / q) }')
              export END SLEEP_S URL METHOD CONTENT_TYPE BODY
              echo "Starting load: method=${METHOD} url=${URL} duration=${DURATION_SECONDS}s qps=${QPS} concurrency=${CONCURRENCY} sleep=${SLEEP_S}s"
              seq 1 "${CONCURRENCY}" | xargs -n1 -P"${CONCURRENCY}" sh -c '
                while [ "$(date +%s)" -lt "${END}" ]; do
                  curl -sS -o /dev/null \
                    --connect-timeout 2 --max-time 5 \
                    -X "${METHOD}" \
                    -H "Content-Type: ${CONTENT_TYPE}" \
                    --data "${BODY}" \
                    "${URL}" || true
                  sleep "${SLEEP_S}" || true
                done
              '
        - name: health
          image: curlimages/curl:8.10.1
          command: ["/bin/sh","-c"]
          env:
            - name: DURATION_SECONDS
              value: "${DURATION_SECONDS}"
            - name: QPS
              value: "${QPS_HEALTH}"
            - name: CONCURRENCY
              value: "${CONCURRENCY_HEALTH}"
            - name: URL
              value: "${HEALTH_URL}"
          args:
            - |
              set -euo pipefail
              : "${DURATION_SECONDS:?}" "${QPS:?}" "${CONCURRENCY:?}" "${URL:?}"
              END=$(( $(date +%s) + DURATION_SECONDS ))
              SLEEP_S=$(awk -v c="${CONCURRENCY}" -v q="${QPS}" 'BEGIN { printf "%.4f", (c / q) }')
              export END SLEEP_S URL
              echo "Starting load: GET url=${URL} duration=${DURATION_SECONDS}s qps=${QPS} concurrency=${CONCURRENCY} sleep=${SLEEP_S}s"
              seq 1 "${CONCURRENCY}" | xargs -n1 -P"${CONCURRENCY}" sh -c '
                while [ "$(date +%s)" -lt "${END}" ]; do
                  curl -sS -o /dev/null \
                    --connect-timeout 2 --max-time 5 \
                    "${URL}" || true
                  sleep "${SLEEP_S}" || true
                done
              '
        - name: ready
          image: curlimages/curl:8.10.1
          command: ["/bin/sh","-c"]
          env:
            - name: DURATION_SECONDS
              value: "${DURATION_SECONDS}"
            - name: QPS
              value: "${QPS_HEALTH}"
            - name: CONCURRENCY
              value: "${CONCURRENCY_HEALTH}"
            - name: URL
              value: "${READY_URL}"
          args:
            - |
              set -euo pipefail
              : "${DURATION_SECONDS:?}" "${QPS:?}" "${CONCURRENCY:?}" "${URL:?}"
              END=$(( $(date +%s) + DURATION_SECONDS ))
              SLEEP_S=$(awk -v c="${CONCURRENCY}" -v q="${QPS}" 'BEGIN { printf "%.4f", (c / q) }')
              export END SLEEP_S URL
              echo "Starting load: GET url=${URL} duration=${DURATION_SECONDS}s qps=${QPS} concurrency=${CONCURRENCY} sleep=${SLEEP_S}s"
              seq 1 "${CONCURRENCY}" | xargs -n1 -P"${CONCURRENCY}" sh -c '
                while [ "$(date +%s)" -lt "${END}" ]; do
                  curl -sS -o /dev/null \
                    --connect-timeout 2 --max-time 5 \
                    "${URL}" || true
                  sleep "${SLEEP_S}" || true
                done
              '
EOF

if [[ "${DETACH}" == "true" ]]; then
  echo "==> Job started (detach mode)."
  echo "    Watch: kubectl -n ${NAMESPACE} get pods -l job-name=${JOB_NAME}"
  echo "    Logs:  kubectl -n ${NAMESPACE} logs -l job-name=${JOB_NAME} -c token-success --tail=50 -f"
  exit 0
fi

echo "==> Waiting for Pod to start"
kubectl -n "${NAMESPACE}" wait --for=condition=Ready pod -l job-name="${JOB_NAME}" --timeout=2m >/dev/null || true

echo "==> Streaming logs (token-success) for quick feedback"
kubectl -n "${NAMESPACE}" logs -l job-name="${JOB_NAME}" -c token-success --tail=20 -f || true

echo "==> Waiting for Job completion"
# This will typically complete when all containers exit after -z duration.
kubectl -n "${NAMESPACE}" wait --for=condition=complete job/"${JOB_NAME}" --timeout=30m >/dev/null || true

echo "==> Summary logs"
for c in token-success token-invalid health ready; do
  echo "--- container: ${c} ---"
  kubectl -n "${NAMESPACE}" logs -l job-name="${JOB_NAME}" -c "${c}" --tail=5 || true
done

if [[ "${CLEANUP}" == "true" ]]; then
  echo "==> Cleaning up Job ${JOB_NAME}"
  kubectl -n "${NAMESPACE}" delete job "${JOB_NAME}" >/dev/null || true
fi

echo "==> Done"
