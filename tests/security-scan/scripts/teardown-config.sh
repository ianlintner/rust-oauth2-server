#!/usr/bin/env bash
set -euo pipefail

PF_PID="${1:-}"
CLUSTER_NAME="${CLUSTER_NAME:-oauth2-security}"
NAMESPACE="${NAMESPACE:-security-scan}"

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
KUBECONFIG="${KUBECONFIG:-${ROOT_DIR}/.kube/kind-kubeconfig}"
export KUBECONFIG

if [[ -n "${PF_PID}" ]]; then
  kill "${PF_PID}" 2>/dev/null || true
fi

kubectl --kubeconfig "${KUBECONFIG}" --context "kind-${CLUSTER_NAME}" \
  delete namespace "${NAMESPACE}" --ignore-not-found 2>/dev/null || true
