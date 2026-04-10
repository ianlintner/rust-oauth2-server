#!/usr/bin/env bash
set -euo pipefail

CONFIGS=("prod-hardened" "dev-relaxed" "misconfig-cors" "misconfig-auth" "edge-empty")
CLUSTER_NAME="${CLUSTER_NAME:-oauth2-security}"
NAMESPACE="${NAMESPACE:-security-scan}"
BUDGET_MINUTES="${BUDGET_MINUTES:-30}"
SKIP_IMAGE_BUILD="${SKIP_IMAGE_BUILD:-0}"

_usage() {
  cat <<'USAGE'
Usage: tests/security-scan/scripts/security-scan.sh [OPTIONS]

Options:
  --matrix all|<config>   Run all configs or a single config (default: all)
  --budget Nm             Wall-clock budget in minutes (default: 30)
  --skip-build            Skip Docker image build
  -h, --help              Show this help

Environment:
  CLUSTER_NAME     (default: oauth2-security)
  NAMESPACE        (default: security-scan)
USAGE
}

MATRIX="all"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --matrix) MATRIX="$2"; shift 2 ;;
    --budget) BUDGET_MINUTES="${2%m}"; shift 2 ;;
    --skip-build) SKIP_IMAGE_BUILD=1; shift ;;
    -h|--help) _usage; exit 0 ;;
    *) echo "Unknown: $1" >&2; _usage >&2; exit 2 ;;
  esac
done

if [[ "$MATRIX" != "all" ]]; then
  CONFIGS=("$MATRIX")
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
SCRIPTS_DIR="${ROOT_DIR}/tests/security-scan/scripts"
REPORT_DIR="${ROOT_DIR}/reports/security-scan"
mkdir -p "$REPORT_DIR"

START_TIME=$(date +%s)
deadline=$((START_TIME + BUDGET_MINUTES * 60))

_budget_ok() {
  [[ $(date +%s) -lt $deadline ]]
}

# Pre-flight
for cmd in docker kind kubectl kustomize jq curl python3; do
  command -v "$cmd" >/dev/null 2>&1 || { echo "Missing: $cmd" >&2; exit 1; }
done

export CLUSTER_NAME NAMESPACE SKIP_IMAGE_BUILD

echo "========================================"
echo "  Security Scan — $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "  Configs: ${CONFIGS[*]}"
echo "  Budget: ${BUDGET_MINUTES}m"
echo "========================================"

ALL_RESULTS=()

for config in "${CONFIGS[@]}"; do
  if ! _budget_ok; then
    echo "Budget exceeded, stopping before config: ${config}"
    break
  fi

  echo ""
  echo "========== Config: ${config} =========="

  # Deploy
  deploy_json=$(bash "${SCRIPTS_DIR}/deploy-config.sh" "${config}")
  status=$(echo "$deploy_json" | jq -r '.status')
  base_url=$(echo "$deploy_json" | jq -r '.base_url')
  pf_pid=$(echo "$deploy_json" | jq -r '.pf_pid // empty')

  if [[ "$status" == "startup_failed" ]]; then
    echo "Config ${config} failed to start (expected for edge-empty)"
    mkdir -p "${REPORT_DIR}/${config}"
    echo "$deploy_json" > "${REPORT_DIR}/${config}/deploy-result.json"
    ALL_RESULTS+=("${REPORT_DIR}/${config}/deploy-result.json")
    continue
  fi

  if [[ "$status" != "ready" ]]; then
    echo "Deploy failed for ${config}: ${deploy_json}" >&2
    continue
  fi

  # Run scanners
  output_dir=$(bash "${SCRIPTS_DIR}/run-scanners.sh" "${base_url}" "${config}" || true)
  if [[ -d "$output_dir" ]]; then
    ALL_RESULTS+=("${output_dir}/all-findings.json")
  fi

  # Teardown
  bash "${SCRIPTS_DIR}/teardown-config.sh" "${pf_pid}" || true
done

# Merge all results
FINAL_REPORT="${REPORT_DIR}/all-configs-findings.json"
if [[ ${#ALL_RESULTS[@]} -gt 0 ]]; then
  jq -s 'flatten' "${ALL_RESULTS[@]}" > "$FINAL_REPORT" 2>/dev/null || echo "[]" > "$FINAL_REPORT"
  total=$(jq '[.[].findings | length] | add // 0' "$FINAL_REPORT")
  echo ""
  echo "========================================"
  echo "  Scan Complete"
  echo "  Total findings: ${total}"
  echo "  Report: ${FINAL_REPORT}"
  echo "========================================"
else
  echo "[]" > "$FINAL_REPORT"
  echo "No scan results collected."
fi

elapsed=$(( $(date +%s) - START_TIME ))
echo "Elapsed: $((elapsed / 60))m $((elapsed % 60))s"
