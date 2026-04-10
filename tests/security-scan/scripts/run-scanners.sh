#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${1:?Usage: run-scanners.sh <base_url> <config_name>}"
CONFIG_NAME="${2:?}"

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
SCANNERS_DIR="${ROOT_DIR}/tests/security-scan/scanners"
SCENARIOS_DIR="${ROOT_DIR}/tests/security-scan/scenarios/${CONFIG_NAME}"
OUTPUT_DIR="${ROOT_DIR}/reports/security-scan/${CONFIG_NAME}/$(date +%Y%m%d-%H%M%S)"
mkdir -p "$OUTPUT_DIR"

echo "==> Running scanners for config: ${CONFIG_NAME}"
echo "    Base URL: ${BASE_URL}"
echo "    Output:   ${OUTPUT_DIR}"

# Authenticate for scanners that need it
COOKIE_JAR="/tmp/security-scan-cookies-${CONFIG_NAME}.txt"
curl -sS -X POST "${BASE_URL}/auth/login" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "username=${OAUTH2_SEED_USERNAME:-admin}" \
  --data-urlencode "password=${OAUTH2_SEED_PASSWORD:-changeme}" \
  -c "${COOKIE_JAR}" -o /dev/null 2>/dev/null || true

# Run scanners in parallel
pids=()

bash "${SCANNERS_DIR}/flow-tester.sh" "$BASE_URL" "$CONFIG_NAME" "$SCENARIOS_DIR" "${OUTPUT_DIR}/flow-tester.json" &
pids+=($!)

python3 "${SCANNERS_DIR}/timing-analyzer.py" --base-url "$BASE_URL" --config "$CONFIG_NAME" \
  --samples 30 --output "${OUTPUT_DIR}/timing-analyzer.json" &
pids+=($!)

bash "${SCANNERS_DIR}/error-leakage.sh" "$BASE_URL" "$CONFIG_NAME" "${OUTPUT_DIR}/error-leakage.json" &
pids+=($!)

python3 "${SCANNERS_DIR}/token-entropy.py" --base-url "$BASE_URL" --config "$CONFIG_NAME" \
  --cookie-jar "${COOKIE_JAR}" --count 20 --output "${OUTPUT_DIR}/token-entropy.json" &
pids+=($!)

# Wait for all scanners
failed=0
for pid in "${pids[@]}"; do
  if ! wait "$pid"; then
    echo "Scanner PID $pid failed" >&2
    ((failed++)) || true
  fi
done

# Merge all findings
jq -s '.' "${OUTPUT_DIR}"/*.json > "${OUTPUT_DIR}/all-findings.json"

total=$(jq '[.[].findings | length] | add // 0' "${OUTPUT_DIR}/all-findings.json")
echo "==> Scan complete: ${total} total findings across all scanners"
echo "${OUTPUT_DIR}"

exit $failed
