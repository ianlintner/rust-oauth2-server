#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${1:?Usage: error-leakage.sh <base_url> <config_name> <output_file>}"
CONFIG_NAME="${2:?}"
OUTPUT_FILE="${3:?}"

TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
findings="[]"

_add_finding() {
  local id="$1" severity="$2" title="$3" evidence="$4"
  findings=$(echo "$findings" | jq --arg id "$id" --arg sev "$severity" \
    --arg title "$title" --argjson ev "$evidence" \
    '. + [{"id":$id,"severity":$sev,"category":"runtime","title":$title,"evidence":$ev,"reproducible":null,"follow_up_suggested":true}]')
}

_check_leakage() {
  local label="$1" body="$2" url="$3"
  # Check for stack traces, SQL, internal paths
  if echo "$body" | grep -qiE '(stack trace|backtrace|panic|thread.*panicked)'; then
    _add_finding "LEAK-STACK-${label}" "high" "Stack trace in response from ${url}" \
      "{\"url\":\"${url}\",\"snippet\":$(echo "$body" | head -5 | jq -Rs .)}"
  fi
  if echo "$body" | grep -qiE '(SELECT.*FROM|INSERT.*INTO|UPDATE.*SET|syntax error.*sql|pg_|postgresql)'; then
    _add_finding "LEAK-SQL-${label}" "high" "SQL fragment in response from ${url}" \
      "{\"url\":\"${url}\",\"snippet\":$(echo "$body" | head -5 | jq -Rs .)}"
  fi
  if echo "$body" | grep -qiE '(/app/|/home/|/usr/|\.rs:|src/)'; then
    _add_finding "LEAK-PATH-${label}" "medium" "Internal path in response from ${url}" \
      "{\"url\":\"${url}\",\"snippet\":$(echo "$body" | head -5 | jq -Rs .)}"
  fi
}

# Malformed requests
endpoints=(
  "GET /oauth/token"
  "POST /oauth/token"
  "GET /auth/login?return_to=javascript:alert(1)"
  "POST /auth/login"
  "GET /admin/clients/register"
  "GET /nonexistent/path"
  "POST /oauth/introspect"
)

for ep in "${endpoints[@]}"; do
  method="${ep%% *}"
  path="${ep#* }"
  url="${BASE_URL}${path}"
  body=$(curl -sS -X "${method}" "${url}" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "invalid=%%%malformed&grant_type=<script>alert(1)</script>" \
    2>/dev/null || echo "")
  _check_leakage "${method}-$(echo "$path" | tr '/' '-')" "$body" "$url"
done

# Check /metrics for PII/secrets
metrics=$(curl -sS "${BASE_URL}/metrics" 2>/dev/null || echo "")
if echo "$metrics" | grep -qiE '(password|secret|token_value|jwt|session_key)'; then
  _add_finding "LEAK-METRICS-001" "high" "Potential secret/PII in /metrics" \
    "{\"endpoint\":\"/metrics\",\"snippet\":$(echo "$metrics" | grep -iE '(password|secret)' | head -3 | jq -Rs .)}"
fi

jq -n --arg scanner "error-leakage" --arg config "$CONFIG_NAME" \
  --arg ts "$TIMESTAMP" --argjson findings "$findings" \
  '{"scanner":$scanner,"config":$config,"timestamp":$ts,"findings":$findings}' > "$OUTPUT_FILE"

echo "Error leakage: $(echo "$findings" | jq length) findings for ${CONFIG_NAME}"
