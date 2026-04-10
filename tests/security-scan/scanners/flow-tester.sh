#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${1:?Usage: flow-tester.sh <base_url> <config_name> <scenarios_dir> <output_file>}"
CONFIG_NAME="${2:?}"
SCENARIOS_DIR="${3:?}"
OUTPUT_FILE="${4:?}"

COOKIE_JAR="/tmp/flow-tester-cookies-${CONFIG_NAME}.txt"
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

findings="[]"

_add_finding() {
  local id="$1" severity="$2" title="$3" evidence="$4"
  findings=$(echo "$findings" | jq --arg id "$id" --arg sev "$severity" \
    --arg title "$title" --argjson ev "$evidence" \
    '. + [{"id":$id,"severity":$sev,"category":"application","title":$title,"evidence":$ev,"reproducible":null,"follow_up_suggested":true}]')
}

# Test 1: Health endpoints
for ep in /health /ready /.well-known/openid-configuration; do
  status=$(curl -sS -o /dev/null -w '%{http_code}' "${BASE_URL}${ep}" || echo "000")
  if [[ "$status" != "200" ]]; then
    _add_finding "FLOW-HEALTH-${ep}" "high" "Health endpoint ${ep} returned ${status}" \
      "$(jq -n --arg ep "${ep}" --arg st "${status}" '{"endpoint":$ep,"status":$st}')"
  fi
done

# Test 2: Admin login
login_status=$(curl -sS -X POST "${BASE_URL}/auth/login" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "username=${OAUTH2_SEED_USERNAME:-admin}" \
  --data-urlencode "password=${OAUTH2_SEED_PASSWORD:-changeme}" \
  -c "${COOKIE_JAR}" -o /dev/null -w '%{http_code}' 2>/dev/null || echo "000")

if [[ "$login_status" != "302" ]]; then
  _add_finding "FLOW-LOGIN-001" "medium" "Admin login returned ${login_status} (expected 302)" \
    "$(jq -n --arg ep "/auth/login" --arg st "${login_status}" '{"endpoint":$ep,"status":$st}')"
fi

# Test 3: Client registration without auth
unreg_status=$(curl -sS -X POST "${BASE_URL}/admin/clients/register" \
  -H "Content-Type: application/json" \
  -d '{"client_name":"unauth-test","redirect_uris":["http://evil.com"],"grant_types":["client_credentials"],"scope":"read"}' \
  -o /dev/null -w '%{http_code}' 2>/dev/null || echo "000")

if [[ "$unreg_status" == "200" || "$unreg_status" == "201" ]]; then
  _add_finding "FLOW-AUTH-001" "critical" "Unauthenticated client registration succeeded" \
    "$(jq -n --arg ep "/admin/clients/register" --arg st "${unreg_status}" '{"endpoint":$ep,"status":$st}')"
fi

# Test 4: Open redirect via return_to
if [[ -f "${SCENARIOS_DIR}/attacks.json" ]]; then
  jq -c '.[]' "${SCENARIOS_DIR}/attacks.json" 2>/dev/null | while IFS= read -r attack; do
    attack_id=$(echo "$attack" | jq -r '.id // empty')
    requests=$(echo "$attack" | jq -c '.requests // []')
    echo "$requests" | jq -c '.[]' | while IFS= read -r req; do
      path=$(echo "$req" | jq -r '.path // empty')
      method=$(echo "$req" | jq -r '.method // "GET"')
      query=$(echo "$req" | jq -r '.query // {} | to_entries | map("\(.key)=\(.value|@uri)") | join("&")')
      url="${BASE_URL}${path}"
      if [[ -n "$query" ]]; then
        url="${url}?${query}"
      fi
      resp_headers=$(curl -sS -D - -o /dev/null -X "${method}" "${url}" 2>/dev/null || true)
      location=$(echo "$resp_headers" | awk 'BEGIN{IGNORECASE=1} /^Location:/{sub(/\r$/,""); sub(/^Location:[[:space:]]*/,""); print; exit}')
      if [[ -n "$location" ]] && [[ "$location" == http* ]] && [[ "$location" != "${BASE_URL}"* ]] && [[ "$location" != "/" ]]; then
        _add_finding "FLOW-REDIRECT-${attack_id}" "high" "Open redirect to external URL: ${location}" \
          "{\"url\":\"${url}\",\"redirect\":\"${location}\"}"
      fi
    done
  done
fi

# Test 5: Client credentials flow (if logged in)
if [[ -f "${COOKIE_JAR}" ]] && grep -Eq '^(#HttpOnly_)?[^[:space:]#]+' "${COOKIE_JAR}"; then
  client_json=$(curl -fsS -X POST "${BASE_URL}/admin/clients/register" \
    -H "Content-Type: application/json" \
    -b "${COOKIE_JAR}" \
    -d '{"client_name":"scan-test","redirect_uris":["http://localhost:3000/callback"],"grant_types":["client_credentials"],"scope":"read write"}' 2>/dev/null || echo "{}")
  cid=$(echo "$client_json" | jq -r '.client_id // empty')
  csecret=$(echo "$client_json" | jq -r '.client_secret // empty')

  if [[ -n "$cid" && -n "$csecret" ]]; then
    token_json=$(curl -fsS -X POST "${BASE_URL}/oauth/token" \
      -H "Content-Type: application/x-www-form-urlencoded" \
      -d "grant_type=client_credentials&client_id=${cid}&client_secret=${csecret}&scope=read" 2>/dev/null || echo "{}")
    at=$(echo "$token_json" | jq -r '.access_token // empty')
    if [[ -z "$at" || "$at" == "null" ]]; then
      _add_finding "FLOW-TOKEN-001" "medium" "Client credentials token request failed" \
        "$(echo "$token_json" | jq -c '.')"
    fi
  fi
fi

# Output unified format
jq -n --arg scanner "flow-tester" --arg config "$CONFIG_NAME" \
  --arg ts "$TIMESTAMP" --argjson findings "$findings" \
  '{"scanner":$scanner,"config":$config,"timestamp":$ts,"findings":$findings}' > "$OUTPUT_FILE"

echo "Flow tester: $(echo "$findings" | jq length) findings for ${CONFIG_NAME}"
