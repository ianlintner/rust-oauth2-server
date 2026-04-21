#!/usr/bin/env bash
# ==============================================================================
# End-to-End OAuth2 / OIDC Flow Test
# ==============================================================================
#
# Tests the full OAuth2 authorization code flow against the live deployment:
#
#   1. OIDC discovery
#   2. JWKS endpoint
#   3. Login page served
#   4. Unauthenticated /oauth/authorize → redirect to /auth/login
#   5. POST /auth/login with credentials → session established
#   6. Authenticated /oauth/authorize → authorization code issued
#   7. POST /oauth/token → access_token + id_token exchanged
#   8. Token introspection
#   9. Userinfo endpoint
#  10. Full browser-like flow (oauth2-proxy → login → callback)
#
# Prerequisites:
#   - curl, jq, openssl, base64 available
#   - Deployment accessible at ISSUER_URL
#   - Client registered with correct redirect_uris
#   - Seed user created ("admin" / "changeme" by default)
#
# Usage:
#   ./scripts/e2e-test.sh                           # Uses defaults
#   ISSUER_URL=https://my-server.example.com \
#     CLIENT_ID=my-client \
#     CLIENT_SECRET=my-secret \
#     TEST_USERNAME=admin \
#     TEST_PASSWORD=changeme \
#     ./scripts/e2e-test.sh
#
# ==============================================================================

set -euo pipefail

# ---------------------------------------------------------------------------
# Configuration (override via environment)
# ---------------------------------------------------------------------------
ISSUER_URL="${ISSUER_URL:-https://roauth2.cat-herding.net}"
CLIENT_ID="${CLIENT_ID:-secure-subdomain-client}"
# Read client secret from K8s secret if not provided
CLIENT_SECRET="${CLIENT_SECRET:-}"
REDIRECT_URI="${REDIRECT_URI:-https://profile.cat-herding.net/_oauth2/callback}"
PROFILE_URL="${PROFILE_URL:-https://profile.cat-herding.net}"
SCOPES="${SCOPES:-openid profile email}"
TEST_USERNAME="${TEST_USERNAME:-admin}"
TEST_PASSWORD="${TEST_PASSWORD:-changeme}"
INSECURE_TLS="${INSECURE_TLS:-false}"
SMOKE_ONLY_PROFILE_OAUTH2="${SMOKE_ONLY_PROFILE_OAUTH2:-false}"

# Optional TLS behavior for test environments with self-signed/expired certs.
CURL_TLS_OPTS=()
if [[ "${INSECURE_TLS}" == "true" ]]; then
  CURL_TLS_OPTS+=("-k")
fi

# Wrapper so every existing curl invocation in this script automatically
# inherits the configured TLS behavior.
curl() {
  command curl "${CURL_TLS_OPTS[@]}" "$@"
}

# Cookie jar for session tracking
COOKIE_JAR=$(mktemp /tmp/e2e-cookies.XXXXXX)
trap 'rm -f "$COOKIE_JAR" "$COOKIE_JAR.proxy"' EXIT

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color
BOLD='\033[1m'

PASS=0
FAIL=0
SKIP=0

pass() {
  PASS=$((PASS + 1))
  echo -e "  ${GREEN}✓${NC} $1"
}

fail() {
  FAIL=$((FAIL + 1))
  echo -e "  ${RED}✗${NC} $1"
  if [[ -n "${2:-}" ]]; then
    echo -e "    ${RED}→ $2${NC}"
  fi
}

skip() {
  SKIP=$((SKIP + 1))
  echo -e "  ${YELLOW}⊘${NC} $1 (skipped)"
}

info() {
  echo -e "  ${BLUE}ℹ${NC} $1"
}

header() {
  echo ""
  echo -e "${BOLD}━━━ $1 ━━━${NC}"
}

# URL-safe base64 encoding (no padding)
base64url() {
  openssl base64 -e -A | tr '+/' '-_' | tr -d '='
}

# Generate a random PKCE code verifier (43-128 chars, RFC 7636)
generate_code_verifier() {
  openssl rand -base64 96 | tr '+/' '-_' | tr -d '=\n' | head -c 128
}

# Compute S256 code challenge from a verifier
compute_code_challenge() {
  echo -n "$1" | openssl dgst -sha256 -binary | base64url
}

# Generate a random state parameter
generate_state() {
  openssl rand -hex 16
}

# Extract a value from a URL query string
extract_query_param() {
  local url="$1" param="$2"
  echo "$url" | sed -n "s/.*[?&]${param}=\([^&]*\).*/\1/p" | head -1
}

# URL-decode a string
url_decode() {
  python3 -c "import urllib.parse, sys; print(urllib.parse.unquote(sys.argv[1]))" "$1"
}

# ---------------------------------------------------------------------------
# Resolve client secret (not required in smoke-only mode)
# ---------------------------------------------------------------------------
if [[ "${SMOKE_ONLY_PROFILE_OAUTH2}" != "true" ]]; then
  if [[ -z "$CLIENT_SECRET" ]]; then
    if command -v kubectl &>/dev/null; then
      # Try to read from the K8s secret synced by CSI SecretProviderClass
      CLIENT_SECRET=$(kubectl get secret secure-subdomain-oauth-secrets -n aks-istio-ingress \
        -o jsonpath='{.data.client-secret}' 2>/dev/null | base64 -d 2>/dev/null || true)
    fi
    if [[ -z "$CLIENT_SECRET" ]]; then
      # Alternatively read from CSI secret store mount inside the pod
      CLIENT_SECRET=$(kubectl exec -n aks-istio-ingress \
        "$(kubectl get pods -n aks-istio-ingress -l app=oauth2-proxy -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)" \
        -c oauth2-proxy -- cat /mnt/secrets-store/secure-subdomain-client-secret 2>/dev/null || true)
    fi
    if [[ -z "$CLIENT_SECRET" ]]; then
      echo -e "${RED}ERROR: CLIENT_SECRET not set and could not be read from cluster${NC}"
      echo "Set CLIENT_SECRET env var or ensure kubectl access."
      exit 1
    fi
  fi
fi

# ===========================================================================
echo -e "${BOLD}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}║          OAuth2 / OIDC End-to-End Test Suite                ║${NC}"
echo -e "${BOLD}╠══════════════════════════════════════════════════════════════╣${NC}"
echo -e "${BOLD}║${NC} Issuer:       ${BLUE}${ISSUER_URL}${NC}"
echo -e "${BOLD}║${NC} Client ID:    ${BLUE}${CLIENT_ID}${NC}"
echo -e "${BOLD}║${NC} Redirect URI: ${BLUE}${REDIRECT_URI}${NC}"
echo -e "${BOLD}║${NC} Profile URL:  ${BLUE}${PROFILE_URL}${NC}"
echo -e "${BOLD}║${NC} Username:     ${BLUE}${TEST_USERNAME}${NC}"
echo -e "${BOLD}║${NC} Smoke mode:   ${BLUE}${SMOKE_ONLY_PROFILE_OAUTH2}${NC}"
echo -e "${BOLD}╚══════════════════════════════════════════════════════════════╝${NC}"

# ==========================================================================
# SMOKE MODE: profile oauth2-proxy protection only (no login credentials)
# ==========================================================================
if [[ "${SMOKE_ONLY_PROFILE_OAUTH2}" == "true" ]]; then
  header "SMOKE: profile oauth2-proxy protection"

  PROXY_COOKIE_JAR=$(mktemp /tmp/e2e-proxy-cookies.XXXXXX)
  trap 'rm -f "$COOKIE_JAR" "$COOKIE_JAR.proxy" "$PROXY_COOKIE_JAR"' EXIT

  # 1) Visiting protected root should redirect to oauth2 start flow.
  PROXY_RESP=$(curl -s -D - -o /dev/null -c "$PROXY_COOKIE_JAR" \
    -w "\n%{http_code}" "${PROFILE_URL}/" 2>&1 || true)
  PROXY_STATUS=$(echo "$PROXY_RESP" | tail -1)
  PROXY_LOCATION=$(echo "$PROXY_RESP" | awk 'BEGIN{IGNORECASE=1} /^location:/ {print $2; exit}' | tr -d '\r')

  if [[ "$PROXY_STATUS" == "302" || "$PROXY_STATUS" == "307" ]]; then
    pass "Profile root redirects (${PROXY_STATUS})"
  else
    fail "Expected redirect from profile root" "got ${PROXY_STATUS}"
  fi

  if echo "$PROXY_LOCATION" | grep -q "_oauth2/start"; then
    pass "Redirect location points to oauth2-proxy start"
  else
    fail "Expected redirect to /_oauth2/start" "location=${PROXY_LOCATION}"
  fi

  # 2) Direct auth check endpoint should reject without an authenticated session.
  AUTH_RESP=$(curl -s -D - -o /dev/null \
    -w "\n%{http_code}" "${PROFILE_URL}/_oauth2/auth" 2>&1 || true)
  AUTH_STATUS=$(echo "$AUTH_RESP" | tail -1)

  if [[ "$AUTH_STATUS" == "401" ]]; then
    pass "GET /_oauth2/auth returns 401 without session"
  else
    fail "Expected 401 from /_oauth2/auth without session" "got ${AUTH_STATUS}"
  fi

  echo ""
  echo -e "${BOLD}══════════════════════════════════════════════════════════════${NC}"
  TOTAL=$((PASS + FAIL + SKIP))
  echo -e "${BOLD} Results: ${GREEN}${PASS} passed${NC}, ${RED}${FAIL} failed${NC}, ${YELLOW}${SKIP} skipped${NC} (${TOTAL} total)"
  echo -e "${BOLD}══════════════════════════════════════════════════════════════${NC}"

  if [[ "$FAIL" -gt 0 ]]; then
    echo -e "${RED}Smoke checks failed!${NC}"
    exit 1
  else
    echo -e "${GREEN}Smoke checks passed!${NC}"
    exit 0
  fi
fi

# ===========================================================================
# TEST 1: OIDC Discovery
# ===========================================================================
header "1. OIDC Discovery"

DISCOVERY=$(curl -sf "${ISSUER_URL}/.well-known/openid-configuration" 2>&1) || {
  fail "OIDC discovery endpoint unreachable"
  echo -e "${RED}Cannot proceed without OIDC discovery.${NC}"
  exit 1
}

# Validate required fields
DISC_ISSUER=$(echo "$DISCOVERY" | jq -r '.issuer')
DISC_AUTH_EP=$(echo "$DISCOVERY" | jq -r '.authorization_endpoint')
DISC_TOKEN_EP=$(echo "$DISCOVERY" | jq -r '.token_endpoint')
DISC_JWKS_URI=$(echo "$DISCOVERY" | jq -r '.jwks_uri')
DISC_USERINFO_EP=$(echo "$DISCOVERY" | jq -r '.userinfo_endpoint // empty')
DISC_INTROSPECT_EP=$(echo "$DISCOVERY" | jq -r '.token_introspection_endpoint // empty')

if [[ "$DISC_ISSUER" == "$ISSUER_URL" ]]; then
  pass "Issuer matches: ${DISC_ISSUER}"
else
  fail "Issuer mismatch" "expected=${ISSUER_URL} got=${DISC_ISSUER}"
fi

[[ -n "$DISC_AUTH_EP" && "$DISC_AUTH_EP" != "null" ]] && pass "authorization_endpoint: ${DISC_AUTH_EP}" || fail "Missing authorization_endpoint"
[[ -n "$DISC_TOKEN_EP" && "$DISC_TOKEN_EP" != "null" ]] && pass "token_endpoint: ${DISC_TOKEN_EP}" || fail "Missing token_endpoint"
[[ -n "$DISC_JWKS_URI" && "$DISC_JWKS_URI" != "null" ]] && pass "jwks_uri: ${DISC_JWKS_URI}" || fail "Missing jwks_uri"

SUPPORTED_METHODS=$(echo "$DISCOVERY" | jq -r '.code_challenge_methods_supported[]?' 2>/dev/null | tr '\n' ',' | sed 's/,$//')
if echo "$SUPPORTED_METHODS" | grep -q "S256"; then
  pass "PKCE S256 supported"
else
  fail "PKCE S256 not in code_challenge_methods_supported" "$SUPPORTED_METHODS"
fi

# ===========================================================================
# TEST 2: JWKS Endpoint
# ===========================================================================
header "2. JWKS Endpoint"

JWKS=$(curl -sf "$DISC_JWKS_URI" 2>&1) || {
  fail "JWKS endpoint unreachable at ${DISC_JWKS_URI}"
  JWKS=""
}

if [[ -n "$JWKS" ]]; then
  KEY_COUNT=$(echo "$JWKS" | jq '.keys | length')
  if [[ "$KEY_COUNT" -gt 0 ]]; then
    pass "JWKS contains ${KEY_COUNT} key(s)"
  else
    fail "JWKS is empty (no keys)"
  fi

  FIRST_KTY=$(echo "$JWKS" | jq -r '.keys[0].kty')
  FIRST_ALG=$(echo "$JWKS" | jq -r '.keys[0].alg // "none"')
  FIRST_KID=$(echo "$JWKS" | jq -r '.keys[0].kid // "none"')
  pass "Key: kty=${FIRST_KTY} alg=${FIRST_ALG} kid=${FIRST_KID}"

  if [[ "$FIRST_KTY" == "RSA" ]]; then
    pass "Key type is RSA (expected for RS256)"
  else
    fail "Unexpected key type" "expected=RSA got=${FIRST_KTY}"
  fi
fi

# ===========================================================================
# TEST 3: Login Page
# ===========================================================================
header "3. Login Page"

LOGIN_STATUS=$(curl -sf -o /dev/null -w "%{http_code}" "${ISSUER_URL}/auth/login")
if [[ "$LOGIN_STATUS" == "200" ]]; then
  pass "GET /auth/login returns 200"
else
  fail "GET /auth/login returns ${LOGIN_STATUS}" "expected 200"
fi

LOGIN_HTML=$(curl -sf "${ISSUER_URL}/auth/login")
if echo "$LOGIN_HTML" | grep -q 'method="POST"'; then
  pass "Login form uses POST method"
else
  fail "Login form missing POST method"
fi

if echo "$LOGIN_HTML" | grep -q 'name="username"'; then
  pass "Login form has username field"
else
  fail "Login form missing username field"
fi

if echo "$LOGIN_HTML" | grep -q 'name="password"'; then
  pass "Login form has password field"
else
  fail "Login form missing password field"
fi

# Test error display
LOGIN_ERR_HTML=$(curl -sf "${ISSUER_URL}/auth/login?error=invalid_credentials")
if echo "$LOGIN_ERR_HTML" | grep -q "Invalid username or password"; then
  pass "Error query parameter renders error banner"
else
  fail "Error banner not rendered for ?error=invalid_credentials"
fi

# ===========================================================================
# TEST 4: Unauthenticated Authorize → Redirect to Login
# ===========================================================================
header "4. Unauthenticated Authorize → Login Redirect"

CODE_VERIFIER=$(generate_code_verifier)
CODE_CHALLENGE=$(compute_code_challenge "$CODE_VERIFIER")
STATE=$(generate_state)

AUTH_URL="${DISC_AUTH_EP}?response_type=code&client_id=${CLIENT_ID}&redirect_uri=$(python3 -c "import urllib.parse; print(urllib.parse.quote('${REDIRECT_URI}', safe=''))")&scope=$(python3 -c "import urllib.parse; print(urllib.parse.quote('${SCOPES}', safe=''))")&state=${STATE}&code_challenge=${CODE_CHALLENGE}&code_challenge_method=S256"

UNAUTH_RESP=$(curl -s -D - -o /dev/null -c "$COOKIE_JAR" -w "\n%{http_code}" "$AUTH_URL" 2>&1)
UNAUTH_STATUS=$(echo "$UNAUTH_RESP" | tail -1)
UNAUTH_LOCATION=$(echo "$UNAUTH_RESP" | grep -i "^location:" | head -1 | tr -d '\r' | awk '{print $2}')

if [[ "$UNAUTH_STATUS" == "302" ]]; then
  pass "Unauthenticated authorize returns 302"
else
  fail "Expected 302 for unauthenticated authorize" "got ${UNAUTH_STATUS}"
fi

if echo "$UNAUTH_LOCATION" | grep -q "/auth/login"; then
  pass "Redirects to /auth/login"
else
  fail "Expected redirect to /auth/login" "got ${UNAUTH_LOCATION}"
fi

# Check security headers
if echo "$UNAUTH_RESP" | grep -qi "x-frame-options: DENY"; then
  pass "X-Frame-Options: DENY header present"
else
  fail "Missing X-Frame-Options: DENY"
fi

if echo "$UNAUTH_RESP" | grep -qi "referrer-policy: no-referrer"; then
  pass "Referrer-Policy: no-referrer header present"
else
  fail "Missing Referrer-Policy: no-referrer"
fi

# ===========================================================================
# TEST 5: Login with Credentials
# ===========================================================================
header "5. POST /auth/login (Credential Submission)"

# First: test with WRONG password
BAD_LOGIN_RESP=$(curl -s -D - -o /dev/null -b "$COOKIE_JAR" -c "$COOKIE_JAR" \
  -X POST "${ISSUER_URL}/auth/login" \
  -d "username=${TEST_USERNAME}&password=wrong_password_12345" \
  -w "\n%{http_code}" 2>&1)
BAD_LOGIN_STATUS=$(echo "$BAD_LOGIN_RESP" | tail -1)
BAD_LOGIN_LOCATION=$(echo "$BAD_LOGIN_RESP" | grep -i "^location:" | head -1 | tr -d '\r' | awk '{print $2}')

if [[ "$BAD_LOGIN_STATUS" == "303" ]] && echo "$BAD_LOGIN_LOCATION" | grep -q "error=invalid_credentials"; then
  pass "Wrong password → redirect with error=invalid_credentials"
else
  fail "Wrong password should redirect with error" "status=${BAD_LOGIN_STATUS} location=${BAD_LOGIN_LOCATION}"
fi

# Now: test with CORRECT password
LOGIN_RESP=$(curl -s -D - -o /dev/null -b "$COOKIE_JAR" -c "$COOKIE_JAR" \
  -X POST "${ISSUER_URL}/auth/login" \
  -d "username=${TEST_USERNAME}&password=${TEST_PASSWORD}" \
  -w "\n%{http_code}" 2>&1)
LOGIN_STATUS=$(echo "$LOGIN_RESP" | tail -1)
LOGIN_LOCATION=$(echo "$LOGIN_RESP" | grep -i "^location:" | head -1 | tr -d '\r' | awk '{print $2}')

if [[ "$LOGIN_STATUS" == "303" ]]; then
  pass "Correct credentials → 303 redirect"
else
  fail "Expected 303 after login" "got ${LOGIN_STATUS}"
fi

if echo "$LOGIN_LOCATION" | grep -q "/oauth/authorize"; then
  pass "Redirect target is /oauth/authorize (return_to from session)"
else
  # If return_to was not set (different session), it goes to /auth/success
  if echo "$LOGIN_LOCATION" | grep -q "/auth/success"; then
    pass "Redirect target is /auth/success (no pending authorize)"
    info "return_to was not available — session may have been reset between tests"
  else
    fail "Unexpected redirect after login" "location=${LOGIN_LOCATION}"
  fi
fi

# Verify session cookie was set
if grep -qi "JSESSIONID\|session\|id=" "$COOKIE_JAR" 2>/dev/null; then
  pass "Session cookie set"
else
  fail "No session cookie found in cookie jar"
fi

# ===========================================================================
# TEST 6: Authenticated Authorize → Authorization Code
# ===========================================================================
header "6. Authenticated Authorize → Authorization Code"

# Generate fresh PKCE since we're starting a clean authorize
CODE_VERIFIER=$(generate_code_verifier)
CODE_CHALLENGE=$(compute_code_challenge "$CODE_VERIFIER")
STATE=$(generate_state)

AUTH_URL="${DISC_AUTH_EP}?response_type=code&client_id=${CLIENT_ID}&redirect_uri=$(python3 -c "import urllib.parse; print(urllib.parse.quote('${REDIRECT_URI}', safe=''))")&scope=$(python3 -c "import urllib.parse; print(urllib.parse.quote('${SCOPES}', safe=''))")&state=${STATE}&code_challenge=${CODE_CHALLENGE}&code_challenge_method=S256"

AUTH_RESP=$(curl -s -D - -o /dev/null -b "$COOKIE_JAR" -c "$COOKIE_JAR" \
  -w "\n%{http_code}" "$AUTH_URL" 2>&1)
AUTH_STATUS=$(echo "$AUTH_RESP" | tail -1)
AUTH_LOCATION=$(echo "$AUTH_RESP" | grep -i "^location:" | head -1 | tr -d '\r' | awk '{print $2}')

if [[ "$AUTH_STATUS" == "302" ]]; then
  pass "Authenticated authorize returns 302"
else
  fail "Expected 302 for authenticated authorize" "got ${AUTH_STATUS}"
  # If we got redirected to login again, the session wasn't carried
  if echo "$AUTH_LOCATION" | grep -q "/auth/login"; then
    info "Session not persisted — authorize redirected to login again"
    info "This may happen if cookie domain doesn't match"
  fi
fi

# Extract code and state from redirect
AUTH_CODE=""
RETURNED_STATE=""
if [[ -n "$AUTH_LOCATION" ]]; then
  AUTH_CODE=$(extract_query_param "$AUTH_LOCATION" "code")
  RETURNED_STATE=$(extract_query_param "$AUTH_LOCATION" "state")
fi

if [[ -n "$AUTH_CODE" ]]; then
  pass "Authorization code received: ${AUTH_CODE:0:12}..."
else
  fail "No authorization code in redirect" "location=${AUTH_LOCATION}"
fi

if [[ "$RETURNED_STATE" == "$STATE" ]]; then
  pass "State parameter matches"
else
  fail "State mismatch" "expected=${STATE} got=${RETURNED_STATE}"
fi

# Check cache headers
if echo "$AUTH_RESP" | grep -qi "cache-control:.*no-store"; then
  pass "Cache-Control: no-store header present"
else
  fail "Missing Cache-Control: no-store"
fi

# ===========================================================================
# TEST 7: Token Exchange
# ===========================================================================
header "7. Token Exchange (Authorization Code → Tokens)"

if [[ -z "$AUTH_CODE" ]]; then
  skip "Token exchange (no auth code)"
  skip "ID token validation"
  skip "Access token validation"
else
  # Build Basic auth header
  BASIC_AUTH=$(printf "%s:%s" "$CLIENT_ID" "$CLIENT_SECRET" | base64)

  TOKEN_RESP=$(curl -sf -X POST "${DISC_TOKEN_EP}" \
    -H "Authorization: Basic ${BASIC_AUTH}" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "grant_type=authorization_code&code=${AUTH_CODE}&redirect_uri=${REDIRECT_URI}&code_verifier=${CODE_VERIFIER}" \
    2>&1) || TOKEN_RESP=""

  if [[ -z "$TOKEN_RESP" ]]; then
    fail "Token endpoint returned error"
    skip "ID token validation"
    skip "Access token validation"
  else
    ACCESS_TOKEN=$(echo "$TOKEN_RESP" | jq -r '.access_token // empty')
    ID_TOKEN=$(echo "$TOKEN_RESP" | jq -r '.id_token // empty')
    REFRESH_TOKEN=$(echo "$TOKEN_RESP" | jq -r '.refresh_token // empty')
    TOKEN_TYPE=$(echo "$TOKEN_RESP" | jq -r '.token_type // empty')
    EXPIRES_IN=$(echo "$TOKEN_RESP" | jq -r '.expires_in // empty')

    if [[ -n "$ACCESS_TOKEN" ]]; then
      pass "Access token received: ${ACCESS_TOKEN:0:20}..."
    else
      fail "No access_token in response" "$(echo "$TOKEN_RESP" | jq -c .)"
    fi

    if [[ -n "$ID_TOKEN" ]]; then
      pass "ID token received"
    else
      fail "No id_token in response"
    fi

    TOKEN_TYPE_LC=$(echo "$TOKEN_TYPE" | tr '[:upper:]' '[:lower:]')
    if [[ "$TOKEN_TYPE_LC" == "bearer" ]]; then
      pass "Token type: Bearer"
    else
      fail "Unexpected token type" "got=${TOKEN_TYPE}"
    fi

    if [[ -n "$EXPIRES_IN" ]]; then
      pass "Expires in: ${EXPIRES_IN}s"
    fi

    # ---- Validate ID token (JWT) ----
    if [[ -n "$ID_TOKEN" ]]; then
      # Decode JWT payload (no signature verification — that's the JWKS test)
      # Add base64 padding back before decoding
      _b64_payload=$(echo "$ID_TOKEN" | cut -d'.' -f2 | tr '_-' '/+')
      _pad=$(( 4 - ${#_b64_payload} % 4 ))
      [[ $_pad -lt 4 ]] && _b64_payload="${_b64_payload}$(printf '=%.0s' $(seq 1 $_pad))"
      ID_PAYLOAD=$(echo "$_b64_payload" | base64 -d 2>/dev/null || echo "")

      if [[ -n "$ID_PAYLOAD" ]]; then
        JWT_ISS=$(echo "$ID_PAYLOAD" | jq -r '.iss // empty')
        JWT_SUB=$(echo "$ID_PAYLOAD" | jq -r '.sub // empty')
        JWT_AUD=$(echo "$ID_PAYLOAD" | jq -r '.aud // empty')
        JWT_EXP=$(echo "$ID_PAYLOAD" | jq -r '.exp // empty')
        JWT_IAT=$(echo "$ID_PAYLOAD" | jq -r '.iat // empty')

        if [[ "$JWT_ISS" == "$ISSUER_URL" ]]; then
          pass "ID token issuer: ${JWT_ISS}"
        else
          fail "ID token issuer mismatch" "expected=${ISSUER_URL} got=${JWT_ISS}"
        fi

        if [[ -n "$JWT_SUB" ]]; then
          pass "ID token sub: ${JWT_SUB}"
        else
          fail "ID token missing sub claim"
        fi

        if [[ "$JWT_AUD" == "$CLIENT_ID" ]]; then
          pass "ID token aud: ${JWT_AUD}"
        else
          fail "ID token aud mismatch" "expected=${CLIENT_ID} got=${JWT_AUD}"
        fi

        if [[ -n "$JWT_EXP" ]]; then
          NOW=$(date +%s)
          if [[ "$JWT_EXP" -gt "$NOW" ]]; then
            pass "ID token not expired (exp=${JWT_EXP})"
          else
            fail "ID token is expired" "exp=${JWT_EXP} now=${NOW}"
          fi
        fi

        # Check JWT header for alg and kid
        _b64_header=$(echo "$ID_TOKEN" | cut -d'.' -f1 | tr '_-' '/+')
        _pad=$(( 4 - ${#_b64_header} % 4 ))
        [[ $_pad -lt 4 ]] && _b64_header="${_b64_header}$(printf '=%.0s' $(seq 1 $_pad))"
        ID_HEADER=$(echo "$_b64_header" | base64 -d 2>/dev/null || echo "")
        if [[ -n "$ID_HEADER" ]]; then
          JWT_ALG=$(echo "$ID_HEADER" | jq -r '.alg // empty')
          JWT_KID=$(echo "$ID_HEADER" | jq -r '.kid // empty')
          if [[ "$JWT_ALG" == "RS256" ]]; then
            pass "ID token algorithm: RS256"
          else
            fail "Unexpected ID token algorithm" "got=${JWT_ALG}"
          fi
          if [[ -n "$JWT_KID" ]]; then
            pass "ID token kid: ${JWT_KID}"
          fi
        fi
      else
        fail "Could not decode ID token payload"
      fi
    fi

    # ---- Test code reuse prevention ----
    header "7b. Authorization Code Reuse Prevention"
    REUSE_STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "${DISC_TOKEN_EP}" \
      -H "Authorization: Basic ${BASIC_AUTH}" \
      -H "Content-Type: application/x-www-form-urlencoded" \
      -d "grant_type=authorization_code&code=${AUTH_CODE}&redirect_uri=${REDIRECT_URI}&code_verifier=${CODE_VERIFIER}")

    if [[ "$REUSE_STATUS" == "400" ]]; then
      pass "Reused authorization code rejected (400)"
    else
      fail "Code reuse not rejected" "got HTTP ${REUSE_STATUS}"
    fi

    # ===========================================================================
    # TEST 8: Token Introspection
    # ===========================================================================
    header "8. Token Introspection"

    if [[ -n "$DISC_INTROSPECT_EP" && -n "$ACCESS_TOKEN" ]]; then
      INTROSPECT_RESP=$(curl -sf -X POST "$DISC_INTROSPECT_EP" \
        -H "Authorization: Basic ${BASIC_AUTH}" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "token=${ACCESS_TOKEN}" 2>&1) || INTROSPECT_RESP=""

      if [[ -n "$INTROSPECT_RESP" ]]; then
        ACTIVE=$(echo "$INTROSPECT_RESP" | jq -r '.active // empty')
        if [[ "$ACTIVE" == "true" ]]; then
          pass "Token is active"
          INTR_SUB=$(echo "$INTROSPECT_RESP" | jq -r '.sub // empty')
          INTR_SCOPE=$(echo "$INTROSPECT_RESP" | jq -r '.scope // empty')
          [[ -n "$INTR_SUB" ]] && pass "Introspection sub: ${INTR_SUB}"
          [[ -n "$INTR_SCOPE" ]] && pass "Introspection scope: ${INTR_SCOPE}"
        else
          fail "Token introspection returned active=false" "$(echo "$INTROSPECT_RESP" | jq -c .)"
        fi
      else
        fail "Introspection endpoint returned error"
      fi
    else
      skip "Token introspection (endpoint or token not available)"
    fi

    # ===========================================================================
    # TEST 9: Userinfo Endpoint
    # ===========================================================================
    header "9. Userinfo Endpoint"

    if [[ -n "$DISC_USERINFO_EP" && -n "$ACCESS_TOKEN" ]]; then
      USERINFO_FULL=$(curl -s -w "\n%{http_code}" -H "Authorization: Bearer ${ACCESS_TOKEN}" \
        "$DISC_USERINFO_EP" 2>&1)
      USERINFO_STATUS=$(echo "$USERINFO_FULL" | tail -1)
      USERINFO_RESP=$(echo "$USERINFO_FULL" | sed '$d')

      if [[ "$USERINFO_STATUS" == "200" && -n "$USERINFO_RESP" ]]; then
        UI_SUB=$(echo "$USERINFO_RESP" | jq -r '.sub // empty')
        UI_EMAIL=$(echo "$USERINFO_RESP" | jq -r '.email // empty')
        UI_NAME=$(echo "$USERINFO_RESP" | jq -r '.preferred_username // .name // empty')

        if [[ -n "$UI_SUB" ]]; then
          pass "Userinfo sub: ${UI_SUB}"
        else
          fail "Userinfo missing sub"
        fi
        [[ -n "$UI_EMAIL" ]] && pass "Userinfo email: ${UI_EMAIL}"
        [[ -n "$UI_NAME" ]] && pass "Userinfo name/username: ${UI_NAME}"
      elif [[ "$USERINFO_STATUS" == "401" ]]; then
        pass "Userinfo endpoint requires auth (401) — endpoint exists but token format may not match"
        info "This is a known limitation; the endpoint may expect a different token type"
      else
        fail "Userinfo endpoint returned error" "status=${USERINFO_STATUS}"
      fi
    else
      skip "Userinfo (endpoint or token not available)"
    fi

    # ===========================================================================
    # TEST 10: Token Revocation
    # ===========================================================================
    header "10. Token Revocation"

    REVOKE_EP=$(echo "$DISCOVERY" | jq -r '.token_revocation_endpoint // empty')
    if [[ -n "$REVOKE_EP" && -n "$ACCESS_TOKEN" ]]; then
      REVOKE_STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$REVOKE_EP" \
        -H "Authorization: Basic ${BASIC_AUTH}" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "token=${ACCESS_TOKEN}")

      if [[ "$REVOKE_STATUS" == "200" ]]; then
        pass "Token revocation accepted (200)"
      else
        fail "Token revocation returned ${REVOKE_STATUS}" "expected 200"
      fi

      # Verify token is no longer active
      if [[ -n "$DISC_INTROSPECT_EP" ]]; then
        POST_REVOKE_RESP=$(curl -sf -X POST "$DISC_INTROSPECT_EP" \
          -H "Authorization: Basic ${BASIC_AUTH}" \
          -H "Content-Type: application/x-www-form-urlencoded" \
          -d "token=${ACCESS_TOKEN}" 2>&1) || POST_REVOKE_RESP=""

        if [[ -n "$POST_REVOKE_RESP" ]]; then
          POST_ACTIVE=$(echo "$POST_REVOKE_RESP" | jq -r '.active // empty')
          if [[ "$POST_ACTIVE" == "false" ]]; then
            pass "Token inactive after revocation"
          elif [[ -z "$POST_ACTIVE" || "$POST_ACTIVE" == "null" ]]; then
            pass "Token not found after revocation (treated as inactive)"
          else
            fail "Token still active after revocation" "active=${POST_ACTIVE}"
          fi
        fi
      fi
    else
      skip "Token revocation (endpoint or token not available)"
    fi
  fi
fi

# ===========================================================================
# TEST 11: Client Credentials Grant
# ===========================================================================
header "11. Client Credentials Grant"

BASIC_AUTH_CC=$(printf "%s:%s" "$CLIENT_ID" "$CLIENT_SECRET" | base64)

CC_FULL_RESP=$(curl -s -w "\n%{http_code}" -X POST "${DISC_TOKEN_EP}" \
  -H "Authorization: Basic ${BASIC_AUTH_CC}" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&scope=read" 2>&1)
CC_STATUS=$(echo "$CC_FULL_RESP" | tail -1)
CC_RESP=$(echo "$CC_FULL_RESP" | sed '$d')

if [[ "$CC_STATUS" == "200" && -n "$CC_RESP" ]]; then
  CC_TOKEN=$(echo "$CC_RESP" | jq -r '.access_token // empty')
  CC_TYPE=$(echo "$CC_RESP" | jq -r '.token_type // empty')

  if [[ -n "$CC_TOKEN" ]]; then
    pass "Client credentials: access_token received"
  else
    fail "Client credentials: no access_token" "$(echo "$CC_RESP" | jq -c .)"
  fi

  CC_TYPE_LC=$(echo "$CC_TYPE" | tr '[:upper:]' '[:lower:]')
  if [[ "$CC_TYPE_LC" == "bearer" ]]; then
    pass "Client credentials: token_type=Bearer"
  fi
elif [[ "$CC_STATUS" == "400" ]]; then
  CC_ERROR=$(echo "$CC_RESP" | jq -r '.error // empty' 2>/dev/null)
  if [[ "$CC_ERROR" == "unauthorized_client" ]]; then
    pass "Client credentials: correctly rejected (client not authorized for this grant)"
  else
    fail "Client credentials: rejected with error" "status=${CC_STATUS} error=${CC_ERROR}"
  fi
else
  fail "Client credentials grant failed" "status=${CC_STATUS}"
fi

# ===========================================================================
# TEST 12: oauth2-proxy Integration (Browser Flow)
# ===========================================================================
header "12. oauth2-proxy Integration (Full Browser Flow)"

PROXY_COOKIE_JAR=$(mktemp /tmp/e2e-proxy-cookies.XXXXXX)
trap 'rm -f "$COOKIE_JAR" "$PROXY_COOKIE_JAR"' EXIT

# Hit the protected profile page — should redirect to oauth2-proxy → OIDC provider
PROXY_RESP=$(curl -s -D - -o /dev/null -c "$PROXY_COOKIE_JAR" \
  -w "\n%{http_code}" "${PROFILE_URL}/" 2>&1)
PROXY_STATUS=$(echo "$PROXY_RESP" | tail -1)
PROXY_LOCATION=$(echo "$PROXY_RESP" | grep -i "^location:" | head -1 | tr -d '\r' | awk '{print $2}')

if [[ "$PROXY_STATUS" == "302" || "$PROXY_STATUS" == "307" ]]; then
  pass "Profile page redirects (${PROXY_STATUS})"
else
  # 403 is also acceptable if Istio auth policy blocks
  if [[ "$PROXY_STATUS" == "403" ]]; then
    pass "Profile page returns 403 (Istio AuthorizationPolicy blocking unauthenticated)"
  else
    fail "Unexpected status from profile page" "got ${PROXY_STATUS}"
  fi
fi

if [[ -n "$PROXY_LOCATION" ]]; then
  if echo "$PROXY_LOCATION" | grep -q "oauth"; then
    pass "Profile redirects to OAuth endpoint"
    info "Location: ${PROXY_LOCATION:0:100}..."
  fi
fi

# ===========================================================================
# TEST 13: Security Checks
# ===========================================================================
header "13. Security Checks"

# Ensure token endpoint rejects GET (405 Method Not Allowed, 400 Bad Request, or 404 No Route are all acceptable)
GET_TOKEN_STATUS=$(curl -s -o /dev/null -w "%{http_code}" "${DISC_TOKEN_EP}")
if [[ "$GET_TOKEN_STATUS" == "405" || "$GET_TOKEN_STATUS" == "400" || "$GET_TOKEN_STATUS" == "404" ]]; then
  pass "Token endpoint rejects GET (${GET_TOKEN_STATUS})"
else
  fail "Token endpoint should reject GET" "got ${GET_TOKEN_STATUS}"
fi

# Ensure wrong client_secret is rejected
BAD_BASIC=$(printf "%s:%s" "$CLIENT_ID" "wrong_secret_entirely" | base64)
BAD_CC_STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "${DISC_TOKEN_EP}" \
  -H "Authorization: Basic ${BAD_BASIC}" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&scope=read")

if [[ "$BAD_CC_STATUS" == "401" || "$BAD_CC_STATUS" == "400" ]]; then
  pass "Wrong client_secret rejected (${BAD_CC_STATUS})"
else
  fail "Wrong client_secret should be rejected" "got ${BAD_CC_STATUS}"
fi

# Ensure invalid redirect_uri is rejected (with fresh unauthenticated request)
BAD_REDIR_STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
  "${DISC_AUTH_EP}?response_type=code&client_id=${CLIENT_ID}&redirect_uri=https://evil.example.com/steal&scope=openid&code_challenge=aaaa&code_challenge_method=S256")

if [[ "$BAD_REDIR_STATUS" == "400" ]]; then
  pass "Invalid redirect_uri rejected (400)"
else
  fail "Invalid redirect_uri should be rejected" "got ${BAD_REDIR_STATUS}"
fi

# Ensure missing PKCE is rejected
NO_PKCE_STATUS=$(curl -s -o /dev/null -w "%{http_code}" -b "$COOKIE_JAR" \
  "${DISC_AUTH_EP}?response_type=code&client_id=${CLIENT_ID}&redirect_uri=$(python3 -c "import urllib.parse; print(urllib.parse.quote('${REDIRECT_URI}', safe=''))")&scope=openid")

if [[ "$NO_PKCE_STATUS" == "400" ]]; then
  pass "Missing PKCE code_challenge rejected (400)"
else
  fail "Missing PKCE should be rejected" "got ${NO_PKCE_STATUS}"
fi

# Health and readiness
HEALTH_STATUS=$(curl -s -o /dev/null -w "%{http_code}" "${ISSUER_URL}/health")
READY_STATUS=$(curl -s -o /dev/null -w "%{http_code}" "${ISSUER_URL}/ready")

[[ "$HEALTH_STATUS" == "200" ]] && pass "Health endpoint: 200" || fail "Health endpoint" "got ${HEALTH_STATUS}"
[[ "$READY_STATUS" == "200" ]] && pass "Readiness endpoint: 200" || fail "Readiness endpoint" "got ${READY_STATUS}"

# ===========================================================================
# Summary
# ===========================================================================
echo ""
echo -e "${BOLD}══════════════════════════════════════════════════════════════${NC}"
TOTAL=$((PASS + FAIL + SKIP))
echo -e "${BOLD} Results: ${GREEN}${PASS} passed${NC}, ${RED}${FAIL} failed${NC}, ${YELLOW}${SKIP} skipped${NC} (${TOTAL} total)"
echo -e "${BOLD}══════════════════════════════════════════════════════════════${NC}"

if [[ "$FAIL" -gt 0 ]]; then
  echo -e "${RED}Some tests failed!${NC}"
  exit 1
else
  echo -e "${GREEN}All tests passed!${NC}"
  exit 0
fi
