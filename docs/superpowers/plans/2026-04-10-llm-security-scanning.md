# Implementation Plan: LLM-Driven Adaptive Security Scanning

**Spec:** `docs/superpowers/specs/2026-04-09-llm-security-scanning-design.md`
**Date:** 2026-04-10
**Status:** Draft

---

## Scope

MVP implementation of the security scanning framework covering:

- 5 kustomize overlay configs (prod-hardened, dev-relaxed, misconfig-cors, misconfig-auth, edge-empty)
- Core orchestration scripts (deploy, scan, analyze)
- 4 scanner implementations (OAuth2 flow tester, timing analyzer, error leakage, token entropy)
- LLM integration for scenario generation and feedback analysis
- Unified finding format and report generation

**Deferred to phase 2:** OWASP ZAP (requires ZAP Docker image in KinD), kubeaudit, kube-bench, network policy validator.

---

## Task Breakdown

### Task 1: Directory scaffolding and .gitignore

**Files:**

- `tests/security-scan/.gitkeep` (marker)
- `tests/security-scan/configs/.gitkeep`
- `tests/security-scan/scenarios/.gitkeep`
- `tests/security-scan/scanners/.gitkeep`
- `tests/security-scan/scripts/.gitkeep`
- `.gitignore` (append reports/ entry)

**Test:** `ls tests/security-scan/{configs,scenarios,scanners,scripts}` succeeds. `git check-ignore reports/foo.json` returns match.

**Steps:**

1. Create directory tree with .gitkeep files
2. Append `reports/` to .gitignore if not already present

---

### Task 2: Kustomize overlay — `prod-hardened`

**Purpose:** Baseline secure config. Strong JWT, strict CORS (explicit origin), admin auth required, Postgres.

**Files:**

- `tests/security-scan/configs/prod-hardened/kustomization.yaml`
- `tests/security-scan/configs/prod-hardened/patches/secret-prod.yaml`
- `tests/security-scan/configs/prod-hardened/patches/deployment-prod.yaml`
- `tests/security-scan/configs/prod-hardened/patches/delete-ingress.yaml`
- `tests/security-scan/configs/prod-hardened/patches/delete-hpa.yaml`
- `tests/security-scan/configs/prod-hardened/patches/delete-postgres-pvc.yaml`
- `tests/security-scan/configs/prod-hardened/patches/postgres-ephemeral.json`
- `tests/security-scan/configs/prod-hardened/patches/deployment-replicas.json`

**Test:** `kustomize build tests/security-scan/configs/prod-hardened` succeeds and output contains `OAUTH2_ALLOWED_ORIGINS` set to `http://localhost:3000`.

```yaml
# kustomization.yaml
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization

resources:
  - ../../../../k8s/base

images:
  - name: docker.io/ianlintner068/oauth2-server
    newTag: test

patches:
  - path: patches/delete-ingress.yaml
  - path: patches/delete-hpa.yaml
  - path: patches/delete-postgres-pvc.yaml
  - path: patches/secret-prod.yaml
  - target:
      group: apps
      version: v1
      kind: Deployment
      name: oauth2-server
    path: patches/deployment-replicas.json
  - target:
      group: apps
      version: v1
      kind: Deployment
      name: oauth2-server
    path: patches/deployment-prod.yaml
  - target:
      group: apps
      version: v1
      kind: StatefulSet
      name: postgres
    path: patches/postgres-ephemeral.json
```

```yaml
# patches/secret-prod.yaml
apiVersion: v1
kind: Secret
metadata:
  name: oauth2-server-secret
stringData:
  OAUTH2_JWT_SECRET: "prod-scan-64char-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
  OAUTH2_SEED_PASSWORD: "prod-scan-seed-pw-change-me"
```

```yaml
# patches/deployment-prod.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: oauth2-server
spec:
  template:
    spec:
      containers:
        - name: oauth2-server
          env:
            - name: OAUTH2_ALLOWED_ORIGINS
              value: "http://localhost:3000"
            - name: RUST_LOG
              value: "info"
```

Reuse existing patches for delete-ingress, delete-hpa, delete-postgres-pvc, postgres-ephemeral, deployment-replicas — copy verbatim from `k8s/overlays/e2e-kind/patches/`.

---

### Task 3: Kustomize overlay — `dev-relaxed`

**Purpose:** Relaxed dev config. Short JWT secret, insecure defaults allowed, permissive CORS.

**Files:**

- `tests/security-scan/configs/dev-relaxed/kustomization.yaml`
- `tests/security-scan/configs/dev-relaxed/patches/secret-dev.yaml`
- `tests/security-scan/configs/dev-relaxed/patches/deployment-dev.yaml`
- (plus shared patches copied from prod-hardened)

**Test:** `kustomize build tests/security-scan/configs/dev-relaxed` output contains `OAUTH2_ALLOW_INSECURE_DEFAULTS: "1"` and `OAUTH2_JWT_SECRET` is short.

```yaml
# patches/secret-dev.yaml
apiVersion: v1
kind: Secret
metadata:
  name: oauth2-server-secret
stringData:
  OAUTH2_JWT_SECRET: "dev123"
  OAUTH2_SEED_PASSWORD: "changeme"
```

```yaml
# patches/deployment-dev.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: oauth2-server
spec:
  template:
    spec:
      containers:
        - name: oauth2-server
          env:
            - name: OAUTH2_ALLOW_INSECURE_DEFAULTS
              value: "1"
            - name: OAUTH2_PUBLIC_INTROSPECTION
              value: "1"
            - name: RUST_LOG
              value: "debug"
```

---

### Task 4: Kustomize overlay — `misconfig-cors`

**Purpose:** Strong auth but wildcard CORS.

```yaml
# patches/deployment-cors.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: oauth2-server
spec:
  template:
    spec:
      containers:
        - name: oauth2-server
          env:
            - name: OAUTH2_ALLOWED_ORIGINS
              value: "*"
            - name: OAUTH2_ALLOW_INSECURE_DEFAULTS
              value: "1"
```

```yaml
# patches/secret-cors.yaml — same strong JWT as prod-hardened
apiVersion: v1
kind: Secret
metadata:
  name: oauth2-server-secret
stringData:
  OAUTH2_JWT_SECRET: "cors-scan-64char-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
  OAUTH2_SEED_PASSWORD: "cors-scan-seed-pw"
```

**Test:** `kustomize build` output contains `OAUTH2_ALLOWED_ORIGINS: "*"`.

---

### Task 5: Kustomize overlay — `misconfig-auth`

**Purpose:** Strong JWT/CORS but admin auth bypass re-enabled (via env var if supported, else skip).

```yaml
# patches/deployment-auth.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: oauth2-server
spec:
  template:
    spec:
      containers:
        - name: oauth2-server
          env:
            - name: OAUTH2_ALLOW_INSECURE_DEFAULTS
              value: "1"
            - name: OAUTH2_PUBLIC_INTROSPECTION
              value: "1"
            - name: OAUTH2_ALLOWED_ORIGINS
              value: "http://localhost:3000"
```

**Test:** `kustomize build` succeeds.

---

### Task 6: Kustomize overlay — `edge-empty`

**Purpose:** Empty JWT secret — tests startup validation / fail-closed behavior.

```yaml
# patches/secret-empty.yaml
apiVersion: v1
kind: Secret
metadata:
  name: oauth2-server-secret
stringData:
  OAUTH2_JWT_SECRET: ""
  OAUTH2_SEED_PASSWORD: "edge-scan-seed-pw"
```

```yaml
# patches/deployment-empty.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: oauth2-server
spec:
  template:
    spec:
      containers:
        - name: oauth2-server
          env:
            - name: RUST_LOG
              value: "debug"
```

**Test:** `kustomize build` succeeds. (The server itself may crash on startup — that's the expected finding.)

---

### Task 7: Shared patches symlink script

To avoid duplicating delete-ingress, delete-hpa, delete-postgres-pvc, postgres-ephemeral, deployment-replicas across all 5 configs, create a `_shared/` directory and a setup script that copies or symlinks them.

**Files:**

- `tests/security-scan/configs/_shared/delete-ingress.yaml`
- `tests/security-scan/configs/_shared/delete-hpa.yaml`
- `tests/security-scan/configs/_shared/delete-postgres-pvc.yaml`
- `tests/security-scan/configs/_shared/postgres-ephemeral.json`
- `tests/security-scan/configs/_shared/deployment-replicas.json`

Each config's kustomization.yaml references `../_shared/<file>` for shared patches and `patches/<file>` for config-specific ones.

**Test:** All 5 `kustomize build` commands succeed.

---

### Task 8: `deploy-config.sh` — Deploy a single config to KinD

**File:** `tests/security-scan/scripts/deploy-config.sh`

Adapts `scripts/e2e_kind.sh` but:

- Takes `--config <name>` to pick the kustomize overlay
- Reuses existing cluster if present (no delete-recreate)
- Outputs the port-forwarded BASE_URL
- Runs readiness checks but no E2E flow tests

```bash
#!/usr/bin/env bash
set -euo pipefail

CONFIG_NAME="${1:?Usage: deploy-config.sh <config-name>}"
CLUSTER_NAME="${CLUSTER_NAME:-oauth2-security}"
NAMESPACE="${NAMESPACE:-security-scan}"
IMAGE_REF="${IMAGE_REF:-docker.io/ianlintner068/oauth2-server:test}"
PORT="${PORT:-}"
SKIP_IMAGE_BUILD="${SKIP_IMAGE_BUILD:-0}"

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
  echo "==> Creating KinD cluster (${CLUSTER_NAME})"
  mkdir -p "$(dirname "${KUBECONFIG}")"
  kind create cluster --name "${CLUSTER_NAME}" --kubeconfig "${KUBECONFIG}"
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
  echo "==> Building image (${IMAGE_REF})"
  docker build -t "${IMAGE_REF}" -f Dockerfile . 2>&1 | tail -5
fi
kind load docker-image "${IMAGE_REF}" --name "${CLUSTER_NAME}" 2>/dev/null || true

# Clean namespace
_kubectl delete namespace "${NAMESPACE}" --ignore-not-found 2>/dev/null || true
_kubectl create namespace "${NAMESPACE}"

# Deploy
echo "==> Deploying config: ${CONFIG_NAME}"
kustomize build "${KUSTOMIZE_DIR}" | _kubectl apply -n "${NAMESPACE}" -f -
_kubectl delete job flyway-migration -n "${NAMESPACE}" --ignore-not-found 2>/dev/null || true
kustomize build "${KUSTOMIZE_DIR}" | _kubectl apply -n "${NAMESPACE}" -f -

# Wait for postgres
echo "==> Waiting for Postgres"
_kubectl rollout status statefulset/postgres -n "${NAMESPACE}" --timeout=240s

# Wait for migration
echo "==> Waiting for migrations"
if ! _kubectl wait --for=condition=complete job/flyway-migration -n "${NAMESPACE}" --timeout=360s; then
  echo "Migration failed" >&2
  _kubectl logs -n "${NAMESPACE}" -l job-name=flyway-migration -c flyway --tail=100 >&2 || true
  exit 1
fi

# Restart deployment for clean start
_kubectl rollout restart deployment/oauth2-server -n "${NAMESPACE}"
echo "==> Waiting for oauth2-server"
if ! _kubectl rollout status deployment/oauth2-server -n "${NAMESPACE}" --timeout=240s; then
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

for _ in {1..60}; do
  curl -fsS "${BASE_URL}/health" >/dev/null 2>&1 && break
  sleep 1
done

echo '{"config":"'"${CONFIG_NAME}"'","status":"ready","base_url":"'"${BASE_URL}"'","port":'"${PORT}"',"pf_pid":'"${PF_PID}"'}'
```

**Test:** `bash tests/security-scan/scripts/deploy-config.sh prod-hardened` outputs JSON with `status: "ready"`.

---

### Task 9: `teardown-config.sh` — Tear down namespace

**File:** `tests/security-scan/scripts/teardown-config.sh`

```bash
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
```

---

### Task 10: OAuth2 Flow Tester scanner

**File:** `tests/security-scan/scanners/flow-tester.sh`

Tests OAuth2 endpoints using the LLM-generated `attacks.json` and `flows.json` scenarios. Outputs unified finding JSON.

```bash
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
      "{\"endpoint\":\"${ep}\",\"status\":${status}}"
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
    "{\"endpoint\":\"/auth/login\",\"status\":${login_status}}"
fi

# Test 3: Client registration without auth
unreg_status=$(curl -sS -X POST "${BASE_URL}/admin/clients/register" \
  -H "Content-Type: application/json" \
  -d '{"client_name":"unauth-test","redirect_uris":["http://evil.com"],"grant_types":["client_credentials"],"scope":"read"}' \
  -o /dev/null -w '%{http_code}' 2>/dev/null || echo "000")

if [[ "$unreg_status" == "200" || "$unreg_status" == "201" ]]; then
  _add_finding "FLOW-AUTH-001" "critical" "Unauthenticated client registration succeeded" \
    "{\"endpoint\":\"/admin/clients/register\",\"status\":${unreg_status}}"
fi

# Test 4: Open redirect via return_to
if [[ -f "${SCENARIOS_DIR}/attacks.json" ]]; then
  echo "$( jq -c '.[]' "${SCENARIOS_DIR}/attacks.json" 2>/dev/null )" | while IFS= read -r attack; do
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
```

**Test:** Run against a deployed prod-hardened config — expect 0 critical findings.

---

### Task 11: Timing Analyzer scanner

**File:** `tests/security-scan/scanners/timing-analyzer.py`

Python script that measures response times and applies Welch's t-test.

```python
#!/usr/bin/env python3
"""Timing analyzer — detects timing side-channels via statistical comparison."""

import argparse
import json
import sys
import time
import urllib.request
import urllib.parse
from datetime import datetime, timezone


def measure_endpoint(url: str, method: str, body: dict | None, n: int) -> list[float]:
    """Measure response time for n requests, return times in ms."""
    times = []
    data = None
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    if body:
        data = urllib.parse.urlencode(body).encode()
    for _ in range(n):
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        start = time.perf_counter()
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                resp.read()
        except Exception:
            pass
        elapsed = (time.perf_counter() - start) * 1000
        times.append(elapsed)
    return times


def welch_t_test(a: list[float], b: list[float]) -> tuple[float, float]:
    """Return (t_stat, p_value) for two-sample Welch's t-test."""
    import math
    n1, n2 = len(a), len(b)
    if n1 < 2 or n2 < 2:
        return 0.0, 1.0
    m1 = sum(a) / n1
    m2 = sum(b) / n2
    v1 = sum((x - m1) ** 2 for x in a) / (n1 - 1)
    v2 = sum((x - m2) ** 2 for x in b) / (n2 - 1)
    se = math.sqrt(v1 / n1 + v2 / n2) if (v1 / n1 + v2 / n2) > 0 else 1e-9
    t_stat = (m1 - m2) / se
    # Approximate p-value using normal distribution for large n
    p_value = 2 * (1 - _norm_cdf(abs(t_stat)))
    return t_stat, p_value


def _norm_cdf(x: float) -> float:
    """Approximate standard normal CDF."""
    import math
    return 0.5 * (1 + math.erf(x / math.sqrt(2)))


def main():
    parser = argparse.ArgumentParser(description="Timing side-channel analyzer")
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--config", required=True)
    parser.add_argument("--samples", type=int, default=30)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    findings = []

    # Test: login timing for valid vs invalid username
    valid_user_times = measure_endpoint(
        f"{args.base_url}/auth/login", "POST",
        {"username": "admin", "password": "wrong_password_xyz"}, args.samples
    )
    invalid_user_times = measure_endpoint(
        f"{args.base_url}/auth/login", "POST",
        {"username": "definitely_nonexistent_user_12345", "password": "wrong_password_xyz"}, args.samples
    )

    avg_valid = sum(valid_user_times) / len(valid_user_times)
    avg_invalid = sum(invalid_user_times) / len(invalid_user_times)
    diff = abs(avg_valid - avg_invalid)
    t_stat, p_value = welch_t_test(valid_user_times, invalid_user_times)

    if p_value < 0.05 and diff > 3.0:
        findings.append({
            "id": "TIMING-001",
            "severity": "medium",
            "category": "runtime",
            "title": f"Login timing variance {diff:.1f}ms between valid/invalid usernames (p={p_value:.4f})",
            "evidence": {
                "endpoint": "/auth/login",
                "measurements": [
                    {"input": "valid_user", "avg_ms": round(avg_valid, 2), "samples": args.samples},
                    {"input": "invalid_user", "avg_ms": round(avg_invalid, 2), "samples": args.samples},
                ],
                "variance_ms": round(diff, 2),
                "t_statistic": round(t_stat, 4),
                "p_value": round(p_value, 6),
            },
            "reproducible": None,
            "follow_up_suggested": True,
        })

    # Test: token endpoint timing for valid vs invalid client
    valid_client_times = measure_endpoint(
        f"{args.base_url}/oauth/token", "POST",
        {"grant_type": "client_credentials", "client_id": "default_client",
         "client_secret": "wrong_secret", "scope": "read"}, args.samples
    )
    invalid_client_times = measure_endpoint(
        f"{args.base_url}/oauth/token", "POST",
        {"grant_type": "client_credentials", "client_id": "nonexistent_client_xyz",
         "client_secret": "wrong_secret", "scope": "read"}, args.samples
    )

    avg_vc = sum(valid_client_times) / len(valid_client_times)
    avg_ic = sum(invalid_client_times) / len(invalid_client_times)
    diff_c = abs(avg_vc - avg_ic)
    t_stat_c, p_value_c = welch_t_test(valid_client_times, invalid_client_times)

    if p_value_c < 0.05 and diff_c > 3.0:
        findings.append({
            "id": "TIMING-002",
            "severity": "medium",
            "category": "runtime",
            "title": f"Token endpoint timing variance {diff_c:.1f}ms between valid/invalid clients (p={p_value_c:.4f})",
            "evidence": {
                "endpoint": "/oauth/token",
                "measurements": [
                    {"input": "valid_client", "avg_ms": round(avg_vc, 2), "samples": args.samples},
                    {"input": "invalid_client", "avg_ms": round(avg_ic, 2), "samples": args.samples},
                ],
                "variance_ms": round(diff_c, 2),
                "t_statistic": round(t_stat_c, 4),
                "p_value": round(p_value_c, 6),
            },
            "reproducible": None,
            "follow_up_suggested": True,
        })

    result = {
        "scanner": "timing-analyzer",
        "config": args.config,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "findings": findings,
    }
    with open(args.output, "w") as f:
        json.dump(result, f, indent=2)

    print(f"Timing analyzer: {len(findings)} findings for {args.config}")


if __name__ == "__main__":
    main()
```

**Test:** Run against a deployed config — produces valid JSON output.

---

### Task 12: Error Leakage Detector scanner

**File:** `tests/security-scan/scanners/error-leakage.sh`

Sends malformed requests and checks responses for stack traces, SQL fragments, internal paths.

```bash
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
```

---

### Task 13: Token Entropy Validator scanner

**File:** `tests/security-scan/scanners/token-entropy.py`

Collects multiple tokens and validates entropy + uniqueness.

```python
#!/usr/bin/env python3
"""Token entropy validator — checks randomness of issued tokens."""

import argparse
import json
import math
import sys
import urllib.request
import urllib.parse
from collections import Counter
from datetime import datetime, timezone


def get_token(base_url: str, client_id: str, client_secret: str) -> str | None:
    """Request a client_credentials token, return access_token or None."""
    data = urllib.parse.urlencode({
        "grant_type": "client_credentials",
        "client_id": client_id,
        "client_secret": client_secret,
        "scope": "read",
    }).encode()
    req = urllib.request.Request(
        f"{base_url}/oauth/token", data=data,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            body = json.loads(resp.read())
            return body.get("access_token")
    except Exception:
        return None


def shannon_entropy(s: str) -> float:
    """Calculate Shannon entropy in bits per character."""
    if not s:
        return 0.0
    freq = Counter(s)
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())


def register_client(base_url: str, cookie_jar_path: str) -> tuple[str, str] | None:
    """Register a test client using admin session cookie."""
    import http.cookiejar
    cj = http.cookiejar.MozillaCookieJar(cookie_jar_path)
    cj.load(ignore_discard=True, ignore_expires=True)
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))
    data = json.dumps({
        "client_name": "entropy-test",
        "redirect_uris": ["http://localhost:3000/callback"],
        "grant_types": ["client_credentials"],
        "scope": "read",
    }).encode()
    req = urllib.request.Request(
        f"{base_url}/admin/clients/register", data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with opener.open(req, timeout=10) as resp:
            body = json.loads(resp.read())
            return body.get("client_id"), body.get("client_secret")
    except Exception:
        return None


def main():
    parser = argparse.ArgumentParser(description="Token entropy validator")
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--config", required=True)
    parser.add_argument("--client-id", default="")
    parser.add_argument("--client-secret", default="")
    parser.add_argument("--cookie-jar", default="")
    parser.add_argument("--count", type=int, default=20)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    findings = []

    cid, csecret = args.client_id, args.client_secret
    if (not cid or not csecret) and args.cookie_jar:
        result = register_client(args.base_url, args.cookie_jar)
        if result:
            cid, csecret = result

    if not cid or not csecret:
        findings.append({
            "id": "ENTROPY-SKIP",
            "severity": "info",
            "category": "runtime",
            "title": "Could not obtain client credentials — skipping token entropy test",
            "evidence": {},
            "reproducible": None,
            "follow_up_suggested": False,
        })
    else:
        tokens = []
        for _ in range(args.count):
            t = get_token(args.base_url, cid, csecret)
            if t:
                tokens.append(t)

        if len(tokens) < 5:
            findings.append({
                "id": "ENTROPY-FAIL",
                "severity": "medium",
                "category": "runtime",
                "title": f"Only {len(tokens)}/{args.count} tokens obtained",
                "evidence": {"obtained": len(tokens), "requested": args.count},
                "reproducible": None,
                "follow_up_suggested": True,
            })
        else:
            # Check uniqueness
            unique = len(set(tokens))
            if unique < len(tokens):
                findings.append({
                    "id": "ENTROPY-DUP",
                    "severity": "critical",
                    "category": "runtime",
                    "title": f"Duplicate tokens detected: {len(tokens)-unique} duplicates in {len(tokens)} tokens",
                    "evidence": {"total": len(tokens), "unique": unique},
                    "reproducible": None,
                    "follow_up_suggested": True,
                })

            # Check entropy
            entropies = [shannon_entropy(t) for t in tokens]
            avg_entropy = sum(entropies) / len(entropies)
            min_entropy = min(entropies)

            # JWTs typically have high entropy (>4.0 bits/char)
            if min_entropy < 3.0:
                findings.append({
                    "id": "ENTROPY-LOW",
                    "severity": "high",
                    "category": "runtime",
                    "title": f"Low token entropy: min={min_entropy:.2f} bits/char (threshold: 3.0)",
                    "evidence": {
                        "avg_entropy": round(avg_entropy, 4),
                        "min_entropy": round(min_entropy, 4),
                        "sample_count": len(tokens),
                        "sample_lengths": [len(t) for t in tokens[:3]],
                    },
                    "reproducible": None,
                    "follow_up_suggested": True,
                })

    result = {
        "scanner": "token-entropy",
        "config": args.config,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "findings": findings,
    }
    with open(args.output, "w") as f:
        json.dump(result, f, indent=2)

    print(f"Token entropy: {len(findings)} findings for {args.config}")


if __name__ == "__main__":
    main()
```

---

### Task 14: `run-scanners.sh` — Run all scanners against a deployed config

**File:** `tests/security-scan/scripts/run-scanners.sh`

```bash
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
```

---

### Task 15: `security-scan.sh` — Main orchestration entrypoint

**File:** `tests/security-scan/scripts/security-scan.sh`

```bash
#!/usr/bin/env bash
set -euo pipefail

CONFIGS=("prod-hardened" "dev-relaxed" "misconfig-cors" "misconfig-auth" "edge-empty")
FEEDBACK_LOOPS="${FEEDBACK_LOOPS:-0}"
CLUSTER_NAME="${CLUSTER_NAME:-oauth2-security}"
NAMESPACE="${NAMESPACE:-security-scan}"
BUDGET_MINUTES="${BUDGET_MINUTES:-30}"
SKIP_IMAGE_BUILD="${SKIP_IMAGE_BUILD:-0}"

_usage() {
  cat <<'USAGE'
Usage: tests/security-scan/scripts/security-scan.sh [OPTIONS]

Options:
  --matrix all|<config>   Run all configs or a single config (default: all)
  --feedback-loops N      Max LLM feedback rounds per finding (default: 0)
  --budget Nm             Wall-clock budget in minutes (default: 30)
  --skip-build            Skip Docker image build
  -h, --help              Show this help

Environment:
  CLUSTER_NAME     (default: oauth2-security)
  NAMESPACE        (default: security-scan)
  ANTHROPIC_API_KEY  Required for feedback loops > 0
USAGE
}

MATRIX="all"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --matrix) MATRIX="$2"; shift 2 ;;
    --feedback-loops) FEEDBACK_LOOPS="$2"; shift 2 ;;
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

if [[ "$FEEDBACK_LOOPS" -gt 0 ]] && [[ -z "${ANTHROPIC_API_KEY:-}" ]]; then
  echo "ANTHROPIC_API_KEY required for feedback loops" >&2
  exit 1
fi

export CLUSTER_NAME NAMESPACE SKIP_IMAGE_BUILD

echo "========================================"
echo "  Security Scan — $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "  Configs: ${CONFIGS[*]}"
echo "  Feedback loops: ${FEEDBACK_LOOPS}"
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
```

---

### Task 16: `.gitignore` update for reports/

Append to root `.gitignore`:

```
# Security scan reports (generated, not committed)
reports/
```

---

### Task 17: Validate all kustomize overlays build

**Test script** (not committed, run locally):

```bash
for config in prod-hardened dev-relaxed misconfig-cors misconfig-auth edge-empty; do
  echo "Building: $config"
  kustomize build "tests/security-scan/configs/$config" > /dev/null
  echo "  OK"
done
```

---

## Execution Order

```
Task 1:  Directory scaffolding + .gitignore
Task 7:  Shared patches (_shared/)
Tasks 2-6: Kustomize overlays (parallel — independent)
Task 17: Validate all overlays build
Tasks 8-9: Deploy/teardown scripts
Tasks 10-13: Scanner implementations (parallel — independent)
Task 14: run-scanners.sh (depends on 10-13)
Task 15: security-scan.sh (depends on 8, 9, 14)
Task 16: Final .gitignore update
```

---

## Review Checklist

- [ ] All 5 kustomize overlays build without error
- [ ] `deploy-config.sh` successfully deploys prod-hardened to KinD
- [ ] All 4 scanners produce valid unified JSON output
- [ ] `run-scanners.sh` runs all scanners in parallel and merges results
- [ ] `security-scan.sh --matrix prod-hardened` completes end-to-end
- [ ] `reports/` is gitignored
- [ ] No hardcoded secrets (scan configs use clearly-labeled test values)
- [ ] edge-empty config handles startup failure gracefully

---

## Phase 2 (Future)

- OWASP ZAP scanner (ZAP Docker image as KinD Job)
- kubeaudit / kube-bench infrastructure scanners
- `llm-analyze.sh` for Claude API feedback loop integration
- `seed-data.sh` for LLM-generated scenario seeding
- Report generation (summary.md, remediation.md)
