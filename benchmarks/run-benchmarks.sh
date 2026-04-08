#!/usr/bin/env bash
###############################################################################
# OAuth2 Server Load Test Comparison — Main Orchestrator
#
# Runs k6 load tests against each OAuth2 server sequentially,
# ensuring fair comparison with identical resource constraints.
#
# Usage:
#   ./run-benchmarks.sh                    # Run all servers, light profile
#   ./run-benchmarks.sh --profile medium   # Medium load profile
#   ./run-benchmarks.sh --servers rust,hydra --profile heavy
#   ./run-benchmarks.sh --scenarios client-credentials --iterations 5
###############################################################################
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# ── Defaults ─────────────────────────────────────────────────────────────────
ALL_SERVERS="rust rust-mongo keycloak hydra authentik node-oidc"
ALL_SCENARIOS="client-credentials token-introspect discovery health"
LOAD_PROFILE="light"
ITERATIONS=3
SELECTED_SERVERS=""
SELECTED_SCENARIOS=""
SKIP_BUILD=false
COOLDOWN=30

# ── Parse arguments ──────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case "$1" in
    --profile)    LOAD_PROFILE="$2"; shift 2 ;;
    --servers)    SELECTED_SERVERS="$2"; shift 2 ;;
    --scenarios)  SELECTED_SCENARIOS="$2"; shift 2 ;;
    --iterations) ITERATIONS="$2"; shift 2 ;;
    --skip-build) SKIP_BUILD=true; shift ;;
    --cooldown)   COOLDOWN="$2"; shift 2 ;;
    --help|-h)
      echo "Usage: $0 [OPTIONS]"
      echo ""
      echo "Options:"
      echo "  --profile PROFILE       Load profile: light, medium, heavy (default: light)"
      echo "  --servers SERVER,...     Comma-separated servers (default: all)"
      echo "  --scenarios SCENARIO,.. Comma-separated scenarios (default: all)"
      echo "  --iterations N          Number of test iterations per scenario (default: 3)"
      echo "  --skip-build            Skip Docker image builds"
      echo "  --cooldown SECONDS      Cooldown between tests (default: 30)"
      echo ""
      echo "Available servers: $ALL_SERVERS"
      echo "Available scenarios: $ALL_SCENARIOS"
      exit 0
      ;;
    *) echo "Unknown option: $1"; exit 1 ;;
  esac
done

SERVERS="${SELECTED_SERVERS:-$ALL_SERVERS}"
SERVERS="${SERVERS//,/ }"
SCENARIOS="${SELECTED_SCENARIOS:-$ALL_SCENARIOS}"
SCENARIOS="${SCENARIOS//,/ }"

# ── Colours ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

log()  { echo -e "${BLUE}[bench]${NC} $*"; }
ok()   { echo -e "${GREEN}[  ok ]${NC} $*"; }
warn() { echo -e "${YELLOW}[warn ]${NC} $*"; }
err()  { echo -e "${RED}[error]${NC} $*"; }

# ── Preflight checks ────────────────────────────────────────────────────────
command -v docker >/dev/null 2>&1 || { err "docker not found"; exit 1; }
command -v docker compose >/dev/null 2>&1 || { err "docker compose not found"; exit 1; }

mkdir -p results

log "═══════════════════════════════════════════════════════════"
log "  OAuth2 Server Load Test Comparison"
log "═══════════════════════════════════════════════════════════"
log "  Profile:    ${LOAD_PROFILE}"
log "  Servers:    ${SERVERS}"
log "  Scenarios:  ${SCENARIOS}"
log "  Iterations: ${ITERATIONS}"
log "  Cooldown:   ${COOLDOWN}s"
log "═══════════════════════════════════════════════════════════"

# ── Build images ─────────────────────────────────────────────────────────────
if [[ "$SKIP_BUILD" == "false" ]]; then
  log "Building Docker images..."
  docker compose build --parallel 2>&1 | tail -5
  ok "Images built"
fi

# ── Start shared infrastructure ──────────────────────────────────────────────
log "Starting PostgreSQL..."
docker compose up -d bench-postgres
log "Waiting for PostgreSQL to be healthy..."
for i in $(seq 1 60); do
  if docker compose exec -T bench-postgres pg_isready -U postgres >/dev/null 2>&1; then
    break
  fi
  sleep 1
done
ok "PostgreSQL is ready"

# ── Helper: wait for a container's health check ──────────────────────────────
wait_healthy() {
  local service="$1"
  local max_wait="${2:-120}"
  log "Waiting for ${service} to be healthy (max ${max_wait}s)..."

  local container_id
  container_id=$(docker compose ps -q "$service" 2>/dev/null | head -1)
  if [[ -z "$container_id" ]]; then
    err "Could not resolve container id for service: ${service}"
    return 1
  fi

  for i in $(seq 1 "$max_wait"); do
    local status
    status=$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$container_id" 2>/dev/null || echo "unknown")

    if [[ "$status" == "healthy" || "$status" == "running" ]]; then
      ok "${service} is healthy (${i}s)"
      return 0
    fi

    if [[ "$status" == "exited" || "$status" == "dead" ]]; then
      err "${service} entered state: ${status}"
      docker compose logs --tail=50 "$service"
      return 1
    fi

    sleep 1
  done

  err "${service} did not become healthy within ${max_wait}s"
  docker compose logs --tail=20 "$service"
  return 1
}

run_rust_migrations() {
  log "Applying SQL migrations for Rust benchmark database..."

  local migration_dir="${SCRIPT_DIR}/../migrations/sql"
  if [[ ! -d "$migration_dir" ]]; then
    err "Migration directory not found: $migration_dir"
    return 1
  fi

  for sql_file in "$migration_dir"/V*.sql; do
    if [[ ! -f "$sql_file" ]]; then
      continue
    fi

    if ! docker compose exec -T bench-postgres psql -U postgres -d oauth2_rust -v ON_ERROR_STOP=1 < "$sql_file" >/dev/null; then
      err "Failed to apply migration: $(basename "$sql_file")"
      return 1
    fi
  done

  # Ensure benchmark client exists for client_credentials tests
  if ! docker compose exec -T bench-postgres psql -U postgres -d oauth2_rust -v ON_ERROR_STOP=1 >/dev/null <<'SQL'; then
INSERT INTO clients (
  id, client_id, client_secret, redirect_uris, grant_types, scope, name, created_at, updated_at
) VALUES (
  'bench-client-id',
  'bench-client',
  'bench-secret-12345678',
  '["http://localhost/callback"]',
  '["client_credentials"]',
  'openid profile email',
  'Benchmark Client',
  NOW(),
  NOW()
)
ON CONFLICT (client_id) DO UPDATE SET
  client_secret = EXCLUDED.client_secret,
  redirect_uris = EXCLUDED.redirect_uris,
  grant_types = EXCLUDED.grant_types,
  scope = EXCLUDED.scope,
  updated_at = NOW();
SQL
    err "Failed to seed benchmark client for Rust database"
    return 1
  fi

  ok "Rust migrations and benchmark client setup complete"
}

run_rust_mongo_seed() {
  log "Seeding benchmark client in MongoDB for rust-mongo..."

  if ! docker compose exec -T bench-mongo mongosh --quiet "mongodb://localhost:27017/oauth2_bench" --eval '
const now = new Date().toISOString();
db.clients.updateOne(
  { client_id: "bench-client" },
  {
    $set: {
      id: "bench-client-id",
      client_id: "bench-client",
      client_secret: "bench-secret-12345678",
      redirect_uris: "[\"http://localhost/callback\"]",
      grant_types: "[\"client_credentials\"]",
      scope: "openid profile email",
      name: "Benchmark Client",
      updated_at: now,
    },
    $setOnInsert: {
      created_at: now,
    },
  },
  { upsert: true },
);
' >/dev/null; then
    err "Failed to seed benchmark client for rust-mongo"
    return 1
  fi

  ok "Rust Mongo benchmark client seeded"
}

# ── Helper: setup client for servers that need API registration ──────────────
setup_client() {
  local server="$1"

  case "$server" in
    rust)
      # rust benchmark client is seeded directly into Postgres in run_rust_migrations.
      ok "Rust benchmark client pre-seeded (PostgreSQL)"
      ;;

    rust-mongo)
      # rust-mongo benchmark client is seeded directly into Mongo.
      run_rust_mongo_seed
      ;;

    keycloak)
      # Client is pre-configured via realm import
      ok "Keycloak client pre-configured via realm import"
      ;;

    hydra)
      log "Registering client on Hydra..."
      docker compose exec -T bench-hydra wget -q -O - \
        --post-data='{"client_id":"bench-client","client_secret":"bench-secret-12345678","grant_types":["client_credentials"],"response_types":[],"scope":"openid","token_endpoint_auth_method":"client_secret_post"}' \
        --header="Content-Type: application/json" \
        "http://localhost:4445/admin/clients" 2>/dev/null || true
      ok "Hydra client registered"
      ;;

    authentik)
      log "Setting up Authentik OAuth2 provider and application..."
      local API_URL="http://localhost:9000/api/v3"
      local TOKEN="bench-bootstrap-token-12345678"
      local AUTH_HEADER="Authorization: Bearer ${TOKEN}"

      # Create OAuth2 provider
      docker compose exec -T bench-authentik wget -q -O - \
        --post-data='{"name":"benchmark-provider","authorization_flow":"default-provider-authorization-implicit-consent","client_id":"bench-client","client_secret":"bench-secret-12345678","client_type":"confidential","include_claims_in_id_token":true,"sub_mode":"user_id","issuer_mode":"per_provider","property_mappings":[],"redirect_uris":"http://localhost/callback"}' \
        --header="Content-Type: application/json" \
        --header="$AUTH_HEADER" \
        "${API_URL}/providers/oauth2/" 2>/dev/null || true

      # Create application linked to provider
      docker compose exec -T bench-authentik wget -q -O - \
        --post-data='{"name":"benchmark","slug":"benchmark","provider":1,"meta_launch_url":"http://localhost/"}' \
        --header="Content-Type: application/json" \
        --header="$AUTH_HEADER" \
        "${API_URL}/core/applications/" 2>/dev/null || true

      ok "Authentik provider and application created"
      ;;

    node-oidc)
      # Client is pre-configured in server.js
      ok "node-oidc-provider client pre-configured"
      ;;
  esac
}

# ── Helper: get Docker container resource stats ──────────────────────────────
collect_stats() {
  local container="$1"
  local output_file="$2"
  # Sample container stats 5 times over 5 seconds
  docker stats --no-stream --format '{"cpu":"{{.CPUPerc}}","mem":"{{.MemUsage}}","mem_perc":"{{.MemPerc}}","net":"{{.NetIO}}","time":"{{.ID}}"}' "$container" > "$output_file" 2>/dev/null || true
}

# ── Helper: run k6 test ─────────────────────────────────────────────────────
run_k6() {
  local server="$1"
  local scenario="$2"
  local iteration="$3"

  log "  Running ${scenario} (iteration ${iteration}/${ITERATIONS})..."

  # Run k6 as the host user so it can write to the bind-mounted results dir
  # (the grafana/k6 image defaults to non-root uid 12345 which may lack
  # write permission on the host-owned directory).
  docker compose run --rm \
    --user "$(id -u):$(id -g)" \
    -e SERVER="$server" \
    -e LOAD_PROFILE="$LOAD_PROFILE" \
    -e ITERATION="$iteration" \
    --entrypoint "" \
    bench-k6 \
    k6 run \
      --env SERVER="$server" \
      --env LOAD_PROFILE="$LOAD_PROFILE" \
      --env ITERATION="$iteration" \
      --summary-export="/results/${server}_${scenario}_${LOAD_PROFILE}_${iteration}_summary.json" \
      "/scripts/scenarios/${scenario}.js" \
    2>&1 | tail -20

  ok "  Completed ${scenario} iteration ${iteration}"
}

# ── Helper: get the services needed for each server ──────────────────────────
get_server_services() {
  local server="$1"
  case "$server" in
    rust)      echo "bench-rust" ;;
    rust-mongo) echo "bench-mongo bench-rust-mongo" ;;
    keycloak)  echo "bench-keycloak" ;;
    hydra)     echo "bench-hydra-migrate bench-hydra" ;;
    authentik) echo "bench-authentik-redis bench-authentik-worker bench-authentik" ;;
    node-oidc) echo "bench-node-oidc" ;;
  esac
}

get_main_service() {
  local server="$1"
  case "$server" in
    rust)      echo "bench-rust" ;;
    rust-mongo) echo "bench-rust-mongo" ;;
    keycloak)  echo "bench-keycloak" ;;
    hydra)     echo "bench-hydra" ;;
    authentik) echo "bench-authentik" ;;
    node-oidc) echo "bench-node-oidc" ;;
  esac
}

get_health_wait() {
  local server="$1"
  case "$server" in
    keycloak)  echo "300" ;;  # JVM startup is slow, especially in CI
    authentik) echo "180" ;;  # Python + Django migrations
    *)         echo "60" ;;
  esac
}

# ── Main test loop ───────────────────────────────────────────────────────────
TOTAL_TESTS=0
PASSED_TESTS=0

for server in $SERVERS; do
  echo ""
  log "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  log "  Testing: ${server}"
  log "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

  services=$(get_server_services "$server")
  main_service=$(get_main_service "$server")
  health_wait=$(get_health_wait "$server")

  # Start server
  log "Starting ${server} services: ${services}..."

  if [[ "$server" == "rust" ]]; then
    run_rust_migrations
  fi

  # shellcheck disable=SC2086
  docker compose up -d $services

  # Wait for health
  if ! wait_healthy "$main_service" "$health_wait"; then
    err "Skipping ${server} — failed to start"
    docker compose stop $services 2>/dev/null || true
    continue
  fi

  # JVM warmup for Java-based servers
  if [[ "$server" == "keycloak" ]]; then
    log "JVM warmup: sending 100 requests..."
    for _ in $(seq 1 100); do
      docker compose exec -T "$main_service" \
        curl -sf "http://localhost:8080/health/ready" >/dev/null 2>&1 || true
    done
    ok "JVM warmup complete"
  fi

  # Register client
  setup_client "$server"
  sleep 2

  # Collect pre-test stats
  collect_stats "$(docker compose ps -q "$main_service" 2>/dev/null)" \
    "results/${server}_stats_pre.json"

  # Run each scenario
  for scenario in $SCENARIOS; do
    log "  ── Scenario: ${scenario} ──"

    for iter in $(seq 1 "$ITERATIONS"); do
      TOTAL_TESTS=$((TOTAL_TESTS + 1))
      if run_k6 "$server" "$scenario" "$iter"; then
        PASSED_TESTS=$((PASSED_TESTS + 1))
      else
        warn "  Test failed: ${server}/${scenario} iteration ${iter}"
      fi

      # Cooldown between iterations (except the last)
      if [[ "$iter" -lt "$ITERATIONS" ]]; then
        sleep 5
      fi
    done

    # Cooldown between scenarios
    sleep "$COOLDOWN"
  done

  # Collect post-test stats
  collect_stats "$(docker compose ps -q "$main_service" 2>/dev/null)" \
    "results/${server}_stats_post.json"

  # Stop server
  log "Stopping ${server}..."
  # shellcheck disable=SC2086
  docker compose stop $services
  sleep 5

  ok "Completed all tests for ${server}"
done

# ── Summary ──────────────────────────────────────────────────────────────────
echo ""
log "═══════════════════════════════════════════════════════════"
log "  Benchmark Complete"
log "═══════════════════════════════════════════════════════════"
log "  Tests run:    ${TOTAL_TESTS}"
log "  Tests passed: ${PASSED_TESTS}"
log "  Results in:   ${SCRIPT_DIR}/results/"
log ""
log "  Run ./analyze-results.sh to generate the comparison report."
log "═══════════════════════════════════════════════════════════"

# Clean up
log "Stopping all remaining services..."
docker compose down

ok "Done."
