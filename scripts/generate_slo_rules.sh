#!/usr/bin/env bash
set -euo pipefail

# Generates Prometheus SLO recording + alerting rules using Sloth.
#
# Requires:
# - Docker
#
# Output is committed to the repo so Prometheus can load it without Sloth at runtime.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# Use repo-relative paths for Sloth because the spec is mounted into the container at /work.
SLO_SPEC_FILE_REL="observability/slo/sloth/oauth2-server.yml"
OUT_RULES_FILE_REL="observability/prometheus/rules/oauth2_server_slos.yml"


SLO_SPEC_FILE="${ROOT_DIR}/${SLO_SPEC_FILE_REL}"
OUT_RULES_FILE="${ROOT_DIR}/${OUT_RULES_FILE_REL}"

SLOTH_IMAGE="ghcr.io/slok/sloth:v0.15.0"

if ! command -v docker >/dev/null 2>&1; then
  echo "docker is required to run Sloth (ghcr.io/slok/sloth)." >&2
  exit 1
fi

if [[ ! -f "${SLO_SPEC_FILE}" ]]; then
  echo "SLO spec not found: ${SLO_SPEC_FILE}" >&2
  exit 1
fi

echo "==> Validating SLO spec with Sloth"
docker run --rm \
  -v "${ROOT_DIR}:/work" \
  -w /work \
  "${SLOTH_IMAGE}" validate \
  --input "${SLO_SPEC_FILE_REL}"

echo "==> Generating Prometheus rules: ${OUT_RULES_FILE}"
docker run --rm \
  -v "${ROOT_DIR}:/work" \
  -w /work \
  "${SLOTH_IMAGE}" generate \
  -i "${SLO_SPEC_FILE_REL}" \
  -o "${OUT_RULES_FILE_REL}"

echo "==> Syncing observability assets into in-cluster component"
"${ROOT_DIR}/scripts/sync_incluster_observability_assets.sh"

echo "==> Done"
