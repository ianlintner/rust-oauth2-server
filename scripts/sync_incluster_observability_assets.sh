#!/usr/bin/env bash
set -euo pipefail

# Syncs observability assets into the in-cluster Kustomize component.
#
# Why:
# - kustomize has load restrictions that prevent referencing files outside a component
# - keeping the component self-contained makes `kubectl apply -k` work everywhere

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

SRC_RULES_DIR="${ROOT_DIR}/observability/prometheus/rules"
SRC_DASHBOARDS_DIR="${ROOT_DIR}/observability/grafana/dashboards"

DST_RULES_DIR="${ROOT_DIR}/k8s/components/observability/assets/prometheus/rules"
DST_DASHBOARDS_DIR="${ROOT_DIR}/k8s/components/observability/assets/grafana/dashboards"

mkdir -p "${DST_RULES_DIR}" "${DST_DASHBOARDS_DIR}"

cp -f "${SRC_RULES_DIR}/oauth2_server_alerts.yml" "${DST_RULES_DIR}/oauth2_server_alerts.yml"
cp -f "${SRC_RULES_DIR}/oauth2_server_slos.yml" "${DST_RULES_DIR}/oauth2_server_slos.yml"

cp -f "${SRC_DASHBOARDS_DIR}/oauth2-server-overview.json" "${DST_DASHBOARDS_DIR}/oauth2-server-overview.json"
cp -f "${SRC_DASHBOARDS_DIR}/oauth2-server-slos.json" "${DST_DASHBOARDS_DIR}/oauth2-server-slos.json"

echo "==> Synced in-cluster observability assets"
