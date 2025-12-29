.PHONY: help kind-observability-up kind-observability-down kind-observability-traffic kind-observability-sync

help:
	@echo "Common targets:"
	@echo "  make kind-observability-up     Bring up KIND cluster + app + in-cluster observability (Grafana/Jaeger port-forwards)"
	@echo "  make kind-observability-traffic Generate synthetic traffic in the cluster (for dashboards/SLOs)"
	@echo "  make kind-observability-sync   Sync repo observability assets into the in-cluster kustomize component"
	@echo "  make kind-observability-down   Delete the KIND cluster used for observability"
	@echo ""
	@echo "Useful overrides (env vars):"
	@echo "  CLUSTER_NAME (default oauth2-observability)"
	@echo "  NAMESPACE    (default oauth2-server)"
	@echo "  IMAGE_REF    (default docker.io/ianlintner068/oauth2-server:test)"
	@echo "  SKIP_IMAGE_BUILD=1 (use prebuilt local image tag)"
	@echo "  RECREATE_CLUSTER=0 (reuse existing cluster)"

kind-observability-up:
	@bash scripts/kind_up_observability.sh

kind-observability-traffic:
	@bash scripts/kind_generate_traffic.sh

kind-observability-sync:
	@bash scripts/sync_incluster_observability_assets.sh

kind-observability-down:
	@CLUSTER_NAME=$${CLUSTER_NAME:-oauth2-observability} ; \
	if command -v kind >/dev/null 2>&1; then \
		kind delete cluster --name "$${CLUSTER_NAME}"; \
	else \
		echo "kind not found" >&2; exit 1; \
	fi
