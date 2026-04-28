.PHONY: help kind-observability-up kind-observability-down kind-observability-traffic kind-observability-sync \
        compliance-report compliance-report-with-results

help:
	@echo "Common targets:"
	@echo "  make compliance-report                  Regenerate the RFC compliance matrix (Markdown + JSON + JUnit XML) from source annotations"
	@echo "  make compliance-report-with-results     As above, but first runs the compliance test suite to fold in real pass/fail status"
	@echo "  make kind-observability-up              Bring up KIND cluster + app + in-cluster observability (Grafana/Jaeger port-forwards)"
	@echo "  make kind-observability-traffic         Generate synthetic traffic in the cluster (for dashboards/SLOs)"
	@echo "  make kind-observability-sync            Sync repo observability assets into the in-cluster kustomize component"
	@echo "  make kind-observability-down            Delete the KIND cluster used for observability"
	@echo ""
	@echo "Useful overrides (env vars):"
	@echo "  CLUSTER_NAME (default oauth2-observability)"
	@echo "  NAMESPACE    (default oauth2-server)"
	@echo "  IMAGE_REF    (default docker.io/ianlintner068/oauth2-server:test)"
	@echo "  SKIP_IMAGE_BUILD=1 (use prebuilt local image tag)"
	@echo "  RECREATE_CLUSTER=0 (reuse existing cluster)"

# -----------------------------------------------------------------------------
# RFC compliance reporting
# -----------------------------------------------------------------------------
# `make compliance-report` regenerates the matrix from source annotations only
# (status will be "unknown" because no test results are folded in).
#
# `make compliance-report-with-results` runs the relevant test binaries with
# stable libtest pretty output, captures it, and runs the report generator
# with `--results`, so the matrix shows real pass/fail/ignored status.
compliance-report:
	@cargo run --bin compliance_report

compliance-report-with-results:
	@mkdir -p target
	@echo "Running compliance test binaries (this may take a minute)..." >&2
	@cargo test --no-fail-fast \
		--test 'compliance_*' --test 'rfc_compliance' \
		--test 'rfc8252_native_apps' --test 'rfc9700_*' \
		--test 'phase2_rfc_compliance' \
		--all-features --locked -- --nocapture --test-threads=1 \
		> target/compliance-tests.txt 2>&1 || true
	@cargo run --bin compliance_report -- --results target/compliance-tests.txt

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
