# Testing

## For AI Agents

> **Prompt:** "Run the full CI test suite for rust-oauth2-server, including formatting, linting, and all tests"

**Common testing tasks:**

| Task | Prompt Example |
|------|----------------|
| Run full CI gate | "Run all CI checks: formatting, clippy, and tests" |
| Fix formatting | "Auto-fix all formatting issues with cargo fmt" |
| Run specific tests | "Run only the OAuth2 integration tests in oauth2-actix crate" |
| Run RFC tests | "Run the RFC compliance test suite" |
| Debug test failure | "The test 'test_pkce_flow' is failing - help me debug it" |
| Add new test | "Add a new integration test for device authorization flow" |
| Run BDD tests | "Run the Cucumber BDD feature tests" |
| Benchmark | "Run the benchmark suite and compare performance" |

**Quick test commands:**
```bash
# Full CI gate (required before PR)
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --verbose --all-features --locked

# Auto-fix formatting
cargo fmt --all

# Fast iteration
cargo check --all-features
cargo test -p oauth2-actix
cargo test --test rfc_compliance

# Docs validation
python3 -m mkdocs build --strict
```

**Key test files:**
- `tests/rfc_compliance.rs` - RFC spec compliance
- `tests/security_http.rs` - Security integration tests
- `tests/device_flow.rs` - Device authorization flow
- `tests/bdd/` - BDD feature tests

---

This repo has fast local checks, database-backed integration tests, KIND-based end-to-end flows, and a benchmark harness. The only rule that really matters: run the full gate before you call a change done.

## Local CI gate

These are the required local checks for this repository:

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --verbose --all-features --locked
```

If `cargo fmt --check` fails, run `cargo fmt --all` and re-check.

If you changed docs, also run:

```bash
python3 -m mkdocs build --strict
```

## Fast local loops

Use smaller commands while iterating:

```bash
cargo check --all-features
cargo test -p oauth2-actix
cargo test --test integration
```

Useful pitfall from this repo: if you add a new `web::Data<T>` dependency to a handler, update the `App::new()` builders in `tests/security_http.rs` or the integration suite will start yelling for good reasons.

## Integration tests

Integration tests expect a working database.

- CI provides Postgres through service containers
- locally, point `OAUTH2_DATABASE_URL` at your Postgres instance or compose stack

Example:

```bash
export OAUTH2_DATABASE_URL=postgresql://user:pass@localhost:5432/oauth2
cargo test --test integration
```

## RFC compliance tests

RFC-level compliance tests live in dedicated files under `tests/`. Each file maps test functions to specific RFC sections — see `docs/compliance/RFC_COMPLIANCE.md` for the full coverage matrix.

| File | RFCs covered |
| ---- | ------------ |
| `tests/compliance_rfc6749.rs` | RFC 6749 core |
| `tests/compliance_rfc6750.rs` | RFC 6750 bearer token usage |
| `tests/compliance_rfc7636.rs` | RFC 7636 PKCE |
| `tests/compliance_rfc7662_7009.rs` | RFC 7662 introspection + RFC 7009 revocation |
| `tests/compliance_rfc8414.rs` | RFC 8414 authorization server metadata |
| `tests/compliance_rfc8628.rs` | RFC 8628 device authorization grant |
| `tests/compliance_oidc_core.rs` | OIDC Core 1.0 |
| `tests/compliance_wave3.rs` | RFC 9126 PAR, RFC 8707 resource indicators, RFC 9701 JWT introspection |
| `tests/phase2_rfc_compliance.rs` | RFC 7591/7592 dynamic client registration, RFC 7523 JWT client auth |
| `tests/compliance_wave4.rs` | DPoP, mTLS, token exchange, RAR, step-up, protected resource metadata (discovery advertising) |

Run all compliance tests:

```bash
cargo test --test compliance_rfc6749 --test compliance_rfc6750 \
  --test compliance_rfc7636 --test compliance_rfc7662_7009 \
  --test compliance_rfc8414 --test compliance_rfc8628 \
  --test compliance_oidc_core --test compliance_wave3 \
  --test phase2_rfc_compliance --test compliance_wave4
```

Or run all tests at once:

```bash
cargo test --all-features --locked
```

```bash
cargo test --test bdd
```

## Testcontainers and feature-gated backends

Some suites require Docker and optional features.

Example Mongo storage run:

```bash
RUN_TESTCONTAINERS=1 cargo test --test mongo_storage --features mongo
```

Use the same pattern for other feature-gated backends when the test target requires real infrastructure.

## KIND end-to-end flows

Local and CI-compatible cluster smoke tests live in:

- `scripts/e2e_kind.sh`
- `scripts/e2e_kind_extended.sh`

Typical prerequisites:

- Docker
- kind
- kubectl
- kustomize
- jq

The standard flow builds an image, loads it into KIND, deploys `k8s/overlays/e2e-kind`, waits for Postgres plus Flyway, and runs an OAuth smoke path. Use `--keep-cluster` when you need to inspect a failure after the script stops.

## Benchmarks and load tests

The benchmark harness lives under `benchmarks/` and compares this server with other OAuth2 implementations.

Start with:

- `benchmarks/README.md`
- `benchmarks/run-benchmarks.sh`
- `benchmarks/results/comparison-report.md`

Keep benchmark instructions in the benchmark repo files, not duplicated across the docs site.

The repository also includes a **Weekly Benchmarks** GitHub Actions workflow (`.github/workflows/weekly-benchmarks.yml`) that runs overnight on Mondays and auto-selects which servers to re-benchmark based on recent changes to `main`. Trigger it manually from the GitHub Actions tab when needed.

Repo-local guide: [benchmarks/README.md](https://github.com/ianlintner/rust-oauth2-server/blob/main/benchmarks/README.md)
