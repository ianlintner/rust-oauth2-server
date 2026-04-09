# Testing

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

## BDD tests

BDD coverage is under `tests/features/` and runs through the dedicated test target:

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
