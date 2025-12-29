# CI/CD

CI is implemented with GitHub Actions.

## Workflows

- `/.github/workflows/ci.yml`
  - formatting (rustfmt)
  - linting (clippy)
  - tests (all features)
  - security checks (audit/deny)
  - integration tests (PostgreSQL)
  - Mongo feature tests (testcontainers)
  - E2E on KIND

- `/.github/workflows/e2e-kind.yml`
  - manual trigger for KIND E2E runs

## Running CI checks locally

Recommended local pre-push checks:

```bash
cargo fmt -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
```

## Building the documentation site

The docs site is built with MkDocs + Material.

Install doc dependencies:

```bash
python3 -m pip install -r requirements-docs.txt
```

Serve locally:

```bash
python3 -m mkdocs serve
```

Build a static site:

```bash
python3 -m mkdocs build --strict
```
