Run the CI gate checks locally.

## Quick loop (while iterating)

Use this between edits — it catches type/lint/test failures fast without
paying for the full all-features build:

1. `cargo fmt --all`
2. `cargo check --all-targets`
3. Targeted tests for what you touched, e.g. `cargo nextest run --test <file>`
   or `cargo nextest run -p <crate>` (fallback: `cargo test --test <file>`)

## Full gate (must pass before any commit/PR)

1. Format check: `cargo fmt --all -- --check`
2. Lint check: `cargo clippy --all-targets --all-features -- -D warnings`
3. Tests: `cargo nextest run --all-features --locked -E 'not binary(bdd)'`
4. BDD suite: `cargo test --test bdd --all-features --locked`
5. Doctests: `cargo test --doc --all-features --locked`

If formatting fails, auto-fix with: `cargo fmt --all`

If `cargo-nextest` is missing (`cargo nextest --version` fails), install it
with `cargo install cargo-nextest --locked`, or fall back to
`cargo test --all-features --locked` (slower, same coverage).

All full-gate checks must pass before any code change is considered complete.
