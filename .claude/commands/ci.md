Run the CI gate checks locally before committing code.

This includes:
1. Format check: `cargo fmt --all -- --check`
2. Lint check: `cargo clippy --all-targets --all-features -- -D warnings`
3. Tests: `cargo test --verbose --all-features --locked`

If formatting fails, auto-fix with: `cargo fmt --all`

All three checks must pass before any code change is considered complete.
