# Argon2 0.6 password-hashing stack: owner-authorized AI-assisted review

## Ownership and decision

On 2026-10-02, repository owner Ian Lintner (@ianlintner) explicitly selected:

> Authorize a human-owned, AI-assisted attestation for these four exact versions,
> accepting the stated limitations.

The decision was made after disclosure of the four missing cargo-vet audits,
passing upstream and compatibility tests, Argon2's new unsafe allocator/memory
code, unexecuted ignored tests, and incomplete source review of additional
transitives. This authorizes repository-local `safe-to-deploy` entries for the
versions below. It is not an independent human source audit, third-party
certification, approval of other dependencies, or permission to merge this PR.
The owner accepts the residual risk described here. IkitClaw records the decision
and evidence; the owner, not an AI reviewer, owns the attestation.

## Exact artifact and feature scope

All four artifacts are from `registry+https://github.com/rust-lang/crates.io-index`.
Their downloaded `.crate` SHA-256 values were calculated and matched `Cargo.lock`:

| Crate | Version | Resolved workspace/all-features features | SHA-256 |
| --- | --- | --- | --- |
| argon2 | 0.6.0 | alloc, default, getrandom, password-hash | `134c52ddac6d63c576bef8168db10c83c49c26444ecbc68060fef078925a901c` |
| blake2 | 0.11.0 | none | `5b5d4d889834ee8ecfc0f8426ad30faf7cdcb10f741a8e6d7224d95325479f6f` |
| password-hash | 0.6.1 | alloc, getrandom, phc | `aab41826031698d6ffcd9cff78ef56ef998e39dc7e5067cdfebe373842d4723b` |
| phc | 0.6.1 | alloc, getrandom | `44dc769b75f93afdddd8c7fa12d685292ddeff1e66f7f0f3a234cf1818afe892` |

`cargo metadata --locked --all-features --format-version 1` describes the unified
workspace graph, not all optional features of every dependency. In particular,
Argon2 `parallel`, `kdf`, and `zeroize` are not enabled and are outside this
attestation, as are any other feature additions or removals. Version, registry,
checksum, or feature changes need a new scope assessment and owner decision.
The CI guard `scripts/check_argon2_audit_scope.py` checks this exact graph and
lockfile before cargo-vet. The entries are `importable = false`: downstream
repositories must not inherit them without this repository's scope controls.
The existing base64 scalar-only guard remains unchanged and required.

## Source-level findings

Reviewed evidence includes the 0.5.3 to 0.6.0 Argon2 delta, the 0.10.6 to 0.11.0
BLAKE2 delta, the 0.5.0 to 0.6.1 password-hash delta, PHC parsing/comparison, and
both production hashing callers. This is bounded AI-assisted source analysis,
not a proof of memory safety or cryptographic security.

### Argon2 allocator, indexing, and CPU dispatch

- `src/block.rs`: the new `Blocks` allocation rejects zero length, checks
  `Layout::array::<Block>` for overflow, allocates zeroed storage, and rejects a
  null allocation result. `as_slice` borrows the owned allocation mutably; `Drop`
  reconstructs the checked layout and deallocates the same pointer. `Block`
  contains integer words for which an all-zero representation is valid.
- `src/memory.rs`: raw block access asserts bounds and lane/slice membership
  before creating references. In the enabled sequential path, one segment view
  is constructed at a time from an exclusive mutable memory borrow. The new
  unsafe `Send`/`Sync` and parallel segment design still warrant caution; the
  `parallel` feature is excluded from this attestation.
- `src/lib.rs`: the x86/x86_64 AVX2 `#[target_feature]` function is called only
  after the stored CPU feature token reports AVX2 support. Other architectures
  use the portable `Block::compress` path. Inspection is not execution coverage
  on every architecture, nor verification of the transitive CPU detector.
- Parameter validation and checked allocation constrain indexing, but high
  memory/time costs in stored PHC values remain a potential resource-exhaustion
  risk. This PR does not redesign password-hash resource policy.

### BLAKE2 representation

- The old optional SIMD machinery is replaced by scalar four-word structs.
  The file name `src/simd.rs` does not imply an enabled SIMD feature.
- Its `as_bytes` uses `slice::from_raw_parts` over a shared reference to a
  `#[repr(C)]` tuple of four homogeneous `u32` or `u64` fields. The byte view is
  lifetime-bound to the reference, read-only, and sized to the struct; the
  homogeneous integer layout has no inter-field padding. This unsafe byte view
  was inspected rather than omitted from the review.
- Endian conversion and wrapping arithmetic were inspected; big-endian targets
  were not executed. The disabled `zeroize` feature is outside scope.

### Password-hash and PHC

- `password-hash` and `phc` forbid unsafe code within their own crates. That does
  not certify their transitive dependencies.
- The enabled single-argument `PasswordHasher::hash_password` generates a fresh
  16-byte salt via `try_generate_salt` and the operating-system RNG. Failures
  return an error through the production callers rather than falling back to a
  fixed salt. Separate convenience APIs can panic on RNG failure and are not
  used by the changed callers.
- PHC parsing, salt/output boundaries, wrong-password rejection, and
  constant-time output comparison were examined and exercised. Missing salt or
  output can be accepted by the PHC parser as a partial representation, but the
  verifier rejects it; parse success alone is not authentication success.
- Default emitted hashes retain Argon2id version 19 and `m=19456,t=2,p=1`.
  Both changed production callers use the new salt-generating API. Their error
  propagation remains intact.

## Executed evidence

The following are observed results, not fabricated attestations:

- A standalone old/new differential probe linking Argon2 0.5.3 and 0.6.0 returned
  `pass=41 diff=0 xfail=0 total=41`. Cases include deterministic PHC equality,
  both directions of cross-version verification, wrong passwords, empty/binary/
  Unicode passwords, malformed PHC strings, padding/trailing-data boundaries,
  salt lengths, and parameter validity. This probe was run locally, not as a
  published CI job.
- The pre-upgrade synthetic hash in the regression test was independently
  generated/verified with 0.5.3 and verified with 0.6.0. The previous RFC fixture
  failed under both versions; the corrected login test also asserts the success
  redirect `/profile` rather than accepting any HTTP 303.
- Local upstream rechecks on 2026-10-02 used `cargo test --locked --all-features`
  in extracted crate source directories. Argon2 suite summaries were 6/25/15/3
  passed, with 9 and 5 ignored cases in two suites; BLAKE2 summaries were
  0/4/1/3/2/2 passed; password-hash 0/1/0 passed; PHC 35/2/7/2/0 passed. All
  commands returned zero. An upstream all-features test result does not widen
  the reviewed deployment feature scope.
- Before adding these attestations, local workspace nextest passed 579 tests;
  BDD passed 35 scenarios with 3 skipped; formatting, clippy, build, and doctests
  passed (one documented doctest was ignored). Independent code review of the
  production/test changes reported no blocking security or logic defects.
- At published head `8ed1d374e25047c30e557e16b748b80fcac219a4`, build, main tests,
  database tests, and KIND end-to-end checks passed. Copilot completed an
  exact-head review with no inline findings and identified the missing vet
  coverage. Security failed on these four missing audits; CodeQL flagged three
  hard-coded synthetic inputs in new fresh-hash tests. Those tests now generate
  runtime UUID inputs; fixed, explicitly test-only legacy fixtures are retained.
  New-head CI and review must be checked separately after publication.

Repository regressions can be rerun with:

```sh
cargo test --locked -p oauth2-actix --test password_hash
cargo test --locked -p rust_oauth2_server --test password_hash
python3 scripts/test_argon2_audit_scope.py
python3 scripts/check_argon2_audit_scope.py
python3 scripts/check_base64_audit_scope.py
cargo vet --locked
```

## Residual limits accepted by the owner

- The analysis is AI-assisted, not an independent human cryptographic audit.
- There was no Miri, sanitizer, exhaustive fuzzing, side-channel measurement,
  deliberate RNG/allocator fault injection, or execution on every target/CPU.
- Upstream ignored cases and skipped BDD scenarios were not executed.
- Optional features and no-alloc/no-std deployment variants are not covered.
- Changes to extra transitives such as digest, block-buffer, crypto-common,
  ctutils/cmov, hybrid-array, and CPU/RNG plumbing were not all fully
  source-reviewed. Existing policy coverage and passing tests do not erase this
  limitation, and this authorization creates no new audits for those crates.
- No reusable third-party audit coverage was found for these four versions in
  the queried stores. Passing cargo-vet after inserting the authorized local
  entries demonstrates policy resolution, not independent evidence of safety.
- Approval is scoped to these artifacts and this feature graph. It does not
  authorize Swagger's base64 SIMD path, OpenTelemetry upgrade tradeoffs, other
  dependencies, or a merge.
