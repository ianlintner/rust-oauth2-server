# utoipa/Swagger exact-stack: owner-authorized scalar patch + five attestations

## Authorization

Durable owner authorization receipt:
[utoipa-swagger-ui-owner-authorization.json](utoipa-swagger-ui-owner-authorization.json) (owner decision recorded
2026-10-02T21:38:55Z), quoted scope:

> Authorize the scalar-only patch and five limited human-owned AI-assisted
> attestations

Scope: the owner explicitly authorized **a scalar-only local patch of
`utoipa-swagger-ui 10.0.1`** and **five limited, human-owned AI-assisted
attestations** for:

| crate | version | role |
| --- | --- | --- |
| `utoipa` | 6.0.0 | registry crate |
| `utoipa-gen` | 6.0.1 | registry crate |
| `utoipa-swagger-ui` | 10.0.1 | **vendored local path override** (patched) |
| `zip` | 8.6.0 | registry crate |
| `typed-path` | 0.12.3 | registry crate |

**Bounds of this authorization (must not be over-read):**

- Limited, human-owned, AI-assisted attestation — **not an independent
  security audit**, and **not a third-party audit**.
- The attestations are `importable = false`: other projects may not reuse them.
- This is **not merge approval**. Authorization to attest is not authorization
  to merge the PR.
- The base64 0.23.1 SIMD exclusion scope is **unchanged** and remains enforced
  by `scripts/check_base64_audit_scope.py`; this work is additive.
- The scalar patch adds no dependency beyond the coordinated upgrade, enables
  no vendored-Swagger-asset feature, and changes no Rust source.

## What changed and why

`utoipa-swagger-ui 10.0.1` depends on `base64 0.23.1` with default features,
which pulls in `simd-unsafe`. This repository deliberately keeps `base64 0.23.1`
in its **scalar `std` + `alloc`** configuration (the `simd-unsafe` path is
excluded, per the base64 attestation and CI scope gate). The published
`utoipa-swagger-ui 10.0.1` cannot express that; a feature-flag change in the
dependency is required.

The owner authorized exactly **one** class of change: a scalar-only patch of the
vendored crate's **dependency declaration**. Accordingly the vendored crate
differs from the published artifact by **two lines only**:

```diff
 [dependencies.base64]
 version = "0.23.1"
+default-features = false
+features = ["std"]
```

No other source, manifest, license, or provenance file was modified. The
`[patch.crates-io]` override in the root `Cargo.toml` routes
`utoipa-swagger-ui 10.0.1` to `vendor/utoipa-swagger-ui-10.0.1`.

## Artifact identity and provenance

The vendored tree is the exact verified published crate, plus the two-line
delta above. The bounded source review, executed probes, corrections to the
earlier baseline, and limitations are recorded in
[utoipa-swagger-ui-source-review.md](utoipa-swagger-ui-source-review.md).
Evidence chain from verified published archives:

- `utoipa-swagger-ui-10.0.1.crate` archive SHA-256:
  `3f5ec9d7816e4ce8ccb7e0bd7276e090cad0fcb1def4f3540e5b0f7485d7583e`
  — this **matches the original (pre-patch) `Cargo.lock` checksum** for
  `utoipa-swagger-ui 10.0.1`, establishing original-crate ↔ archive identity.
- Extracting that archive and diffing against the vendored tree shows the
  **only** difference is the two-line `base64` dependency delta; every other
  file is byte-identical.
- Registry crate archive SHA-256 values (each matches its `Cargo.lock`
  checksum):
  - `utoipa 6.0.0`: `8765fe27aeff71012a3f90fa474cf1df863a7d0dd81ed25de4e63fff2544994f`
  - `utoipa-gen 6.0.1`: `d935f1c83fdf8b88f09bbe050d0cea78ea4afee6d7b0317403228c1200b2c8ab`
  - `zip 8.6.0`: `2d04a6b5381502aa6087c94c669499eb1602eb9c5e8198e534de571f7154809b`
  - `typed-path 0.12.3`: `8e28f89b80c87b8fb0cf04ab448d5dd0dd0ade2f8891bae878de66a75a28600e`

Checksums establish that reviewed bytes match locked published bytes; they do
not prove publisher integrity.

## cargo-vet coverage: what is — and is not — meaningful

`utoipa-swagger-ui 10.0.1` is consumed as a local **path** override. To
cargo-vet a path (nominally first-party) dependency is implicitly trusted, so
`supply-chain/config.toml` sets:

```toml
[policy."utoipa-swagger-ui:10.0.1"]
audit-as-crates-io = true
```

**Honest mechanic (verified against installed cargo-vet 0.10.2, `format.rs`):**
`audit-as-crates-io = true` makes cargo-vet require an audit for the **published
crates.io version** (10.0.1) — "the versions `cargo vet diff` and `cargo vet
inspect` will fetch". It carries **no hash and no provenance of the local,
patched tree**. A local path audit is therefore **not** equal to auditing the
modified source. `cargo vet --locked` proves the published 10.0.1 was attested;
it does **not** prove the vendored bytes match that attestation.

Verified behavior: with the policy present, `cargo vet --locked` reports
**128 fully audited** (the published 10.0.1 attestation is consumed). With the
policy set to `false` or removed, vet still succeeds at **127 fully audited** —
i.e. the crate silently reverts to "trusted first-party" and the attestation
sits unused. The policy is meaningful; its limitation is the absence of a local
content hash.

Because cargo-vet cannot bind the local tree, integrity of the vendored bytes is
enforced **separately and fail-closed** by
`scripts/check_utoipa_stack_scope.py` (below), which runs **before** `cargo vet`
in CI.

## Fail-closed CI guard

`scripts/check_utoipa_stack_scope.py` rejects, before `cargo vet`, any of:

- **Aggregate-count-first:** for **each** of the five names, exactly **one**
  package may exist across `cargo metadata --all-features` on **all targets** —
  counted **before** the version check, so an extra older/newer copy of the same
  crate name cannot hide behind the reviewed version.
- Wrong version, wrong source (`git+…`, alternate registry), wrong Cargo.lock
  source/checksum for the four registry crates.
- Feature drift (extra or missing) against the exact approved sets:
  `utoipa` {chrono, default, macros, uuid}, `utoipa-gen` {chrono, uuid},
  `utoipa-swagger-ui` {actix-web, default, url},
  `zip` {_deflate-any, deflate, deflate-flate2, deflate-flate2-zlib-rs,
  deflate-zopfli}, `typed-path` {default, std}.
- For the vendored `utoipa-swagger-ui`: resolved path swap (the absolute
  manifest_path must match the exact vendored directory whose bytes are checked,
  not merely a matching suffix in another checkout), unexpected registry
  source/checksum in `Cargo.lock`, and **byte hashes of all 14 files** of the
  vendored crate — missing file, extra file, or any single changed byte fails.

`scripts/test_utoipa_stack_scope.py` covers all of the above as RED-then-GREEN
regressions (missing/wrong/older-additional/duplicate version **per name**,
wrong source, checksum drift, feature drift, vendored source/manifest tampering,
extra/missing file, path swap, malformed metadata/lockfile).

## Residual limits and disclosed risk (no independent-audit claim)

- **Not an independent audit.** These are human-owned, AI-assisted attestations.
  The owner authorized this limited evidence-based approach and accepted the
  disclosed risks; this is not a claim they inspected every source file.
- **zip 8.6.0 large delta:** this covers a large version jump from the
  previously reviewed 3.0.0.
- **Unverified build-time Swagger asset integrity:** building against cached or
  downloaded Swagger assets does not independently verify their content. This
  review did not verify an asset archive hash. The risk was disclosed and
  accepted; the authorized patch does
  **not** enable the vendored-asset feature.
- **Patched-crate cargo-vet semantics:** as documented above, the
  `audit-as-crates-io` policy audits the published version only and does not
  hash the patched tree; byte-integrity rests on the separate CI guard.
- **Untested architectures:** the review and tests were executed on this
  machine's target only; other targets/architectures were not exercised.
- **Bounded source review:** ZIP reader/path probes were not exhaustive, and
  the unavailable upstream ZIP dev-dependencies prevented an offline upstream
  unit-suite run. No Miri, sanitizer or fuzzing campaign ran. The syn 2 to 3
  parser change is a new build-time surface, not separately attested here.
- The scalar patch adds no further dependency; the coordinated upgrade does
  change transitives as described in the source-review note. The base64
  SIMD-exclusion scope is unchanged.
