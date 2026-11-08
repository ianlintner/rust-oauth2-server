# PR #452 RUSTSEC lockfile delta: AI-assisted review (2026-10-25)

## Scope and ownership

AI-assisted source-delta review by the IkitClaw agent (profile `coder-claude`)
for `supply-chain/audits.toml` entries on `ctutils`, `webpki-roots` and
`webpki-root-certs`. These are **owner-attributed** (`Ian Lintner`) but are
effective only if the owner approves the **exact PR head** on GitHub after
reading this evidence. They are not an independent third-party audit, not a
certification, and not merge approval. They are `importable = false`.
No exemption was added and no gate was disabled or bypassed.

## Why the Security job failed

PR #452 locks four RustSec fixes (ctutils 0.4.2 -> 0.4.5 [0385],
rustls-webpki 0.103.15 -> 0.103.16 [0382], webpki-root-certs 1.0.8 -> 1.0.11
[0383], webpki-roots 1.0.8 -> 1.0.11 [0381]). On that head:

1. `cargo audit` / `cargo deny` failed on **RUSTSEC-2026-0387** (crypto-bigint
   0.5.5, timing variability, fixed in >= 0.7.6). Path:
   `jsonwebtoken` `rust_crypto` -> p256/ecdsa 0.13/16 -> elliptic-curve 0.13 ->
   crypto-bigint 0.5.5. No patched version is reachable on that path.
2. `cargo vet --locked` failed with unvetted `ctutils`, `rustls-webpki`,
   `webpki-root-certs`, `webpki-roots` at the new versions.

## Fixes

- **RUSTSEC-2026-0387:** switch `jsonwebtoken` provider `rust_crypto` ->
  `aws_lc_rs` (workspace, `oauth2-actix`, `oauth2-core`). `aws-lc-rs` was
  already in the graph (rustls/reqwest) and exempted. The whole vulnerable
  RustCrypto elliptic-curve subtree is removed from `Cargo.lock`; only
  `untrusted 0.7.1` is added. `cargo audit` clean; `cargo deny check` ok.
- **rustls-webpki 0.103.16:** covered by the upstream bytecode-alliance audit
  `0.103.15 -> 0.103.16` (Alex Crichton, safe-to-deploy), added to
  `supply-chain/imports.lock` as published (imports refreshed surgically; a
  full `cargo vet regenerate imports` would also delete the owner-approved zip
  audit and exemptions, so it was not committed).
- **untrusted 0.7.1:** covered by the imported ISRG audit (David Cook,
  safe-to-deploy, version 0.7.1), added to `imports.lock`. Local check: crate
  has `#![forbid(unsafe_code, ...)]`, no build script, no dependencies.
- **ctutils, webpki-roots, webpki-root-certs:** local owner-attributed delta
  audits (below).

## Source evidence (crates.io artifacts as locked)

| Crate | From -> To | sha256 of locked `.crate` |
| --- | --- | --- |
| ctutils | 0.4.2 -> 0.4.5 | `38d28fb6aa7dd680b3ffd1a3e64e115c177bdba63c0ae7f9cd48129ff05c4fa0` |
| webpki-roots | 1.0.8 -> 1.0.11 | `f5f280bbb2b287bc8e7de7e3852945a0ff50d1bbcb5ed42b6c7a568c546df171` |
| webpki-root-certs | 1.0.8 -> 1.0.11 | `e49d0e65abc00c142e8f9428da991da9f1a250c39be97459901eb12b9b49f62a` |

Checksums equal the `Cargo.lock` values; they prove byte identity with the
locked artifact, not publisher integrity.

### webpki-roots / webpki-root-certs

`diff -r` of 1.0.8 vs 1.0.11: only `src/lib.rs` (data), manifests and metadata
change. Rust items are unchanged (118 trust-anchor/certificate entries in both
versions; entries swapped for the Mozilla store update, e.g. emSign/Atos
removed, Telia/SECOM added). Manifest delta: version and `rust-version`
1.70 -> 1.71 only; dependency lists identical. No build script, no `unsafe`,
`#![forbid(unsafe_code, unstable_features)]`. Residual risk: trust-store
*content* is policy data from Mozilla's store; this review did not
independently validate each certificate.

### ctutils (constant-time helpers, `#![forbid(unsafe_code)]`)

Changed files: `src/choice.rs`, `src/ct_option.rs`, `src/lib.rs`,
`src/traits/ct_{gt,lt}.rs`, new `src/primitives.rs`, tests, manifest, docs.
- `choice.rs`: `bitle!/bitlt!/bitnz!` macros moved to `primitives.rs`;
  `from_u{32,64}_{le,lt,nz}` now call `primitives::*` (same Hacker's Delight
  formulas, plus a `core::hint::black_box` barrier only on `target_arch="arm"`
  without pointer atomics); `from_u128_le/lt` get a 32-bit-pointer path;
  `i64` eq uses `cast_unsigned` (MSRV 1.87). `and()` uses `to_u8()` on that
  same ARM cfg only.
- `ct_option.rs`: `to_bool_vartime()` -> `to_bool()` in `expect`/unwrap-style
  paths (fewer variable-time branches).
- `ct_gt/ct_lt`: `u128` split out to explicit impls via `Choice::from_u128_lt`;
  signed variants use `cast_unsigned`.
- No `unsafe`, `asm!`, `extern`, `include!`, build script or new dependencies;
  the only manifest dependency change is `subtle` min version 2 -> 2.6
  (optional) and `rust-version` 1.85 -> 1.87.
- Consumed in this repo through `aes-gcm 0.11.1` and RustCrypto password-hash
  crates with default features; x86_64 takes the non-ARM/non-32-bit paths.

## Verification (local, x86_64 Linux)

- `cargo audit`: no vulnerabilities (1 allowed warning RUSTSEC-2026-0173).
- `cargo deny check`: advisories, bans, licenses, sources ok.
- `cargo vet --locked`: succeeded.
- All repo scope gates (`scripts/test_*`, `check_*` for base64, argon2,
  utoipa stack) exit 0.
- `cargo nextest run --all-features --locked -E 'not binary(bdd)'`:
  595 passed, 0 failed (includes JWT RS/ES/EdDSA, DPoP, private_key_jwt and
  workload-identity suites exercised through the new `aws_lc_rs` provider).

## Not covered

No Miri, sanitizer, fuzzing, or non-x86_64 execution; ARM/32-bit ctutils
paths were read, not run. The `aws_lc_rs` provider switch is a behavioural
dependency change for JWT signing/verification and is called out for review.
