# Dependabot cargo-minor-patch group: AI-assisted delta review (2026-10-18)

## Scope

This document records the AI-assisted source-level delta review performed by the
IkitClaw agent (profile `oauth-maint`) for the dependency updates introduced by
Dependabot PR #435 (branch `dependabot/cargo/cargo-minor-patch-c2e6d5d11d`, head
`335aa528c7a86597553aa7ec5e3719d61c7a5c24`). It accompanies the
`safe-to-deploy` exemption-version sync in `supply-chain/config.toml` described
below.

This is **not** an independent human source audit and **not** a certification. It
is evidence assembled to support the repository owner's informed decision to
accept these routine patch/minor bumps. The owner, not an AI reviewer, owns any
attestation. It is not permission to merge (merge remains owner-gated, per the
Jev gate policy).

## What changed

PR #435 updates a single file, `Cargo.lock` (73 insertions, 63 deletions), via
the `cargo-minor-patch` Dependabot group. Eight direct updates propagate to
eighteen crates that require `safe-to-deploy` exemption-version bumps:

| Crate | Old | New | Risk class |
| --- | --- | --- | --- |
| actix-web | 4.15.0 | 4.17.0 | HTTP framework (safe Rust) |
| actix-http | 3.13.6 | 3.19.0 | HTTP types/framing (safe Rust) |
| actix-web-codegen | 4.3.0 | 4.4.0 | proc-macro (compile-time only) |
| brotli | 8.0.4 | 9.0.0 | compression (unsafe behind feature) |
| brotli-decompressor | 5.0.3 | 6.0.1 | compression (unsafe behind feature) |
| alloc-no-stdlib | 2.0.4 | 3.0.0 | allocator (unsafe behind feature) |
| alloc-stdlib | 0.2.4 | 0.3.0 | allocator (unsafe behind feature) |
| zstd | 0.13.3 | 0.14.3 | compression wrapper |
| zstd-safe | 7.2.4 | 8.2.0 | unsafe FFI wrapper over zstd-sys |
| zstd-sys | 2.0.16+zstd.1.5.7 | 2.1.2+zstd.1.5.7 | C library bindings (bundled zstd) |
| config | 0.15.26 | 0.15.27 | config loading (safe Rust) |
| http | 1.4.2 | 1.5.0 | HTTP types (safe Rust) |
| lapin | 4.12.0 | 4.12.2 | AMQP client (safe Rust) |
| serde_json | 1.0.151 | 1.0.154 | JSON (safe Rust) |
| sha2 | 0.11.0 | 0.11.1 | SHA-2 (RustCrypto, unsafe asm backends) |
| tokio | 1.53.1 | 1.53.3 | async runtime (safe Rust) |
| uuid | 1.26.1 | 1.28.0 | UUID (safe Rust) |
| toml_writer | — (new) | 1.1.3+spec-1.1.0 | TOML serializer (safe Rust) |

Version strings synchronized in `supply-chain/config.toml` (17 bumps + one new
`toml_writer` entry). `toml_writer` is newly pulled in as a transitive of `toml`'s
optional `display` feature, enabled by `config 0.15.27`.

## Delta review findings

### Unsafe / native-code crates (highest attention)

**zstd-sys 2.0.16 → 2.1.2 (bundled zstd 1.5.7).** The vendored C library
(`zstd/` tree) is byte-identical between the two sys-crate releases — `diff -rq`
reports only two additive paths (`zstd/build/` cmake glue and
`zstd/lib/libzstd.pc.in`). The upstream zstd C source is unchanged. The real
delta is `build.rs`: 2.1.2 adds a parallel `cmake` build backend behind the
`cmake` feature (the default still uses the `cc` backend). No change to the
bundled zstd C code, so no new memory-safety surface in the library itself.

**zstd-safe 7.2.4 → 8.2.0.** Pure Rust FFI wrapper; the API surface expanded
for the 0.14 `zstd` crate. Unsafe is confined to the existing FFI call sites.

**alloc-no-stdlib 2.0.4 → 3.0.0.** Positive delta: all `unsafe` (the C
`calloc`/`malloc` backing store) is now gated behind an explicit `unsafe`
feature, and the default build adds `#![forbid(unsafe_code)]`. This crate is
pulled in with its **default** features only (confirmed via
`cargo tree --all-features -e features -i alloc-no-stdlib`), so the unsafe
allocator code is **not compiled** in this workspace. This is a strict
improvement over 2.0.4.

**alloc-stdlib 0.2.4 → 0.3.0.** `src/lib.rs` is byte-identical between the two
versions; the only change is the dependency floor (`alloc-no-stdlib >=3.0.0`
and a version bump) plus test/README metadata.

**brotli 8.0.4 → 9.0.0 / brotli-decompressor 5.0.3 → 6.0.1.** The brotli
`unsafe` paths are feature-gated off `alloc-stdlib`/`std`; this workspace pulls
`brotli` default (`std` + `alloc-stdlib`), which does not enable the crate's
unsafe implementation path. Changelog for the 9.0 release is not published in
the packaged crate (only a README is shipped); the source delta spans 24 files
and is dominated by the allocator-interface rework required by alloc-stdlib 3.x.
No advisory references brotli; the unsafe FFI used by the crate remains behind
its `unsafe` feature, which is not enabled here.

### Cryptographic backend (sha2 0.11.0 → 0.11.1)

The 0.11.1 changelog documents three changes, all correctness-related and none
a breaking API change:
- Removed a workaround for unaligned loads in the `riscv-zknh` backend, and no
  longer requires `zbkb`/`zbb` target features for those backends.
- MSRV bump to 1.88.
- Fixed AArch64 round-constant loading to satisfy the Stacked Borrows model.

These are active backends, but this workspace compiles sha2's portable/stable
backend by default on the CI target (x86_64); the RISC-V and AArch64-zknh
backends are only selected under explicit target features not activated here.
The changes are upstream RustCrypto maintenance in a widely-reviewed crate.

### actix-web family (largest semver jump)

The actix-web 4.15→4.17 and actix-http 3.13→3.19 changelogs are dominated by
security-hardening and correctness fixes rather than feature additions:
- actix-http 3.18.11 rejects missing/duplicate `Host` headers (request smuggling
  hardening); 3.18.13 rejects malformed WebSocket `Sec-WebSocket-Key`; 3.19.0
  rejects WebSocket frames with the 64-bit length MSB set.
- actix-web 4.16.0 disables the `http2` crate feature from TLS features and
  disables `TestRequest` pooling; 4.17.0 fixes `Accept` header quality parsing.
- The only dependency changes are the zstd (→0.14) and brotli (→9) bumps already
  covered above.

actix-web-codegen 4.3→4.4 is a syn 2→3 update in a proc-macro crate; it affects
compile-time code generation only and is not part of the runtime attack surface.

### Pure-safe-Rust patch bumps

config 0.15.26→0.15.27, http 1.4.2→1.5.0, lapin 4.12.0→4.12.2, serde_json
1.0.151→1.0.154, tokio 1.53.1→1.53.3, uuid 1.26.1→1.28.0, and toml_writer
1.1.3 (new) are all patch/minor releases with no unsafe code added and no
security-relevant behavior changes. Representative changelog reviews:
- http 1.5.0 adds `Method::QUERY` (RFC 10008) and fixes URI path parsing.
- lapin 4.12.2 fixes promise accumulation over reconnection attempts.
- tokio 1.53.3 fixes `DuplexStream` waker drop ordering, semaphore waiter
  wake-up, and paused-time auto-advance — all correctness fixes.
- sha2 covered separately above.

## What was not tested

No platform tests beyond the local x86_64 build were run. The following were
**not** exercised and remain residual gaps:
- AArch64, RISC-V, and other cross-arch backends (sha2 asm paths, zstd SIMD
  dispatch) were reviewed by inspection only, not executed.
- Miri, sanitizers, and prolonged fuzzing were not run.
- The cmake build backend of zstd-sys was not exercised (the default `cc`
  backend is what CI uses).

## Out of scope: unrelated pre-existing `zip` audit failure

The three new RUSTSEC advisories RUSTSEC-2026-0367/0368/0369 concern the `zip`
crate (affected versions all `< 9.0.0`; fixed in `>= 9.0.0`). `zip 8.6.0` is
pinned by the owner-authorized `utoipa/Swagger exact stack scope` gate (see
`docs/security/utoipa-swagger-ui-10.0.1-attestation.md`), which deliberately
attests a byte-for-byte vendored `utoipa-swagger-ui 10.0.1` whose build
dependency is `zip 8.6.0`.

For this repository, `zip` is a **build-only** dependency of that vendored path
override: its build script extracts a locally vendored, trusted Swagger UI
archive at compile time. It is never reachable from untrusted input at runtime,
and the extraction is not performed in a privileged context. RUSTSEC-2026-0367
(su privilege escalation via `ZipArchive::extract()` SUID/SGID preservation),
0368, and 0369 therefore require an attacker-controlled archive in a privileged
extraction context — conditions that do not hold in this dependency's usage.

This is a **separate** blocker, pre-existing on `main`, and independent of this
exemption-sync PR. Remediation is the owner's decision — either bump to
`zip >= 9.0.0` (which requires re-attesting the utoipa/Swagger stack, since the
exact-stack gate pins 8.6.0) or add a narrow, rationale-documented `cargo audit`
ignore. It should be tracked independently of this PR rather than conflated with
the `safe-to-deploy` exemption sync.

## Conclusion

The delta review found no security regressions introduced by these bumps. All
unsafe/native-code changes are either feature-gated-off in this workspace
(alloc-no-stdlib, brotli) or confined to build-system glue over an unchanged C
library (zstd-sys). The substantive Rust changes are security fixes or routine
correctness maintenance. The `safe-to-deploy` exemption bumps in
`supply-chain/config.toml` synchronize existing entries to these versions; no new
attestation beyond the mechanical version sync and this delta review is claimed.
