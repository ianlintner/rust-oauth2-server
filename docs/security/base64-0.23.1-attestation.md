# base64 0.22.1 → 0.23.1: owner-approved scalar delta attestation

## Attestation and scope

Attesting owner: Ian Lintner (`@ianlintner`). Review evidence: AI-assisted
source-delta inspection and locally executed tests. On 2026-10-02 the owner
explicitly authorized this attestation model and accepted the disclosed risk:

> I am telling you your review + my approvable is acceptable risk and due dilligence for attetstation lets do that and stop beating around the bush

> I am a human and reading your review and output and validating that is attestation

This records the owner's validation/approval of AI-assisted evidence, not a claim
that the owner personally ran tests or independently inspected every source file.
The local `safe-to-deploy` delta is restricted to this repository's `std` + `alloc`
scalar configuration. `simd-unsafe` and default feature activation are excluded.
The audit is **non-importable** so other projects cannot treat it as a general
all-features audit. No exemption, publisher trust or gate bypass was added.
Authorization to attest is not authorization to merge this PR.

The dependency snapshot reviewed is PR #413 HEAD
`42cf9550ef144b0b1e9ed53b9a61fdfa8695d65c`. Changes accompanying this report
add the attestation, evidence and CI scope enforcement; they do not change
production call sites or enable additional base64 features.

## Artifact identity

Published crates were downloaded from `https://static.crates.io/crates/base64/`
and archive SHA-256 values matched the exact PR `Cargo.lock`. Each archive member
was compared byte-for-byte with the extracted source before testing:

- 0.22.1: `72b3254f16251a8381aa12e40e3c4d2f0199f8c6508fbecb9d91f575e0fbb8c6`
- 0.23.1: `ac07cdecf99051d9a5238b80f35af32cdeba5b336e55d957b318b50137e18da5`

Checksums establish that reviewed bytes match locked published bytes; they do not
prove publisher integrity. Existing imported audit coverage for 0.22.1 supplies
the baseline; this local audit covers the delta, not a new full 0.22.1 audit.
No covering 0.23.1 audit was found in the configured imports or public cargo-vet
registry sources checked. This is a bounded search, not a universal negative.

## Source-delta findings

All changed production files and manifests were inspected, except the explicitly
excluded SIMD implementation (`src/engine/simd.rs`). Tests/doc/tooling changes
were distinguished from runtime code. Anchors below refer to published 0.23.1:

- `src/engine/general_purpose/mod.rs:81-108`: scalar encode/decode supply an empty
  `(0, 0)` SIMD prefix; `:127-269` preserves scalar encode grouping and tail logic.
- `src/engine/general_purpose/decode.rs:37-174`: complete-quad decoding is factored
  into a helper. With the scalar zero prefix, offsets, output lengths and terminal
  quad handling retain the prior behavior. Bounds checks precede scalar writes.
- `src/engine/general_purpose/decode_suffix.rs`: padding is engine-supplied;
  canonical padding and nonzero trailing-bit rejection remain enforced. Capturing
  the last symbol's decoded value enriches diagnostics, not acceptance.
- `src/alphabet.rs:94-132`: custom padding must be printable and absent from the
  64-symbol alphabet. Stock alphabets still use `=`. Constructor duplicate and
  length checks preserve alphabet/table invariants.
- `src/encode.rs:136-144`, `src/chunked_encoder.rs:40`, `src/read/decoder.rs`:
  engine-specific padding is threaded consistently. Padding length arithmetic
  remains unchanged. Reader error-offset rebasing forwards the new payload.
- `src/write/encoder.rs`: finish/write guards change from explicit panic branches
  to equivalent assertions. Streaming buffer bookkeeping is unchanged.
  `src/write/encoder_string_writer.rs` production logic is unchanged.
- `src/lib.rs:284-285`: disabling `simd-unsafe` retains `forbid(unsafe_code)`.
  `src/prelude.rs` changes are documentary. No new scalar unsafe was found.
- Manifests: no build script and no runtime dependencies. Edition is now 2021;
  MSRV increases to 1.71, below this workspace's 1.88 minimum.

No blocking functional/security regression was identified in the reviewed scalar
configuration. This is a bounded review conclusion, not proof of absence of bugs.

Compatibility and residual findings:

1. `Engine::padding()` is newly required for trait implementors.
   `DecodeError::InvalidLastSymbol` changes from a tuple to a struct variant, and
   its Debug formatting changes. The OAuth2 call-site search found no custom
   Engine implementations or affected variant patterns.
2. SIMD is default-on in 0.23.1. The manifest's “Off by default” comment is wrong;
   the crate rustdoc correctly says it is on. The three upgraded dependency
   declarations opt out; dependency feature unification is checked by CI.
3. SIMD prefix contracts use debug assertions. Their nonzero-prefix behavior is
   outside this attestation; the scalar engine uses the fixed zero prefix.
4. GeneralPurpose is not constant-time. This is pre-existing and this review does
   not establish constant-time handling of cryptographic material.

## Executed evidence

Environment: Linux x86_64; rustc 1.98.1; cargo 1.98.1; cargo-vet 0.10.2.

- `cargo test --locked --no-default-features --features std` in the verified
  0.23.1 published source: 204 library, 6 encode integration, 7 integration and
  26 documentation tests passed (243 tests; zero failures).
- `cargo rustc --lib --locked --no-default-features --features std -- -F unsafe-code`:
  passed. This is a separate library build, not a claim about the entire server.
- `cargo run --release --locked --manifest-path tools/base64-scalar-review/Cargo.toml`:
  2,076 encode/decode/slice/stream scenarios and 82,048 malformed/trailing-bit
  comparisons passed against exact 0.22.1 and 0.23.1 registry versions.
  Four stock engines, lengths 0..512 plus 1023/1024/1025/4095/4096/4097,
  exact/oversized/undersized decode buffers, stream writes in 1/2/3/7/31-byte
  chunks, deterministic mixed valid/invalid symbols and exhaustive final-byte
  variations. Error text/enum shape is intentionally not required to match;
  acceptance and successful decoded bytes are required to match.
- `cargo tree --locked --workspace --all-features --target all -e features -i base64@0.23.1`:
  resolved only `std` + `alloc` (resolution across targets, not execution on them).
- The CI scope gate and regression tests pass. It obtains all-feature Cargo
  metadata without a target filter, rejects SIMD/default/unknown features and
  unreviewed no-std configurations before cargo-vet.

The evidence harness is reproducible and separately locked; it is not a server
workspace member. Upstream tests and raw fetched audit stores are retained in
the local review evidence directory; their local filesystem paths are not part
of the public attestation.

Not exercised: SIMD/AVX2/NEON, native ARM execution, Miri, sanitizers, prolonged
fuzzing, publisher-signature validation, or a full local deployment/database test
suite. Scope restrictions are an explicit part of the owner's risk acceptance.

## Gate interpretation

`cargo-vet --locked` passing confirms the approved delta connects existing
coverage to 0.23.1. It does not independently validate source safety. Cargo-audit
and cargo-deny remain separate gates. The imported audit lock was normalized by
cargo-vet 0.10.2; parsed TOML comparison confirms no imported trust/audit values
changed. CI pins that cargo-vet version to keep serialization reproducible.
