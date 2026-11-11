# actix-http 3.20.5: vendored scalar-base64 override

## Why

RUSTSEC-2026-0446, -0448 and -0455 (request smuggling, unbounded decompression,
Brotli window bypass) are fixed only in `actix-http >= 3.20.1`. Every one of
those releases declares `base64 = "0.23"` **with default features**, and
base64 0.23's default features include `simd-unsafe`. Cargo unifies features,
so taking the security fix by itself would switch `simd-unsafe` on for the
whole graph.

The owner decided not to use `simd-unsafe` (PR #414), and
`scripts/check_base64_audit_scope.py` enforces that boundary
(`std` + `alloc` only). Same situation, same remedy as
`utoipa-swagger-ui 10.0.1` (PR #415).

## What changed

`vendor/actix-http-3.20.5/` is the published crate archive, extracted
unmodified (sha256 of the `.crate`:
`26d4b0133245a77674c3703c71b416c59cbee8b570368fc263d3154604c6841c`, matching
the crates.io API checksum) except for one delta in `Cargo.toml`:

```diff
 [dependencies.base64]
 version = "0.23"
 optional = true
+default-features = false
+features = ["std"]
```

No Rust source changed. `Cargo.toml.orig` is left as published. The root
`Cargo.toml` routes `actix-http` to that directory through `[patch.crates-io]`,
and `supply-chain/config.toml` marks it `audit-as-crates-io`.

Reproduce the claim:

```bash
curl -sLO https://static.crates.io/crates/actix-http/actix-http-3.20.5.crate
sha256sum actix-http-3.20.5.crate        # must equal the hash above
mkdir /tmp/ah && tar -xzf actix-http-3.20.5.crate -C /tmp/ah
diff -r /tmp/ah/actix-http-3.20.5 vendor/actix-http-3.20.5   # only Cargo.toml differs
```

## Known limits

- This is a vendored third-party crate. When upstream ships a release that
  keeps `base64` at `default-features = false` (or the owner accepts
  `simd-unsafe`), delete the override.
- A path override has no `source`/`checksum` in `Cargo.lock`, so `cargo audit`
  **does not scan this crate** for future advisories. Watch actix-http
  advisories manually, or drop the override as soon as it is no longer needed.
- `cargo vet` treats the crate as the crates.io 3.20.5 release through an
  exemption. That is an unaudited-dependency exemption, **not** an audit and
  not an attestation by anyone.
- This note records a change; it is not merge approval.
