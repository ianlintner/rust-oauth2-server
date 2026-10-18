# zip 8.6.0 -> 9.0.5 remediation (vendored utoipa-swagger-ui 10.0.1)

Advisories: RUSTSEC-2026-0367 (SUID/SGID/sticky preserved from
`external_attributes`), RUSTSEC-2026-0368 (symlink target escape) and
RUSTSEC-2026-0369 (permission change through symlink). All patched in
`zip >= 9.0.0`. `cargo audit` on main failed on zip 8.6.0.

## Reachability

`zip` is only a build-dependency of the vendored `utoipa-swagger-ui`. Its
`build.rs` (`extract_dist`) extracts the pinned Swagger UI zip by hand, using
`enclosed_name()`, `io::copy` and, on Unix, `fs::set_permissions(unix_mode())`.
It does not call `ZipArchive::extract`, so 0368/0369 are not reachable
through our code; 0367 is, because 8.6.0 `unix_mode()` returned the raw
special bits. The build input is a fixed archive, but the dependency was
vulnerable regardless, and the audit gate is required.

## Changes

- `vendor/utoipa-swagger-ui-10.0.1/Cargo.toml`: `zip` `8.6` -> `9.0.5`
  (same `default-features = false`, `features = ["deflate"]`).
- `vendor/utoipa-swagger-ui-10.0.1/build.rs`: one line,
  `file.name().ends_with('/')` -> `file.is_dir()`. zip 9 changed `name()` to
  return `ZipResult<Cow<str>>`, so the original does not compile. No upstream
  release (10.0.1 is latest) supports zip 9.
- `Cargo.lock`: zip 9.0.5; new target-cfg dependency `nix 0.31.3` (zip >= 9.0.1,
  macOS/BSD only; does not resolve on Linux builds).
- `supply-chain/config.toml`: `safe-to-deploy` exemptions for `zip 9.0.5` and
  `nix 0.31.3`. These are unreviewed exemptions, NOT audits. No audit entry
  was added or edited, and none is attributed to a bot.
- `scripts/check_utoipa_stack_scope.py` / `test_utoipa_stack_scope.py`:
  re-baselined to zip 9.0.5, its registry checksum, and the new hashes for the
  vendored `Cargo.toml` and `build.rs`; added `test_vulnerable_zip_rejected`
  (8.6.0, 8.6.1, 3.0.0 are rejected).

## Regression evidence

Probe applying the vendored extraction logic to an archive whose entries carry
mode 04755 / 02755 / 01777 / 0644:

    zip 8.6.0: on-disk 4755, 2755, 1777, 644
    zip 9.0.5: on-disk  755,  755,  777, 644

## Open items for the owner

The existing owner attestation, authorization JSON, source review, the
`[[audits.zip]] 8.6.0` entry and the `ci.yml` comment still describe the
approved stack with zip 8.6.0 and the previous `Cargo.toml`/`build.rs`
bytes. They were deliberately left untouched. The gate now pins zip 9.0.5 and
the new hashes, so the owner must re-attest (or explicitly accept) this delta
and decide whether to replace the exemptions with an owner-authored audit.
