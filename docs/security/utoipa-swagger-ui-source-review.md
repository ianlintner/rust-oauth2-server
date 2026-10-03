# Swagger dependency review evidence and limitations

This is AI-assisted evidence for the owner's five repository-local, non-importable
attestations. It is not an independent security audit or merge authorization.
The exact owner decision is recorded in
[utoipa-swagger-ui-owner-authorization.json](utoipa-swagger-ui-owner-authorization.json).
Artifact checksums and enforced features are listed in
[the attestation scope](utoipa-swagger-ui-10.0.1-attestation.md).

## Artifact identity

The five target .crate archives were hashed and compared against the original
pre-patch Cargo.lock on PR #415. Their gzip/tar contents were readable. The entire
14-file local Swagger crate was compared against its published archive: the only
change is the two-line base64 dependency declaration in Cargo.toml. All source,
build-script, license and provenance bytes remain identical.

Archives can be retrieved from
https://static.crates.io/crates/NAME/NAME-VERSION.crate using each exact name and
version in the attestation document. Checksums establish byte identity, not
publisher integrity or absence of vulnerabilities.

## Source-review corrections

An earlier local report used an invalid typed-path 0.11.2 baseline: the supposed
archive was a 243-byte AccessDenied XML response, not a gzip crate. That comparison
is void and is not evidence for this attestation. The corrected reference
comparison used an authentic typed-path 0.11.0 archive instead. In the relevant
zip 3.0.0 to 8.6.0 upgrade, typed-path is a newly introduced dependency, not an
existing 0.11.2 dependency being upgraded.

Upstream Swagger 10.0.1 already declares zip with default-features=false and
features=["deflate"]. The local patch changes only base64, not zip's feature
selection. The actual unified sets include the implied deflate features,
typed-path default+std, and base64 alloc+std. They are enforced by the guards;
"deflate only" means the selected compression family, not a one-element Cargo
feature set.

## Bounded source inspection and executed probes

The source reviewer inspected the changed macro, path and ZIP reader/build-script
surfaces, inventoried unsafe sites, and distinguished compiled-but-unused APIs
from feature-gated code. The parent verified the archive identity and the
manifest-only local patch independently.

- utoipa and utoipa-gen sources contained no unsafe sites in that inventory.
  utoipa-gen changes its parser dependency from syn 2 to syn 3: this is a new
  build-time major-version surface. The five attestations do not independently
  attest syn or other transitives; their coverage remains the existing vet policy.
- typed-path's 0.11.0 reference and 0.12.3 source inventories each contained 36
  unsafe tokens, primarily transparent-wrapper/raw-pointer conversions. Counts
  alone are not a safety proof.
- zip's AES modules are feature-gated out of this resolved deflate configuration.
  Fixed-size reader block conversions remain compiled. Writer APIs are compiled
  but are not called by Swagger's build script; neither is ZipArchive::extract().
- The actual Swagger build path uses ZipArchive::new, by_index, enclosed_name
  and io::copy. Small constructed archives exercised these APIs. Tested parent
  traversal entries were rejected. zip 8.6.0 normalizes dot components and
  re-relativizes absolute or Windows-prefixed paths that zip 3.0.0 handled
  differently. In the tested fresh extraction directories, rewritten paths
  remained contained; this is not a universal filesystem-safety proof.
- Tests of truncated end records, truncated directory data and oversized declared
  lengths returned errors or read the actual payload. The oversized-length case
  was accepted and yielded 11 bytes, not an error. No observed panic or excess
  read occurred in these bounded probes; no memory-safety instrumentation ran.
  These constructed stored-entry probes do not verify the deflate backends.
- A small ToSchema/OpenApi example produced identical output under utoipa 5.5.0
  and 6.0.0. The server's actual OpenAPI export also ran. These checks do not prove
  every schema or generated client remains compatible.

The parent separately reran the workspace all-feature library/binary tests,
root all-target/all-feature clippy with -D warnings, formatting and cargo vet.
These are not the full integration/BDD/doctest suite; published final-head CI
must still pass before owner review is requested.

## Limits

All runtime probes were on x86_64 Linux. No ARM execution, Miri, sanitizer,
fuzzing, exhaustive malformed-input or resource-exhaustion campaign was run.
Upstream ZIP unit tests could not run offline because dev-dependencies were
unavailable; the custom executed probes were the bounded alternative, not a
substitute claim that upstream tests passed. ZIP's large source delta was not
exhaustively verified, including unused writer/encryption paths.

The build-time Swagger UI asset archive has no independently verified content
hash in this review. Building against cached or downloaded assets does not prove
asset integrity. The source patch does not enable a vendored-asset feature or
remove this disclosed risk. The owner accepted the stated limited review scope;
that acceptance and cargo-vet success are not security guarantees.
