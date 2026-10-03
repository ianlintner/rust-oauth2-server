"""Regression tests for the repository-local utoipa/Swagger exact-stack gate.

Owner-authorized (2026-10-02) scalar-only patch plus five human-owned
AI-assisted, non-importable attestations for utoipa 6.0.0, utoipa-gen 6.0.1,
utoipa-swagger-ui 10.0.1, zip 8.6.0 and typed-path 0.12.3. See
docs/security/utoipa-swagger-ui-10.0.1-attestation.md and
docs/security/utoipa-swagger-ui-owner-authorization.json.

These fixtures are explicit unit fixtures, but each one runs the *production*
decision function (`check_utoipa_stack_scope.main`) as a subprocess against an
explicit cargo-metadata snapshot, a Cargo.lock, and a vendored crate directory.
No fixture can pass by bypassing the real predicate. The default (no
``--metadata``) path is exercised separately by the CI step against the live
``cargo metadata --locked --all-features``.

Coverage:
- happy path (registry quartet + patched path crate + real vendored bytes)
- missing package / wrong version / older additional version / additional copy
  for EACH attested name (aggregate-count before version check)
- wrong source, wrong checksum, feature drift (extra + missing) for each name
- vendored source-file tampering, manifest tampering, extra file, missing file
- vendored path swap (directory replaced with a different tree)
- manifest_path bound to exactly the checked directory (same-suffix cross-checkout
  must be rejected); symlinked files/directories in the vendored tree rejected
- pin-table injection override argument rejected (baked-in pins only)
- malformed metadata / lockfile

The fixtures copy the real approved ``vendor/utoipa-swagger-ui-10.0.1`` source
(the 14 reviewed files) into a unique temporary directory and mutate it there.
Every fixture therefore exercises the production CLI with its *baked-in*
approved hashes; no fixture can inject a replacement pin table.
"""

import hashlib
import itertools
import json
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest

SCRIPT = pathlib.Path(__file__).with_name("check_utoipa_stack_scope.py")
REPO_ROOT = SCRIPT.parent.parent

# Real approved vendored source tree, copied verbatim into each fixture.
VENDOR_SRC = REPO_ROOT / "vendor" / "utoipa-swagger-ui-10.0.1"

WORKFLOW = REPO_ROOT / ".github" / "workflows" / "ci.yml"

# The gate step is gated on the dorny `code` paths-filter output. Every
# non-Rust file in the reviewed 14-file vendored tree must therefore be an
# ACTIVE `code` entry, or a change to it yields code == false and the
# whole-tree hash check is skipped. See Copilot review 5397373028.
VENDOR_WILDCARD = "vendor/utoipa-swagger-ui-10.0.1/**"

# Pinned non-Rust filenames in the vendored tree (mirror of the guard's
# 14-file inventory); each must be selected by the active `code` filter.
VENDOR_NONRUST_RELPATHS = (
    "vendor/utoipa-swagger-ui-10.0.1/Cargo.toml",
    "vendor/utoipa-swagger-ui-10.0.1/Cargo.toml.orig",
    "vendor/utoipa-swagger-ui-10.0.1/Cargo.lock",
    "vendor/utoipa-swagger-ui-10.0.1/.cargo_vcs_info.json",
    "vendor/utoipa-swagger-ui-10.0.1/LICENSE-APACHE",
    "vendor/utoipa-swagger-ui-10.0.1/LICENSE-MIT",
    "vendor/utoipa-swagger-ui-10.0.1/README.md",
    "vendor/utoipa-swagger-ui-10.0.1/CHANGELOG.md",
    "vendor/utoipa-swagger-ui-10.0.1/build.rs",
    # arbitrary non-Rust file added anywhere under the reviewed tree
    "vendor/utoipa-swagger-ui-10.0.1/arbitrary-added.txt",
)


def parse_active_filter_entries(workflow_text, filter_name):
    """Extract the ACTIVE entries of one embedded dorny ``filters: |`` filter.

    Intentionally narrow, indentation-aware parser for this single controlled
    workflow (not a general YAML reader, and deliberately NOT broad substring
    matching — a token that only appears in a ``#`` comment or under a
    different filter block must NOT be reported as an active entry).

    The block shape in ``.github/workflows/ci.yml`` is::

        with:
          filters: |
            code:
              - '**/*.rs'
            docs:
              - 'docs/**'

    so: locate ``filters: |``; then entries whose indentation is exactly one
    level deeper than a ``<name>:`` header line belong to that header's filter.
    A line is an entry only when the stripped text starts with ``- ``; trailing
    `` # comment`` is stripped before unquoting. Returns the list of unquoted
    glob strings for ``filter_name`` (empty if the filter is absent).
    """
    lines = workflow_text.splitlines()
    # 1. Find the embedded `filters: |` block.
    start = None
    for idx, line in enumerate(lines):
        if line.strip() == "filters: |":
            start = idx + 1
            break
    if start is None:
        return []

    filters_indent = len(lines[start - 1]) - len(lines[start - 1].lstrip(" "))

    current = None
    header_indent = None
    entries = []
    for raw in lines[start:]:
        if raw.strip() == "":
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        if indent <= filters_indent:
            break  # dedented out of the embedded block
        stripped = raw.strip()
        if stripped.startswith("#"):
            continue  # comment line is never an active entry
        # Strip an inline trailing comment before interpreting the token.
        code_part = stripped.split(" #", 1)[0].rstrip()
        if code_part.endswith(":") and not code_part.startswith("-"):
            # A filter header such as `code:` or `docs:`.
            current = code_part[:-1].strip()
            header_indent = indent
            continue
        if not code_part.startswith("-"):
            continue
        if current is None or indent <= (header_indent or 0):
            continue  # entry not under a header at the right depth
        token = code_part[1:].strip()
        if len(token) >= 2 and token[0] in "'\"" and token[-1] == token[0]:
            token = token[1:-1]
        if current == filter_name:
            entries.append(token)
    return entries

REGISTRY_SOURCE = "registry+https://github.com/rust-lang/crates.io-index"

# Exact reviewed stack (mirrors the guard's pinning table).
REGISTRY = {
    "utoipa": (
        "6.0.0",
        {"chrono", "default", "macros", "uuid"},
        "8765fe27aeff71012a3f90fa474cf1df863a7d0dd81ed25de4e63fff2544994f",
    ),
    "utoipa-gen": (
        "6.0.1",
        {"chrono", "uuid"},
        "d935f1c83fdf8b88f09bbe050d0cea78ea4afee6d7b0317403228c1200b2c8ab",
    ),
    "zip": (
        "8.6.0",
        {
            "_deflate-any",
            "deflate",
            "deflate-flate2",
            "deflate-flate2-zlib-rs",
            "deflate-zopfli",
        },
        "2d04a6b5381502aa6087c94c669499eb1602eb9c5e8198e534de571f7154809b",
    ),
    "typed-path": (
        "0.12.3",
        {"default", "std"},
        "8e28f89b80c87b8fb0cf04ab448d5dd0dd0ade2f8891bae878de66a75a28600e",
    ),
}

PATCHED_NAME = "utoipa-swagger-ui"
PATCHED_VERSION = "10.0.1"
PATCHED_FEATURES = {"actix-web", "default", "url"}
VENDOR_DIRNAME = "utoipa-swagger-ui-10.0.1"


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


_VENDOR_COUNTER = itertools.count(1)


def copy_approved_vendor(dest_root: pathlib.Path) -> pathlib.Path:
    """Copy the real approved vendored source into a fresh dir under ``dest_root``.

    Every fixture starts from the *actual* 14-file approved tree, so the guard's
    baked-in approved hashes are exercised against real bytes; mutations are
    applied by the caller afterwards. A unique subdirectory is used per call so
    repeated (subTest) invocations within one test never collide.
    """
    vendor = (
        dest_root
        / f"checkout-{next(_VENDOR_COUNTER)}"
        / "vendor"
        / VENDOR_DIRNAME
    )
    vendor.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(VENDOR_SRC, vendor)
    return vendor


def build_metadata(
    vendor_manifest: pathlib.Path,
    overrides=None,
    drop_packages=(),
    drop_nodes=(),
    drop_lock_entries=(),
    additional=(),
):
    """Build a cargo-metadata snapshot + matching Cargo.lock.

    ``vendor_manifest`` is the *exact* manifest the patched package must resolve
    from; it is written verbatim as the resolved ``manifest_path`` so a fixture
    that swaps in a different tree cannot pass by suffix coincidence.
    ``overrides`` maps crate name -> dict of package fields to override.
    ``additional`` is a list of extra package dicts appended verbatim.
    """
    overrides = overrides or {}
    packages = []
    nodes = []
    lock_sections = []

    for name, (version, features, checksum) in REGISTRY.items():
        if name in drop_packages:
            continue
        crate = overrides.get(name, {})
        package_version = crate.get("version", version)
        package_source = crate.get("source", REGISTRY_SOURCE)
        identifier = f"{REGISTRY_SOURCE}#{name}@{version}"
        packages.append(
            {
                "name": name,
                "version": package_version,
                "source": package_source,
                "id": crate.get("id", identifier),
            }
        )
        if name not in drop_nodes:
            nodes.append(
                {"id": crate.get("id", identifier), "features": crate.get("features", sorted(features))}
            )
        if name not in drop_lock_entries:
            lock_sections.append(
                "[[package]]\n"
                f'name = "{name}"\n'
                f'version = "{version}"\n'
                f'source = "{crate.get("lock_source", REGISTRY_SOURCE)}"\n'
                f'checksum = "{crate.get("lock_checksum", checksum)}"\n'
            )

    # Patched path crate.
    patched = overrides.get(PATCHED_NAME, {})
    if PATCHED_NAME not in drop_packages:
        identifier = patched.get(
            "id", f"path+file:///vendor#utoipa-swagger-ui@{PATCHED_VERSION}"
        )
        packages.append(
            {
                "name": PATCHED_NAME,
                "version": patched.get("version", PATCHED_VERSION),
                "source": patched.get("source", None),
                "id": identifier,
                "manifest_path": patched.get("manifest_path", str(vendor_manifest)),
            }
        )
        if PATCHED_NAME not in drop_nodes:
            nodes.append(
                {
                    "id": identifier,
                    "features": patched.get("features", sorted(PATCHED_FEATURES)),
                }
            )
        if PATCHED_NAME not in drop_lock_entries:
            # Path packages carry no source/checksum in Cargo.lock.
            lock_sections.append(
                "[[package]]\n"
                f'name = "{PATCHED_NAME}"\n'
                f'version = "{PATCHED_VERSION}"\n'
            )

    packages.extend(additional)
    metadata = {"packages": packages, "resolve": {"nodes": nodes}}
    return metadata, "\n".join(lock_sections)


class ScopeTests(unittest.TestCase):
    def setUp(self):
        self.assertTrue(SCRIPT.exists(), "missing utoipa stack scope gate")
        self.assertTrue(
            VENDOR_SRC.is_dir(),
            f"approved vendored source missing: {VENDOR_SRC}",
        )
        # Unique temporary fixture root under the scratch TMPDIR, never the repo.
        self._tmp = tempfile.TemporaryDirectory(prefix="utoipa-scope-")
        self.fixture = pathlib.Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def run_gate(self, metadata, lockfile, vendor_manifest, extra_args=()):
        """Run the production CLI against one fixture.

        ``vendor_manifest`` is the manifest path the metadata resolves to; the
        vendor directory checked is its parent, so happy fixtures bind the two
        to the same directory. ``metadata`` may be a dict or a raw string.
        """
        metadata_path = self.fixture / "metadata.json"
        lock_path = self.fixture / "Cargo.lock"
        if isinstance(metadata, str):
            metadata_path.write_text(metadata)
        else:
            metadata_path.write_text(json.dumps(metadata))
        lock_path.write_text(lockfile if lockfile is not None else "")
        return subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "--metadata",
                str(metadata_path),
                "--lockfile",
                str(lock_path),
                "--vendor",
                str(vendor_manifest.parent),
                *extra_args,
            ],
            text=True,
            capture_output=True,
            check=False,
        )

    # ----- happy path -----------------------------------------------------

    def test_reviewed_stack_is_accepted(self):
        vendor = copy_approved_vendor(self.fixture)
        manifest = vendor / "Cargo.toml"
        metadata, lock = build_metadata(manifest)
        # The fixture is the reviewed bytes at the fixture's OWN resolved path,
        # not a hardcoded literal: metadata.manifest_path must be this tree.
        patched = next(p for p in metadata["packages"] if p["name"] == PATCHED_NAME)
        self.assertEqual(patched["manifest_path"], str(manifest))
        self.assertTrue(
            str(manifest).startswith(str(self.fixture)),
            "happy fixture must bind to its own temporary checkout, not a literal",
        )
        result = self.run_gate(metadata, lock, manifest)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("14 files pinned", result.stdout)

    # ----- aggregate count before version (all five names) ----------------

    def test_missing_package_rejected_per_name(self):
        names = list(REGISTRY) + [PATCHED_NAME]
        for name in names:
            with self.subTest(crate=name):
                vendor = copy_approved_vendor(self.fixture)
                manifest = vendor / "Cargo.toml"
                metadata, lock = build_metadata(manifest, drop_packages=(name,))
                result = self.run_gate(metadata, lock, manifest)
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertIn(name, result.stderr)

    def test_older_additional_version_rejected_per_name(self):
        # typed-path 0.11.2 does not exist on crates.io (original typo'd
        # fixture); 0.11.0 is the authentic prior release, so model that.
        older = {
            "utoipa": "5.5.0",
            "utoipa-gen": "5.5.0",
            "zip": "3.0.0",
            "typed-path": "0.11.0",
            PATCHED_NAME: "10.0.0",
        }
        for name, old in older.items():
            with self.subTest(crate=name):
                vendor = copy_approved_vendor(self.fixture)
                manifest = vendor / "Cargo.toml"
                metadata, lock = build_metadata(manifest)
                additional = dict(
                    next(p for p in metadata["packages"] if p["name"] == name)
                )
                additional["version"] = old
                additional["id"] = f"{REGISTRY_SOURCE}#{name}@{old}"
                metadata["packages"].append(additional)
                metadata["resolve"]["nodes"].append(
                    {"id": additional["id"], "features": []}
                )
                result = self.run_gate(metadata, lock, manifest)
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertIn("exactly one", result.stderr)
                self.assertIn(name, result.stderr)

    def test_duplicate_reviewed_version_rejected_per_name(self):
        for name in list(REGISTRY) + [PATCHED_NAME]:
            with self.subTest(crate=name):
                vendor = copy_approved_vendor(self.fixture)
                manifest = vendor / "Cargo.toml"
                metadata, lock = build_metadata(manifest)
                duplicate = dict(
                    next(p for p in metadata["packages"] if p["name"] == name)
                )
                duplicate["id"] = duplicate["id"] + "-dup"
                metadata["packages"].append(duplicate)
                metadata["resolve"]["nodes"].append(
                    {"id": duplicate["id"], "features": []}
                )
                result = self.run_gate(metadata, lock, manifest)
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertIn("exactly one", result.stderr)
                self.assertIn(name, result.stderr)

    def test_wrong_version_rejected_per_name(self):
        drift = {
            "utoipa": "6.0.1",
            "utoipa-gen": "6.0.2",
            "zip": "8.6.1",
            "typed-path": "0.12.4",
            PATCHED_NAME: "10.0.2",
        }
        for name, bad in drift.items():
            with self.subTest(crate=name):
                vendor = copy_approved_vendor(self.fixture)
                manifest = vendor / "Cargo.toml"
                metadata, lock = build_metadata(
                    manifest, overrides={name: {"version": bad}}
                )
                result = self.run_gate(metadata, lock, manifest)
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertIn(name, result.stderr)

    # ----- source / checksum ---------------------------------------------

    def test_registry_source_drift_rejected_per_name(self):
        for name in REGISTRY:
            with self.subTest(crate=name):
                vendor = copy_approved_vendor(self.fixture)
                manifest = vendor / "Cargo.toml"
                metadata, lock = build_metadata(
                    manifest,
                    overrides={name: {"source": "git+https://example.invalid/" + name}},
                )
                result = self.run_gate(metadata, lock, manifest)
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertIn("source", result.stderr)

    def test_checksum_drift_rejected_per_name(self):
        for name in REGISTRY:
            with self.subTest(crate=name):
                vendor = copy_approved_vendor(self.fixture)
                manifest = vendor / "Cargo.toml"
                metadata, lock = build_metadata(
                    manifest, overrides={name: {"lock_checksum": "0" * 64}}
                )
                result = self.run_gate(metadata, lock, manifest)
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertIn("checksum", result.stderr)

    def test_lock_source_drift_rejected_per_name(self):
        for name in REGISTRY:
            with self.subTest(crate=name):
                vendor = copy_approved_vendor(self.fixture)
                manifest = vendor / "Cargo.toml"
                metadata, lock = build_metadata(
                    manifest,
                    overrides={name: {"lock_source": "git+https://example.invalid/" + name}},
                )
                result = self.run_gate(metadata, lock, manifest)
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertIn("source", result.stderr)

    # ----- feature drift --------------------------------------------------

    def test_extra_feature_rejected_per_name(self):
        for name in REGISTRY:
            with self.subTest(crate=name):
                base = sorted(REGISTRY[name][1])
                vendor = copy_approved_vendor(self.fixture)
                manifest = vendor / "Cargo.toml"
                metadata, lock = build_metadata(
                    manifest, overrides={name: {"features": base + ["extra-feature"]}}
                )
                result = self.run_gate(metadata, lock, manifest)
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertIn("extra-feature", result.stderr)

    def test_missing_feature_rejected_per_name(self):
        for name in REGISTRY:
            with self.subTest(crate=name):
                base = sorted(REGISTRY[name][1])
                vendor = copy_approved_vendor(self.fixture)
                manifest = vendor / "Cargo.toml"
                metadata, lock = build_metadata(
                    manifest, overrides={name: {"features": base[1:]}}
                )
                result = self.run_gate(metadata, lock, manifest)
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertIn("feature drift", result.stderr)

    def test_patched_feature_drift_rejected(self):
        vendor = copy_approved_vendor(self.fixture)
        manifest = vendor / "Cargo.toml"
        metadata, lock = build_metadata(
            manifest,
            overrides={PATCHED_NAME: {"features": sorted(PATCHED_FEATURES | {"vendored"})}},
        )
        result = self.run_gate(metadata, lock, manifest)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("vendored", result.stderr)

    # ----- manifest_path bound to the checked directory (defect 1) --------

    def test_cross_checkout_same_suffix_manifest_rejected(self):
        """The resolved manifest_path must be the EXACT directory checked.

        A metadata snapshot that resolves the patched crate from a different
        checkout whose path merely *ends* with the reviewed relative path (e.g.
        ``/unreviewed/other-checkout/vendor/utoipa-swagger-ui-10.0.1``) must be
        rejected, even when the bytes in the checked local tree are reviewed.
        """
        vendor = copy_approved_vendor(self.fixture)
        manifest = vendor / "Cargo.toml"
        # Bytes checked are the approved tree; metadata points elsewhere.
        foreign = "/unreviewed/other-checkout/vendor/utoipa-swagger-ui-10.0.1/Cargo.toml"
        metadata, lock = build_metadata(manifest)
        patched = next(
            p for p in metadata["packages"] if p["name"] == PATCHED_NAME
        )
        patched["manifest_path"] = foreign
        result = self.run_gate(metadata, lock, manifest)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("manifest", result.stderr)

    def test_same_suffix_foreign_vendor_dir_rejected(self):
        """A vendor dir that does not match the resolved manifest is rejected.

        Here cargo resolves the *real* reviewed path, but the ``--vendor``
        directory (whose bytes are hashed) lives in another checkout with the
        same suffix. The two must coincide.
        """
        vendor = copy_approved_vendor(self.fixture)
        manifest = vendor / "Cargo.toml"
        metadata, lock = build_metadata(manifest)
        # Point cargo at a legitimately named but different directory.
        other = self.fixture / "other-checkout" / "vendor" / VENDOR_DIRNAME
        shutil.copytree(VENDOR_SRC, other)
        foreign_manifest = other / "Cargo.toml"
        patched = next(
            p for p in metadata["packages"] if p["name"] == PATCHED_NAME
        )
        patched["manifest_path"] = str(foreign_manifest)
        result = self.run_gate(metadata, lock, manifest)
        self.assertNotEqual(result.returncode, 0, result.stdout)

    def test_symlinked_vendor_file_rejected(self):
        """A symlinked file in the vendored tree must not satisfy the inventory.

        ``rglob`` would follow or skip a symlink depending on platform; a
        symlink is not a reviewed regular file and must fail closed.
        """
        vendor = copy_approved_vendor(self.fixture)
        manifest = vendor / "Cargo.toml"
        metadata, lock = build_metadata(manifest)
        target = vendor / "src" / "lib.rs"
        real = target.read_bytes()
        decoy = self.fixture / "decoy-lib.rs"
        decoy.write_bytes(real)
        target.unlink()
        target.symlink_to(decoy)
        result = self.run_gate(metadata, lock, manifest)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("symlink", result.stderr)

    def test_symlinked_vendor_directory_rejected(self):
        """A symlinked directory inside the vendored tree must fail closed."""
        vendor = copy_approved_vendor(self.fixture)
        manifest = vendor / "Cargo.toml"
        metadata, lock = build_metadata(manifest)
        real_src = vendor / "src"
        moved = self.fixture / "moved-src"
        shutil.move(str(real_src), str(moved))
        real_src.symlink_to(moved, target_is_directory=True)
        result = self.run_gate(metadata, lock, manifest)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("symlink", result.stderr)

    # ----- vendored tree integrity ---------------------------------------

    def test_vendored_source_tampering_rejected(self):
        vendor = copy_approved_vendor(self.fixture)
        manifest = vendor / "Cargo.toml"
        metadata, lock = build_metadata(manifest)
        (vendor / "src" / "lib.rs").write_bytes(b"// tampered\n")
        result = self.run_gate(metadata, lock, manifest)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("src/lib.rs", result.stderr)

    def test_vendored_manifest_tampering_rejected(self):
        vendor = copy_approved_vendor(self.fixture)
        manifest = vendor / "Cargo.toml"
        metadata, lock = build_metadata(manifest)
        manifest.write_bytes(
            b'[package]\nname = "utoipa-swagger-ui"\n# tampered\n'
        )
        result = self.run_gate(metadata, lock, manifest)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("Cargo.toml", result.stderr)

    def test_vendored_extra_file_rejected(self):
        vendor = copy_approved_vendor(self.fixture)
        manifest = vendor / "Cargo.toml"
        metadata, lock = build_metadata(manifest)
        (vendor / "src" / "injected.rs").write_bytes(b"// untracked\n")
        result = self.run_gate(metadata, lock, manifest)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("injected.rs", result.stderr)

    def test_vendored_missing_file_rejected(self):
        vendor = copy_approved_vendor(self.fixture)
        manifest = vendor / "Cargo.toml"
        metadata, lock = build_metadata(manifest)
        (vendor / "LICENSE-MIT").unlink()
        result = self.run_gate(metadata, lock, manifest)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("LICENSE-MIT", result.stderr)

    def test_vendored_path_swap_rejected(self):
        # Replace the checked tree with a different tree at the same name.
        vendor = copy_approved_vendor(self.fixture)
        manifest = vendor / "Cargo.toml"
        metadata, lock = build_metadata(manifest)
        shutil.rmtree(vendor)
        (vendor / "src").mkdir(parents=True)
        (vendor / "Cargo.toml").write_bytes(
            b'[package]\nname = "utoipa-swagger-ui"\nversion = "10.0.1"\n# swapped\n'
        )
        (vendor / "src" / "other.rs").write_bytes(b"// other\n")
        result = self.run_gate(metadata, lock, vendor / "Cargo.toml")
        self.assertNotEqual(result.returncode, 0, result.stdout)

    # ----- override-flag removal (defect 2) -------------------------------

    def test_unknown_hash_override_argument_is_rejected(self):
        """The reviewed pin table is baked in; no caller may substitute it.

        The production CLI must not accept ``--self-test-vendor-hashes`` (or any
        other pin-injection override): that flag let a caller replace the
        reviewed byte hashes with hashes of a tampered tree.
        """
        vendor = copy_approved_vendor(self.fixture)
        manifest = vendor / "Cargo.toml"
        metadata, lock = build_metadata(manifest)
        override_path = self.fixture / "override.json"
        override_path.write_text(json.dumps({"Cargo.toml": "0" * 64}))
        result = self.run_gate(
            metadata,
            lock,
            manifest,
            extra_args=("--self-test-vendor-hashes", str(override_path)),
        )
        self.assertNotEqual(result.returncode, 0, result.stdout)

    # ----- malformed inputs ----------------------------------------------

    def test_cargo_metadata_failure_fails_closed(self):
        """A failing ``cargo metadata`` must be a clean nonzero scope failure.

        On the default (no ``--metadata``) path a cargo error previously
        escaped as an unhandled traceback; it must instead fail closed with a
        scope message and a nonzero exit.
        """
        fake_bin = self.fixture / "bin"
        fake_bin.mkdir()
        fake_cargo = fake_bin / "cargo"
        fake_cargo.write_text("#!/bin/sh\necho 'boom: not in a cargo project' >&2\nexit 101\n")
        fake_cargo.chmod(0o755)
        env = dict(**__import__("os").environ)
        env["PATH"] = str(fake_bin) + ":" + env.get("PATH", "")
        result = subprocess.run(
            [sys.executable, str(SCRIPT)],
            text=True,
            capture_output=True,
            check=False,
            env=env,
            cwd=str(self.fixture),
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("utoipa stack scope", result.stderr)
        self.assertNotIn("Traceback", result.stderr)

    def test_malformed_metadata_json_rejected(self):
        vendor = copy_approved_vendor(self.fixture)
        manifest = vendor / "Cargo.toml"
        _, lock = build_metadata(manifest)
        result = self.run_gate("{not json", lock, manifest)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("utoipa", result.stderr)

    def test_malformed_lockfile_rejected(self):
        vendor = copy_approved_vendor(self.fixture)
        manifest = vendor / "Cargo.toml"
        metadata, _ = build_metadata(manifest)
        result = self.run_gate(metadata, "this = = broken", manifest)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("utoipa", result.stderr)

    def test_missing_metadata_rejected(self):
        vendor = copy_approved_vendor(self.fixture)
        manifest = vendor / "Cargo.toml"
        _, lock = build_metadata(manifest)
        result = self.run_gate({"packages": []}, lock, manifest)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("utoipa", result.stderr)


class WorkflowWiringTests(unittest.TestCase):
    """The exact-stack gate must actually RUN for every vendored-tree change.

    Copilot review 5397373028: the gate step in ``.github/workflows/ci.yml``
    is ``if: needs.changes.outputs.code == 'true'``, but the dorny ``code``
    paths-filter did not list ``vendor/**``. A change confined to a non-Rust
    file in the reviewed vendored tree (``Cargo.toml.orig``, ``LICENSE-*``,
    ``.cargo_vcs_info.json``, the nested ``Cargo.lock``, or an arbitrary added
    file) therefore produced ``code == false`` and silently skipped the
    whole-tree hash check.

    These tests parse the *actual* workflow file with an indentation-aware
    parser (not broad substring matching, which a ``#`` comment or a token in
    an unrelated filter would falsely satisfy) and assert the vendor wildcard
    is an ACTIVE ``code`` entry. Mutation fixtures prove the parser would
    catch comment-only / wrong-filter / wrong-depth regressions.
    """

    def setUp(self):
        self.assertTrue(WORKFLOW.is_file(), f"missing workflow: {WORKFLOW}")
        self.text = WORKFLOW.read_text()
        self.entries = parse_active_filter_entries(self.text, "code")

    # ----- parser sanity (so the assertions below cannot be vacuous) ------

    def test_parser_reads_the_live_code_filter(self):
        self.assertIn("**/*.rs", self.entries)
        self.assertIn(".github/workflows/**", self.entries)
        # A non-`code` filter must not leak into the `code` read.
        inject = self.text.replace(
            "            code:\n",
            "            code:\n              - '**/*.rs'\n"
            "            docs:\n              - 'docs/**'\n",
            1,
        )
        entries = parse_active_filter_entries(inject, "code")
        self.assertIn("**/*.rs", entries)
        self.assertNotIn("docs/**", entries)

    def test_parser_ignores_comment_only_and_wrong_indent_tokens(self):
        # Self-contained controlled block (independent of the live entry) so
        # these mutations prove the parser rejects non-active tokens.
        def block(entry_line, indent):
            return (
                "      - uses: dorny/paths-filter@deadbeef\n"
                "        with:\n"
                "          filters: |\n"
                "            code:\n"
                "              - '**/*.rs'\n"
                f"{' ' * indent}{entry_line}\n"
                "            docs:\n"
                "              - 'docs/**'\n"
            )

        # 1. A token that appears ONLY in a comment is not an active entry.
        comment_only = block(f"# - '{VENDOR_WILDCARD}'", 14)
        self.assertNotIn(
            VENDOR_WILDCARD, parse_active_filter_entries(comment_only, "code")
        )

        # 2. A token under a DIFFERENT filter (`docs:`) is not a `code` entry.
        other_filter = (
            "      - uses: dorny/paths-filter@deadbeef\n"
            "        with:\n"
            "          filters: |\n"
            "            code:\n"
            "              - '**/*.rs'\n"
            "            docs:\n"
            f"              - '{VENDOR_WILDCARD}'\n"
        )
        self.assertNotIn(
            VENDOR_WILDCARD, parse_active_filter_entries(other_filter, "code")
        )
        # ...and it IS an active `docs` entry, proving the scope is exact.
        self.assertIn(
            VENDOR_WILDCARD, parse_active_filter_entries(other_filter, "docs")
        )

        # 3. A token at the WRONG indent depth is not an active entry.
        wrong_depth = block(f"- '{VENDOR_WILDCARD}'", 10)
        self.assertNotIn(
            VENDOR_WILDCARD, parse_active_filter_entries(wrong_depth, "code")
        )

    # ----- the actual regression (this is the RED assertion) --------------

    def test_vendor_tree_is_active_code_trigger(self):
        self.assertIn(
            VENDOR_WILDCARD,
            self.entries,
            "the dorny `code` paths-filter must list the reviewed vendored tree "
            "so the exact-stack gate is not skipped for non-Rust vendor edits",
        )

    def test_vendor_wildcard_covers_every_pinned_nonrust_file(self):
        # The wildcard must sit in the SAME directory as the pinned files, so
        # `<dir>/**` selects each of them (and any arbitrary added file).
        for relpath in VENDOR_NONRUST_RELPATHS:
            with self.subTest(path=relpath):
                self.assertTrue(
                    relpath.startswith(VENDOR_WILDCARD[:-3]),
                    f"{relpath} is not under {VENDOR_WILDCARD}",
                )

    def test_gate_step_still_gated_on_code(self):
        # The fix must not narrow the trigger or disable the step; the gate
        # stays tied to `code`, the vendor wildcard just widens `code`.
        self.assertRegex(
            self.text,
            r"Verify utoipa/Swagger exact stack scope\s*\n\s*if:\s*"
            r"needs\.changes\.outputs\.code == 'true'",
        )
        self.assertIn("python3 scripts/check_utoipa_stack_scope.py", self.text)


if __name__ == "__main__":
    unittest.main()
