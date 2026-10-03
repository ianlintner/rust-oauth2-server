"""Fail-closed exact-stack gate for the owner-authorized utoipa/Swagger upgrade.

Owner authorization (2026-10-02): a scalar-only local patch of utoipa-swagger-ui
10.0.1 plus five human-owned, AI-assisted, non-importable ``safe-to-deploy``
attestations for utoipa 6.0.0, utoipa-gen 6.0.1, utoipa-swagger-ui 10.0.1,
zip 8.6.0 and typed-path 0.12.3. See
``docs/security/utoipa-swagger-ui-owner-authorization.json`` and
``docs/security/utoipa-swagger-ui-10.0.1-attestation.md``.

Cargo-vet cannot enforce feature scope, source/checksum pinning, or the exact
contents of a *path* override (``audit-as-crates-io`` for a path dependency only
requires an audit of the base published version; it has no hash of the local
tree). This gate therefore fails closed *before* ``cargo vet`` if any attested
crate drifts in name/version/source/checksum/features, or if the vendored
patched crate drifts by even one byte or one file.

The base64 0.23.1 SIMD exclusion is enforced separately and unchanged by
``scripts/check_base64_audit_scope.py``; this gate is additive.

Exit codes: 0 = reviewed stack intact; 1 = any drift or malformed input.
"""

import argparse
import hashlib
import json
import os
import pathlib
import subprocess
import sys
import tomllib

REGISTRY_SOURCE = "registry+https://github.com/rust-lang/crates.io-index"

# Reviewed registry crates: exact version, exact resolved feature set, and the
# Cargo.lock checksum taken from the verified .crate archives.
REVIEWED_REGISTRY = {
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

# Reviewed local path override of utoipa-swagger-ui 10.0.1.
PATCHED_NAME = "utoipa-swagger-ui"
PATCHED_VERSION = "10.0.1"
PATCHED_FEATURES = {"actix-web", "default", "url"}
# Repository-relative path of the vendored crate; the resolved manifest_path
# must equal this checkout's checked manifest after resolving symlinks.
PATCHED_VENDOR_RELPATH = "vendor/utoipa-swagger-ui-10.0.1"
PATCHED_VENDOR_ARCHIVE_SHA256 = (
    "3f5ec9d7816e4ce8ccb7e0bd7276e090cad0fcb1def4f3540e5b0f7485d7583e"
)

# SHA-256 of every file in the vendored crate, exactly as delivered. The
# manifest (Cargo.toml) is the reviewed *patched* manifest. Byte-pinning the
# whole tree is what makes the local (unhashable-by-cargo-vet) override
# auditable here.
REVIEWED_VENDOR_FILES = {
    ".cargo_vcs_info.json": "cd24436439dc3a2d80c52f3ee1937a355d12d17b9b9d729687a1f04b49fac16c",
    "CHANGELOG.md": "407a2d06576b574bb8bfd6b2853ae51ccbb16aee3f835d8d053d4ab672283e49",
    "Cargo.lock": "a2c980d56bcfb6ca72c76f180c669dfa534f1efa65afc5a28e143c1813f77683",
    "Cargo.toml": "0d776b0efad38f890c342e14a1230310ac12c6ddfc15f3d54150b4c19b3268d1",
    "Cargo.toml.orig": "3bf06e4ed5bdf5e485fb87a8f50874b6b71fb8bf2873126ba3ce11cca643e294",
    "LICENSE-APACHE": "43070e2d4e532684de521b885f385d0841030efa2b1a20bafb76133a5e1379c1",
    "LICENSE-MIT": "82b13fb25622b1950fecb9efa76d8b3cfd956ecc136893e4fe47fbaf74fba097",
    "README.md": "12f52b9aee64dafd83e74ce7ecdcf47bf305fcc56409798c3edf09c24b754a4f",
    "build.rs": "263bbd27b5d734cffdd6cfdffcc36eca81c0de86f355fc983205b1c6b059a97d",
    "src/actix.rs": "f3e2d24924f875c0142a192a2a710d530427a36b36bd7e350f2c38a2b3c7f8a2",
    "src/axum.rs": "55e915b1efd142008a1b2df1c033a2e0441896f3120a44f5b87846ee8e7f4ef2",
    "src/lib.rs": "878fb16de644da96d5da27d945176b3aa9f653cac6d173a8694fc673ec033ab4",
    "src/oauth.rs": "fba12149325e87060598fa40f07d13bb75cc75924b7302f2a30c25eebe4b36e3",
    "src/rocket.rs": "811c3270ad9014c403c5889632ba3d22cee1811e5a90896f77de130044663438",
}


def fail(message):
    print("utoipa stack scope: " + message, file=sys.stderr)
    return 1


def load_metadata(path):
    if path is not None:
        raw = path.read_text()
    else:
        try:
            result = subprocess.run(
                ["cargo", "metadata", "--locked", "--all-features", "--format-version", "1"],
                check=True,
                text=True,
                capture_output=True,
            )
        except FileNotFoundError:
            raise SystemExit(
                "utoipa stack scope INCONCLUSIVE: cargo not found on PATH"
            )
        except subprocess.CalledProcessError as error:
            detail = (error.stderr or "").strip().splitlines()
            raise SystemExit(
                "utoipa stack scope INCONCLUSIVE: cargo metadata failed "
                f"(exit {error.returncode}): "
                + (detail[-1] if detail else "no stderr")
            )
        raw = result.stdout
    return json.loads(raw)


def load_lockfile(path):
    if not path.exists():
        raise FileNotFoundError(path)
    data = tomllib.loads(path.read_text())
    entries = {}
    for package in data.get("package", []):
        entries.setdefault(package["name"], []).append(package)
    return entries


def sha256_file(path):
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def check_registry_crate(name, version, features, checksum, packages, nodes, lock_entries):
    """Verify one registry crate: sole package of this name, exact version,
    registry source, exact features, and matching Cargo.lock source/checksum.

    The aggregate count is done BEFORE the version check so an extra older or
    newer copy of the same crate name cannot hide behind the reviewed version
    (a legacy cargo-vet exemption for a sibling version can otherwise pass vet).
    """
    matched = [package for package in packages if package["name"] == name]
    if len(matched) != 1:
        return fail(
            f"expected exactly one resolved {name} {version}, found {len(matched)}"
        )
    package = matched[0]
    if package.get("version") != version:
        return fail(f"expected reviewed {name} {version}, found {package.get('version')!r}")
    if package.get("source") != REGISTRY_SOURCE:
        return fail(f"{name} {version} source not reviewable: {package.get('source')!r}")
    if package["id"] not in nodes:
        return fail(f"{name} {version} missing from resolve.nodes")
    enabled = set(nodes[package["id"]]["features"])
    unexpected = enabled - features
    missing = features - enabled
    if unexpected or missing:
        return fail(
            f"{name} {version} feature drift: unexpected="
            + ", ".join(sorted(unexpected))
            + " missing="
            + ", ".join(sorted(missing))
        )
    lock_matches = [
        entry for entry in lock_entries.get(name, []) if entry.get("version") == version
    ]
    if len(lock_matches) != 1:
        return fail(f"Cargo.lock missing reviewed entry for {name} {version}")
    if lock_matches[0].get("checksum") != checksum:
        return fail(f"{name} {version} checksum drift in Cargo.lock")
    if lock_matches[0].get("source") != REGISTRY_SOURCE:
        return fail(f"{name} {version} source drift in Cargo.lock")
    return None


def resolve_dir(path):
    """Return the real (symlink-resolved) absolute form of a directory path."""
    return pathlib.Path(os.path.realpath(path))


def is_symlink(path):
    return path.is_symlink()


def check_patched_crate(packages, nodes, lock_entries, vendor_dir, expected_files):
    """Verify the local utoipa-swagger-ui path override.

    - exactly one package of this name (aggregate count before version)
    - version 10.0.1, no registry source (path package), expected features
    - resolved manifest_path is *exactly* ``<vendor_dir>/Cargo.toml`` after
      symlink-resolving both sides: the metadata must describe the very
      directory whose bytes are inventoried below, not merely a path that
      shares the reviewed suffix from some other checkout
    - Cargo.lock has no source/checksum for it (it is first-party)
    - the on-disk vendored tree matches the reviewed byte hashes exactly:
      no extra file, no missing file, no altered byte, no symlink.
    """
    matched = [package for package in packages if package["name"] == PATCHED_NAME]
    if len(matched) != 1:
        return fail(
            f"expected exactly one resolved {PATCHED_NAME} {PATCHED_VERSION}, "
            f"found {len(matched)}"
        )
    package = matched[0]
    if package.get("version") != PATCHED_VERSION:
        return fail(
            f"expected reviewed {PATCHED_NAME} {PATCHED_VERSION}, "
            f"found {package.get('version')!r}"
        )
    if package.get("source") is not None:
        return fail(
            f"{PATCHED_NAME} {PATCHED_VERSION} is not the reviewed local path "
            f"override (source={package.get('source')!r})"
        )
    if is_symlink(vendor_dir):
        return fail(f"vendored crate directory is a symlink: {vendor_dir}")
    resolved_manifest = package.get("manifest_path") or ""
    expected_manifest = resolve_dir(vendor_dir) / "Cargo.toml"
    if resolve_dir(resolved_manifest) != expected_manifest:
        return fail(
            f"{PATCHED_NAME} {PATCHED_VERSION} resolved from unexpected "
            f"manifest_path: {resolved_manifest!r} "
            f"(expected exactly {str(expected_manifest)!r})"
        )
    if package["id"] not in nodes:
        return fail(f"{PATCHED_NAME} {PATCHED_VERSION} missing from resolve.nodes")
    enabled = set(nodes[package["id"]]["features"])
    unexpected = enabled - PATCHED_FEATURES
    missing = PATCHED_FEATURES - enabled
    if unexpected or missing:
        return fail(
            f"{PATCHED_NAME} {PATCHED_VERSION} feature drift: unexpected="
            + ", ".join(sorted(unexpected))
            + " missing="
            + ", ".join(sorted(missing))
        )
    lock_matches = [
        entry
        for entry in lock_entries.get(PATCHED_NAME, [])
        if entry.get("version") == PATCHED_VERSION
    ]
    if len(lock_matches) != 1:
        return fail(
            f"Cargo.lock missing reviewed entry for {PATCHED_NAME} {PATCHED_VERSION}"
        )
    if lock_matches[0].get("source") is not None or lock_matches[0].get("checksum") is not None:
        return fail(
            f"{PATCHED_NAME} {PATCHED_VERSION} unexpectedly has a registry "
            "source/checksum in Cargo.lock"
        )

    # Vendored tree integrity.
    if not vendor_dir.is_dir():
        return fail(f"vendored crate directory missing: {vendor_dir}")
    on_disk = {}
    for path in vendor_dir.rglob("*"):
        rel = path.relative_to(vendor_dir).as_posix()
        # A symlink is not a reviewed regular file: ``rglob`` may follow it
        # (silently substituting other bytes) or skip it (silently dropping a
        # reviewed file). Either way the whole-tree inventory claim is void.
        if is_symlink(path):
            return fail(f"vendored crate contains a symlink: {rel}")
        if path.is_dir():
            continue
        if not path.is_file():
            return fail(f"vendored crate contains a non-regular file: {rel}")
        on_disk[rel] = sha256_file(path)
    missing_files = sorted(set(expected_files) - set(on_disk))
    extra_files = sorted(set(on_disk) - set(expected_files))
    if missing_files:
        return fail("vendored crate missing files: " + ", ".join(missing_files))
    if extra_files:
        return fail("vendored crate has unexpected files: " + ", ".join(extra_files))
    tampered = sorted(
        rel for rel, digest in expected_files.items() if on_disk[rel] != digest
    )
    if tampered:
        return fail("vendored crate file hash mismatch: " + ", ".join(tampered))
    return None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--metadata", type=pathlib.Path, help="Use an existing Cargo metadata snapshot"
    )
    parser.add_argument(
        "--lockfile", type=pathlib.Path, help="Cargo.lock to verify (default: ./Cargo.lock)"
    )
    parser.add_argument(
        "--vendor",
        type=pathlib.Path,
        help=f"Vendored crate directory (default: ./{PATCHED_VENDOR_RELPATH})",
    )
    args = parser.parse_args()

    try:
        metadata = load_metadata(args.metadata)
    except (OSError, ValueError) as error:
        return fail(f"unreadable cargo metadata: {error}")

    lock_path = args.lockfile or pathlib.Path("Cargo.lock")
    try:
        lock_entries = load_lockfile(lock_path)
    except (OSError, tomllib.TOMLDecodeError) as error:
        return fail(f"unreadable Cargo.lock {lock_path}: {error}")

    vendor_dir = args.vendor or pathlib.Path(PATCHED_VENDOR_RELPATH)
    expected_files = REVIEWED_VENDOR_FILES

    try:
        nodes = {node["id"]: node for node in metadata["resolve"]["nodes"]}
        packages = metadata["packages"]
    except (KeyError, TypeError) as error:
        return fail(f"malformed cargo metadata graph: {error!r}")

    for name, (version, features, checksum) in REVIEWED_REGISTRY.items():
        error = check_registry_crate(
            name, version, features, checksum, packages, nodes, lock_entries
        )
        if error is not None:
            return error

    error = check_patched_crate(packages, nodes, lock_entries, vendor_dir, expected_files)
    if error is not None:
        return error

    print(
        "utoipa stack scope OK: "
        + ", ".join(f"{n} {v}" for n, (v, _, _) in REVIEWED_REGISTRY.items())
        + f", {PATCHED_NAME} {PATCHED_VERSION} (vendored path, "
        + f"{len(expected_files)} files pinned)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
