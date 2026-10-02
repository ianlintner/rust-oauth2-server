"""Enforce the exact reviewed scope of the owner-authorized Argon2 stack audit.

Owner-authorized human attestation of AI-assisted safe-to-deploy review for
argon2 0.6.0, blake2 0.11.0, password-hash 0.6.1 and phc 0.6.1 (see
docs/supply-chain/argon2-0.6.0-ai-assisted-review.md). Cargo-vet does not
enforce feature scope, so this gate fails closed before vet if any reviewed
crate drifts in version, source, checksum or enabled features.

cargo metadata without --filter-platform covers the resolved target graph and
--all-features covers every workspace feature, matching cargo-vet's scope.
"""

import argparse
import json
import pathlib
import subprocess
import sys
import tomllib

SOURCE = "registry+https://github.com/rust-lang/crates.io-index"

# Reviewed version, allowed feature set and Cargo.lock checksum per crate.
REVIEWED = {
    "argon2": (
        "0.6.0",
        {"alloc", "default", "getrandom", "password-hash"},
        "134c52ddac6d63c576bef8168db10c83c49c26444ecbc68060fef078925a901c",
    ),
    "blake2": (
        "0.11.0",
        set(),
        "5b5d4d889834ee8ecfc0f8426ad30faf7cdcb10f741a8e6d7224d95325479f6f",
    ),
    "password-hash": (
        "0.6.1",
        {"alloc", "getrandom", "phc"},
        "aab41826031698d6ffcd9cff78ef56ef998e39dc7e5067cdfebe373842d4723b",
    ),
    "phc": (
        "0.6.1",
        {"alloc", "getrandom"},
        "44dc769b75f93afdddd8c7fa12d685292ddeff1e66f7f0f3a234cf1818afe892",
    ),
}


def fail(message):
    print("argon2 audit scope: " + message, file=sys.stderr)
    return 1


def load_metadata(path):
    if path is not None:
        raw = path.read_text()
    else:
        result = subprocess.run(
            ["cargo", "metadata", "--locked", "--all-features", "--format-version", "1"],
            check=True,
            text=True,
            capture_output=True,
        )
        raw = result.stdout
    return json.loads(raw)


def resolve_graph(metadata):
    nodes = {node["id"]: node for node in metadata["resolve"]["nodes"]}
    return nodes, metadata["packages"]


def load_lockfile(path):
    if not path.exists():
        raise FileNotFoundError(path)
    data = tomllib.loads(path.read_text())
    entries = {}
    for package in data.get("package", []):
        entries.setdefault(package["name"], []).append(package)
    return entries


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--metadata", type=pathlib.Path, help="Use an existing Cargo metadata snapshot"
    )
    parser.add_argument(
        "--lockfile", type=pathlib.Path, help="Cargo.lock to verify (default: ./Cargo.lock)"
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

    try:
        nodes, packages = resolve_graph(metadata)
    except (KeyError, TypeError) as error:
        return fail(f"malformed cargo metadata graph: {error!r}")
    for name, (version, features, checksum) in REVIEWED.items():
        matched = [
            package
            for package in packages
            if package["name"] == name
        ]
        if len(matched) != 1:
            return fail(
                f"expected exactly one resolved {name} {version}, found {len(matched)}"
            )
        package = matched[0]
        if package.get("version") != version:
            return fail(
                f"expected reviewed {name} {version}, found {package.get('version')!r}"
            )
        if package.get("source") != SOURCE:
            return fail(
                f"{name} {version} source not reviewable: {package.get('source')!r}"
            )
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
            entry
            for entry in lock_entries.get(name, [])
            if entry.get("version") == version
        ]
        if len(lock_matches) != 1:
            return fail(
                f"Cargo.lock missing reviewed entry for {name} {version}"
            )
        if lock_matches[0].get("checksum") != checksum:
            return fail(f"{name} {version} checksum drift in Cargo.lock")
        if lock_matches[0].get("source") != SOURCE:
            return fail(f"{name} {version} source drift in Cargo.lock")

    print(
        "argon2 audit scope OK: "
        + ", ".join(
            f"{name} {version}{'(' + ', '.join(sorted(features)) + ')' if features else ''}"
            for name, (version, features, _) in REVIEWED.items()
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
