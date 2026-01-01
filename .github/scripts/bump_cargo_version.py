#!/usr/bin/env python3
"""Bump the root crate version in Cargo.toml.

Why this exists:
- We want a simple, deterministic way for CI to sync Cargo.toml's [package].version
  to a release version, without depending on extra Rust tools.

This script updates only the *top-level* [package] section in the provided Cargo.toml.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path


PACKAGE_HEADER_RE = re.compile(r"^\[package\]\s*$")
SECTION_HEADER_RE = re.compile(r"^\[[^\]]+\]\s*$")
VERSION_LINE_RE = re.compile(r"^(?P<indent>\s*)version\s*=\s*\"(?P<ver>[^\"]+)\"\s*$")


def bump_version(cargo_toml_path: Path, new_version: str) -> bool:
    text = cargo_toml_path.read_text(encoding="utf-8").splitlines(keepends=True)

    in_package = False
    changed = False

    for i, line in enumerate(text):
        if PACKAGE_HEADER_RE.match(line.strip()):
            in_package = True
            continue

        if in_package and SECTION_HEADER_RE.match(line.strip()):
            # End of [package] section
            break

        if in_package:
            m = VERSION_LINE_RE.match(line)
            if m:
                indent = m.group("indent")
                old_version = m.group("ver")
                if old_version == new_version:
                    return False
                text[i] = f'{indent}version = "{new_version}"\n'
                changed = True
                break

    if not changed:
        raise RuntimeError(
            f"Could not find [package].version in {cargo_toml_path}. "
            "Expected a line like: version = \"x.y.z\" within the [package] section."
        )

    cargo_toml_path.write_text("".join(text), encoding="utf-8")
    return True


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--file", default="Cargo.toml", help="Path to Cargo.toml")
    parser.add_argument("--version", required=True, help="New version (e.g., 0.1.2)")
    args = parser.parse_args()

    cargo_path = Path(args.file)
    if not cargo_path.exists():
        print(f"error: file not found: {cargo_path}", file=sys.stderr)
        return 2

    # Basic sanity: semver-ish (allow prerelease/build metadata)
    # Examples: 1.2.3, 1.2.3-rc.1, 1.2.3+build.7, 1.2.3-rc.1+build.7
    if not re.match(r"^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$", args.version):
        print(f"error: invalid version format: {args.version}", file=sys.stderr)
        return 2

    try:
        changed = bump_version(cargo_path, args.version)
    except Exception as e:
        print(f"error: {e}", file=sys.stderr)
        return 1

    if changed:
        print(f"Updated {cargo_path} to version {args.version}")
    else:
        print(f"No changes needed (already {args.version})")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
