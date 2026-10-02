"""Enforce the feature boundary of our non-importable base64 0.23.1 audit.

cargo metadata without --filter-platform covers the resolved target graph;
--all-features covers every workspace feature, matching cargo-vet's scope.
"""

import argparse
import json
import pathlib
import subprocess
import sys


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--metadata", type=pathlib.Path, help="Use an existing Cargo metadata snapshot"
    )
    args = parser.parse_args()
    if args.metadata:
        metadata = json.loads(args.metadata.read_text())
    else:
        result = subprocess.run(
            [
                "cargo",
                "metadata",
                "--locked",
                "--all-features",
                "--format-version",
                "1",
            ],
            check=True,
            text=True,
            capture_output=True,
        )
        metadata = json.loads(result.stdout)
    nodes = {node["id"]: node for node in metadata["resolve"]["nodes"]}
    found = False
    for package in metadata["packages"]:
        if package["name"] != "base64" or package["version"] != "0.23.1":
            continue
        found = True
        features = set(nodes[package["id"]]["features"])
        outside_scope = features - {"std", "alloc"}
        if "std" not in features:
            print(
                "base64 0.23.1 audit requires the reviewed std configuration",
                file=sys.stderr,
            )
            return 1
        if outside_scope:
            print(
                "base64 0.23.1 audit scope exceeded: "
                + ", ".join(sorted(outside_scope)),
                file=sys.stderr,
            )
            return 1
        print("base64 0.23.1 scalar audit scope OK: " + ", ".join(sorted(features)))
    if not found:
        print(
            "base64 0.23.1 audit scope target missing: "
            "expected at least one resolved base64 0.23.1 package",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
