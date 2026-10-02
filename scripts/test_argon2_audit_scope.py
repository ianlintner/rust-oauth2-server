"""Regression tests for the repository-local Argon2 stack audit scope gate.

Covers owner-authorized exact-feature/version/source/checksum pinning for the
argon2 0.6.0, blake2 0.11.0, password-hash 0.6.1 and phc 0.6.1 reviewed stack.
"""

import json
import pathlib
import subprocess
import sys
import tempfile
import unittest

SCRIPT = pathlib.Path(__file__).with_name("check_argon2_audit_scope.py")

REVIEWED = {
    "argon2": ("0.6.0", ["alloc", "default", "getrandom", "password-hash"]),
    "blake2": ("0.11.0", []),
    "password-hash": ("0.6.1", ["alloc", "getrandom", "phc"]),
    "phc": ("0.6.1", ["alloc", "getrandom"]),
}

SOURCE = "registry+https://github.com/rust-lang/crates.io-index"
CHECKSUMS = {
    "argon2": "134c52ddac6d63c576bef8168db10c83c49c26444ecbc68060fef078925a901c",
    "blake2": "5b5d4d889834ee8ecfc0f8426ad30faf7cdcb10f741a8e6d7224d95325479f6f",
    "password-hash": "aab41826031698d6ffcd9cff78ef56ef998e39dc7e5067cdfebe373842d4723b",
    "phc": "44dc769b75f93afdddd8c7fa12d685292ddeff1e66f7f0f3a234cf1818afe892",
}


def build_fixture(
    overrides=None,
    drop_packages=(),
    drop_nodes=(),
    drop_lock_entries=(),
):
    """Build a synthetic cargo metadata snapshot + matching Cargo.lock text."""
    overrides = overrides or {}
    packages = []
    nodes = []
    lock_sections = []
    for name, (version, features) in REVIEWED.items():
        if name in drop_packages:
            continue
        crate = overrides.get(name, {})
        identifier = f"{name} {version}#{name}@0.6.0"
        package_version = crate.get("version", version)
        package_source = crate.get("source", SOURCE)
        lock_source = crate.get("lock_source", SOURCE)
        packages.append(
            {
                "name": name,
                "version": package_version,
                "source": package_source,
                "id": identifier,
            }
        )
        if name not in drop_nodes:
            nodes.append({"id": identifier, "features": crate.get("features", features)})
        if name not in drop_lock_entries:
            lock_checksum = crate.get("checksum", CHECKSUMS[name])
            lock_sections.append(
                '[[package]]\n'
                f'name = "{name}"\n'
                f'version = "{package_version}"\n'
                f'source = "{lock_source}"\n'
                f'checksum = "{lock_checksum}"\n'
            )
    metadata = {"packages": packages, "resolve": {"nodes": nodes}}
    return metadata, "\n".join(lock_sections)


class ScopeTests(unittest.TestCase):
    def run_gate(
        self,
        metadata,
        lockfile,
        extra_args=(),
    ):
        self.assertTrue(SCRIPT.exists(), "missing argon2 audit scope gate")
        with tempfile.TemporaryDirectory(dir=pathlib.Path(__file__).parent) as directory:
            directory = pathlib.Path(directory)
            metadata_path = directory / "metadata.json"
            lock_path = directory / "Cargo.lock"
            if isinstance(metadata, str):
                metadata_path.write_text(metadata)
            else:
                metadata_path.write_text(json.dumps(metadata))
            if lockfile is not None:
                lock_path.write_text(lockfile)
            args = [
                sys.executable,
                str(SCRIPT),
                "--metadata",
                str(metadata_path),
            ]
            if lockfile is not None:
                args += ["--lockfile", str(lock_path)]
            return subprocess.run(
                [*args, *extra_args],
                text=True,
                capture_output=True,
                check=False,
            )

    def test_reviewed_stack_is_accepted(self):
        result = self.run_gate(*build_fixture())
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_missing_lockfile_is_rejected(self):
        metadata, _ = build_fixture()
        missing = pathlib.Path(__file__).with_name("does-not-exist-Cargo.lock")
        result = self.run_gate(metadata, None, extra_args=["--lockfile", str(missing)])
        self.assertNotEqual(result.returncode, 0, result.stdout)


    def test_feature_expansion_is_rejected(self):
        metadata, lock = build_fixture(
            overrides={"argon2": {"features": ["alloc", "default", "getrandom", "password-hash", "parallel"]}}
        )
        result = self.run_gate(metadata, lock)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("parallel", result.stderr)

    def test_missing_reviewed_feature_is_rejected(self):
        metadata, lock = build_fixture(
            overrides={"phc": {"features": ["alloc"]}}
        )
        result = self.run_gate(metadata, lock)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("getrandom", result.stderr)


    def test_version_drift_is_rejected(self):
        metadata, lock = build_fixture(
            overrides={"argon2": {"version": "0.6.1"}}
        )
        result = self.run_gate(metadata, lock)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("argon2 0.6.0", result.stderr)


    def test_source_drift_is_rejected(self):
        metadata, lock = build_fixture(
            overrides={"blake2": {"source": "git+https://github.com/example/blake2"}}
        )
        result = self.run_gate(metadata, lock)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("source", result.stderr)

    def test_lockfile_source_drift_is_rejected(self):
        metadata, lock = build_fixture(
            overrides={"blake2": {"lock_source": "git+https://github.com/example/blake2"}}
        )
        result = self.run_gate(metadata, lock)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("source drift in Cargo.lock", result.stderr)

    def test_missing_resolve_node_is_rejected(self):
        metadata, lock = build_fixture(drop_nodes=("phc",))
        result = self.run_gate(metadata, lock)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("resolve.nodes", result.stderr)

    def test_missing_package_is_rejected(self):
        metadata, lock = build_fixture(drop_packages=("blake2",))
        result = self.run_gate(metadata, lock)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("blake2", result.stderr)

    def test_missing_lock_entry_is_rejected(self):
        metadata, lock = build_fixture(drop_lock_entries=("password-hash",))
        result = self.run_gate(metadata, lock)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("password-hash", result.stderr)

    def test_checksum_drift_is_rejected(self):
        metadata, lock = build_fixture(
            overrides={"argon2": {"checksum": "0" * 64}}
        )
        result = self.run_gate(metadata, lock)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("checksum", result.stderr)

    def test_duplicate_reviewed_version_is_rejected(self):
        metadata, lock = build_fixture()
        duplicate = dict(metadata["packages"][0])
        duplicate["id"] = duplicate["id"] + "-dup"
        metadata["packages"].append(duplicate)
        metadata["resolve"]["nodes"].append(
            {"id": duplicate["id"], "features": ["alloc", "default", "getrandom", "password-hash"]}
        )
        result = self.run_gate(metadata, lock)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("exactly one", result.stderr)

    def test_malformed_metadata_json_is_rejected(self):
        result = self.run_gate("{not json", "")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("argon2 audit scope:", result.stderr)

    def test_metadata_missing_resolve_is_rejected(self):
        result = self.run_gate({"packages": []}, "")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("argon2 audit scope:", result.stderr)

    def test_malformed_lockfile_toml_is_rejected(self):
        metadata, _ = build_fixture()
        result = self.run_gate(metadata, "this = = broken")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("argon2 audit scope:", result.stderr)


if __name__ == "__main__":
    unittest.main()
