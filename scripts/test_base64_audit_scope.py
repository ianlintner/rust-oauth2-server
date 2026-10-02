"""Regression tests for the repository-local base64 scalar attestation scope."""

import json
import pathlib
import subprocess
import sys
import tempfile
import unittest

SCRIPT = pathlib.Path(__file__).with_name("check_base64_audit_scope.py")


class ScopeTests(unittest.TestCase):
    def check(self, features, package_version: str | None = "0.23.1"):
        self.assertTrue(SCRIPT.exists(), "missing base64 audit scope gate")
        packages = (
            [{"name": "base64", "version": package_version, "id": "base64-id"}]
            if package_version is not None
            else []
        )
        nodes = [{"id": "base64-id", "features": features}] if packages else []
        metadata = {"packages": packages, "resolve": {"nodes": nodes}}
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "metadata.json"
            path.write_text(json.dumps(metadata))
            return subprocess.run(
                [sys.executable, str(SCRIPT), "--metadata", str(path)],
                text=True,
                capture_output=True,
                check=False,
            )

    def test_simd_feature_is_rejected(self):
        result = self.check(["std", "alloc", "simd-unsafe"])
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("simd-unsafe", result.stderr)

    def test_untested_no_std_configuration_is_rejected(self):
        result = self.check(["alloc"])
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("std", result.stderr)

    def test_reviewed_scalar_features_are_accepted(self):
        result = self.check(["std", "alloc"])
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_default_feature_alias_is_rejected(self):
        result = self.check(["std", "alloc", "default"])
        self.assertNotEqual(result.returncode, 0)

    def test_unknown_feature_is_rejected(self):
        result = self.check(["std", "alloc", "future-feature"])
        self.assertNotEqual(result.returncode, 0)

    def test_missing_exact_version_is_rejected(self):
        result = self.check(["std", "alloc"], package_version="0.23.0")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("0.23.1", result.stderr)

    def test_missing_package_is_rejected(self):
        result = self.check([], package_version=None)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("target missing", result.stderr)

    def test_version_drift_does_not_vacuously_pass(self):
        result = self.check(["std", "alloc"], package_version="0.23.2")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("0.23.1", result.stderr)
        self.assertNotIn("scalar audit scope OK", result.stdout)


if __name__ == "__main__":
    unittest.main()
