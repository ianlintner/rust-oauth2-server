"""Regression tests for the CI docker publishing guard.

Ordinary pushes to main (incl. squash merges) and PRs must never publish
images; only tag pushes may. Also statically checks ci.yml wiring: the
`docker` job (runs on main) is build-only with a read-only token, and only the
tag-gated `docker-publish` job logs in to registries / has packages:write.
"""

import pathlib
import re
import subprocess
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
GUARD = ROOT / ".github" / "scripts" / "docker_publish_mode.sh"
CI = ROOT / ".github" / "workflows" / "ci.yml"
WORKFLOWS = ROOT / ".github" / "workflows"


def mode(event, ref):
    return subprocess.run(
        ["bash", str(GUARD), event, ref],
        check=True,
        capture_output=True,
        text=True,
        env={"PATH": "/usr/bin:/bin"},
    ).stdout.strip()


def job(name, next_name):
    text = CI.read_text()
    m = re.search(rf"^  {name}:\n(.*?)^  {next_name}:\n", text, re.S | re.M)
    assert m, f"{name} job not found in ci.yml"
    return m.group(1)


def job_if(body):
    m = re.search(r"^    if: (.*)$", body, re.M)
    assert m, "job has no if:"
    return m.group(1)


class PublishModeTests(unittest.TestCase):
    def test_main_push_does_not_publish(self):
        self.assertEqual(mode("push", "refs/heads/main"), "publish=false")

    def test_develop_push_does_not_publish(self):
        self.assertEqual(mode("push", "refs/heads/develop"), "publish=false")

    def test_pull_request_does_not_publish(self):
        self.assertEqual(mode("pull_request", "refs/pull/432/merge"), "publish=false")

    def test_workflow_dispatch_does_not_publish(self):
        self.assertEqual(mode("workflow_dispatch", "refs/heads/main"), "publish=false")

    def test_tag_push_publishes(self):
        self.assertEqual(mode("push", "refs/tags/v1.2.3"), "publish=true")
        self.assertEqual(mode("push", "refs/tags/1.2.3-rc.1"), "publish=true")

    def test_branch_named_like_tag_does_not_publish(self):
        self.assertEqual(mode("push", "refs/heads/refs/tags/x"), "publish=false")

    def test_tag_ref_on_non_push_event_does_not_publish(self):
        self.assertEqual(mode("pull_request", "refs/tags/v1.2.3"), "publish=false")


class DockerBuildJobTests(unittest.TestCase):
    def setUp(self):
        self.body = job("docker", "docker-publish")

    def test_runs_on_default_branch_not_tags(self):
        cond = job_if(self.body)
        self.assertIn("default_branch", cond)
        self.assertNotIn("refs/tags/", cond)

    def test_no_registry_access(self):
        self.assertNotRegex(self.body, r"push:\s*true")
        self.assertNotIn("docker/login-action", self.body)
        self.assertNotIn("packages: write", self.body)
        self.assertNotIn("DOCKER_TOKEN", self.body)
        self.assertNotIn("ghcr.io", self.body)

    def test_builds_locally_without_push(self):
        self.assertIn("push: false", self.body)
        self.assertIn("load: true", self.body)

    def test_asserts_guard_says_no_publish(self):
        self.assertIn("docker_publish_mode.sh", self.body)
        self.assertIn('"publish=false"', self.body)


class DockerPublishJobTests(unittest.TestCase):
    def setUp(self):
        self.body = job("docker-publish", "docs")

    def test_only_tag_pushes(self):
        cond = job_if(self.body)
        self.assertEqual(
            cond, "github.event_name == 'push' && startsWith(github.ref, 'refs/tags/')"
        )

    def test_asserts_guard_says_publish(self):
        self.assertIn("docker_publish_mode.sh", self.body)
        self.assertIn('"publish=true"', self.body)

    def test_keeps_prerequisite_checks(self):
        for dep in ("checks", "build-binaries", "security", "db-tests", "e2e-kind"):
            self.assertRegex(self.body, rf"needs:.*\b{dep}\b")

    def test_no_branch_image_tags(self):
        self.assertNotIn("type=sha", self.body)
        self.assertNotIn("value=latest", self.body)


class OtherWorkflowTests(unittest.TestCase):
    def test_other_workflows_only_publish_from_release_flow(self):
        for wf in WORKFLOWS.glob("*.yml"):
            if wf.name == "ci.yml":
                continue
            text = wf.read_text()
            if re.search(r"push:\s*true", text):
                self.assertEqual(wf.name, "release.yml", f"{wf.name} publishes images")
                self.assertRegex(text, r"on:\s*\n\s*workflow_dispatch:")

    def test_gate_does_not_depend_on_publish_jobs(self):
        text = CI.read_text()
        m = re.search(r"^  gate:\n(.*)", text, re.S | re.M)
        self.assertNotIn("docker-publish", m.group(1))


if __name__ == "__main__":
    unittest.main()
