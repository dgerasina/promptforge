from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from promptforge.platform.git_identity import GitIdentityClaim
from promptforge.platform.workspace import WorkspaceLifecycle


PRODUCT = Path(__file__).resolve().parents[1]
REPOSITORY = PRODUCT.parent


class WorkspaceBootstrapTest(unittest.TestCase):
    def test_setup_prepares_identity_routing_skills_index_and_local_hub(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory).resolve() / "runtime"
            lifecycle = WorkspaceLifecycle(PRODUCT, REPOSITORY, state)
            payload = lifecycle.setup(refresh_index=False)
            manifest = json.loads((state / "workspace-manifest.json").read_text())

        self.assertEqual("ready", payload["status"])
        self.assertEqual("recognized", payload["identity_status"])
        self.assertEqual("owner-local", payload["principal_id"])
        self.assertFalse(payload["identity_privileged"])
        self.assertEqual("registry_ready", payload["hub_status"])
        self.assertEqual(3, payload["integrations"])
        self.assertGreater(payload["capabilities"], 0)
        self.assertRegex(payload["readiness_digest"], r"^sha256:[0-9a-f]{64}$")
        self.assertEqual(payload["readiness_digest"], manifest["readiness_digest"])
        self.assertNotIn("email", json.dumps(payload))

    def test_doctor_returns_named_bootstrap_checks(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory).resolve() / "runtime"
            lifecycle = WorkspaceLifecycle(PRODUCT, REPOSITORY, state)
            lifecycle.setup(refresh_index=False)
            payload = lifecycle.doctor()

        self.assertEqual("ready", payload["status"])
        self.assertEqual(
            ["state", "manifest", "source", "revision", "profile", "index", "identity", "hub", "runtime"],
            payload["check_ids"],
        )
        self.assertEqual(payload["checks"], payload["passed"])

    def test_setup_rejects_unknown_git_identity(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            state = root / "runtime"
            with patch(
                "promptforge.platform.workspace.GitIdentityResolver.resolve",
                return_value=GitIdentityClaim("denied", "", ""),
            ):
                with self.assertRaises(PermissionError):
                    WorkspaceLifecycle(PRODUCT, REPOSITORY, state).setup(refresh_index=False)

    def test_custom_state_rejects_symlinked_parent(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            actual = root / "actual"
            actual.mkdir(mode=0o700)
            alias = root / "alias"
            alias.symlink_to(actual, target_is_directory=True)

            with self.assertRaises(ValueError):
                WorkspaceLifecycle.from_product(PRODUCT, alias / "runtime")

    def test_doctor_blocks_git_identity_drift(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory).resolve() / "runtime"
            lifecycle = WorkspaceLifecycle(PRODUCT, REPOSITORY, state)
            lifecycle.setup(refresh_index=False)
            with patch(
                "promptforge.platform.workspace.GitIdentityResolver.resolve",
                return_value=GitIdentityClaim("recognized", "maintainer-local", "maintainer"),
            ):
                payload = lifecycle.doctor()

        self.assertEqual("blocked", payload["status"])
        self.assertLess(payload["passed"], payload["checks"])


if __name__ == "__main__":
    unittest.main()
