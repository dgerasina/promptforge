from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from promptforge.platform.operational_acceptance import OperationalAcceptanceRunner
from promptforge.platform.workspace import WorkspaceLifecycle


PRODUCT = Path(__file__).resolve().parents[1]


class OperationalAcceptanceTest(unittest.TestCase):
    def test_all_nine_recovery_and_portability_drills_pass_in_isolation(self) -> None:
        receipt = OperationalAcceptanceRunner(PRODUCT).run()

        self.assertEqual("passed", receipt["status"])
        self.assertEqual(9, receipt["scenarios"])
        self.assertEqual(9, receipt["passed"])
        self.assertEqual(0, receipt["failed"])
        self.assertEqual([
            "kill_switch", "patch_rollback", "interrupted_recovery", "state_cleanup", "owner_key_rotation",
            "owner_key_revocation", "receipt_recovery", "master_update_restart", "clean_repository_portability",
        ], [item["id"] for item in receipt["results"]])
        self.assertTrue(all(item["status"] == "passed" for item in receipt["results"]))
        self.assertFalse(receipt["network_used"])
        self.assertFalse(receipt["real_state_touched"])
        serialized = json.dumps(receipt, sort_keys=True)
        for prohibited in ("private_key", "public_key", "state_root", "/tmp/", "/private/"):
            self.assertNotIn(prohibited, serialized)

    def test_receipt_matches_closed_repository_schema(self) -> None:
        receipt = OperationalAcceptanceRunner(PRODUCT).run()
        schema = json.loads((PRODUCT / "schemas" / "v1" / "operations-acceptance-receipt.json").read_text())

        self.assertFalse(schema["additionalProperties"])
        self.assertEqual(set(schema["required"]), set(receipt))
        self.assertEqual(set(schema["properties"]), set(receipt))

    def test_cli_returns_nonzero_for_failed_acceptance(self) -> None:
        from promptforge import __main__ as cli

        failed = {
            "schema_version": "1.0", "acceptance_version": "operations-v1", "status": "failed",
            "scenarios": 9, "passed": 8, "failed": 1, "results": [], "isolated": True,
            "real_state_touched": False, "network_used": False,
        }
        with patch.object(cli.OperationalAcceptanceRunner, "run", return_value=failed), \
                patch.object(cli.sys, "argv", ["promptforge", "operations-acceptance"]), \
                patch("builtins.print"):
            self.assertEqual(1, cli.main())

    def test_clean_repository_portability_copies_only_promptforge_product(self) -> None:
        runner = OperationalAcceptanceRunner(PRODUCT)

        with tempfile.TemporaryDirectory() as directory:
            repository, product = runner._clean_repository(Path(directory))
            self.assertTrue((repository / ".git").is_dir())
            self.assertTrue(product.is_dir())
            self.assertFalse((repository / "etl").exists())

    def test_workspace_stop_fails_if_runtime_markers_survive(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory).resolve() / "state"
            state.mkdir(mode=0o700)
            runtime = state / "workspace-runtime.json"
            runtime.write_text("{}", encoding="utf-8")
            runtime.chmod(0o600)
            lifecycle = WorkspaceLifecycle(PRODUCT, PRODUCT.parent, state)
            response = {"pid": 999_999, "instance_id": "a" * 32, "manifest_digest": "sha256:" + "1" * 64}
            with patch.object(WorkspaceLifecycle, "_query", return_value=response), \
                    patch("promptforge.platform.workspace.time.monotonic", side_effect=(0, 6)):
                with self.assertRaises(RuntimeError):
                    lifecycle.stop()


if __name__ == "__main__":
    unittest.main()
