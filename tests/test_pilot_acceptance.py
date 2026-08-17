from __future__ import annotations

import json
import unittest
from pathlib import Path
from unittest.mock import patch

from promptforge.__main__ import _pilot_acceptance


class PilotAcceptanceTest(unittest.TestCase):
    def test_acceptance_combines_offline_previews_and_live_metadata_only_smoke(self) -> None:
        smoke = {
            "schema_version": "1.0", "status": "passed", "network_used": True,
            "probes": [
                {"capability": capability, "status": "ok", "reason_code": "completed"}
                for capability in ("confluence.search_pages", "jira.search_issues", "airflow.list_dag_runs")
            ],
        }
        with patch("promptforge.__main__._integration_smoke", return_value=smoke):
            receipt = _pilot_acceptance(["--state-root", "/private/promptforge-state"])

        self.assertEqual("passed", receipt["status"])
        self.assertEqual(4, receipt["representative_previews"])
        self.assertEqual(3, receipt["live_probes"])
        self.assertEqual(0, receipt["mutations_executed"])
        self.assertEqual(7, receipt["role_authorization_cases"])
        self.assertEqual(1, receipt["live_principals"])
        self.assertTrue(receipt["network_used"])
        schema = json.loads((
            Path(__file__).resolve().parents[1] / "schemas" / "v1" / "pilot-acceptance-receipt.json"
        ).read_text(encoding="utf-8"))
        self.assertFalse(schema["additionalProperties"])
        self.assertTrue(set(receipt).issubset(schema["properties"]))
        serialized = str(receipt)
        self.assertNotIn("/private/promptforge-state", serialized)
        self.assertNotIn("query", serialized)

    def test_acceptance_requires_exact_state_option_and_all_live_probes(self) -> None:
        with self.assertRaises(ValueError):
            _pilot_acceptance([])
        failed = {"status": "failed", "network_used": True, "probes": []}
        with patch("promptforge.__main__._integration_smoke", return_value=failed), self.assertRaises(RuntimeError):
            _pilot_acceptance(["--state-root", "/private/promptforge-state"])

    def test_cli_failure_receipt_is_truthful_and_schema_shaped(self) -> None:
        from promptforge import __main__ as cli

        with patch.object(cli, "_pilot_acceptance", side_effect=RuntimeError), \
                patch.object(cli.sys, "argv", ["promptforge", "pilot-acceptance"]), \
                patch("builtins.print") as output:
            self.assertEqual(1, cli.main())
        receipt = json.loads(output.call_args.args[0])
        self.assertEqual({
            "schema_version": "1.0", "status": "error", "code": "pilot_acceptance_failed",
            "network_used": True,
        }, receipt)


if __name__ == "__main__":
    unittest.main()
