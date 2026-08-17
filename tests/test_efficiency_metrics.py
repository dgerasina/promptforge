from __future__ import annotations

import json
from pathlib import Path
import secrets
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from promptforge import __main__ as cli
from promptforge.__main__ import _changed_review
from promptforge.platform.efficiency_metrics import EfficiencyMetricEvent, EfficiencyMetricsStore
from promptforge.platform.pilot import build_offline_pilot
from promptforge.platform.mcp_hub import ApprovalStore, McpRequest
from promptforge.platform.contracts import Principal
from promptforge.platform.privacy import PrivacyContext


PRODUCT = Path(__file__).resolve().parents[1]


class EfficiencyMetricsTest(unittest.TestCase):
    def test_aggregates_only_requested_anonymized_metrics(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory).resolve()
            store = EfficiencyMetricsStore(state / "efficiency-metrics.sqlite3", b"m" * 32)
            store.append(EfficiencyMetricEvent(
                input_tokens=120, output_tokens=30, candidate_input_tokens=160, selected_input_tokens=120,
                model_calls=2, latency_ms=240, agents_invoked=3, skills_invoked=4,
                cache_hits=20, cache_lookups=100, dedup_hits=2, dedup_lookups=10,
                privacy_redactions=5, policy_denials=1, review_findings=6, manual_approvals=2,
                runs=1, first_run_successes=1,
            ))
            summary = store.summary()

        self.assertEqual("ok", summary["status"])
        self.assertEqual(120, summary["input_tokens"])
        self.assertEqual(30, summary["output_tokens"])
        self.assertEqual(0.25, summary["token_saving_ratio"])
        self.assertEqual(2, summary["model_calls"])
        self.assertEqual(120.0, summary["latency_ms"])
        self.assertEqual(3, summary["agents_invoked"])
        self.assertEqual(4, summary["skills_invoked"])
        self.assertEqual(0.2, summary["cache_hit_rate"])
        self.assertEqual(0.2, summary["dedup_hit_rate"])
        self.assertEqual(5, summary["privacy_redactions"])
        self.assertEqual(1, summary["policy_denials"])
        self.assertEqual(6, summary["review_findings"])
        self.assertEqual(2, summary["manual_approvals"])
        self.assertEqual(1.0, summary["first_run_success_rate"])
        encoded = json.dumps(summary, sort_keys=True).lower()
        for forbidden in ("prompt", "response", "diff", "path", "credential", "principal", "trace"):
            self.assertNotIn(forbidden, encoded)

    def test_restart_verification_and_tamper_detection_are_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path, key = Path(directory).resolve() / "efficiency-metrics.sqlite3", b"v" * 32
            store = EfficiencyMetricsStore(path, key)
            store.append(EfficiencyMetricEvent(model_calls=1, runs=1))
            self.assertTrue(EfficiencyMetricsStore(path, key).verify().valid)
            connection = sqlite3.connect(path)
            connection.execute("UPDATE efficiency_metrics SET model_calls=9 WHERE sequence=1")
            connection.commit()
            connection.close()
            self.assertFalse(store.verify().valid)
            with self.assertRaises(RuntimeError):
                store.summary()

    def test_pilot_collects_metrics_automatically_without_raw_content(self) -> None:
        environment = {
            "PF_EMBEDDED_AUTH_KEY_HEX": secrets.token_bytes(32).hex(),
            "PF_LOCAL_AUDIT_KEY_HEX": secrets.token_bytes(32).hex(),
        }
        with tempfile.TemporaryDirectory() as directory:
            runner = build_offline_pilot(PRODUCT, Path(directory).resolve(), environment)
            runner.run()
            summary = runner.runtime.metrics.summary()

        self.assertEqual(1, summary["model_calls"])
        self.assertEqual(1, summary["agents_invoked"])
        self.assertEqual(1, summary["privacy_redactions"])
        self.assertEqual(1, summary["review_findings"])
        self.assertEqual(0, summary["manual_approvals"])
        self.assertEqual(0.0, summary["first_run_success_rate"])
        self.assertGreater(summary["input_tokens"], 0)
        self.assertGreater(summary["output_tokens"], 0)

    def test_metrics_summary_cli_returns_closed_anonymized_schema(self) -> None:
        environment = {
            "PF_EMBEDDED_AUTH_KEY_HEX": secrets.token_bytes(32).hex(),
            "PF_LOCAL_AUDIT_KEY_HEX": secrets.token_bytes(32).hex(),
        }
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory).resolve()
            build_offline_pilot(PRODUCT, state, environment).run()
            with patch.dict(cli.os.environ, environment, clear=False), \
                    patch.object(cli.sys, "argv", ["promptforge", "metrics-summary", "--state-root", str(state)]), \
                    patch("builtins.print") as output:
                self.assertEqual(0, cli.main())
        payload = json.loads(output.call_args.args[0])
        self.assertEqual("ok", payload["status"])
        schema = json.loads((
            PRODUCT / "schemas" / "v1" / "efficiency-metrics-summary.json"
        ).read_text(encoding="utf-8"))
        self.assertFalse(schema["additionalProperties"])
        self.assertEqual(set(schema["properties"]), set(payload))
        serialized = json.dumps(payload, sort_keys=True).lower()
        for forbidden in ("prompt", "response", "diff", "path", "credential", "approval_id", "trace"):
            self.assertNotIn(forbidden, serialized)

    def test_mcp_denial_is_collected_automatically(self) -> None:
        environment = {
            "PF_EMBEDDED_AUTH_KEY_HEX": secrets.token_bytes(32).hex(),
            "PF_LOCAL_AUDIT_KEY_HEX": secrets.token_bytes(32).hex(),
        }
        with tempfile.TemporaryDirectory() as directory:
            runner = build_offline_pilot(PRODUCT, Path(directory).resolve(), environment)
            token = runner.runtime.authenticator.issue("engineer-local")
            result = runner.runtime.mcp.execute(
                token,
                McpRequest(
                    "promptforge", "engineering-change", "missing.capability", "1.0.0", {}, "public",
                    "metrics-denial",
                ),
                PrivacyContext(
                    "promptforge", "metrics-denial", "engineer-local", "engineering-change", "local", False, 60,
                ),
            )
            summary = runner.runtime.metrics.summary()
        self.assertEqual("deny", result.status)
        self.assertEqual(1, summary["policy_denials"])

    def test_consumed_manual_approval_is_collected_once(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = EfficiencyMetricsStore(Path(directory).resolve() / "efficiency-metrics.sqlite3", b"a" * 32)
            approvals = ApprovalStore(clock=lambda: 10.0, metrics=store)
            grant = approvals.issue("digest", "engineer-local", Principal("owner-local", "owner", "promptforge"), 60)
            self.assertTrue(approvals.consume(grant, "digest", "engineer-local"))
            self.assertFalse(approvals.consume(grant, "digest", "engineer-local"))
            self.assertEqual(1, store.summary()["manual_approvals"])

    def test_persisted_changed_review_records_metrics_without_api_drift(self) -> None:
        environment = {"PF_LOCAL_AUDIT_KEY_HEX": secrets.token_bytes(32).hex()}
        with tempfile.TemporaryDirectory() as directory, patch.dict(cli.os.environ, environment, clear=False):
            state = Path(directory).resolve()
            target = PRODUCT / ".gitignore"
            original = target.read_text(encoding="utf-8")
            try:
                target.write_text(original + "\n# test review change\n", encoding="utf-8")
                result = _changed_review(
                    ["--path", ".gitignore", "--state-root", str(state)],
                    None, PRODUCT,
                )
            finally:
                target.write_text(original, encoding="utf-8")
            key = cli.hmac.new(
                bytes.fromhex(environment["PF_LOCAL_AUDIT_KEY_HEX"]),
                b"promptforge-efficiency-metrics-v1", cli.hashlib.sha256,
            ).digest()
            summary = EfficiencyMetricsStore(state / "efficiency-metrics.sqlite3", key).summary()
        self.assertEqual("ok", result["status"])
        self.assertEqual(1, summary["samples"])
        self.assertEqual(1, summary["agents_invoked"])


if __name__ == "__main__":
    unittest.main()
