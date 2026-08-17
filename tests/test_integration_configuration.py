from __future__ import annotations

import json
from pathlib import Path
import ssl
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from promptforge.platform.integration_backends import (
    AirflowHttpBackend,
    IntegrationBackendBundle,
    IntegrationBackendConfig,
    JiraHttpBackend,
    StdlibHttpsTransport,
)
from promptforge.__main__ import _exact_options
from promptforge.platform.integrations import JiraMcpAdapter
from promptforge.platform.integrations import AirflowMcpAdapter
from promptforge.platform.mcp_hub import McpAdapterCall


def environment() -> dict[str, str]:
    return {
        "PF_INTEGRATION_CONFLUENCE_URL": "https://knowledge.corp.example/wiki",
        "PF_INTEGRATION_CONFLUENCE_USERNAME": "service-reader",
        "PF_INTEGRATION_CONFLUENCE_TOKEN": "confluence-test-token",
        "PF_INTEGRATION_CONFLUENCE_AUTH_MODE": "basic",
        "PF_INTEGRATION_CONFLUENCE_SCOPE_MODE": "exact",
        "PF_INTEGRATION_CONFLUENCE_ALLOWED_SPACES": "DATA,PLATFORM",
        "PF_INTEGRATION_JIRA_URL": "https://issues.corp.example",
        "PF_INTEGRATION_JIRA_USERNAME": "service-reader",
        "PF_INTEGRATION_JIRA_TOKEN": "jira-test-token",
        "PF_INTEGRATION_JIRA_AUTH_MODE": "basic",
        "PF_INTEGRATION_JIRA_SCOPE_MODE": "account-visible-read-only",
        "PF_INTEGRATION_AIRFLOW_URL": "https://scheduler.corp.example",
        "PF_INTEGRATION_AIRFLOW_USERNAME": "service-reader",
        "PF_INTEGRATION_AIRFLOW_TOKEN": "airflow-test-token",
        "PF_INTEGRATION_AIRFLOW_AUTH_MODE": "basic",
        "PF_INTEGRATION_AIRFLOW_SCOPE_MODE": "account-visible-read-only",
        "PF_INTEGRATION_TIMEOUT_SECONDS": "10",
        "PF_INTEGRATION_MAX_RESPONSE_BYTES": "1000000",
    }


class IntegrationConfigurationTest(unittest.TestCase):
    def test_explicit_corporate_ca_keeps_peer_and_hostname_verification(self) -> None:
        strict = getattr(ssl, "VERIFY_X509_STRICT", 0)
        context = MagicMock()
        context.verify_flags = strict | 0x4000
        context.verify_mode = ssl.CERT_REQUIRED
        context.check_hostname = True

        with patch("promptforge.platform.integration_backends.ssl.create_default_context", return_value=context):
            transport = StdlibHttpsTransport("knowledge.corp.example", "/rest/api", ca_data="PEM")

        self.assertIs(context, transport.ssl_context)
        self.assertEqual(ssl.CERT_REQUIRED, context.verify_mode)
        self.assertTrue(context.check_hostname)
        if strict:
            self.assertFalse(context.verify_flags & strict)
        self.assertTrue(context.verify_flags & 0x4000)

    def test_readiness_receipt_is_closed_metadata_only_and_stable(self) -> None:
        config = IntegrationBackendConfig.from_env(environment())
        first = config.readiness_receipt()
        second = IntegrationBackendConfig.from_env(environment()).readiness_receipt()

        self.assertEqual(first, second)
        self.assertEqual("ready", first["status"])
        self.assertEqual("https-pinned-read-only", first["transport"])
        self.assertEqual(["confluence", "jira", "airflow"], [item["id"] for item in first["services"]])
        self.assertEqual(
            ["exact", "account-visible-read-only", "account-visible-read-only"],
            [item["scope_mode"] for item in first["services"]],
        )
        self.assertRegex(first["config_digest"], r"^sha256:[0-9a-f]{64}$")
        serialized = json.dumps(first)
        for secret in ("service-reader", "confluence-test-token", "jira-test-token", "airflow-test-token"):
            self.assertNotIn(secret, serialized)
        self.assertNotIn("corp.example", serialized)

    def test_bundle_contains_only_real_http_backends(self) -> None:
        bundle = IntegrationBackendBundle.from_env(environment())
        self.assertEqual("ConfluenceHttpBackend", type(bundle.confluence_backend).__name__)
        self.assertEqual("JiraHttpBackend", type(bundle.jira_backend).__name__)
        self.assertEqual("AirflowHttpBackend", type(bundle.airflow_backend).__name__)

    def test_unknown_or_oversized_credentials_fail_closed(self) -> None:
        unknown = {**environment(), "PF_INTEGRATION_SYNTHETIC_FALLBACK": "true"}
        with self.assertRaises(ValueError):
            IntegrationBackendConfig.from_env(unknown)
        oversized = {**environment(), "PF_INTEGRATION_JIRA_TOKEN": "x" * 8193}
        with self.assertRaises(ValueError):
            IntegrationBackendConfig.from_env(oversized)

    def test_noncanonical_endpoint_fails_closed(self) -> None:
        invalid = {**environment(), "PF_INTEGRATION_AIRFLOW_URL": "https://scheduler.corp.example./"}
        with self.assertRaises(ValueError):
            IntegrationBackendConfig.from_env(invalid)

    def test_account_visible_scope_is_read_only_and_restricted_to_jira_and_airflow(self) -> None:
        config = IntegrationBackendConfig.from_env(environment())
        self.assertTrue(config.jira.allows("ANY"))
        self.assertTrue(config.airflow.allows("any_safe_dag"))
        self.assertFalse(config.jira.allows("unsafe value"))

        invalid = {
            **environment(),
            "PF_INTEGRATION_CONFLUENCE_SCOPE_MODE": "account-visible-read-only",
            "PF_INTEGRATION_CONFLUENCE_ALLOWED_SPACES": "",
        }
        with self.assertRaises(ValueError):
            IntegrationBackendConfig.from_env(invalid)

    def test_session_cookie_is_loaded_only_from_owner_private_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            cookie_file = Path(directory).resolve() / "session.cookie"
            cookie_file.write_text("session=opaque-test-value", encoding="utf-8")
            cookie_file.chmod(0o600)
            values = {
                **environment(),
                "PF_INTEGRATION_JIRA_AUTH_MODE": "session-cookie-file",
                "PF_INTEGRATION_JIRA_USERNAME": "",
                "PF_INTEGRATION_JIRA_TOKEN": "",
                "PF_INTEGRATION_JIRA_SESSION_FILE": str(cookie_file),
            }
            config = IntegrationBackendConfig.from_env(values).jira
            self.assertEqual({"Accept": "application/json", "Cookie": "session=opaque-test-value"},
                             config.authorization_headers())
            self.assertNotIn("opaque-test-value", repr(config))

            cookie_file.chmod(0o644)
            with self.assertRaises(ValueError):
                IntegrationBackendConfig.from_env(values)

            cookie_file.chmod(0o600)
            cookie_file.write_text("session=opaque-test-value\n", encoding="utf-8")
            with self.assertRaises(ValueError):
                IntegrationBackendConfig.from_env(values)

            cookie_file.write_text("session=opaque-test-value", encoding="utf-8")
            link = Path(directory) / "session-link.cookie"
            link.symlink_to(cookie_file)
            with self.assertRaises(ValueError):
                IntegrationBackendConfig.from_env({**values, "PF_INTEGRATION_JIRA_SESSION_FILE": str(link)})

    def test_auth_modes_are_mutually_exclusive_and_unknown_values_fail_closed(self) -> None:
        conflicting = {**environment(), "PF_INTEGRATION_JIRA_SESSION_FILE": "/private/tmp/session.cookie"}
        with self.assertRaises(ValueError):
            IntegrationBackendConfig.from_env(conflicting)
        unknown = {**environment(), "PF_INTEGRATION_JIRA_AUTH_MODE": "browser"}
        with self.assertRaises(ValueError):
            IntegrationBackendConfig.from_env(unknown)

    def test_jira_bearer_token_is_closed_and_never_reused_by_other_services(self) -> None:
        values = {
            **environment(),
            "PF_INTEGRATION_JIRA_AUTH_MODE": "bearer-token",
            "PF_INTEGRATION_JIRA_USERNAME": "",
        }
        config = IntegrationBackendConfig.from_env(values).jira
        self.assertEqual(
            {"Accept": "application/json", "Authorization": "Bearer jira-test-token"},
            config.authorization_headers(),
        )
        self.assertNotIn("jira-test-token", repr(config))

        for service in ("CONFLUENCE", "AIRFLOW"):
            invalid = {
                **environment(),
                f"PF_INTEGRATION_{service}_AUTH_MODE": "bearer-token",
                f"PF_INTEGRATION_{service}_USERNAME": "",
            }
            with self.assertRaises(ValueError):
                IntegrationBackendConfig.from_env(invalid)

    def test_account_visible_backends_still_validate_resource_identifiers(self) -> None:
        class RecordingTransport:
            def __init__(self, response: dict[str, object]) -> None:
                self.response = response

            def get_json(self, *_args: object) -> dict[str, object]:
                return self.response

        config = IntegrationBackendConfig.from_env(environment())
        jira = JiraHttpBackend(config.jira, RecordingTransport({
            "key": "DATA-1",
            "fields": {"summary": "safe", "status": {"name": "Open"},
                       "issuetype": {"name": "Task"}, "assignee": None, "description": ""},
        }))
        self.assertEqual("DATA-1", jira.get_issue("DATA-1")["key"])
        with self.assertRaises(ValueError):
            jira.get_issue("../DATA-1")

        airflow = AirflowHttpBackend(config.airflow, RecordingTransport({"dag_runs": []}))
        self.assertEqual({"dag_runs": []}, airflow.list_dag_runs("calc_daily", 1))
        with self.assertRaises(PermissionError):
            airflow.list_dag_runs("unsafe dag", 1)

    def test_jira_response_identity_must_match_the_exact_request(self) -> None:
        class StaticTransport:
            def get_json(self, *_args: object) -> dict[str, object]:
                return {
                    "key": "OPS-1",
                    "fields": {"summary": "wrong", "status": {"name": "Open"},
                               "issuetype": {"name": "Task"}, "assignee": None, "description": ""},
                }

        config = IntegrationBackendConfig.from_env(environment()).jira
        backend = JiraHttpBackend(config, StaticTransport())
        with self.assertRaises(PermissionError):
            backend.get_issue("DATA-1")

        class MismatchedBackend:
            def search_issues(self, project_key: str, query: str, limit: int) -> dict[str, object]:
                return {"issues": [{"key": "OPS-1", "summary": query, "status": "Open"}]}

            def get_issue(self, issue_key: str) -> dict[str, object]:
                return {"key": "OPS-1", "summary": "wrong", "status": "Open"}

        adapter = JiraMcpAdapter(MismatchedBackend(), config.base_url, frozenset(), account_visible=True)
        with self.assertRaises(PermissionError):
            adapter.invoke(McpAdapterCall(
                "jira.search_issues", "1.0.0", "read",
                {"project_key": "DATA", "query": "readiness", "limit": 1}, "trace-1",
            ))
        with self.assertRaises(PermissionError):
            adapter.invoke(McpAdapterCall(
                "jira.get_issue", "1.0.0", "read", {"issue_key": "DATA-1"}, "trace-2",
            ))

    def test_smoke_resource_is_explicit_for_account_visible_scope(self) -> None:
        config = IntegrationBackendConfig.from_env(environment())
        self.assertEqual("DATA", config.confluence.smoke_resource(None))
        self.assertEqual("DATA", config.jira.smoke_resource("DATA"))
        self.assertEqual("calc_daily", config.airflow.smoke_resource("calc_daily"))
        with self.assertRaises(ValueError):
            config.jira.smoke_resource(None)
        with self.assertRaises(PermissionError):
            config.airflow.smoke_resource("unsafe dag")

    def test_smoke_cli_options_are_closed_and_reject_duplicates(self) -> None:
        allowed = frozenset({"--state-root", "--jira-project", "--airflow-dag"})
        self.assertEqual(
            {"--state-root": "/private/state", "--jira-project": "DATA", "--airflow-dag": "calc_daily"},
            _exact_options([
                "--state-root", "/private/state", "--jira-project", "DATA", "--airflow-dag", "calc_daily",
            ], allowed),
        )
        for arguments in (
            ["--state-root"],
            ["--unknown", "value"],
            ["--state-root", "/one", "--state-root", "/two"],
        ):
            with self.assertRaises(ValueError):
                _exact_options(arguments, allowed)

    def test_airflow_adapter_accepts_standard_timezone_run_id_only(self) -> None:
        class Backend:
            def list_dag_runs(self, dag_id: str, limit: int) -> dict[str, object]:
                return {"dag_runs": [{
                    "dag_id": dag_id,
                    "run_id": "scheduled__2026-08-13T10:00:00+00:00",
                    "state": "success",
                }]}

        adapter = AirflowMcpAdapter(Backend(), frozenset(), account_visible=True)
        response = adapter.invoke(McpAdapterCall(
            "airflow.list_dag_runs", "1.0.0", "read",
            {"dag_id": "source_12_mosgortr_data_kpi_dashboard", "limit": 1}, "trace-airflow",
        ))
        self.assertEqual(1, len(response.data["dag_runs"]))

        unsafe = "scheduled__2026-08-13T10:00:00+00:00/../escape"

        class UnsafeBackend:
            def list_dag_runs(self, dag_id: str, limit: int) -> dict[str, object]:
                return {"dag_runs": [{"dag_id": dag_id, "run_id": unsafe, "state": "success"}]}

        with self.assertRaises(ValueError):
            AirflowMcpAdapter(UnsafeBackend(), frozenset(), account_visible=True).invoke(McpAdapterCall(
                "airflow.list_dag_runs", "1.0.0", "read",
                {"dag_id": "source_12_mosgortr_data_kpi_dashboard", "limit": 1}, "trace-unsafe",
            ))


if __name__ == "__main__":
    unittest.main()
