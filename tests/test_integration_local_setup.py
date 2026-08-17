from __future__ import annotations

import json
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch

from promptforge.__main__ import _integration_credential_update
from promptforge.platform.integration_setup import (
    IntegrationSetupInput,
    LocalIntegrationProfile,
    ServiceSetupInput,
)


class IntegrationLocalSetupTest(unittest.TestCase):
    def setUp(self) -> None:
        self.ssl_context = patch("promptforge.platform.integration_backends.ssl.create_default_context")
        self.ssl_context.start()
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.state = self.root / "state"
        self.state.mkdir(mode=0o700)
        self.ca = self.root / "corporate-ca.crt"
        self.ca.write_text("test-public-ca", encoding="utf-8")
        self.ca.chmod(0o644)
        self.product = Path(__file__).resolve().parents[1]

    def tearDown(self) -> None:
        self.ssl_context.stop()
        self.temporary.cleanup()

    def setup_input(self) -> IntegrationSetupInput:
        return IntegrationSetupInput(
            principal_id="owner-local",
            ca_file=self.ca,
            services=(
                ServiceSetupInput(
                    "confluence", "https://knowledge.corp.example", "basic", "reader", "exact",
                    ("DT",), "DT",
                ),
                ServiceSetupInput(
                    "jira", "https://issues.corp.example", "session-cookie-file", "",
                    "account-visible-read-only", (), "DATA",
                ),
                ServiceSetupInput(
                    "airflow", "https://scheduler.corp.example", "basic", "reader",
                    "account-visible-read-only", (), "source_daily",
                ),
            ),
        )

    def test_setup_writes_private_closed_profile_and_loads_ephemeral_session(self) -> None:
        profile = LocalIntegrationProfile(self.product, self.state)
        receipt = profile.configure(
            self.setup_input(),
            {"confluence": "confluence-password", "jira": "session=opaque", "airflow": "airflow-password"},
        )
        runtime = profile.load()

        self.assertEqual("ready", receipt["status"])
        self.assertEqual("owner-local", runtime.principal_id)
        self.assertEqual("DATA", runtime.jira_project)
        self.assertEqual("source_daily", runtime.airflow_dag)
        self.assertTrue(runtime.work_session)
        self.assertEqual(str(self.ca), runtime.environment["PF_INTEGRATION_CA_FILE"])
        self.assertEqual("session-cookie-file", runtime.environment["PF_INTEGRATION_JIRA_AUTH_MODE"])
        self.assertNotIn(runtime.work_session, json.dumps(receipt))
        self.assertNotIn("corp.example", json.dumps(receipt))
        self.assertNotIn(str(self.ca), json.dumps(receipt))
        for secret in ("confluence-password", "session=opaque", "airflow-password"):
            self.assertNotIn(secret, json.dumps(receipt))
            self.assertNotIn(secret, repr(runtime))

        profile_path = self.state / "integrations" / "profile.json"
        self.assertEqual(0o700, stat.S_IMODE(profile_path.parent.stat().st_mode))
        for path in profile_path.parent.iterdir():
            self.assertEqual(0o600, stat.S_IMODE(path.stat().st_mode))

    def test_setup_rejects_symlink_state_ca_and_unsafe_secret(self) -> None:
        linked_state = self.root / "linked-state"
        linked_state.symlink_to(self.state, target_is_directory=True)
        with self.assertRaises(ValueError):
            LocalIntegrationProfile(self.product, linked_state)

        linked_ca = self.root / "linked-ca.crt"
        linked_ca.symlink_to(self.ca)
        invalid = IntegrationSetupInput("owner-local", linked_ca, self.setup_input().services)
        with self.assertRaises(ValueError):
            LocalIntegrationProfile(self.product, self.state).configure(
                invalid, {"confluence": "safe", "jira": "session=safe", "airflow": "safe"},
            )

        with self.assertRaises(ValueError):
            LocalIntegrationProfile(self.product, self.state).configure(
                self.setup_input(), {"confluence": "safe\nleak", "jira": "session=safe", "airflow": "safe"},
            )

    def test_load_fails_closed_on_permissions_unknown_fields_and_tampering(self) -> None:
        profile = LocalIntegrationProfile(self.product, self.state)
        profile.configure(
            self.setup_input(), {"confluence": "safe", "jira": "session=safe", "airflow": "safe"},
        )
        directory = self.state / "integrations"
        credential = directory / "jira.credential"
        credential.chmod(0o644)
        with self.assertRaises(ValueError):
            profile.load()
        credential.chmod(0o600)

        profile_path = directory / "profile.json"
        payload = json.loads(profile_path.read_text(encoding="utf-8"))
        payload["unexpected"] = True
        profile_path.write_text(json.dumps(payload), encoding="utf-8")
        profile_path.chmod(0o600)
        with self.assertRaises(ValueError):
            profile.load()

    def test_configure_refuses_overwrite_without_explicit_rotation(self) -> None:
        profile = LocalIntegrationProfile(self.product, self.state)
        secrets = {"confluence": "safe", "jira": "session=safe", "airflow": "safe"}
        profile.configure(self.setup_input(), secrets)
        with self.assertRaises(FileExistsError):
            profile.configure(self.setup_input(), secrets)

    def test_jira_credential_rotation_is_atomic_private_and_metadata_only(self) -> None:
        profile = LocalIntegrationProfile(self.product, self.state)
        profile.configure(
            self.setup_input(), {"confluence": "safe", "jira": "session=old", "airflow": "safe"},
        )

        receipt = profile.rotate_credential("jira", "bearer-token", "new-private-token")
        runtime = profile.load()

        self.assertEqual("rotated", receipt["status"])
        self.assertEqual("jira", receipt["service"])
        self.assertEqual("bearer-token", receipt["auth_mode"])
        self.assertFalse(receipt["credential_exposed"])
        self.assertNotIn("new-private-token", json.dumps(receipt))
        self.assertEqual("bearer-token", runtime.environment["PF_INTEGRATION_JIRA_AUTH_MODE"])
        self.assertEqual("new-private-token", runtime.environment["PF_INTEGRATION_JIRA_TOKEN"])
        self.assertNotIn("PF_INTEGRATION_JIRA_USERNAME", runtime.environment)
        credential = self.state / "integrations" / "jira.credential"
        self.assertEqual(0o600, stat.S_IMODE(credential.stat().st_mode))
        self.assertNotEqual("new-private-token", credential.read_text(encoding="utf-8"))
        self.assertFalse(any(path.name.endswith(".tmp") for path in credential.parent.iterdir()))

    def test_rotation_rejects_non_jira_bearer_and_preserves_existing_profile(self) -> None:
        profile = LocalIntegrationProfile(self.product, self.state)
        profile.configure(
            self.setup_input(), {"confluence": "safe", "jira": "session=old", "airflow": "safe"},
        )
        before = (self.state / "integrations" / "profile.json").read_bytes()
        with self.assertRaises(ValueError):
            profile.rotate_credential("airflow", "bearer-token", "unsafe")
        self.assertEqual(before, (self.state / "integrations" / "profile.json").read_bytes())
        self.assertEqual("session=old", (self.state / "integrations" / "jira.credential").read_text())

    def test_update_cli_reads_token_only_from_hidden_prompt(self) -> None:
        profile = LocalIntegrationProfile(self.product, self.state)
        profile.configure(
            self.setup_input(), {"confluence": "safe", "jira": "session=old", "airflow": "safe"},
        )
        identity = type("Identity", (), {"status": "recognized", "principal_id": "owner-local"})()
        with (
            patch("promptforge.__main__.sys.stdin.isatty", return_value=True),
            patch("promptforge.__main__.GitIdentityResolver.resolve", return_value=identity),
            patch("promptforge.__main__.getpass.getpass", return_value="hidden-jira-token") as hidden,
        ):
            receipt = _integration_credential_update([
                "--state-root", str(self.state), "--service", "jira", "--auth-mode", "bearer-token",
            ])
        hidden.assert_called_once()
        self.assertNotIn("hidden-jira-token", json.dumps(receipt))
        self.assertEqual("bearer-token", profile.load().environment["PF_INTEGRATION_JIRA_AUTH_MODE"])

        with self.assertRaises(ValueError):
            _integration_credential_update([
                "--state-root", str(self.state), "--service", "jira", "--auth-mode", "bearer-token",
                "--token", "must-not-be-accepted",
            ])

    def test_rotation_fails_closed_without_removing_an_existing_lock(self) -> None:
        profile = LocalIntegrationProfile(self.product, self.state)
        profile.configure(
            self.setup_input(), {"confluence": "safe", "jira": "session=old", "airflow": "safe"},
        )
        lock = self.state / "integrations" / ".credential-update.lock"
        lock.write_text("active", encoding="utf-8")
        lock.chmod(0o600)
        with self.assertRaises(FileExistsError):
            profile.rotate_credential("jira", "bearer-token", "new-private-token")
        self.assertTrue(lock.exists())
        self.assertEqual("session=old", (self.state / "integrations" / "jira.credential").read_text())

    def test_bearer_initialized_profile_can_rotate_without_exporting_envelope(self) -> None:
        setup = self.setup_input()
        services = tuple(
            ServiceSetupInput(
                item.id, item.url, "bearer-token" if item.id == "jira" else item.auth_mode,
                "" if item.id == "jira" else item.username, item.scope_mode,
                item.allowed_resources, item.smoke_resource,
            )
            for item in setup.services
        )
        profile = LocalIntegrationProfile(self.product, self.state)
        profile.configure(
            IntegrationSetupInput(setup.principal_id, setup.ca_file, services),
            {"confluence": "safe", "jira": "initial-token", "airflow": "safe"},
        )
        profile.rotate_credential("jira", "bearer-token", "rotated-token")
        runtime = profile.load()
        self.assertEqual("rotated-token", runtime.environment["PF_INTEGRATION_JIRA_TOKEN"])
        self.assertFalse(runtime.environment["PF_INTEGRATION_JIRA_TOKEN"].startswith("{"))

    def test_update_cli_rejects_recognized_non_admin_identity(self) -> None:
        identity = type("Identity", (), {"status": "recognized", "principal_id": "engineer-local"})()
        with (
            patch("promptforge.__main__.sys.stdin.isatty", return_value=True),
            patch("promptforge.__main__.GitIdentityResolver.resolve", return_value=identity),
            patch("promptforge.__main__.getpass.getpass") as hidden,
            self.assertRaises(PermissionError),
        ):
            _integration_credential_update([
                "--state-root", str(self.state), "--service", "jira", "--auth-mode", "bearer-token",
            ])
        hidden.assert_not_called()


if __name__ == "__main__":
    unittest.main()
