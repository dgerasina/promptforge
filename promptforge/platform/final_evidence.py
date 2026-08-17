"""Воспроизводимый repository-only security/E2E/load evidence bundle."""

from __future__ import annotations

from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import math
import os
from pathlib import Path
import secrets
import subprocess
import sys
import tempfile
import time
from types import MappingProxyType
from typing import Mapping

from promptforge.platform.pilot import build_offline_pilot
from promptforge.platform.operations import LocalKillSwitch, LocalStateCleaner, OperationsConfig
from promptforge.platform.neutrality import NeutralityGate, repository_neutrality_extras
from promptforge.platform.contracts import Principal
from promptforge.platform.governance import GovernancePolicy
from promptforge.core.project_profile import load_project_profile
from promptforge.platform.security import inspect_text, scan_repository_text_artifacts
from promptforge.platform.task_router import TaskEnvelope, TaskRouter, load_agent_catalog
from promptforge.platform.production_docs import ProductionDocumentationGate
from promptforge.platform.workspace import WorkspaceLifecycle


_MAX_P95_MS = 5000.0
_ASSURANCE_SCOPE = "repository_single_host_mvp"
_KNOWN_LIMITATIONS = (
    "audit_no_external_restart_anchor",
    "local_model_process_not_cryptographically_attested",
    "host_process_memory_not_isolated",
    "external_integrations_not_attested_by_repository",
    "semantic_prompt_injection_not_eliminated",
    "single_host_no_ha_or_multi_host_consistency",
)


def _freeze(value: Mapping[str, object]) -> Mapping[str, object]:
    return MappingProxyType(dict(value))


@dataclass(frozen=True)
class FinalEvidence:
    """Хранит агрегированные проверки и привязку к source tree."""

    status: str
    security: Mapping[str, object]
    e2e: Mapping[str, object]
    load: Mapping[str, object]
    source: Mapping[str, object]
    evidence_digest: str

    def __post_init__(self) -> None:
        if self.status not in {"passed", "failed"}:
            raise ValueError("final evidence status is invalid")
        for field_name in ("security", "e2e", "load", "source"):
            object.__setattr__(self, field_name, _freeze(getattr(self, field_name)))
        if not self.evidence_digest.startswith("sha256:") or len(self.evidence_digest) != 71:
            raise ValueError("final evidence digest is invalid")

    def to_payload(self) -> dict[str, object]:
        return {
            "schema_version": "1.0",
            "status": self.status,
            "security": dict(self.security),
            "e2e": dict(self.e2e),
            "load": dict(self.load),
            "source": dict(self.source),
            "assurance_scope": _ASSURANCE_SCOPE,
            "known_limitations": list(_KNOWN_LIMITATIONS),
            "evidence_digest": self.evidence_digest,
            "network_used": False,
        }


@dataclass(frozen=True)
class FinalEvidenceRunner:
    """Запускает bounded synthetic проверки без сети."""

    repository: Path
    iterations: int = 100
    concurrency: int = 4

    def __post_init__(self) -> None:
        root = Path(self.repository).resolve(strict=True)
        if not root.is_dir() or root.is_symlink():
            raise ValueError("evidence repository must be a regular directory")
        valid_iterations = isinstance(self.iterations, int) and not isinstance(self.iterations, bool)
        if not valid_iterations or not 1 <= self.iterations <= 1000:
            raise ValueError("evidence iterations must be between 1 and 1000")
        valid_concurrency = isinstance(self.concurrency, int) and not isinstance(self.concurrency, bool)
        if not valid_concurrency or not 1 <= self.concurrency <= 32:
            raise ValueError("evidence concurrency must be between 1 and 32")
        object.__setattr__(self, "repository", root)

    def run(self) -> FinalEvidence:
        security = self._security_probes()
        e2e, load = self._e2e_and_load()
        source = self._source_evidence()
        passed = (
            security["cases"] == security["passed"]
            and e2e["iterations"] == e2e["passed"]
            and e2e["audit_valid"] is True
            and e2e["token_receipts"] == e2e["iterations"]
            and e2e["durable_token_receipts"] == e2e["iterations"]
            and e2e["usage_store_valid"] is True
            and load["failures"] == 0
            and load["p95_ms"] <= load["max_p95_ms"]
        )
        unsigned = {
            "schema_version": "1.0", "status": "passed" if passed else "failed",
            "security": security, "e2e": e2e, "load": load, "source": source,
            "assurance_scope": _ASSURANCE_SCOPE, "known_limitations": list(_KNOWN_LIMITATIONS), "network_used": False,
        }
        digest = hashlib.sha256(self._canonical(unsigned)).hexdigest()
        return FinalEvidence(unsigned["status"], security, e2e, load, source, f"sha256:{digest}")

    def _security_probes(self) -> dict[str, object]:
        results = [
            inspect_text("sk-proj-FAKE-DO-NOT-USE-12345678901234567890").outcome == "deny",
            self._pii_is_placeholdered(),
            self._task_intake_is_metadata_only_and_fail_closed(),
            self._unknown_principal_is_denied(),
            self._kill_switch_blocks_adapters(),
            self._legal_hold_blocks_cleanup(),
            self._neutrality_policy_passes(),
            self._repository_secret_scan_passes(),
            self._generic_maintainer_has_no_admin(),
            self._project_profile_is_valid(),
            self._task_router_fails_closed(),
            self._token_runtime_is_enforced(),
            self._production_docs_are_current(),
            self._work_execute_requires_authenticated_session(),
        ]
        return {"cases": len(results), "passed": sum(results), "failed": len(results) - sum(results)}

    @staticmethod
    def _pii_is_placeholdered() -> bool:
        result = inspect_text("Synthetic contact analyst@example.com")
        return result.outcome == "allow_with_transform" and "analyst@example.com" not in result.safe_content

    def _unknown_principal_is_denied(self) -> bool:
        with tempfile.TemporaryDirectory() as directory:
            runner = self._pilot(Path(directory).resolve())
            try:
                runner.run("unknown-principal")
            except PermissionError:
                return not runner.model_adapter.calls and not runner.mcp_adapter.calls
        return False

    def _task_intake_is_metadata_only_and_fail_closed(self) -> bool:
        with tempfile.TemporaryDirectory() as directory:
            state_root = Path(directory).resolve()
            lifecycle = WorkspaceLifecycle.from_product(self.repository, state_root)
            lifecycle.setup(refresh_index=False)
            secret_task = "используй ключ sk-proj-FAKE-DO-NOT-USE-12345678901234567890 и создай кальк"
            try:
                lifecycle.start()
                process = subprocess.run(
                    [
                        sys.executable,
                        "-m",
                        "promptforge",
                        "ask",
                        "--principal-id",
                        "engineer-local",
                        "--state-root",
                        str(state_root),
                    ],
                    cwd=self.repository.parent,
                    env={"PYTHONPATH": str(self.repository), "PATH": os.environ.get("PATH", "")},
                    input=secret_task,
                    capture_output=True,
                    text=True,
                    check=False,
                )
                files_are_clean = True
                for path in state_root.glob("*"):
                    if not path.is_file():
                        continue
                    content = path.read_text(encoding="utf-8", errors="replace")
                    if secret_task in content or "sk-proj-" in content:
                        files_are_clean = False
                        break
            finally:
                lifecycle.stop()
        try:
            payload = json.loads(process.stdout)
        except json.JSONDecodeError:
            return False
        return bool(
            process.returncode == 1
            and not process.stderr
            and payload.get("status") == "denied"
            and payload.get("reason_code") == "sensitive_content_detected"
            and payload.get("network_used") is False
            and secret_task not in process.stdout
            and "sk-proj-" not in process.stdout
            and files_are_clean
        )

    def _kill_switch_blocks_adapters(self) -> bool:
        with tempfile.TemporaryDirectory() as directory:
            runner = self._pilot(Path(directory).resolve())
            runner.runtime.kill_switch.set_state(
                True, Principal("owner-local", "owner", "promptforge"), "final-security-probe",
            )
            try:
                runner.run()
            except RuntimeError:
                return not runner.model_adapter.calls and not runner.mcp_adapter.calls
        return False

    def _legal_hold_blocks_cleanup(self) -> bool:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            key = secrets.token_bytes(32)
            switch = LocalKillSwitch(root, key)
            owner = Principal("owner-local", "owner", "promptforge")
            switch.set_state(True, owner, "final-legal-hold-probe")
            target = root / "context-cache.sqlite3"
            target.write_text("synthetic", encoding="utf-8")
            os.chmod(target, 0o600)
            cleaner = LocalStateCleaner(root, OperationsConfig.from_repository(self.repository), switch)
            try:
                cleaner.cleanup(
                    "ephemeral", owner, "PURGE promptforge", dry_run=False, legal_hold=True,
                )
            except PermissionError:
                return target.exists()
        return False

    def _neutrality_policy_passes(self) -> bool:
        return NeutralityGate(self.repository, repository_neutrality_extras(self.repository)).inspect().status == "passed"

    def _repository_secret_scan_passes(self) -> bool:
        return scan_repository_text_artifacts(self.repository).clean

    def _generic_maintainer_has_no_admin(self) -> bool:
        policy = GovernancePolicy.from_repository(self.repository)
        principal = Principal("maintainer-local", "maintainer", policy.project_id)
        return not any(policy.allows(principal, capability) for capability in policy.capabilities)

    def _project_profile_is_valid(self) -> bool:
        profile = load_project_profile(self.repository / "project-profile.yaml")
        return bool(
            profile.pack.id
            and profile.skills_root.is_dir()
            and len(profile.pack.approved_skill_order) <= len(tuple(profile.skills_root.iterdir()))
        )

    def _task_router_fails_closed(self) -> bool:
        profile = load_project_profile(self.repository / "project-profile.yaml")
        catalog = load_agent_catalog(profile)
        principal = Principal("synthetic-engineer", "engineer", profile.project_key)
        route = TaskRouter(profile.project_key, catalog).route(
            TaskEnvelope(profile.project_key, principal, "unknown.task", "final-router-probe"),
        )
        return route.outcome == "denied" and route.reason_code == "unknown_task_kind"

    def _token_runtime_is_enforced(self) -> bool:
        with tempfile.TemporaryDirectory() as directory:
            evidence = self._pilot(Path(directory).resolve()).run()
            return bool(
                evidence.usage["receipts"] == 1
                and evidence.usage["durable_receipts"] == 1
                and evidence.usage["usage_store_valid"] is True
                and evidence.usage["candidate_input_tokens"] >= evidence.usage["selected_input_tokens"]
                and (
                    evidence.usage["selected_input_tokens"] + evidence.usage["transformation_overhead_tokens"]
                    >= evidence.usage["input_tokens"]
                )
                and 0 <= evidence.usage["token_saving_ratio"] <= 1
            )

    def _production_docs_are_current(self) -> bool:
        return ProductionDocumentationGate.from_repository(self.repository).inspect().status == "passed"

    def _work_execute_requires_authenticated_session(self) -> bool:
        with tempfile.TemporaryDirectory() as directory:
            process = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "promptforge",
                    "work",
                    "--principal-id",
                    "engineer-local",
                    "--path",
                    "README.md",
                    "--mode",
                    "execute",
                    "--state-root",
                    str(Path(directory).resolve()),
                ],
                cwd=self.repository,
                env={
                    "PF_EMBEDDED_AUTH_KEY_HEX": secrets.token_bytes(32).hex(),
                    "PYTHONPATH": str(self.repository),
                    "PATH": os.environ.get("PATH", ""),
                },
                capture_output=True,
                text=True,
                check=False,
            )
        try:
            payload = json.loads(process.stdout)
        except json.JSONDecodeError:
            return False
        return bool(
            process.returncode == 1
            and not process.stderr
            and payload.get("status") == "denied"
            and payload.get("reason_code") == "authenticated_session_required"
            and payload.get("network_used") is False
        )

    def _e2e_and_load(self) -> tuple[dict[str, object], dict[str, object]]:
        latencies: list[float] = []
        passed = 0
        with tempfile.TemporaryDirectory() as directory:
            runner = self._pilot(Path(directory).resolve())
            def invoke(_: int) -> tuple[bool, float, Mapping[str, int | float]]:
                iteration_started = time.perf_counter()
                try:
                    result = runner.run(execution_id=f"load-{_:04d}")
                    success = result.status == "ok" and result.audit_valid
                except (OSError, PermissionError, RuntimeError, ValueError):
                    success = False
                usage = result.usage if success else {}
                return success, (time.perf_counter() - iteration_started) * 1000, usage

            started = time.perf_counter()
            workers = min(self.concurrency, self.iterations)
            with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="pf-evidence") as executor:
                results = tuple(executor.map(invoke, range(self.iterations)))
            passed = sum(success for success, _, _ in results)
            latencies.extend(latency for _, latency, _ in results)
            duration = max(time.perf_counter() - started, 0.000_001)
            audit_valid = runner.runtime.audit.verify().valid
            usage_store_valid = runner.runtime.models.usage_store.verify().valid
        ordered = sorted(latencies)
        p95 = ordered[max(0, math.ceil(len(ordered) * 0.95) - 1)]
        usages = tuple(usage for success, _, usage in results if success)
        candidate_tokens = sum(int(usage["candidate_input_tokens"]) for usage in usages)
        selected_tokens = sum(int(usage["selected_input_tokens"]) for usage in usages)
        billed_tokens = sum(int(usage["input_tokens"]) for usage in usages)
        saving_ratio = round(1 - selected_tokens / candidate_tokens, 6) if candidate_tokens else 0.0
        privacy_reduction_tokens = sum(int(usage["privacy_reduction_tokens"]) for usage in usages)
        transformation_overhead_tokens = sum(int(usage["transformation_overhead_tokens"]) for usage in usages)
        e2e = {
            "iterations": self.iterations, "passed": passed, "audit_valid": audit_valid,
            "token_receipts": sum(int(usage["receipts"]) for usage in usages),
            "durable_token_receipts": sum(int(usage["durable_receipts"]) for usage in usages),
            "candidate_input_tokens": candidate_tokens,
            "selected_input_tokens": selected_tokens,
            "billed_input_tokens": billed_tokens,
            "token_saving_ratio": saving_ratio,
            "privacy_reduction_tokens": privacy_reduction_tokens,
            "transformation_overhead_tokens": transformation_overhead_tokens,
            "usage_store_valid": usage_store_valid,
        }
        load = {
            "requests": self.iterations,
            "concurrency": workers,
            "failures": self.iterations - passed,
            "duration_ms": round(duration * 1000, 3),
            "p95_ms": round(p95, 3),
            "max_p95_ms": _MAX_P95_MS,
            "throughput_rps": round(self.iterations / duration, 3),
        }
        return e2e, load

    def _pilot(self, state_root: Path):
        environment = {
            "PF_EMBEDDED_AUTH_KEY_HEX": secrets.token_bytes(32).hex(),
            "PF_LOCAL_AUDIT_KEY_HEX": secrets.token_bytes(32).hex(),
        }
        return build_offline_pilot(self.repository, state_root, environment)

    def _source_evidence(self) -> dict[str, object]:
        digest = hashlib.sha256()
        files = tuple(
            path for path in sorted(self.repository.rglob("*"))
            if path.is_file() and not path.is_symlink() and path.suffix not in {".pyc", ".pyo"}
            and "__pycache__" not in path.parts and ".local-state" not in path.parts
        )
        for path in files:
            relative = path.relative_to(self.repository).as_posix().encode("utf-8")
            digest.update(len(relative).to_bytes(4, "big"))
            digest.update(relative)
            content = path.read_bytes()
            digest.update(len(content).to_bytes(8, "big"))
            digest.update(content)
        production_docs = ProductionDocumentationGate.from_repository(self.repository).inspect()
        return {
            "files": len(files),
            "sha256": digest.hexdigest(),
            "production_docs_digest": production_docs.documents_digest,
            "threat_model_version": production_docs.threat_model_version,
        }

    @staticmethod
    def _canonical(payload: Mapping[str, object]) -> bytes:
        return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
