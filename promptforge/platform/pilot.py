"""Единый offline pilot: auth → policy/privacy → model → MCP → review → audit."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re
import time
from types import MappingProxyType
from typing import Callable, Mapping

from promptforge.platform.contracts import ModelRequest
from promptforge.platform.gateway import FakeProviderAdapter, LogicalModel, ModelEndpoint, ModelGateway, ModelRegistry
from promptforge.platform.local_audit import AuditEvent
from promptforge.platform.mcp_hub import (
    ApprovalStore,
    FakeMcpAdapter,
    McpCapability,
    McpHub,
    McpRegistry,
    McpRequest,
)
from promptforge.platform.policy import PolicyEngine
from promptforge.platform.privacy import PrivacyContext, PrivacyPipeline, ScopedMappingVault
from promptforge.platform.review import (
    CheckEvidence,
    ChangedFile,
    FakeReviewEvidenceVerifier,
    ReviewEngine,
    ReviewRequest,
    diff_digest,
)
from promptforge.platform.secure_runtime import SecureRuntime, build_secure_runtime
from promptforge.platform.token_efficiency import ContextItem
from promptforge.platform.efficiency_metrics import EfficiencyMetricEvent


_CHECK_IDS = ("syntax", "tests", "contracts", "security", "deploy_safety")
_EXECUTION_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


@dataclass(frozen=True)
class PilotEvidence:
    """Возвращает только metadata единого пилотного прогона."""

    status: str
    principal_id: str
    role: str
    stages: Mapping[str, str]
    usage: Mapping[str, int | float]
    review_findings: Mapping[str, int]
    audit_valid: bool
    audit_events: int

    def __post_init__(self) -> None:
        expected_stages = {"login", "policy", "privacy", "model", "mcp", "review"}
        if self.status != "ok" or set(self.stages) != expected_stages:
            raise ValueError("pilot evidence status or stages are invalid")
        expected_usage = {
            "input_tokens", "output_tokens", "receipts", "candidate_input_tokens", "selected_input_tokens",
            "token_saving_ratio", "deduplication_ratio", "privacy_reduction_tokens", "durable_receipts",
            "transformation_overhead_tokens", "gateway_receipt_digest", "usage_store_valid",
        }
        if set(self.usage) != expected_usage or set(self.review_findings) != {
            "high", "medium", "low",
        }:
            raise ValueError("pilot evidence metrics are invalid")
        counters = (
            self.usage["input_tokens"], self.usage["output_tokens"], self.usage["receipts"],
            self.usage["candidate_input_tokens"], self.usage["selected_input_tokens"],
            self.usage["privacy_reduction_tokens"], self.usage["transformation_overhead_tokens"],
            self.usage["durable_receipts"],
            *self.review_findings.values(), self.audit_events,
        )
        ratios = (self.usage["token_saving_ratio"], self.usage["deduplication_ratio"])
        if any(not isinstance(value, int) or isinstance(value, bool) or value < 0 for value in counters):
            raise ValueError("pilot evidence counters are invalid")
        if (
            not isinstance(self.usage["gateway_receipt_digest"], str)
            or not re.fullmatch(r"sha256:[0-9a-f]{64}", self.usage["gateway_receipt_digest"])
        ):
            raise ValueError("pilot gateway receipt digest is invalid")
        invalid_ratio = any(
            not isinstance(value, (int, float)) or isinstance(value, bool) or not 0 <= value <= 1
            for value in ratios
        )
        if invalid_ratio:
            raise ValueError("pilot evidence ratios are invalid")
        if not isinstance(self.audit_valid, bool):
            raise ValueError("pilot audit status is invalid")
        object.__setattr__(self, "stages", MappingProxyType(dict(self.stages)))
        object.__setattr__(self, "usage", MappingProxyType(dict(self.usage)))
        object.__setattr__(self, "review_findings", MappingProxyType(dict(self.review_findings)))

    def to_payload(self) -> dict[str, object]:
        return {
            "schema_version": "1.0",
            "status": self.status,
            "principal_id": self.principal_id,
            "role": self.role,
            "stages": dict(self.stages),
            "usage": dict(self.usage),
            "review_findings": dict(self.review_findings),
            "audit": {"valid": self.audit_valid, "events": self.audit_events},
            "network_used": False,
        }


@dataclass(frozen=True)
class OfflinePilotRunner:
    """Оркестрирует synthetic E2E, сохраняя execution только за audited boundaries."""

    runtime: SecureRuntime
    model_adapter: FakeProviderAdapter
    mcp_adapter: FakeMcpAdapter
    clock: Callable[[], float] = time.time

    def run(self, principal_id: str = "engineer-local", *, execution_id: str = "default") -> PilotEvidence:
        if not isinstance(execution_id, str) or not _EXECUTION_ID.fullmatch(execution_id):
            raise ValueError("pilot execution id is invalid")
        token = self.runtime.authenticator.issue(principal_id)
        authentication = self.runtime.authenticator.authenticate(token)
        if authentication.principal is None:
            raise PermissionError("pilot login failed")
        principal = authentication.principal
        self._audit(
            f"pilot-login-{execution_id}", principal.id, "pilot.login", "identity:session", "allow", "authenticated",
        )

        model_context = PrivacyContext(
            "promptforge", "pilot-model", principal.id, "engineering-change", "external", True, 3600,
        )
        model_request = ModelRequest(
            "promptforge", "engineering-change", "internal", "Synthetic contact analyst@example.com", "external",
            True, "balanced", f"pilot-model-trace-{execution_id}", 128,
        )
        shared_context = "Repository metadata for the selected engineering task."
        model_result = self.runtime.models.invoke(
            token, model_request, model_context,
            context_items=(
                ContextItem("repository-index", shared_context),
                ContextItem("skill-repository-index", shared_context),
            ),
        )
        if (
            model_result.status != "ok" or model_result.usage_receipt is None
            or model_result.durable_usage_receipt is None
            or not self.runtime.models.optimizer.verify_receipt(model_result.usage_receipt)
            or not self.runtime.models.verify_gateway_receipt(model_result.receipt)
        ):
            self._audit(
                f"pilot-final-{execution_id}", principal.id, "pilot.run", "workflow:pilot", "error", "model_failed",
            )
            raise RuntimeError("pilot model stage failed")

        mcp_context = PrivacyContext(
            "promptforge", "pilot-mcp", principal.id, "engineering-change", "local", False, 3600,
        )
        mcp_request = McpRequest(
            "promptforge", "engineering-change", "confluence.search", "1.0.0", {}, "public",
            f"pilot-mcp-trace-{execution_id}",
        )
        mcp_result = self.runtime.mcp.execute(token, mcp_request, mcp_context)
        if mcp_result.status != "ok":
            self._audit(
                f"pilot-final-{execution_id}", principal.id, "pilot.run", "workflow:pilot", "error", "mcp_failed",
            )
            raise RuntimeError("pilot MCP stage failed")

        review_result = self._review(execution_id)
        review_outcome = "deny" if review_result.receipt.status == "changes_requested" else "ok"
        self._audit(
            f"pilot-review-{execution_id}", principal.id, "review.execute", "review:changed-files", review_outcome,
            review_result.receipt.reason_code,
        )
        self._audit(
            f"pilot-final-{execution_id}", principal.id, "pilot.run", "workflow:pilot", "ok", "pilot_completed",
        )
        verification = self.runtime.audit.verify()
        usage_verification = self.runtime.models.usage_store.verify()
        high, medium, low = review_result.receipt.finding_counts
        findings = high + medium + low
        self.runtime.metrics.append(EfficiencyMetricEvent(
            agents_invoked=1, skills_invoked=1, review_findings=findings,
            runs=1, first_run_successes=1 if review_result.receipt.status == "passed" else 0,
        ))
        return PilotEvidence(
            "ok", principal.id, principal.role,
            {
                "login": authentication.status,
                "policy": model_result.receipt.policy_outcome,
                "privacy": model_result.receipt.privacy_outcome,
                "model": model_result.status,
                "mcp": mcp_result.status,
                "review": review_result.receipt.status,
            },
            {
                "input_tokens": model_result.receipt.input_tokens,
                "output_tokens": model_result.receipt.output_tokens,
                "receipts": 1,
                "durable_receipts": 1,
                "candidate_input_tokens": model_result.usage_receipt.candidate_input_tokens,
                "selected_input_tokens": model_result.usage_receipt.selected_input_tokens,
                "token_saving_ratio": model_result.usage_receipt.token_saving_ratio,
                "deduplication_ratio": model_result.usage_receipt.deduplication_ratio,
                "privacy_reduction_tokens": model_result.usage_receipt.privacy_reduction_tokens,
                "transformation_overhead_tokens": model_result.usage_receipt.transformation_overhead_tokens,
                "gateway_receipt_digest": model_result.usage_receipt.gateway_receipt_digest,
                "usage_store_valid": bool(usage_verification and usage_verification.valid),
            },
            {"high": high, "medium": medium, "low": low}, verification.valid, verification.events,
        )

    def _review(self, execution_id: str):
        changed = ChangedFile(
            "etl/airflow2/dags/pilot_calc_test.py", "+target = 'sandbox_owner-local.pilot'", True,
        )
        checks = tuple(
            CheckEvidence(check_id, "passed", f"receipt:{check_id}:pilot{index:02d}")
            for index, check_id in enumerate(_CHECK_IDS, 1)
        )
        request = ReviewRequest(
            "promptforge", "engineering-change", diff_digest((changed,)), (changed,), checks, True,
            "draft-0.1", "1.0", ("review-engine:1.0.0",), "deterministic-only",
            f"pilot-review-trace-{execution_id}",
        )
        receipts = frozenset(
            (check.check_id, check.status, check.evidence, request.diff_digest) for check in request.checks
        )
        return ReviewEngine(FakeReviewEvidenceVerifier(receipts)).review(request)

    def _audit(
        self, trace_id: str, principal_id: str, action: str, resource: str, outcome: str, reason_code: str,
    ) -> None:
        self.runtime.audit.append(AuditEvent(
            trace_id, principal_id, "promptforge", action, resource, outcome, reason_code, "1.0", int(self.clock()),
        ))


def build_offline_pilot(
    repo_root: Path,
    state_root: Path,
    environment: Mapping[str, str],
    *,
    clock: Callable[[], float] = time.time,
) -> OfflinePilotRunner:
    """Собирает pilot только из repository code, synthetic fixtures и ephemeral local state."""

    principal_id = "engineer-local"
    model_context = PrivacyContext(
        "promptforge", "pilot-model", principal_id, "engineering-change", "external", True, 3600,
    )
    privacy = PrivacyPipeline(
        ScopedMappingVault(clock=clock), frozenset({model_context.scope}),
    )
    model_adapter = FakeProviderAdapter("Synthetic reviewed response.")
    endpoint = ModelEndpoint(
        "pilot-primary", "pilot-provider", "pilot-model", "eu", "internal", "no_training", 4096, 256,
    )
    gateway = ModelGateway(
        ModelRegistry((endpoint,), (LogicalModel("balanced", (endpoint.id,)),)),
        {endpoint.provider: model_adapter}, PolicyEngine(), privacy, frozenset({"eu"}),
    )
    empty = {"type": "object", "properties": {}, "required": [], "additionalProperties": False}
    any_object = {"type": "object", "properties": {}, "required": [], "additionalProperties": True}
    capability = McpCapability.attested(
        "confluence.search", "resource", "confluence", "1.0.0", "Search synthetic pages.", "read", "low",
        ("owner", "maintainer", "engineer", "analyst"), "promptforge", empty, any_object,
    )
    mcp_adapter = FakeMcpAdapter({"pages": ["Synthetic page"]})

    class BootstrapAuthenticator:
        project_id = "promptforge"

        def authenticate(self, token):
            raise RuntimeError("secure runtime must replace bootstrap authentication")

    hub = McpHub(
        BootstrapAuthenticator(), McpRegistry((capability,)), {"confluence": mcp_adapter}, PolicyEngine(), privacy,
        ApprovalStore(clock=clock), clock=clock,
    )
    runtime = build_secure_runtime(repo_root, state_root, environment, gateway, hub, clock=clock)
    return OfflinePilotRunner(runtime, model_adapter, mcp_adapter, clock)
