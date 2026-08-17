"""Детерминированный fail-closed Policy Engine первого product slice."""

from __future__ import annotations

from dataclasses import dataclass

from promptforge.platform.contracts import PolicyDecision, PolicyRequest


_KNOWN_ACTIONS = frozenset({"model.invoke", "mcp.read", "mcp.write", "docs.generate", "review.run"})
_READ_ACTIONS = frozenset({"mcp.read", "docs.generate", "review.run"})
_SENSITIVE = frozenset({"confidential", "restricted", "regulated"})
_ACTION_RESOURCES = {
    "model.invoke": frozenset({"model:external", "model:local"}),
    "mcp.read": frozenset({"mcp:tool", "mcp:resource"}),
    "mcp.write": "mcp:tool",
    "docs.generate": "docs:artifact",
    "review.run": "review:diff",
}
_DEFAULT_PROJECTS = frozenset({"promptforge"})
_DEFAULT_PURPOSES = frozenset(
    {
        "sprint-2-policy-tests", "policy-fixture", "generate-docs", "review-change", "data-analysis",
        "engineering-change",
    }
)


def _decision(
    outcome: str,
    reason_code: str,
    *,
    transforms: tuple[str, ...] = (),
    constraints: tuple[str, ...] = (),
    ttl_seconds: int = 300,
) -> PolicyDecision:
    return PolicyDecision(
        outcome=outcome,
        reason_code=reason_code,
        required_transforms=transforms,
        policy_version="1.0",
        constraints=constraints,
        ttl_seconds=ttl_seconds,
    )


@dataclass(frozen=True)
class PolicyEngine:
    """Вычисляет решения и блокирует неизвестное состояние."""

    available: bool = True
    allowed_projects: frozenset[str] = _DEFAULT_PROJECTS
    allowed_purposes: frozenset[str] = _DEFAULT_PURPOSES

    def decide(self, request: PolicyRequest) -> PolicyDecision:
        """Возвращает metadata-only decision для проверенного запроса."""

        if not self.available:
            return _decision("deny", "policy_engine_unavailable", ttl_seconds=0)
        if request.principal.project_id not in self.allowed_projects:
            return _decision("deny", "project_not_allowed", ttl_seconds=0)
        if request.purpose not in self.allowed_purposes:
            return _decision("deny", "purpose_not_allowed", ttl_seconds=0)
        if request.action not in _KNOWN_ACTIONS:
            return _decision("deny", "unknown_action", ttl_seconds=0)
        expected_resources = _ACTION_RESOURCES[request.action]
        if isinstance(expected_resources, str):
            expected_resources = frozenset({expected_resources})
        if request.resource not in expected_resources:
            return _decision("deny", "unknown_resource", ttl_seconds=0)
        if request.action == "model.invoke":
            return self._decide_model(request)
        if request.action == "mcp.write":
            return self._decide_write(request)
        if request.action in _READ_ACTIONS:
            if request.data_classification in _SENSITIVE:
                return _decision("deny", "sensitive_read_not_enabled", ttl_seconds=0)
            return _decision("allow", "role_read_allowed", constraints=("read_only",))
        return _decision("deny", "no_matching_policy", ttl_seconds=0)

    @staticmethod
    def _decide_model(request: PolicyRequest) -> PolicyDecision:
        if request.resource == "model:local":
            return _decision("allow", "local_model_allowed", constraints=("local_gateway_only",))
        if request.data_classification in _SENSITIVE:
            return _decision("deny", "external_sensitive_data_denied", ttl_seconds=0)
        if request.data_classification == "internal":
            return _decision(
                "allow_with_transform",
                "internal_external_transform_required",
                transforms=("privacy.inspect_and_placeholder",),
                constraints=("synthetic_or_approved_internal", "external_gateway_only"),
            )
        return _decision("allow", "public_external_allowed", constraints=("external_gateway_only",))

    @staticmethod
    def _decide_write(request: PolicyRequest) -> PolicyDecision:
        if request.data_classification in _SENSITIVE:
            return _decision("deny", "sensitive_write_not_enabled", ttl_seconds=0)
        if request.principal.role == "analyst":
            return _decision("deny", "role_write_denied", ttl_seconds=0)
        return _decision(
            "approval_required", "write_requires_exact_action_approval", constraints=("exact_action_hash",),
            ttl_seconds=60,
        )
