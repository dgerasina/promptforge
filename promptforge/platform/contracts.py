"""Неизменяемые контракты границ PromptForge Platform."""

from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Any, ClassVar, Mapping


ROLES = frozenset({"owner", "maintainer", "engineer", "analyst"})
DATA_CLASSIFICATIONS = frozenset({"public", "internal", "confidential", "restricted", "regulated"})
POLICY_OUTCOMES = frozenset({"allow", "deny", "allow_with_transform", "approval_required"})
REVIEW_SEVERITIES = frozenset({"high", "medium", "low"})
SCHEMA_VERSION = "1.0"
_SAFE_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


def _require_text(value: str, field_name: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field_name} must be a non-empty string")


def _require_choice(value: str, choices: frozenset[str], field_name: str) -> None:
    if value not in choices:
        raise ValueError(f"unsupported {field_name}: {value}")


def _require_safe_identifier(value: str, field_name: str) -> None:
    _require_text(value, field_name)
    if not _SAFE_IDENTIFIER.fullmatch(value) or value.lower().startswith("sk-"):
        raise ValueError(f"{field_name} must be a safe identifier")


def _strict_payload(payload: Mapping[str, Any], fields: frozenset[str]) -> dict[str, Any]:
    if not isinstance(payload, Mapping):
        raise ValueError("contract payload must be an object")
    unknown = frozenset(payload) - fields
    missing = fields - frozenset(payload)
    if unknown:
        raise ValueError(f"unknown fields: {', '.join(sorted(unknown))}")
    if missing:
        raise ValueError(f"missing fields: {', '.join(sorted(missing))}")
    if payload.get("schema_version") != SCHEMA_VERSION:
        raise ValueError(f"unsupported schema version: {payload.get('schema_version')}")
    return dict(payload)


@dataclass(frozen=True)
class Principal:
    """Описывает пользователя или workload в рамках одного проекта."""

    id: str
    role: str
    project_id: str
    _WIRE_FIELDS: ClassVar[frozenset[str]] = frozenset({"schema_version", "id", "role", "project_id"})

    def __post_init__(self) -> None:
        _require_text(self.id, "principal id")
        _require_choice(self.role, ROLES, "role")
        _require_text(self.project_id, "project id")

    def to_payload(self) -> dict[str, str]:
        return {"schema_version": SCHEMA_VERSION, "id": self.id, "role": self.role, "project_id": self.project_id}

    def to_wire(self) -> dict[str, str]:
        return self.to_payload()

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> Principal:
        data = _strict_payload(payload, cls._WIRE_FIELDS)
        return cls(id=data["id"], role=data["role"], project_id=data["project_id"])


@dataclass(frozen=True)
class SkillSpec:
    """Описывает доступный роли навык без выдачи runtime-разрешений."""

    id: str
    roles: tuple[str, ...]
    risk: str = "low"

    def __post_init__(self) -> None:
        _require_text(self.id, "skill id")
        frozen_roles = tuple(self.roles)
        if not frozen_roles:
            raise ValueError("skill roles must not be empty")
        for role in frozen_roles:
            _require_choice(role, ROLES, "role")
        if self.risk not in {"low", "medium", "high"}:
            raise ValueError(f"unsupported skill risk: {self.risk}")
        object.__setattr__(self, "roles", frozen_roles)

    def to_payload(self) -> dict[str, object]:
        return {"id": self.id, "roles": list(self.roles), "risk": self.risk}

    def to_wire(self) -> dict[str, object]:
        return self.to_payload()

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> SkillSpec:
        fields = frozenset({"id", "roles", "risk"})
        if not isinstance(payload, Mapping):
            raise ValueError("skill payload must be an object")
        unknown, missing = frozenset(payload) - fields, fields - frozenset(payload)
        if unknown or missing:
            raise ValueError(f"skill fields mismatch: unknown={sorted(unknown)}, missing={sorted(missing)}")
        return cls(id=payload["id"], roles=tuple(payload["roles"]), risk=payload["risk"])


@dataclass(frozen=True)
class PolicyRequest:
    """Передаёт policy engine минимальный контекст решения."""

    principal: Principal
    action: str
    resource: str
    purpose: str
    data_classification: str
    _WIRE_FIELDS: ClassVar[frozenset[str]] = frozenset(
        {"schema_version", "principal", "action", "resource", "purpose", "data_classification"}
    )

    def __post_init__(self) -> None:
        _require_text(self.action, "action")
        _require_text(self.resource, "resource")
        _require_text(self.purpose, "purpose")
        _require_choice(self.data_classification, DATA_CLASSIFICATIONS, "data classification")

    def to_payload(self) -> dict[str, object]:
        return {
            "schema_version": SCHEMA_VERSION, "principal": self.principal.to_payload(), "action": self.action,
            "resource": self.resource, "purpose": self.purpose, "data_classification": self.data_classification,
        }

    def to_wire(self) -> dict[str, object]:
        return self.to_payload()

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> PolicyRequest:
        data = _strict_payload(payload, cls._WIRE_FIELDS)
        return cls(
            principal=Principal.from_payload(data["principal"]), action=data["action"], resource=data["resource"],
            purpose=data["purpose"], data_classification=data["data_classification"],
        )


@dataclass(frozen=True)
class PolicyDecision:
    """Возвращает закрытое и объяснимое policy-решение."""

    outcome: str
    reason_code: str
    required_transforms: tuple[str, ...] = ()
    policy_version: str = "1.0"
    constraints: tuple[str, ...] = ()
    ttl_seconds: int = 300
    _WIRE_FIELDS: ClassVar[frozenset[str]] = frozenset(
        {
            "schema_version", "outcome", "reason_code", "required_transforms", "policy_version", "constraints",
            "ttl_seconds",
        }
    )

    def __post_init__(self) -> None:
        _require_choice(self.outcome, POLICY_OUTCOMES, "policy outcome")
        _require_text(self.reason_code, "reason code")
        if not isinstance(self.required_transforms, (list, tuple)):
            raise ValueError("required transforms must be an array")
        if self.outcome == "allow_with_transform" and not self.required_transforms:
            raise ValueError("allow_with_transform requires at least one transform")
        _require_text(self.policy_version, "policy version")
        if not isinstance(self.constraints, (list, tuple)):
            raise ValueError("constraints must be an array")
        if not isinstance(self.ttl_seconds, int) or isinstance(self.ttl_seconds, bool) or self.ttl_seconds < 0:
            raise ValueError("ttl seconds must be a non-negative integer")
        object.__setattr__(self, "required_transforms", tuple(self.required_transforms))
        object.__setattr__(self, "constraints", tuple(self.constraints))

    def to_payload(self) -> dict[str, object]:
        return {
            "schema_version": SCHEMA_VERSION, "outcome": self.outcome, "reason_code": self.reason_code,
            "required_transforms": list(self.required_transforms),
            "policy_version": self.policy_version,
            "constraints": list(self.constraints),
            "ttl_seconds": self.ttl_seconds,
        }

    def to_wire(self) -> dict[str, object]:
        return self.to_payload()

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> PolicyDecision:
        data = _strict_payload(payload, cls._WIRE_FIELDS)
        return cls(
            data["outcome"], data["reason_code"], tuple(data["required_transforms"]), data["policy_version"],
            tuple(data["constraints"]), data["ttl_seconds"],
        )


@dataclass(frozen=True)
class ModelRequest:
    """Описывает разрешённый запрос к logical model route."""

    project_id: str
    purpose: str
    data_classification: str
    content: str
    route: str = "external"
    transformed: bool = False
    logical_model: str = "balanced"
    trace_id: str = "local-trace"
    max_output_tokens: int = 256
    _WIRE_FIELDS: ClassVar[frozenset[str]] = frozenset(
        {
            "schema_version", "project_id", "purpose", "data_classification", "content", "route", "transformed",
            "logical_model", "trace_id", "max_output_tokens",
        }
    )

    def __post_init__(self) -> None:
        _require_text(self.project_id, "project id")
        _require_text(self.purpose, "purpose")
        _require_choice(self.data_classification, DATA_CLASSIFICATIONS, "data classification")
        _require_text(self.content, "content")
        if self.route not in {"external", "local"}:
            raise ValueError(f"unsupported model route: {self.route}")
        if not isinstance(self.transformed, bool):
            raise ValueError("transformed must be a boolean")
        _require_safe_identifier(self.logical_model, "logical model")
        _require_safe_identifier(self.trace_id, "trace id")
        if (
            not isinstance(self.max_output_tokens, int)
            or isinstance(self.max_output_tokens, bool)
            or self.max_output_tokens <= 0
        ):
            raise ValueError("max output tokens must be a positive integer")
        if self.route == "external" and self.data_classification not in {"public", "internal"}:
            raise ValueError("external model accepts only public or approved internal data")
        if self.route == "external" and self.data_classification == "internal" and not self.transformed:
            raise ValueError("external model accepts internal data only as a transformed internal payload")

    def to_payload(self) -> dict[str, object]:
        return {
            "schema_version": SCHEMA_VERSION, "project_id": self.project_id, "purpose": self.purpose,
            "data_classification": self.data_classification, "content": self.content, "route": self.route,
            "transformed": self.transformed,
            "logical_model": self.logical_model,
            "trace_id": self.trace_id,
            "max_output_tokens": self.max_output_tokens,
        }

    def to_wire(self) -> dict[str, object]:
        return self.to_payload()

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> ModelRequest:
        data = _strict_payload(payload, cls._WIRE_FIELDS)
        return cls(
            data["project_id"], data["purpose"], data["data_classification"], data["content"], data["route"],
            data["transformed"], data["logical_model"], data["trace_id"], data["max_output_tokens"],
        )


@dataclass(frozen=True)
class ReviewFinding:
    """Фиксирует проверяемое замечание автоматического ревью."""

    severity: str
    category: str
    location: str
    claim: str
    evidence: tuple[str, ...]
    impact: str
    remediation: str
    confidence: float
    _WIRE_FIELDS: ClassVar[frozenset[str]] = frozenset(
        {
            "schema_version", "severity", "category", "location", "claim", "evidence", "impact", "remediation",
            "confidence",
        }
    )

    def __post_init__(self) -> None:
        _require_choice(self.severity, REVIEW_SEVERITIES, "review severity")
        _require_text(self.category, "review category")
        _require_text(self.claim, "review claim")
        _require_text(self.impact, "review impact")
        _require_text(self.remediation, "review remediation")
        if not isinstance(self.evidence, (list, tuple)):
            raise ValueError("evidence must be an array")
        frozen_evidence = tuple(self.evidence)
        if self.severity in {"high", "medium"} and (not self.location.strip() or not frozen_evidence):
            raise ValueError("blocking review finding requires location and evidence")
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("review confidence must be between 0 and 1")
        object.__setattr__(self, "evidence", frozen_evidence)

    def to_payload(self) -> dict[str, object]:
        return {
            "schema_version": SCHEMA_VERSION, "severity": self.severity, "category": self.category,
            "location": self.location, "claim": self.claim, "evidence": list(self.evidence), "impact": self.impact,
            "remediation": self.remediation, "confidence": self.confidence,
        }

    def to_wire(self) -> dict[str, object]:
        return self.to_payload()

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> ReviewFinding:
        data = _strict_payload(payload, cls._WIRE_FIELDS)
        return cls(
            data["severity"], data["category"], data["location"], data["claim"], tuple(data["evidence"]),
            data["impact"], data["remediation"], data["confidence"],
        )
