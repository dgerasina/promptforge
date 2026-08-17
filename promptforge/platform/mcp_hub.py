"""Authenticated MCP Hub с registry entitlements и exact-action approvals."""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import hmac
import json
import re
import secrets
from threading import Lock
from time import time
from types import MappingProxyType
from typing import Callable, Mapping, Protocol

from promptforge.platform.auth import Authenticator
from promptforge.platform.contracts import DATA_CLASSIFICATIONS, PolicyRequest, Principal, ROLES, SCHEMA_VERSION
from promptforge.platform.governance import GovernancePolicy
from promptforge.platform.policy import PolicyEngine
from promptforge.platform.privacy import PrivacyContext, PrivacyPipeline
from promptforge.platform.efficiency_metrics import EfficiencyMetricEvent, EfficiencyMetricsStore


_KINDS = frozenset({"tool", "resource"})
_OPERATIONS = frozenset({"read", "write", "execute", "delete", "send", "permission_management"})
_RISKS = frozenset({"low", "medium", "high"})
_SAFE_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


def _safe_identifier(value: object) -> bool:
    return bool(
        isinstance(value, str)
        and _SAFE_IDENTIFIER.fullmatch(value)
        and not value.lower().startswith("sk-")
    )


def _canonical_json(value: object) -> str:
    try:
        return json.dumps(_plain(value), ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    except (RecursionError, TypeError, ValueError) as error:
        raise ValueError("value must be JSON serializable") from error


def _plain(value: object) -> object:
    if isinstance(value, Mapping):
        return {key: _plain(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_plain(item) for item in value]
    return value


def _deep_freeze(value: object) -> object:
    if isinstance(value, Mapping):
        return MappingProxyType({key: _deep_freeze(item) for key, item in value.items()})
    if isinstance(value, list):
        return tuple(_deep_freeze(item) for item in value)
    return value


def _freeze_mapping(value: Mapping[str, object], field_name: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or any(not isinstance(key, str) for key in value):
        raise ValueError(f"{field_name} must be an object with string keys")
    return _deep_freeze(json.loads(_canonical_json(dict(value))))


def _validate_object(schema: Mapping[str, object], value: object) -> bool:
    return _validate_value(schema, value, 0)


def _schema_is_supported(
    schema: Mapping[str, object],
    depth: int = 0,
    require_closed_objects: bool = False,
) -> bool:
    if depth > 12 or not isinstance(schema, Mapping):
        return False
    common = {"type", "enum", "const", "description"}
    by_type = {
        "object": {"properties", "required", "additionalProperties", "minProperties", "maxProperties"},
        "array": {"items", "minItems", "maxItems"},
        "string": {"minLength", "maxLength"},
        "integer": {"minimum", "maximum"},
        "boolean": set(),
    }
    schema_type = schema.get("type")
    if schema_type not in by_type or set(schema) - common - by_type[schema_type]:
        return False
    if "description" in schema and not isinstance(schema["description"], str):
        return False
    if "enum" in schema and (
        not isinstance(schema["enum"], (list, tuple)) or not schema["enum"]
    ):
        return False
    if "enum" in schema and any(not _value_matches_type(schema_type, value) for value in schema["enum"]):
        return False
    if "const" in schema and not _value_matches_type(schema_type, schema["const"]):
        return False
    if schema_type == "object":
        properties = schema.get("properties", {})
        required = schema.get("required", [])
        if not isinstance(properties, Mapping) or not isinstance(required, (list, tuple)):
            return False
        if any(not isinstance(key, str) for key in properties) or not set(required) <= set(properties):
            return False
        if any(not isinstance(key, str) for key in required) or len(set(required)) != len(required):
            return False
        if not isinstance(schema.get("additionalProperties", False), bool):
            return False
        if require_closed_objects and schema.get("additionalProperties") is not False:
            return False
        if not _valid_bounds(schema, "minProperties", "maxProperties"):
            return False
        return all(
            _schema_is_supported(item, depth + 1, require_closed_objects) for item in properties.values()
        )
    if schema_type == "array":
        return _valid_bounds(schema, "minItems", "maxItems") and _schema_is_supported(
            schema.get("items"), depth + 1, require_closed_objects,
        )
    if schema_type == "string":
        return _valid_bounds(schema, "minLength", "maxLength")
    if schema_type == "integer":
        minimum, maximum = schema.get("minimum"), schema.get("maximum")
        if minimum is not None and (not isinstance(minimum, int) or isinstance(minimum, bool)):
            return False
        if maximum is not None and (not isinstance(maximum, int) or isinstance(maximum, bool)):
            return False
        if minimum is not None and maximum is not None and minimum > maximum:
            return False
    return True


def _valid_bounds(schema: Mapping[str, object], minimum_key: str, maximum_key: str) -> bool:
    minimum, maximum = schema.get(minimum_key, 0), schema.get(maximum_key)
    if not isinstance(minimum, int) or isinstance(minimum, bool) or minimum < 0:
        return False
    if maximum is None:
        return True
    return isinstance(maximum, int) and not isinstance(maximum, bool) and maximum >= minimum


def _value_matches_type(schema_type: object, value: object) -> bool:
    if schema_type == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    expected = {"string": str, "boolean": bool, "object": Mapping, "array": (list, tuple)}.get(schema_type)
    return expected is not None and isinstance(value, expected)


def _validate_value(schema: Mapping[str, object], value: object, depth: int) -> bool:
    if depth > 12 or not isinstance(schema, Mapping):
        return False
    schema_type = schema.get("type")
    types = {"string": str, "integer": int, "boolean": bool, "object": Mapping, "array": (list, tuple)}
    expected = types.get(schema_type)
    if expected is None or not isinstance(value, expected) or schema_type == "integer" and isinstance(value, bool):
        return False
    if "const" in schema and value != schema["const"]:
        return False
    if "enum" in schema and value not in schema["enum"]:
        return False
    if schema_type == "string":
        if len(value) < schema.get("minLength", 0) or len(value) > schema.get("maxLength", len(value)):
            return False
        pattern = schema.get("pattern")
        return pattern is None or isinstance(pattern, str) and re.search(pattern, value) is not None
    if schema_type == "integer":
        return value >= schema.get("minimum", value) and value <= schema.get("maximum", value)
    if schema_type == "array":
        if len(value) < schema.get("minItems", 0) or len(value) > schema.get("maxItems", len(value)):
            return False
        items = schema.get("items")
        return isinstance(items, Mapping) and all(_validate_value(items, item, depth + 1) for item in value)
    if schema_type == "boolean":
        return True
    properties = schema.get("properties", {})
    required = schema.get("required", [])
    if not isinstance(properties, Mapping) or not isinstance(required, (list, tuple)):
        return False
    if any(key not in value for key in required):
        return False
    if len(value) < schema.get("minProperties", 0) or len(value) > schema.get("maxProperties", len(value)):
        return False
    if schema.get("additionalProperties") is False and set(value) - set(properties):
        return False
    for key, item in value.items():
        definition = properties.get(key)
        if definition is None:
            continue
        if not _validate_value(definition, item, depth + 1):
            return False
    return True


@dataclass(frozen=True)
class McpCapability:
    """Описывает pinned MCP tool/resource и его authorization surface."""

    id: str
    kind: str
    server: str
    version: str
    description: str
    operation: str
    risk: str
    roles: tuple[str, ...]
    project_id: str
    input_schema: Mapping[str, object]
    output_schema: Mapping[str, object]
    attested_digest: str
    destination: str = "local"
    enabled: bool = True
    max_argument_chars: int = 4096
    max_result_chars: int = 8192

    def __post_init__(self) -> None:
        if any(not _safe_identifier(value) for value in (self.id, self.server, self.version, self.project_id)):
            raise ValueError("MCP capability identifiers must be safe")
        if not isinstance(self.description, str) or not self.description.strip():
            raise ValueError("MCP capability text fields must be non-empty")
        if self.kind not in _KINDS or self.operation not in _OPERATIONS or self.risk not in _RISKS:
            raise ValueError("unsupported MCP capability enum")
        if self.kind == "resource" and self.operation != "read":
            raise ValueError("MCP resources must be read-only")
        if self.destination not in {"local", "external"}:
            raise ValueError("unsupported MCP destination")
        roles = tuple(self.roles)
        if not roles or any(role not in ROLES for role in roles) or len(set(roles)) != len(roles):
            raise ValueError("MCP capability roles are invalid")
        limits = (self.max_argument_chars, self.max_result_chars)
        if any(not isinstance(value, int) or isinstance(value, bool) or value <= 0 for value in limits):
            raise ValueError("MCP capability limits must be positive integers")
        frozen_input = _freeze_mapping(self.input_schema, "input schema")
        frozen_output = _freeze_mapping(self.output_schema, "output schema")
        if not _schema_is_supported(frozen_input, require_closed_objects=True):
            raise ValueError("MCP input schema must be a supported closed schema")
        if not _schema_is_supported(frozen_output):
            raise ValueError("unsupported MCP JSON Schema subset")
        object.__setattr__(self, "roles", roles)
        object.__setattr__(self, "input_schema", frozen_input)
        object.__setattr__(self, "output_schema", frozen_output)
        if len(self.attested_digest) != 64 or any(char not in "0123456789abcdef" for char in self.attested_digest):
            raise ValueError("attested digest must be lowercase SHA-256")

    @classmethod
    def attested(
        cls,
        capability_id: str,
        kind: str,
        server: str,
        version: str,
        description: str,
        operation: str,
        risk: str,
        roles: tuple[str, ...],
        project_id: str,
        input_schema: Mapping[str, object],
        output_schema: Mapping[str, object],
        destination: str = "local",
    ) -> McpCapability:
        """Создаёт локально аттестованный synthetic descriptor."""

        placeholder = "0" * 64
        capability = cls(
            capability_id, kind, server, version, description, operation, risk, roles, project_id,
            input_schema, output_schema, placeholder, destination,
        )
        return cls(
            capability_id, kind, server, version, description, operation, risk, roles, project_id,
            input_schema, output_schema, capability.descriptor_digest, destination,
        )

    @property
    def descriptor_digest(self) -> str:
        descriptor = {
            "id": self.id, "kind": self.kind, "server": self.server, "version": self.version,
            "description": self.description, "operation": self.operation, "risk": self.risk,
            "roles": list(self.roles), "project_id": self.project_id,
            "input_schema": _plain(self.input_schema), "output_schema": _plain(self.output_schema),
            "destination": self.destination,
            "enabled": self.enabled, "max_argument_chars": self.max_argument_chars,
            "max_result_chars": self.max_result_chars,
        }
        return hashlib.sha256(_canonical_json(descriptor).encode()).hexdigest()

    @property
    def is_attested(self) -> bool:
        return hmac.compare_digest(self.descriptor_digest, self.attested_digest)


@dataclass(frozen=True)
class McpRegistry:
    """Хранит immutable snapshot только зарегистрированных capabilities."""

    capabilities: tuple[McpCapability, ...]

    def __post_init__(self) -> None:
        values = tuple(self.capabilities)
        keys = {(item.id, item.version) for item in values}
        if len(keys) != len(values):
            raise ValueError("duplicate MCP capability id/version")
        object.__setattr__(self, "capabilities", values)

    def resolve(self, capability_id: str, version: str) -> McpCapability | None:
        return next(
            (item for item in self.capabilities if item.id == capability_id and item.version == version), None,
        )

    def visible(self, role: str, project_id: str) -> tuple[McpCapability, ...]:
        return tuple(
            item for item in self.capabilities
            if item.enabled and item.is_attested and item.project_id == project_id and role in item.roles
        )


@dataclass(frozen=True)
class McpRequest:
    """Нормализует один exact MCP action."""

    project_id: str
    purpose: str
    capability_id: str
    capability_version: str
    arguments: Mapping[str, object]
    data_classification: str
    trace_id: str
    approval_id: str = ""

    def __post_init__(self) -> None:
        texts = (self.project_id, self.purpose, self.capability_id, self.capability_version, self.trace_id)
        if any(not _safe_identifier(value) for value in texts):
            raise ValueError("MCP request identifiers must be safe")
        if self.approval_id and not re.fullmatch(r"[0-9a-f]{32}", self.approval_id):
            raise ValueError("approval id must be an opaque identifier")
        if self.data_classification not in DATA_CLASSIFICATIONS:
            raise ValueError("unsupported MCP request classification")
        object.__setattr__(self, "arguments", _freeze_mapping(self.arguments, "arguments"))

    def with_approval(self, approval_id: str) -> McpRequest:
        return McpRequest(
            self.project_id, self.purpose, self.capability_id, self.capability_version, self.arguments,
            self.data_classification, self.trace_id, approval_id,
        )


@dataclass(frozen=True)
class McpAdapterCall:
    """Передаёт downstream только safe arguments, без inbound bearer token."""

    capability_id: str
    version: str
    operation: str
    arguments: Mapping[str, object]
    trace_id: str


@dataclass(frozen=True)
class McpAdapterResponse:
    data: Mapping[str, object]
    side_effect: bool = False


class McpAdapter(Protocol):
    def invoke(self, call: McpAdapterCall) -> McpAdapterResponse:
        """Выполняет один MCP call серверными credentials."""


@dataclass
class FakeMcpAdapter:
    """Детерминированный adapter без сети и credentials."""

    response: Mapping[str, object]
    fail: bool = False
    side_effect: bool = False
    calls: list[McpAdapterCall] = field(default_factory=list, init=False)

    def invoke(self, call: McpAdapterCall) -> McpAdapterResponse:
        self.calls = [*self.calls, call]
        if self.fail:
            raise RuntimeError("synthetic MCP adapter failure")
        return McpAdapterResponse(_freeze_mapping(self.response, "adapter response"), self.side_effect)


@dataclass(frozen=True)
class ApprovalGrant:
    id: str
    action_digest: str
    requester_id: str
    approver_id: str
    expires_at: float


@dataclass
class ApprovalStore:
    """Хранит одноразовые exact-action grants текущего process."""

    clock: Callable[[], float] = time
    governance: GovernancePolicy = field(default_factory=GovernancePolicy.builtin)
    metrics: EfficiencyMetricsStore | None = field(default=None, repr=False, compare=False)
    _grants: dict[str, ApprovalGrant] = field(default_factory=dict, init=False, repr=False)
    _key: bytes = field(default_factory=lambda: secrets.token_bytes(32), init=False, repr=False)
    _lock: Lock = field(default_factory=Lock, init=False, repr=False)

    def bind(self, canonical_action: str) -> str:
        """Создаёт непубличный HMAC binding без хранения arguments."""

        return hmac.new(self._key, canonical_action.encode(), hashlib.sha256).hexdigest()

    def issue(
        self,
        action_digest: str,
        requester_id: str,
        approver: Principal,
        ttl_seconds: int,
    ) -> str:
        self.governance.require(approver, "mcp.approve")
        if approver.id == requester_id:
            raise PermissionError("self approval is forbidden")
        if not isinstance(ttl_seconds, int) or not 0 < ttl_seconds <= 300:
            raise ValueError("approval ttl must be from 1 to 300 seconds")
        grant_id = secrets.token_hex(16)
        grant = ApprovalGrant(grant_id, action_digest, requester_id, approver.id, self.clock() + ttl_seconds)
        with self._lock:
            self._grants = {**self._grants, grant_id: grant}
        return grant_id

    def consume(self, grant_id: str, action_digest: str, requester_id: str) -> bool:
        with self._lock:
            grant = self._grants.get(grant_id)
            self._grants = {key: value for key, value in self._grants.items() if key != grant_id}
        consumed = bool(
            grant
            and grant.expires_at > self.clock()
            and grant.requester_id == requester_id
            and hmac.compare_digest(grant.action_digest, action_digest)
        )
        if consumed and self.metrics is not None:
            self.metrics.append(EfficiencyMetricEvent(manual_approvals=1))
        return consumed


@dataclass(frozen=True)
class McpReceipt:
    status: str
    reason_code: str
    trace_id: str
    project_id: str
    capability_id: str
    capability_version: str
    server: str
    kind: str
    operation: str
    policy_outcome: str
    policy_version: str
    privacy_outcome: str
    approval_id: str
    side_effect: bool
    registry_version: str = "1.0"

    def to_payload(self) -> dict[str, object]:
        return {
            "schema_version": SCHEMA_VERSION, "status": self.status, "reason_code": self.reason_code,
            "trace_id": self.trace_id, "project_id": self.project_id, "capability_id": self.capability_id,
            "capability_version": self.capability_version, "server": self.server, "kind": self.kind,
            "operation": self.operation, "policy_outcome": self.policy_outcome,
            "policy_version": self.policy_version, "privacy_outcome": self.privacy_outcome,
            "approval_id": self.approval_id, "side_effect": self.side_effect,
            "registry_version": self.registry_version,
        }


@dataclass(frozen=True)
class McpResult:
    status: str
    data: Mapping[str, object] | None
    receipt: McpReceipt


@dataclass(frozen=True)
class McpDiscoveryResult:
    status: str
    capabilities: tuple[McpCapability, ...]
    receipt: McpReceipt


@dataclass(frozen=True)
class McpHub:
    """Аутентифицирует discovery/calls и применяет registry, policy, privacy и approvals."""

    authenticator: Authenticator
    registry: McpRegistry
    adapters: Mapping[str, McpAdapter]
    policy_engine: PolicyEngine
    privacy_pipeline: PrivacyPipeline
    approvals: ApprovalStore
    clock: Callable[[], float] = time
    enabled: bool = True
    metrics: EfficiencyMetricsStore | None = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        adapters = dict(self.adapters)
        if any(not callable(getattr(adapter, "invoke", None)) for adapter in adapters.values()):
            raise ValueError("MCP adapter must implement invoke")
        object.__setattr__(self, "adapters", MappingProxyType(adapters))

    def discover(self, token: str, project_id: str, purpose: str) -> McpDiscoveryResult:
        authentication = self.authenticator.authenticate(token)
        if not self.enabled or authentication.principal is None:
            receipt = self._receipt("deny", "authentication_required", self.authenticator.project_id)
            return McpDiscoveryResult("deny", (), receipt)
        principal = authentication.principal
        if principal.project_id != project_id or purpose not in self.policy_engine.allowed_purposes:
            return McpDiscoveryResult("deny", (), self._receipt("deny", "scope_denied", project_id))
        visible = tuple(
            capability for capability in self.registry.visible(principal.role, project_id)
            if self._discovery_policy_allows(principal, capability, purpose)
        )
        return McpDiscoveryResult("ok", visible, self._receipt("ok", "discovered", project_id))

    def approve(
        self,
        approver_token: str,
        requester_token: str,
        request: McpRequest,
        context: PrivacyContext,
        ttl_seconds: int,
    ) -> str:
        if not self.enabled:
            raise PermissionError("MCP Hub is disabled")
        approver_auth = self.authenticator.authenticate(approver_token)
        requester_auth = self.authenticator.authenticate(requester_token)
        if approver_auth.principal is None or requester_auth.principal is None:
            raise PermissionError("authentication required")
        requester = requester_auth.principal
        capability = self.registry.resolve(request.capability_id, request.capability_version)
        if capability is None or capability.operation == "read" or not capability.is_attested:
            raise PermissionError("capability is not approval eligible")
        if self._boundary_error(requester, request, context):
            raise PermissionError("approval project scope mismatch")
        if capability not in self.registry.visible(requester.role, request.project_id):
            raise PermissionError("requester is not entitled")
        if context.destination != capability.destination:
            raise PermissionError("approval destination mismatch")
        raw_arguments = _canonical_json(dict(request.arguments))
        if len(raw_arguments) > capability.max_argument_chars:
            raise PermissionError("approval arguments too large")
        if not _validate_object(capability.input_schema, dict(request.arguments)):
            raise PermissionError("approval arguments schema invalid")
        policy = self.policy_engine.decide(
            PolicyRequest(requester, "mcp.write", "mcp:tool", request.purpose, request.data_classification)
        )
        if policy.outcome != "approval_required":
            raise PermissionError("approval policy denied")
        privacy = self.privacy_pipeline.transform(raw_arguments, request.data_classification, context)
        if privacy.outcome == "deny":
            raise PermissionError("approval privacy denied")
        try:
            safe_arguments = json.loads(privacy.safe_content)
        except json.JSONDecodeError as error:
            raise PermissionError("approval transformed arguments invalid") from error
        if not _validate_object(capability.input_schema, safe_arguments):
            raise PermissionError("approval transformed schema invalid")
        return self.approvals.issue(
            self.approvals.bind(
                self._action_binding(requester.id, request, capability, policy.policy_version, safe_arguments)
            ),
            requester.id, approver_auth.principal, ttl_seconds,
        )

    def execute(self, token: str, request: McpRequest, context: PrivacyContext) -> McpResult:
        result = self._execute(token, request, context)
        if self.metrics is not None:
            self.metrics.append(EfficiencyMetricEvent(
                policy_denials=1 if result.status == "deny" else 0,
            ))
        return result

    def _execute(self, token: str, request: McpRequest, context: PrivacyContext) -> McpResult:
        authentication = self.authenticator.authenticate(token)
        if not self.enabled or authentication.principal is None:
            return self._deny(request, "authentication_required")
        principal = authentication.principal
        boundary_error = self._boundary_error(principal, request, context)
        if boundary_error:
            return self._deny(request, boundary_error)
        capability = self.registry.resolve(request.capability_id, request.capability_version)
        if capability is None:
            return self._deny(request, "unknown_capability")
        if capability not in self.registry.visible(principal.role, request.project_id):
            return self._deny(request, "capability_not_entitled", capability)
        if context.destination != capability.destination:
            return self._deny(request, "destination_scope_mismatch", capability)
        raw_arguments = _canonical_json(dict(request.arguments))
        if len(raw_arguments) > capability.max_argument_chars:
            return self._deny(request, "arguments_too_large", capability)
        if not _validate_object(capability.input_schema, dict(request.arguments)):
            return self._deny(request, "arguments_schema_invalid", capability)
        action = "mcp.read" if capability.operation == "read" else "mcp.write"
        resource = "mcp:resource" if capability.kind == "resource" else "mcp:tool"
        try:
            policy = self.policy_engine.decide(
                PolicyRequest(principal, action, resource, request.purpose, request.data_classification)
            )
        except Exception:
            return self._deny(request, "policy_engine_error", capability)
        expected_outcome = "allow" if action == "mcp.read" else "approval_required"
        if policy.outcome != expected_outcome:
            return self._deny(request, policy.reason_code, capability, policy.outcome, policy.policy_version)
        try:
            privacy = self.privacy_pipeline.transform(raw_arguments, request.data_classification, context)
        except Exception:
            return self._deny(request, "privacy_pipeline_error", capability, policy.outcome, policy.policy_version)
        if privacy.outcome == "deny":
            return self._deny(
                request, "arguments_privacy_denied", capability, policy.outcome, policy.policy_version,
                privacy.outcome,
            )
        try:
            safe_arguments = json.loads(privacy.safe_content)
        except json.JSONDecodeError:
            return self._deny(request, "transformed_arguments_invalid", capability)
        if not _validate_object(capability.input_schema, safe_arguments):
            return self._deny(request, "transformed_arguments_schema_invalid", capability)
        if action == "mcp.write":
            digest = self.approvals.bind(
                self._action_binding(principal.id, request, capability, policy.policy_version, safe_arguments)
            )
            if not request.approval_id:
                return self._deny(
                    request, "approval_required", capability, policy.outcome, policy.policy_version, privacy.outcome,
                )
            if not self.approvals.consume(request.approval_id, digest, principal.id):
                return self._deny(
                    request, "approval_invalid", capability, policy.outcome, policy.policy_version, privacy.outcome,
                )
        adapter = self.adapters.get(capability.server)
        if adapter is None:
            return self._deny(request, "adapter_unavailable", capability)
        call = McpAdapterCall(
            capability.id, capability.version, capability.operation,
            _freeze_mapping(safe_arguments, "safe arguments"), request.trace_id,
        )
        try:
            response = adapter.invoke(call)
            if not isinstance(response, McpAdapterResponse):
                raise TypeError("invalid MCP adapter response")
            if not isinstance(response.data, Mapping) or not isinstance(response.side_effect, bool):
                raise TypeError("invalid MCP adapter response fields")
            response_data = dict(response.data)
        except Exception:
            return self._deny(request, "adapter_error", capability)
        if capability.operation == "read" and response.side_effect:
            return self._deny(request, "read_side_effect_detected", capability)
        try:
            raw_result = _canonical_json(response_data)
        except ValueError:
            return self._deny(request, "result_invalid", capability)
        if len(raw_result) > capability.max_result_chars:
            return self._deny(request, "result_too_large", capability)
        try:
            inspected = self.privacy_pipeline.inspect_provider_output(
                raw_result, request.data_classification, context,
            )
        except Exception:
            return self._deny(request, "result_privacy_error", capability)
        if inspected.outcome == "deny":
            return self._deny(request, "result_privacy_denied", capability, privacy_outcome=inspected.outcome)
        try:
            safe_result = json.loads(inspected.safe_content)
        except json.JSONDecodeError:
            return self._deny(request, "result_invalid", capability)
        if not _validate_object(capability.output_schema, safe_result):
            return self._deny(request, "result_schema_invalid", capability)
        receipt = self._receipt(
            "ok", "completed", request.project_id, request, capability, policy.outcome, policy.policy_version,
            inspected.outcome, self._approval_reference(request.approval_id), response.side_effect,
        )
        return McpResult("ok", _deep_freeze(safe_result), receipt)

    @staticmethod
    def _boundary_error(principal: Principal, request: McpRequest, context: PrivacyContext) -> str:
        if request.project_id != principal.project_id or request.project_id != context.project_id:
            return "project_scope_mismatch"
        if request.purpose != context.purpose or principal.id != context.principal_id:
            return "principal_context_mismatch"
        return ""

    def _discovery_policy_allows(
        self,
        principal: Principal,
        capability: McpCapability,
        purpose: str,
    ) -> bool:
        action = "mcp.read" if capability.operation == "read" else "mcp.write"
        resource = "mcp:resource" if capability.kind == "resource" else "mcp:tool"
        try:
            decision = self.policy_engine.decide(
                PolicyRequest(principal, action, resource, purpose, "public")
            )
        except Exception:
            return False
        expected = "allow" if action == "mcp.read" else "approval_required"
        return decision.outcome == expected

    @staticmethod
    def _action_binding(
        requester_id: str,
        request: McpRequest,
        capability: McpCapability,
        policy_version: str,
        arguments: Mapping[str, object] | None = None,
    ) -> str:
        value = {
            "requester_id": requester_id, "project_id": request.project_id, "purpose": request.purpose,
            "capability_id": capability.id, "version": capability.version,
            "capability_digest": capability.descriptor_digest, "operation": capability.operation,
            "arguments": dict(arguments or request.arguments), "policy_version": policy_version,
        }
        return _canonical_json(value)

    def _deny(
        self,
        request: McpRequest,
        reason_code: str,
        capability: McpCapability | None = None,
        policy_outcome: str = "deny",
        policy_version: str = "1.0",
        privacy_outcome: str = "not_run",
    ) -> McpResult:
        receipt = self._receipt(
            "deny", reason_code, request.project_id, request, capability, policy_outcome, policy_version,
            privacy_outcome, self._approval_reference(request.approval_id),
        )
        return McpResult("deny", None, receipt)

    @staticmethod
    def _receipt(
        status: str,
        reason_code: str,
        project_id: str,
        request: McpRequest | None = None,
        capability: McpCapability | None = None,
        policy_outcome: str = "deny",
        policy_version: str = "1.0",
        privacy_outcome: str = "not_run",
        approval_id: str = "",
        side_effect: bool = False,
    ) -> McpReceipt:
        return McpReceipt(
            status, reason_code, request.trace_id if request else "", project_id,
            capability.id if capability else request.capability_id if request else "",
            capability.version if capability else request.capability_version if request else "",
            capability.server if capability else "", capability.kind if capability else "",
            capability.operation if capability else "", policy_outcome, policy_version, privacy_outcome,
            approval_id, side_effect,
        )

    @staticmethod
    def _approval_reference(approval_id: str) -> str:
        if not approval_id:
            return ""
        return hashlib.sha256(approval_id.encode()).hexdigest()[:16]


AuthenticatedMcpHub = McpHub
