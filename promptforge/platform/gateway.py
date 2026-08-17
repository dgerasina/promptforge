"""Provider-neutral Model Gateway с policy/privacy enforcement."""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import hmac
import secrets
from types import MappingProxyType
from typing import Mapping, Protocol

from promptforge.platform.contracts import ModelRequest, PolicyRequest, Principal, SCHEMA_VERSION
from promptforge.platform.policy import PolicyEngine
from promptforge.platform.privacy import PrivacyContext, PrivacyPipeline


_CLASSIFICATION_RANK = {"public": 0, "internal": 1, "confidential": 2, "restricted": 3, "regulated": 4}


@dataclass(frozen=True)
class ModelEndpoint:
    """Описывает deployment, скрытый от model client."""

    id: str
    provider: str
    model: str
    region: str
    max_classification: str
    privacy_profile: str
    max_input_chars: int
    max_output_tokens: int
    max_output_bytes: int = 100_000
    timeout_seconds: int = 30
    enabled: bool = True
    destination: str = "external"

    def __post_init__(self) -> None:
        text_fields = (self.id, self.provider, self.model, self.region, self.privacy_profile)
        if any(not isinstance(value, str) or not value.strip() for value in text_fields):
            raise ValueError("model endpoint text fields must be non-empty")
        if self.max_classification not in _CLASSIFICATION_RANK:
            raise ValueError("unknown model endpoint classification")
        if self.destination not in {"external", "local"}:
            raise ValueError("unsupported model endpoint destination")
        limits = (self.max_input_chars, self.max_output_tokens, self.max_output_bytes, self.timeout_seconds)
        if any(isinstance(value, bool) or not isinstance(value, int) or value <= 0 for value in limits):
            raise ValueError("model endpoint limits must be positive integers")


@dataclass(frozen=True)
class LogicalModel:
    """Связывает logical model с упорядоченными endpoint candidates."""

    id: str
    endpoint_ids: tuple[str, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.id, str) or not self.id.strip():
            raise ValueError("logical model id must be non-empty")
        if not self.endpoint_ids or any(not endpoint_id for endpoint_id in self.endpoint_ids):
            raise ValueError("logical model endpoints must be non-empty")
        if len(set(self.endpoint_ids)) != len(self.endpoint_ids):
            raise ValueError("duplicate endpoint in logical model")


@dataclass(frozen=True)
class ModelRegistry:
    """Хранит immutable endpoints и logical routes."""

    endpoints: tuple[ModelEndpoint, ...]
    logical_models: tuple[LogicalModel, ...]

    def __post_init__(self) -> None:
        if len({endpoint.id for endpoint in self.endpoints}) != len(self.endpoints):
            raise ValueError("duplicate model endpoint id")
        if len({model.id for model in self.logical_models}) != len(self.logical_models):
            raise ValueError("duplicate logical model id")
        endpoint_ids = {endpoint.id for endpoint in self.endpoints}
        for logical_model in self.logical_models:
            unknown = set(logical_model.endpoint_ids) - endpoint_ids
            if unknown:
                raise ValueError(f"logical model references unknown endpoint: {sorted(unknown)[0]}")
            destinations = {
                endpoint.destination for endpoint in self.endpoints if endpoint.id in logical_model.endpoint_ids
            }
            if len(destinations) != 1:
                raise ValueError("logical model cannot contain mixed destinations")

    def candidates(self, logical_model: str) -> tuple[ModelEndpoint, ...]:
        """Возвращает кандидатов или пустой tuple для unknown route."""

        route = next((model for model in self.logical_models if model.id == logical_model), None)
        if route is None:
            return ()
        by_id = {endpoint.id: endpoint for endpoint in self.endpoints}
        return tuple(by_id[endpoint_id] for endpoint_id in route.endpoint_ids if endpoint_id in by_id)


@dataclass(frozen=True)
class ProviderCall:
    """Передаёт adapter только model payload без credentials."""

    model: str
    content: str
    trace_id: str
    timeout_seconds: int
    max_output_tokens: int


@dataclass(frozen=True)
class ProviderResponse:
    """Нормализует provider response и usage."""

    content: str
    input_tokens: int
    output_tokens: int


class ProviderAdapter(Protocol):
    """Изолирует provider SDK/credentials от gateway contract."""

    def invoke(self, call: ProviderCall) -> ProviderResponse:
        """Выполняет один provider call."""


@dataclass
class FakeProviderAdapter:
    """Детерминированный adapter без сети и credentials."""

    response_text: str
    fail: bool = False
    calls: list[ProviderCall] = field(default_factory=list, init=False)

    def invoke(self, call: ProviderCall) -> ProviderResponse:
        self.calls = [*self.calls, call]
        if self.fail:
            raise RuntimeError("provider unavailable")
        return ProviderResponse(
            self.response_text,
            max(1, len(call.content) // 4),
            max(1, len(self.response_text) // 4),
        )


@dataclass(frozen=True)
class GatewayReceipt:
    """Фиксирует route/policy/usage без prompt и provider credentials."""

    status: str
    reason_code: str
    trace_id: str
    logical_model: str
    endpoint_id: str
    provider: str
    provider_model: str
    policy_outcome: str
    policy_version: str
    privacy_outcome: str
    fallback_count: int
    input_tokens: int
    output_tokens: int
    identity_attestation: str = ""
    destination: str = "external"

    def __post_init__(self) -> None:
        if self.destination not in {"external", "local"}:
            raise ValueError("unsupported gateway receipt destination")

    def to_payload(self) -> dict[str, object]:
        return {
            "schema_version": SCHEMA_VERSION,
            "status": self.status,
            "reason_code": self.reason_code,
            "trace_id": self.trace_id,
            "logical_model": self.logical_model,
            "endpoint_id": self.endpoint_id,
            "provider": self.provider,
            "provider_model": self.provider_model,
            "policy_outcome": self.policy_outcome,
            "policy_version": self.policy_version,
            "privacy_outcome": self.privacy_outcome,
            "fallback_count": self.fallback_count,
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "identity_attestation": self.identity_attestation,
            "destination": self.destination,
        }


@dataclass(frozen=True)
class GatewayResult:
    """Возвращает safe response и metadata receipt."""

    status: str
    content: str
    receipt: GatewayReceipt
    privacy_redactions: int = 0
    model_calls: int = 0


@dataclass(frozen=True)
class ModelGateway:
    """Применяет policy/privacy до routing и запрещает unsafe fallback."""

    registry: ModelRegistry
    adapters: Mapping[str, ProviderAdapter]
    policy_engine: PolicyEngine
    privacy_pipeline: PrivacyPipeline
    allowed_regions: frozenset[str]
    enabled: bool = True
    attestation_key: bytes = field(default_factory=lambda: secrets.token_bytes(32), repr=False, compare=False)

    def __post_init__(self) -> None:
        adapter_copy = dict(self.adapters)
        if any(not isinstance(provider, str) or not provider.strip() for provider in adapter_copy):
            raise ValueError("adapter provider ids must be non-empty")
        if any(not callable(getattr(adapter, "invoke", None)) for adapter in adapter_copy.values()):
            raise ValueError("provider adapter must implement invoke")
        if not isinstance(self.attestation_key, bytes) or len(self.attestation_key) < 32:
            raise ValueError("gateway attestation key must contain at least 32 bytes")
        object.__setattr__(self, "adapters", MappingProxyType(adapter_copy))

    def _invoke_trusted(
        self,
        principal: Principal,
        request: ModelRequest,
        context: PrivacyContext,
    ) -> GatewayResult:
        """Выполняет внутренний вызов для проверенного Principal."""

        boundary_error = self._validate_boundary(principal, request, context)
        if boundary_error:
            return self._deny(request, boundary_error)
        try:
            policy = self.policy_engine.decide(
                PolicyRequest(
                    principal, "model.invoke", f"model:{request.route}", request.purpose,
                    request.data_classification,
                )
            )
        except Exception:
            return self._deny(request, "policy_engine_error")
        if policy.outcome not in {"allow", "allow_with_transform"}:
            return self._deny(request, policy.reason_code, policy.outcome, policy.policy_version)

        try:
            privacy = self.privacy_pipeline.transform(request.content, request.data_classification, context)
        except Exception:
            return self._deny(request, "privacy_pipeline_error", policy.outcome, policy.policy_version)
        if privacy.outcome == "deny":
            return self._deny(
                request, "privacy_denied", policy.outcome, policy.policy_version, privacy.outcome,
                privacy_redactions=privacy.receipt.transformation_count,
            )
        if policy.outcome == "allow_with_transform" and privacy.outcome != "allow_with_transform":
            return self._deny(
                request, "required_transform_missing", policy.outcome, policy.policy_version, privacy.outcome,
                privacy_redactions=privacy.receipt.transformation_count,
            )

        configured_candidates = self.registry.candidates(request.logical_model)
        if not configured_candidates:
            return self._deny(
                request, "unknown_logical_model", policy.outcome, policy.policy_version, privacy.outcome,
                privacy_redactions=privacy.receipt.transformation_count,
            )
        required_privacy_profile = configured_candidates[0].privacy_profile
        candidates = self._eligible_candidates(request, privacy.effective_classification, privacy.safe_content)
        if not candidates:
            return self._deny(
                request, "no_eligible_model", policy.outcome, policy.policy_version, privacy.outcome,
                privacy_redactions=privacy.receipt.transformation_count,
            )
        failures = 0
        attempts = 0
        for endpoint in candidates:
            if endpoint.privacy_profile != required_privacy_profile:
                continue
            adapter = self.adapters.get(endpoint.provider)
            if adapter is None:
                failures += 1
                continue
            call = ProviderCall(
                endpoint.model,
                privacy.safe_content,
                request.trace_id,
                endpoint.timeout_seconds,
                request.max_output_tokens,
            )
            try:
                attempts += 1
                provider_response = adapter.invoke(call)
            except Exception:
                failures += 1
                continue
            if not self._provider_response_is_valid(
                provider_response, request.max_output_tokens, endpoint.max_output_bytes,
            ):
                return self._deny(
                    request, "invalid_provider_response", policy.outcome, policy.policy_version, privacy.outcome,
                    privacy_redactions=privacy.receipt.transformation_count, model_calls=attempts,
                )
            inspected = self.privacy_pipeline.inspect_provider_output(
                provider_response.content, privacy.effective_classification, context,
            )
            if inspected.outcome == "deny":
                return self._deny(
                    request, "provider_output_denied", policy.outcome, policy.policy_version, inspected.outcome,
                    privacy_redactions=privacy.receipt.transformation_count + inspected.receipt.transformation_count,
                    model_calls=attempts,
                )
            unsigned = GatewayReceipt(
                "ok", "completed", request.trace_id, request.logical_model, endpoint.id, endpoint.provider,
                endpoint.model, policy.outcome, policy.policy_version, privacy.outcome, failures,
                provider_response.input_tokens, provider_response.output_tokens, destination=request.route,
            )
            receipt = GatewayReceipt(
                **{**unsigned.__dict__, "identity_attestation": self._attest_identity(unsigned)}
            )
            return GatewayResult(
                "ok", inspected.safe_content, receipt,
                privacy.receipt.transformation_count + inspected.receipt.transformation_count, attempts,
            )
        return self._deny(
            request, "providers_unavailable", policy.outcome, policy.policy_version, privacy.outcome,
            privacy_redactions=privacy.receipt.transformation_count, model_calls=attempts,
        )

    @staticmethod
    def _provider_response_is_valid(response: object, max_output_tokens: int, max_output_bytes: int) -> bool:
        content = getattr(response, "content", None)
        input_tokens = getattr(response, "input_tokens", None)
        output_tokens = getattr(response, "output_tokens", None)
        token_values = (input_tokens, output_tokens)
        return (
            isinstance(content, str)
            and len(content.encode("utf-8")) <= max_output_bytes
            and all(isinstance(value, int) and not isinstance(value, bool) and value >= 0 for value in token_values)
            and output_tokens <= max_output_tokens
        )

    def _validate_boundary(
        self,
        principal: Principal,
        request: ModelRequest,
        context: PrivacyContext,
    ) -> str:
        if not self.enabled:
            return "model_gateway_disabled"
        if context.destination != request.route:
            return "destination_scope_mismatch"
        if request.project_id != principal.project_id or request.project_id != context.project_id:
            return "project_scope_mismatch"
        if request.purpose != context.purpose or principal.id != context.principal_id:
            return "principal_context_mismatch"
        return ""

    def _eligible_candidates(
        self,
        request: ModelRequest,
        classification: str,
        safe_content: str,
    ) -> tuple[ModelEndpoint, ...]:
        candidates = self.registry.candidates(request.logical_model)
        return tuple(
            endpoint
            for endpoint in candidates
            if endpoint.enabled
            and endpoint.destination == request.route
            and endpoint.region in self.allowed_regions
            and _CLASSIFICATION_RANK[classification] <= _CLASSIFICATION_RANK[endpoint.max_classification]
            and len(safe_content) <= endpoint.max_input_chars
            and request.max_output_tokens <= endpoint.max_output_tokens
        )

    def verify_identity(self, receipt: GatewayReceipt) -> bool:
        """Проверяет, что provider/endpoint identity выпущена этим Gateway."""

        return bool(
            receipt.status == "ok" and receipt.identity_attestation
            and hmac.compare_digest(receipt.identity_attestation, self._attest_identity(receipt))
        )

    def _attest_identity(self, receipt: GatewayReceipt) -> str:
        message = "\0".join((
            receipt.status, receipt.reason_code, receipt.trace_id, receipt.logical_model, receipt.endpoint_id, receipt.provider,
            receipt.provider_model, receipt.policy_outcome, receipt.policy_version, receipt.privacy_outcome,
            str(receipt.fallback_count), str(receipt.input_tokens), str(receipt.output_tokens), receipt.destination,
        )).encode("utf-8")
        return "hmac-sha256:" + hmac.new(self.attestation_key, message, hashlib.sha256).hexdigest()

    @staticmethod
    def _deny(
        request: ModelRequest,
        reason_code: str,
        policy_outcome: str = "deny",
        policy_version: str = "1.0",
        privacy_outcome: str = "not_run",
        *,
        privacy_redactions: int = 0,
        model_calls: int = 0,
    ) -> GatewayResult:
        receipt = GatewayReceipt(
            "deny", reason_code, request.trace_id, request.logical_model, "", "", "", policy_outcome,
            policy_version, privacy_outcome, 0, 0, 0, destination=request.route,
        )
        return GatewayResult("deny", "", receipt, privacy_redactions, model_calls)
