"""Provider-neutral local inference adapter with a closed network boundary."""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import http.client
import ipaddress
import json
import os
import time
from types import MappingProxyType
from typing import Any, Callable, Mapping, Protocol
from urllib.parse import urlsplit, urlunsplit

from promptforge.platform.gateway import (
    LogicalModel, ModelEndpoint, ModelRegistry, ProviderAdapter, ProviderCall, ProviderResponse,
)
from promptforge.platform.model_admission import (
    ModelAdmissionAuthority, ModelAdmissionDecision, ModelAdmissionManifest,
)


_ENV_PREFIX = "PF_LOCAL_INFERENCE_"
_ENV_KEYS = frozenset({
    "PF_LOCAL_INFERENCE_URL",
    "PF_LOCAL_INFERENCE_API_KEY",
    "PF_LOCAL_INFERENCE_MAX_RESPONSE_BYTES",
    "PF_LOCAL_INFERENCE_READINESS_TTL_SECONDS",
})
_DEPLOYMENT_FIELDS = frozenset({
    "schema_version", "endpoint_id", "provider", "provider_model", "logical_model", "region",
    "max_classification", "privacy_profile", "max_input_chars", "max_output_tokens", "max_output_bytes",
    "timeout_seconds", "destination",
})


@dataclass(frozen=True)
class LocalInferenceDeployment:
    """Описывает безопасную несекретную часть local deployment."""

    endpoint_id: str
    provider: str
    provider_model: str
    logical_model: str
    region: str
    max_classification: str
    privacy_profile: str
    max_input_chars: int
    max_output_tokens: int
    max_output_bytes: int
    timeout_seconds: int
    destination: str

    def __post_init__(self) -> None:
        if self.provider != "local-chat-compatible" or self.destination != "local":
            raise ValueError("local deployment provider and destination are fixed")
        ModelEndpoint(
            self.endpoint_id, self.provider, self.provider_model, self.region, self.max_classification,
            self.privacy_profile, self.max_input_chars, self.max_output_tokens, self.max_output_bytes,
            self.timeout_seconds, destination=self.destination,
        )
        LogicalModel(self.logical_model, (self.endpoint_id,))

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> LocalInferenceDeployment:
        """Строго разбирает versioned deployment manifest без credentials."""

        if not isinstance(payload, Mapping) or set(payload) != _DEPLOYMENT_FIELDS:
            raise ValueError("local inference deployment fields mismatch")
        if payload.get("schema_version") != "1.0":
            raise ValueError("unsupported local inference deployment schema")
        values = {key: value for key, value in payload.items() if key != "schema_version"}
        return cls(**values)

    def endpoint(self) -> ModelEndpoint:
        """Возвращает Model Gateway endpoint для local deployment."""

        return ModelEndpoint(
            self.endpoint_id, self.provider, self.provider_model, self.region, self.max_classification,
            self.privacy_profile, self.max_input_chars, self.max_output_tokens, self.max_output_bytes,
            self.timeout_seconds, destination=self.destination,
        )


@dataclass(frozen=True)
class LocalInferenceConfig:
    """Хранит проверенную runtime-конфигурацию локального inference endpoint."""

    endpoint_url: str
    api_key: str = field(default="", repr=False, compare=False)
    max_response_bytes: int = 100_000
    readiness_ttl_seconds: int = 60

    def __post_init__(self) -> None:
        parsed = urlsplit(self.endpoint_url)
        if (
            parsed.scheme != "http"
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
            or parsed.path != "/v1/chat/completions"
            or parsed.port is None
        ):
            raise ValueError("local inference URL must be credential-free loopback HTTP chat-completions endpoint")
        try:
            address = ipaddress.ip_address(parsed.hostname or "")
        except ValueError as error:
            raise ValueError("local inference host must be a numeric loopback address") from error
        if not address.is_loopback:
            raise ValueError("local inference host must be a numeric loopback address")
        if not 1 <= parsed.port <= 65_535:
            raise ValueError("local inference port is invalid")
        if self.api_key and (not self.api_key.strip() or "\r" in self.api_key or "\n" in self.api_key):
            raise ValueError("local inference API key is invalid")
        if (
            not isinstance(self.max_response_bytes, int)
            or isinstance(self.max_response_bytes, bool)
            or not 1 <= self.max_response_bytes <= 10_000_000
        ):
            raise ValueError("local inference response limit is invalid")
        if (
            not isinstance(self.readiness_ttl_seconds, int)
            or isinstance(self.readiness_ttl_seconds, bool)
            or not 1 <= self.readiness_ttl_seconds <= 300
        ):
            raise ValueError("local inference readiness TTL is invalid")

    @classmethod
    def from_env(cls, environment: Mapping[str, str] | None = None) -> LocalInferenceConfig:
        """Создаёт конфигурацию только из разрешённых environment variables."""

        source = os.environ if environment is None else environment
        unknown = sorted(key for key in source if key.startswith(_ENV_PREFIX) and key not in _ENV_KEYS)
        if unknown:
            raise ValueError(f"unknown local inference environment: {unknown[0]}")
        endpoint_url = source.get("PF_LOCAL_INFERENCE_URL", "")
        if not endpoint_url:
            raise ValueError("PF_LOCAL_INFERENCE_URL is required")
        raw_limit = source.get("PF_LOCAL_INFERENCE_MAX_RESPONSE_BYTES", "100000")
        try:
            limit = int(raw_limit)
        except (TypeError, ValueError) as error:
            raise ValueError("PF_LOCAL_INFERENCE_MAX_RESPONSE_BYTES must be an integer") from error
        try:
            readiness_ttl = int(source.get("PF_LOCAL_INFERENCE_READINESS_TTL_SECONDS", "60"))
        except (TypeError, ValueError) as error:
            raise ValueError("PF_LOCAL_INFERENCE_READINESS_TTL_SECONDS must be an integer") from error
        return cls(endpoint_url, source.get("PF_LOCAL_INFERENCE_API_KEY", ""), limit, readiness_ttl)


class LocalInferenceTransport(Protocol):
    """Isolates HTTP transport for deterministic adapter tests."""

    def post_json(
        self,
        url: str,
        headers: dict[str, str],
        body: bytes,
        timeout_seconds: int,
        max_response_bytes: int,
    ) -> bytes: ...

    def get_json(
        self, url: str, headers: dict[str, str], timeout_seconds: int, max_response_bytes: int,
    ) -> bytes: ...


@dataclass(frozen=True)
class LoopbackHttpTransport:
    """Выполняет один POST напрямую на loopback без proxy и redirects."""

    def post_json(
        self,
        url: str,
        headers: dict[str, str],
        body: bytes,
        timeout_seconds: int,
        max_response_bytes: int,
    ) -> bytes:
        return self._request_json("POST", url, headers, body, timeout_seconds, max_response_bytes)

    def get_json(
        self, url: str, headers: dict[str, str], timeout_seconds: int, max_response_bytes: int,
    ) -> bytes:
        return self._request_json("GET", url, headers, None, timeout_seconds, max_response_bytes)

    @staticmethod
    def _request_json(
        method: str, url: str, headers: dict[str, str], body: bytes | None, timeout_seconds: int,
        max_response_bytes: int,
    ) -> bytes:
        parsed = urlsplit(url)
        try:
            address = ipaddress.ip_address(parsed.hostname or "")
            valid_port = parsed.port is not None and 1 <= parsed.port <= 65_535
        except ValueError:
            address, valid_port = None, False
        valid_target = (
            parsed.scheme == "http"
            and address is not None
            and address.is_loopback
            and valid_port
            and parsed.username is None
            and parsed.password is None
            and not parsed.query
            and not parsed.fragment
            and (method, parsed.path) in {("GET", "/v1/models"), ("POST", "/v1/chat/completions")}
        )
        if not valid_target:
            raise RuntimeError("local inference transport target is not allowed")
        connection = http.client.HTTPConnection(parsed.hostname, parsed.port, timeout=timeout_seconds)
        try:
            connection.request(method, parsed.path, body=body, headers=headers)
            response = connection.getresponse()
            content_type = response.getheader("Content-Type", "").split(";", 1)[0].strip().lower()
            content_length = response.getheader("Content-Length")
            if response.status != 200 or content_type != "application/json":
                raise RuntimeError("local inference returned an invalid response")
            if content_length is not None:
                try:
                    if int(content_length) > max_response_bytes:
                        raise RuntimeError("local inference response exceeds configured limit")
                except ValueError as error:
                    raise RuntimeError("local inference returned an invalid content length") from error
            payload = response.read(max_response_bytes + 1)
            if len(payload) > max_response_bytes:
                raise RuntimeError("local inference response exceeds configured limit")
            return payload
        except Exception:
            raise RuntimeError("local inference request failed") from None
        finally:
            connection.close()


@dataclass(frozen=True)
class LocalReadinessReceipt:
    """Подтверждает exact model identity на короткий срок без prompt/response data."""

    model: str
    revision: str
    artifact_sha256: str
    endpoint_fingerprint: str
    checked_at: float
    expires_at: float


@dataclass(frozen=True)
class LocalChatAdapter:
    """Maps gateway calls to the local chat-completions protocol."""

    config: LocalInferenceConfig
    transport: LocalInferenceTransport = field(default_factory=LoopbackHttpTransport)
    readiness: LocalReadinessReceipt | None = None
    clock: Callable[[], float] = field(default=time.time, repr=False, compare=False)

    @classmethod
    def prepare(
        cls,
        config: LocalInferenceConfig,
        expected_model: str,
        transport: LocalInferenceTransport | None = None,
        readiness_ttl_seconds: int | None = None,
        clock: Callable[[], float] = time.time,
        expected_revision: str = "",
        expected_artifact_sha256: str = "",
    ) -> LocalChatAdapter:
        """Performs readiness preflight and returns a short-lived receipt."""

        actual_transport = transport or LoopbackHttpTransport()
        parsed = urlsplit(config.endpoint_url)
        models_url = urlunsplit((parsed.scheme, parsed.netloc, "/v1/models", "", ""))
        raw_models = actual_transport.get_json(models_url, cls._headers(config), 5, config.max_response_bytes)
        models = cls._parse_models(raw_models)
        identity = models.get(expected_model)
        if identity is None:
            raise RuntimeError("local inference expected model is not ready")
        if (expected_revision or expected_artifact_sha256) and identity != (
            expected_revision, expected_artifact_sha256,
        ):
            raise RuntimeError("local inference runtime identity does not match admission")
        ttl = config.readiness_ttl_seconds if readiness_ttl_seconds is None else readiness_ttl_seconds
        if not isinstance(ttl, int) or isinstance(ttl, bool) or not 1 <= ttl <= 300:
            raise ValueError("local inference readiness TTL is invalid")
        checked_at = clock()
        fingerprint = hashlib.sha256(config.endpoint_url.encode("utf-8")).hexdigest()
        return cls(
            config, actual_transport,
            LocalReadinessReceipt(
                expected_model, identity[0], identity[1], fingerprint, checked_at, checked_at + ttl,
            ), clock,
        )

    def invoke(self, call: ProviderCall) -> ProviderResponse:
        fingerprint = hashlib.sha256(self.config.endpoint_url.encode("utf-8")).hexdigest()
        if (
            self.readiness is None
            or self.readiness.model != call.model
            or self.readiness.endpoint_fingerprint != fingerprint
            or self.clock() >= self.readiness.expires_at
        ):
            raise RuntimeError("local inference is not ready")
        headers = self._headers(self.config)
        body = json.dumps({
            "model": call.model,
            "messages": [{"role": "user", "content": call.content}],
            "max_tokens": call.max_output_tokens,
            "stream": False,
        }, ensure_ascii=True, separators=(",", ":")).encode("utf-8")
        raw_response = self.transport.post_json(
            self.config.endpoint_url, headers, body, call.timeout_seconds, self.config.max_response_bytes,
        )
        response = self._parse_response(raw_response)
        if response.output_tokens > call.max_output_tokens:
            raise ValueError("local inference response exceeds requested token budget")
        return response

    @staticmethod
    def _headers(config: LocalInferenceConfig) -> dict[str, str]:
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        return {**headers, "Authorization": f"Bearer {config.api_key}"} if config.api_key else headers

    @staticmethod
    def _parse_models(raw_response: bytes) -> dict[str, tuple[str, str]]:
        payload = LocalChatAdapter._load_json(raw_response)
        data = payload.get("data") if isinstance(payload, dict) else None
        if not isinstance(data, list) or len(data) > 1_000:
            raise ValueError("local inference model catalog is invalid")
        models: dict[str, tuple[str, str]] = {}
        for item in data:
            if not isinstance(item, dict) or not isinstance(item.get("id"), str) or not item["id"].strip():
                raise ValueError("local inference model identity is invalid")
            revision = item.get("revision", "")
            artifact_sha256 = item.get("artifact_sha256", "")
            if not isinstance(revision, str) or not isinstance(artifact_sha256, str):
                raise ValueError("local inference model identity metadata is invalid")
            if item["id"] in models:
                raise ValueError("duplicate local inference model identity")
            models[item["id"]] = (revision, artifact_sha256)
        return models

    @staticmethod
    def _parse_response(raw_response: bytes) -> ProviderResponse:
        payload = LocalChatAdapter._load_json(raw_response)
        if not isinstance(payload, dict):
            raise ValueError("local inference response must be an object")
        choices, usage = payload.get("choices"), payload.get("usage")
        if not isinstance(choices, list) or not choices or not isinstance(choices[0], dict):
            raise ValueError("local inference choices are invalid")
        message = choices[0].get("message")
        content = message.get("content") if isinstance(message, dict) else None
        if not isinstance(content, str):
            raise ValueError("local inference content is invalid")
        if not isinstance(usage, dict):
            raise ValueError("local inference usage is invalid")
        input_tokens, output_tokens = usage.get("prompt_tokens"), usage.get("completion_tokens")
        token_values = (input_tokens, output_tokens)
        if any(not isinstance(value, int) or isinstance(value, bool) or value < 0 for value in token_values):
            raise ValueError("local inference token usage is invalid")
        return ProviderResponse(content, input_tokens, output_tokens)

    @staticmethod
    def _load_json(raw_response: bytes) -> object:
        def strict_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
            if len({key for key, _ in pairs}) != len(pairs):
                raise ValueError("local inference JSON contains duplicate keys")
            return dict(pairs)

        try:
            return json.loads(raw_response, object_pairs_hook=strict_object)
        except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, ValueError) as error:
            raise ValueError("local inference response is not valid JSON") from error


def build_local_inference(
    deployment: LocalInferenceDeployment,
    environment: Mapping[str, str] | None = None,
    transport: LocalInferenceTransport | None = None,
    admission_manifest: ModelAdmissionManifest | None = None,
    admission: ModelAdmissionDecision | None = None,
    admission_authority: ModelAdmissionAuthority | None = None,
) -> tuple[ModelRegistry, Mapping[str, ProviderAdapter]]:
    """Собирает registry и adapter map, получая runtime URL/key только из environment."""

    config = LocalInferenceConfig.from_env(environment)
    if (
        admission is None
        or admission_manifest is None
        or admission_authority is None
        or admission.model_id != deployment.provider_model
        or not admission.artifact_sha256
        or not admission_authority.verify(admission, admission_manifest)
    ):
        raise PermissionError("local model admission is missing or invalid")
    if config.max_response_bytes > deployment.max_output_bytes:
        raise ValueError("runtime response limit exceeds attested endpoint output limit")
    adapter = LocalChatAdapter.prepare(
        config, deployment.provider_model, transport or LoopbackHttpTransport(),
        expected_revision=admission.revision, expected_artifact_sha256=admission.artifact_sha256,
    )
    registry = ModelRegistry(
        (deployment.endpoint(),),
        (LogicalModel(deployment.logical_model, (deployment.endpoint_id,)),),
    )
    return registry, MappingProxyType({deployment.provider: adapter})
