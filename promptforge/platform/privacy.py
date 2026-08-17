"""Локальный privacy pipeline с неперсистентным scoped mapping vault."""

from __future__ import annotations

import re
import secrets
import time
from dataclasses import dataclass, field, replace
from typing import Callable, Protocol

from promptforge.platform.contracts import Principal, SCHEMA_VERSION
from promptforge.platform.governance import GovernancePolicy


_CLASSIFICATION_RANK = {"public": 0, "internal": 1, "confidential": 2, "restricted": 3, "regulated": 4}
_SECRET_PATTERNS = (
    ("provider_api_key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b")),
    ("password_assignment", re.compile(r"\b(?:password|passwd|pwd)\s*[:=]\s*[^\s]+", re.IGNORECASE)),
    (
        "private_key",
        re.compile(r"-----BEGIN (?:RSA |OPENSSH |EC )?PRIVATE KEY-----[\s\S]*?(?:-----END[^-]+-----|$)"),
    ),
)
_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_PHONE = re.compile(r"\+?\d[\d -]{8,}\d")
_PLACEHOLDER = re.compile(r"<PF_(?:EMAIL|PHONE)_[a-f0-9]{16}>")
_ANY_PLACEHOLDER = re.compile(r"<PF_[A-Z]+_[^>]+>")
_MAX_MAPPING_TTL_SECONDS = 86_400
_MAX_GRANT_TTL_SECONDS = 300


class _AuthenticationResult(Protocol):
    principal: Principal | None


class _PrincipalAuthenticator(Protocol):
    project_id: str

    def authenticate(self, token: str) -> _AuthenticationResult: ...


def _require_text(value: str, name: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a non-empty string")


def _detect_secrets(content: str) -> tuple[str, ...]:
    return tuple(name for name, pattern in _SECRET_PATTERNS if pattern.search(content))


def _redact_secrets(content: str) -> str:
    safe_content = content
    for _, pattern in _SECRET_PATTERNS:
        safe_content = pattern.sub("<PF_SECRET_REDACTED>", safe_content)
    return safe_content


@dataclass(frozen=True)
class PrivacyContext:
    """Ограничивает mapping одним project/execution/principal."""

    project_id: str
    execution_id: str
    principal_id: str
    purpose: str
    destination: str
    synthetic: bool
    ttl_seconds: int

    def __post_init__(self) -> None:
        for value, name in (
            (self.project_id, "project id"),
            (self.execution_id, "execution id"),
            (self.principal_id, "principal id"),
            (self.purpose, "purpose"),
        ):
            _require_text(value, name)
        if self.destination not in {"external", "local"}:
            raise ValueError(f"unsupported destination: {self.destination}")
        if not isinstance(self.synthetic, bool):
            raise ValueError("synthetic must be a boolean")
        if not isinstance(self.ttl_seconds, int) or not 0 < self.ttl_seconds <= _MAX_MAPPING_TTL_SECONDS:
            raise ValueError("mapping TTL must be between 1 and 86400 seconds")

    @property
    def scope(self) -> tuple[str, str, str, str, str]:
        """Возвращает точную область видимости mapping."""

        return self.project_id, self.execution_id, self.principal_id, self.purpose, self.destination


@dataclass(frozen=True)
class PrivacyReceipt:
    """Содержит только metadata, без исходного текста и mappings."""

    outcome: str
    effective_classification: str
    detections: tuple[str, ...]
    transformation_count: int

    def to_payload(self) -> dict[str, object]:
        """Возвращает versioned metadata-only wire payload."""

        return {
            "schema_version": SCHEMA_VERSION,
            "outcome": self.outcome,
            "effective_classification": self.effective_classification,
            "detections": list(self.detections),
            "transformation_count": self.transformation_count,
        }


@dataclass(frozen=True)
class PrivacyResult:
    """Возвращает безопасный текст и metadata-only receipt."""

    outcome: str
    effective_classification: str
    safe_content: str
    receipt: PrivacyReceipt


@dataclass(frozen=True)
class _Mapping:
    scope: tuple[str, str, str, str, str]
    raw_value: str
    expires_at: float


@dataclass(frozen=True)
class _Grant:
    scope: tuple[str, str, str, str, str]
    expires_at: float


@dataclass
class ScopedMappingVault:
    """Хранит plaintext mappings только в памяти процесса и в заданном scope."""

    clock: Callable[[], float] = time.time
    available: bool = True
    approved_rehydration_approvers: frozenset[tuple[str, str]] = frozenset()
    governance: GovernancePolicy = field(default_factory=GovernancePolicy.builtin)
    authenticator: _PrincipalAuthenticator | None = None
    _mappings: dict[str, _Mapping] = field(default_factory=dict, init=False, repr=False)
    _grants: dict[str, _Grant] = field(default_factory=dict, init=False, repr=False)

    @property
    def mapping_count(self) -> int:
        """Возвращает число активных и ещё не очищенных mappings."""

        self._purge_expired()
        return len(self._mappings)

    def _purge_expired(self) -> None:
        now = self.clock()
        self._mappings = {
            placeholder: mapping for placeholder, mapping in self._mappings.items() if mapping.expires_at > now
        }
        self._grants = {grant_id: grant for grant_id, grant in self._grants.items() if grant.expires_at > now}

    def placeholder(self, kind: str, raw_value: str, context: PrivacyContext) -> str:
        """Создаёт случайный placeholder, стабильный только внутри scope."""

        if not self.available:
            raise RuntimeError("mapping vault unavailable")
        self._purge_expired()
        for placeholder, mapping in self._mappings.items():
            if mapping.scope == context.scope and mapping.raw_value == raw_value and mapping.expires_at > self.clock():
                return placeholder
        placeholder = f"<PF_{kind}_{secrets.token_hex(8)}>"
        mapping = _Mapping(context.scope, raw_value, self.clock() + context.ttl_seconds)
        self._mappings = {**self._mappings, placeholder: mapping}
        return placeholder

    def issue_rehydration_grant(
        self,
        context: PrivacyContext,
        *,
        approver_token: str,
        ttl_seconds: int,
    ) -> str:
        """Выдаёт одноразовый opaque grant для точного scope."""

        if self.authenticator is None:
            raise PermissionError("rehydration authentication unavailable")
        authentication = self.authenticator.authenticate(approver_token)
        approver = authentication.principal
        if approver is None or (approver.id, approver.role) not in self.approved_rehydration_approvers:
            raise PermissionError("rehydration approver is not registered")
        if approver.project_id != context.project_id:
            raise PermissionError("rehydration approver project mismatch")
        self.governance.require(approver, "privacy.rehydrate")
        if not self.available:
            raise PermissionError("rehydration grant service unavailable")
        self._purge_expired()
        if not isinstance(ttl_seconds, int) or not 0 < ttl_seconds <= _MAX_GRANT_TTL_SECONDS:
            raise ValueError("rehydration grant TTL must be between 1 and 300 seconds")
        grant_id = secrets.token_urlsafe(24)
        self._grants = {**self._grants, grant_id: _Grant(context.scope, self.clock() + ttl_seconds)}
        return grant_id

    def placeholders_are_valid(self, content: str, context: PrivacyContext) -> bool:
        """Проверяет placeholders без раскрытия mappings."""

        self._purge_expired()
        for placeholder in _ANY_PLACEHOLDER.findall(content):
            mapping = self._mappings.get(placeholder)
            if mapping is None or mapping.scope != context.scope:
                return False
        return True

    def rehydrate(self, grant_id: str, content: str) -> str:
        """Восстанавливает известные placeholders и сразу потребляет grant."""

        grant = self._grants.get(grant_id)
        if grant is None:
            raise PermissionError("rehydration grant is missing or already consumed")
        self._grants = {stored_id: stored for stored_id, stored in self._grants.items() if stored_id != grant_id}
        if grant.expires_at <= self.clock():
            raise PermissionError("rehydration grant expired")
        if _detect_secrets(content):
            raise PermissionError("response secret detected before rehydration")
        untrusted_output = _PLACEHOLDER.sub("", content)
        if _EMAIL.search(untrusted_output) or _PHONE.search(untrusted_output):
            raise PermissionError("new response PII detected before rehydration")
        placeholders = tuple(_PLACEHOLDER.findall(content))
        restored = content
        for placeholder in placeholders:
            mapping = self._mappings.get(placeholder)
            if mapping is None or mapping.expires_at <= self.clock():
                raise PermissionError("placeholder mapping is missing or expired")
            if mapping.scope != grant.scope:
                raise PermissionError("placeholder scope does not match rehydration grant")
            restored = restored.replace(placeholder, mapping.raw_value)
        if "<PF_" in restored:
            raise PermissionError("placeholder mapping is missing or unsupported")
        return restored


@dataclass(frozen=True)
class PrivacyPipeline:
    """Классифицирует, блокирует secrets и применяет scoped placeholders."""

    vault: ScopedMappingVault
    approved_synthetic_scopes: frozenset[tuple[str, str, str, str, str]] = frozenset()

    def transform(self, content: str, declared_classification: str, context: PrivacyContext) -> PrivacyResult:
        """Возвращает safe representation без понижения класса."""

        _require_text(content, "content")
        if declared_classification not in _CLASSIFICATION_RANK:
            raise ValueError(f"unsupported data classification: {declared_classification}")
        secret_detections = _detect_secrets(content)
        if secret_detections:
            safe_content = _redact_secrets(content)
            return self._result("deny", "restricted", safe_content, secret_detections, len(secret_detections))

        email_values = tuple(dict.fromkeys(_EMAIL.findall(content)))
        phone_values = tuple(dict.fromkeys(value.strip() for value in _PHONE.findall(content)))
        if not email_values and not phone_values:
            return self._result("allow", declared_classification, content, (), 0)

        detections = tuple(
            (["synthetic_email"] if email_values else []) + (["synthetic_phone"] if phone_values else [])
        )
        synthetic_is_attested = context.synthetic and context.scope in self.approved_synthetic_scopes
        if not synthetic_is_attested:
            safe_content = _EMAIL.sub("<PF_EMAIL_REDACTED>", _PHONE.sub("<PF_PHONE_REDACTED>", content))
            outcome = "deny" if context.destination == "external" else "allow_with_transform"
            return self._result(outcome, "restricted", safe_content, ("pii",), len(email_values) + len(phone_values))

        safe_content = content
        try:
            for value in email_values:
                safe_content = safe_content.replace(value, self.vault.placeholder("EMAIL", value, context))
            for value in phone_values:
                safe_content = safe_content.replace(value, self.vault.placeholder("PHONE", value, context))
        except RuntimeError:
            redacted = _EMAIL.sub("<PF_EMAIL_REDACTED>", _PHONE.sub("<PF_PHONE_REDACTED>", content))
            return self._result("deny", "restricted", redacted, ("mapping_vault_unavailable",), 0)
        effective = self._max_classification(declared_classification, "internal")
        return self._result(
            "allow_with_transform", effective, safe_content, detections, len(email_values) + len(phone_values)
        )

    def inspect_provider_output(
        self,
        content: str,
        declared_classification: str,
        context: PrivacyContext,
    ) -> PrivacyResult:
        """Проверяет provider output до возврата пользователю."""

        if not self.vault.placeholders_are_valid(content, context):
            safe_content = _ANY_PLACEHOLDER.sub("<PF_PLACEHOLDER_REDACTED>", content)
            return self._result("deny", "restricted", safe_content, ("unknown_placeholder",), 0)
        return self.transform(content, declared_classification, replace(context, synthetic=False, destination="local"))

    @staticmethod
    def _max_classification(left: str, right: str) -> str:
        return left if _CLASSIFICATION_RANK[left] >= _CLASSIFICATION_RANK[right] else right

    @staticmethod
    def _result(
        outcome: str,
        classification: str,
        safe_content: str,
        detections: tuple[str, ...],
        transformation_count: int,
    ) -> PrivacyResult:
        receipt = PrivacyReceipt(outcome, classification, detections, transformation_count)
        return PrivacyResult(outcome, classification, safe_content, receipt)
