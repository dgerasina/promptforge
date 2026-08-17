"""Fail-closed embedded и optional OIDC authentication boundaries."""

from __future__ import annotations

import base64
from dataclasses import dataclass, field
import hashlib
import hmac
import json
import os
import re
import secrets
from time import time
from types import MappingProxyType
from typing import Callable, Mapping, Protocol

from promptforge.platform.contracts import Principal, ROLES, SCHEMA_VERSION
from promptforge.platform.gateway import GatewayResult, ModelGateway
from promptforge.platform.contracts import ModelRequest
from promptforge.platform.privacy import PrivacyContext


_REGISTRY_FIELDS = frozenset({
    "schema_version", "auth_version", "issuer", "audience", "project_id", "session_ttl_seconds",
    "session_epoch", "principals",
})
_PRINCIPAL_FIELDS = frozenset({"id", "role", "enabled"})
_SESSION_FIELDS = frozenset({"v", "iss", "aud", "sub", "project", "iat", "exp", "epoch", "nonce"})
_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_EMBEDDED_AUTH_ENV_PREFIX = "PF_EMBEDDED_AUTH_"
_EMBEDDED_AUTH_ENV_KEYS = frozenset({"PF_EMBEDDED_AUTH_KEY_HEX"})


def embedded_auth_key_from_env(environment: Mapping[str, str] | None = None) -> bytes:
    """Загружает signing key только из разрешённой environment variable."""

    source = os.environ if environment is None else environment
    unknown = sorted(
        key for key in source if key.startswith(_EMBEDDED_AUTH_ENV_PREFIX) and key not in _EMBEDDED_AUTH_ENV_KEYS
    )
    if unknown:
        raise ValueError(f"unknown embedded auth environment: {unknown[0]}")
    encoded = source.get("PF_EMBEDDED_AUTH_KEY_HEX", "")
    if not re.fullmatch(r"[0-9a-f]{64,128}", encoded):
        raise ValueError("PF_EMBEDDED_AUTH_KEY_HEX must contain 32-64 lowercase hex bytes")
    return bytes.fromhex(encoded)


class Authenticator(Protocol):
    """Общая fail-closed граница для embedded и optional OIDC authentication."""

    project_id: str

    def authenticate(self, token: str) -> AuthenticationResult: ...


@dataclass(frozen=True)
class OIDCClaims:
    """Хранит claims после проверки token verifier."""

    issuer: str
    audiences: tuple[str, ...]
    subject: str
    expires_at: int
    issued_at: int
    email_verified: bool
    groups: tuple[str, ...]
    project_id: str
    not_before: int = 0

    def __post_init__(self) -> None:
        text_claims = (self.issuer, self.subject, self.project_id)
        if any(not isinstance(value, str) or not value.strip() for value in text_claims):
            raise ValueError("OIDC text claims must be non-empty")
        if not self.audiences or any(not isinstance(value, str) or not value for value in self.audiences):
            raise ValueError("OIDC audiences must be non-empty")
        if not isinstance(self.groups, (tuple, list)) or any(not isinstance(value, str) for value in self.groups):
            raise ValueError("OIDC groups must be an array of strings")
        timestamps = (self.expires_at, self.issued_at, self.not_before)
        if any(isinstance(value, bool) or not isinstance(value, int) for value in timestamps):
            raise ValueError("OIDC timestamps must be integers")
        if not isinstance(self.email_verified, bool):
            raise ValueError("email_verified must be a boolean")
        object.__setattr__(self, "audiences", tuple(self.audiences))
        object.__setattr__(self, "groups", tuple(self.groups))


class OIDCTokenVerifier(Protocol):
    """Делегирует проверку JWT/JWKS стандартной библиотеке."""

    def verify(self, token: str) -> OIDCClaims:
        """Проверяет signature/algorithm/key и возвращает нормализованные claims."""


@dataclass(frozen=True)
class FakeOIDCTokenVerifier:
    """Проверяет synthetic fixtures без сети и реальных tokens."""

    tokens: Mapping[str, OIDCClaims]
    available: bool = True

    def __post_init__(self) -> None:
        object.__setattr__(self, "tokens", MappingProxyType(dict(self.tokens)))

    def verify(self, token: str) -> OIDCClaims:
        if not self.available:
            raise RuntimeError("OIDC verifier unavailable")
        try:
            return self.tokens[token]
        except KeyError as error:
            raise ValueError("invalid OIDC token") from error


@dataclass(frozen=True)
class AuthReceipt:
    """Metadata-only результат аутентификации."""

    status: str
    reason_code: str
    issuer: str
    principal_id: str
    project_id: str
    role: str
    expires_at: int
    auth_version: str = "1.0"

    def to_payload(self) -> dict[str, object]:
        return {
            "schema_version": SCHEMA_VERSION,
            "status": self.status,
            "reason_code": self.reason_code,
            "issuer": self.issuer,
            "principal_id": self.principal_id,
            "project_id": self.project_id,
            "role": self.role,
            "expires_at": self.expires_at,
            "auth_version": self.auth_version,
        }


@dataclass(frozen=True)
class AuthenticationResult:
    """Выдаёт Principal только после полного OIDC/RBAC validation."""

    status: str
    principal: Principal | None
    receipt: AuthReceipt


@dataclass(frozen=True)
class EmbeddedPrincipal:
    """Описывает одну server-side роль во встроенном registry."""

    id: str
    role: str
    enabled: bool

    def __post_init__(self) -> None:
        if not isinstance(self.id, str) or not _SAFE_ID.fullmatch(self.id):
            raise ValueError("embedded principal id is invalid")
        if self.role not in ROLES or not isinstance(self.enabled, bool):
            raise ValueError("embedded principal role or state is invalid")


@dataclass(frozen=True)
class EmbeddedRoleRegistry:
    """Хранит versioned роли и global session epoch в репозитории."""

    auth_version: str
    issuer: str
    audience: str
    project_id: str
    session_ttl_seconds: int
    session_epoch: int
    principals: tuple[EmbeddedPrincipal, ...]

    def __post_init__(self) -> None:
        for value in (self.auth_version, self.issuer, self.audience, self.project_id):
            if not isinstance(value, str) or not _SAFE_ID.fullmatch(value):
                raise ValueError("embedded auth registry identity is invalid")
        if (
            not isinstance(self.session_ttl_seconds, int) or isinstance(self.session_ttl_seconds, bool)
            or not 1 <= self.session_ttl_seconds <= 3_600
            or not isinstance(self.session_epoch, int) or isinstance(self.session_epoch, bool)
            or self.session_epoch < 1
        ):
            raise ValueError("embedded auth registry lifetime is invalid")
        principals = tuple(self.principals)
        ids = tuple(item.id for item in principals)
        owners = tuple(item for item in principals if item.role == "owner" and item.enabled)
        if (
            not principals or len(ids) != len(set(ids)) or {item.role for item in principals} != ROLES
            or len(owners) != 1 or owners[0].id != "owner-local"
        ):
            raise ValueError("embedded auth role registry is invalid")
        object.__setattr__(self, "principals", principals)

    @classmethod
    def from_payload(cls, payload: Mapping[str, object]) -> EmbeddedRoleRegistry:
        if not isinstance(payload, Mapping) or set(payload) != _REGISTRY_FIELDS:
            raise ValueError("embedded auth registry fields mismatch")
        if payload.get("schema_version") != "1.0" or not isinstance(payload.get("principals"), list):
            raise ValueError("unsupported embedded auth registry")
        principals = []
        for item in payload["principals"]:
            if not isinstance(item, Mapping) or set(item) != _PRINCIPAL_FIELDS:
                raise ValueError("embedded auth principal fields mismatch")
            principals.append(EmbeddedPrincipal(item["id"], item["role"], item["enabled"]))
        return cls(
            payload["auth_version"], payload["issuer"], payload["audience"], payload["project_id"],
            payload["session_ttl_seconds"], payload["session_epoch"], tuple(principals),
        )

    def principal(self, principal_id: str) -> EmbeddedPrincipal | None:
        return next((item for item in self.principals if item.id == principal_id and item.enabled), None)


@dataclass(frozen=True)
class EmbeddedSessionAuthenticator:
    """Проверяет короткоживущие HMAC sessions без внешнего IdP."""

    registry: EmbeddedRoleRegistry
    key: bytes = field(repr=False, compare=False)
    clock: Callable[[], float] = field(default=time, repr=False, compare=False)
    nonce_factory: Callable[[], str] = field(default=lambda: secrets.token_hex(16), repr=False, compare=False)

    def __post_init__(self) -> None:
        if not isinstance(self.key, bytes) or len(self.key) < 32:
            raise ValueError("embedded auth key must contain at least 32 bytes")

    @property
    def project_id(self) -> str:
        return self.registry.project_id

    def issue(self, principal_id: str) -> str:
        principal = self.registry.principal(principal_id)
        if principal is None:
            raise PermissionError("embedded principal is disabled or unknown")
        now = int(self.clock())
        nonce = self.nonce_factory()
        if not isinstance(nonce, str) or not re.fullmatch(r"[0-9a-f]{32,64}", nonce):
            raise ValueError("embedded session nonce is invalid")
        payload = {
            "v": "1.0", "iss": self.registry.issuer, "aud": self.registry.audience, "sub": principal.id,
            "project": self.registry.project_id, "iat": now, "exp": now + self.registry.session_ttl_seconds,
            "epoch": self.registry.session_epoch, "nonce": nonce,
        }
        encoded = self._encode(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8"))
        signature = hmac.new(self.key, encoded.encode("ascii"), hashlib.sha256).digest()
        return encoded + "." + self._encode(signature)

    def authenticate(self, token: str) -> AuthenticationResult:
        if not isinstance(token, str) or not token or len(token) > 4_096:
            return self._deny("missing_or_invalid_session")
        try:
            encoded, encoded_signature = token.split(".")
            signature = self._decode(encoded_signature)
            expected = hmac.new(self.key, encoded.encode("ascii"), hashlib.sha256).digest()
            if not hmac.compare_digest(expected, signature):
                return self._deny("session_signature_invalid")
            payload = self._load_payload(self._decode(encoded))
            reason = self._validate_payload(payload)
            if reason:
                return self._deny(reason)
            registered = self.registry.principal(payload["sub"])
            if registered is None:
                return self._deny("principal_disabled_or_unknown")
            principal = Principal(registered.id, registered.role, self.registry.project_id)
            receipt = AuthReceipt(
                "allow", "authenticated", self.registry.issuer, principal.id, principal.project_id,
                principal.role, payload["exp"], self.registry.auth_version,
            )
            return AuthenticationResult("allow", principal, receipt)
        except Exception:
            return self._deny("session_verification_failed")

    def _validate_payload(self, payload: Mapping[str, object]) -> str:
        now = int(self.clock())
        if payload["v"] != "1.0" or payload["iss"] != self.registry.issuer:
            return "session_issuer_mismatch"
        if payload["aud"] != self.registry.audience or payload["project"] != self.registry.project_id:
            return "session_scope_mismatch"
        if payload["epoch"] != self.registry.session_epoch:
            return "session_revoked"
        if payload["iat"] > now or payload["exp"] <= now:
            return "session_not_current"
        if payload["exp"] - payload["iat"] != self.registry.session_ttl_seconds:
            return "session_lifetime_invalid"
        return ""

    @staticmethod
    def _load_payload(raw: bytes) -> Mapping[str, object]:
        def strict_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
            if len(pairs) != len({key for key, _ in pairs}):
                raise ValueError("duplicate embedded session field")
            return dict(pairs)

        payload = json.loads(raw, object_pairs_hook=strict_object)
        if not isinstance(payload, dict) or set(payload) != _SESSION_FIELDS:
            raise ValueError("embedded session fields mismatch")
        integers = (payload["iat"], payload["exp"], payload["epoch"])
        texts = (payload["v"], payload["iss"], payload["aud"], payload["sub"], payload["project"], payload["nonce"])
        if any(not isinstance(value, int) or isinstance(value, bool) for value in integers):
            raise ValueError("embedded session timestamps are invalid")
        if any(not isinstance(value, str) or not value for value in texts):
            raise ValueError("embedded session identity is invalid")
        return payload

    @staticmethod
    def _encode(raw: bytes) -> str:
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")

    @staticmethod
    def _decode(encoded: str) -> bytes:
        if not encoded or not re.fullmatch(r"[A-Za-z0-9_-]+", encoded):
            raise ValueError("embedded session encoding is invalid")
        padding = "=" * (-len(encoded) % 4)
        return base64.b64decode(encoded + padding, altchars=b"-_", validate=True)

    def _deny(self, reason_code: str) -> AuthenticationResult:
        receipt = AuthReceipt(
            "deny", reason_code, self.registry.issuer, "", self.registry.project_id, "", 0,
            self.registry.auth_version,
        )
        return AuthenticationResult("deny", None, receipt)


@dataclass(frozen=True)
class AuthentikAuthenticator:
    """Связывает verified Authentik claims с одной проектной ролью."""

    verifier: OIDCTokenVerifier
    issuer: str
    audience: str
    project_id: str
    group_roles: Mapping[str, str]
    owner_subjects: frozenset[str]
    clock: Callable[[], float] = time
    max_session_seconds: int = 3600

    def __post_init__(self) -> None:
        config = (self.issuer, self.audience, self.project_id)
        if any(not isinstance(value, str) or not value.strip() for value in config):
            raise ValueError("OIDC configuration values must be non-empty")
        group_roles = dict(self.group_roles)
        if set(group_roles.values()) != ROLES or len(group_roles) != len(ROLES):
            raise ValueError("group role mapping must contain each supported role exactly once")
        if any(not group or role not in ROLES for group, role in group_roles.items()):
            raise ValueError("invalid group role mapping")
        if not self.owner_subjects:
            raise ValueError("owner subjects must not be empty")
        if not isinstance(self.max_session_seconds, int) or self.max_session_seconds <= 0:
            raise ValueError("max session seconds must be a positive integer")
        object.__setattr__(self, "group_roles", MappingProxyType(group_roles))
        object.__setattr__(self, "owner_subjects", frozenset(self.owner_subjects))

    def authenticate(self, token: str) -> AuthenticationResult:
        """Fail-closed проверяет token и возвращает scoped Principal."""

        if not isinstance(token, str) or not token:
            return self._deny("missing_token")
        try:
            claims = self.verifier.verify(token)
            reason = self._validate_claims(claims)
        except Exception:
            return self._deny("token_verification_failed")
        if reason:
            return self._deny(reason)
        roles = {self.group_roles[group] for group in claims.groups if group in self.group_roles}
        if len(roles) != 1:
            return self._deny("ambiguous_or_missing_role")
        role = next(iter(roles))
        if role == "owner" and claims.subject not in self.owner_subjects:
            return self._deny("owner_subject_not_allowed")
        principal = Principal(claims.subject, role, claims.project_id)
        receipt = AuthReceipt(
            "allow", "authenticated", claims.issuer, principal.id, principal.project_id, principal.role,
            claims.expires_at,
        )
        return AuthenticationResult("allow", principal, receipt)

    def _validate_claims(self, claims: OIDCClaims) -> str:
        now = int(self.clock())
        if claims.issuer != self.issuer:
            return "issuer_mismatch"
        if self.audience not in claims.audiences:
            return "audience_mismatch"
        if claims.expires_at <= now:
            return "token_expired"
        if claims.issued_at > now:
            return "token_not_yet_valid"
        if claims.not_before > now:
            return "token_not_yet_valid"
        if claims.expires_at - claims.issued_at > self.max_session_seconds:
            return "token_lifetime_exceeded"
        if not claims.email_verified:
            return "email_not_verified"
        if claims.project_id != self.project_id:
            return "project_scope_mismatch"
        return ""

    def _deny(self, reason_code: str) -> AuthenticationResult:
        receipt = AuthReceipt("deny", reason_code, self.issuer, "", self.project_id, "", 0)
        return AuthenticationResult("deny", None, receipt)


@dataclass(frozen=True)
class AuthenticatedModelGateway:
    """Проверяет bearer token на каждом внешнем model request."""

    authenticator: Authenticator
    gateway: ModelGateway

    def invoke(self, token: str, request: ModelRequest, context: PrivacyContext) -> GatewayResult:
        authentication = self.authenticator.authenticate(token)
        if authentication.status != "allow" or authentication.principal is None:
            return self.gateway._deny(request, "authentication_required")
        return self.gateway._invoke_trusted(authentication.principal, request, context)
