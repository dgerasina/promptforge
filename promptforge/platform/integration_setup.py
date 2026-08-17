"""Owner-private local setup for authenticated corporate integration reads."""

from __future__ import annotations

from dataclasses import dataclass, field
import json
import os
from pathlib import Path
import re
import secrets
import stat
from types import MappingProxyType
from typing import Mapping

from promptforge.platform.auth import EmbeddedRoleRegistry, EmbeddedSessionAuthenticator
from promptforge.platform.integration_backends import IntegrationBackendConfig
from promptforge.platform.secure_filesystem import SECURE_FILESYSTEM


_SERVICES = ("confluence", "jira", "airflow")
_PROFILE_FIELDS = frozenset({"schema_version", "profile_version", "principal_id", "ca_file", "services"})
_SERVICE_FIELDS = frozenset({
    "id", "url", "auth_mode", "username", "scope_mode", "allowed_resources", "smoke_resource",
    "credential_file",
})
_SAFE_FILE = re.compile(r"^[a-z][a-z0-9-]{0,63}\.credential$")
_MAX_PROFILE_BYTES = 100_000
_MAX_CA_BYTES = 2_000_000
_CREDENTIAL_ENVELOPE_FIELDS = frozenset({"schema_version", "auth_mode", "secret"})


@dataclass(frozen=True)
class ServiceSetupInput:
    """Describes one service without containing its credential value."""

    id: str
    url: str
    auth_mode: str
    username: str
    scope_mode: str
    allowed_resources: tuple[str, ...]
    smoke_resource: str

    def __post_init__(self) -> None:
        if self.id not in _SERVICES or not isinstance(self.allowed_resources, (tuple, list)):
            raise ValueError("integration setup service is invalid")
        if not isinstance(self.smoke_resource, str) or not self.smoke_resource:
            raise ValueError("integration setup smoke resource is invalid")
        object.__setattr__(self, "allowed_resources", tuple(self.allowed_resources))


@dataclass(frozen=True)
class IntegrationSetupInput:
    """Closed metadata input for all configured integrations."""

    principal_id: str
    ca_file: Path
    services: tuple[ServiceSetupInput, ...]

    def __post_init__(self) -> None:
        services = tuple(self.services)
        if tuple(item.id for item in services) != _SERVICES:
            raise ValueError("integration setup requires exact service order")
        object.__setattr__(self, "ca_file", Path(self.ca_file))
        object.__setattr__(self, "services", services)


@dataclass(frozen=True)
class LoadedIntegrationRuntime:
    """Carries ephemeral secrets only in memory and hides them from repr."""

    principal_id: str
    jira_project: str
    airflow_dag: str
    environment: Mapping[str, str] = field(repr=False, compare=False)
    work_session: str = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "environment", MappingProxyType(dict(self.environment)))


@dataclass(frozen=True)
class LocalIntegrationProfile:
    """Creates and loads one fail-closed owner-private integration profile."""

    product_root: Path
    state_root: Path

    def __post_init__(self) -> None:
        product = Path(self.product_root).resolve(strict=True)
        state = Path(self.state_root)
        if not product.is_dir() or product.is_symlink():
            raise ValueError("integration product root is invalid")
        _ensure_private_state(state)
        _require_private_directory(state, "integration state root")
        object.__setattr__(self, "product_root", product)
        object.__setattr__(self, "state_root", state)

    @property
    def directory(self) -> Path:
        return self.state_root / "integrations"

    def configure(self, setup: IntegrationSetupInput, credential_values: Mapping[str, str]) -> dict[str, object]:
        """Creates a new local profile and never overwrites existing credentials."""

        if set(credential_values) != set(_SERVICES):
            raise ValueError("integration credential set is incomplete")
        registry = self._registry()
        if registry.principal(setup.principal_id) is None:
            raise PermissionError("integration setup principal is not registered")
        ca_file = _require_ca_file(setup.ca_file)
        directory = self.directory
        if directory.exists() or directory.is_symlink():
            raise FileExistsError("integration profile already exists; approved cleanup is required")
        SECURE_FILESYSTEM.ensure_private_directory(directory)
        created: list[Path] = []
        try:
            for service in setup.services:
                value = credential_values[service.id]
                if not _valid_secret(value):
                    raise ValueError("integration credential is invalid")
                credential = directory / f"{service.id}.credential"
                _write_new_private(credential, value.encode("utf-8"))
                created.append(credential)
            auth_key = secrets.token_bytes(32).hex()
            audit_key = secrets.token_bytes(32).hex()
            _write_new_private(directory / "embedded-auth.key", auth_key.encode("ascii"))
            created.append(directory / "embedded-auth.key")
            _write_new_private(directory / "local-audit.key", audit_key.encode("ascii"))
            created.append(directory / "local-audit.key")
            payload = self._payload(setup, ca_file)
            environment = self._environment(payload, auth_key, audit_key)
            config = IntegrationBackendConfig.from_env(environment)
            self._validate_smoke(config, setup.services)
            _write_new_private(directory / "profile.json", _canonical(payload) + b"\n")
            created.append(directory / "profile.json")
            _sync_directory(directory)
        except BaseException:
            for path in reversed(created):
                try:
                    path.unlink()
                except FileNotFoundError:
                    pass
            try:
                directory.rmdir()
            except OSError:
                pass
            raise
        return {
            "schema_version": "1.0", "status": "ready", "services": 3, "principal_id": setup.principal_id,
            "auth_modes": [service.auth_mode for service in setup.services], "credentials_exposed": False,
            "network_used": False,
        }

    def load(self) -> LoadedIntegrationRuntime:
        """Loads validated private state and issues a fresh short-lived work session."""

        _require_private_directory(self.directory, "integration profile directory")
        payload = _read_private_json(self.directory / "profile.json")
        if set(payload) != _PROFILE_FIELDS or payload.get("schema_version") != "1.0" \
                or payload.get("profile_version") != "integration-local-v1":
            raise ValueError("integration profile fields are invalid")
        services = self._services(payload.get("services"))
        principal_id = payload.get("principal_id")
        if not isinstance(principal_id, str) or self._registry().principal(principal_id) is None:
            raise PermissionError("integration profile principal is invalid")
        _require_ca_file(Path(str(payload.get("ca_file", ""))))
        auth_key = _read_private_text(self.directory / "embedded-auth.key", 128)
        audit_key = _read_private_text(self.directory / "local-audit.key", 128)
        environment = self._environment(payload, auth_key, audit_key)
        config = IntegrationBackendConfig.from_env(environment)
        self._validate_smoke(config, services)
        token = EmbeddedSessionAuthenticator(self._registry(), bytes.fromhex(auth_key)).issue(principal_id)
        by_id = {service.id: service for service in services}
        return LoadedIntegrationRuntime(
            principal_id, by_id["jira"].smoke_resource, by_id["airflow"].smoke_resource, environment, token,
        )

    def rotate_credential(self, service: str, auth_mode: str, credential: str) -> dict[str, object]:
        """Atomically rotates one supported credential without exposing its value."""

        if service != "jira" or auth_mode != "bearer-token" or not _valid_secret(credential):
            raise ValueError("integration credential rotation is invalid")
        _require_private_directory(self.directory, "integration profile directory")
        payload = _read_private_json(self.directory / "profile.json")
        if set(payload) != _PROFILE_FIELDS or payload.get("profile_version") != "integration-local-v1":
            raise ValueError("integration profile fields are invalid")
        services = self._services(payload.get("services"))
        principal_id = payload.get("principal_id")
        if not isinstance(principal_id, str) or self._registry().principal(principal_id) is None:
            raise PermissionError("integration profile principal is invalid")
        envelope = b"PFCE1:" + _canonical({
            "schema_version": "1.0", "auth_mode": auth_mode, "secret": credential,
        })
        destination = self.directory / f"{service}.credential"
        _read_private_text(destination, 9_000)
        original = destination.stat(follow_symlinks=False)
        lock = self.directory / ".credential-update.lock"
        temporary = self.directory / f".{service}.credential.tmp"
        lock_descriptor = -1
        try:
            lock_descriptor = os.open(
                lock, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600,
            )
            if hasattr(os, "fchmod"):
                os.fchmod(lock_descriptor, 0o600)
            os.fsync(lock_descriptor)
            if os.name == "nt":
                SECURE_FILESYSTEM.windows.apply_and_verify(lock, directory=False)
            _write_new_private(temporary, envelope)
            current = destination.stat(follow_symlinks=False)
            if (
                not stat.S_ISREG(current.st_mode)
                or os.name != "nt" and stat.S_IMODE(current.st_mode) != 0o600
                or (current.st_dev, current.st_ino) != (original.st_dev, original.st_ino)
            ):
                raise RuntimeError("integration credential changed during rotation")
            os.replace(temporary, destination)
            _sync_directory(self.directory)
        finally:
            if lock_descriptor >= 0:
                os.close(lock_descriptor)
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass
            if lock_descriptor >= 0:
                try:
                    lock.unlink()
                except FileNotFoundError:
                    pass
        return {
            "schema_version": "1.0", "status": "rotated", "service": service,
            "auth_mode": auth_mode, "credential_exposed": False, "network_used": False,
        }

    def _registry(self) -> EmbeddedRoleRegistry:
        payload = json.loads(
            (self.product_root / "config" / "local-auth.json").read_bytes(), object_pairs_hook=_unique_object,
        )
        return EmbeddedRoleRegistry.from_payload(payload)

    def _payload(self, setup: IntegrationSetupInput, ca_file: Path) -> dict[str, object]:
        return {
            "schema_version": "1.0", "profile_version": "integration-local-v1",
            "principal_id": setup.principal_id, "ca_file": str(ca_file),
            "services": [
                {
                    "id": service.id, "url": service.url, "auth_mode": service.auth_mode,
                    "username": service.username, "scope_mode": service.scope_mode,
                    "allowed_resources": list(service.allowed_resources), "smoke_resource": service.smoke_resource,
                    "credential_file": f"{service.id}.credential",
                }
                for service in setup.services
            ],
        }

    def _environment(self, payload: Mapping[str, object], auth_key: str, audit_key: str) -> dict[str, str]:
        services = self._services(payload.get("services"))
        environment = {
            "PF_EMBEDDED_AUTH_KEY_HEX": auth_key, "PF_LOCAL_AUDIT_KEY_HEX": audit_key,
            "PF_INTEGRATION_CA_FILE": str(payload["ca_file"]),
        }
        for service in services:
            prefix = f"PF_INTEGRATION_{service.id.upper()}_"
            credential_file = self.directory / f"{service.id}.credential"
            value = _read_private_text(credential_file, 9_000)
            effective_auth_mode, effective_username = service.auth_mode, service.username
            encoded_envelope = value.removeprefix("PFCE1:") if value.startswith("PFCE1:") else ""
            if not encoded_envelope and service.id == "jira" and service.auth_mode != "bearer-token" \
                    and value.startswith("{"):
                encoded_envelope = value
            if encoded_envelope:
                envelope = _credential_envelope(encoded_envelope)
                effective_auth_mode = str(envelope["auth_mode"])
                effective_username = ""
                value = str(envelope["secret"])
            environment.update({
                f"{prefix}URL": service.url, f"{prefix}AUTH_MODE": effective_auth_mode,
                f"{prefix}SCOPE_MODE": service.scope_mode,
            })
            resource_name = {"confluence": "ALLOWED_SPACES", "jira": "ALLOWED_PROJECTS", "airflow": "ALLOWED_DAGS"}[
                service.id
            ]
            environment[f"{prefix}{resource_name}"] = ",".join(service.allowed_resources)
            if effective_auth_mode in {"basic", "bearer-token"}:
                if effective_auth_mode == "basic":
                    environment[f"{prefix}USERNAME"] = effective_username
                environment[f"{prefix}TOKEN"] = value
            else:
                environment[f"{prefix}SESSION_FILE"] = str(credential_file)
        return environment

    @staticmethod
    def _services(value: object) -> tuple[ServiceSetupInput, ...]:
        if not isinstance(value, list) or len(value) != 3:
            raise ValueError("integration profile services are invalid")
        services = []
        for item in value:
            if not isinstance(item, Mapping) or set(item) != _SERVICE_FIELDS:
                raise ValueError("integration profile service fields are invalid")
            credential_file = item["credential_file"]
            if not isinstance(credential_file, str) or not _SAFE_FILE.fullmatch(credential_file):
                raise ValueError("integration credential filename is invalid")
            service = ServiceSetupInput(
                item["id"], item["url"], item["auth_mode"], item["username"], item["scope_mode"],
                tuple(item["allowed_resources"]) if isinstance(item["allowed_resources"], list) else (),
                item["smoke_resource"],
            )
            if credential_file != f"{service.id}.credential":
                raise ValueError("integration credential binding is invalid")
            services.append(service)
        if tuple(item.id for item in services) != _SERVICES:
            raise ValueError("integration profile service order is invalid")
        return tuple(services)

    @staticmethod
    def _validate_smoke(config: IntegrationBackendConfig, services: tuple[ServiceSetupInput, ...]) -> None:
        by_id = {service.id: service for service in services}
        config.confluence.smoke_resource(by_id["confluence"].smoke_resource)
        config.jira.smoke_resource(by_id["jira"].smoke_resource)
        config.airflow.smoke_resource(by_id["airflow"].smoke_resource)


def _canonical(payload: object) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate integration profile field")
        result[key] = value
    return result


def _valid_secret(value: object) -> bool:
    return isinstance(value, str) and 1 <= len(value) <= 8_192 and all(0x20 <= ord(char) < 0x7F for char in value)


def _credential_envelope(value: str) -> Mapping[str, object]:
    try:
        payload = json.loads(value, object_pairs_hook=_unique_object)
    except (json.JSONDecodeError, ValueError) as error:
        raise ValueError("integration credential envelope is invalid") from error
    if (
        not isinstance(payload, Mapping) or set(payload) != _CREDENTIAL_ENVELOPE_FIELDS
        or payload.get("schema_version") != "1.0" or payload.get("auth_mode") != "bearer-token"
        or not _valid_secret(payload.get("secret"))
    ):
        raise ValueError("integration credential envelope is invalid")
    return payload


def _require_private_directory(path: Path, label: str) -> Path:
    candidate = Path(path)
    try:
        SECURE_FILESYSTEM.require_private_directory(candidate)
    except (PermissionError, ValueError) as error:
        raise ValueError(f"{label} is not owner-private") from error
    return candidate


def _ensure_private_state(path: Path) -> None:
    candidate = Path(path)
    if not candidate.is_absolute():
        raise ValueError("integration state root must be absolute")
    current = Path(candidate.anchor)
    for part in candidate.parts[1:]:
        current = current / part
        if current.is_symlink():
            raise ValueError("integration state path must not contain symlinks")
        if not current.exists():
            break
    if candidate.exists():
        return
    parent = candidate.parent
    if not parent.is_dir() or parent.is_symlink() or parent.resolve() != parent:
        raise ValueError("integration state parent is invalid")
    SECURE_FILESYSTEM.ensure_private_directory(candidate)


def _require_ca_file(path: Path) -> Path:
    candidate = Path(path)
    try:
        SECURE_FILESYSTEM.require_trusted_file(candidate, _MAX_CA_BYTES)
    except (PermissionError, ValueError) as error:
        raise ValueError("integration CA file permissions or size are invalid") from error
    return candidate


def _write_new_private(path: Path, content: bytes) -> None:
    SECURE_FILESYSTEM.write_new_private(path, content)


def _read_private_text(path: Path, maximum: int) -> str:
    try:
        return SECURE_FILESYSTEM.read_private(path, maximum).decode("utf-8")
    except (OSError, UnicodeError) as error:
        raise ValueError("integration private file is unavailable") from error


def _read_private_json(path: Path) -> dict[str, object]:
    raw = _read_private_text(path, _MAX_PROFILE_BYTES)
    try:
        payload = json.loads(raw, object_pairs_hook=_unique_object)
    except json.JSONDecodeError as error:
        raise ValueError("integration profile JSON is invalid") from error
    if not isinstance(payload, dict):
        raise ValueError("integration profile JSON root is invalid")
    return payload


def _sync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
