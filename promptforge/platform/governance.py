"""Repository-owned identity-bound governance policy."""

from __future__ import annotations

from dataclasses import dataclass
import json
import os
from pathlib import Path
import re
import stat
from typing import Mapping

from promptforge.platform.contracts import Principal, SCHEMA_VERSION


_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_CONFIG_FIELDS = frozenset({"schema_version", "policy_version", "project_id", "administrators", "capabilities"})
_ACTOR_FIELDS = frozenset({"id", "role"})
_ADMINISTRATORS = frozenset({("owner-local", "owner"), ("maintainer-local", "maintainer")})
_CAPABILITIES = frozenset({
    "docs.sync",
    "mcp.approve",
    "models.admit",
    "operations.manage",
    "policy.manage",
    "privacy.rehydrate",
    "roles.manage",
    "skills.manage",
})
_MAX_CONFIG_BYTES = 100_000


def _strict_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate governance field")
        result = {**result, key: value}
    return result


@dataclass(frozen=True)
class GovernanceActor:
    """Связывает административную identity с её точной runtime-ролью."""

    id: str
    role: str

    def __post_init__(self) -> None:
        if (
            not isinstance(self.id, str) or not _SAFE_ID.fullmatch(self.id)
            or not isinstance(self.role, str) or self.role not in {"owner", "maintainer"}
        ):
            raise ValueError("governance actor is invalid")


@dataclass(frozen=True)
class GovernancePolicy:
    """Разрешает administrative capability только двум закреплённым identities."""

    project_id: str
    administrators: tuple[GovernanceActor, ...]
    capabilities: frozenset[str]
    policy_version: str = "governance-v1"

    def __post_init__(self) -> None:
        actors = tuple(self.administrators)
        bindings = frozenset((actor.id, actor.role) for actor in actors)
        if (
            self.project_id != "promptforge"
            or self.policy_version != "governance-v1"
            or len(bindings) != len(actors)
            or bindings != _ADMINISTRATORS
            or frozenset(self.capabilities) != _CAPABILITIES
        ):
            raise ValueError("governance policy is invalid")
        object.__setattr__(self, "administrators", actors)
        object.__setattr__(self, "capabilities", frozenset(self.capabilities))

    @classmethod
    def from_repository(cls, repository: Path) -> GovernancePolicy:
        root = Path(repository).resolve(strict=True)
        path = root / "config" / "governance.json"
        if not root.is_dir() or Path(repository).is_symlink():
            raise ValueError("governance config must be a bounded regular repository file")
        descriptor = -1
        try:
            descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > _MAX_CONFIG_BYTES:
                raise ValueError("governance config must be a bounded regular repository file")
            with os.fdopen(descriptor, "r", encoding="utf-8") as stream:
                descriptor = -1
                payload = json.load(stream, object_pairs_hook=_strict_object)
        except (OSError, UnicodeError, json.JSONDecodeError) as error:
            raise ValueError("governance config is invalid") from error
        finally:
            if descriptor >= 0:
                os.close(descriptor)
        return cls.from_payload(payload)

    @classmethod
    def from_payload(cls, payload: Mapping[str, object]) -> GovernancePolicy:
        if not isinstance(payload, Mapping) or set(payload) != _CONFIG_FIELDS:
            raise ValueError("governance config fields mismatch")
        raw_actors = payload.get("administrators")
        raw_capabilities = payload.get("capabilities")
        if (
            payload.get("schema_version") != SCHEMA_VERSION
            or not isinstance(raw_actors, list)
            or not isinstance(raw_capabilities, list)
            or any(not isinstance(item, Mapping) or set(item) != _ACTOR_FIELDS for item in raw_actors)
            or any(not isinstance(item, str) or not _SAFE_ID.fullmatch(item) for item in raw_capabilities)
        ):
            raise ValueError("governance config contract is invalid")
        actors = tuple(GovernanceActor(item["id"], item["role"]) for item in raw_actors)
        return cls(payload["project_id"], actors, frozenset(raw_capabilities), payload["policy_version"])

    @classmethod
    def builtin(cls) -> GovernancePolicy:
        return cls(
            "promptforge",
            (GovernanceActor("owner-local", "owner"), GovernanceActor("maintainer-local", "maintainer")),
            _CAPABILITIES,
        )

    def allows(self, principal: Principal, capability: str) -> bool:
        """Проверяет exact identity-role-project binding и известную capability."""

        return bool(
            principal.project_id == self.project_id
            and capability in self.capabilities
            and (principal.id, principal.role) in {(actor.id, actor.role) for actor in self.administrators}
        )

    def require(self, principal: Principal, capability: str) -> None:
        """Fail closed блокирует неизвестного или generic role holder."""

        if not self.allows(principal, capability):
            raise PermissionError("administrative capability denied")
