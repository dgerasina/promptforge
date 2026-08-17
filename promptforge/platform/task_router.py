"""Детерминированная маршрутизация exact task kinds в versioned agents."""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json
import os
from pathlib import Path
import re
import stat
from typing import Mapping

from promptforge.core.project_profile import ProjectProfile
from promptforge.platform.contracts import Principal, ROLES
from promptforge.platform.skill_library import RepositorySkillApprovalRegistry, SkillRelease, load_skill_library


_AGENT_ID = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
_VERSION = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")
_TASK_KIND = re.compile(r"^[a-z][a-z0-9-]*(?:\.[a-z0-9-]+)+$")
_CAPABILITY = re.compile(r"^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)+$")
_DIGEST = re.compile(r"^sha256:[a-f0-9]{64}$")
_CATALOG_FIELDS = frozenset({"schema_version", "catalog_version", "agents", "catalog_digest"})
_AGENT_FIELDS = frozenset({
    "id", "version", "status", "roles", "task_kinds", "skill_refs", "required_capabilities",
    "review_agent_id",
})
_VALIDATED_CATALOG = object()


def _canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")


def _strict_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("agent catalog contains duplicate fields")
        result = {**result, key: value}
    return result


def _digest(value: object) -> str:
    return f"sha256:{hashlib.sha256(_canonical(value)).hexdigest()}"


def _unique_strings(value: object, name: str, *, allow_empty: bool = False) -> tuple[str, ...]:
    if (
        not isinstance(value, list)
        or (not allow_empty and not value)
        or any(not isinstance(item, str) or not item for item in value)
        or len(set(value)) != len(value)
    ):
        raise ValueError(f"{name} must be a unique string array")
    return tuple(value)


@dataclass(frozen=True)
class AgentSpec:
    """Описывает один immutable routing target."""

    id: str
    version: str
    roles: tuple[str, ...]
    task_kinds: tuple[str, ...]
    skill_refs: tuple[str, ...]
    required_capabilities: tuple[str, ...]
    review_agent_id: str | None

    @classmethod
    def from_payload(cls, payload: object) -> AgentSpec:
        if not isinstance(payload, Mapping) or set(payload) != _AGENT_FIELDS or payload.get("status") != "active":
            raise ValueError("agent catalog entry fields or status mismatch")
        roles = _unique_strings(payload["roles"], "agent roles")
        task_kinds = _unique_strings(payload["task_kinds"], "agent task kinds")
        skill_refs = _unique_strings(payload["skill_refs"], "agent skill refs", allow_empty=True)
        capabilities = _unique_strings(payload["required_capabilities"], "agent capabilities")
        review_agent = payload["review_agent_id"]
        if (
            not _AGENT_ID.fullmatch(str(payload["id"]))
            or not _VERSION.fullmatch(str(payload["version"]))
            or any(role not in ROLES for role in roles)
            or any(not _TASK_KIND.fullmatch(item) for item in task_kinds)
            or any(not _CAPABILITY.fullmatch(item) for item in capabilities)
            or (review_agent is not None and not _AGENT_ID.fullmatch(str(review_agent)))
        ):
            raise ValueError("agent catalog entry values are invalid")
        return cls(
            payload["id"], payload["version"], roles, task_kinds, skill_refs, capabilities, review_agent,
        )

    def to_payload(self) -> dict[str, object]:
        return {
            "id": self.id,
            "version": self.version,
            "status": "active",
            "roles": list(self.roles),
            "task_kinds": list(self.task_kinds),
            "skill_refs": list(self.skill_refs),
            "required_capabilities": list(self.required_capabilities),
            "review_agent_id": self.review_agent_id,
        }


@dataclass(frozen=True)
class AgentCatalog:
    """Хранит integrity-bound список разрешённых agents."""

    version: str
    agents: tuple[AgentSpec, ...]
    digest: str
    _validation_token: object = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        if self._validation_token is not _VALIDATED_CATALOG:
            raise ValueError("agent catalog must be created by the verified loader")

    @classmethod
    def with_digest(cls, unsigned: Mapping[str, object]) -> dict[str, object]:
        return {**unsigned, "catalog_digest": _digest(unsigned)}

    @classmethod
    def from_payload(cls, payload: object, profile: ProjectProfile) -> AgentCatalog:
        if (
            not isinstance(payload, Mapping)
            or set(payload) != _CATALOG_FIELDS
            or payload.get("schema_version") != "1.0"
        ):
            raise ValueError("agent catalog fields or schema version mismatch")
        unsigned = {key: value for key, value in payload.items() if key != "catalog_digest"}
        if payload["catalog_digest"] != _digest(unsigned) or not _DIGEST.fullmatch(str(payload["catalog_digest"])):
            raise ValueError("agent catalog digest mismatch")
        if not _VERSION.fullmatch(str(payload["catalog_version"])) or not isinstance(payload["agents"], list):
            raise ValueError("agent catalog version or agents are invalid")
        agents = tuple(AgentSpec.from_payload(item) for item in payload["agents"])
        catalog = cls(payload["catalog_version"], agents, payload["catalog_digest"], _VALIDATED_CATALOG)
        catalog._validate(profile)
        return catalog

    def _validate(self, profile: ProjectProfile) -> None:
        if len({agent.id for agent in self.agents}) != len(self.agents):
            raise ValueError("agent catalog contains duplicate ids")
        routes = tuple(
            (task_kind, role)
            for agent in self.agents for task_kind in agent.task_kinds for role in agent.roles
        )
        if len(set(routes)) != len(routes):
            raise ValueError("agent catalog contains ambiguous role routes")
        release_by_ref = self._approved_releases(profile)
        by_id = {agent.id: agent for agent in self.agents}
        for agent in self.agents:
            if not agent.skill_refs:
                invalid_terminal = (
                    agent.task_kinds != ("review.changed-files",)
                    or agent.review_agent_id is not None
                    or agent.required_capabilities != ("repository.read",)
                )
                if invalid_terminal and profile.skill_approvals is not None:
                    raise ValueError("only terminal changed-files review agent may omit skills")
            else:
                self._validate_skill_binding(agent, release_by_ref)
            if agent.review_agent_id is not None:
                reviewer = by_id.get(agent.review_agent_id)
                invalid_review = (
                    reviewer is None
                    or reviewer.review_agent_id is not None
                    or "review.changed-files" not in reviewer.task_kinds
                )
                if invalid_review:
                    raise ValueError("agent review binding is invalid")

    @staticmethod
    def _approved_releases(profile: ProjectProfile) -> dict[str, SkillRelease]:
        if profile.skill_approvals is None:
            return {}
        registry = RepositorySkillApprovalRegistry.from_file(profile.skill_approvals)
        if registry.ordered_skill_ids != profile.pack.approved_skill_order:
            raise ValueError("agent catalog skill approval order drift")
        library = load_skill_library(profile.skills_root, registry.verify)
        return {
            f"{release.id}@{release.version}": release
            for release in library.releases if release.status == "approved" and release.integrity_verified
        }

    @staticmethod
    def _validate_skill_binding(agent: AgentSpec, releases: Mapping[str, SkillRelease]) -> None:
        bound = tuple(releases.get(reference) for reference in agent.skill_refs)
        if any(release is None for release in bound):
            raise ValueError("agent references an unapproved skill release")
        typed = tuple(release for release in bound if release is not None)
        if any(not set(agent.roles).issubset(release.roles) for release in typed):
            raise ValueError("agent roles exceed bound skill roles")
        capabilities = tuple(sorted({item for release in typed for item in release.permissions_required}))
        if tuple(sorted(agent.required_capabilities)) != capabilities:
            raise ValueError("agent capabilities drift from skill releases")


@dataclass(frozen=True)
class TaskEnvelope:
    """Передаёт router только authenticated metadata, без task content."""

    project_id: str
    principal: Principal
    task_kind: str
    trace_id: str

    _FIELDS = frozenset({"schema_version", "project_id", "principal", "task_kind", "trace_id"})

    def __post_init__(self) -> None:
        if (
            not isinstance(self.project_id, str) or not self.project_id
            or not _TASK_KIND.fullmatch(self.task_kind)
            or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", self.trace_id)
        ):
            raise ValueError("task envelope metadata is invalid")

    def to_payload(self) -> dict[str, object]:
        return {
            "schema_version": "1.0",
            "project_id": self.project_id,
            "principal": self.principal.to_payload(),
            "task_kind": self.task_kind,
            "trace_id": self.trace_id,
        }

    @classmethod
    def from_payload(cls, payload: object) -> TaskEnvelope:
        if not isinstance(payload, Mapping) or set(payload) != cls._FIELDS or payload.get("schema_version") != "1.0":
            raise ValueError("task envelope fields or version mismatch")
        return cls(
            payload["project_id"], Principal.from_payload(payload["principal"]), payload["task_kind"],
            payload["trace_id"],
        )


@dataclass(frozen=True)
class TaskRoute:
    """Возвращает объяснимый metadata-only routing receipt."""

    outcome: str
    reason_code: str
    task_kind: str
    envelope_digest: str
    catalog_version: str
    catalog_digest: str
    primary_agent_id: str | None
    primary_agent_version: str | None
    skill_refs: tuple[str, ...]
    required_capabilities: tuple[str, ...]
    review_agent_id: str | None
    route_digest: str

    @classmethod
    def create(cls, catalog: AgentCatalog, request: TaskEnvelope, reason: str, agent: AgentSpec | None) -> TaskRoute:
        envelope_digest = _digest({
            "project_id": request.project_id,
            "principal_project_id": request.principal.project_id,
            "principal_role": request.principal.role,
            "task_kind": request.task_kind,
            "trace_id": request.trace_id,
        })
        unsigned = {
            "schema_version": "1.0",
            "outcome": "selected" if agent else "denied",
            "reason_code": reason,
            "task_kind": request.task_kind,
            "envelope_digest": envelope_digest,
            "catalog_version": catalog.version,
            "catalog_digest": catalog.digest,
            "primary_agent_id": agent.id if agent else None,
            "primary_agent_version": agent.version if agent else None,
            "skill_refs": list(agent.skill_refs) if agent else [],
            "required_capabilities": list(agent.required_capabilities) if agent else [],
            "review_agent_id": agent.review_agent_id if agent else None,
        }
        return cls(
            unsigned["outcome"], reason, request.task_kind, envelope_digest, catalog.version, catalog.digest,
            agent.id if agent else None, agent.version if agent else None,
            agent.skill_refs if agent else (), agent.required_capabilities if agent else (),
            agent.review_agent_id if agent else None, _digest(unsigned),
        )

    def to_payload(self) -> dict[str, object]:
        return {
            "schema_version": "1.0",
            "outcome": self.outcome,
            "reason_code": self.reason_code,
            "task_kind": self.task_kind,
            "envelope_digest": self.envelope_digest,
            "catalog_version": self.catalog_version,
            "catalog_digest": self.catalog_digest,
            "primary_agent_id": self.primary_agent_id,
            "primary_agent_version": self.primary_agent_version,
            "skill_refs": list(self.skill_refs),
            "required_capabilities": list(self.required_capabilities),
            "review_agent_id": self.review_agent_id,
            "route_digest": self.route_digest,
        }

    def to_bytes(self) -> bytes:
        return _canonical(self.to_payload())


@dataclass(frozen=True)
class TaskRouter:
    """Выбирает ровно один agent по exact task kind и authenticated role."""

    project_id: str
    catalog: AgentCatalog

    def __post_init__(self) -> None:
        if not self.project_id or self.catalog._validation_token is not _VALIDATED_CATALOG:
            raise ValueError("task router requires a verified catalog")

    def route(self, request: TaskEnvelope) -> TaskRoute:
        if request.project_id != self.project_id or request.principal.project_id != self.project_id:
            return TaskRoute.create(self.catalog, request, "project_mismatch", None)
        task_agents = tuple(agent for agent in self.catalog.agents if request.task_kind in agent.task_kinds)
        if not task_agents:
            return TaskRoute.create(self.catalog, request, "unknown_task_kind", None)
        eligible = tuple(agent for agent in task_agents if request.principal.role in agent.roles)
        if not eligible:
            return TaskRoute.create(self.catalog, request, "role_not_allowed", None)
        if len(eligible) != 1:
            return TaskRoute.create(self.catalog, request, "ambiguous_route", None)
        return TaskRoute.create(self.catalog, request, "exact_task_role_match", eligible[0])


def load_agent_catalog(profile: ProjectProfile) -> AgentCatalog:
    """Загружает bounded pack-owned catalog без auto-discovery."""

    path = profile.pack.agent_catalog
    descriptor = -1
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > 500_000:
            raise ValueError("agent catalog must be a bounded regular file")
        with os.fdopen(descriptor, "r", encoding="utf-8") as stream:
            descriptor = -1
            payload = json.load(stream, object_pairs_hook=_strict_object)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ValueError("agent catalog must use JSON-compatible YAML 1.2") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    return AgentCatalog.from_payload(payload, profile)
