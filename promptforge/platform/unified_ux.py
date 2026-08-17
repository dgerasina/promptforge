"""Единый deterministic UX поверх identity, task router и agent catalog."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re
from types import MappingProxyType
from typing import Mapping

from promptforge.core.project_profile import ProjectProfile, load_project_profile
from promptforge.platform.contracts import Principal, ROLES
from promptforge.platform.secure_runtime import load_embedded_registry
from promptforge.platform.task_router import AgentCatalog, TaskEnvelope, TaskRouter, load_agent_catalog


_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_SAFE_PATH = re.compile(r"^[A-Za-z0-9._/-]{1,512}$")
_ROUTE_DIGEST = re.compile(r"^(|sha256:[0-9a-f]{64})$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_STAGE_IDS = (
    "resolve-identity", "route", "execute-skill", "changed-files-review", "documentation", "evidence",
)
_STAGE_STATUSES = frozenset({"complete", "ready", "planned", "blocked", "denied", "not-applicable"})


def _digest(value: object) -> str:
    encoded = json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


@dataclass(frozen=True)
class WorkRequest:
    principal_id: str
    task_kind: str | None
    trace_id: str
    paths: tuple[str, ...] = ()
    deploy_paths: tuple[str, ...] = ()
    mode: str = "preview"
    inputs_present: bool = False

    def __post_init__(self) -> None:
        paths, deploy = tuple(self.paths), tuple(self.deploy_paths)
        if not _SAFE_ID.fullmatch(self.principal_id) or not _SAFE_ID.fullmatch(self.trace_id):
            raise ValueError("work identity or trace is invalid")
        if self.task_kind is not None and not re.fullmatch(r"[a-z][a-z0-9-]*(?:\.[a-z0-9-]+)+", self.task_kind):
            raise ValueError("work task kind is invalid")
        if self.mode not in {"preview", "execute"}:
            raise ValueError("work mode is invalid")
        if not isinstance(self.inputs_present, bool):
            raise ValueError("work inputs marker is invalid")
        if any(
            not _SAFE_PATH.fullmatch(path) or path.startswith(("/", "../")) or "/../" in path
            for path in (*paths, *deploy)
        ):
            raise ValueError("work path is unsafe")
        if len(set(paths)) != len(paths) or len(set(deploy)) != len(deploy) or not set(deploy) <= set(paths):
            raise ValueError("work path scope is invalid")
        object.__setattr__(self, "paths", paths)
        object.__setattr__(self, "deploy_paths", deploy)


@dataclass(frozen=True)
class WorkResult:
    mode: str
    status: str
    reason_code: str
    task_kind: str
    principal_id: str
    role: str
    agent_id: str | None
    agent_version: str | None
    skills: tuple[str, ...]
    required_capabilities: tuple[str, ...]
    review_agent_id: str | None
    stages: tuple[Mapping[str, object], ...]
    required_inputs: tuple[str, ...]
    route_digest: str
    catalog_version: str
    catalog_digest: str
    execution: Mapping[str, object] | None = None
    authorization: Mapping[str, object] | None = None

    def __post_init__(self) -> None:
        if self.mode not in {"preview", "execute"}:
            raise ValueError("work result mode is invalid")
        if self.status not in {"ready", "completed", "blocked", "denied"}:
            raise ValueError("work result status is invalid")
        if not self.reason_code or not self.task_kind or not self.principal_id:
            raise ValueError("work result identity is incomplete")
        if self.role not in {"", *ROLES}:
            raise ValueError("work result role is invalid")
        if self.agent_id is None and self.agent_version is not None:
            raise ValueError("work result agent version has no agent")
        if self.agent_id is not None and self.agent_version is None:
            raise ValueError("work result agent has no version")
        if not _ROUTE_DIGEST.fullmatch(self.route_digest):
            raise ValueError("work result route digest is invalid")
        if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", self.catalog_version) or not _DIGEST.fullmatch(
            self.catalog_digest
        ):
            raise ValueError("work result catalog binding is invalid")
        if (
            len(self.stages) != len(_STAGE_IDS)
            or tuple(stage.get("id") for stage in self.stages) != _STAGE_IDS
            or any(stage.get("status") not in _STAGE_STATUSES for stage in self.stages)
            or any(not isinstance(stage.get("automatic"), bool) for stage in self.stages)
        ):
            raise ValueError("work result stages are invalid")
        if len(self.skills) != len(set(self.skills)) or len(self.required_capabilities) != len(set(self.required_capabilities)):
            raise ValueError("work result references are duplicated")
        if self.status == "completed" and self.execution is None:
            raise ValueError("completed work result requires execution evidence")
        if self.status not in {"completed", "blocked"} and self.execution is not None:
            raise ValueError("work result status must not include execution evidence")
        object.__setattr__(self, "stages", tuple(MappingProxyType(dict(stage)) for stage in self.stages))
        if self.execution is not None:
            object.__setattr__(self, "execution", MappingProxyType(dict(self.execution)))
        if self.authorization is not None:
            object.__setattr__(self, "authorization", MappingProxyType(dict(self.authorization)))

    def to_payload(self) -> dict[str, object]:
        agent = None if self.agent_id is None else {"id": self.agent_id, "version": self.agent_version}
        unsigned = {
            "schema_version": "1.0", "ux_version": "1.0", "mode": self.mode, "status": self.status,
            "reason_code": self.reason_code, "task_kind": self.task_kind, "principal_id": self.principal_id,
            "role": self.role, "agent": agent, "skills": list(self.skills),
            "required_capabilities": list(self.required_capabilities), "review_agent_id": self.review_agent_id,
            "stages": [dict(stage) for stage in self.stages], "required_inputs": list(self.required_inputs),
            "route_digest": self.route_digest, "execution": None if self.execution is None else dict(self.execution),
            "authorization": None if self.authorization is None else dict(self.authorization),
            "catalog_version": self.catalog_version, "catalog_digest": self.catalog_digest,
            "network_used": bool(self.execution and self.execution.get("network_used", False)),
        }
        return {**unsigned, "plan_digest": _digest(unsigned)}


@dataclass(frozen=True)
class UnifiedWorkCoordinator:
    profile: ProjectProfile
    catalog: AgentCatalog
    principals: Mapping[str, tuple[str, bool]]

    @classmethod
    def from_repository(cls, repository: Path) -> UnifiedWorkCoordinator:
        root = Path(repository).resolve(strict=True)
        profile = load_project_profile(root / "project-profile.yaml")
        registry = load_embedded_registry(root)
        principals = MappingProxyType({item.id: (item.role, item.enabled) for item in registry.principals})
        return cls(profile, load_agent_catalog(profile), principals)

    def plan(self, request: WorkRequest) -> WorkResult:
        task_kind = request.task_kind or ("review.changed-files" if request.paths else None)
        if task_kind is None:
            raise ValueError("task kind is required when changed paths are absent")
        identity = self.principals.get(request.principal_id)
        if identity is None or not identity[1]:
            return self._denied(request, task_kind, "principal_unknown")
        role = identity[0]
        if task_kind in {
            "documentation.sync", "confluence.snapshot", "documentation.from-snapshot",
        } and request.principal_id not in {"owner-local", "maintainer-local"}:
            return self._denied(request, task_kind, "governance_identity_required", role)
        principal = Principal(request.principal_id, role, self.profile.project_key)
        route = TaskRouter(self.profile.project_key, self.catalog).route(
            TaskEnvelope(self.profile.project_key, principal, task_kind, request.trace_id),
        )
        if route.outcome != "selected":
            return self._denied(request, task_kind, route.reason_code, role, route.route_digest)
        required_inputs = self._required_inputs(request, task_kind)
        status, reason = "ready", "preview_ready"
        if request.mode == "execute":
            if required_inputs:
                status, reason = "blocked", "required_inputs_missing"
            else:
                reason = "execution_ready"
        stages = self._stages(task_kind, status, route.review_agent_id)
        return WorkResult(
            request.mode, status, reason, task_kind, request.principal_id, role, route.primary_agent_id,
            route.primary_agent_version, route.skill_refs, route.required_capabilities, route.review_agent_id,
            stages, required_inputs, route.route_digest, route.catalog_version, route.catalog_digest,
        )

    @staticmethod
    def _stages(task_kind: str, status: str, review_agent_id: str | None) -> tuple[Mapping[str, object], ...]:
        execution_status = "blocked" if status == "blocked" else "ready"
        return (
            {"id": "resolve-identity", "status": "complete", "automatic": True},
            {"id": "route", "status": "complete", "automatic": True},
            {"id": "execute-skill", "status": execution_status, "automatic": task_kind == "review.changed-files"},
            {
                "id": "changed-files-review", "status": "ready" if review_agent_id or task_kind == "review.changed-files"
                else "not-applicable", "automatic": True,
            },
            {"id": "documentation", "status": "planned", "automatic": True},
            {"id": "evidence", "status": "planned", "automatic": True},
        )

    @staticmethod
    def _required_inputs(request: WorkRequest, task_kind: str) -> tuple[str, ...]:
        if task_kind == "review.changed-files":
            return () if request.paths else ("changed_paths",)
        return () if request.inputs_present else ("task_inputs",)

    def _denied(
        self, request: WorkRequest, task_kind: str, reason: str, role: str = "", route_digest: str = "",
    ) -> WorkResult:
        stages = (
            {"id": "resolve-identity", "status": "complete" if role else "denied", "automatic": True},
            {"id": "route", "status": "denied", "automatic": True},
            {"id": "execute-skill", "status": "blocked", "automatic": False},
            {"id": "changed-files-review", "status": "blocked", "automatic": True},
            {"id": "documentation", "status": "blocked", "automatic": True},
            {"id": "evidence", "status": "blocked", "automatic": True},
        )
        return WorkResult(
            request.mode, "denied", reason, task_kind, request.principal_id, role, None, None, (), (), None,
            stages, (), route_digest,
            self.catalog.version, self.catalog.digest,
        )
