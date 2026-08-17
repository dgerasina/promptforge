"""Ролевой каталог первых навыков PromptForge Platform."""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
from typing import Any, Mapping

from promptforge.core.project_profile import ProjectProfile, load_project_profile
from promptforge.platform.contracts import ROLES, SCHEMA_VERSION, SkillSpec
from promptforge.platform.skill_library import RepositorySkillApprovalRegistry, load_skill_library


@dataclass(frozen=True)
class SkillCatalog:
    """Предоставляет роли только видимые ей навыки."""

    skills: tuple[SkillSpec, ...]

    def __post_init__(self) -> None:
        frozen_skills = tuple(self.skills)
        if len({skill.id for skill in frozen_skills}) != len(frozen_skills):
            raise ValueError("skill catalog contains duplicate ids")
        object.__setattr__(self, "skills", frozen_skills)

    def for_role(self, role: str) -> tuple[SkillSpec, ...]:
        """Возвращает новый кортеж навыков для указанной роли."""

        if role not in ROLES:
            raise ValueError(f"unsupported role: {role}")
        return tuple(skill for skill in self.skills if role in skill.roles)

    def to_payload(self) -> dict[str, object]:
        """Сериализует каталог без выдачи дополнительных прав."""

        return {"schema_version": SCHEMA_VERSION, "skills": [skill.to_payload() for skill in self.skills]}

    def to_wire(self) -> dict[str, object]:
        return self.to_payload()

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> SkillCatalog:
        """Восстанавливает каталог из закрытого versioned payload."""

        if not isinstance(payload, Mapping):
            raise ValueError("skill catalog payload must be an object")
        fields = frozenset({"schema_version", "skills"})
        unknown, missing = frozenset(payload) - fields, fields - frozenset(payload)
        if unknown or missing:
            raise ValueError(f"skill catalog fields mismatch: unknown={sorted(unknown)}, missing={sorted(missing)}")
        if payload["schema_version"] != SCHEMA_VERSION:
            raise ValueError(f"unsupported schema version: {payload['schema_version']}")
        if not isinstance(payload["skills"], list):
            raise ValueError("skills must be an array")
        return cls(tuple(SkillSpec.from_payload(item) for item in payload["skills"]))


def builtin_skill_catalog() -> SkillCatalog:
    """Возвращает каталог активного repository profile."""

    root = Path(__file__).resolve().parents[2]
    return catalog_from_project_profile(load_project_profile(root / "project-profile.yaml"))


def catalog_from_project_profile(profile: ProjectProfile) -> SkillCatalog:
    """Строит каталог только из registry-approved integrity-verified releases."""

    if profile.skill_approvals is None:
        if profile.pack.approved_skill_order:
            raise ValueError("project pack approval registry is missing")
        return SkillCatalog(())
    registry = RepositorySkillApprovalRegistry.from_file(profile.skill_approvals)
    if registry.ordered_skill_ids != profile.pack.approved_skill_order:
        raise ValueError("project pack approval order drift")
    library = load_skill_library(profile.skills_root, registry.verify)
    return catalog_from_skill_library(library, registry.ordered_skill_ids)


def catalog_from_skill_library(library: object, ordered_skill_ids: tuple[str, ...]) -> SkillCatalog:
    """Строит discovery catalog только из approved integrity-verified releases."""

    releases = getattr(library, "releases", None)
    if not isinstance(releases, tuple):
        raise ValueError("skill library is invalid")
    approved = {
        release.id: release for release in releases
        if release.status == "approved" and release.integrity_verified
    }
    if set(approved) != set(ordered_skill_ids) or len(approved) != len(ordered_skill_ids):
        raise ValueError("approved skill library does not match lifecycle order")
    return SkillCatalog(
        tuple(SkillSpec(skill_id, approved[skill_id].roles, approved[skill_id].risk) for skill_id in ordered_skill_ids)
    )
