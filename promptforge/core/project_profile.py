"""Dependency-free loader JSON-compatible YAML project profiles."""

from __future__ import annotations

from dataclasses import dataclass
import json
import os
from pathlib import Path
import re
import stat
from typing import Mapping

from promptforge.core.repository_index import RepositoryIndexConfig


_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_SAFE_RELATIVE = re.compile(r"^[A-Za-z0-9._/-]{1,512}$")
_PROFILE_FIELDS = frozenset({"schema_version", "profile_id", "project_key", "pack"})
_PACK_FIELDS = frozenset({
    "schema_version", "id", "description", "integrations", "skills", "skill_approvals", "review",
    "repository_index", "agent_catalog", "task_intents",
})
_SKILLS_FIELDS = frozenset({"root", "approved_order"})
_REVIEW_FIELDS = frozenset({"non_prod_suffixes", "sandbox_names", "sandbox_target_fields", "surfaces"})
_SURFACE_FIELDS = frozenset({"id", "extensions", "path_markers"})
_MAX_DOCUMENT_BYTES = 100_000


def _strict_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate project profile field")
        result = {**result, key: value}
    return result


def _safe_id(value: object, name: str) -> str:
    if not isinstance(value, str) or not _SAFE_ID.fullmatch(value):
        raise ValueError(f"{name} is invalid")
    return value


def _string_tuple(value: object, name: str, *, allow_empty: bool = True) -> tuple[str, ...]:
    if (
        not isinstance(value, list) or (not allow_empty and not value)
        or any(not isinstance(item, str) or not item or len(item) > 128 for item in value)
        or len(set(value)) != len(value)
    ):
        raise ValueError(f"{name} must be a unique string array")
    return tuple(value)


def _identifier_tuple(value: object, name: str) -> tuple[str, ...]:
    return tuple(_safe_id(item, name) for item in _string_tuple(value, name))


def _safe_relative(root: Path, value: object, name: str, *, require_file: bool = False) -> Path:
    if (
        not isinstance(value, str) or not _SAFE_RELATIVE.fullmatch(value) or value.startswith(("/", "../"))
        or "/../" in value or "//" in value
    ):
        raise ValueError(f"{name} is unsafe")
    path = root / value
    if path.is_symlink() or path.resolve() != path or not path.resolve().is_relative_to(root):
        raise ValueError(f"{name} escapes its root")
    if require_file and not path.is_file():
        raise ValueError(f"{name} must be a regular file")
    return path


def _load_document(path: Path, name: str) -> Mapping[str, object]:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > _MAX_DOCUMENT_BYTES:
                raise ValueError(f"{name} must be a bounded regular file")
            with os.fdopen(descriptor, "r", encoding="utf-8") as stream:
                descriptor = -1
                payload = json.load(stream, object_pairs_hook=_strict_object)
        finally:
            if descriptor >= 0:
                os.close(descriptor)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ValueError(f"{name} must use JSON-compatible YAML 1.2") from error
    if not isinstance(payload, Mapping):
        raise ValueError(f"{name} must be an object")
    return payload


@dataclass(frozen=True)
class SurfaceRule:
    """Описывает один project-defined review surface."""

    id: str
    extensions: tuple[str, ...]
    path_markers: tuple[str, ...]

    def __post_init__(self) -> None:
        _safe_id(self.id, "surface id")
        if not self.extensions and not self.path_markers:
            raise ValueError("surface must define an extension or path marker")


@dataclass(frozen=True)
class ReviewRules:
    """Хранит review markers, передаваемые core из выбранного pack."""

    non_prod_suffixes: tuple[str, ...]
    sandbox_names: tuple[str, ...]
    sandbox_target_fields: tuple[str, ...]
    surfaces: tuple[SurfaceRule, ...]

    def __post_init__(self) -> None:
        if not self.non_prod_suffixes or any(not item.startswith("_") for item in self.non_prod_suffixes):
            raise ValueError("review non-production suffixes are invalid")
        if len({surface.id for surface in self.surfaces}) != len(self.surfaces):
            raise ValueError("review surfaces contain duplicate ids")


@dataclass(frozen=True)
class ProjectPack:
    """Описывает domain assets и правила, не входящие в переносимое ядро."""

    id: str
    description: str
    integrations: tuple[str, ...]
    skills_root: Path
    skill_approvals: Path | None
    approved_skill_order: tuple[str, ...]
    review: ReviewRules
    repository_index: RepositoryIndexConfig
    agent_catalog: Path
    task_intents: Path

    @classmethod
    def from_file(cls, path: Path) -> ProjectPack:
        resolved = Path(path)
        payload = _load_document(resolved, "project pack")
        if set(payload) != _PACK_FIELDS or payload.get("schema_version") != "1.0":
            raise ValueError("project pack fields or version mismatch")
        skills = payload.get("skills")
        review = payload.get("review")
        if not isinstance(skills, Mapping) or set(skills) != _SKILLS_FIELDS:
            raise ValueError("project pack skills contract is invalid")
        if not isinstance(review, Mapping) or set(review) != _REVIEW_FIELDS:
            raise ValueError("project pack review contract is invalid")
        surfaces_raw = review.get("surfaces")
        if not isinstance(surfaces_raw, list) or not surfaces_raw:
            raise ValueError("project pack surfaces are invalid")
        surfaces = []
        for item in surfaces_raw:
            if not isinstance(item, Mapping) or set(item) != _SURFACE_FIELDS:
                raise ValueError("project pack surface fields mismatch")
            surfaces.append(SurfaceRule(
                _safe_id(item["id"], "surface id"),
                _string_tuple(item["extensions"], "surface extensions"),
                _string_tuple(item["path_markers"], "surface path markers"),
            ))
        root = resolved.parent.resolve(strict=True)
        skills_root = _safe_relative(root, skills["root"], "skills root")
        if not skills_root.is_dir():
            raise ValueError("skills root must be a directory")
        approval_value = payload["skill_approvals"]
        if approval_value is None:
            approval_path = None
        else:
            approval_path = _safe_relative(root, approval_value, "skill approvals", require_file=True)
        return cls(
            _safe_id(payload["id"], "pack id"),
            _safe_id(payload["description"], "pack description"),
            _identifier_tuple(payload["integrations"], "pack integrations"),
            skills_root,
            approval_path,
            _identifier_tuple(skills["approved_order"], "approved skill order"),
            ReviewRules(
                _string_tuple(review["non_prod_suffixes"], "non-production suffixes", allow_empty=False),
                _string_tuple(review["sandbox_names"], "sandbox names"),
                _string_tuple(review["sandbox_target_fields"], "sandbox target fields"),
                tuple(surfaces),
            ),
            RepositoryIndexConfig.from_payload(payload["repository_index"]),
            _safe_relative(root, payload["agent_catalog"], "agent catalog", require_file=True),
            _safe_relative(root, payload["task_intents"], "task intents", require_file=True),
        )


@dataclass(frozen=True)
class ProjectProfile:
    """Связывает универсальный runtime с одним repository-local pack."""

    profile_id: str
    project_key: str
    pack: ProjectPack
    source: Path

    @property
    def skills_root(self) -> Path:
        """Возвращает pack-owned корень skills."""

        return self.pack.skills_root

    @property
    def skill_approvals(self) -> Path | None:
        """Возвращает pack-owned approval registry, если он объявлен."""

        return self.pack.skill_approvals

    @classmethod
    def from_file(cls, path: Path) -> ProjectProfile:
        source = Path(path)
        return cls.from_payload(_load_document(source, "project profile"), source.parent.resolve(strict=True), source)

    @classmethod
    def from_payload(
        cls, payload: Mapping[str, object], root: Path, source: Path | None = None,
    ) -> ProjectProfile:
        if (
            not isinstance(payload, Mapping)
            or set(payload) != _PROFILE_FIELDS
            or payload.get("schema_version") != "1.0"
        ):
            raise ValueError("project profile fields or version mismatch")
        base = Path(root).resolve(strict=True)
        pack_path = _safe_relative(base, payload["pack"], "project pack", require_file=True)
        return cls(
            _safe_id(payload["profile_id"], "profile id"),
            _safe_id(payload["project_key"], "project key"),
            ProjectPack.from_file(pack_path),
            Path(source).resolve(strict=True) if source else base / "project-profile.yaml",
        )


def load_project_profile(path: Path) -> ProjectProfile:
    """Загружает exact profile file без fallback и auto-discovery."""

    return ProjectProfile.from_file(path)
