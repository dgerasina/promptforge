"""Versioned и integrity-checked библиотека PromptForge skills."""

from __future__ import annotations

from dataclasses import dataclass, replace
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
from typing import Any, Callable, Mapping

from promptforge.platform.contracts import Principal, ROLES, SCHEMA_VERSION
from promptforge.platform.governance import GovernancePolicy
from promptforge.platform.skill_signatures import (
    SkillSigningKeyRegistry, load_detached_signatures, verify_release_signature,
)


_SKILL_ID = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
_VERSION = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_STATUSES = frozenset({"draft", "review", "approved", "deprecated", "quarantined", "revoked"})
_RISKS = frozenset({"low", "medium", "high"})
_MANIFEST_FIELDS = frozenset(
    {
        "schema_version", "id", "name", "version", "owner", "description", "status", "roles", "risk",
        "audiences", "entrypoint", "inputs_schema", "permissions", "compatibility", "evals", "reviewer_set",
        "content_digest", "signature",
    }
)
_SAFE_OWNER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_LIFECYCLE_TRANSITIONS = {
    "draft": frozenset({"review"}),
    "review": frozenset({"approved", "quarantined"}),
    "approved": frozenset({"deprecated", "quarantined", "revoked"}),
    "deprecated": frozenset({"revoked"}),
    "quarantined": frozenset({"review", "revoked"}),
    "revoked": frozenset(),
}


@dataclass(frozen=True)
class SkillApproval:
    """Связывает Git-reviewed approval с exact immutable package release."""

    id: str
    version: str
    content_digest: str
    release_digest: str
    signature: str
    reviewer_set: tuple[str, ...]
    evals_passed: bool

    def __post_init__(self) -> None:
        if not _SKILL_ID.fullmatch(self.id) or not _VERSION.fullmatch(self.version):
            raise ValueError("skill approval identity is invalid")
        if not _DIGEST.fullmatch(self.content_digest) or not _DIGEST.fullmatch(self.release_digest):
            raise ValueError("skill approval digest is invalid")
        if not re.fullmatch(r"repository:v1:[0-9a-f]{64}", self.signature):
            raise ValueError("skill approval signature is invalid")
        if len(self.reviewer_set) < 2 or len(set(self.reviewer_set)) != len(self.reviewer_set):
            raise ValueError("skill approval reviewers are invalid")
        if self.evals_passed is not True:
            raise ValueError("skill approval eval gate is not passed")


@dataclass(frozen=True)
class RepositorySkillApprovalRegistry:
    """Использует reviewable Git registry как repository-only approval trust root."""

    owner: str
    ordered_skill_ids: tuple[str, ...]
    approvals: tuple[SkillApproval, ...]

    def __post_init__(self) -> None:
        ordered = tuple(self.ordered_skill_ids)
        invalid_order = not ordered or any(not _SKILL_ID.fullmatch(item) for item in ordered)
        if not _SAFE_OWNER.fullmatch(self.owner) or invalid_order:
            raise ValueError("skill approval owner or order is invalid")
        approval_ids = tuple(approval.id for approval in self.approvals)
        if approval_ids != ordered or len(set(approval_ids)) != len(approval_ids):
            raise ValueError("skill approvals must follow configured order")
        object.__setattr__(self, "ordered_skill_ids", ordered)

    @classmethod
    def from_file(cls, path: Path) -> RepositorySkillApprovalRegistry:
        """Загружает closed registry без duplicate JSON keys."""

        try:
            payload = json.loads(
                path.read_text(encoding="utf-8"),
                object_pairs_hook=lambda pairs: _unique_json_object(pairs),
            )
        except (OSError, UnicodeError, json.JSONDecodeError) as error:
            raise ValueError("skill approval registry is invalid") from error
        if not isinstance(payload, Mapping) or set(payload) != {
            "schema_version", "owner", "ordered_skill_ids", "approvals",
        }:
            raise ValueError("skill approval registry fields mismatch")
        if payload["schema_version"] != SCHEMA_VERSION or not isinstance(payload["approvals"], list):
            raise ValueError("skill approval registry version or approvals are invalid")
        approvals = []
        for item in payload["approvals"]:
            if not isinstance(item, Mapping) or set(item) != {
                "id", "version", "content_digest", "release_digest", "signature", "reviewer_set", "evals_passed",
            }:
                raise ValueError("skill approval fields mismatch")
            approvals.append(
                SkillApproval(
                    item["id"], item["version"], item["content_digest"], item["release_digest"], item["signature"],
                    tuple(item["reviewer_set"]), item["evals_passed"],
                )
            )
        registry = cls(payload["owner"], tuple(payload["ordered_skill_ids"]), tuple(approvals))
        keys = SkillSigningKeyRegistry.from_file(path.parents[2] / "config" / "skill-signing-keys.json")
        detached = load_detached_signatures(path.with_name("skill-signatures.json"))
        by_release = {(item.skill_id, item.version): item for item in detached}
        if len(detached) != len(approvals):
            raise ValueError("every skill approval requires one detached signature")
        for approval in approvals:
            signature = by_release.get((approval.id, approval.version))
            if (
                signature is None or signature.release_digest != approval.release_digest
                or not verify_release_signature(signature, keys)
            ):
                raise PermissionError("skill detached signature verification failed")
        return registry

    def signature_for(self, release: SkillRelease) -> str:
        approval = self._approval(release)
        if tuple(release.reviewer_set) != approval.reviewer_set:
            raise PermissionError("skill reviewer gate mismatch")
        return approval.signature

    def verify(self, release: SkillRelease, package: Path) -> bool:
        """Проверяет exact registry binding; package integrity отдельно проверяет loader."""

        try:
            approval = self._approval(release)
        except PermissionError:
            return False
        return (
            package.name == release.id
            and release.status == "approved"
            and _release_binding(release) == approval.release_digest
            and release.signature == approval.signature
            and tuple(release.reviewer_set) == approval.reviewer_set
        )

    def _approval(self, release: SkillRelease) -> SkillApproval:
        approval = next((item for item in self.approvals if item.id == release.id), None)
        if approval is None or (
            approval.version != release.version or approval.content_digest != release.content_digest
            or approval.release_digest != _release_binding(release)
        ):
            raise PermissionError("skill release has no exact approval")
        return approval


@dataclass(frozen=True)
class SkillLifecycle:
    """Применяет последовательные owner-controlled lifecycle transitions."""

    owner: str

    def __post_init__(self) -> None:
        if not _SAFE_OWNER.fullmatch(self.owner):
            raise ValueError("skill lifecycle owner is invalid")

    def transition(
        self,
        release: SkillRelease,
        target_status: str,
        actor: Principal,
        registry: RepositorySkillApprovalRegistry,
    ) -> SkillRelease:
        """Возвращает новый release или блокирует skip/unauthorized transition."""

        if (
            not GovernancePolicy.builtin().allows(actor, "skills.manage")
            or target_status not in _LIFECYCLE_TRANSITIONS.get(release.status, frozenset())
        ):
            raise PermissionError("skill lifecycle transition is not allowed")
        transitioned = replace(release, status=target_status)
        if target_status == "approved":
            transitioned = replace(transitioned, signature=registry.signature_for(transitioned))
            if not registry.verify(transitioned, Path(transitioned.id)):
                raise PermissionError("skill approval verification failed")
        return transitioned


@dataclass(frozen=True)
class SkillRelease:
    """Описывает неизменяемый release одного skill-пакета."""

    id: str
    name: str
    version: str
    owner: str
    description: str
    status: str
    roles: tuple[str, ...]
    risk: str
    audiences: tuple[str, ...]
    entrypoint: str
    inputs_schema: str
    permissions_required: tuple[str, ...]
    permissions_forbidden: tuple[str, ...]
    compatible_clients: tuple[str, ...]
    evals: str
    reviewer_set: tuple[str, ...]
    content_digest: str
    signature: str
    integrity_verified: bool = False

    def __post_init__(self) -> None:
        roles = tuple(self.roles)
        audiences = tuple(self.audiences)
        required = tuple(self.permissions_required)
        forbidden = tuple(self.permissions_forbidden)
        clients = tuple(self.compatible_clients)
        reviewers = tuple(self.reviewer_set)
        entrypoint = PurePosixPath(self.entrypoint)
        if not _SKILL_ID.fullmatch(self.id) or not _VERSION.fullmatch(self.version):
            raise ValueError("skill id or version is invalid")
        if self.status not in _STATUSES or self.risk not in _RISKS:
            raise ValueError("skill status or risk is invalid")
        if not roles or len(set(roles)) != len(roles) or any(role not in ROLES for role in roles):
            raise ValueError("skill roles are invalid")
        if not all(isinstance(value, str) and value.strip() for value in (self.name, self.owner, self.description)):
            raise ValueError("skill metadata is invalid")
        if (
            not audiences or not clients or len(set(audiences)) != len(audiences)
            or any(not isinstance(item, str) or not item.strip() for item in audiences + clients + reviewers)
        ):
            raise ValueError("skill audiences or compatibility is invalid")
        if entrypoint != PurePosixPath("SKILL.md") or entrypoint.is_absolute() or ".." in entrypoint.parts:
            raise ValueError("skill entrypoint is invalid")
        if len(set(required + forbidden)) != len(required + forbidden):
            raise ValueError("skill permissions overlap or contain duplicates")
        if any(not _safe_capability(item) for item in required + forbidden):
            raise ValueError("skill permissions are invalid")
        if self.risk in {"medium", "high"} and len(reviewers) < 2:
            raise ValueError("medium/high risk skill requires domain and security reviewers")
        for path_value in (self.inputs_schema, self.evals):
            path = PurePosixPath(path_value)
            if path.is_absolute() or ".." in path.parts:
                raise ValueError("skill resource path is invalid")
        if not _DIGEST.fullmatch(self.content_digest):
            raise ValueError("skill content digest is invalid")
        if not isinstance(self.signature, str) or (
            self.signature and not re.fullmatch(r"(?:minisign:.+|repository:v1:[0-9a-f]{64})", self.signature)
        ):
            raise ValueError("skill signature is invalid")
        object.__setattr__(self, "roles", roles)
        object.__setattr__(self, "audiences", audiences)
        object.__setattr__(self, "permissions_required", required)
        object.__setattr__(self, "permissions_forbidden", forbidden)
        object.__setattr__(self, "compatible_clients", clients)
        object.__setattr__(self, "reviewer_set", reviewers)

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> SkillRelease:
        if not isinstance(payload, Mapping) or frozenset(payload) != _MANIFEST_FIELDS:
            raise ValueError("skill manifest fields mismatch")
        if payload["schema_version"] != SCHEMA_VERSION:
            raise ValueError("unsupported skill manifest schema version")
        permissions = payload["permissions"]
        compatibility = payload["compatibility"]
        if not isinstance(permissions, Mapping) or frozenset(permissions) != {"required", "forbidden"}:
            raise ValueError("skill permissions fields mismatch")
        if not isinstance(compatibility, Mapping) or frozenset(compatibility) != {"clients"}:
            raise ValueError("skill compatibility fields mismatch")
        return cls(
            id=payload["id"], name=payload["name"], version=payload["version"], owner=payload["owner"],
            description=payload["description"], status=payload["status"], roles=tuple(payload["roles"]),
            risk=payload["risk"], audiences=tuple(payload["audiences"]), entrypoint=payload["entrypoint"],
            inputs_schema=payload["inputs_schema"], permissions_required=tuple(permissions["required"]),
            permissions_forbidden=tuple(permissions["forbidden"]),
            compatible_clients=tuple(compatibility["clients"]), evals=payload["evals"],
            reviewer_set=tuple(payload["reviewer_set"]), content_digest=payload["content_digest"],
            signature=payload["signature"],
        )

    def verified(self) -> SkillRelease:
        return SkillRelease(
            self.id, self.name, self.version, self.owner, self.description, self.status, self.roles, self.risk,
            self.audiences, self.entrypoint, self.inputs_schema, self.permissions_required,
            self.permissions_forbidden, self.compatible_clients, self.evals, self.reviewer_set,
            self.content_digest, self.signature, True,
        )


@dataclass(frozen=True)
class SkillLibrary:
    """Выдаёт только approved и integrity-verified releases разрешённой роли."""

    releases: tuple[SkillRelease, ...]

    def __post_init__(self) -> None:
        releases = tuple(self.releases)
        identities = tuple((release.id, release.version) for release in releases)
        if len(set(identities)) != len(identities):
            raise ValueError("skill library contains duplicate releases")
        object.__setattr__(self, "releases", releases)

    def for_role(self, role: str) -> tuple[SkillRelease, ...]:
        if role not in ROLES:
            raise ValueError(f"unsupported role: {role}")
        eligible = (
            release for release in self.releases
            if release.status == "approved" and release.integrity_verified and role in release.roles
        )
        latest: dict[str, SkillRelease] = {}
        for release in eligible:
            current = latest.get(release.id)
            if current is None or _version_key(release.version) > _version_key(current.version):
                latest = {**latest, release.id: release}
        return tuple(latest[key] for key in sorted(latest))

    def review_queue(self, role: str) -> tuple[SkillRelease, ...]:
        if role not in {"owner", "maintainer"}:
            return ()
        return tuple(release for release in self.releases if release.status == "review" and release.integrity_verified)


def load_skill_library(
    root: Path, signature_verifier: Callable[[SkillRelease, Path], bool] | None = None,
) -> SkillLibrary:
    """Загружает manifests без symlinks и fail closed проверяет package digest."""

    if not root.is_dir() or root.is_symlink():
        raise ValueError("skill library root must be a real directory")
    releases: list[SkillRelease] = []
    for package in sorted(root.iterdir()):
        if not package.is_dir() or package.is_symlink():
            continue
        manifest_path = package / "manifest.json"
        if manifest_path.is_symlink():
            raise ValueError(f"skill manifest must not be a symlink: {package.name}")
        try:
            payload = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as error:
            raise ValueError(f"invalid skill manifest: {package.name}") from error
        release = SkillRelease.from_payload(payload)
        entrypoint = _package_resource(package, release.entrypoint)
        if release.id != package.name or not entrypoint.is_file():
            raise ValueError("skill package identity or entrypoint mismatch")
        _validate_skill_frontmatter(entrypoint, release.id)
        _validate_input_schema(_package_resource(package, release.inputs_schema))
        _validate_evals(_package_resource(package, release.evals))
        if _package_digest(package) != release.content_digest:
            raise ValueError(f"skill package integrity mismatch: {release.id}")
        if release.status == "approved" and (
            not release.signature or signature_verifier is None or not signature_verifier(release, package)
        ):
            raise ValueError(f"approved skill signature is not verified: {release.id}")
        releases.append(release.verified())
    return SkillLibrary(tuple(releases))


def evaluate_skill_evals(package: Path, release: SkillRelease) -> tuple[int, int]:
    """Проверяет покрытие expectations corpus в instructions."""

    eval_path = _package_resource(package, release.evals)
    cases = _validate_evals(eval_path)
    entrypoint = _package_resource(package, release.entrypoint).read_text(encoding="utf-8").lower()
    required_sections = ("workflow", "fail closed")
    passed = sum(
        all(str(expectation).lower() in entrypoint for expectation in case["expected"])
        and all(section in entrypoint for section in required_sections)
        for case in cases
    )
    return len(cases), passed


def require_skill_evals(package: Path, release: SkillRelease) -> tuple[int, int]:
    """Возвращает полный eval result или блокирует distribution."""

    total, passed = evaluate_skill_evals(package, release)
    if total == 0 or passed != total:
        raise PermissionError("skill eval gate is incomplete")
    return total, passed


def _package_digest(package: Path) -> str:
    digest = hashlib.sha256()
    entries = tuple(package.rglob("*"))
    if any(path.is_symlink() for path in entries):
        raise ValueError("skill package must not contain symlinks")
    files = sorted(path for path in entries if path.is_file() and path != package / "manifest.json")
    if not files or len(files) > 128:
        raise ValueError("skill package contents are invalid")
    total_size = 0
    for path in files:
        relative = path.relative_to(package).as_posix()
        content = path.read_bytes()
        if len(content) > 256_000:
            raise ValueError("skill package file is too large")
        total_size += len(content)
        if total_size > 1_000_000:
            raise ValueError("skill package is too large")
        digest.update(relative.encode("utf-8") + b"\0" + content + b"\0")
    return f"sha256:{digest.hexdigest()}"


def _release_binding(release: SkillRelease) -> str:
    payload = {
        "id": release.id, "name": release.name, "version": release.version, "owner": release.owner,
        "description": release.description, "status": "approved", "roles": list(release.roles), "risk": release.risk,
        "audiences": list(release.audiences), "entrypoint": release.entrypoint,
        "inputs_schema": release.inputs_schema,
        "permissions": {
            "required": list(release.permissions_required), "forbidden": list(release.permissions_forbidden),
        },
        "compatibility": {"clients": list(release.compatible_clients)}, "evals": release.evals,
        "reviewer_set": list(release.reviewer_set), "content_digest": release.content_digest,
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def _package_resource(package: Path, relative: str) -> Path:
    root = package.resolve(strict=True)
    resource = (package / relative).resolve(strict=True)
    if not resource.is_relative_to(root) or resource.is_symlink():
        raise ValueError("skill resource escapes package boundary")
    return resource


def _safe_capability(value: object) -> bool:
    return isinstance(value, str) and bool(re.fullmatch(r"[a-z][a-z0-9_.:-]{0,127}", value))


def _unique_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result = {**result, key: value}
    return result


def _version_key(value: str) -> tuple[int, int, int]:
    major, minor, patch = value.split(".")
    return int(major), int(minor), int(patch)


def _validate_skill_frontmatter(entrypoint: Path, skill_id: str) -> None:
    try:
        text = entrypoint.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        raise ValueError("skill entrypoint is not valid UTF-8") from error
    match = re.match(r"\A---\nname: ([a-z0-9-]+)\ndescription: ([^\n]+)\n---\n", text)
    if not match or match.group(1) != skill_id or not match.group(2).strip():
        raise ValueError("skill frontmatter must contain exact name and description")
    lowered = text.lower()
    if "ignore previous instructions" in lowered or "disable security" in lowered:
        raise ValueError("skill contains a suspicious instruction")


def _validate_input_schema(path: Path) -> None:
    try:
        schema = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ValueError("skill input schema is invalid") from error
    if schema.get("type") != "object" or schema.get("additionalProperties") is not False:
        raise ValueError("skill input schema must be a closed object")


def _validate_evals(path: Path) -> tuple[Mapping[str, object], ...]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ValueError("skill evals are invalid") from error
    if not isinstance(payload, Mapping) or set(payload) != {"schema_version", "cases"}:
        raise ValueError("skill eval fields mismatch")
    if payload["schema_version"] != SCHEMA_VERSION:
        raise ValueError("skill eval version is invalid")
    cases = payload.get("cases")
    if not isinstance(cases, list) or any(not isinstance(case, Mapping) for case in cases):
        raise ValueError("skill eval cases must be objects")
    for case in cases:
        if set(case) != {"id", "kind", "expected"} or not _SKILL_ID.fullmatch(str(case["id"])):
            raise ValueError("skill eval case contract is invalid")
        if (
            not isinstance(case["expected"], list) or not case["expected"]
            or any(not isinstance(item, str) or not item.strip() for item in case["expected"])
        ):
            raise ValueError("skill eval expectations are invalid")
    kinds = {case.get("kind") for case in cases}
    if kinds != {"happy_path", "edge", "security"}:
        raise ValueError("skill evals must cover happy_path, edge and security")
    return tuple(cases)
