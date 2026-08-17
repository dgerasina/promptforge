"""Repository-only documentation impact, generation и safe minimal sync."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date
import difflib
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import tempfile
from typing import Callable, Mapping

from promptforge.platform.security import inspect_text
from promptforge.platform.governance import GovernancePolicy
from promptforge.platform.contracts import Principal


_CONFIG_FIELDS = frozenset({"schema_version", "targets"})
_TARGET_FIELDS = frozenset({
    "document_id", "version", "owner", "audience", "classification", "source_schema",
    "source_classification", "document_path", "generated_section", "reviewed_at", "stale_after_days",
})
_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_SAFE_PATH = re.compile(r"^[A-Za-z0-9._/-]{1,512}$")
_SEMVER = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")
_LINK = re.compile(r"(?<!!)\[[^\]]+\]\(([^)]+)\)")
_CLASSIFICATION_RANK = {"public": 0, "internal": 1, "confidential": 2, "restricted": 3, "regulated": 4}
_AUDIENCES = frozenset({"public", "internal", "engineering", "analyst"})
_OWNERS = frozenset({"owner-local", "maintainer-local"})
_MAX_CONFIG_BYTES = 100_000
_MAX_SCHEMA_BYTES = 1_000_000
_MAX_DOCUMENT_BYTES = 500_000
_UNSAFE_MARKDOWN = re.compile(r"(?:<!--|-->|<[^>]+>|!\[|\]\(|PF:GENERATED|PF:DOC-METADATA)", re.IGNORECASE)


def _strict_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate documentation JSON field: {key}")
        result[key] = value
    return result


def _safe_relative(value: object, name: str) -> str:
    if (
        not isinstance(value, str) or not _SAFE_PATH.fullmatch(value) or value.startswith(("/", "../"))
        or "/../" in value or "//" in value
    ):
        raise ValueError(f"documentation {name} path is unsafe")
    return value


@dataclass(frozen=True)
class DocumentationTarget:
    """Связывает один generated section с exact schema и docs policy."""

    document_id: str
    version: str
    owner: str
    audience: str
    classification: str
    source_schema: str
    source_classification: str
    document_path: str
    generated_section: str
    reviewed_at: date
    stale_after_days: int

    @classmethod
    def from_payload(cls, payload: Mapping[str, object]) -> DocumentationTarget:
        if not isinstance(payload, Mapping) or set(payload) != _TARGET_FIELDS:
            raise ValueError("documentation target fields mismatch")
        identifiers = (payload["document_id"], payload["owner"], payload["generated_section"])
        if any(not isinstance(value, str) or not _SAFE_ID.fullmatch(value) for value in identifiers):
            raise ValueError("documentation target identity is invalid")
        if payload["owner"] not in _OWNERS or payload["audience"] not in _AUDIENCES:
            raise ValueError("documentation owner or audience is unknown")
        if payload["classification"] not in _CLASSIFICATION_RANK:
            raise ValueError("documentation classification is unknown")
        if payload["source_classification"] not in _CLASSIFICATION_RANK:
            raise ValueError("documentation source classification is unknown")
        if not isinstance(payload["version"], str) or not _SEMVER.fullmatch(payload["version"]):
            raise ValueError("documentation version is invalid")
        try:
            reviewed_at = date.fromisoformat(payload["reviewed_at"])
        except (TypeError, ValueError) as error:
            raise ValueError("documentation review date is invalid") from error
        stale_after = payload["stale_after_days"]
        if not isinstance(stale_after, int) or isinstance(stale_after, bool) or not 1 <= stale_after <= 365:
            raise ValueError("documentation stale interval is invalid")
        return cls(
            payload["document_id"], payload["version"], payload["owner"], payload["audience"],
            payload["classification"], _safe_relative(payload["source_schema"], "source"),
            payload["source_classification"], _safe_relative(payload["document_path"], "document"),
            payload["generated_section"], reviewed_at, stale_after,
        )


@dataclass(frozen=True)
class DocumentationPlan:
    """Описывает metadata-only impact и хранит proposed document только внутри процесса."""

    status: str
    document_id: str
    document_path: str
    source_digest: str
    document_digest: str
    patch_digest: str
    changed_lines: int
    reason_codes: tuple[str, ...]
    updated_document: str = field(repr=False, compare=False)

    def to_payload(self) -> dict[str, object]:
        return {
            "schema_version": "1.0", "status": self.status, "document_id": self.document_id,
            "document_path": self.document_path, "source_digest": self.source_digest,
            "document_digest": self.document_digest, "patch_digest": self.patch_digest,
            "changed_lines": self.changed_lines, "reason_codes": list(self.reason_codes),
        }


@dataclass(frozen=True)
class DocumentationImpactReport:
    """Агрегирует impact без generated content и patch body."""

    plans: tuple[DocumentationPlan, ...]

    def to_payload(self) -> dict[str, object]:
        counts = {status: sum(plan.status == status for plan in self.plans) for status in ("current", "drift", "blocked")}
        return {
            "schema_version": "1.0", "status": "ok", "targets": len(self.plans), **counts,
            "documents": [plan.to_payload() for plan in self.plans], "network_used": False,
        }


@dataclass(frozen=True)
class DocumentationAutomation:
    """Строит deterministic docs sections и изменяет только размеченный generated block."""

    repository: Path
    targets: tuple[DocumentationTarget, ...]
    today: Callable[[], date] = field(default=date.today, repr=False, compare=False)

    @classmethod
    def from_repository(
        cls, repository: Path, *, today: Callable[[], date] = date.today,
    ) -> DocumentationAutomation:
        root = Path(repository).resolve(strict=True)
        if not root.is_dir() or Path(repository).is_symlink():
            raise ValueError("documentation repository must be a regular directory")
        config_path = root / "config" / "docs-automation.json"
        payload = cls._load_json(config_path, root, _MAX_CONFIG_BYTES, "documentation config")
        if set(payload) != _CONFIG_FIELDS or payload.get("schema_version") != "1.0":
            raise ValueError("documentation config fields mismatch")
        raw_targets = payload.get("targets")
        if not isinstance(raw_targets, list) or not raw_targets or len(raw_targets) > 100:
            raise ValueError("documentation targets are invalid")
        targets = tuple(DocumentationTarget.from_payload(item) for item in raw_targets)
        if len({target.document_id for target in targets}) != len(targets):
            raise ValueError("duplicate documentation target")
        return cls(root, targets, today)

    def check_all(self) -> DocumentationImpactReport:
        return DocumentationImpactReport(tuple(self.plan(target.document_id) for target in self.targets))

    def plan(self, document_id: str) -> DocumentationPlan:
        target = self._target(document_id)
        source_path = self._file(target.source_schema, _MAX_SCHEMA_BYTES, "source schema")
        document_path = self._file(target.document_path, _MAX_DOCUMENT_BYTES, "document")
        source_raw = source_path.read_bytes()
        source_digest = "sha256:" + hashlib.sha256(source_raw).hexdigest()
        schema = self._decode_json(source_raw, "source schema")
        current = document_path.read_text(encoding="utf-8")
        generated = self._render(target, schema, source_digest)
        updated, marker_error = self._replace_generated(current, target.generated_section, generated)
        reasons: list[str] = []
        if marker_error:
            reasons.append(marker_error)
        if _CLASSIFICATION_RANK[target.source_classification] > _CLASSIFICATION_RANK[target.classification]:
            reasons.append("classification_exceeds_document")
        if (self.today() - target.reviewed_at).days > target.stale_after_days:
            reasons.append("document_stale")
        if inspect_text(updated).outcome != "allow":
            reasons.append("unsafe_generated_content")
        if self._has_broken_link(updated, document_path.parent):
            reasons.append("broken_local_link")
        if updated != current:
            reasons.append("generated_section_drift")
        blocking = {
            "generated_section_missing", "classification_exceeds_document", "document_stale",
            "unsafe_generated_content", "broken_local_link",
        }
        status = "blocked" if blocking.intersection(reasons) else "drift" if updated != current else "current"
        patch = "".join(difflib.unified_diff(
            current.splitlines(keepends=True), updated.splitlines(keepends=True),
            fromfile=target.document_path, tofile=target.document_path,
        ))
        changed_lines = sum(
            line.startswith(("+", "-")) and not line.startswith(("+++", "---")) for line in patch.splitlines()
        )
        return DocumentationPlan(
            status, target.document_id, target.document_path, source_digest,
            "sha256:" + hashlib.sha256(current.encode("utf-8")).hexdigest(),
            "sha256:" + hashlib.sha256(patch.encode("utf-8")).hexdigest(), changed_lines,
            tuple(dict.fromkeys(reasons)), updated,
        )

    def sync(self, document_id: str, approver: Principal) -> DocumentationPlan:
        target = self._target(document_id)
        GovernancePolicy.builtin().require(approver, "docs.sync")
        plan = self.plan(document_id)
        if plan.status == "blocked":
            raise PermissionError("documentation quality gate blocked sync")
        if plan.status == "current":
            return plan
        path = self._file(target.document_path, _MAX_DOCUMENT_BYTES, "document")
        self._atomic_write(path, plan.updated_document)
        return self.plan(document_id)

    def target_path(self, document_id: str) -> str:
        """Returns the exact configured repository-relative document path."""

        return self._target(document_id).document_path

    def source_digest(self, document_id: str) -> str:
        """Recomputes the configured source digest for a CAS-style generation check."""

        target = self._target(document_id)
        content = self._file(target.source_schema, _MAX_SCHEMA_BYTES, "source schema").read_bytes()
        return "sha256:" + hashlib.sha256(content).hexdigest()

    def document_digest(self, document_id: str) -> str:
        """Returns the exact configured document digest for a CAS update."""

        target = self._target(document_id)
        return "sha256:" + hashlib.sha256(
            self._file(target.document_path, _MAX_DOCUMENT_BYTES, "document").read_bytes()
        ).hexdigest()

    def _target(self, document_id: str) -> DocumentationTarget:
        target = next((item for item in self.targets if item.document_id == document_id), None)
        if target is None:
            raise ValueError("unknown documentation target")
        return target

    def _file(self, relative: str, max_bytes: int, name: str) -> Path:
        path = self.repository / relative
        if path.is_symlink() or not path.is_file() or path.resolve() != path:
            raise ValueError(f"{name} must be a regular repository file")
        if not path.resolve().is_relative_to(self.repository) or path.stat().st_size > max_bytes:
            raise ValueError(f"{name} is outside limits")
        return path

    @staticmethod
    def _load_json(path: Path, root: Path, max_bytes: int, name: str) -> Mapping[str, object]:
        if path.is_symlink() or not path.is_file() or path.resolve() != path or not path.resolve().is_relative_to(root):
            raise ValueError(f"{name} must be a regular repository file")
        raw = path.read_bytes()
        if len(raw) > max_bytes:
            raise ValueError(f"{name} exceeds size limit")
        return DocumentationAutomation._decode_json(raw, name)

    @staticmethod
    def _decode_json(raw: bytes, name: str) -> Mapping[str, object]:
        try:
            payload = json.loads(raw, object_pairs_hook=_strict_object)
        except (UnicodeError, json.JSONDecodeError) as error:
            raise ValueError(f"{name} is invalid JSON") from error
        if not isinstance(payload, Mapping):
            raise ValueError(f"{name} root must be an object")
        return payload

    @staticmethod
    def _render(target: DocumentationTarget, schema: Mapping[str, object], source_digest: str) -> str:
        if (
            schema.get("type") != "object" or schema.get("additionalProperties") is not False
            or not isinstance(schema.get("title"), str) or not isinstance(schema.get("properties"), Mapping)
            or not isinstance(schema.get("required", []), list)
        ):
            raise ValueError("documentation source must be a closed object JSON Schema")
        properties = schema["properties"]
        required = set(schema.get("required", []))
        if any(not isinstance(name, str) or not isinstance(value, Mapping) for name, value in properties.items()):
            raise ValueError("documentation schema properties are invalid")
        derived = [schema["title"], *properties]
        derived.extend(str(value.get("description", "")) for value in properties.values())
        if any(_UNSAFE_MARKDOWN.search(value) for value in derived):
            raise ValueError("documentation schema contains unsafe markdown")
        relative_source = os.path.relpath(target.source_schema, Path(target.document_path).parent).replace(os.sep, "/")
        metadata = {
            "document_id": target.document_id, "version": target.version, "owner": target.owner,
            "audience": target.audience, "classification": target.classification,
            "source": target.source_schema, "source_digest": source_digest,
            "generated_section": target.generated_section, "generator_version": "1.0",
        }
        lines = [
            f"<!-- PF:DOC-METADATA {json.dumps(metadata, sort_keys=True, separators=(',', ':'))} -->",
            "", "## Справочник API", "", f"**{schema['title']}**", "",
            f"Источник: [`{target.source_schema}`]({relative_source})", "", f"Хеш: `{source_digest}`", "",
            "| Поле | Обязательно | Тип | Описание |", "|---|---:|---|---|",
        ]
        for name in sorted(properties):
            definition = properties[name]
            field_type = DocumentationAutomation._schema_type(definition)
            description = str(definition.get("description", "—")).replace("|", "\\|").replace("\n", " ")
            lines.append(f"| `{name}` | {'да' if name in required else 'нет'} | `{field_type}` | {description} |")
        return "\n".join(lines) + "\n"

    @staticmethod
    def _schema_type(definition: Mapping[str, object]) -> str:
        if isinstance(definition.get("type"), str):
            return definition["type"]
        if isinstance(definition.get("$ref"), str):
            return "ref"
        if "const" in definition:
            return "const"
        if isinstance(definition.get("enum"), list):
            return "enum"
        return "unknown"

    @staticmethod
    def _replace_generated(current: str, section: str, generated: str) -> tuple[str, str]:
        begin = f"<!-- PF:GENERATED {section} BEGIN -->"
        end = f"<!-- PF:GENERATED {section} END -->"
        if current.count(begin) != 1 or current.count(end) != 1 or current.index(begin) > current.index(end):
            return current, "generated_section_missing"
        before, remainder = current.split(begin, 1)
        _, after = remainder.split(end, 1)
        return f"{before}{begin}\n{generated}{end}{after}", ""

    def _has_broken_link(self, document: str, parent: Path) -> bool:
        for raw_target in _LINK.findall(document):
            target = raw_target.split("#", 1)[0]
            if not target or target.startswith(("http://", "https://", "mailto:", "#")):
                continue
            candidate = parent / target
            if candidate.is_symlink() or not candidate.is_file() or not candidate.resolve().is_relative_to(self.repository):
                return True
        return False

    @staticmethod
    def _atomic_write(path: Path, content: str) -> None:
        mode = stat.S_IMODE(path.stat().st_mode)
        temporary_name = ""
        try:
            with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=path.parent, delete=False) as temporary:
                temporary.write(content)
                temporary.flush()
                os.fsync(temporary.fileno())
                temporary_name = temporary.name
            os.chmod(temporary_name, mode)
            os.replace(temporary_name, path)
        finally:
            if temporary_name and Path(temporary_name).exists():
                Path(temporary_name).unlink()
