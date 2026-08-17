"""Проверяет нейтральность product surface по fingerprint policy."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
from pathlib import Path

from promptforge.core.prohibited_terms import contains_prohibited_term


_POLICY_VERSION = "neutrality-v1"
_TEXT_SUFFIXES = frozenset({"", ".diff", ".json", ".md", ".py", ".sh", ".toml", ".txt", ".yaml", ".yml"})
_REPOSITORY_SPEC_PATH = Path("docs/specs/promptforge-platform-v1-spec.md")


@dataclass(frozen=True)
class NeutralityReport:
    """Публикует только агрегаты без найденных названий и путей."""

    status: str
    files_scanned: int
    violations: int
    violations_digest: str

    def to_payload(self) -> dict[str, object]:
        return {
            "schema_version": "1.0",
            "status": self.status,
            "policy_version": _POLICY_VERSION,
            "files_scanned": self.files_scanned,
            "violations": self.violations,
            "violations_digest": self.violations_digest,
            "network_used": False,
        }


@dataclass(frozen=True)
class NeutralityGate:
    """Сканирует имена и текстовые артефакты без сетевых вызовов."""

    root: Path
    extra_files: tuple[Path, ...] = ()

    def __post_init__(self) -> None:
        root = Path(self.root).resolve(strict=True)
        if not root.is_dir() or Path(self.root).is_symlink():
            raise ValueError("neutrality root must be a regular directory")
        extras = []
        for path in self.extra_files:
            candidate = Path(path)
            if not candidate.exists():
                continue
            extras.append(candidate.resolve(strict=True))
        extras = tuple(extras)
        if any(not path.is_file() or path.is_symlink() for path in extras):
            raise ValueError("neutrality extra files must be regular files")
        object.__setattr__(self, "root", root)
        object.__setattr__(self, "extra_files", extras)

    def inspect(self) -> NeutralityReport:
        files = tuple(self._files())
        violations: list[str] = []
        for index, path in enumerate(files):
            label = self._label(path, index)
            if self._contains_marker(label) or self._contains_marker(path.name):
                violations.append(f"name:{label}")
            if path.suffix.lower() in _TEXT_SUFFIXES:
                try:
                    content = path.read_text(encoding="utf-8")
                except (OSError, UnicodeError) as error:
                    raise RuntimeError("neutrality artifact is unreadable") from error
                if self._contains_marker(content):
                    violations.append(f"content:{label}")
        material = "\n".join(sorted(violations)).encode("utf-8")
        digest = "sha256:" + hashlib.sha256(material).hexdigest()
        return NeutralityReport("blocked" if violations else "passed", len(files), len(violations), digest)

    def _files(self):
        for path in sorted(self.root.rglob("*")):
            if "__pycache__" in path.parts or ".local-state" in path.parts:
                continue
            if path.is_symlink():
                raise ValueError("neutrality tree must not contain symlinks")
            if path.is_file() and path.suffix.lower() not in {".pyc", ".pyo"}:
                yield path
        yield from self.extra_files

    def _label(self, path: Path, index: int) -> str:
        if path.is_relative_to(self.root):
            return path.relative_to(self.root).as_posix()
        return f"external:{index}"

    @staticmethod
    def _contains_marker(value: str) -> bool:
        return contains_prohibited_term(value)


def repository_neutrality_extras(root: Path) -> tuple[Path, ...]:
    """Возвращает только versioned/locally-generated extras, доступные в текущем checkout."""

    repository_root = Path(root).resolve(strict=True)
    spec = repository_root / _REPOSITORY_SPEC_PATH
    repository_index = repository_root.parent / ".promptforge" / "repository-index.yaml"
    candidates = (spec, repository_index)
    return tuple(path for path in candidates if path.is_file() and not path.is_symlink())
