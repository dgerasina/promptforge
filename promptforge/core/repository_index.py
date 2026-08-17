"""Детерминированный metadata-only индекс файлов repository."""

from __future__ import annotations

from dataclasses import dataclass
import fnmatch
import hashlib
import json
import os
from pathlib import Path
import tempfile

from promptforge.core.prohibited_terms import neutral_repository_path


_MAX_FILES_LIMIT = 1_000_000
_MAX_FILE_BYTES_LIMIT = 1_000_000_000


def _safe_relative(value: str, name: str, *, allow_dot: bool = False) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value.startswith(("/", "../"))
        or "/../" in value
        or "//" in value
        or (value == "." and not allow_dot)
        or "\\" in value
    ):
        raise ValueError(f"{name} is unsafe")
    return value


def _digest(payload: object) -> str:
    encoded = json.dumps(payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return f"sha256:{hashlib.sha256(encoded).hexdigest()}"


@dataclass(frozen=True)
class RepositoryIndexConfig:
    """Ограничивает область и размер repository index."""

    include_roots: tuple[str, ...]
    exclude_patterns: tuple[str, ...]
    allowed_extensions: tuple[str, ...]
    output_path: str
    max_files: int
    max_file_bytes: int

    def __post_init__(self) -> None:
        roots = tuple(_safe_relative(item, "index include root", allow_dot=True) for item in self.include_roots)
        excludes = tuple(_safe_relative(item, "index exclusion", allow_dot=True) for item in self.exclude_patterns)
        extensions = tuple(self.allowed_extensions)
        if (
            not roots
            or len(set(roots)) != len(roots)
            or len(set(excludes)) != len(excludes)
            or not extensions
            or len(set(extensions)) != len(extensions)
            or any(not isinstance(item, str) or not item.startswith(".") or "/" in item for item in extensions)
        ):
            raise ValueError("repository index arrays are invalid")
        _safe_relative(self.output_path, "index output")
        valid_max_files = isinstance(self.max_files, int) and not isinstance(self.max_files, bool)
        if not valid_max_files or not 1 <= self.max_files <= _MAX_FILES_LIMIT:
            raise ValueError("repository index max_files is invalid")
        if (
            not isinstance(self.max_file_bytes, int)
            or isinstance(self.max_file_bytes, bool)
            or not 1 <= self.max_file_bytes <= _MAX_FILE_BYTES_LIMIT
        ):
            raise ValueError("repository index max_file_bytes is invalid")
        object.__setattr__(self, "include_roots", roots)
        object.__setattr__(self, "exclude_patterns", excludes)
        object.__setattr__(self, "allowed_extensions", extensions)

    @classmethod
    def from_payload(cls, payload: object) -> RepositoryIndexConfig:
        fields = {
            "include_roots", "exclude_patterns", "allowed_extensions", "output_path", "max_files",
            "max_file_bytes",
        }
        if not isinstance(payload, dict) or set(payload) != fields:
            raise ValueError("repository index config fields mismatch")
        arrays = (payload["include_roots"], payload["exclude_patterns"], payload["allowed_extensions"])
        if any(not isinstance(value, list) or any(not isinstance(item, str) for item in value) for value in arrays):
            raise ValueError("repository index config arrays must contain strings")
        return cls(
            tuple(payload["include_roots"]), tuple(payload["exclude_patterns"]),
            tuple(payload["allowed_extensions"]), payload["output_path"], payload["max_files"],
            payload["max_file_bytes"],
        )

    def binding(self) -> dict[str, object]:
        return {
            "include_roots": list(self.include_roots),
            "exclude_patterns": list(self.exclude_patterns),
            "allowed_extensions": list(self.allowed_extensions),
            "output_path": self.output_path,
            "max_files": self.max_files,
            "max_file_bytes": self.max_file_bytes,
        }


@dataclass(frozen=True)
class RepositoryIndex:
    """Содержит воспроизводимый индекс без исходного содержимого файлов."""

    project_key: str
    config_digest: str
    entries: tuple[dict[str, object], ...]

    def to_payload(self) -> dict[str, object]:
        summary_by_extension: dict[str, int] = {}
        for entry in self.entries:
            extension = str(entry["extension"])
            summary_by_extension = {
                **summary_by_extension,
                extension: summary_by_extension.get(extension, 0) + 1,
            }
        unsigned = {
            "schema_version": "1.0",
            "project_key": self.project_key,
            "config_digest": self.config_digest,
            "summary": {
                "files": len(self.entries),
                "bytes": sum(int(entry["size_bytes"]) for entry in self.entries),
                "by_extension": dict(sorted(summary_by_extension.items())),
            },
            "files": list(self.entries),
        }
        return {**unsigned, "index_digest": _digest(unsigned)}

    def to_bytes(self) -> bytes:
        """Возвращает canonical JSON, являющийся валидным YAML 1.2."""

        return (json.dumps(self.to_payload(), ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")


@dataclass(frozen=True)
class RepositoryIndexer:
    """Сканирует только явно разрешённые roots без перехода по symlink."""

    repository: Path
    config: RepositoryIndexConfig
    project_key: str = "repository"

    def __post_init__(self) -> None:
        root = Path(self.repository).resolve(strict=True)
        if not root.is_dir() or Path(self.repository).is_symlink():
            raise ValueError("repository index root must be a regular directory")
        object.__setattr__(self, "repository", root)

    def build(self) -> RepositoryIndex:
        entries: list[dict[str, object]] = []
        seen: set[str] = set()
        for configured_root in self.config.include_roots:
            root = self.repository if configured_root == "." else self.repository / configured_root
            if root.is_symlink() or not root.is_dir() or not root.resolve().is_relative_to(self.repository):
                raise ValueError("repository index include root is invalid")
            for path in self._walk(root):
                relative = path.relative_to(self.repository).as_posix()
                safe_relative = neutral_repository_path(relative)
                if safe_relative in seen:
                    continue
                seen.add(safe_relative)
                metadata = path.lstat()
                if metadata.st_size > self.config.max_file_bytes:
                    raise ValueError("repository index file exceeds configured limit")
                entries.append({
                    "path": safe_relative,
                    "extension": path.suffix.lower() or "[none]",
                    "size_bytes": metadata.st_size,
                    "content_digest": f"sha256:{self._file_digest(path)}",
                })
                if len(entries) > self.config.max_files:
                    raise ValueError("repository index exceeds configured file limit")
        ordered = tuple(sorted(entries, key=lambda entry: str(entry["path"])))
        return RepositoryIndex(self.project_key, _digest(self.config.binding()), ordered)

    def write(self, snapshot: RepositoryIndex | None = None) -> Path:
        """Атомарно записывает canonical index с owner-only permissions."""

        target = self.repository / self.config.output_path
        if target.is_symlink() or not target.parent.resolve().is_relative_to(self.repository):
            raise ValueError("repository index output is unsafe")
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        index = snapshot or self.build()
        if index.project_key != self.project_key or index.config_digest != _digest(self.config.binding()):
            raise ValueError("repository index snapshot binding mismatch")
        content = index.to_bytes()
        descriptor, temporary = tempfile.mkstemp(prefix=".repository-index-", dir=target.parent)
        try:
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, target)
            directory_descriptor = os.open(target.parent, os.O_RDONLY)
            try:
                os.fsync(directory_descriptor)
            finally:
                os.close(directory_descriptor)
        except BaseException:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass
            raise
        return target

    def _walk(self, root: Path):
        for current, directories, files in os.walk(root, topdown=True, followlinks=False):
            current_path = Path(current)
            safe_directories = []
            for name in sorted(directories):
                candidate = current_path / name
                relative = candidate.relative_to(self.repository).as_posix()
                if self._excluded(relative, directory=True):
                    continue
                if candidate.is_symlink():
                    raise ValueError("repository index refuses symlink directories")
                safe_directories.append(name)
            directories[:] = safe_directories
            for name in sorted(files):
                path = current_path / name
                relative = path.relative_to(self.repository).as_posix()
                excluded = self._excluded(relative, directory=False)
                if excluded or path.suffix.lower() not in self.config.allowed_extensions:
                    continue
                if path.is_symlink() or not path.is_file() or not path.resolve().is_relative_to(self.repository):
                    raise ValueError("repository index refuses unsafe files")
                yield path

    def _excluded(self, relative: str, *, directory: bool) -> bool:
        candidate = f"{relative}/" if directory else relative
        for pattern in self.config.exclude_patterns:
            variants = (pattern, pattern[3:]) if pattern.startswith("**/") else (pattern,)
            if any(
                fnmatch.fnmatchcase(candidate, variant) or fnmatch.fnmatchcase(relative, variant)
                for variant in variants
            ):
                return True
        return candidate == self.config.output_path

    @staticmethod
    def _file_digest(path: Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            while chunk := stream.read(1024 * 1024):
                digest.update(chunk)
        return digest.hexdigest()
