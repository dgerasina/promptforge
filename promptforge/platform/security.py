"""Минимальная локальная проверка текста и release-tree hygiene."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path


_PROVIDER_API_KEY = re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b")
_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@example\.com\b")
_PHONE = re.compile(r"\+1-202-555-\d{4}\b")
_REDACTION = "<PF_SECRET_REDACTED>"
_TEXT_ARTIFACT_SUFFIXES = frozenset({
    "", ".json", ".md", ".py", ".rst", ".sh", ".sql", ".toml", ".txt", ".yaml", ".yml",
})
_MAX_ARTIFACT_BYTES = 1_000_000


@dataclass(frozen=True)
class InspectionResult:
    """Возвращает решение, типы находок и безопасное представление текста."""

    outcome: str
    detections: tuple[str, ...]
    safe_content: str


@dataclass(frozen=True)
class RepositorySecretScan:
    """Публикует только агрегированные результаты release-tree secret scan."""

    files_scanned: int
    secret_files: int
    unreadable_files: int

    @property
    def clean(self) -> bool:
        return self.secret_files == 0 and self.unreadable_files == 0


def inspect_text(content: str) -> InspectionResult:
    """Блокирует provider-like secrets и возвращает очищенный текст."""

    if not isinstance(content, str) or not content.strip():
        raise ValueError("content must be a non-empty string")
    if _PROVIDER_API_KEY.search(content):
        return InspectionResult(
            outcome="deny",
            detections=("provider_api_key",),
            safe_content=_PROVIDER_API_KEY.sub(_REDACTION, content),
        )
    detections = tuple(
        name for name, pattern in (("synthetic_email", _EMAIL), ("synthetic_phone", _PHONE))
        if pattern.search(content)
    )
    if detections:
        safe_content = _PHONE.sub("<PF_PHONE>", _EMAIL.sub("<PF_EMAIL>", content))
        return InspectionResult("allow_with_transform", detections, safe_content)
    return InspectionResult(outcome="allow", detections=(), safe_content=content)


def scan_repository_text_artifacts(root: Path) -> RepositorySecretScan:
    """Сканирует bounded text artifacts и fail-closed учитывает unreadable files."""

    repository = Path(root).resolve(strict=True)
    scanned = 0
    secret_files = 0
    unreadable = 0
    for path in sorted(repository.rglob("*")):
        if (
            not path.is_file() or path.is_symlink() or "__pycache__" in path.parts
            or path.suffix.lower() not in _TEXT_ARTIFACT_SUFFIXES
        ):
            continue
        try:
            size = path.stat().st_size
            if size > _MAX_ARTIFACT_BYTES:
                unreadable += 1
                continue
            content = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            unreadable += 1
            continue
        scanned += 1
        matches = tuple(_PROVIDER_API_KEY.finditer(content))
        if any("FAKE-DO-NOT-USE" not in match.group(0) for match in matches):
            secret_files += 1
    return RepositorySecretScan(scanned, secret_files, unreadable)
