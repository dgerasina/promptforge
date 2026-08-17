"""Fail-closed atomic create/update patch engine for repository mutations."""

from __future__ import annotations

from dataclasses import dataclass
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import stat


_SAFE_PATH = re.compile(r"^[A-Za-z0-9._/-]{1,512}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_MAX_FILE_BYTES = 256_000
_MAIL_CONFIG = "etl/docker/utility/mail_loader_v2/config/config.json"


def _digest(content: bytes) -> str:
    return "sha256:" + hashlib.sha256(content).hexdigest()


def _object_json(content: bytes | str, label: str) -> dict[str, object]:
    raw = content.decode("utf-8") if isinstance(content, bytes) else content

    def closed_object(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate {label} JSON field")
            result[key] = value
        return result

    value = json.loads(raw, object_pairs_hook=closed_object)
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be a JSON object")
    return value


@dataclass(frozen=True)
class MutationSpec:
    path: str
    artifact_kind: str
    content: str
    expected_sha256: str | None

    def __post_init__(self) -> None:
        candidate = Path(self.path)
        if (
            not _SAFE_PATH.fullmatch(self.path) or candidate.is_absolute() or ".." in candidate.parts
            or self.artifact_kind not in {"production", "test", "history", "config", "documentation"}
            or not self.content or len(self.content.encode("utf-8")) > _MAX_FILE_BYTES
            or self.expected_sha256 is not None and not _DIGEST.fullmatch(self.expected_sha256)
        ):
            raise ValueError("mutation spec is invalid")


@dataclass(frozen=True)
class _Original:
    path: Path
    content: bytes | None
    mode: int | None


@dataclass(frozen=True)
class AppliedMutation:
    changed_paths: tuple[str, ...]
    originals: tuple[_Original, ...]
    applied_digests: tuple[str, ...]
    journal: Path | None = None
    created_directories: tuple[Path, ...] = ()

    def finalize(self) -> None:
        if self.journal is not None:
            self.journal.unlink(missing_ok=True)

    def rollback(self) -> None:
        for original, applied_digest in reversed(tuple(zip(self.originals, self.applied_digests, strict=True))):
            descriptor = os.open(original.path, os.O_RDWR | getattr(os, "O_NOFOLLOW", 0))
            metadata = os.fstat(descriptor)
            with os.fdopen(os.dup(descriptor), "rb") as reader:
                current = reader.read(_MAX_FILE_BYTES + 1)
            if not stat.S_ISREG(metadata.st_mode) or _digest(current) != applied_digest:
                os.close(descriptor)
                raise PermissionError("rollback target changed after mutation")
            if original.content is None:
                os.close(descriptor)
                original.path.unlink()
                continue
            os.ftruncate(descriptor, 0)
            os.lseek(descriptor, 0, os.SEEK_SET)
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(original.content)
                os.fchmod(stream.fileno(), original.mode or 0o600)
        for directory in reversed(self.created_directories):
            try:
                directory.rmdir()
            except OSError:
                continue
        self.finalize()


class MutationPatch:
    def __init__(
        self, repository: Path, specs: tuple[MutationSpec, ...], *, domain: str = "generic", scope: str = "",
        journal: Path | None = None,
    ):
        self.repository = Path(repository).resolve(strict=True)
        if not self.repository.is_dir() or self.repository.is_symlink() or not 1 <= len(specs) <= 20:
            raise ValueError("mutation patch boundary is invalid")
        if len({item.path for item in specs}) != len(specs):
            raise ValueError("mutation paths must be unique")
        self.specs = tuple(specs)
        self.domain = domain
        self.scope = scope
        self.journal = journal

    @classmethod
    def for_mail(
        cls, repository: Path, delivery_scope: str, specs: tuple[MutationSpec, ...], journal: Path | None = None,
    ) -> MutationPatch:
        return cls(repository, specs, domain="mail", scope=delivery_scope, journal=journal)

    def _begin_journal(self) -> None:
        if self.journal is None:
            return
        if self.journal.exists() or self.journal.is_symlink():
            raise PermissionError("unfinished repository mutation requires manual recovery")
        changes = []
        for item in self.specs:
            target = self._target(item)
            before = target.read_bytes() if target.exists() else None
            mode = stat.S_IMODE(target.stat().st_mode) if target.exists() else None
            changes.append({
                "path": item.path, "before_sha256": item.expected_sha256,
                "after_sha256": _digest(item.content.encode("utf-8")),
                "before_base64": base64.b64encode(before).decode("ascii") if before is not None else None,
                "mode": mode,
            })
        payload = {
            "schema_version": "1.0", "status": "pending",
            "changes": changes,
        }
        descriptor = os.open(self.journal, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(payload, stream, sort_keys=True, separators=(",", ":"))
            stream.flush()
            os.fsync(stream.fileno())

    @classmethod
    def recover(cls, repository: Path, journal: Path) -> tuple[str, ...]:
        """CAS-restores an interrupted patch from an owner-private durable journal."""

        root = Path(repository).resolve(strict=True)
        marker = Path(journal).resolve(strict=True)
        payload = _object_json(marker.read_bytes(), "mutation recovery journal")
        if set(payload) != {"schema_version", "status", "changes"} or payload["status"] != "pending":
            raise ValueError("mutation recovery journal is invalid")
        changes = payload["changes"]
        if not isinstance(changes, list) or not changes:
            raise ValueError("mutation recovery changes are invalid")
        restored = []
        for item in reversed(changes):
            if not isinstance(item, dict) or set(item) != {
                "path", "before_sha256", "after_sha256", "before_base64", "mode",
            }:
                raise ValueError("mutation recovery entry is invalid")
            spec = MutationSpec(item["path"], "production", "recovery", item["before_sha256"])
            target = root / spec.path
            if item["before_sha256"] is None and not target.exists() and not target.is_symlink():
                restored.append(item["path"])
                continue
            descriptor = os.open(target, os.O_RDWR | getattr(os, "O_NOFOLLOW", 0))
            with os.fdopen(os.dup(descriptor), "rb") as reader:
                current = reader.read(_MAX_FILE_BYTES + 1)
            current_digest = _digest(current)
            if item["before_sha256"] is not None and current_digest == item["before_sha256"]:
                os.close(descriptor)
                restored.append(item["path"])
                continue
            if current_digest != item["after_sha256"]:
                os.close(descriptor)
                raise PermissionError("interrupted mutation diverged; manual recovery required")
            if item["before_base64"] is None:
                os.close(descriptor)
                target.unlink()
            else:
                before = base64.b64decode(item["before_base64"], validate=True)
                if _digest(before) != item["before_sha256"]:
                    os.close(descriptor)
                    raise ValueError("mutation recovery backup digest mismatch")
                os.ftruncate(descriptor, 0)
                os.lseek(descriptor, 0, os.SEEK_SET)
                with os.fdopen(descriptor, "wb") as writer:
                    writer.write(before)
                    os.fchmod(writer.fileno(), item["mode"])
            restored.append(item["path"])
        marker.unlink()
        return tuple(reversed(restored))

    def _target(self, spec: MutationSpec) -> Path:
        target = self.repository / spec.path
        parent = target.parent
        existing = parent
        while not existing.exists() and existing != self.repository:
            existing = existing.parent
        if (
            existing.resolve(strict=True) != existing or not existing.is_relative_to(self.repository)
            or target.is_symlink()
        ):
            raise PermissionError("mutation target escapes repository or uses symlink")
        return target

    def _ensure_parent(self, target: Path) -> tuple[Path, ...]:
        parent = target.parent
        pending: list[Path] = []
        current = parent
        while not current.exists() and current != self.repository:
            pending.append(current)
            current = current.parent
        created: list[Path] = []
        for directory in reversed(pending):
            directory.mkdir(mode=0o700, exist_ok=True)
            if directory.resolve(strict=True) != directory or not directory.is_relative_to(self.repository):
                raise PermissionError("mutation parent escapes repository or uses symlink")
            created.append(directory)
        if parent.exists() and (parent.resolve(strict=True) != parent or not parent.is_relative_to(self.repository)):
            raise PermissionError("mutation parent escapes repository or uses symlink")
        return tuple(created)

    def validate(self) -> None:
        for spec in self.specs:
            target = self._target(spec)
            if target.exists():
                metadata = target.lstat()
                if not stat.S_ISREG(metadata.st_mode) or spec.expected_sha256 is None:
                    raise PermissionError("existing mutation target requires an exact old digest")
                if _digest(target.read_bytes()) != spec.expected_sha256:
                    raise PermissionError("mutation target changed since patch generation")
            elif spec.expected_sha256 is not None:
                raise PermissionError("new mutation target cannot declare an old digest")
        if self.domain == "mail":
            self._validate_mail()

    def _validate_mail(self) -> None:
        if self.scope not in {"stage1_only", "full_delivery"}:
            raise ValueError("mail delivery scope is invalid")
        config_specs = tuple(item for item in self.specs if item.path == _MAIL_CONFIG)
        if len(config_specs) != 1:
            raise ValueError("mail mutation requires exact loader config")
        if self.scope == "stage1_only" and len(self.specs) != 1:
            raise ValueError("mail stage one is config-only")
        if self.scope == "full_delivery" and len(self.specs) < 3:
            raise ValueError("full mail delivery requires a reviewed multi-file bundle")
        spec = config_specs[0]
        before = _object_json((self.repository / spec.path).read_bytes(), "existing mail config")
        after = _object_json(spec.content, "proposed mail config")
        if set(before) != set(after) or not isinstance(before.get("entities"), list) or not isinstance(after["entities"], list):
            raise ValueError("mail config shape cannot change")
        old_entities, new_entities = before["entities"], after["entities"]
        if new_entities[:-1] != old_entities or len(new_entities) != len(old_entities) + 1:
            raise ValueError("mail entity must be appended exactly once")
        if {key: value for key, value in before.items() if key != "entities"} != {
            key: value for key, value in after.items() if key != "entities"
        }:
            raise ValueError("mail stage must not change unrelated config")

    def apply(self) -> AppliedMutation:
        self.validate()
        self._begin_journal()
        originals = []
        intended_digests = []
        created_directories: list[Path] = []
        try:
            for spec in self.specs:
                target = self._target(spec)
                for directory in self._ensure_parent(target):
                    if directory not in created_directories:
                        created_directories.append(directory)
                nofollow = getattr(os, "O_NOFOLLOW", 0)
                if spec.expected_sha256 is None:
                    descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | nofollow, 0o600)
                    originals.append(_Original(target, None, None))
                else:
                    descriptor = os.open(target, os.O_RDWR | nofollow)
                    metadata = os.fstat(descriptor)
                    if not stat.S_ISREG(metadata.st_mode):
                        os.close(descriptor)
                        raise PermissionError("mutation target is not a regular file")
                    with os.fdopen(os.dup(descriptor), "rb") as reader:
                        content = reader.read(_MAX_FILE_BYTES + 1)
                    if len(content) > _MAX_FILE_BYTES or _digest(content) != spec.expected_sha256:
                        os.close(descriptor)
                        raise PermissionError("mutation target changed before write")
                    originals.append(_Original(target, content, stat.S_IMODE(metadata.st_mode)))
                    os.ftruncate(descriptor, 0)
                    os.lseek(descriptor, 0, os.SEEK_SET)
                with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                    stream.write(spec.content)
                intended_digests.append(_digest(spec.content.encode("utf-8")))
            return AppliedMutation(
                tuple(item.path for item in self.specs), tuple(originals),
                tuple(_digest(item.content.encode("utf-8")) for item in self.specs),
                self.journal,
                tuple(created_directories),
            )
        except Exception:
            if len(intended_digests) == len(originals):
                AppliedMutation(
                    (), tuple(originals), tuple(intended_digests), self.journal, tuple(created_directories),
                ).rollback()
            else:
                for directory in reversed(created_directories):
                    try:
                        directory.rmdir()
                    except OSError:
                        continue
            raise
