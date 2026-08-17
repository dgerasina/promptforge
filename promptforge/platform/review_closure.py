"""Metadata-only worktree baselines for fail-closed targeted review closure."""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import stat
import time
from types import MappingProxyType
from typing import Callable, Iterable, Mapping


_SAFE_PATH = re.compile(r"^[A-Za-z0-9._/-]{1,512}$")
_MAX_FILE_BYTES = 4_000_000


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def _sha256(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _path_token(key: bytes, path: str) -> str:
    return "hmac-sha256:" + hmac.new(key, path.encode("utf-8"), hashlib.sha256).hexdigest()


@dataclass(frozen=True)
class WorktreeBaseline:
    """Attested file-state map whose durable/public representation contains no paths."""

    repository_digest: str
    entries: Mapping[str, str]
    attestation: str
    _key: bytes = field(repr=False, compare=False)

    @classmethod
    def capture(cls, repository: Path, key: bytes, paths: Iterable[str]) -> "WorktreeBaseline":
        root = Path(repository).resolve(strict=True)
        if not root.is_dir() or len(key) < 32:
            raise ValueError("review closure baseline context is invalid")
        normalized = tuple(sorted(set(paths)))
        if not normalized or any(not _SAFE_PATH.fullmatch(path) or path.startswith("/") for path in normalized):
            raise ValueError("review closure paths are invalid")
        entries: dict[str, str] = {}
        for relative in normalized:
            target = root / relative
            try:
                descriptor = os.open(target, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            except FileNotFoundError:
                state = "missing"
            except OSError:
                state = "invalid"
            else:
                with os.fdopen(descriptor, "rb") as stream:
                    metadata = os.fstat(stream.fileno())
                    if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > _MAX_FILE_BYTES:
                        state = "invalid"
                    else:
                        raw = stream.read(_MAX_FILE_BYTES + 1)
                        state = _sha256(raw) if len(raw) <= _MAX_FILE_BYTES else "invalid"
            entries[_path_token(key, relative)] = state
        digest = _sha256(_canonical(entries))
        attestation = "hmac-sha256:" + hmac.new(key, digest.encode("ascii"), hashlib.sha256).hexdigest()
        return cls(digest, MappingProxyType(entries), attestation, bytes(key))

    @classmethod
    def capture_tree(cls, repository: Path, key: bytes) -> "WorktreeBaseline":
        root = Path(repository).resolve(strict=True)
        paths = tuple(
            path.relative_to(root).as_posix() for path in root.rglob("*")
            if path.is_file() and not path.is_symlink() and ".git" not in path.relative_to(root).parts
            and ".promptforge" not in path.relative_to(root).parts
        )
        if not paths:
            raise ValueError("review closure repository has no files")
        return cls.capture(root, key, paths)

    def verify(self) -> bool:
        digest = _sha256(_canonical(dict(self.entries)))
        expected = "hmac-sha256:" + hmac.new(self._key, digest.encode("ascii"), hashlib.sha256).hexdigest()
        return hmac.compare_digest(digest, self.repository_digest) and hmac.compare_digest(expected, self.attestation)

    def rekey(self, key: bytes) -> "WorktreeBaseline":
        digest = _sha256(_canonical(dict(self.entries)))
        attestation = "hmac-sha256:" + hmac.new(key, digest.encode("ascii"), hashlib.sha256).hexdigest()
        return WorktreeBaseline(digest, self.entries, attestation, bytes(key))

    def to_payload(self) -> dict[str, object]:
        return {
            "schema_version": "1.0", "repository_digest": self.repository_digest,
            "entry_tokens_digest": _sha256(_canonical(sorted(self.entries))), "entries": len(self.entries),
            "attestation": self.attestation,
        }


@dataclass(frozen=True)
class ClosureScopeDecision:
    allowed: bool
    reason_code: str
    baseline_digest: str
    current_digest: str
    targeted_tokens_digest: str
    out_of_scope_tokens: tuple[str, ...]

    def to_payload(self) -> dict[str, object]:
        return {"schema_version": "1.0", **self.__dict__}


def compare_closure_scope(
    baseline: WorktreeBaseline, current: WorktreeBaseline, targeted_paths: frozenset[str],
) -> ClosureScopeDecision:
    if baseline._key != current._key or not baseline.verify() or not current.verify():
        raise PermissionError("review closure baseline attestation failed")
    if not targeted_paths or any(not _SAFE_PATH.fullmatch(path) for path in targeted_paths):
        raise ValueError("review closure target scope is invalid")
    targeted = frozenset(_path_token(baseline._key, path) for path in targeted_paths)
    if not targeted <= baseline.entries.keys() or not targeted <= current.entries.keys():
        reason = "target_scope_invalid"
        drift = ()
    elif any(current.entries[token] in {"missing", "invalid"} for token in targeted):
        reason = "target_scope_invalid"
        drift = ()
    else:
        drift = tuple(sorted(
            token for token in baseline.entries.keys() | current.entries.keys()
            if token not in targeted and baseline.entries.get(token) != current.entries.get(token)
        ))
        reason = "scope_drift_detected" if drift else "closure_scope_verified"
    return ClosureScopeDecision(
        reason == "closure_scope_verified", reason, baseline.repository_digest, current.repository_digest,
        _sha256(_canonical(sorted(targeted))), drift,
    )


@dataclass(frozen=True)
class ReviewClosureContextReceipt:
    parent_review_id: str
    context_digest: str
    expires_at: int

    def to_payload(self) -> dict[str, object]:
        return {"schema_version": "1.0", **self.__dict__}


@dataclass(frozen=True)
class ReviewClosureContext:
    parent_review_id: str
    principal_id: str
    project_id: str
    baseline: WorktreeBaseline
    open_finding_keys: tuple[str, ...]
    agent_catalog_digest: str
    bindings_digest: str
    parent_provenance_digest: str


class ReviewClosureContextStore:
    """Owner-private one-time parent binding; persists only digests and path tokens."""

    def __init__(self, state_root: Path, key: bytes, *, clock=lambda: int(time.time())) -> None:
        root = Path(state_root).resolve(strict=True)
        metadata = root.lstat()
        if root.is_symlink() or not root.is_dir() or stat.S_IMODE(metadata.st_mode) != 0o700 or len(key) < 32:
            raise ValueError("review closure state is invalid")
        contexts = root / "review-closures"
        contexts.mkdir(mode=0o700, exist_ok=True)
        if contexts.is_symlink() or stat.S_IMODE(contexts.stat().st_mode) != 0o700:
            raise ValueError("review closure directory is invalid")
        self.root, self.key, self.clock = contexts, bytes(key), clock

    def register(
        self, parent_review_id: str, principal_id: str, project_id: str, baseline: WorktreeBaseline,
        open_finding_keys: tuple[str, ...], agent_catalog_digest: str, bindings_digest: str,
        parent_provenance_digest: str, *, ttl_seconds: int = 86_400,
    ) -> ReviewClosureContextReceipt:
        identifiers = (parent_review_id, principal_id, project_id)
        digests = (*open_finding_keys, agent_catalog_digest, bindings_digest, parent_provenance_digest)
        if (
            any(not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", item) for item in identifiers)
            or any(not re.fullmatch(r"sha256:[0-9a-f]{64}", item) for item in digests)
            or not baseline.verify() or not 60 <= ttl_seconds <= 604_800
        ):
            raise ValueError("review closure context is invalid")
        created_at = self.clock()
        unsigned = {
            "schema_version": "1.0", "parent_review_id": parent_review_id, "principal_id": principal_id,
            "project_id": project_id, "baseline": {
                "repository_digest": baseline.repository_digest, "entries": dict(baseline.entries),
                "attestation": baseline.attestation,
            }, "open_finding_keys": list(open_finding_keys), "agent_catalog_digest": agent_catalog_digest,
            "bindings_digest": bindings_digest, "created_at": created_at, "expires_at": created_at + ttl_seconds,
            "parent_provenance_digest": parent_provenance_digest,
        }
        signature = hmac.new(self.key, _canonical(unsigned), hashlib.sha256).hexdigest()
        encoded = _canonical({**unsigned, "attestation": "hmac-sha256:" + signature})
        path = self.root / f"{parent_review_id}.json"
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
        return ReviewClosureContextReceipt(parent_review_id, _sha256(encoded), created_at + ttl_seconds)

    def load(
        self, parent_review_id: str, context_digest: str, principal_id: str, project_id: str,
    ) -> ReviewClosureContext:
        if (self.root / f"{parent_review_id}.consumed").exists():
            raise PermissionError("review closure context was consumed")
        path = self.root / f"{parent_review_id}.json"
        try:
            descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        except OSError as error:
            raise PermissionError("review closure context is unavailable") from error
        with os.fdopen(descriptor, "rb") as stream:
            metadata = os.fstat(stream.fileno())
            if not stat.S_ISREG(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != 0o600:
                raise PermissionError("review closure context file is invalid")
            raw = stream.read(1_000_001)
        if len(raw) > 1_000_000 or _sha256(raw) != context_digest:
            raise PermissionError("review closure context digest mismatch")
        payload = json.loads(raw)
        signature = payload.pop("attestation", "")
        expected = "hmac-sha256:" + hmac.new(self.key, _canonical(payload), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(str(signature), expected):
            raise PermissionError("review closure context attestation failed")
        if (
            payload.get("parent_review_id") != parent_review_id or payload.get("principal_id") != principal_id
            or payload.get("project_id") != project_id or self.clock() > payload.get("expires_at", 0)
        ):
            raise PermissionError("review closure context scope mismatch")
        stored = payload["baseline"]
        baseline = WorktreeBaseline(
            stored["repository_digest"], MappingProxyType(dict(stored["entries"])), stored["attestation"], self.key,
        )
        if not baseline.verify():
            raise PermissionError("review closure baseline failed verification")
        return ReviewClosureContext(
            parent_review_id, principal_id, project_id, baseline, tuple(payload["open_finding_keys"]),
            payload["agent_catalog_digest"], payload["bindings_digest"],
            payload["parent_provenance_digest"],
        )

    def consume(self, parent_review_id: str, context_digest: str, principal_id: str) -> None:
        source = self.root / f"{parent_review_id}.json"
        try:
            descriptor = os.open(source, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        except OSError as error:
            raise PermissionError("review closure context is unavailable") from error
        with os.fdopen(descriptor, "rb") as stream:
            metadata = os.fstat(stream.fileno())
            if not stat.S_ISREG(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != 0o600:
                raise PermissionError("review closure context file is invalid")
            raw = stream.read(1_000_001)
        if len(raw) > 1_000_000 or _sha256(raw) != context_digest:
            raise PermissionError("review closure consumption binding failed")
        try:
            payload = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise PermissionError("review closure context is invalid") from error
        signature = payload.pop("attestation", "")
        expected = "hmac-sha256:" + hmac.new(self.key, _canonical(payload), hashlib.sha256).hexdigest()
        if (
            payload.get("parent_review_id") != parent_review_id or payload.get("principal_id") != principal_id
            or not hmac.compare_digest(str(signature), expected) or self.clock() > payload.get("expires_at", 0)
        ):
            raise PermissionError("review closure consumption binding failed")
        marker = self.root / f"{parent_review_id}.consumed"
        descriptor = os.open(
            marker, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600,
        )
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(_canonical({"context_digest": context_digest, "consumed_at": self.clock()}))
            stream.flush()
            os.fsync(stream.fileno())
        source.unlink()


@dataclass(frozen=True)
class TargetedReviewClosureExecutor:
    """Coordinates one mutation-free closure after every durable binding is revalidated."""

    store: ReviewClosureContextStore
    review: Callable[[frozenset[str], tuple[str, ...], str], Mapping[str, object]]

    def execute(
        self, parent_review_id: str, context_digest: str, principal_id: str, project_id: str,
        targeted_paths: frozenset[str], current: WorktreeBaseline, agent_catalog_digest: str,
        bindings_digest: str,
    ) -> Mapping[str, object]:
        context = self.store.load(parent_review_id, context_digest, principal_id, project_id)
        if (
            context.agent_catalog_digest != agent_catalog_digest or context.bindings_digest != bindings_digest
            or not context.open_finding_keys
        ):
            raise PermissionError("review closure parent bindings changed")
        scope = compare_closure_scope(context.baseline, current, targeted_paths)
        if not scope.allowed:
            return MappingProxyType({
                "status": "blocked", "reason_code": scope.reason_code,
                "scope": scope.to_payload(), "network_used": False,
            })
        result = dict(self.review(targeted_paths, context.open_finding_keys, context.parent_provenance_digest))
        open_keys = tuple(result.get("open_finding_keys", ()))
        closed_keys = tuple(result.get("closed_finding_keys", ()))
        if (
            result.get("status") != "passed" or open_keys
            or frozenset(closed_keys) != frozenset(context.open_finding_keys)
            or not re.fullmatch(r"sha256:[0-9a-f]{64}", str(result.get("diff_digest", "")))
        ):
            return MappingProxyType({
                "status": "blocked", "reason_code": "targeted_closure_failed",
                "scope": scope.to_payload(), "network_used": False,
            })
        self.store.consume(parent_review_id, context_digest, principal_id)
        return MappingProxyType({
            "status": "passed", "reason_code": "targeted_closure_passed", "parent_review_id": parent_review_id,
            "diff_digest": result["diff_digest"], "closed_findings_digest": _sha256(_canonical(sorted(closed_keys))),
            "scope": scope.to_payload(), "network_used": False,
        })
