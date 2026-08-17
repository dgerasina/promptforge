"""Production-like Git ingestion и trusted evidence для Automated Review Engine."""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import hmac
import os
from pathlib import Path
import secrets
import subprocess
from threading import Lock
from time import time
from typing import Callable

from promptforge.platform.review import CheckEvidence, ChangedFile, ReviewEngine, ReviewRequest, ReviewResult


_MAX_FILES = 100
_MAX_DIFF_BYTES = 1_000_000


class GitReviewCollector:
    """Собирает tracked и untracked text changes из одного exact Git worktree."""

    def __init__(self, repository: Path) -> None:
        self._repository = repository.resolve(strict=True)
        if not self._repository.is_dir():
            raise ValueError("review repository must be a directory")
        top_level = Path(self._git("rev-parse", "--show-toplevel").strip()).resolve(strict=True)
        if top_level != self._repository:
            raise ValueError("review repository must be the Git worktree root")

    def collect(self, deploy_candidates: frozenset[str]) -> tuple[ChangedFile, ...]:
        if not isinstance(deploy_candidates, frozenset):
            raise ValueError("deploy candidates must be an immutable set")
        unsupported = self._nul_paths(
            self._git("diff", "--name-only", "-z", "--diff-filter=RTUXB", "HEAD", "--")
        )
        if unsupported:
            raise ValueError("review change set contains an unsupported Git status")
        tracked = self._nul_paths(
            self._git("diff", "--name-only", "-z", "--diff-filter=ACDM", "HEAD", "--")
        )
        untracked = self._nul_paths(self._git("ls-files", "--others", "--exclude-standard", "-z", "--"))
        paths = tuple(sorted(set(tracked + untracked)))
        if not paths or len(paths) > _MAX_FILES:
            raise ValueError("review change set is empty or too large")
        if not deploy_candidates <= frozenset(paths):
            raise ValueError("deploy plan references a file outside the Git change set")
        files = tuple(
            ChangedFile(path, self._untracked_diff(path) if path in untracked else self._tracked_diff(path),
                        path in deploy_candidates)
            for path in paths
        )
        if sum(len(item.diff.encode("utf-8")) for item in files) > _MAX_DIFF_BYTES:
            raise ValueError("review diff set is too large")
        return files

    def collect_selected(
        self, selected_paths: frozenset[str], deploy_candidates: frozenset[str],
    ) -> tuple[ChangedFile, ...]:
        """Собирает только явно выбранное подмножество реального Git change set."""

        if not isinstance(selected_paths, frozenset) or not isinstance(deploy_candidates, frozenset):
            raise ValueError("review paths must be immutable sets")
        if not selected_paths or len(selected_paths) > _MAX_FILES or not deploy_candidates <= selected_paths:
            raise ValueError("selected review or deploy scope is invalid")
        ordered = tuple(sorted(selected_paths))
        unsupported = self._nul_paths(
            self._git("diff", "--name-only", "-z", "--diff-filter=RTUXB", "HEAD", "--", *ordered)
        )
        if unsupported:
            raise ValueError("selected review scope contains an unsupported Git status")
        tracked = frozenset(self._nul_paths(
            self._git("diff", "--name-only", "-z", "--diff-filter=ACDM", "HEAD", "--", *ordered)
        ))
        untracked = frozenset(self._nul_paths(
            self._git("ls-files", "--others", "--exclude-standard", "-z", "--", *ordered)
        ))
        if selected_paths != tracked | untracked:
            raise ValueError("selected path is not an exact Git change")
        files = tuple(
            ChangedFile(path, self._untracked_diff(path) if path in untracked else self._tracked_diff(path),
                        path in deploy_candidates)
            for path in ordered
        )
        if sum(len(item.diff.encode("utf-8")) for item in files) > _MAX_DIFF_BYTES:
            raise ValueError("selected review diff set is too large")
        return files

    def _tracked_diff(self, relative: str) -> str:
        path = self._safe_path(relative, allow_missing=True)
        if path.exists() and (path.is_symlink() or not path.is_file()):
            raise ValueError("review supports only regular text files")
        raw = self._git("diff", "--no-ext-diff", "--unified=0", "HEAD", "--", relative)
        start = raw.find("--- ")
        if start < 0 or "Binary files " in raw:
            raise ValueError("review does not accept binary or unsupported Git diffs")
        return raw[start:]

    def _untracked_diff(self, relative: str) -> str:
        path = self._safe_path(relative)
        if path.is_symlink() or not path.is_file():
            raise ValueError("review supports only regular text files")
        try:
            content = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as error:
            raise ValueError("review does not accept unreadable or binary files") from error
        lines = content.splitlines()
        if not lines:
            raise ValueError("review does not accept empty untracked files")
        added = "\n".join(f"+{line}" for line in lines)
        return f"--- /dev/null\n+++ b/{relative}\n@@ -0,0 +1,{len(lines)} @@\n{added}\n"

    def _safe_path(self, relative: str, allow_missing: bool = False) -> Path:
        candidate = self._repository / relative
        resolved_parent = candidate.parent.resolve(strict=True)
        if not resolved_parent.is_relative_to(self._repository):
            raise ValueError("Git returned a path outside repository")
        if candidate.exists() or candidate.is_symlink():
            resolved = candidate.resolve(strict=True)
            if not resolved.is_relative_to(self._repository):
                raise ValueError("Git path escapes repository")
        elif not allow_missing:
            raise ValueError("Git path does not exist")
        return candidate

    def _git(self, *arguments: str) -> str:
        environment = {**os.environ, "LC_ALL": "C", "GIT_OPTIONAL_LOCKS": "0"}
        result = subprocess.run(
            ["git", *arguments], cwd=self._repository, env=environment, capture_output=True,
            check=False, timeout=15,
        )
        if result.returncode != 0 or len(result.stdout) > _MAX_DIFF_BYTES:
            raise ValueError("Git review command failed or returned too much data")
        try:
            return result.stdout.decode("utf-8")
        except UnicodeDecodeError as error:
            raise ValueError("Git review output is not UTF-8") from error

    @staticmethod
    def _nul_paths(value: str) -> tuple[str, ...]:
        paths = tuple(item for item in value.split("\0") if item)
        if any("\n" in item or "\r" in item for item in paths):
            raise ValueError("Git path contains unsupported control characters")
        return paths


@dataclass(frozen=True)
class _ReceiptRecord:
    check_id: str
    status: str
    binding: str
    expires_at: float
    signature: str


@dataclass(frozen=True)
class _PriorReview:
    project_id: str
    finding_keys: tuple[str, ...]
    paths: tuple[str, ...]
    expires_at: float


@dataclass
class HmacReviewEvidenceService:
    """Выпускает exact-diff receipts и хранит provenance targeted re-review."""

    key: bytes
    clock: Callable[[], float] = time
    _receipts: dict[str, _ReceiptRecord] = field(default_factory=dict, init=False, repr=False)
    _prior_reviews: tuple[_PriorReview, ...] = field(default=(), init=False, repr=False)
    _lock: Lock = field(default_factory=Lock, init=False, repr=False)

    def __post_init__(self) -> None:
        if not isinstance(self.key, bytes) or len(self.key) < 32:
            raise ValueError("review evidence key must contain at least 32 bytes")

    def issue(self, check_id: str, status: str, binding: str, ttl_seconds: int) -> CheckEvidence:
        if not isinstance(ttl_seconds, int) or isinstance(ttl_seconds, bool) or not 0 < ttl_seconds <= 300:
            raise ValueError("review evidence ttl must be from 1 to 300 seconds")
        nonce = secrets.token_hex(16)
        expires_at = self.clock() + ttl_seconds
        if not isinstance(binding, str) or not binding.startswith("sha256:") or len(binding) != 71:
            raise ValueError("review evidence binding is invalid")
        signature = self._sign(check_id, status, binding, expires_at, nonce)
        evidence = f"receipt:{check_id}:{nonce}{signature}"
        check = CheckEvidence(check_id, status, evidence)
        record = _ReceiptRecord(check_id, status, binding, expires_at, signature)
        with self._lock:
            self._receipts = {**self._receipts, evidence: record}
        return check

    def verify(self, check: CheckEvidence, request: ReviewRequest) -> bool:
        with self._lock:
            record = self._receipts.get(check.evidence)
        if record is None or record.expires_at <= self.clock():
            return False
        nonce = check.evidence.rsplit(":", 1)[-1][:32]
        binding = review_evidence_binding(request)
        expected = self._sign(record.check_id, record.status, record.binding, record.expires_at, nonce)
        return bool(
            record.check_id == check.check_id and record.status == check.status
            and record.binding == binding and hmac.compare_digest(record.signature, expected)
        )

    def review(self, request: ReviewRequest, ttl_seconds: int = 1_209_600) -> ReviewResult:
        """Выполняет review и сохраняет provenance только для собственного результата engine."""
        if not isinstance(ttl_seconds, int) or isinstance(ttl_seconds, bool) or not 0 < ttl_seconds <= 1_209_600:
            raise ValueError("prior review ttl must be from 1 second to 14 days")
        result = ReviewEngine(self).review(request)
        self._record_review(request, result, ttl_seconds)
        return result

    def _record_review(self, request: ReviewRequest, result: ReviewResult, ttl_seconds: int) -> None:
        expected_keys = tuple(ReviewEngine._finding_key(finding) for finding in result.findings)
        if (
            result.receipt.project_id != request.project_id or result.receipt.diff_digest != request.diff_digest
            or result.receipt.open_finding_keys != expected_keys
            or result.affected_surface != result.receipt.affected_surface
        ):
            raise ValueError("review result does not match request")
        paths = tuple(finding.location.rsplit(":", 1)[0] for finding in result.findings)
        record = _PriorReview(
            request.project_id, result.receipt.open_finding_keys, paths, self.clock() + ttl_seconds,
        )
        with self._lock:
            self._prior_reviews = (*self._prior_reviews, record)

    def verify_prior_findings(
        self, finding_keys: tuple[str, ...], project_id: str, targeted_paths: tuple[str, ...],
    ) -> bool:
        with self._lock:
            records = self._prior_reviews
        return any(
            record.expires_at > self.clock() and record.project_id == project_id
            and record.finding_keys == finding_keys and set(record.paths) <= set(targeted_paths)
            for record in records
        )

    def authorize_prior_findings(
        self, finding_keys: tuple[str, ...], project_id: str, targeted_paths: tuple[str, ...], ttl_seconds: int = 300,
    ) -> None:
        """Imports an already HMAC-verified durable parent scope for one local re-review."""

        if not finding_keys or not targeted_paths or not 0 < ttl_seconds <= 300:
            raise ValueError("targeted prior review scope is invalid")
        record = _PriorReview(project_id, tuple(finding_keys), tuple(targeted_paths), self.clock() + ttl_seconds)
        with self._lock:
            self._prior_reviews = (*self._prior_reviews, record)

    def _sign(self, check_id: str, status: str, binding: str, expires_at: float, nonce: str) -> str:
        message = "\0".join((check_id, status, binding, str(expires_at), nonce)).encode()
        return hmac.new(self.key, message, hashlib.sha256).hexdigest()


def review_evidence_binding(request: ReviewRequest) -> str:
    """Хэширует весь контекст, способный изменить смысл deterministic check."""
    fields = (
        request.project_id, request.purpose, request.diff_digest, request.spec_version,
        request.policy_version, *request.skill_versions, request.model_route, request.trace_id,
        "targeted", *request.targeted_paths, "prior_findings", *request.prior_finding_keys,
    )
    return "sha256:" + hashlib.sha256("\0".join(fields).encode("utf-8")).hexdigest()
