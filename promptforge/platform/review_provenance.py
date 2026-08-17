"""Durable, repository-only provenance for Review foundation 2.0."""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import time

from promptforge.platform.secure_filesystem import SECURE_FILESYSTEM
from typing import Callable, Mapping

from promptforge.platform.review import ReviewEngine, ReviewRequest, ReviewResult


_DIGEST_PREFIX = "sha256:"
_ZERO_DIGEST = _DIGEST_PREFIX + "0" * 64
_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_STATUSES = frozenset({"approved", "changes_requested", "incomplete"})
_SCHEMA_SQL = (
    "CREATE TABLE review_provenance (sequence INTEGER PRIMARY KEY AUTOINCREMENT,review_id TEXT NOT NULL UNIQUE,"
    "project_id TEXT NOT NULL,request_digest TEXT NOT NULL,result_digest TEXT NOT NULL,receipt_digest TEXT NOT NULL,"
    "diff_digest TEXT NOT NULL,status TEXT NOT NULL,spec_version TEXT NOT NULL,policy_version TEXT NOT NULL,"
    "skills_digest TEXT NOT NULL,checks_digest TEXT NOT NULL,agent_catalog_digest TEXT NOT NULL,recorded_at INTEGER "
    "NOT NULL,previous_digest TEXT NOT NULL,record_digest TEXT NOT NULL,attestation TEXT NOT NULL)"
)


def _canonical_digest(payload: object) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    return _DIGEST_PREFIX + hashlib.sha256(encoded).hexdigest()


def _valid_digest(value: object) -> bool:
    return isinstance(value, str) and len(value) == 71 and value.startswith(_DIGEST_PREFIX) and all(
        character in "0123456789abcdef" for character in value[7:]
    )


@dataclass(frozen=True)
class ReviewProvenanceReceipt:
    sequence: int
    review_id: str
    request_digest: str
    result_digest: str
    receipt_digest: str
    record_digest: str
    recorded_at: int
    review_version: str = "2.0"

    def to_payload(self) -> dict[str, object]:
        return {"schema_version": "1.0", **self.__dict__}


@dataclass(frozen=True)
class ReviewProvenanceVerification:
    valid: bool
    records: int
    last_digest: str

    def to_payload(self) -> dict[str, object]:
        return {"schema_version": "1.0", **self.__dict__, "review_version": "2.0"}


@dataclass(frozen=True)
class ReviewProvenanceStore:
    """Owner-private SQLite chain; persists digests and bounded review metadata only."""

    path: Path
    key: bytes = field(repr=False, compare=False)
    clock: Callable[[], float] = field(default=time.time, repr=False, compare=False)
    timeout_seconds: int = 5
    _device: int = field(init=False, repr=False, compare=False)
    _inode: int = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        if not isinstance(self.key, bytes) or len(self.key) < 32:
            raise ValueError("review provenance key must contain at least 32 bytes")
        path = Path(self.path)
        if not path.is_absolute() or path.suffix != ".sqlite3" or not path.parent.is_dir():
            raise ValueError("review provenance path must be an absolute SQLite path")
        try:
            SECURE_FILESYSTEM.require_private_directory(path.parent)
        except (PermissionError, ValueError) as error:
            raise ValueError("review provenance directory must be owner-private") from error
        if (
            not isinstance(self.timeout_seconds, int) or isinstance(self.timeout_seconds, bool)
            or not 1 <= self.timeout_seconds <= 30
        ):
            raise ValueError("review provenance timeout is invalid")
        if path.exists() and (path.is_symlink() or not path.is_file()):
            raise ValueError("review provenance path must be a regular file")
        object.__setattr__(self, "path", path)
        created = self._secure_create()
        metadata = path.lstat()
        try:
            SECURE_FILESYSTEM.require_private_file(path, 100_000_000, allow_empty=created)
        except (PermissionError, ValueError) as error:
            raise ValueError("review provenance file must be owner-only") from error
        object.__setattr__(self, "_device", metadata.st_dev)
        object.__setattr__(self, "_inode", metadata.st_ino)
        self._initialize(created)

    def append(self, metadata: Mapping[str, object]) -> ReviewProvenanceReceipt:
        required = {
            "review_id", "project_id", "request_digest", "result_digest", "receipt_digest", "diff_digest",
            "status", "spec_version", "policy_version", "skills_digest", "checks_digest", "agent_catalog_digest",
        }
        if set(metadata) != required or any(not isinstance(metadata[name], str) for name in required):
            raise ValueError("review provenance metadata fields mismatch")
        digest_fields = {name for name in required if name.endswith("digest")}
        if any(not _valid_digest(metadata[name]) for name in digest_fields):
            raise ValueError("review provenance digest is invalid")
        identifier_fields = ("review_id", "project_id", "spec_version", "policy_version")
        if any(not _SAFE_ID.fullmatch(str(metadata[name])) for name in identifier_fields):
            raise ValueError("review provenance identifier is invalid")
        if metadata["status"] not in _STATUSES:
            raise ValueError("review provenance status is invalid")
        recorded_at = int(self.clock())
        if recorded_at < 0:
            raise ValueError("review provenance timestamp is invalid")
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            verification = self._verify_connection(connection)
            if not verification.valid:
                connection.rollback()
                raise RuntimeError("review provenance verification failed")
            previous = verification.last_digest
            record_payload = {**metadata, "recorded_at": recorded_at, "previous_digest": previous}
            record_digest = _canonical_digest(record_payload)
            attestation = self._attest(record_digest)
            columns = tuple(record_payload)
            result = connection.execute(
                f"INSERT INTO review_provenance ({','.join(columns)},record_digest,attestation) "
                f"VALUES ({','.join('?' for _ in range(len(columns) + 2))})",
                (*tuple(record_payload[name] for name in columns), record_digest, attestation),
            )
            connection.commit()
        except sqlite3.IntegrityError as error:
            connection.rollback()
            raise ValueError("review provenance replay is denied") from error
        except sqlite3.Error as error:
            connection.rollback()
            raise RuntimeError("review provenance append failed") from error
        finally:
            connection.close()
        return ReviewProvenanceReceipt(
            result.lastrowid, str(metadata["review_id"]), str(metadata["request_digest"]),
            str(metadata["result_digest"]), str(metadata["receipt_digest"]), record_digest, recorded_at,
        )

    def verify(self) -> ReviewProvenanceVerification:
        connection = self._connect()
        try:
            return self._verify_connection(connection)
        finally:
            connection.close()

    def _verify_connection(self, connection: sqlite3.Connection) -> ReviewProvenanceVerification:
        columns = (
            "review_id", "project_id", "request_digest", "result_digest", "receipt_digest", "diff_digest",
            "status", "spec_version", "policy_version", "skills_digest", "checks_digest", "agent_catalog_digest",
            "recorded_at", "previous_digest",
        )
        rows = connection.execute(
            f"SELECT sequence,{','.join(columns)},record_digest,attestation FROM review_provenance ORDER BY sequence"
        ).fetchall()
        previous = _ZERO_DIGEST
        for expected, row in enumerate(rows, 1):
            sequence, *values, record_digest, attestation = row
            payload = dict(zip(columns, values, strict=True))
            expected_digest = _canonical_digest(payload)
            if not (
                sequence == expected and payload["previous_digest"] == previous
                and hmac.compare_digest(record_digest, expected_digest)
                and hmac.compare_digest(attestation, self._attest(record_digest))
            ):
                return ReviewProvenanceVerification(False, len(rows), previous)
            previous = record_digest
        return ReviewProvenanceVerification(True, len(rows), previous)

    def _attest(self, digest: str) -> str:
        return "hmac-sha256:" + hmac.new(self.key, digest.encode("ascii"), hashlib.sha256).hexdigest()

    def _secure_create(self) -> bool:
        if os.name == "nt":
            try:
                SECURE_FILESYSTEM.write_new_private(self.path, b"")
            except FileExistsError:
                return False
            return True
        try:
            descriptor = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0), 0o600)
        except FileExistsError:
            return False
        os.close(descriptor)
        return True

    def _initialize(self, created: bool) -> None:
        connection = self._connect_unchecked()
        try:
            if created:
                connection.execute(_SCHEMA_SQL)
                connection.execute("PRAGMA user_version=2")
                connection.commit()
            schema = connection.execute(
                "SELECT sql FROM sqlite_master WHERE type='table' AND name='review_provenance'"
            ).fetchone()
            if schema != (_SCHEMA_SQL,) or connection.execute("PRAGMA user_version").fetchone() != (2,):
                raise RuntimeError("review provenance schema mismatch")
        finally:
            connection.close()

    def _connect_unchecked(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=self.timeout_seconds, isolation_level=None)
        connection.execute("PRAGMA journal_mode=DELETE")
        connection.execute("PRAGMA synchronous=FULL")
        return connection

    def _connect(self) -> sqlite3.Connection:
        metadata = self.path.lstat()
        if not stat.S_ISREG(metadata.st_mode) or (metadata.st_dev, metadata.st_ino) != (self._device, self._inode):
            raise RuntimeError("review provenance file identity changed")
        connection = self._connect_unchecked()
        current = self.path.lstat()
        if (current.st_dev, current.st_ino) != (self._device, self._inode):
            connection.close()
            raise RuntimeError("review provenance file identity changed")
        return connection


@dataclass(frozen=True)
class DurableReviewFoundation:
    store: ReviewProvenanceStore

    def record(
        self, request: ReviewRequest, result: ReviewResult, *, agent_catalog_digest: str,
    ) -> ReviewProvenanceReceipt:
        expected_keys = tuple(ReviewEngine._finding_key(finding) for finding in result.findings)
        receipt = result.receipt
        finding_counts = tuple(
            sum(finding.severity == severity for finding in result.findings)
            for severity in ("high", "medium", "low")
        )
        failed_checks = tuple(sorted(check.check_id for check in request.checks if check.status == "failed"))
        if (
            receipt.trace_id != request.trace_id or receipt.project_id != request.project_id
            or receipt.diff_digest != request.diff_digest or receipt.spec_version != request.spec_version
            or receipt.policy_version != request.policy_version or receipt.open_finding_keys != expected_keys
            or receipt.affected_surface != result.affected_surface
            or receipt.finding_counts != finding_counts or receipt.checks_failed != failed_checks
            or receipt.contract_reviewed != request.contract_reviewed
            or receipt.targeted != bool(request.targeted_paths)
        ):
            raise ValueError("review result provenance does not match request")
        return self.store.append({
            "review_id": request.trace_id, "project_id": request.project_id,
            "request_digest": _canonical_digest(request.to_payload()),
            "result_digest": _canonical_digest(result.to_payload()),
            "receipt_digest": _canonical_digest(receipt.to_payload()), "diff_digest": request.diff_digest,
            "status": "approved" if receipt.status == "passed" else receipt.status,
            "spec_version": request.spec_version, "policy_version": request.policy_version,
            "skills_digest": _canonical_digest(list(request.skill_versions)),
            "checks_digest": _canonical_digest([check.to_payload() for check in request.checks]),
            "agent_catalog_digest": agent_catalog_digest,
        })
