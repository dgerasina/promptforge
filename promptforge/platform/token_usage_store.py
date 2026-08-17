"""Owner-private tamper-evident chain for metadata-only token usage digests."""

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
from typing import Callable


_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_ZERO_DIGEST = "sha256:" + "0" * 64
_SCHEMA_SQL = """
CREATE TABLE token_usage (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id TEXT NOT NULL,
    principal_id TEXT NOT NULL,
    trace_id TEXT NOT NULL,
    receipt_digest TEXT NOT NULL,
    recorded_at INTEGER NOT NULL,
    previous_digest TEXT NOT NULL,
    record_digest TEXT NOT NULL,
    attestation TEXT NOT NULL,
    UNIQUE(trace_id)
)
""".strip()


def _canonical_digest(payload: object) -> str:
    encoded = json.dumps(payload, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


@dataclass(frozen=True)
class DurableUsageReceipt:
    sequence: int
    trace_id: str
    receipt_digest: str
    record_digest: str
    recorded_at: int

    def to_payload(self) -> dict[str, object]:
        return {"schema_version": "1.0", "store_version": "1.0.0", **self.__dict__}


@dataclass(frozen=True)
class TokenUsageVerification:
    valid: bool
    records: int
    last_digest: str

    def to_payload(self) -> dict[str, object]:
        return {"schema_version": "1.0", "store_version": "1.0.0", **self.__dict__}


@dataclass(frozen=True)
class TokenUsageStore:
    """Persists only receipt digests and bounded identities; raw context is forbidden."""

    path: Path
    key: bytes = field(repr=False, compare=False)
    clock: Callable[[], float] = field(default=time.time, repr=False, compare=False)
    timeout_seconds: int = 5
    _device: int = field(init=False, repr=False, compare=False)
    _inode: int = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        path = Path(self.path)
        if not isinstance(self.key, bytes) or len(self.key) < 32:
            raise ValueError("token usage key must contain at least 32 bytes")
        if not path.is_absolute() or path.suffix != ".sqlite3" or not path.parent.is_dir():
            raise ValueError("token usage path must be an absolute SQLite path")
        if (
            not isinstance(self.timeout_seconds, int) or isinstance(self.timeout_seconds, bool)
            or not 1 <= self.timeout_seconds <= 30
        ):
            raise ValueError("token usage timeout is invalid")
        if path.exists() and (path.is_symlink() or not path.is_file()):
            raise ValueError("token usage path must be a regular file")
        object.__setattr__(self, "path", path)
        try:
            self._validate_parent()
        except RuntimeError as error:
            raise ValueError(str(error)) from error
        created = self._secure_create()
        try:
            metadata = self._validate_file_metadata(allow_empty=created)
        except RuntimeError as error:
            raise ValueError(str(error)) from error
        object.__setattr__(self, "_device", metadata.st_dev)
        object.__setattr__(self, "_inode", metadata.st_ino)
        self._initialize(created)

    def append_digest(
        self, project_id: str, principal_id: str, trace_id: str, receipt_digest: str,
    ) -> DurableUsageReceipt:
        if any(not isinstance(value, str) or not _SAFE_ID.fullmatch(value) for value in (
            project_id, principal_id, trace_id,
        )) or not _DIGEST.fullmatch(receipt_digest):
            raise ValueError("token usage metadata is invalid")
        recorded_at = int(self.clock())
        if recorded_at < 0:
            raise ValueError("token usage timestamp is invalid")
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            verification = self._verify_connection(connection)
            if not verification.valid:
                raise RuntimeError("token usage verification failed")
            payload = {
                "project_id": project_id, "principal_id": principal_id, "trace_id": trace_id,
                "receipt_digest": receipt_digest, "recorded_at": recorded_at,
                "previous_digest": verification.last_digest,
            }
            record_digest = _canonical_digest(payload)
            attestation = self._attest(record_digest)
            result = connection.execute(
                "INSERT INTO token_usage (project_id,principal_id,trace_id,receipt_digest,recorded_at,"
                "previous_digest,record_digest,attestation) VALUES (?,?,?,?,?,?,?,?)",
                (*tuple(payload.values()), record_digest, attestation),
            )
            connection.commit()
            return DurableUsageReceipt(result.lastrowid, trace_id, receipt_digest, record_digest, recorded_at)
        except sqlite3.IntegrityError as error:
            connection.rollback()
            raise ValueError("token usage replay is denied") from error
        except sqlite3.Error as error:
            connection.rollback()
            raise RuntimeError("token usage append failed") from error
        finally:
            connection.close()

    def verify(self) -> TokenUsageVerification:
        connection = self._connect()
        try:
            return self._verify_connection(connection)
        finally:
            connection.close()

    def _verify_connection(self, connection: sqlite3.Connection) -> TokenUsageVerification:
        columns = ("project_id", "principal_id", "trace_id", "receipt_digest", "recorded_at", "previous_digest")
        rows = connection.execute(
            f"SELECT sequence,{','.join(columns)},record_digest,attestation FROM token_usage ORDER BY sequence"
        ).fetchall()
        previous = _ZERO_DIGEST
        for expected, row in enumerate(rows, 1):
            sequence, *values, record_digest, attestation = row
            payload = dict(zip(columns, values, strict=True))
            calculated = _canonical_digest(payload)
            if not (
                sequence == expected and payload["previous_digest"] == previous
                and hmac.compare_digest(record_digest, calculated)
                and hmac.compare_digest(attestation, self._attest(record_digest))
            ):
                return TokenUsageVerification(False, len(rows), previous)
            previous = record_digest
        return TokenUsageVerification(True, len(rows), previous)

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
            descriptor = os.open(
                self.path, os.O_CREAT | os.O_EXCL | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0), 0o600,
            )
        except FileExistsError:
            return False
        os.close(descriptor)
        return True

    def _initialize(self, created: bool) -> None:
        connection = self._connect_unchecked()
        try:
            if created:
                connection.execute(_SCHEMA_SQL)
                connection.execute("PRAGMA user_version=1")
                connection.commit()
            schema = connection.execute(
                "SELECT sql FROM sqlite_master WHERE type='table' AND name='token_usage'"
            ).fetchone()
            if schema != (_SCHEMA_SQL,) or connection.execute("PRAGMA user_version").fetchone() != (1,):
                raise RuntimeError("token usage schema mismatch")
        finally:
            connection.close()

    def _connect_unchecked(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=self.timeout_seconds, isolation_level=None)
        connection.execute("PRAGMA journal_mode=DELETE")
        connection.execute("PRAGMA synchronous=FULL")
        return connection

    def _connect(self) -> sqlite3.Connection:
        self._validate_parent()
        metadata = self._validate_file_metadata()
        if (metadata.st_dev, metadata.st_ino) != (self._device, self._inode):
            raise RuntimeError("token usage file identity changed")
        connection = self._connect_unchecked()
        self._validate_parent()
        current = self._validate_file_metadata()
        if (current.st_dev, current.st_ino) != (self._device, self._inode):
            connection.close()
            raise RuntimeError("token usage file identity changed")
        return connection

    def _validate_parent(self) -> None:
        try:
            SECURE_FILESYSTEM.require_private_directory(self.path.parent)
        except (PermissionError, ValueError) as error:
            raise RuntimeError("token usage directory must be owner-private") from error

    def _validate_file_metadata(self, *, allow_empty: bool = False) -> os.stat_result:
        metadata = self.path.lstat()
        try:
            SECURE_FILESYSTEM.require_private_file(self.path, 100_000_000, allow_empty=allow_empty)
        except (PermissionError, ValueError) as error:
            raise RuntimeError("token usage file must be owner-only") from error
        return metadata
