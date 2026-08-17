"""Локальный metadata-only audit trail с tamper-evident hash chain."""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import sqlite3
import stat
import time

from promptforge.platform.secure_filesystem import SECURE_FILESYSTEM
from typing import Callable, Mapping, Protocol


_EVENT_FIELDS = frozenset({
    "schema_version", "trace_id", "principal_id", "project_id", "action", "resource", "outcome",
    "reason_code", "policy_version", "occurred_at",
})
_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_OUTCOMES = frozenset({"allow", "deny", "allow_with_transform", "approval_required", "ok", "error"})
_ZERO_HASH = "0" * 64
_LOCAL_AUDIT_ENV_PREFIX = "PF_LOCAL_AUDIT_"
_LOCAL_AUDIT_ENV_KEYS = frozenset({"PF_LOCAL_AUDIT_KEY_HEX"})
_SCHEMA_SQL = (
    "CREATE TABLE audit_events (sequence INTEGER PRIMARY KEY AUTOINCREMENT,event_id TEXT NOT NULL UNIQUE,"
    "trace_id TEXT NOT NULL,principal_id TEXT NOT NULL,project_id TEXT NOT NULL,action TEXT NOT NULL,"
    "resource TEXT NOT NULL,outcome TEXT NOT NULL,reason_code TEXT NOT NULL,policy_version TEXT NOT NULL,"
    "occurred_at INTEGER NOT NULL,previous_hash TEXT NOT NULL,event_hash TEXT NOT NULL,attestation TEXT NOT NULL)"
)


class AuditSink(Protocol):
    """Минимальная граница обязательной записи audit metadata."""

    def append(self, event: AuditEvent) -> AuditReceipt: ...


def local_audit_key_from_env(environment: Mapping[str, str] | None = None) -> bytes:
    """Загружает audit key из единственной разрешённой environment variable."""

    source = os.environ if environment is None else environment
    unknown = sorted(
        key for key in source if key.startswith(_LOCAL_AUDIT_ENV_PREFIX) and key not in _LOCAL_AUDIT_ENV_KEYS
    )
    if unknown:
        raise ValueError(f"unknown local audit environment: {unknown[0]}")
    encoded = source.get("PF_LOCAL_AUDIT_KEY_HEX", "")
    if not re.fullmatch(r"[0-9a-f]{64,128}", encoded):
        raise ValueError("PF_LOCAL_AUDIT_KEY_HEX must contain 32-64 lowercase hex bytes")
    return bytes.fromhex(encoded)


def _safe(value: object, name: str) -> str:
    if not isinstance(value, str) or not _SAFE_ID.fullmatch(value) or value.lower().startswith("sk-"):
        raise ValueError(f"audit {name} is invalid")
    return value


@dataclass(frozen=True)
class AuditEvent:
    """Описывает только разрешённую metadata одного security/runtime события."""

    trace_id: str
    principal_id: str
    project_id: str
    action: str
    resource: str
    outcome: str
    reason_code: str
    policy_version: str
    occurred_at: int

    def __post_init__(self) -> None:
        for value, name in (
            (self.trace_id, "trace id"), (self.principal_id, "principal id"), (self.project_id, "project id"),
            (self.action, "action"), (self.resource, "resource"), (self.reason_code, "reason code"),
            (self.policy_version, "policy version"),
        ):
            _safe(value, name)
        if self.outcome not in _OUTCOMES:
            raise ValueError("audit outcome is invalid")
        if not isinstance(self.occurred_at, int) or isinstance(self.occurred_at, bool) or self.occurred_at < 0:
            raise ValueError("audit timestamp is invalid")

    def to_payload(self) -> dict[str, object]:
        return {"schema_version": "1.0", **self.__dict__}

    @classmethod
    def from_payload(cls, payload: Mapping[str, object]) -> AuditEvent:
        if not isinstance(payload, Mapping) or set(payload) != _EVENT_FIELDS:
            raise ValueError("audit event fields mismatch")
        if payload.get("schema_version") != "1.0":
            raise ValueError("unsupported audit event schema")
        return cls(**{key: value for key, value in payload.items() if key != "schema_version"})


@dataclass(frozen=True)
class AuditReceipt:
    """Подтверждает append без раскрытия event metadata."""

    sequence: int
    event_id: str
    previous_hash: str
    event_hash: str
    occurred_at: int

    def to_payload(self) -> dict[str, object]:
        return {"schema_version": "1.0", **self.__dict__}


@dataclass(frozen=True)
class AuditVerification:
    valid: bool
    events: int
    last_hash: str


@dataclass(frozen=True)
class LocalAuditStore:
    """Атомарно добавляет и проверяет локальную SQLite audit chain."""

    path: Path
    key: bytes = field(repr=False, compare=False)
    clock: Callable[[], float] = field(default=time.time, repr=False, compare=False)
    id_factory: Callable[[], str] = field(default=lambda: secrets.token_hex(16), repr=False, compare=False)
    timeout_seconds: int = 30
    _device: int = field(init=False, repr=False, compare=False)
    _inode: int = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        if not isinstance(self.key, bytes) or len(self.key) < 32:
            raise ValueError("local audit key must contain at least 32 bytes")
        if (
            not isinstance(self.timeout_seconds, int) or isinstance(self.timeout_seconds, bool)
            or not 1 <= self.timeout_seconds <= 30
        ):
            raise ValueError("local audit SQLite timeout is invalid")
        path = Path(self.path)
        if not path.is_absolute() or path.suffix != ".sqlite3" or not path.parent.is_dir():
            raise ValueError("audit SQLite path must be absolute in an existing directory")
        try:
            SECURE_FILESYSTEM.require_private_directory(path.parent)
        except (PermissionError, ValueError) as error:
            raise ValueError("audit SQLite directory must be owner-private") from error
        if path.exists() and (path.is_symlink() or not path.is_file()):
            raise ValueError("audit SQLite path must be a regular file")
        object.__setattr__(self, "path", path)
        created = self._secure_create()
        file_stat = path.lstat()
        try:
            SECURE_FILESYSTEM.require_private_file(path, 100_000_000, allow_empty=created)
        except (PermissionError, ValueError) as error:
            raise ValueError("audit SQLite file must be owner-only") from error
        object.__setattr__(self, "_device", file_stat.st_dev)
        object.__setattr__(self, "_inode", file_stat.st_ino)
        self._initialize(created)

    def append(self, event: AuditEvent) -> AuditReceipt:
        if event.occurred_at > int(self.clock()):
            raise ValueError("future audit event is invalid")
        event_id = _safe(self.id_factory(), "event id")
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            verification = self._verify_connection(connection)
            if not verification.valid:
                connection.rollback()
                raise RuntimeError("audit chain verification failed")
            previous_hash = verification.last_hash
            event_hash = self._event_hash(event_id, event, previous_hash)
            attestation = self._attest(event_hash)
            statement_result = connection.execute(
                "INSERT INTO audit_events (event_id,trace_id,principal_id,project_id,action,resource,outcome,"
                "reason_code,policy_version,occurred_at,previous_hash,event_hash,attestation) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    event_id, event.trace_id, event.principal_id, event.project_id, event.action, event.resource,
                    event.outcome, event.reason_code, event.policy_version, event.occurred_at, previous_hash,
                    event_hash, attestation,
                ),
            )
            connection.commit()
            return AuditReceipt(statement_result.lastrowid, event_id, previous_hash, event_hash, event.occurred_at)
        except sqlite3.Error as error:
            connection.rollback()
            raise RuntimeError("audit append failed") from error
        finally:
            connection.close()

    def verify(self) -> AuditVerification:
        connection = self._connect()
        try:
            return self._verify_connection(connection)
        except sqlite3.Error as error:
            raise RuntimeError("audit verification failed") from error
        finally:
            connection.close()

    def _verify_connection(self, connection: sqlite3.Connection) -> AuditVerification:
        previous_hash = _ZERO_HASH
        rows = connection.execute(
            "SELECT sequence,event_id,trace_id,principal_id,project_id,action,resource,outcome,reason_code,"
            "policy_version,occurred_at,previous_hash,event_hash,attestation FROM audit_events ORDER BY sequence"
        ).fetchall()
        expected_sequence = 1
        for row in rows:
            sequence, event_id, *values, stored_previous, event_hash, attestation = row
            event = AuditEvent(*values)
            expected_hash = self._event_hash(event_id, event, previous_hash)
            valid = bool(
                sequence == expected_sequence and stored_previous == previous_hash
                and hmac.compare_digest(event_hash, expected_hash)
                and hmac.compare_digest(attestation, self._attest(event_hash))
            )
            if not valid:
                return AuditVerification(False, len(rows), previous_hash)
            previous_hash = event_hash
            expected_sequence += 1
        return AuditVerification(True, len(rows), previous_hash)

    def _event_hash(self, event_id: str, event: AuditEvent, previous_hash: str) -> str:
        canonical = json.dumps(
            {"event_id": event_id, **event.to_payload(), "previous_hash": previous_hash},
            sort_keys=True, separators=(",", ":"),
        ).encode("utf-8")
        return hashlib.sha256(canonical).hexdigest()

    def _attest(self, event_hash: str) -> str:
        return "hmac-sha256:" + hmac.new(self.key, event_hash.encode("ascii"), hashlib.sha256).hexdigest()

    def _secure_create(self) -> bool:
        if os.name == "nt":
            try:
                SECURE_FILESYSTEM.write_new_private(self.path, b"")
            except FileExistsError:
                return False
            return True
        flags = os.O_CREAT | os.O_EXCL | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(self.path, flags, 0o600)
        except FileExistsError:
            return False
        else:
            os.close(descriptor)
            return True

    def _initialize(self, created: bool) -> None:
        connection = self._connect()
        try:
            if created:
                connection.execute(_SCHEMA_SQL)
                connection.execute("PRAGMA user_version=1")
                connection.commit()
            schema = connection.execute(
                "SELECT sql FROM sqlite_master WHERE type='table' AND name='audit_events'"
            ).fetchone()
            version = connection.execute("PRAGMA user_version").fetchone()
            if schema != (_SCHEMA_SQL,) or version != (1,):
                raise RuntimeError("audit SQLite schema mismatch")
        finally:
            connection.close()

    def _connect(self) -> sqlite3.Connection:
        try:
            metadata = self.path.lstat()
        except OSError as error:
            raise RuntimeError("audit SQLite identity unavailable") from error
        if not stat.S_ISREG(metadata.st_mode) or (metadata.st_dev, metadata.st_ino) != (self._device, self._inode):
            raise RuntimeError("audit SQLite file identity changed")
        connection = sqlite3.connect(self.path, timeout=self.timeout_seconds, isolation_level=None)
        current = self.path.lstat()
        if (current.st_dev, current.st_ino) != (self._device, self._inode):
            connection.close()
            raise RuntimeError("audit SQLite file identity changed")
        connection.execute("PRAGMA journal_mode=DELETE")
        connection.execute("PRAGMA synchronous=FULL")
        return connection
