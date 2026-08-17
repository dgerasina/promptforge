"""Owner-controlled model admission без автоматического изменения manifest в Git."""

from __future__ import annotations

from dataclasses import dataclass, field, replace
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import sqlite3
import stat
import threading
import time
from typing import Callable, Protocol

from promptforge.platform.contracts import Principal
from promptforge.platform.governance import GovernancePolicy
from promptforge.platform.model_admission import (
    ModelAdmissionAuthority, ModelAdmissionDecision, ModelAdmissionManifest, ModelEvalEvidence,
)


_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_ATTESTATION = re.compile(r"^hmac-sha256:[0-9a-f]{64}$")
_CONSUMPTION_SCHEMA = (
    "CREATE TABLE consumed_approvals ("
    "approval_id TEXT PRIMARY KEY, expires_at INTEGER NOT NULL CHECK (expires_at > 0))"
)


def _evidence_sha256(evidence: ModelEvalEvidence) -> str:
    payload = json.dumps(evidence.to_payload(), sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _decision_sha256(decision: ModelAdmissionDecision) -> str:
    payload = json.dumps(decision.to_payload(), sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


class ApprovalConsumptionStore(Protocol):
    """Атомарно отмечает approval как использованный до его expiry."""

    def consume(self, approval_id: str, expires_at: int) -> bool: ...


@dataclass
class InMemoryApprovalConsumptionStore:
    """Локальная реализация; production требует shared durable adapter."""

    clock: Callable[[], float] = field(default=time.time, repr=False)
    _consumed: dict[str, int] = field(default_factory=dict, init=False, repr=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, init=False, repr=False)

    def consume(self, approval_id: str, expires_at: int) -> bool:
        with self._lock:
            now = int(self.clock())
            self._consumed = {key: expiry for key, expiry in self._consumed.items() if expiry > now}
            if approval_id in self._consumed:
                return False
            self._consumed = {**self._consumed, approval_id: expires_at}
            return True


@dataclass(frozen=True)
class SqliteApprovalConsumptionStore:
    """Атомарно хранит consumed approvals без отдельного сервиса."""

    path: Path
    clock: Callable[[], float] = field(default=time.time, repr=False, compare=False)
    timeout_seconds: int = 5

    def __post_init__(self) -> None:
        path = Path(self.path)
        if not path.is_absolute() or path.suffix != ".sqlite3" or not path.parent.is_dir():
            raise ValueError("approval SQLite path must be an absolute .sqlite3 path in an existing directory")
        parent = path.parent
        parent_stat = parent.lstat()
        owner_ok = not hasattr(os, "getuid") or parent_stat.st_uid == os.getuid()
        if parent.resolve() != parent or stat.S_IMODE(parent_stat.st_mode) != 0o700 or not owner_ok:
            raise ValueError("approval SQLite directory must be owner-private and must not use symlinks")
        if path.exists() and (path.is_symlink() or not path.is_file()):
            raise ValueError("approval SQLite path must be a regular file")
        if (
            not isinstance(self.timeout_seconds, int) or isinstance(self.timeout_seconds, bool)
            or not 1 <= self.timeout_seconds <= 30
        ):
            raise ValueError("approval SQLite timeout is invalid")
        object.__setattr__(self, "path", path)
        created = self._secure_create()
        file_stat = path.lstat()
        file_owner_ok = not hasattr(os, "getuid") or file_stat.st_uid == os.getuid()
        if not stat.S_ISREG(file_stat.st_mode) or stat.S_IMODE(file_stat.st_mode) != 0o600 or not file_owner_ok:
            raise ValueError("approval SQLite file must be owner-only")
        self._initialize(created)

    def consume(self, approval_id: str, expires_at: int) -> bool:
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", approval_id):
            raise ValueError("approval id is invalid")
        now = int(self.clock())
        if not isinstance(expires_at, int) or isinstance(expires_at, bool) or expires_at <= now:
            raise ValueError("approval expiry is invalid")
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute("DELETE FROM consumed_approvals WHERE expires_at <= ?", (now,))
            try:
                connection.execute(
                    "INSERT INTO consumed_approvals (approval_id, expires_at) VALUES (?, ?)",
                    (approval_id, expires_at),
                )
            except sqlite3.IntegrityError:
                connection.rollback()
                return False
            connection.commit()
            return True
        finally:
            connection.close()

    def _secure_create(self) -> bool:
        flags = os.O_CREAT | os.O_EXCL | os.O_RDWR
        flags |= getattr(os, "O_NOFOLLOW", 0)
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
                connection.execute(_CONSUMPTION_SCHEMA)
                connection.execute("PRAGMA user_version=1")
                connection.commit()
            schema = connection.execute(
                "SELECT sql FROM sqlite_master WHERE type='table' AND name='consumed_approvals'"
            ).fetchone()
            version = connection.execute("PRAGMA user_version").fetchone()
            if schema != (_CONSUMPTION_SCHEMA,) or version != (1,):
                raise RuntimeError("approval SQLite schema mismatch")
        finally:
            connection.close()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=self.timeout_seconds, isolation_level=None)
        connection.execute("PRAGMA journal_mode=DELETE")
        connection.execute("PRAGMA synchronous=FULL")
        return connection


@dataclass(frozen=True)
class ModelOwnerApproval:
    """Связывает одно owner-подтверждение с exact manifest и signed evidence."""

    approval_id: str
    manifest_binding: str
    evidence_sha256: str
    owner_id: str
    project_id: str
    issued_at: int
    expires_at: int
    attestation: str

    def __post_init__(self) -> None:
        if not self.approval_id or not self.owner_id or not self.project_id:
            raise ValueError("model owner approval identity is invalid")
        if not _DIGEST.fullmatch(self.manifest_binding) or not _DIGEST.fullmatch(self.evidence_sha256):
            raise ValueError("model owner approval binding is invalid")
        if (
            not isinstance(self.issued_at, int) or isinstance(self.issued_at, bool)
            or not isinstance(self.expires_at, int) or isinstance(self.expires_at, bool)
            or self.expires_at <= self.issued_at
        ):
            raise ValueError("model owner approval expiry is invalid")
        if not _ATTESTATION.fullmatch(self.attestation):
            raise ValueError("model owner approval attestation is invalid")


@dataclass(frozen=True)
class ModelAdmissionRelease:
    """Возвращает approved runtime manifest copy и signed admission decision."""

    manifest: ModelAdmissionManifest
    decision: ModelAdmissionDecision
    owner_id: str
    approval_id: str
    receipt: ModelAdmissionReleaseReceipt


@dataclass(frozen=True)
class ModelAdmissionReleaseReceipt:
    """Доказывает downstream, что decision прошёл exact owner approval."""

    approval_id: str
    owner_id: str
    project_id: str
    manifest_binding: str
    decision_sha256: str
    approval_expires_at: int
    released_at: int
    attestation: str


@dataclass
class ModelAdmissionWorkflow:
    """Требует exact owner approval и одноразово выпускает runtime release."""

    authority: ModelAdmissionAuthority
    approval_key: bytes = field(repr=False)
    owner_ids: frozenset[str]
    project_id: str
    consumption_store: ApprovalConsumptionStore
    approval_ttl_seconds: int = 300
    clock: Callable[[], float] = field(default=time.time, repr=False)
    id_factory: Callable[[], str] = field(default=lambda: secrets.token_hex(16), repr=False)

    def __post_init__(self) -> None:
        if not isinstance(self.approval_key, bytes) or len(self.approval_key) < 32:
            raise ValueError("model owner approval key must contain at least 32 bytes")
        if self.owner_ids != frozenset({"owner-local", "maintainer-local"}) or self.project_id != "promptforge":
            raise ValueError("model owner approval policy is invalid")
        if (
            not isinstance(self.approval_ttl_seconds, int) or isinstance(self.approval_ttl_seconds, bool)
            or not 1 <= self.approval_ttl_seconds <= 3_600
        ):
            raise ValueError("model owner approval TTL is invalid")

    def approve(
        self, principal: Principal, manifest: ModelAdmissionManifest, evidence: ModelEvalEvidence,
    ) -> ModelOwnerApproval:
        if (
            not GovernancePolicy.builtin().allows(principal, "models.admit") or principal.id not in self.owner_ids
            or principal.project_id != self.project_id or manifest.status != "review"
            or self.authority.decide(manifest, evidence).status != "approved"
        ):
            raise PermissionError("model admission owner approval denied")
        now = int(self.clock())
        unsigned = ModelOwnerApproval(
            self.id_factory(), manifest.binding(), _evidence_sha256(evidence), principal.id,
            principal.project_id, now, now + self.approval_ttl_seconds, "hmac-sha256:" + "0" * 64,
        )
        return replace(unsigned, attestation=self._sign(unsigned))

    def release(
        self, manifest: ModelAdmissionManifest, evidence: ModelEvalEvidence, approval: ModelOwnerApproval,
    ) -> ModelAdmissionRelease:
        now = int(self.clock())
        expected = self._sign(replace(approval, attestation="hmac-sha256:" + "0" * 64))
        valid = bool(
            manifest.status == "review"
            and approval.owner_id in self.owner_ids
            and approval.project_id == self.project_id
            and approval.manifest_binding == manifest.binding()
            and approval.evidence_sha256 == _evidence_sha256(evidence)
            and approval.issued_at <= now < approval.expires_at
            and hmac.compare_digest(expected, approval.attestation)
        )
        if not valid:
            raise PermissionError("model admission release denied")
        decision = self.authority.decide(manifest, evidence)
        if decision.status != "approved":
            raise PermissionError("model admission evidence no longer passes")
        if not self.consumption_store.consume(approval.approval_id, approval.expires_at):
            raise PermissionError("model admission approval already consumed")
        approved_manifest = replace(manifest, status="approved")
        unsigned_receipt = ModelAdmissionReleaseReceipt(
            approval.approval_id, approval.owner_id, approval.project_id, manifest.binding(),
            _decision_sha256(decision), approval.expires_at, now, "hmac-sha256:" + "0" * 64,
        )
        receipt = replace(unsigned_receipt, attestation=self._sign_release(unsigned_receipt))
        return ModelAdmissionRelease(approved_manifest, decision, approval.owner_id, approval.approval_id, receipt)

    def verify_release(self, release: ModelAdmissionRelease) -> bool:
        receipt = release.receipt
        expected = self._sign_release(replace(receipt, attestation="hmac-sha256:" + "0" * 64))
        return bool(
            release.manifest.status == "approved"
            and release.owner_id == receipt.owner_id
            and release.owner_id in self.owner_ids
            and release.approval_id == receipt.approval_id
            and receipt.project_id == self.project_id
            and receipt.manifest_binding == release.manifest.binding()
            and receipt.decision_sha256 == _decision_sha256(release.decision)
            and receipt.released_at <= int(self.clock()) < receipt.approval_expires_at
            and self.authority.verify(release.decision, release.manifest)
            and hmac.compare_digest(expected, receipt.attestation)
        )

    def _sign(self, approval: ModelOwnerApproval) -> str:
        message = "\0".join((
            approval.approval_id, approval.manifest_binding, approval.evidence_sha256, approval.owner_id,
            approval.project_id, str(approval.issued_at), str(approval.expires_at),
        ))
        return "hmac-sha256:" + hmac.new(self.approval_key, message.encode("utf-8"), hashlib.sha256).hexdigest()

    def _sign_release(self, receipt: ModelAdmissionReleaseReceipt) -> str:
        message = "\0".join((
            "model-admission-release", receipt.approval_id, receipt.owner_id, receipt.project_id,
            receipt.manifest_binding, receipt.decision_sha256, str(receipt.approval_expires_at),
            str(receipt.released_at),
        ))
        return "hmac-sha256:" + hmac.new(self.approval_key, message.encode("utf-8"), hashlib.sha256).hexdigest()
