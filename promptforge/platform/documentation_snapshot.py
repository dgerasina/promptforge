"""Owner-private attested snapshots for untrusted external documentation."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import stat
import time
from types import MappingProxyType
from typing import Callable

from promptforge.platform.security import inspect_text


_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_SPACE = re.compile(r"^[A-Z][A-Z0-9_]{0,31}$")
_PAGE = re.compile(r"^[0-9]{1,32}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_CLASSIFICATIONS = frozenset({"public", "internal"})
_SNAPSHOT_FIELDS = frozenset({
    "schema_version", "snapshot_id", "document_id", "principal_id", "trace_id", "source", "classification",
    "content", "content_digest", "mcp_receipt_digest", "captured_at", "expires_at", "content_trust",
    "instruction_authority", "attestation",
})
_SOURCE_FIELDS = frozenset({"space_key", "page_id", "page_version"})
_RESERVATION_FIELDS = frozenset({"schema_version", "snapshot_id", "snapshot_digest", "principal_id", "reserved_at"})
_UNSAFE = re.compile(
    r"(?:<[^>]+>|!\[|\]\(|<!--|PF:GENERATED|ignore\s+(?:all\s+)?previous\s+instructions)", re.IGNORECASE,
)
_MAX_CONTENT_BYTES = 20_000


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _digest(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _strict_json(raw: bytes) -> object:
    def unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON field")
            result = {**result, key: value}
        return result

    return json.loads(raw, object_pairs_hook=unique)


def _inert_markdown(content: str) -> str:
    escaped = content.replace("\\", "\\\\")
    return re.sub(r"([`*_{}\[\]()#+.!|>~-])", r"\\\1", escaped)


def _read_private_file(path: Path, *, max_bytes: int) -> bytes:
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError as error:
        raise PermissionError("documentation snapshot file is invalid") from error
    with os.fdopen(descriptor, "rb") as stream:
        metadata = os.fstat(stream.fileno())
        if not stat.S_ISREG(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != 0o600:
            raise PermissionError("documentation snapshot file is invalid")
        raw = stream.read(max_bytes + 1)
        if len(raw) > max_bytes:
            raise PermissionError("documentation snapshot file is oversized")
    return raw


@dataclass(frozen=True)
class SnapshotSource:
    space_key: str
    page_id: str
    page_version: int

    def __post_init__(self) -> None:
        if not _SPACE.fullmatch(self.space_key) or not _PAGE.fullmatch(self.page_id):
            raise ValueError("documentation snapshot source is invalid")
        if not isinstance(self.page_version, int) or isinstance(self.page_version, bool) or self.page_version < 0:
            raise ValueError("documentation snapshot version is invalid")


@dataclass(frozen=True)
class SnapshotReceipt:
    snapshot_id: str
    snapshot_digest: str
    content_digest: str
    source: SnapshotSource
    expires_at: int

    def to_payload(self) -> dict[str, object]:
        return {
            "schema_version": "1.0", "snapshot_id": self.snapshot_id,
            "snapshot_digest": self.snapshot_digest, "content_digest": self.content_digest,
            "source": {
                "space_key": self.source.space_key, "page_id": self.source.page_id,
                "page_version": self.source.page_version,
            },
            "expires_at": self.expires_at, "content_trust": "untrusted_external_data",
            "instruction_authority": False,
        }


@dataclass(frozen=True)
class DocumentationSnapshot:
    snapshot_id: str
    document_id: str
    principal_id: str
    source: SnapshotSource
    classification: str
    content: str
    content_digest: str
    mcp_receipt_digest: str
    instruction_authority: bool = False


class DocumentationSnapshotStore:
    """Stores exact HMAC-attested snapshots outside Git in owner-private state."""

    def __init__(self, state_root: Path, key: bytes, *, clock: Callable[[], int] = lambda: int(time.time())) -> None:
        root = Path(state_root).resolve(strict=True)
        metadata = root.lstat()
        if root.is_symlink() or not root.is_dir() or stat.S_IMODE(metadata.st_mode) != 0o700 or len(key) < 32:
            raise ValueError("documentation snapshot state is invalid")
        snapshots = root / "documentation-snapshots"
        snapshots.mkdir(mode=0o700, exist_ok=True)
        if snapshots.is_symlink() or stat.S_IMODE(snapshots.stat().st_mode) != 0o700:
            raise ValueError("documentation snapshot directory is invalid")
        self.root, self.key, self.clock = snapshots, bytes(key), clock

    def capture(
        self, document_id: str, source: SnapshotSource, content: str, classification: str,
        trace_id: str, principal_id: str, mcp_receipt_digest: str, *, ttl_seconds: int = 900,
    ) -> SnapshotReceipt:
        if any(not _ID.fullmatch(value) for value in (document_id, trace_id, principal_id)):
            raise ValueError("documentation snapshot identity is invalid")
        raw = content.encode("utf-8")
        if (
            classification not in _CLASSIFICATIONS or not 1 <= len(raw) <= _MAX_CONTENT_BYTES
            or _UNSAFE.search(content) or not _DIGEST.fullmatch(mcp_receipt_digest)
            or not 60 <= ttl_seconds <= 3600
        ):
            raise ValueError("documentation snapshot content or policy is invalid")
        if inspect_text(content).outcome != "allow":
            raise ValueError("documentation snapshot contains sensitive data")
        captured_at = self.clock()
        content_digest = _digest(raw)
        snapshot_id = hashlib.sha256(
            _canonical([document_id, source.space_key, source.page_id, source.page_version, content_digest, trace_id])
        ).hexdigest()[:32]
        unsigned = {
            "schema_version": "1.0", "snapshot_id": snapshot_id, "document_id": document_id,
            "principal_id": principal_id, "trace_id": trace_id,
            "source": {"space_key": source.space_key, "page_id": source.page_id, "page_version": source.page_version},
            "classification": classification, "content": content, "content_digest": content_digest,
            "mcp_receipt_digest": mcp_receipt_digest, "captured_at": captured_at,
            "expires_at": captured_at + ttl_seconds, "content_trust": "untrusted_external_data",
            "instruction_authority": False,
        }
        signature = hmac.new(self.key, _canonical(unsigned), hashlib.sha256).hexdigest()
        payload = {**unsigned, "attestation": "hmac-sha256:" + signature}
        encoded = _canonical(payload)
        path = self.root / f"{snapshot_id}.json"
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
        return SnapshotReceipt(snapshot_id, _digest(encoded), content_digest, source, captured_at + ttl_seconds)

    def load(
        self, snapshot_id: str, snapshot_digest: str, document_id: str, principal_id: str,
    ) -> DocumentationSnapshot:
        if not re.fullmatch(r"[0-9a-f]{32}", snapshot_id) or not _DIGEST.fullmatch(snapshot_digest):
            raise ValueError("documentation snapshot reference is invalid")
        path = self.root / f"{snapshot_id}.json"
        raw = _read_private_file(path, max_bytes=_MAX_CONTENT_BYTES + 20_000)
        if _digest(raw) != snapshot_digest:
            raise PermissionError("documentation snapshot digest mismatch")
        payload = _strict_json(raw)
        if not isinstance(payload, dict):
            raise PermissionError("documentation snapshot payload is invalid")
        if set(payload) != _SNAPSHOT_FIELDS:
            raise PermissionError("documentation snapshot payload is invalid")
        attestation = payload.pop("attestation", "")
        expected = "hmac-sha256:" + hmac.new(self.key, _canonical(payload), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(attestation, expected):
            raise PermissionError("documentation snapshot attestation failed")
        source = payload.get("source")
        if (
            payload.get("snapshot_id") != snapshot_id or payload.get("document_id") != document_id
            or payload.get("principal_id") != principal_id or self.clock() > payload.get("expires_at", 0)
            or payload.get("instruction_authority") is not False or payload.get("classification") not in _CLASSIFICATIONS
            or payload.get("content_trust") != "untrusted_external_data"
            or not isinstance(payload.get("content"), str)
            or inspect_text(str(payload.get("content"))).outcome != "allow"
            or _digest(str(payload.get("content")).encode("utf-8")) != payload.get("content_digest")
            or not _DIGEST.fullmatch(str(payload.get("mcp_receipt_digest")))
            or not isinstance(source, dict) or set(source) != _SOURCE_FIELDS
        ):
            raise PermissionError("documentation snapshot scope or TTL mismatch")
        return DocumentationSnapshot(
            snapshot_id, document_id, principal_id,
            SnapshotSource(source["space_key"], source["page_id"], source["page_version"]),
            payload["classification"], payload["content"], payload["content_digest"],
            payload["mcp_receipt_digest"], False,
        )

    def reserve(self, snapshot_id: str, snapshot_digest: str, principal_id: str) -> None:
        """Creates a durable one-time reservation before any repository mutation."""

        if not re.fullmatch(r"[0-9a-f]{32}", snapshot_id) or not _DIGEST.fullmatch(snapshot_digest):
            raise ValueError("documentation snapshot reference is invalid")
        if not _ID.fullmatch(principal_id):
            raise ValueError("documentation snapshot principal is invalid")
        consumed = self.root / f"{snapshot_id}.consumed.json"
        reservation = self.root / f"{snapshot_id}.reserved.json"
        if consumed.exists():
            raise PermissionError("documentation snapshot was already consumed")
        payload = _canonical({
            "schema_version": "1.0", "snapshot_id": snapshot_id, "snapshot_digest": snapshot_digest,
            "principal_id": principal_id, "reserved_at": self.clock(),
        })
        try:
            descriptor = os.open(
                reservation, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600,
            )
        except FileExistsError as error:
            raise PermissionError("documentation snapshot is already reserved") from error
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())

    def release(self, snapshot_id: str) -> None:
        reservation = self.root / f"{snapshot_id}.reserved.json"
        try:
            reservation.unlink()
        except FileNotFoundError:
            pass

    def consume(self, snapshot_id: str, snapshot_digest: str, principal_id: str) -> None:
        reservation = self.root / f"{snapshot_id}.reserved.json"
        consumed = self.root / f"{snapshot_id}.consumed.json"
        try:
            payload = _strict_json(_read_private_file(reservation, max_bytes=1_024))
        except (OSError, ValueError, json.JSONDecodeError) as error:
            raise PermissionError("documentation snapshot reservation is invalid") from error
        expected = {
            "schema_version": "1.0", "snapshot_id": snapshot_id, "snapshot_digest": snapshot_digest,
            "principal_id": principal_id,
        }
        if (
            not isinstance(payload, dict) or set(payload) != _RESERVATION_FIELDS
            or any(payload.get(key) != value for key, value in expected.items())
        ):
            raise PermissionError("documentation snapshot reservation scope mismatch")
        os.replace(reservation, consumed)
        (self.root / f"{snapshot_id}.json").unlink(missing_ok=True)


def configured_source(repository: Path, document_id: str) -> tuple[SnapshotSource, str, str]:
    """Loads one closed external-source binding from repository config."""

    path = Path(repository).resolve(strict=True) / "config" / "docs-external-sources.json"
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 100_000:
        raise ValueError("external documentation config is invalid")
    payload = _strict_json(path.read_bytes())
    if set(payload) != {"schema_version", "sources"} or payload["schema_version"] != "1.0":
        raise ValueError("external documentation config fields mismatch")
    sources = payload["sources"]
    if not isinstance(sources, list):
        raise ValueError("external documentation sources are invalid")
    matches = [item for item in sources if isinstance(item, dict) and item.get("document_id") == document_id]
    if len(matches) != 1 or set(matches[0]) != {
        "document_id", "space_key", "page_id", "classification", "generated_section",
    }:
        raise ValueError("external documentation source is unknown")
    item = matches[0]
    if item["classification"] not in _CLASSIFICATIONS:
        raise ValueError("external documentation classification is invalid")
    if not _ID.fullmatch(item["generated_section"]):
        raise ValueError("external documentation section is invalid")
    return SnapshotSource(item["space_key"], item["page_id"], 0), item["classification"], item["generated_section"]


def render_snapshot_section(document: str, section: str, snapshot: DocumentationSnapshot) -> str:
    """Replaces one exact generated block with inert snapshot text and digest metadata."""

    begin, end = f"<!-- PF:GENERATED {section} BEGIN -->", f"<!-- PF:GENERATED {section} END -->"
    if document.count(begin) != 1 or document.count(end) != 1 or document.index(begin) > document.index(end):
        raise ValueError("external documentation generated markers are invalid")
    metadata = {
        "snapshot_id": snapshot.snapshot_id, "content_digest": snapshot.content_digest,
        "space_key": snapshot.source.space_key, "page_id": snapshot.source.page_id,
        "page_version": snapshot.source.page_version, "content_trust": "untrusted_external_data",
        "instruction_authority": False,
    }
    body = (
        f"{begin}\n<!-- PF:EXTERNAL-SNAPSHOT {_canonical(metadata).decode('utf-8')} -->\n\n"
        f"## External reference snapshot\n\n{_inert_markdown(snapshot.content)}\n{end}"
    )
    before, remainder = document.split(begin, 1)
    _, after = remainder.split(end, 1)
    return before + body + after
