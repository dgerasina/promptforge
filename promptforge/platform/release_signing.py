"""Owner-controlled detached signatures for accepted release-candidate manifests."""

from __future__ import annotations

import base64
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tempfile
from time import time
from typing import Mapping

from promptforge.platform.skill_signatures import SkillSigningKeyRegistry


_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_B64 = re.compile(r"^[A-Za-z0-9+/]{80,120}={0,2}$")
_OPENSSL = shutil.which("openssl")
_MAX_LIFETIME_SECONDS = 14 * 24 * 60 * 60
_MANIFEST_FIELDS = frozenset({
    "schema_version", "status", "reason_codes", "source_digest", "release_scope", "gates", "skills", "agents",
    "final_evidence_status", "assurance_scope", "known_limitations", "release_digest", "network_used",
    "gate_config_digest", "portability_digest", "product_version", "spec_version", "evidence",
})


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def _manifest_digest(manifest: Mapping[str, object]) -> str:
    return "sha256:" + hashlib.sha256(_canonical(dict(manifest))).hexdigest()


def _validate_manifest(manifest: Mapping[str, object]) -> None:
    if not isinstance(manifest, Mapping):
        raise ValueError("only an accepted release manifest can be signed")
    unsigned = {key: value for key, value in manifest.items() if key != "release_digest"}
    expected_release_digest = "sha256:" + hashlib.sha256(_canonical(unsigned)).hexdigest()
    if (
        set(manifest) != _MANIFEST_FIELDS
        or manifest.get("schema_version") != "1.0"
        or manifest.get("status") != "accepted"
        or manifest.get("reason_codes") != []
        or manifest.get("final_evidence_status") != "passed"
        or manifest.get("network_used") is not False
        or not _DIGEST.fullmatch(str(manifest.get("source_digest", "")))
        or not _DIGEST.fullmatch(str(manifest.get("release_digest", "")))
        or not hmac_compare(str(manifest.get("release_digest", "")), expected_release_digest)
    ):
        raise ValueError("only an accepted release manifest can be signed")


def hmac_compare(left: str, right: str) -> bool:
    """Uses constant-time comparison for integrity identifiers."""

    import hmac
    return hmac.compare_digest(left, right)


def _run(command: list[str]) -> subprocess.CompletedProcess[bytes]:
    if _OPENSSL is None:
        raise RuntimeError("release signature backend unavailable")
    try:
        return subprocess.run(
            [_OPENSSL, *command], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            timeout=10, check=False, env={"PATH": os.environ.get("PATH", "")},
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise RuntimeError("release signature backend unavailable") from error


def _private_existing_directory(path: Path) -> Path:
    supplied = Path(path).absolute()
    current = Path(supplied.anchor)
    for part in supplied.parts[1:]:
        current = current / part
        if current.is_symlink():
            raise ValueError("owner-private path must not contain symlinks")
    directory = supplied.resolve(strict=True)
    metadata = directory.lstat()
    owner_ok = not hasattr(os, "getuid") or metadata.st_uid == os.getuid()
    if not directory.is_dir() or stat.S_IMODE(metadata.st_mode) & 0o077 or not owner_ok:
        raise ValueError("owner-private directory is invalid")
    return directory


@dataclass(frozen=True)
class DetachedReleaseSignature:
    """Detached Ed25519 envelope bound to the full canonical RC manifest."""

    manifest_digest: str
    source_digest: str
    signer_id: str
    key_id: str
    issued_at: int
    expires_at: int
    signature: str
    algorithm: str = "ed25519-openssl-v1"

    def __post_init__(self) -> None:
        if (
            not _DIGEST.fullmatch(self.manifest_digest) or not _DIGEST.fullmatch(self.source_digest)
            or self.signer_id != "owner-local" or not _ID.fullmatch(self.key_id)
            or self.algorithm != "ed25519-openssl-v1" or not _B64.fullmatch(self.signature)
            or isinstance(self.issued_at, bool) or not isinstance(self.issued_at, int)
            or isinstance(self.expires_at, bool) or not isinstance(self.expires_at, int)
            or not self.issued_at < self.expires_at <= self.issued_at + _MAX_LIFETIME_SECONDS
        ):
            raise ValueError("detached release signature is invalid")

    def unsigned_payload(self) -> dict[str, object]:
        return {
            "schema_version": "1.0", "manifest_digest": self.manifest_digest,
            "source_digest": self.source_digest, "signer_id": self.signer_id, "key_id": self.key_id,
            "algorithm": self.algorithm, "issued_at": self.issued_at, "expires_at": self.expires_at,
        }

    def to_payload(self) -> dict[str, object]:
        return {**self.unsigned_payload(), "signature": self.signature}

    @classmethod
    def from_payload(cls, payload: Mapping[str, object]) -> "DetachedReleaseSignature":
        expected = {
            "schema_version", "manifest_digest", "source_digest", "signer_id", "key_id", "algorithm",
            "issued_at", "expires_at", "signature",
        }
        if not isinstance(payload, Mapping) or set(payload) != expected or payload.get("schema_version") != "1.0":
            raise ValueError("detached release signature fields mismatch")
        return cls(
            str(payload["manifest_digest"]), str(payload["source_digest"]), str(payload["signer_id"]),
            str(payload["key_id"]), payload["issued_at"], payload["expires_at"], str(payload["signature"]),
            str(payload["algorithm"]),
        )


def generate_owner_keypair(private_key: Path, public_key: Path) -> None:
    """Creates a new external owner keypair without overwriting existing files."""

    private, public = Path(private_key).absolute(), Path(public_key).absolute()
    if private == public or private.exists() or public.exists() or private.parent != public.parent:
        raise ValueError("owner key paths must be new sibling files")
    parent = _private_existing_directory(private.parent)
    result = _run(["genpkey", "-algorithm", "ED25519", "-out", str(private)])
    if result.returncode != 0:
        private.unlink(missing_ok=True)
        raise RuntimeError("owner private key generation failed")
    os.chmod(private, 0o600)
    result = _run(["pkey", "-in", str(private), "-pubout", "-out", str(public)])
    if result.returncode != 0:
        private.unlink(missing_ok=True)
        raise RuntimeError("owner public key generation failed")
    os.chmod(public, 0o644)


def sign_release_candidate(
    manifest: Mapping[str, object], signer_id: str, key_id: str, private_key: Path,
    registry: SkillSigningKeyRegistry, *, issued_at: int | None = None, expires_at: int | None = None,
) -> DetachedReleaseSignature:
    """Signs an accepted manifest with the exact active owner key."""

    _validate_manifest(manifest)
    if signer_id != "owner-local":
        raise PermissionError("release candidate signing requires owner")
    registry.require_active(key_id, signer_id)
    supplied_key = Path(private_key).absolute()
    if supplied_key.is_symlink():
        raise ValueError("private signing key must not be a symlink")
    key = supplied_key.resolve(strict=True)
    metadata = key.lstat()
    owner_ok = not hasattr(os, "getuid") or metadata.st_uid == os.getuid()
    if key.is_symlink() or not key.is_file() or stat.S_IMODE(metadata.st_mode) != 0o600 or not owner_ok:
        raise ValueError("private signing key must be owner-private")
    issued = int(time()) if issued_at is None else issued_at
    expires = issued + _MAX_LIFETIME_SECONDS if expires_at is None else expires_at
    unsigned = {
        "schema_version": "1.0", "manifest_digest": _manifest_digest(manifest),
        "source_digest": manifest["source_digest"], "signer_id": signer_id, "key_id": key_id,
        "algorithm": "ed25519-openssl-v1", "issued_at": issued, "expires_at": expires,
    }
    with tempfile.TemporaryDirectory() as directory:
        message = Path(directory) / "message"
        message.write_bytes(_canonical(unsigned))
        result = _run(["pkeyutl", "-sign", "-rawin", "-inkey", str(key), "-in", str(message)])
    if result.returncode != 0 or len(result.stdout) != 64:
        raise RuntimeError("release candidate signing failed")
    signature = DetachedReleaseSignature(
        unsigned["manifest_digest"], unsigned["source_digest"], signer_id, key_id, issued, expires,
        base64.b64encode(result.stdout).decode("ascii"),
    )
    if not verify_release_candidate(manifest, signature, registry, at_time=issued):
        raise PermissionError("private signing key does not match registered owner key")
    return signature


def verify_release_candidate(
    manifest: Mapping[str, object], signature: DetachedReleaseSignature, registry: SkillSigningKeyRegistry,
    *, at_time: int | None = None,
) -> bool:
    """Verifies manifest binding, owner/key policy, lifetime and Ed25519 signature offline."""

    now = int(time()) if at_time is None else at_time
    try:
        _validate_manifest(manifest)
        policy = registry.require_active(signature.key_id, signature.signer_id)
        raw = base64.b64decode(signature.signature, validate=True)
    except (PermissionError, ValueError):
        return False
    if (
        signature.signer_id != "owner-local" or signature.manifest_digest != _manifest_digest(manifest)
        or signature.source_digest != manifest["source_digest"]
        or not signature.issued_at <= now <= signature.expires_at
    ):
        return False
    with tempfile.TemporaryDirectory() as directory:
        message, detached = Path(directory) / "message", Path(directory) / "signature"
        message.write_bytes(_canonical(signature.unsigned_payload()))
        detached.write_bytes(raw)
        result = _run([
            "pkeyutl", "-verify", "-rawin", "-pubin", "-inkey", str(policy.public_key),
            "-sigfile", str(detached), "-in", str(message),
        ])
    return result.returncode == 0


def load_json_object(path: Path, *, max_bytes: int = 1_000_000) -> dict[str, object]:
    """Loads one bounded regular JSON object without following the final symlink."""

    source = Path(path).absolute()
    _private_existing_directory(source.parent)
    descriptor = -1
    try:
        descriptor = os.open(source, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or not 0 < metadata.st_size <= max_bytes:
            raise ValueError("release artifact must be a bounded regular file")
        with os.fdopen(descriptor, "r", encoding="utf-8") as stream:
            descriptor = -1
            payload = json.load(stream, object_pairs_hook=_unique_object)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ValueError("release artifact is invalid") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if not isinstance(payload, dict):
        raise ValueError("release artifact must be an object")
    return payload


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate release artifact field")
        result = {**result, key: value}
    return result


def write_private_json(path: Path, payload: Mapping[str, object]) -> None:
    """Atomically creates a new owner-private JSON artifact without overwrite."""

    target = Path(path).absolute()
    parent = _private_existing_directory(target.parent)
    if target.exists() or target.is_symlink():
        raise ValueError("release artifact target must be new in an owner-private directory")
    descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            descriptor = -1
            json.dump(dict(payload), stream, sort_keys=True, separators=(",", ":"))
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        if descriptor >= 0:
            os.close(descriptor)
