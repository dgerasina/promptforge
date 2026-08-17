"""Detached Ed25519 release signatures verified through a bounded local OpenSSL process."""

from __future__ import annotations

from dataclasses import dataclass
import base64
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tempfile
from typing import Mapping


_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_VERSION = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_B64 = re.compile(r"^[A-Za-z0-9+/]{80,120}={0,2}$")
_OPENSSL = shutil.which("openssl")


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


@dataclass(frozen=True)
class SigningKeyPolicy:
    key_id: str
    signer_id: str
    status: str
    public_key: Path


@dataclass(frozen=True)
class SkillSigningKeyRegistry:
    policies: tuple[SigningKeyPolicy | Mapping[str, object], ...]

    def __post_init__(self) -> None:
        converted = tuple(
            item if isinstance(item, SigningKeyPolicy) else SigningKeyPolicy(
                str(item.get("key_id", "")), str(item.get("signer_id", "")), str(item.get("status", "")),
                Path(str(item.get("public_key", ""))),
            ) for item in self.policies
        )
        if len({item.key_id for item in converted}) != len(converted):
            raise ValueError("skill signing key registry contains duplicates")
        for item in converted:
            if (
                not _ID.fullmatch(item.key_id) or item.signer_id not in {"owner-local", "maintainer-local"}
                or item.status not in {"active", "revoked"}
            ):
                raise ValueError("skill signing key policy is invalid")
            key = item.public_key.resolve(strict=True)
            if key.is_symlink() or not key.is_file() or key.stat().st_size > 8_192:
                raise ValueError("skill public key file is invalid")
            content = key.read_text(encoding="ascii")
            if "BEGIN PUBLIC KEY" not in content or "PRIVATE KEY" in content:
                raise ValueError("skill public key is not a public Ed25519 key")
            object.__setattr__(item, "public_key", key)
        object.__setattr__(self, "policies", converted)

    def require_active(self, key_id: str, signer_id: str) -> SigningKeyPolicy:
        policy = next((item for item in self.policies if item.key_id == key_id), None)
        if policy is None or policy.status != "active" or policy.signer_id != signer_id:
            raise PermissionError("skill signing key is not active for signer")
        return policy

    @classmethod
    def from_file(cls, path: Path) -> "SkillSigningKeyRegistry":
        source = Path(path).resolve(strict=True)
        if source.is_symlink() or not source.is_file() or source.stat().st_size > 100_000:
            raise ValueError("skill signing registry file is invalid")
        payload = json.loads(source.read_bytes(), object_pairs_hook=_unique_object)
        if set(payload) != {"schema_version", "keys"} or payload["schema_version"] != "1.0":
            raise ValueError("skill signing registry fields mismatch")
        keys = payload["keys"]
        if not isinstance(keys, list) or not keys:
            raise ValueError("skill signing registry is empty")
        policies = []
        for item in keys:
            if not isinstance(item, dict) or set(item) != {"key_id", "signer_id", "status", "public_key"}:
                raise ValueError("skill signing key fields mismatch")
            relative = Path(str(item["public_key"]))
            public_key = (source.parent / relative).resolve(strict=True)
            if relative.is_absolute() or not public_key.is_relative_to(source.parent):
                raise ValueError("skill signing public key escapes config")
            policies.append({**item, "public_key": public_key})
        return cls(tuple(policies))


@dataclass(frozen=True)
class DetachedSkillSignature:
    skill_id: str
    version: str
    release_digest: str
    signer_id: str
    key_id: str
    algorithm: str
    signature: str

    def __post_init__(self) -> None:
        if (
            not _ID.fullmatch(self.skill_id) or not _VERSION.fullmatch(self.version)
            or not _DIGEST.fullmatch(self.release_digest) or self.signer_id not in {"owner-local", "maintainer-local"}
            or not _ID.fullmatch(self.key_id) or self.algorithm != "ed25519-openssl-v1"
            or not _B64.fullmatch(self.signature)
        ):
            raise ValueError("detached skill signature is invalid")

    def unsigned_payload(self) -> dict[str, str]:
        return {
            "schema_version": "1.0", "skill_id": self.skill_id, "version": self.version,
            "release_digest": self.release_digest, "signer_id": self.signer_id,
            "key_id": self.key_id, "algorithm": self.algorithm,
        }

    def to_payload(self) -> dict[str, str]:
        return {**self.unsigned_payload(), "signature": self.signature}


def _run(command: list[str]) -> subprocess.CompletedProcess[bytes]:
    if _OPENSSL is None or command[0] != "openssl":
        raise RuntimeError("skill signature backend unavailable")
    command = [_OPENSSL, *command[1:]]
    try:
        return subprocess.run(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                              check=False, timeout=10, env={"PATH": os.environ.get("PATH", "")})
    except (OSError, subprocess.TimeoutExpired) as error:
        raise RuntimeError("skill signature backend unavailable") from error


def sign_release_digest(
    skill_id: str, version: str, release_digest: str, signer_id: str, key_id: str,
    private_key: Path, registry: SkillSigningKeyRegistry,
) -> DetachedSkillSignature:
    registry.require_active(key_id, signer_id)
    key = Path(private_key).resolve(strict=True)
    metadata = key.lstat()
    if key.is_symlink() or not key.is_file() or stat.S_IMODE(metadata.st_mode) != 0o600:
        raise ValueError("private signing key must be owner-private")
    unsigned = {
        "schema_version": "1.0", "skill_id": skill_id, "version": version,
        "release_digest": release_digest, "signer_id": signer_id, "key_id": key_id,
        "algorithm": "ed25519-openssl-v1",
    }
    with tempfile.TemporaryDirectory() as directory:
        message = Path(directory) / "message"
        message.write_bytes(_canonical(unsigned))
        result = _run(["openssl", "pkeyutl", "-sign", "-rawin", "-inkey", str(key), "-in", str(message)])
    if result.returncode != 0 or len(result.stdout) != 64:
        raise RuntimeError("skill release signing failed")
    return DetachedSkillSignature(
        skill_id, version, release_digest, signer_id, key_id, "ed25519-openssl-v1",
        base64.b64encode(result.stdout).decode("ascii"),
    )


def verify_release_signature(signature: DetachedSkillSignature, registry: SkillSigningKeyRegistry) -> bool:
    try:
        policy = registry.require_active(signature.key_id, signature.signer_id)
        raw = base64.b64decode(signature.signature, validate=True)
    except (PermissionError, ValueError):
        return False
    with tempfile.TemporaryDirectory() as directory:
        message, detached = Path(directory) / "message", Path(directory) / "signature"
        message.write_bytes(_canonical(signature.unsigned_payload()))
        detached.write_bytes(raw)
        result = _run([
            "openssl", "pkeyutl", "-verify", "-rawin", "-pubin", "-inkey", str(policy.public_key),
            "-sigfile", str(detached), "-in", str(message),
        ])
    return result.returncode == 0


def load_detached_signatures(path: Path) -> tuple[DetachedSkillSignature, ...]:
    source = Path(path).resolve(strict=True)
    if source.is_symlink() or not source.is_file() or source.stat().st_size > 1_000_000:
        raise ValueError("detached signature registry is invalid")
    payload = json.loads(source.read_bytes(), object_pairs_hook=_unique_object)
    if set(payload) != {"schema_version", "signatures"} or payload["schema_version"] != "1.0":
        raise ValueError("detached signature registry fields mismatch")
    signatures = payload["signatures"]
    if not isinstance(signatures, list):
        raise ValueError("detached signatures must be a list")
    parsed = tuple(DetachedSkillSignature(
        item["skill_id"], item["version"], item["release_digest"], item["signer_id"], item["key_id"],
        item["algorithm"], item["signature"],
    ) for item in signatures if isinstance(item, dict) and set(item) == {
        "skill_id", "version", "release_digest", "signer_id", "key_id", "algorithm", "signature",
    })
    if len(parsed) != len(signatures) or len({(item.skill_id, item.version) for item in parsed}) != len(parsed):
        raise ValueError("detached signature registry contains invalid or duplicate records")
    return parsed


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result = {**result, key: value}
    return result
