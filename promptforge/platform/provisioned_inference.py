"""Exact pre-exec identity checks for an externally provisioned local inference runtime."""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import time
from typing import Callable


_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_MAX_ARTIFACT_BYTES = 100_000_000_000


def _identity(path: Path, expected_digest: str, *, executable: bool) -> tuple[int, int]:
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError as error:
        raise PermissionError("provisioned runtime file is unavailable") from error
    digest = hashlib.sha256()
    with os.fdopen(descriptor, "rb") as stream:
        metadata = os.fstat(stream.fileno())
        mode = stat.S_IMODE(metadata.st_mode)
        if (
            not stat.S_ISREG(metadata.st_mode) or metadata.st_size > _MAX_ARTIFACT_BYTES
            or mode & 0o022 or (executable and not mode & 0o100) or (not executable and mode & 0o111)
        ):
            raise PermissionError("provisioned runtime file permissions are invalid")
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    if digest.hexdigest() != expected_digest:
        raise PermissionError("provisioned runtime digest mismatch")
    return metadata.st_dev, metadata.st_ino


@dataclass(frozen=True)
class ProvisionedRuntimeBinding:
    executable_path: Path
    artifact_path: Path
    executable_sha256: str
    artifact_sha256: str
    model_id: str
    revision: str
    protocol: str

    def __post_init__(self) -> None:
        executable, artifact = Path(self.executable_path), Path(self.artifact_path)
        if (
            not executable.is_absolute() or not artifact.is_absolute() or executable == artifact
            or not _DIGEST.fullmatch(self.executable_sha256) or not _DIGEST.fullmatch(self.artifact_sha256)
            or any(not _ID.fullmatch(value) for value in (self.model_id, self.revision, self.protocol))
            or self.protocol != "stdio-json-v1"
        ):
            raise ValueError("provisioned runtime binding is invalid")
        for path, executable_flag in ((executable, True), (artifact, False)):
            metadata = path.lstat()
            mode = stat.S_IMODE(metadata.st_mode)
            if path.is_symlink() or not path.is_file() or mode & 0o022 or (executable_flag and not mode & 0o100):
                raise ValueError("provisioned runtime path or mode is invalid")
        object.__setattr__(self, "executable_path", executable)
        object.__setattr__(self, "artifact_path", artifact)


@dataclass(frozen=True)
class ProvisionedReadinessReceipt:
    status: str
    model_id: str
    revision: str
    protocol: str
    executable_sha256: str
    artifact_sha256: str
    checked_at: int
    executed: bool = False
    network_used: bool = False

    def to_payload(self) -> dict[str, object]:
        return {"schema_version": "1.0", **self.__dict__}


@dataclass(frozen=True)
class ProvisionedRuntimeVerifier:
    binding: ProvisionedRuntimeBinding
    clock: Callable[[], float] = field(default=time.time, repr=False, compare=False)

    def readiness(self) -> ProvisionedReadinessReceipt:
        _identity(self.binding.executable_path, self.binding.executable_sha256, executable=True)
        _identity(self.binding.artifact_path, self.binding.artifact_sha256, executable=False)
        return ProvisionedReadinessReceipt(
            "ready", self.binding.model_id, self.binding.revision, self.binding.protocol,
            self.binding.executable_sha256, self.binding.artifact_sha256, int(self.clock()),
        )


@dataclass(frozen=True)
class ProvisionedInvocationReceipt:
    status: str
    trace_id: str
    model_id: str
    revision: str
    protocol: str
    executable_sha256: str
    artifact_sha256: str
    response_digest: str
    input_tokens: int
    output_tokens: int
    network_used: bool = False

    def to_payload(self) -> dict[str, object]:
        return {"schema_version": "1.0", **self.__dict__}


@dataclass(frozen=True)
class ProvisionedRuntimeInvoker:
    binding: ProvisionedRuntimeBinding
    state_root: Path
    timeout_seconds: int = 60
    max_output_bytes: int = 100_000

    def __post_init__(self) -> None:
        root = Path(self.state_root).resolve(strict=True)
        if root.is_symlink() or not root.is_dir() or stat.S_IMODE(root.stat().st_mode) != 0o700:
            raise ValueError("provisioned runtime state must be owner-private")
        if not 1 <= self.timeout_seconds <= 300 or not 1 <= self.max_output_bytes <= 10_000_000:
            raise ValueError("provisioned runtime limits are invalid")
        object.__setattr__(self, "state_root", root)

    def invoke(self, trace_id: str, content: str, max_output_tokens: int) -> tuple[str, ProvisionedInvocationReceipt]:
        if not _ID.fullmatch(trace_id) or not isinstance(content, str) or not content or len(content) > 1_000_000:
            raise ValueError("provisioned inference request is invalid")
        if not isinstance(max_output_tokens, int) or isinstance(max_output_tokens, bool) or not 1 <= max_output_tokens <= 8192:
            raise ValueError("provisioned inference output budget is invalid")
        before = (
            _identity(self.binding.executable_path, self.binding.executable_sha256, executable=True),
            _identity(self.binding.artifact_path, self.binding.artifact_sha256, executable=False),
        )
        request = json.dumps({
            "schema_version": "1.0", "trace_id": trace_id, "model_id": self.binding.model_id,
            "revision": self.binding.revision, "protocol": self.binding.protocol, "content": content,
            "max_output_tokens": max_output_tokens, "artifact_path": str(self.binding.artifact_path),
        }, separators=(",", ":")).encode("utf-8")
        try:
            process = subprocess.run(
                [str(self.binding.executable_path)], input=request, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                cwd=self.state_root, env={"PATH": "/usr/bin:/bin"}, check=False, timeout=self.timeout_seconds,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise RuntimeError("provisioned inference execution failed") from error
        after = (
            _identity(self.binding.executable_path, self.binding.executable_sha256, executable=True),
            _identity(self.binding.artifact_path, self.binding.artifact_sha256, executable=False),
        )
        if before != after or process.returncode != 0 or len(process.stdout) > self.max_output_bytes:
            raise RuntimeError("provisioned inference identity or output failed")
        try:
            payload = json.loads(process.stdout, object_pairs_hook=_unique_object)
        except (UnicodeError, json.JSONDecodeError) as error:
            raise RuntimeError("provisioned inference response is invalid") from error
        required = {
            "trace_id", "model_id", "revision", "protocol", "content", "input_tokens", "output_tokens",
        }
        if not isinstance(payload, dict) or set(payload) != required or any(
            payload[name] != value for name, value in (
                ("trace_id", trace_id), ("model_id", self.binding.model_id),
                ("revision", self.binding.revision), ("protocol", self.binding.protocol),
            )
        ):
            raise RuntimeError("provisioned inference response identity mismatch")
        output = payload["content"]
        token_values = (payload["input_tokens"], payload["output_tokens"])
        if (
            not isinstance(output, str) or not output or len(output.encode("utf-8")) > self.max_output_bytes
            or any(not isinstance(value, int) or isinstance(value, bool) or value < 0 for value in token_values)
            or payload["output_tokens"] > max_output_tokens
        ):
            raise RuntimeError("provisioned inference response budget is invalid")
        receipt = ProvisionedInvocationReceipt(
            "completed", trace_id, self.binding.model_id, self.binding.revision, self.binding.protocol,
            self.binding.executable_sha256, self.binding.artifact_sha256,
            hashlib.sha256(output.encode("utf-8")).hexdigest(), payload["input_tokens"], payload["output_tokens"],
        )
        return output, receipt


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON field")
        result = {**result, key: value}
    return result
