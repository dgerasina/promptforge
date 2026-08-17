"""Repository-only kill switch и безопасная очистка локального runtime state."""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import stat
import tempfile
import time
from typing import Callable, Mapping

from promptforge.platform.contracts import Principal, SCHEMA_VERSION
from promptforge.platform.governance import GovernancePolicy


_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_STATE_FILE = "kill-switch.json"
_ANCHOR_FILE = "kill-switch.anchor.json"
_CONFIRMATION = "PURGE promptforge"


def _strict_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON field: {key}")
        result = {**result, key: value}
    return result


def _private_root(value: Path) -> Path:
    root = Path(value)
    if not root.is_absolute() or not root.is_dir() or root.is_symlink() or root.resolve() != root:
        raise ValueError("operations state root must be an absolute regular directory")
    metadata = root.lstat()
    owner_ok = not hasattr(os, "getuid") or metadata.st_uid == os.getuid()
    if stat.S_IMODE(metadata.st_mode) != 0o700 or not owner_ok:
        raise ValueError("operations state root must be owner-private")
    return root


def _safe_text(value: object, name: str) -> str:
    if not isinstance(value, str) or not _SAFE_ID.fullmatch(value):
        raise ValueError(f"operations {name} is invalid")
    return value


@dataclass(frozen=True)
class OperationsConfig:
    """Определяет только явно разрешённые state filenames и retention."""

    ephemeral_targets: tuple[str, ...]
    protected_targets: tuple[str, ...]
    debug_retention_days: int
    placeholder_max_hours: int

    def __post_init__(self) -> None:
        targets = (*self.ephemeral_targets, *self.protected_targets)
        if (
            not self.ephemeral_targets or not self.protected_targets or len(set(targets)) != len(targets)
            or any(not re.fullmatch(r"[a-z][a-z0-9-]*\.sqlite3", item) for item in targets)
        ):
            raise ValueError("operations cleanup targets are invalid")
        limits = (self.debug_retention_days, self.placeholder_max_hours)
        if any(isinstance(value, bool) or not isinstance(value, int) or value <= 0 for value in limits):
            raise ValueError("operations retention limits are invalid")

    @classmethod
    def from_repository(cls, repository: Path) -> OperationsConfig:
        root = Path(repository).resolve(strict=True)
        path = root / "config" / "operations.json"
        if path.is_symlink() or not path.is_file() or path.resolve() != path:
            raise ValueError("operations config must be a regular repository file")
        try:
            payload = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_strict_object)
        except (OSError, UnicodeError, json.JSONDecodeError) as error:
            raise ValueError("operations config is invalid") from error
        if not isinstance(payload, Mapping) or set(payload) != {
            "schema_version", "ephemeral_targets", "protected_targets", "retention",
        }:
            raise ValueError("operations config fields mismatch")
        retention = payload["retention"]
        if (
            payload["schema_version"] != SCHEMA_VERSION or not isinstance(retention, Mapping)
            or set(retention) != {"debug_days", "placeholder_max_hours"}
        ):
            raise ValueError("operations config version or retention is invalid")
        return cls(
            tuple(payload["ephemeral_targets"]), tuple(payload["protected_targets"]),
            retention["debug_days"], retention["placeholder_max_hours"],
        )


@dataclass(frozen=True)
class KillSwitchState:
    engaged: bool
    generation: int
    changed_by: str
    reason_code: str
    changed_at: int
    attestation: str

    def to_payload(self) -> dict[str, object]:
        return {"schema_version": SCHEMA_VERSION, **self.__dict__}


@dataclass(frozen=True)
class LocalKillSwitch:
    """Хранит HMAC-attested emergency state в owner-private local state."""

    state_root: Path
    key: bytes = field(repr=False, compare=False)
    clock: Callable[[], float] = field(default=time.time, repr=False, compare=False)

    def __post_init__(self) -> None:
        root = _private_root(self.state_root)
        if not isinstance(self.key, bytes) or len(self.key) < 32:
            raise ValueError("operations key must contain at least 32 bytes")
        object.__setattr__(self, "state_root", root)
        path = root / _STATE_FILE
        anchor = root / _ANCHOR_FILE
        if path.exists() or path.is_symlink() or anchor.exists() or anchor.is_symlink():
            self._validate_file(path)
            self._validate_file(anchor)
            self.status()
        else:
            initial = self._signed(False, 0, "system", "initialized", int(self.clock()))
            self._write_state(initial)
            self._write_anchor(initial)

    @property
    def path(self) -> Path:
        return self.state_root / _STATE_FILE

    @property
    def anchor_path(self) -> Path:
        return self.state_root / _ANCHOR_FILE

    def status(self) -> KillSwitchState:
        """Проверяет exact state shape и HMAC; ошибка всегда fail closed для builder."""

        self._validate_file(self.path)
        try:
            payload = json.loads(self.path.read_text(encoding="utf-8"), object_pairs_hook=_strict_object)
        except (OSError, UnicodeError, json.JSONDecodeError) as error:
            raise RuntimeError("kill switch state is unreadable") from error
        expected = {
            "schema_version", "engaged", "generation", "changed_by", "reason_code", "changed_at", "attestation",
        }
        if not isinstance(payload, Mapping) or set(payload) != expected or payload["schema_version"] != SCHEMA_VERSION:
            raise RuntimeError("kill switch state contract is invalid")
        try:
            state = KillSwitchState(
                payload["engaged"], payload["generation"], payload["changed_by"], payload["reason_code"],
                payload["changed_at"], payload["attestation"],
            )
            self._validate_state(state)
        except (TypeError, ValueError) as error:
            raise RuntimeError("kill switch state values are invalid") from error
        unsigned = KillSwitchState(**{**state.__dict__, "attestation": ""})
        if not hmac.compare_digest(state.attestation, self._attest(unsigned)):
            raise RuntimeError("kill switch state attestation is invalid")
        self._verify_anchor(state)
        return state

    def set_state(self, engaged: bool, actor: Principal, reason_code: str) -> KillSwitchState:
        """Меняет switch только exact owner-ом и атомарно сохраняет generation."""

        GovernancePolicy.builtin().require(actor, "operations.manage")
        if not isinstance(engaged, bool):
            raise ValueError("kill switch state must be boolean")
        _safe_text(reason_code, "reason code")
        current = self.status()
        if current.engaged == engaged:
            return current
        updated = self._signed(engaged, current.generation + 1, actor.id, reason_code, int(self.clock()))
        self._write_state(updated)
        self._write_anchor(updated)
        return self.status()

    def _signed(self, engaged: bool, generation: int, actor: str, reason: str, changed_at: int) -> KillSwitchState:
        unsigned = KillSwitchState(engaged, generation, actor, reason, changed_at, "")
        return KillSwitchState(**{**unsigned.__dict__, "attestation": self._attest(unsigned)})

    def _attest(self, state: KillSwitchState) -> str:
        payload = {"schema_version": SCHEMA_VERSION, **state.__dict__}
        payload["attestation"] = ""
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return "hmac-sha256:" + hmac.new(self.key, encoded, hashlib.sha256).hexdigest()

    def _anchor_attestation(self, generation: int, state_attestation: str) -> str:
        encoded = f"kill-switch-anchor-v1:{generation}:{state_attestation}".encode("utf-8")
        return "hmac-sha256:" + hmac.new(self.key, encoded, hashlib.sha256).hexdigest()

    def _write_anchor(self, state: KillSwitchState) -> None:
        payload = {
            "schema_version": SCHEMA_VERSION,
            "generation": state.generation,
            "state_attestation": state.attestation,
            "attestation": self._anchor_attestation(state.generation, state.attestation),
        }
        self._write_json(self.anchor_path, payload, ".kill-switch-anchor-")

    def _verify_anchor(self, state: KillSwitchState) -> None:
        self._validate_file(self.anchor_path)
        try:
            anchor = json.loads(self.anchor_path.read_text(encoding="utf-8"), object_pairs_hook=_strict_object)
        except (OSError, UnicodeError, json.JSONDecodeError) as error:
            raise RuntimeError("kill switch anchor is unreadable") from error
        expected_fields = {"schema_version", "generation", "state_attestation", "attestation"}
        valid_shape = isinstance(anchor, Mapping) and set(anchor) == expected_fields
        if not valid_shape or anchor["schema_version"] != SCHEMA_VERSION:
            raise RuntimeError("kill switch anchor contract is invalid")
        expected = self._anchor_attestation(anchor["generation"], anchor["state_attestation"])
        if not isinstance(anchor["attestation"], str) or not hmac.compare_digest(anchor["attestation"], expected):
            raise RuntimeError("kill switch anchor attestation is invalid")
        if (anchor["generation"], anchor["state_attestation"]) != (state.generation, state.attestation):
            raise RuntimeError("kill switch state rollback or incomplete transition detected")

    @staticmethod
    def _validate_state(state: KillSwitchState) -> None:
        if not isinstance(state.engaged, bool) or isinstance(state.generation, bool) or state.generation < 0:
            raise ValueError("kill switch state or generation is invalid")
        if not isinstance(state.generation, int) or not isinstance(state.changed_at, int) or state.changed_at < 0:
            raise ValueError("kill switch generation or timestamp is invalid")
        _safe_text(state.changed_by, "actor")
        _safe_text(state.reason_code, "reason code")
        if not re.fullmatch(r"hmac-sha256:[a-f0-9]{64}", state.attestation):
            raise ValueError("kill switch attestation is invalid")

    @staticmethod
    def _validate_file(path: Path) -> None:
        if path.is_symlink() or not path.is_file():
            raise ValueError("kill switch path must be a regular file")
        metadata = path.lstat()
        owner_ok = not hasattr(os, "getuid") or metadata.st_uid == os.getuid()
        if stat.S_IMODE(metadata.st_mode) != 0o600 or not owner_ok:
            raise ValueError("kill switch file must be owner-only")

    def _write_state(self, state: KillSwitchState) -> None:
        self._write_json(self.path, state.to_payload(), ".kill-switch-")

    def _write_json(self, destination: Path, payload: Mapping[str, object], prefix: str) -> None:
        descriptor, temporary = tempfile.mkstemp(prefix=prefix, dir=self.state_root)
        try:
            os.fchmod(descriptor, 0o600)
            content = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
            os.write(descriptor, content)
            os.fsync(descriptor)
            os.close(descriptor)
            descriptor = -1
            os.replace(temporary, destination)
            directory_fd = os.open(self.state_root, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            if os.path.exists(temporary):
                os.unlink(temporary)


@dataclass(frozen=True)
class CleanupReceipt:
    status: str
    scope: str
    removed_files: int
    retained_files: int
    targets_digest: str
    kill_switch_generation: int
    completed_at: int

    def to_payload(self) -> dict[str, object]:
        return {"schema_version": SCHEMA_VERSION, **self.__dict__}


@dataclass(frozen=True)
class LocalStateCleaner:
    """Удаляет только allowlisted regular files после обязательного stop gate."""

    state_root: Path
    config: OperationsConfig
    kill_switch: LocalKillSwitch
    clock: Callable[[], float] = field(default=time.time, repr=False, compare=False)

    def __post_init__(self) -> None:
        root = _private_root(self.state_root)
        if self.kill_switch.state_root != root:
            raise ValueError("cleanup and kill switch roots must match")
        object.__setattr__(self, "state_root", root)

    def cleanup(
        self,
        scope: str,
        actor: Principal,
        confirmation: str,
        *,
        dry_run: bool,
        legal_hold: bool = False,
    ) -> CleanupReceipt:
        """Планирует или удаляет exact files; recursive cleanup запрещён."""

        if (
            confirmation != _CONFIRMATION
        ):
            raise PermissionError("state cleanup approval is invalid")
        GovernancePolicy.builtin().require(actor, "operations.manage")
        if scope not in {"ephemeral", "all"} or not isinstance(dry_run, bool) or not isinstance(legal_hold, bool):
            raise ValueError("state cleanup options are invalid")
        if legal_hold:
            raise PermissionError("state cleanup is blocked by legal hold")
        switch = self.kill_switch.status()
        if not switch.engaged:
            raise PermissionError("state cleanup requires engaged kill switch")
        if scope == "all":
            raise PermissionError("protected state cleanup is not supported; preserve audit for investigation")
        targets = self.config.ephemeral_targets
        candidates = self._candidates(targets)
        digest = "sha256:" + hashlib.sha256("\n".join(path.name for path in candidates).encode("utf-8")).hexdigest()
        if not dry_run:
            self._remove(candidates)
        retained = len(tuple(path for path in self.state_root.iterdir() if path.is_file())) - (
            len(candidates) if not dry_run else 0
        )
        return CleanupReceipt(
            "planned" if dry_run else "completed", scope, 0 if dry_run else len(candidates), max(0, retained),
            digest, switch.generation, int(self.clock()),
        )

    def _candidates(self, targets: tuple[str, ...]) -> tuple[Path, ...]:
        names = tuple(sorted({name for target in targets for name in (target, target + "-shm", target + "-wal")}))
        candidates = []
        for name in names:
            path = self.state_root / name
            if not path.exists() and not path.is_symlink():
                continue
            if path.is_symlink() or not path.is_file() or path.parent != self.state_root:
                raise ValueError("cleanup target must be an allowlisted regular file")
            metadata = path.lstat()
            owner_ok = not hasattr(os, "getuid") or metadata.st_uid == os.getuid()
            if stat.S_IMODE(metadata.st_mode) != 0o600 or not owner_ok:
                raise ValueError("cleanup target must be owner-only")
            candidates.append(path)
        return tuple(candidates)

    def _remove(self, candidates: tuple[Path, ...]) -> None:
        directory_fd = os.open(self.state_root, os.O_RDONLY)
        try:
            for path in candidates:
                before = path.lstat()
                current = os.stat(path.name, dir_fd=directory_fd, follow_symlinks=False)
                same_file = (before.st_dev, before.st_ino) == (current.st_dev, current.st_ino)
                if not same_file or not stat.S_ISREG(current.st_mode):
                    raise RuntimeError("cleanup target changed after validation")
                os.unlink(path.name, dir_fd=directory_fd)
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
