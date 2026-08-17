"""Read-only Git identity discovery for local UX, never privileged authentication."""

from __future__ import annotations

from dataclasses import dataclass
import json
import os
from pathlib import Path
import re
import stat
import subprocess

from promptforge.platform.auth import EmbeddedRoleRegistry

_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate identity registry field")
        result = {**result, key: value}
    return result


@dataclass(frozen=True)
class GitIdentityClaim:
    """Metadata-only convenience claim obtained from local Git configuration."""

    status: str
    principal_id: str
    role: str
    assurance: str = "untrusted_git_claim"
    privileged: bool = False

    def to_payload(self) -> dict[str, object]:
        return {
            "schema_version": "1.0", "status": self.status, "principal_id": self.principal_id,
            "role": self.role, "assurance": self.assurance, "privileged": self.privileged,
            "network_used": False,
        }


@dataclass(frozen=True)
class GitIdentityResolver:
    """Maps an exact Git user.name to a repository role without granting authority."""

    repository: Path
    registry_path: Path

    def resolve(self) -> GitIdentityClaim:
        repository = Path(self.repository).resolve(strict=True)
        registry_path = Path(self.registry_path).resolve(strict=True)
        if Path(self.repository).is_symlink() or not repository.is_dir():
            raise ValueError("repository identity root is invalid")
        if Path(self.registry_path).is_symlink():
            raise ValueError("identity registry must not be a symlink")
        metadata = registry_path.stat()
        owner_ok = not hasattr(os, "getuid") or metadata.st_uid == os.getuid()
        if (
            not registry_path.is_file() or metadata.st_size > 100_000
            or stat.S_IMODE(metadata.st_mode) & 0o022 or not owner_ok
        ):
            raise ValueError("identity registry is not a trusted repository file")
        registry = EmbeddedRoleRegistry.from_payload(
            json.loads(registry_path.read_bytes(), object_pairs_hook=_unique_object),
        )
        result = subprocess.run(
            ["git", "config", "--get", "user.name"], cwd=repository, stdin=subprocess.DEVNULL,
            capture_output=True, text=True, timeout=5, check=False,
        )
        claimed = result.stdout.strip() if result.returncode == 0 else ""
        if not _SAFE_ID.fullmatch(claimed):
            return GitIdentityClaim("denied", "", "")
        principal = registry.principal(claimed)
        if principal is None:
            return GitIdentityClaim("denied", "", "")
        return GitIdentityClaim("recognized", claimed, principal.role)
