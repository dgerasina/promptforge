"""One-command repository workspace lifecycle with owner-private local state."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
import time

from promptforge.core.project_profile import load_project_profile
from promptforge.core.repository_index import RepositoryIndexer
from promptforge.platform.git_identity import GitIdentityResolver
from promptforge.platform.integrations import capabilities_for_project_profile
from promptforge.platform.mcp_hub import McpRegistry
from promptforge.platform.skill_library import RepositorySkillApprovalRegistry, load_skill_library
from promptforge.platform.secure_filesystem import SECURE_FILESYSTEM
from promptforge.platform.task_router import load_agent_catalog


_MANIFEST = "workspace-manifest.json"
_RUNTIME = "workspace-runtime.json"
_LOG = "workspace.log"
_LOCK = "workspace.lock"
_STOP = "workspace-stop.json"
_INSTANCE = re.compile(r"^[0-9a-f]{32}$")
_SPAWNED: dict[int, subprocess.Popen[bytes]] = {}


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def _digest(value: object) -> str:
    return "sha256:" + hashlib.sha256(_canonical(value)).hexdigest()


def _atomic_json(path: Path, payload: object) -> None:
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}-", dir=path.parent)
    try:
        if hasattr(os, "fchmod"):
            os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(_canonical(payload) + b"\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        if os.name != "nt":
            directory = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        if os.name == "nt":
            SECURE_FILESYSTEM.windows.apply_and_verify(path, directory=False)
    except BaseException:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


@dataclass(frozen=True)
class WorkspaceLifecycle:
    """Prepares, starts and controls one local PromptForge workspace."""

    product_root: Path
    repository_root: Path
    state_root: Path

    def __post_init__(self) -> None:
        product = Path(self.product_root).resolve(strict=True)
        repository = Path(self.repository_root).resolve(strict=True)
        state = Path(self.state_root)
        if (
            not product.is_dir() or product.is_symlink() or not repository.is_dir() or repository.is_symlink()
            or not product.is_relative_to(repository) or not state.is_absolute()
        ):
            raise ValueError("workspace roots are invalid")
        if state.exists() or state.is_symlink():
            if state.is_symlink() or not state.is_dir() or state.resolve() != state:
                raise ValueError("workspace state root is unsafe")
            self._require_private(state)
        object.__setattr__(self, "product_root", product)
        object.__setattr__(self, "repository_root", repository)
        object.__setattr__(self, "state_root", state)

    @classmethod
    def from_product(cls, product_root: Path, state_root: Path | None = None) -> WorkspaceLifecycle:
        product = Path(product_root).resolve(strict=True)
        repository = product.parent
        state = Path(state_root).absolute() if state_root is not None else repository / ".promptforge" / "runtime"
        cls._require_no_symlink_components(state.parent)
        return cls(product, repository, state)

    def setup(self, *, refresh_index: bool = True) -> dict[str, object]:
        """Creates private state and refreshes exact repository metadata."""

        self._ensure_state()
        running = self._query("status", required=False)
        profile = load_project_profile(self.product_root / "project-profile.yaml")
        catalog = load_agent_catalog(profile)
        if profile.skill_approvals is None:
            if profile.pack.approved_skill_order:
                raise ValueError("workspace project pack requires skill approvals")
            approved_skills = 0
            total_skills = 0
        else:
            approvals = RepositorySkillApprovalRegistry.from_file(profile.skill_approvals)
            library = load_skill_library(profile.skills_root, approvals.verify)
            approved_skills = len(approvals.approvals)
            total_skills = len(library.releases)
        index = RepositoryIndexer(self.repository_root, profile.pack.repository_index, profile.project_key).build()
        identity, readiness = self._bootstrap_readiness(profile)
        manifest = {
            "schema_version": "1.0", "manifest_version": "workspace-v1",
            "git_revision": self._git_revision(), "source_digest": self._source_digest(),
            "project_key": profile.project_key, "profile_id": profile.profile_id,
            "catalog_digest": catalog.digest, "agents": len(catalog.agents),
            "skills": total_skills, "approved_skills": approved_skills,
            "repository_index_digest": index.to_payload()["index_digest"], "network_used": False,
            "identity_status": identity["status"], "principal_id": identity["principal_id"],
            "principal_role": identity["role"], "identity_privileged": False,
            "hub_status": readiness["hub_status"], "integrations": readiness["integrations"],
            "capabilities": readiness["capabilities"], "readiness_digest": readiness["readiness_digest"],
        }
        payload = {**manifest, "manifest_digest": _digest(manifest)}
        if running is not None and running["manifest_digest"] != payload["manifest_digest"]:
            raise RuntimeError("workspace source changed; stop is required before setup")
        self._require_no_ambiguous_runtime(running)
        if refresh_index:
            RepositoryIndexer(self.repository_root, profile.pack.repository_index, profile.project_key).write(index)
        _atomic_json(self.state_root / _MANIFEST, payload)
        return {
            "schema_version": "1.0", "command": "setup", "status": "ready",
            "manifest_digest": payload["manifest_digest"],
            "repository_index_digest": manifest["repository_index_digest"],
            "agents": manifest["agents"], "skills": manifest["approved_skills"], "network_used": False,
            "identity_status": manifest["identity_status"], "principal_id": manifest["principal_id"],
            "principal_role": manifest["principal_role"], "identity_privileged": False,
            "hub_status": manifest["hub_status"], "integrations": manifest["integrations"],
            "capabilities": manifest["capabilities"], "readiness_digest": manifest["readiness_digest"],
        }

    def start(self) -> dict[str, object]:
        """Starts one detached local control process or returns the running instance."""

        current = self._query("status", required=False)
        if current is not None:
            manifest = self._read_manifest()
            profile = load_project_profile(self.product_root / "project-profile.yaml")
            identity, readiness = self._bootstrap_readiness(profile)
            if (
                current["manifest_digest"] != manifest["manifest_digest"]
                or manifest["source_digest"] != self._source_digest()
                or manifest["git_revision"] != self._git_revision()
                or identity["principal_id"] != manifest["principal_id"]
                or identity["role"] != manifest["principal_role"]
                or readiness["readiness_digest"] != manifest["readiness_digest"]
            ):
                raise RuntimeError("workspace source changed; stop is required before restart")
            return self._runtime_payload("start", "running", current)
        setup = self.setup(refresh_index=True)
        self._require_no_ambiguous_runtime(None)
        instance = os.urandom(16).hex()
        environment = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "LANG": os.environ.get("LANG", "C.UTF-8"),
            "PYTHONDONTWRITEBYTECODE": "1",
        }
        python_path = str(self.product_root)
        environment["PYTHONPATH"] = python_path
        log_path = self.state_root / _LOG
        descriptor = os.open(
            log_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0), 0o600,
        )
        if os.name == "nt":
            SECURE_FILESYSTEM.windows.apply_and_verify(log_path, directory=False)
        try:
            process = subprocess.Popen(
                [sys.executable, "-m", "promptforge.platform.workspace_service", "--state-root", str(self.state_root),
                 "--instance-id", instance, "--manifest-digest", str(setup["manifest_digest"])],
                cwd=self.repository_root, env=environment, stdin=subprocess.DEVNULL,
                stdout=descriptor, stderr=descriptor,
                close_fds=True, start_new_session=True,
            )
            _SPAWNED[process.pid] = process
        finally:
            os.close(descriptor)
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            response = self._query("status", required=False)
            if response is not None and response.get("instance_id") == instance:
                return self._runtime_payload("start", "running", response)
            if process.poll() is not None:
                break
            time.sleep(0.05)
        raise RuntimeError("workspace runtime failed to start")

    def status(self) -> dict[str, object]:
        response = self._query("status", required=False)
        if response is None:
            return {
                "schema_version": "1.0", "command": "status", "status": "stopped", "running": False,
                "manifest_digest": self._manifest_digest(required=False), "network_used": False,
            }
        return self._runtime_payload("status", "running", response)

    def stop(self) -> dict[str, object]:
        response = self._query("stop", required=False)
        if response is None:
            self._require_no_ambiguous_runtime(None)
            return {
                "schema_version": "1.0", "command": "stop", "status": "stopped", "running": False,
                "manifest_digest": self._manifest_digest(required=False), "network_used": False,
            }
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and (self.state_root / _RUNTIME).exists():
            time.sleep(0.05)
        process = _SPAWNED.pop(int(response["pid"]), None)
        if process is not None:
            try:
                process.wait(timeout=1)
            except subprocess.TimeoutExpired:
                pass
        if any(
            path.exists() or path.is_symlink()
            for path in (self.state_root / _RUNTIME, self.state_root / _STOP)
        ):
            raise RuntimeError("workspace runtime did not stop cleanly")
        return {
            "schema_version": "1.0", "command": "stop", "status": "stopped", "running": False,
            "manifest_digest": response["manifest_digest"], "network_used": False,
        }

    def doctor(self) -> dict[str, object]:
        check_ids = ("state", "manifest", "source", "revision", "profile", "index", "identity", "hub", "runtime")
        results = {check_id: False for check_id in check_ids}
        try:
            self._require_private(self.state_root)
            results["state"] = True
            manifest = self._read_manifest()
            results["manifest"] = True
            results["source"] = manifest["source_digest"] == self._source_digest()
            results["revision"] = manifest["git_revision"] == self._git_revision()
            profile = load_project_profile(self.product_root / "project-profile.yaml")
            results["profile"] = True
            current_index = RepositoryIndexer(
                self.repository_root, profile.pack.repository_index, profile.project_key,
            ).build().to_payload()["index_digest"]
            results["index"] = current_index == manifest["repository_index_digest"]
            identity, readiness = self._bootstrap_readiness(profile)
            results["identity"] = bool(
                identity["status"] == manifest["identity_status"] == "recognized"
                and identity["principal_id"] == manifest["principal_id"]
                and identity["role"] == manifest["principal_role"]
                and manifest["identity_privileged"] is False
            )
            results["hub"] = bool(
                readiness["hub_status"] == manifest["hub_status"] == "registry_ready"
                and readiness["readiness_digest"] == manifest["readiness_digest"]
            )
            runtime = self._query("status", required=False)
            results["runtime"] = runtime is None or runtime["manifest_digest"] == manifest["manifest_digest"]
        except (OSError, RuntimeError, ValueError):
            pass
        checks = tuple(results.values())
        return {
            "schema_version": "1.0", "command": "doctor", "status": "ready" if all(checks) else "blocked",
            "checks": len(checks), "passed": sum(checks), "running": self._query("status", required=False) is not None,
            "check_ids": list(check_ids), "network_used": False,
        }

    def _runtime_payload(self, command: str, status_value: str, response: dict[str, object]) -> dict[str, object]:
        return {
            "schema_version": "1.0", "command": command, "status": status_value, "running": True,
            "instance_id": response["instance_id"], "manifest_digest": response["manifest_digest"],
            "pid": response["pid"], "network_used": False,
        }

    def _query(self, command: str, *, required: bool) -> dict[str, object] | None:
        try:
            runtime = self._read_runtime()
            if not self._pid_alive(int(runtime["pid"])):
                raise RuntimeError("workspace runtime pid is not alive")
            if command == "stop":
                _atomic_json(self.state_root / _STOP, {
                    "schema_version": "1.0", "instance_id": runtime["instance_id"],
                })
            return {
                "status": "running", "instance_id": runtime["instance_id"],
                "manifest_digest": runtime["manifest_digest"], "pid": runtime["pid"], "network_used": False,
            }
        except (OSError, RuntimeError, ValueError, json.JSONDecodeError):
            if required:
                raise RuntimeError("workspace runtime is unavailable")
            return None

    def _read_manifest(self) -> dict[str, object]:
        payload = self._read_private_json(self.state_root / _MANIFEST)
        expected = {
            "schema_version", "manifest_version", "git_revision", "source_digest", "project_key", "profile_id",
            "catalog_digest", "agents", "skills", "approved_skills", "repository_index_digest", "network_used",
            "identity_status", "principal_id", "principal_role", "identity_privileged", "hub_status",
            "integrations", "capabilities", "readiness_digest", "manifest_digest",
        }
        if set(payload) != expected or payload["schema_version"] != "1.0" or payload["network_used"] is not False:
            raise RuntimeError("workspace manifest contract is invalid")
        unsigned = {key: value for key, value in payload.items() if key != "manifest_digest"}
        if payload["manifest_digest"] != _digest(unsigned):
            raise RuntimeError("workspace manifest integrity failed")
        return payload

    def _bootstrap_readiness(self, profile: object) -> tuple[dict[str, object], dict[str, object]]:
        identity = GitIdentityResolver(
            self.repository_root, self.product_root / "config" / "local-auth.json",
        ).resolve().to_payload()
        if identity["status"] != "recognized" or identity["privileged"] is not False:
            raise PermissionError("workspace Git identity is unknown")
        capabilities = capabilities_for_project_profile(profile)
        registry = McpRegistry(capabilities)
        capability_ids = tuple(item.id for item in capabilities)
        if (
            len(capability_ids) != len(set(capability_ids))
            or any(item.operation != "read" or item.project_id != "promptforge" for item in capabilities)
        ):
            raise ValueError("workspace MCP capability catalog is unsafe")
        unsigned = {
            "identity_status": identity["status"], "principal_id": identity["principal_id"],
            "principal_role": identity["role"], "identity_privileged": False,
            "hub_status": "registry_ready", "integrations": len(profile.pack.integrations),
            "capabilities": len(registry.capabilities), "capability_ids": capability_ids,
        }
        return identity, {**unsigned, "readiness_digest": _digest(unsigned)}

    def _read_runtime(self) -> dict[str, object]:
        payload = self._read_private_json(self.state_root / _RUNTIME)
        if set(payload) != {"schema_version", "instance_id", "manifest_digest", "pid"} or not _INSTANCE.fullmatch(
            str(payload.get("instance_id", ""))
        ):
            raise RuntimeError("workspace runtime state is invalid")
        return payload

    @staticmethod
    def _pid_alive(pid: int) -> bool:
        if not isinstance(pid, int) or pid <= 0:
            return False
        try:
            os.kill(pid, 0)
        except OSError:
            return False
        return True

    @staticmethod
    def _read_private_json(path: Path) -> dict[str, object]:
        try:
            payload = json.loads(SECURE_FILESYSTEM.read_private(path, 1_000_000))
        except (OSError, PermissionError, ValueError, json.JSONDecodeError) as error:
            raise RuntimeError("workspace state file is unsafe") from error
        if not isinstance(payload, dict):
            raise RuntimeError("workspace state document is invalid")
        return payload

    def _manifest_digest(self, *, required: bool) -> str | None:
        try:
            return str(self._read_manifest()["manifest_digest"])
        except (OSError, RuntimeError, ValueError):
            if required:
                raise
            return None

    def _ensure_state(self) -> None:
        parent = self.state_root.parent
        self._require_no_symlink_components(parent)
        parent.mkdir(parents=True, exist_ok=True)
        if parent.is_symlink() or parent.resolve() != parent:
            raise ValueError("workspace state parent is unsafe")
        if self.state_root.exists() or self.state_root.is_symlink():
            if self.state_root.is_symlink() or not self.state_root.is_dir():
                raise ValueError("workspace state root is unsafe")
            self._require_private(self.state_root)
        else:
            SECURE_FILESYSTEM.ensure_private_directory(self.state_root)
        self._require_private(self.state_root)

    @staticmethod
    def _require_private(path: Path) -> None:
        try:
            SECURE_FILESYSTEM.require_private_directory(path)
        except (PermissionError, ValueError) as error:
            raise ValueError("workspace state root must be owner-private")

    @staticmethod
    def _require_no_symlink_components(path: Path) -> None:
        candidate = Path(path).absolute()
        current = Path(candidate.anchor)
        for part in candidate.parts[1:]:
            current = current / part
            if current.is_symlink():
                raise ValueError("workspace state path must not contain symlinks")
            if not current.exists():
                break

    def _require_no_ambiguous_runtime(self, running: dict[str, object] | None) -> None:
        if running is not None:
            return
        runtime = self.state_root / _RUNTIME
        if runtime.exists() or runtime.is_symlink():
            raise RuntimeError("workspace runtime state requires approved cleanup")
        stop = self.state_root / _STOP
        if stop.exists() or stop.is_symlink():
            raise RuntimeError("workspace stop state requires approved cleanup")

    def _git_revision(self) -> str:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=self.repository_root, capture_output=True,
            text=True, check=False, timeout=10,
        )
        revision = result.stdout.strip()
        if result.returncode != 0 or not re.fullmatch(r"[0-9a-f]{40,64}", revision):
            raise ValueError("workspace repository revision is unavailable")
        return revision

    def _source_digest(self) -> str:
        digest = hashlib.sha256()
        files = []
        for path in self.product_root.rglob("*"):
            if path.is_symlink():
                raise ValueError("workspace product contains a symlink")
            if path.is_file() and "__pycache__" not in path.parts and path.name != ".DS_Store":
                files.append(path)
        for path in sorted(files):
            digest.update(path.relative_to(self.product_root).as_posix().encode() + b"\0" + path.read_bytes() + b"\0")
        return "sha256:" + digest.hexdigest()
