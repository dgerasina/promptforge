"""Isolated repository-only operational recovery and portability drills."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import tempfile
from typing import Callable

from promptforge.platform.contracts import Principal
from promptforge.platform.local_audit import AuditEvent, LocalAuditStore
from promptforge.platform.mutation_patch import MutationPatch, MutationSpec
from promptforge.platform.operations import LocalKillSwitch, LocalStateCleaner, OperationsConfig
from promptforge.platform.release_signing import generate_owner_keypair, sign_release_candidate, verify_release_candidate
from promptforge.platform.skill_signatures import SkillSigningKeyRegistry
from promptforge.platform.workspace import WorkspaceLifecycle


def _digest(content: bytes) -> str:
    return "sha256:" + hashlib.sha256(content).hexdigest()


def _private_directory(path: Path) -> Path:
    path.mkdir(mode=0o700, parents=True)
    path.chmod(0o700)
    return path.resolve()


class OperationalAcceptanceRunner:
    """Runs destructive-looking drills only against disposable private directories."""

    scenario_ids = (
        "kill_switch", "patch_rollback", "interrupted_recovery", "state_cleanup", "owner_key_rotation",
        "owner_key_revocation", "receipt_recovery", "master_update_restart", "clean_repository_portability",
    )

    def __init__(self, product_root: Path):
        root = Path(product_root).resolve(strict=True)
        if (
            not root.is_dir() or root.is_symlink() or not (root / "project-profile.yaml").is_file()
            or any(path.is_symlink() for path in root.rglob("*"))
        ):
            raise ValueError("operational acceptance product root is invalid")
        self.product_root = root

    def run(self) -> dict[str, object]:
        drills: tuple[Callable[[], bool], ...] = (
            self._kill_switch, self._patch_rollback, self._interrupted_recovery, self._state_cleanup,
            lambda: self._key_lifecycle()[0], lambda: self._key_lifecycle()[1], self._receipt_recovery,
            self._master_update_restart, self._clean_repository_portability,
        )
        results = []
        for scenario_id, drill in zip(self.scenario_ids, drills, strict=True):
            try:
                passed = drill() is True
            except (OSError, PermissionError, RuntimeError, ValueError, subprocess.SubprocessError):
                passed = False
            results.append({"id": scenario_id, "status": "passed" if passed else "failed"})
        passed = sum(item["status"] == "passed" for item in results)
        return {
            "schema_version": "1.0", "acceptance_version": "operations-v1",
            "status": "passed" if passed == len(results) else "failed",
            "scenarios": len(results), "passed": passed, "failed": len(results) - passed,
            "results": results, "isolated": True, "real_state_touched": False, "network_used": False,
        }

    @staticmethod
    def _owner() -> Principal:
        return Principal("owner-local", "owner", "promptforge")

    def _kill_switch(self) -> bool:
        with tempfile.TemporaryDirectory() as directory:
            state = _private_directory(Path(directory) / "state")
            switch = LocalKillSwitch(state, b"k" * 32, clock=lambda: 100)
            engaged = switch.set_state(True, self._owner(), "operations-drill")
            released = switch.set_state(False, self._owner(), "recovery-verified")
            return engaged.engaged and engaged.generation == 1 and not released.engaged and released.generation == 2

    def _patch_rollback(self) -> bool:
        with tempfile.TemporaryDirectory() as directory:
            repository = _private_directory(Path(directory) / "repository")
            target = repository / "artifact.txt"
            target.write_text("before", encoding="utf-8")
            patch = MutationPatch(repository, (MutationSpec(
                "artifact.txt", "production", "after", _digest(b"before"),
            ),))
            applied = patch.apply()
            applied.rollback()
            return target.read_text(encoding="utf-8") == "before"

    def _interrupted_recovery(self) -> bool:
        with tempfile.TemporaryDirectory() as directory:
            root = _private_directory(Path(directory) / "root")
            repository = _private_directory(root / "repository")
            state = _private_directory(root / "state")
            target = repository / "artifact.txt"
            target.write_text("before", encoding="utf-8")
            journal = state / "mutation-recovery.json"
            MutationPatch(repository, (MutationSpec(
                "artifact.txt", "production", "after", _digest(b"before"),
            ),), journal=journal).apply()
            recovered = MutationPatch.recover(repository, journal)
            return recovered == ("artifact.txt",) and target.read_text(encoding="utf-8") == "before" and not journal.exists()

    def _state_cleanup(self) -> bool:
        with tempfile.TemporaryDirectory() as directory:
            state = _private_directory(Path(directory) / "state")
            switch = LocalKillSwitch(state, b"c" * 32, clock=lambda: 100)
            switch.set_state(True, self._owner(), "cleanup-drill")
            ephemeral = state / "context-cache.sqlite3"
            protected = tuple(
                state / name
                for target in OperationsConfig.from_repository(self.product_root).protected_targets
                for name in (target, target + "-wal", target + "-shm")
            )
            for path in (ephemeral, *protected):
                path.write_bytes(b"synthetic")
                path.chmod(0o600)
            cleaner = LocalStateCleaner(
                state, OperationsConfig.from_repository(self.product_root), switch, clock=lambda: 101,
            )
            planned = cleaner.cleanup("ephemeral", self._owner(), "PURGE promptforge", dry_run=True)
            completed = cleaner.cleanup("ephemeral", self._owner(), "PURGE promptforge", dry_run=False)
            return (
                planned.status == "planned" and completed.status == "completed" and completed.removed_files == 1
                and not ephemeral.exists() and all(path.exists() for path in protected)
            )

    def _key_lifecycle(self) -> tuple[bool, bool]:
        with tempfile.TemporaryDirectory() as directory:
            root = _private_directory(Path(directory) / "keys")
            old_private, old_public = root / "old.key.pem", root / "old.pub.pem"
            new_private, new_public = root / "new.key.pem", root / "new.pub.pem"
            generate_owner_keypair(old_private, old_public)
            generate_owner_keypair(new_private, new_public)
            active = self._key_registry(root, old_public, new_public, old_status="active")
            manifest = self._accepted_manifest()
            old_signature = sign_release_candidate(
                manifest, "owner-local", "owner-old", old_private, active, issued_at=100, expires_at=200,
            )
            new_signature = sign_release_candidate(
                manifest, "owner-local", "owner-new", new_private, active, issued_at=100, expires_at=200,
            )
            rotation = (
                verify_release_candidate(manifest, old_signature, active, at_time=150)
                and verify_release_candidate(manifest, new_signature, active, at_time=150)
            )
            revoked = self._key_registry(root, old_public, new_public, old_status="revoked")
            revocation = (
                not verify_release_candidate(manifest, old_signature, revoked, at_time=150)
                and verify_release_candidate(manifest, new_signature, revoked, at_time=150)
            )
            return rotation, revocation

    @staticmethod
    def _key_registry(root: Path, old_public: Path, new_public: Path, *, old_status: str) -> SkillSigningKeyRegistry:
        registry = root / f"registry-{old_status}.json"
        registry.write_text(json.dumps({
            "schema_version": "1.0", "keys": [
                {"key_id": "owner-old", "signer_id": "owner-local", "status": old_status,
                 "public_key": old_public.name},
                {"key_id": "owner-new", "signer_id": "owner-local", "status": "active",
                 "public_key": new_public.name},
            ],
        }, sort_keys=True), encoding="utf-8")
        return SkillSigningKeyRegistry.from_file(registry)

    @staticmethod
    def _accepted_manifest() -> dict[str, object]:
        unsigned = {
            "schema_version": "1.0", "status": "accepted", "reason_codes": [],
            "source_digest": "sha256:" + "1" * 64, "release_scope": {}, "gates": {}, "skills": {},
            "agents": 16, "final_evidence_status": "passed", "assurance_scope": "repository_single_host_mvp",
            "known_limitations": [], "network_used": False, "gate_config_digest": "sha256:" + "2" * 64,
            "portability_digest": "sha256:" + "3" * 64, "product_version": "1.0.0",
            "spec_version": "platform-v1", "evidence": {},
        }
        encoded = json.dumps(unsigned, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
        return {**unsigned, "release_digest": "sha256:" + hashlib.sha256(encoded).hexdigest()}

    def _receipt_recovery(self) -> bool:
        with tempfile.TemporaryDirectory() as directory:
            state = _private_directory(Path(directory) / "state")
            path, backup, key = state / "audit.sqlite3", state / "audit.backup", b"a" * 32
            store = LocalAuditStore(path, key, clock=lambda: 100, id_factory=lambda: "event-1")
            store.append(AuditEvent(
                "trace-1", "owner-local", "promptforge", "operations", "receipt", "ok", "completed", "1.0", 100,
            ))
            shutil.copyfile(path, backup)
            backup.chmod(0o600)
            connection = sqlite3.connect(path)
            connection.execute("UPDATE audit_events SET event_hash=? WHERE sequence=1", ("0" * 64,))
            connection.commit()
            connection.close()
            detected = not store.verify().valid
            os.replace(backup, path)
            path.chmod(0o600)
            recovered = LocalAuditStore(path, key).verify()
            return detected and recovered.valid and recovered.events == 1

    def _master_update_restart(self) -> bool:
        with tempfile.TemporaryDirectory() as directory:
            repository, product = self._clean_repository(Path(directory))
            state = _private_directory(Path(directory) / "state-update")
            lifecycle = WorkspaceLifecycle(product, repository, state)
            before = lifecycle.setup(refresh_index=False)["manifest_digest"]
            initial = lifecycle.start()
            readme = product / "README.md"
            readme.write_text(readme.read_text(encoding="utf-8") + "\n", encoding="utf-8")
            self._git(repository, "add", "promptforge/README.md")
            self._git(repository, "commit", "-qm", "test: simulate master update")
            blocked = lifecycle.doctor()["status"] == "blocked"
            try:
                lifecycle.start()
            except RuntimeError:
                running_restart_blocked = True
            else:
                running_restart_blocked = False
            first_stop = lifecycle.stop()
            after = lifecycle.setup(refresh_index=False)["manifest_digest"]
            started = lifecycle.start()
            try:
                running = lifecycle.status()["running"] is True
            finally:
                stopped = lifecycle.stop()["status"] == "stopped"
            return (
                initial["status"] == "running" and blocked and running_restart_blocked
                and first_stop["status"] == "stopped" and before != after
                and started["status"] == "running" and running and stopped
            )

    def _clean_repository_portability(self) -> bool:
        with tempfile.TemporaryDirectory() as directory:
            repository, product = self._clean_repository(Path(directory))
            check = subprocess.run(
                [sys.executable, "-m", "promptforge", "check"], cwd=repository,
                env={"PYTHONPATH": str(product), "PATH": os.environ.get("PATH", "")},
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                text=True, timeout=30, check=False,
            )
            payload = json.loads(check.stdout) if check.returncode == 0 else {}
            state = _private_directory(Path(directory) / "state-portable")
            lifecycle = WorkspaceLifecycle(product, repository, state)
            setup = lifecycle.setup(refresh_index=False)
            started = lifecycle.start()
            try:
                doctor = lifecycle.doctor()
            finally:
                stopped = lifecycle.stop()
            return (
                payload.get("status") == "ok" and setup["status"] == "ready" and started["status"] == "running"
                and doctor["status"] == "ready" and stopped["status"] == "stopped"
            )

    def _clean_repository(self, root: Path) -> tuple[Path, Path]:
        repository = root / "clean-repository"
        product = repository / "promptforge"
        repository.mkdir()
        shutil.copytree(
            self.product_root, product,
            ignore=shutil.ignore_patterns("__pycache__", "*.pyc", ".DS_Store"),
        )
        (product / "project-profile.yaml").write_text(json.dumps({
            "schema_version": "1.0", "profile_id": "portable-operations-drill",
            "project_key": "example-project", "pack": "packs/core/pack.yaml",
        }, sort_keys=True), encoding="utf-8")
        self._git(repository, "init", "-q", "-b", "master")
        self._git(repository, "config", "user.name", "owner-local")
        self._git(repository, "config", "user.email", "local@example.invalid")
        self._git(repository, "add", "promptforge")
        self._git(repository, "commit", "-qm", "test: clean repository")
        return repository.resolve(), product.resolve()

    @staticmethod
    def _git(repository: Path, *arguments: str) -> None:
        subprocess.run(
            ["git", "-c", "core.hooksPath=/dev/null", "-c", "commit.gpgsign=false", *arguments],
            cwd=repository, stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30, check=True,
            env={"PATH": os.environ.get("PATH", ""), "LANG": "C"},
        )
