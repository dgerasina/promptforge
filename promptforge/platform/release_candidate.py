"""Deterministic, metadata-only release-candidate acceptance gate."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
from types import MappingProxyType
from typing import Mapping

from promptforge.core.project_profile import load_project_profile
from promptforge.platform.catalog import catalog_from_project_profile
from promptforge.platform.contracts import Principal
from promptforge.platform.final_evidence import FinalEvidenceRunner
from promptforge.platform.production_docs import ProductionDocumentationGate
from promptforge.platform.neutrality import NeutralityGate, repository_neutrality_extras
from promptforge.platform.security import scan_repository_text_artifacts
from promptforge.platform.skill_library import RepositorySkillApprovalRegistry, load_skill_library, require_skill_evals
from promptforge.platform.task_router import TaskEnvelope, TaskRouter, load_agent_catalog
from promptforge import __version__


_LIMITATIONS = (
    "external_integrations_require_injected_authenticated_runtime",
    "local_inference_requires_separate_provisioned_admission",
    "single_host_no_ha_or_external_audit_anchor",
)
_DENIED_SUFFIXES = frozenset({".sqlite", ".sqlite3", ".db", ".key", ".bin", ".gguf", ".safetensors"})
_DENIED_NAMES = frozenset({".env", "id_rsa", "id_ed25519"})
_PRIVATE_KEY_MARKERS = (
    b"-----BEGIN PRIVATE KEY-----",
    b"-----BEGIN ENCRYPTED PRIVATE KEY-----",
    b"-----BEGIN RSA PRIVATE KEY-----",
    b"-----BEGIN EC PRIVATE KEY-----",
    b"-----BEGIN OPENSSH PRIVATE KEY-----",
)
_GATE_CONFIG_FIELDS = frozenset({
    "schema_version", "assurance_scope", "required_gates", "deploy_prefix", "excluded_roots",
    "prohibited_suffixes", "network_allowed",
})
_SUPPORTED_GATES = frozenset({
    "production_docs", "security", "e2e", "load", "skills", "agent_catalog", "neutrality", "portability",
    "secret_scan",
})
_REF = re.compile(r"^[A-Za-z0-9._/-]+$")
_AUTO_IGNORED_NAMES = frozenset({".DS_Store"})
_AUTO_IGNORED_SUFFIXES = frozenset({".pyc", ".pyo"})


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def _is_prohibited_release_file(path: Path) -> bool:
    lowered = path.name.lower()
    if path.suffix.lower() in _DENIED_SUFFIXES or lowered in _DENIED_NAMES or lowered.endswith(".pending.json"):
        return True
    if lowered.endswith(".pub.pem"):
        return False
    if path.suffix.lower() == ".pem":
        header = path.read_bytes()[:4096]
        return any(marker in header for marker in _PRIVATE_KEY_MARKERS)
    return False


def _is_auto_ignored_release_artifact(path: Path) -> bool:
    return path.name in _AUTO_IGNORED_NAMES or path.suffix.lower() in _AUTO_IGNORED_SUFFIXES


def prune_auto_ignored_release_artifacts(root: Path) -> int:
    removed = 0
    for path in sorted(root.rglob("*"), reverse=True):
        if path.is_symlink():
            continue
        if path.is_file() and _is_auto_ignored_release_artifact(path):
            path.unlink(missing_ok=False)
            removed += 1
            continue
        if path.is_dir() and path.name == "__pycache__":
            try:
                path.rmdir()
                removed += 1
            except OSError:
                continue
    return removed


@dataclass(frozen=True)
class ReleaseCandidate:
    status: str
    reason_codes: tuple[str, ...]
    source_digest: str
    release_scope: Mapping[str, object]
    gates: Mapping[str, object]
    skills: Mapping[str, object]
    agents: int
    final_evidence_status: str
    release_digest: str
    gate_config_digest: str
    portability_digest: str
    evidence: Mapping[str, object]

    def to_payload(self) -> dict[str, object]:
        return {
            "schema_version": "1.0", "status": self.status, "reason_codes": list(self.reason_codes),
            "source_digest": self.source_digest, "release_scope": dict(self.release_scope),
            "gates": dict(self.gates), "skills": dict(self.skills), "agents": self.agents,
            "final_evidence_status": self.final_evidence_status,
            "assurance_scope": "repository_single_host_mvp", "known_limitations": list(_LIMITATIONS),
            "release_digest": self.release_digest, "network_used": False,
            "gate_config_digest": self.gate_config_digest, "portability_digest": self.portability_digest,
            "product_version": __version__, "spec_version": "platform-v1",
            "evidence": dict(self.evidence),
        }


@dataclass(frozen=True)
class ReleaseCandidateRunner:
    repository: Path
    evidence_iterations: int = 100

    def __post_init__(self) -> None:
        root = Path(self.repository).resolve(strict=True)
        valid = isinstance(self.evidence_iterations, int) and not isinstance(self.evidence_iterations, bool)
        if root.is_symlink() or not root.is_dir():
            raise ValueError("release repository must be a regular directory")
        if not valid or not 1 <= self.evidence_iterations <= 1000:
            raise ValueError("release evidence iterations must be between 1 and 1000")
        object.__setattr__(self, "repository", root)

    def run(self) -> ReleaseCandidate:
        prune_auto_ignored_release_artifacts(self.repository)
        before = self._snapshot()
        gate_config, gate_config_digest = self._gate_config()
        secrets_scan = scan_repository_text_artifacts(self.repository)
        profile = load_project_profile(self.repository / "project-profile.yaml")
        if profile.skill_approvals is None:
            if profile.pack.approved_skill_order:
                raise ValueError("release requires skill approvals for approved skills")
            approvals_count = 0
            approved = ()
            eval_cases = 0
        else:
            approvals = RepositorySkillApprovalRegistry.from_file(profile.skill_approvals)
            library = load_skill_library(profile.skills_root, approvals.verify)
            approved = library.for_role("owner")
            approvals_count = len(approvals.approvals)
            eval_cases = sum(require_skill_evals(profile.skills_root / release.id, release)[0] for release in approved)
        agents = len(load_agent_catalog(profile).agents)
        docs = ProductionDocumentationGate.from_repository(self.repository).inspect()
        neutrality = NeutralityGate(
            self.repository, repository_neutrality_extras(self.repository),
        ).inspect()
        final = FinalEvidenceRunner(self.repository, iterations=self.evidence_iterations).run().to_payload()
        portability, portability_digest = self._portability_gate()
        # Some in-process gates import modules after the initial cleanup. Remove only the
        # explicitly allowlisted interpreter residue again before measuring exact Git scope.
        prune_auto_ignored_release_artifacts(self.repository)
        scope = self._git_scope()
        scope = {
            **scope,
            "secret_text_files": secrets_scan.secret_files,
            "unreadable_text_files": secrets_scan.unreadable_files,
        }
        after = self._snapshot()
        reasons = []
        if before != after:
            reasons.append("source_changed_during_acceptance")
        if scope["dirty_entries"] or scope["untracked_entries"] or scope["tracked_files"] == 0:
            reasons.append("release_scope_not_clean")
        if scope["ignored_entries"] or scope["ignored_artifacts"]:
            reasons.append("ignored_release_artifact")
        if scope["prohibited_files"]:
            reasons.append("prohibited_release_artifact")
        if not secrets_scan.clean:
            reasons.append("release_secret_scan_failed")
        if docs.status != "passed":
            reasons.append("production_docs_gate_failed")
        if final["status"] != "passed":
            reasons.append("final_evidence_gate_failed")
        if len(approved) != approvals_count:
            reasons.append("skill_approval_gate_failed")
        if not portability:
            reasons.append("portable_core_gate_failed")
        if neutrality.status != "passed":
            reasons.append("neutrality_gate_failed")
        gates = {
            "production_docs": docs.status, "security": final["security"]["failed"] == 0,
            "e2e": final["e2e"]["passed"] == final["e2e"]["iterations"],
            "load": final["load"]["failures"] == 0, "portability": portability, "secret_scan": secrets_scan.clean,
            "neutrality": neutrality.status, "skills": len(approved) == approvals_count,
            "agent_catalog": agents > 0,
        }
        if any(gates[name] not in {True, "passed"} for name in gate_config["required_gates"]):
            reasons.append("required_gate_failed")
        evidence = {
            "security_cases": final["security"]["cases"], "security_failed": final["security"]["failed"],
            "e2e_iterations": final["e2e"]["iterations"], "e2e_passed": final["e2e"]["passed"],
            "load_requests": final["load"]["requests"], "load_failures": final["load"]["failures"],
            "load_max_p95_ms": final["load"]["max_p95_ms"],
        }
        unsigned = {
            "schema_version": "1.0", "status": "accepted" if not reasons else "blocked",
            "reason_codes": sorted(reasons), "source_digest": before, "release_scope": scope,
            "gates": gates, "skills": {"approved": len(approved), "detached_signatures": approvals_count,
            "eval_cases": eval_cases}, "agents": agents, "final_evidence_status": final["status"],
            "assurance_scope": "repository_single_host_mvp", "known_limitations": list(_LIMITATIONS),
            "network_used": False,
            "gate_config_digest": gate_config_digest, "portability_digest": portability_digest,
            "product_version": __version__, "spec_version": "platform-v1",
            "evidence": evidence,
        }
        digest = "sha256:" + hashlib.sha256(_canonical(unsigned)).hexdigest()
        return ReleaseCandidate(
            unsigned["status"], tuple(unsigned["reason_codes"]), before, MappingProxyType(scope),
            MappingProxyType(gates), MappingProxyType(unsigned["skills"]), agents, final["status"], digest,
            gate_config_digest, portability_digest,
            MappingProxyType(evidence),
        )

    def _gate_config(self) -> tuple[dict[str, object], str]:
        path = self.repository / "config" / "release-gates.json"
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 100_000:
            raise ValueError("release gate config is invalid")
        payload = json.loads(path.read_bytes(), object_pairs_hook=self._unique_object)
        if not isinstance(payload, dict) or set(payload) != _GATE_CONFIG_FIELDS or payload["schema_version"] != "1.0":
            raise ValueError("release gate config fields mismatch")
        required = payload["required_gates"]
        if (
            not isinstance(required, list) or not required or len(required) != len(set(required))
            or not set(required) <= _SUPPORTED_GATES or payload["network_allowed"] is not False
            or payload["deploy_prefix"] != "promptforge/" or payload["excluded_roots"] != [".promptforge/"]
            or payload["assurance_scope"] != "repository_single_host_mvp"
            or set(payload["prohibited_suffixes"]) != _DENIED_SUFFIXES
        ):
            raise ValueError("release gate config policy is invalid")
        return payload, "sha256:" + hashlib.sha256(_canonical(payload)).hexdigest()

    @staticmethod
    def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate release gate config field")
            result[key] = value
        return result

    def _snapshot(self) -> str:
        digest = hashlib.sha256()
        files = []
        for path in self.repository.rglob("*"):
            if path.is_symlink():
                raise ValueError("release source must not contain symlinks")
            if path.is_file() and "__pycache__" not in path.parts and not path.name.startswith(".DS_Store"):
                files.append(path)
        if not files or len(files) > 10_000:
            raise ValueError("release source file count is invalid")
        for path in sorted(files):
            relative = path.relative_to(self.repository).as_posix()
            content = path.read_bytes()
            digest.update(relative.encode("utf-8") + b"\0" + content + b"\0")
        return "sha256:" + digest.hexdigest()

    def _git_scope(self) -> dict[str, object]:
        git_root = self.repository.parent
        relative = self.repository.name
        tracked = subprocess.run(
            ["git", "ls-files", "--", relative], cwd=git_root, check=True, capture_output=True, text=True,
        ).stdout.splitlines()
        status = subprocess.run(
            ["git", "status", "--porcelain=v1", "--untracked-files=all", "--", relative],
            cwd=git_root, check=True, capture_output=True, text=True,
        ).stdout.splitlines()
        ignored = subprocess.run(
            ["git", "status", "--porcelain=v1", "--ignored=matching", "--", relative],
            cwd=git_root, check=True, capture_output=True, text=True,
        ).stdout.splitlines()
        prohibited = 0
        ignored_artifacts = 0
        for path in self.repository.rglob("*"):
            if not path.is_file():
                continue
            if _is_prohibited_release_file(path):
                prohibited += 1
            if path.suffix.lower() in {".pyc", ".pyo"} or "__pycache__" in path.parts:
                ignored_artifacts += 1
        return {
            "tracked_files": len(tracked), "dirty_entries": sum(not line.startswith("??") for line in status),
            "untracked_entries": sum(line.startswith("??") for line in status),
            "ignored_entries": sum(line.startswith("!!") for line in ignored),
            "ignored_artifacts": ignored_artifacts, "prohibited_files": prohibited,
            "deploy_prefix": "promptforge/", "private_state_excluded": True,
        }

    def _portability_gate(self) -> tuple[bool, str]:
        with tempfile.TemporaryDirectory() as directory:
            copied = Path(directory) / "promptforge"
            shutil.copytree(self.repository, copied, ignore=shutil.ignore_patterns("__pycache__", "*.pyc", ".DS_Store"))
            result = subprocess.run(
                [sys.executable, "-m", "promptforge", "check"], cwd=copied,
                env={"PYTHONPATH": str(copied), "PATH": os.environ.get("PATH", "")},
                stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=30, check=False,
            )
            try:
                payload = json.loads(result.stdout)
            except json.JSONDecodeError:
                payload = {}
            copied_core = load_project_profile(copied / "packs" / "core" / "project-profile.yaml")
            copied_catalog = load_agent_catalog(copied_core)
            copied_route = TaskRouter(copied_core.project_key, copied_catalog).route(
                TaskEnvelope(
                    copied_core.project_key,
                    Principal("portable-engineer", "engineer", copied_core.project_key),
                    "review.changed-files",
                    "portable-core-check",
                )
            )
            core_ok = (
                copied_core.skill_approvals is None
                and not copied_core.pack.approved_skill_order
                and len(catalog_from_project_profile(copied_core).skills) == 0
                and copied_route.outcome == "selected"
                and copied_route.reason_code == "exact_task_role_match"
                and len(copied_catalog.agents) == 1
            )
            digest = "sha256:" + hashlib.sha256(_canonical({
                "returncode": result.returncode, "payload": payload, "portable_core": core_ok,
            })).hexdigest()
            return result.returncode == 0 and payload.get("status") == "ok" and core_ok, digest


@dataclass(frozen=True)
class MergeRequestScopeReport:
    status: str
    reason_codes: tuple[str, ...]
    base_ref: str
    head_ref: str
    current_branch: str
    changed_files: tuple[str, ...]
    outside_scope_files: tuple[str, ...]
    mr_allowlist: tuple[str, ...]
    deploy_allowlist: tuple[str, ...]
    do_not_deploy: tuple[str, ...]
    diff_digest: str

    def to_payload(self) -> dict[str, object]:
        return {
            "schema_version": "1.0",
            "status": self.status,
            "reason_codes": list(self.reason_codes),
            "base_ref": self.base_ref,
            "head_ref": self.head_ref,
            "current_branch": self.current_branch,
            "changed_files": list(self.changed_files),
            "outside_scope_files": list(self.outside_scope_files),
            "mr_allowlist": list(self.mr_allowlist),
            "deploy_allowlist": list(self.deploy_allowlist),
            "do_not_deploy": list(self.do_not_deploy),
            "diff_digest": self.diff_digest,
            "network_used": False,
        }


@dataclass(frozen=True)
class MergeRequestScopeChecker:
    repository: Path
    base_ref: str
    head_ref: str = "HEAD"

    def __post_init__(self) -> None:
        root = Path(self.repository).resolve(strict=True)
        if root.is_symlink() or not root.is_dir():
            raise ValueError("mr scope repository must be a regular directory")
        if not _REF.fullmatch(self.base_ref) or not _REF.fullmatch(self.head_ref):
            raise ValueError("mr scope refs are invalid")
        object.__setattr__(self, "repository", root)

    def run(self) -> MergeRequestScopeReport:
        git_root = self.repository.parent
        self._resolve_commit(git_root, self.base_ref)
        self._resolve_commit(git_root, self.head_ref)
        product_prefix = f"{self.repository.name}/"
        changed = tuple(self._diff_files(git_root))
        outside = tuple(path for path in changed if not path.startswith(product_prefix))
        allowlist = tuple(path for path in changed if path.startswith(product_prefix))
        do_not_deploy = tuple(path for path in allowlist if path.startswith(f"{product_prefix}tests/"))
        deploy_allowlist = tuple(path for path in allowlist if path not in do_not_deploy)
        reasons: list[str] = []
        if not changed:
            reasons.append("mr_diff_empty")
        if outside:
            reasons.append("mr_scope_outside_product")
        if not allowlist:
            reasons.append("mr_scope_missing_product_changes")
        branch = subprocess.run(
            ["git", "branch", "--show-current"], cwd=git_root, check=True, capture_output=True, text=True,
        ).stdout.strip()
        digest = "sha256:" + hashlib.sha256(_canonical({
            "base_ref": self.base_ref,
            "head_ref": self.head_ref,
            "changed_files": changed,
            "outside_scope_files": outside,
            "mr_allowlist": allowlist,
            "deploy_allowlist": deploy_allowlist,
            "do_not_deploy": do_not_deploy,
        })).hexdigest()
        return MergeRequestScopeReport(
            "passed" if not reasons else "blocked",
            tuple(reasons),
            self.base_ref,
            self.head_ref,
            branch,
            changed,
            outside,
            allowlist,
            deploy_allowlist,
            do_not_deploy,
            digest,
        )

    def _diff_files(self, git_root: Path) -> list[str]:
        return [
            line for line in subprocess.run(
                ["git", "diff", "--name-only", f"{self.base_ref}..{self.head_ref}"],
                cwd=git_root, check=True, capture_output=True, text=True,
            ).stdout.splitlines() if line
        ]

    @staticmethod
    def _resolve_commit(git_root: Path, ref: str) -> None:
        try:
            subprocess.run(
                ["git", "rev-parse", "--verify", f"{ref}^{{commit}}"],
                cwd=git_root,
                check=True,
                capture_output=True,
                text=True,
            )
        except subprocess.CalledProcessError as error:
            raise ValueError("mr scope ref is unavailable") from error
