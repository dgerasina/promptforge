"""Общий fail-closed lifecycle для versioned agent/skill execution."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import stat
from types import MappingProxyType
from typing import Mapping

from promptforge.core.project_profile import load_project_profile
from promptforge.platform.contracts import Principal
from promptforge.platform.changed_review import ChangedFilesReviewRunner
from promptforge.platform.docs_automation import DocumentationAutomation
from promptforge.platform.documentation_snapshot import (
    DocumentationSnapshotStore, SnapshotSource, configured_source, render_snapshot_section,
)
from promptforge.platform.governance import GovernancePolicy
from promptforge.platform.audit_runtime import AuditedMcpHub
from promptforge.platform.mcp_hub import McpRequest
from promptforge.platform.mutation_patch import MutationPatch, MutationSpec
from promptforge.platform.privacy import PrivacyContext
from promptforge.platform.review_provenance import DurableReviewFoundation, ReviewProvenanceStore
from promptforge.platform.review_evidence_loop import ReviewEvidenceLoop, documentation_evidence_digest
from promptforge.platform.review_closure import ReviewClosureContextStore, TargetedReviewClosureExecutor, WorktreeBaseline
from promptforge.platform.secure_runtime import local_audit_key_from_env
from promptforge.platform.security import inspect_text
from promptforge.platform.task_router import load_agent_catalog
from promptforge.platform.skill_library import RepositorySkillApprovalRegistry, SkillRelease, load_skill_library
from promptforge.platform.unified_ux import WorkResult
from promptforge.platform.efficiency_metrics import EfficiencyMetricEvent, EfficiencyMetricsStore


_TASK_KIND = re.compile(r"^[a-z][a-z0-9-]*(?:\.[a-z0-9-]+)+$")
_TRACE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_SAFE_PATH = re.compile(r"^[A-Za-z0-9._/-]{1,512}$")
_MAX_GENERATED_FILE_BYTES = 256_000
MCP_READ_TASK_KINDS = frozenset({
    "workflow.debug", "table.freshness", "confluence.search", "confluence.read", "jira.search", "jira.read",
})
MUTATION_TASK_KINDS = frozenset({"calc.create", "calc.attribute", "mail.integration"})


@dataclass(frozen=True)
class GeneratedFile:
    path: str
    artifact_kind: str
    content: str
    expected_sha256: str | None = None

    def __post_init__(self) -> None:
        path = Path(self.path)
        if (
            not _SAFE_PATH.fullmatch(self.path) or path.is_absolute() or ".." in path.parts
            or self.artifact_kind not in {"production", "test", "history", "config", "documentation"}
            or not self.content or len(self.content.encode("utf-8")) > _MAX_GENERATED_FILE_BYTES
        ):
            raise ValueError("generated file contract is invalid")
        if inspect_text(self.content).outcome != "allow":
            raise ValueError("generated file content failed privacy gate")


def _freeze(value: Mapping[str, object]) -> Mapping[str, object]:
    return MappingProxyType(json.loads(json.dumps(dict(value), sort_keys=True)))


@dataclass(frozen=True)
class AgentExecutionRequest:
    task_kind: str
    trace_id: str
    inputs: Mapping[str, object]

    def __post_init__(self) -> None:
        if not _TASK_KIND.fullmatch(self.task_kind) or not _TRACE_ID.fullmatch(self.trace_id):
            raise ValueError("agent execution identity is invalid")
        if not isinstance(self.inputs, Mapping):
            raise ValueError("agent execution inputs must be an object")
        object.__setattr__(self, "inputs", _freeze(self.inputs))


@dataclass(frozen=True)
class AgentExecutionContext:
    repository: Path
    state_root: Path
    principal: Principal
    route: WorkResult
    governance: GovernancePolicy | None = None
    product_root: Path | None = None

    def __post_init__(self) -> None:
        repository = Path(self.repository).resolve(strict=True)
        product_root = Path(self.product_root or repository).resolve(strict=True)
        state_root = Path(self.state_root).resolve(strict=True)
        if not repository.is_dir() or repository.is_symlink():
            raise ValueError("agent execution repository is invalid")
        metadata = state_root.lstat()
        owner_ok = not hasattr(metadata, "st_uid") or not hasattr(__import__("os"), "getuid")
        if hasattr(__import__("os"), "getuid"):
            owner_ok = metadata.st_uid == __import__("os").getuid()
        if not state_root.is_dir() or state_root.is_symlink() or stat.S_IMODE(metadata.st_mode) != 0o700 or not owner_ok:
            raise ValueError("agent execution state must be owner-private")
        if self.route.status != "ready":
            raise ValueError("agent execution route is not ready")
        if (
            self.route.principal_id != self.principal.id
            or self.route.role != self.principal.role
        ):
            raise PermissionError("agent execution principal does not match route")
        if not product_root.is_dir() or product_root.is_symlink() or not product_root.is_relative_to(repository):
            raise ValueError("agent execution product root is invalid")
        governance = self.governance or GovernancePolicy.from_repository(product_root)
        if governance.project_id != self.principal.project_id:
            raise PermissionError("agent execution governance scope mismatch")
        object.__setattr__(self, "repository", repository)
        object.__setattr__(self, "state_root", state_root)
        object.__setattr__(self, "governance", governance)
        object.__setattr__(self, "product_root", product_root)


@dataclass(frozen=True)
class AgentExecutionResult:
    task_kind: str
    trace_id: str
    skill_ref: str
    status: str
    reason_code: str
    output: Mapping[str, object]
    changed_paths: tuple[str, ...] = ()
    side_effect: bool = False
    network_used: bool = False

    def __post_init__(self) -> None:
        if self.status not in {"completed", "blocked"} or not self.reason_code:
            raise ValueError("agent execution result is invalid")
        if any(
            not _SAFE_PATH.fullmatch(path) or path.startswith(("/", "../")) or "/../" in path
            for path in self.changed_paths
        ):
            raise ValueError("agent execution changed path is unsafe")
        if self.side_effect != bool(self.changed_paths):
            raise ValueError("agent execution side effect does not match changed paths")
        object.__setattr__(self, "output", _freeze(self.output))
        object.__setattr__(self, "changed_paths", tuple(self.changed_paths))

    def to_payload(self) -> dict[str, object]:
        return {
            "schema_version": "1.0",
            "task_kind": self.task_kind,
            "trace_id": self.trace_id,
            "skill_ref": self.skill_ref,
            "status": self.status,
            "reason_code": self.reason_code,
            "output": dict(self.output),
            "changed_paths": list(self.changed_paths),
            "side_effect": self.side_effect,
            "network_used": self.network_used,
        }


class AgentExecutor(ABC):
    task_kind: str
    required_capabilities: tuple[str, ...]
    mutates_repository: bool = False

    @abstractmethod
    def execute(self, request: AgentExecutionRequest, context: AgentExecutionContext) -> AgentExecutionResult:
        """Выполняет один exact task kind в bounded context."""

    def result(
        self,
        request: AgentExecutionRequest,
        context: AgentExecutionContext,
        *,
        status: str,
        reason_code: str,
        output: Mapping[str, object],
        changed_paths: tuple[str, ...] = (),
        network_used: bool = False,
    ) -> AgentExecutionResult:
        skill_ref = context.route.skills[0] if context.route.skills else ""
        return AgentExecutionResult(
            request.task_kind,
            request.trace_id,
            skill_ref,
            status,
            reason_code,
            output,
            changed_paths,
            bool(changed_paths),
            network_used,
        )


def _execute_reviewed_patch(
    executor: AgentExecutor, request: AgentExecutionRequest, context: AgentExecutionContext,
    files: tuple[GeneratedFile, ...], patch: MutationPatch,
) -> AgentExecutionResult:
    applied = patch.apply()
    repository_rolled_back = False
    retained_evidence_recorded = False
    try:
        changed_paths = applied.changed_paths
        review_request, review_result = ChangedFilesReviewRunner(
        patch.repository, local_audit_key_from_env(),
        ).review_context(frozenset(changed_paths), frozenset(
            item.path for item in files if item.artifact_kind in {"production", "config"}
        ))
        docs_automation = DocumentationAutomation.from_repository(context.product_root)
        docs = docs_automation.check_all().to_payload()
        docs_blocked = int(docs.get("blocked", 0)) > 0
        target_current = (
            docs_automation.plan(str(request.inputs["document_id"])).status == "current"
            if executor.task_kind == "documentation.sync" else True
        )
        approved = review_result.receipt.status == "passed" and not docs_blocked and target_current
        catalog = load_agent_catalog(load_project_profile(context.product_root / "project-profile.yaml"))
        docs_digest = documentation_evidence_digest(docs)
        if approved:
            evidence = ReviewEvidenceLoop(context.state_root, local_audit_key_from_env()).record(
                review_request, review_result, catalog.digest, context.principal, "retained", docs_digest,
            )
            retained_evidence_recorded = True
            applied.finalize()
        else:
            applied.rollback()
            repository_rolled_back = True
            evidence = ReviewEvidenceLoop(context.state_root, local_audit_key_from_env()).record(
                review_request, review_result, catalog.digest, context.principal, "rolled-back", docs_digest,
            )
        return executor.result(
            request, context, status="completed" if approved else "blocked",
            reason_code="mutation_reviewed" if approved else (
                "documentation_impact_blocked" if docs_blocked or not target_current else "mutation_review_blocked"
            ),
            output={
                "patch_digest": "sha256:" + hashlib.sha256("".join(
                    item.path + "\0" + item.content for item in files
                ).encode()).hexdigest(),
                "review": review_result.to_payload(), "provenance_receipt": evidence.provenance.to_payload(),
                "documentation_impact": docs,
                "evidence_receipt": evidence.to_payload(), "proposed_paths": list(changed_paths),
            }, changed_paths=changed_paths if approved else (),
        )
    except Exception:
        if not repository_rolled_back and not retained_evidence_recorded:
            applied.rollback()
        raise


class _UnavailableExecutor(AgentExecutor):
    def __init__(self, task_kind: str, capabilities: tuple[str, ...]) -> None:
        self.task_kind = task_kind
        self.required_capabilities = capabilities

    def execute(self, request: AgentExecutionRequest, context: AgentExecutionContext) -> AgentExecutionResult:
        return self.result(
            request,
            context,
            status="blocked",
            reason_code="runtime_adapter_unavailable",
            output={"handler": "not-configured"},
        )


class RepositoryEvidenceExecutor(AgentExecutor):
    """Выполняет bounded repository-only read tasks без shell и сети."""

    def __init__(self, task_kind: str, capabilities: tuple[str, ...]) -> None:
        self.task_kind = task_kind
        self.required_capabilities = capabilities

    def execute(self, request: AgentExecutionRequest, context: AgentExecutionContext) -> AgentExecutionResult:
        needle = str(
            request.inputs.get("target")
            or request.inputs.get("source")
            or request.inputs.get("dag_id")
            or request.inputs.get("table")
            or ""
        ).casefold()
        matches = []
        for path in sorted(context.repository.rglob("*")):
            if len(matches) >= 50:
                break
            if path.is_symlink() or not path.is_file() or path.suffix not in {".py", ".sql", ".json", ".yaml", ".yml"}:
                continue
            relative = path.relative_to(context.repository).as_posix()
            if needle and needle in relative.casefold():
                matches.append(relative)
        reason = "repository_evidence_found" if matches else "repository_evidence_boundary"
        return self.result(
            request,
            context,
            status="completed",
            reason_code=reason,
            output={"evidence_paths": matches, "evidence_count": len(matches), "external_runtime_used": False},
        )


class AuthenticatedMcpReadExecutor(AgentExecutor):
    """Делегирует только attested read capability во внедрённый audited MCP Hub."""

    def __init__(
        self, task_kind: str, capabilities: tuple[str, ...], hub: AuditedMcpHub, token: str,
        capability_id: str, argument_names: tuple[str, ...],
    ) -> None:
        if not token:
            raise ValueError("authenticated MCP session is required")
        self.task_kind = task_kind
        self.required_capabilities = capabilities
        self.hub = hub
        self.token = token
        self.capability_id = capability_id
        self.argument_names = argument_names

    def execute(self, request: AgentExecutionRequest, context: AgentExecutionContext) -> AgentExecutionResult:
        arguments = {name: request.inputs[name] for name in self.argument_names if name in request.inputs}
        if "limit" in self.argument_names and "limit" not in arguments:
            arguments = {**arguments, "limit": 20}
        privacy = PrivacyContext(
            context.principal.project_id, request.trace_id, context.principal.id,
            "engineering-change", "local", False, 900,
        )
        result = self.hub.execute(self.token, McpRequest(
            context.principal.project_id, "engineering-change", self.capability_id, "1.0.0",
            arguments, "internal", request.trace_id,
        ), privacy)
        if result.status != "ok" or result.data is None or result.receipt.operation != "read":
            return self.result(
                request, context, status="blocked", reason_code=result.receipt.reason_code,
                output={"mcp_receipt": result.receipt.to_payload()}, network_used=True,
            )
        return self.result(
            request, context, status="completed", reason_code="authenticated_mcp_read",
            output={
                "data": dict(result.data), "content_trust": "untrusted_external_data",
                "instruction_authority": False, "mcp_receipt": result.receipt.to_payload(),
            },
            network_used=True,
        )


class RepositoryMutationExecutor(AgentExecutor):
    """Атомарно создаёт bounded files и фиксирует review/docs/provenance evidence."""

    mutates_repository = True

    def _execute_applied_patch(
        self, request: AgentExecutionRequest, context: AgentExecutionContext,
        files: tuple[GeneratedFile, ...], patch: MutationPatch,
    ) -> AgentExecutionResult:
        return _execute_reviewed_patch(self, request, context, files, patch)

    def __init__(self, task_kind: str, capabilities: tuple[str, ...], required_kinds: frozenset[str]) -> None:
        self.task_kind = task_kind
        self.required_capabilities = capabilities
        self.required_kinds = required_kinds

    @classmethod
    def calc_create(cls) -> RepositoryMutationExecutor:
        return cls(
            "calc.create", ("repository.read", "repository.write", "airflow.validate", "lineage.read"),
            frozenset({"production", "test", "history"}),
        )

    def generated_files(self, inputs: Mapping[str, object]) -> tuple[GeneratedFile, ...]:
        changes = inputs.get("changes")
        if not isinstance(changes, (list, tuple)) or not 1 <= len(changes) <= 20:
            raise ValueError("generated changes are required")
        files = tuple(GeneratedFile(
            item["path"], item["artifact_kind"], item["content"], item.get("expected_sha256"),
        )
                      for item in changes if isinstance(item, Mapping))
        if len(files) != len(changes) or len({item.path for item in files}) != len(files):
            raise ValueError("generated changes must have unique closed entries")
        if self.required_kinds and {item.artifact_kind for item in files} != self.required_kinds:
            raise ValueError("generated changes artifact set is incomplete")
        if self.task_kind == "calc.create":
            calc_id = str(inputs.get("calc_id", ""))
            dag_id = "calc_" + calc_id.removeprefix("calc")
            roots = (
                f"etl/airflow2/pyspark/{calc_id}/",
                f"etl/airflow2/dag_factory/configs/{dag_id}/",
                f"etl/airflow2/dags/{dag_id}",
            )
            exact_dags = {
                f"etl/airflow2/dags/{dag_id}.py", f"etl/airflow2/dags/{dag_id}_test.py",
                f"etl/airflow2/dags/{dag_id}_history.py",
            }
            if any(
                item.path.startswith("etl/airflow2/dags/") and item.path not in exact_dags
                or not item.path.startswith(roots)
                for item in files
            ):
                raise ValueError("calc mutation path is outside exact calc surface")
            paths = {item.path for item in files}
            mandatory = {
                f"etl/airflow2/pyspark/{calc_id}/calc.py",
                f"etl/airflow2/pyspark/{calc_id}/config.json",
                f"etl/airflow2/pyspark/{calc_id}/config_test.json",
                f"etl/airflow2/dags/{dag_id}_history.py",
            }
            manual = {f"etl/airflow2/dags/{dag_id}.py", f"etl/airflow2/dags/{dag_id}_test.py"}
            factory = {
                f"etl/airflow2/dag_factory/configs/{dag_id}/{dag_id}.yaml",
                f"etl/airflow2/dag_factory/configs/{dag_id}/{dag_id}_test.yaml",
            }
            delivery_modes = sum(candidate <= paths for candidate in (manual, factory))
            if not mandatory <= paths or delivery_modes != 1 or bool(manual & paths) == bool(factory & paths):
                raise ValueError("calc mutation delivery bundle is incomplete or mixed")
            by_path = {item.path: item for item in files}
            if (
                by_path[f"etl/airflow2/pyspark/{calc_id}/calc.py"].artifact_kind != "production"
                or
                by_path[f"etl/airflow2/pyspark/{calc_id}/config.json"].artifact_kind != "production"
                or by_path[f"etl/airflow2/pyspark/{calc_id}/config_test.json"].artifact_kind != "test"
                or by_path[f"etl/airflow2/dags/{dag_id}_history.py"].artifact_kind != "history"
            ):
                raise ValueError("calc mutation artifact roles do not match exact paths")
            test_files = tuple(item for item in files if item.artifact_kind == "test")
            history = by_path[f"etl/airflow2/dags/{dag_id}_history.py"].content.casefold()
            if any("schedule" in item.content.casefold() and "none" not in item.content.casefold()
                   and "null" not in item.content.casefold() for item in test_files):
                raise ValueError("calc test artifact must have disabled schedule")
            if "config_test.json" in history:
                raise ValueError("calc history must use production config")
        elif self.task_kind == "calc.attribute":
            calc_id = str(inputs.get("calc_id", ""))
            dag_id = "calc_" + calc_id.removeprefix("calc")
            allowed_dags = {
                f"etl/airflow2/dags/{dag_id}.py", f"etl/airflow2/dags/{dag_id}_test.py",
                f"etl/airflow2/dags/{dag_id}_history.py",
            }
            allowed_prefixes = (
                f"etl/airflow2/pyspark/{calc_id}/", f"etl/airflow2/dag_factory/configs/{dag_id}/",
            )
            if any(item.path not in allowed_dags and not item.path.startswith(allowed_prefixes) for item in files):
                raise ValueError("calc attribute mutation is outside exact calc surface")
            kinds = {item.artifact_kind for item in files}
            if not {"production", "test", "history"} <= kinds:
                raise ValueError("calc attribute requires paired production, test and history impact")
            if any(item.expected_sha256 is None for item in files if item.artifact_kind != "documentation"):
                raise ValueError("calc attribute updates require exact old digests")
            exact_roles = {
                f"etl/airflow2/pyspark/{calc_id}/calc.py": "production",
                f"etl/airflow2/pyspark/{calc_id}/config.json": "production",
                f"etl/airflow2/pyspark/{calc_id}/config_test.json": "test",
                f"etl/airflow2/dags/{dag_id}.py": "production",
                f"etl/airflow2/dags/{dag_id}_test.py": "test",
                f"etl/airflow2/dags/{dag_id}_history.py": "history",
            }
            if any(item.path in exact_roles and item.artifact_kind != exact_roles[item.path] for item in files):
                raise ValueError("calc attribute artifact role does not match exact path")
        elif self.task_kind == "mail.integration":
            allowed_roots = (
                "etl/docker/utility/mail_loader_v2/",
                "etl/airflow2/dag_factory/configs/",
                "etl/airflow2/dags/",
                "datamodel/",
            )
            if any(not item.path.startswith(allowed_roots) for item in files):
                raise ValueError("mail mutation is outside approved delivery surface")
            integration_id = str(inputs.get("integration_id", ""))
            config_path = "etl/docker/utility/mail_loader_v2/config/config.json"
            if not re.fullmatch(r"[a-z][a-z0-9_]{2,63}", integration_id):
                raise ValueError("mail integration identity is invalid")
            allowed_stems = {integration_id, f"{integration_id}_test", f"{integration_id}_history"}
            if any(item.path != config_path and Path(item.path).stem not in allowed_stems for item in files):
                raise ValueError("mail delivery path is not bound to integration identity")
            config = next((item for item in files if item.path == config_path), None)
            if config is None:
                raise ValueError("mail loader config is required")
            proposed = json.loads(config.content)
            entities = proposed.get("entities") if isinstance(proposed, dict) else None
            appended = entities[-1] if isinstance(entities, list) and entities else None
            entity_id = appended.get("id") if isinstance(appended, dict) else None
            if entity_id != integration_id:
                raise ValueError("mail appended entity is not bound to integration identity")
            if str(inputs.get("delivery_scope")) == "full_delivery":
                kinds = {item.artifact_kind for item in files}
                if not {"config", "production", "test"} <= kinds:
                    raise ValueError("full mail delivery requires config, production and test artifacts")
        return files

    def mutation_patch(
        self, inputs: Mapping[str, object], context: AgentExecutionContext, files: tuple[GeneratedFile, ...],
    ) -> MutationPatch:
        """Builds the shared crash-recoverable patch for every repository mutation."""

        specs = tuple(MutationSpec(
            item.path, item.artifact_kind, item.content, item.expected_sha256,
        ) for item in files)
        journal = context.state_root / "repository-mutation.pending.json"
        if self.task_kind == "mail.integration":
            return MutationPatch.for_mail(context.repository, str(inputs["delivery_scope"]), specs, journal)
        return MutationPatch(context.repository, specs, journal=journal)

    def execute(self, request: AgentExecutionRequest, context: AgentExecutionContext) -> AgentExecutionResult:
        files = self.generated_files(request.inputs)
        return self._execute_applied_patch(request, context, files, self.mutation_patch(request.inputs, context, files))


class DocumentationSyncExecutor(AgentExecutor):
    """Runs schema-backed documentation generation through the mutation lifecycle."""

    task_kind = "documentation.sync"
    required_capabilities = ("repository.read", "repository.write", "docs.generate")
    mutates_repository = True

    def _execute_applied_patch(
        self, request: AgentExecutionRequest, context: AgentExecutionContext,
        files: tuple[GeneratedFile, ...], patch: MutationPatch,
    ) -> AgentExecutionResult:
        return _execute_reviewed_patch(self, request, context, files, patch)

    @staticmethod
    def require_governance(context: AgentExecutionContext) -> None:
        context.governance.require(context.principal, "docs.sync")

    def execute(self, request: AgentExecutionRequest, context: AgentExecutionContext) -> AgentExecutionResult:
        self.require_governance(context)
        document_id = str(request.inputs["document_id"])
        automation = DocumentationAutomation.from_repository(context.product_root)
        plan = automation.plan(document_id)
        if plan.status == "blocked":
            return self.result(
                request, context, status="blocked", reason_code="documentation_quality_blocked",
                output={"document_id": document_id, "reason_codes": list(plan.reason_codes)},
            )
        if plan.status == "current":
            return self.result(
                request, context, status="completed", reason_code="documentation_current",
                output={"document_id": document_id, "source_digest": plan.source_digest, "changed": False},
            )
        path = automation.target_path(document_id)
        if automation.source_digest(document_id) != plan.source_digest:
            raise PermissionError("documentation source changed after generation")
        generated = GeneratedFile(path, "documentation", plan.updated_document, plan.document_digest)
        patch = MutationPatch(context.product_root, (
            MutationSpec(path, "documentation", plan.updated_document, plan.document_digest),
        ), journal=context.state_root / "repository-mutation.pending.json")
        result = self._execute_applied_patch(request, context, (generated,), patch)
        return AgentExecutionResult(
            result.task_kind, result.trace_id, result.skill_ref, result.status, result.reason_code,
            {**dict(result.output), "document_id": document_id, "source_digest": plan.source_digest},
            result.changed_paths, result.side_effect, result.network_used,
        )


class ConfluenceSnapshotExecutor(AgentExecutor):
    """Captures one configured external page through an authenticated audited Hub."""

    task_kind = "confluence.snapshot"
    required_capabilities = ("confluence.read", "docs.snapshot")

    def __init__(self, hub: AuditedMcpHub, token: str) -> None:
        self.hub, self.token = hub, token

    def execute(self, request: AgentExecutionRequest, context: AgentExecutionContext) -> AgentExecutionResult:
        document_id = str(request.inputs["document_id"])
        configured, classification, _ = configured_source(context.product_root, document_id)
        privacy = PrivacyContext(
            context.principal.project_id, request.trace_id, context.principal.id,
            "documentation-snapshot", "local", False, 900,
        )
        result = self.hub.execute(self.token, McpRequest(
            context.principal.project_id, "documentation-snapshot", "confluence.get_page", "1.0.0",
            {"space_key": configured.space_key, "page_id": configured.page_id}, "internal", request.trace_id,
        ), privacy)
        if result.status != "ok" or result.data is None or result.receipt.operation != "read":
            return self.result(request, context, status="blocked", reason_code="snapshot_source_denied", output={})
        data = dict(result.data)
        if data.get("content_trust") != "untrusted_external_data":
            raise PermissionError("external documentation trust label is missing")
        receipt_digest = "sha256:" + hashlib.sha256(
            json.dumps(result.receipt.to_payload(), sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        store = DocumentationSnapshotStore(context.state_root, local_audit_key_from_env())
        receipt = store.capture(
            document_id, SnapshotSource(configured.space_key, configured.page_id, int(data["version"])),
            str(data["text"]), classification, request.trace_id, context.principal.id, receipt_digest,
        )
        return self.result(
            request, context, status="completed", reason_code="documentation_snapshot_captured",
            output=receipt.to_payload(), network_used=True,
        )


class DocumentationFromSnapshotExecutor(DocumentationSyncExecutor):
    """Renders an attested snapshot as data through the documentation mutation lifecycle."""

    task_kind = "documentation.from-snapshot"
    required_capabilities = ("repository.read", "repository.write", "docs.generate", "docs.snapshot.read")

    def execute(self, request: AgentExecutionRequest, context: AgentExecutionContext) -> AgentExecutionResult:
        self.require_governance(context)
        store = DocumentationSnapshotStore(context.state_root, local_audit_key_from_env())
        snapshot = store.load(
            str(request.inputs["snapshot_id"]), str(request.inputs["snapshot_digest"]),
            str(request.inputs["document_id"]), context.principal.id,
        )
        configured, classification, section = configured_source(context.product_root, snapshot.document_id)
        if (
            snapshot.source.space_key != configured.space_key or snapshot.source.page_id != configured.page_id
            or snapshot.classification != classification or snapshot.instruction_authority
        ):
            raise PermissionError("documentation snapshot binding mismatch")
        automation = DocumentationAutomation.from_repository(context.product_root)
        path = automation.target_path(snapshot.document_id)
        target = context.product_root / path
        before = target.read_text(encoding="utf-8")
        before_digest = automation.document_digest(snapshot.document_id)
        updated = render_snapshot_section(before, section, snapshot)
        store.reserve(snapshot.snapshot_id, str(request.inputs["snapshot_digest"]), context.principal.id)
        if updated == before:
            store.consume(snapshot.snapshot_id, str(request.inputs["snapshot_digest"]), context.principal.id)
            return self.result(
                request, context, status="completed", reason_code="documentation_snapshot_current",
                output={
                    "document_id": snapshot.document_id, "snapshot_id": snapshot.snapshot_id,
                    "snapshot_content_digest": snapshot.content_digest, "changed": False,
                },
            )
        generated = GeneratedFile(path, "documentation", updated, before_digest)
        patch = MutationPatch(context.product_root, (
            MutationSpec(path, "documentation", updated, before_digest),
        ), journal=context.state_root / "repository-mutation.pending.json")
        try:
            result = self._execute_applied_patch(request, context, (generated,), patch)
            if result.status == "completed":
                store.consume(snapshot.snapshot_id, str(request.inputs["snapshot_digest"]), context.principal.id)
            else:
                store.release(snapshot.snapshot_id)
        except Exception:
            store.release(snapshot.snapshot_id)
            raise
        return AgentExecutionResult(
            result.task_kind, result.trace_id, result.skill_ref, result.status, result.reason_code,
            {
                **dict(result.output), "document_id": snapshot.document_id,
                "snapshot_id": snapshot.snapshot_id, "snapshot_content_digest": snapshot.content_digest,
                "mcp_receipt_digest": snapshot.mcp_receipt_digest,
            },
            result.changed_paths, result.side_effect, result.network_used,
        )


class ReviewTargetedClosureAgentExecutor(AgentExecutor):
    """Runs a network-free, one-time targeted re-review with repository drift guards."""

    task_kind = "review.targeted-closure"
    required_capabilities = ("repository.read",)

    def execute(self, request: AgentExecutionRequest, context: AgentExecutionContext) -> AgentExecutionResult:
        key = local_audit_key_from_env()
        catalog = load_agent_catalog(load_project_profile(context.product_root / "project-profile.yaml"))
        bindings_digest = "sha256:" + hashlib.sha256(json.dumps({
            "spec_version": "draft-0.1", "policy_version": "1.0", "skill_versions": ("review-engine:1.0.0",),
        }, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        paths = frozenset(str(item) for item in request.inputs["targeted_paths"])
        runner = ChangedFilesReviewRunner(context.repository, key)

        def review(
            selected: frozenset[str], findings: tuple[str, ...], parent_provenance_digest: str,
        ) -> Mapping[str, object]:
            review_request, review_result = runner.review_targeted_context(selected, frozenset(), findings)
            provenance = DurableReviewFoundation(ReviewProvenanceStore(
                context.state_root / "review-provenance.sqlite3", key,
            )).record(review_request, review_result, agent_catalog_digest=catalog.digest)
            return {
                "status": review_result.receipt.status,
                "open_finding_keys": review_result.receipt.open_finding_keys,
                "closed_finding_keys": review_result.receipt.closed_finding_keys,
                "diff_digest": review_result.receipt.diff_digest, "provenance_digest": provenance.record_digest,
                "parent_provenance_digest": parent_provenance_digest,
            }

        outcome = TargetedReviewClosureExecutor(ReviewClosureContextStore(context.state_root, key), review).execute(
            str(request.inputs["parent_review_id"]), str(request.inputs["context_digest"]),
            context.principal.id, context.principal.project_id, paths,
            WorktreeBaseline.capture_tree(context.repository, key), catalog.digest, bindings_digest,
        )
        return self.result(
            request, context, status="completed" if outcome["status"] == "passed" else "blocked",
            reason_code=str(outcome["reason_code"]), output=dict(outcome),
        )

@dataclass(frozen=True)
class AgentExecutionRegistry:
    repository: Path
    releases: Mapping[str, SkillRelease]
    executors: Mapping[str, AgentExecutor]
    blocked_task_kinds: tuple[str, ...] = ()
    metrics: EfficiencyMetricsStore | None = None

    @classmethod
    def from_repository(
        cls,
        repository: Path,
        executors: tuple[AgentExecutor, ...],
    ) -> AgentExecutionRegistry:
        root = Path(repository).resolve(strict=True)
        profile = load_project_profile(root / "project-profile.yaml")
        if profile.skill_approvals is None:
            if profile.pack.approved_skill_order:
                raise ValueError("agent execution requires skill approvals")
            releases = MappingProxyType({})
        else:
            approvals = RepositorySkillApprovalRegistry.from_file(profile.skill_approvals)
            library = load_skill_library(profile.skills_root, approvals.verify)
            releases = MappingProxyType({f"{item.id}@{item.version}": item for item in library.releases})
        executor_map = {item.task_kind: item for item in executors}
        if len(executor_map) != len(executors) or any(not _TASK_KIND.fullmatch(item) for item in executor_map):
            raise ValueError("agent executor registry is invalid")
        blocked = tuple(sorted(item.task_kind for item in executors if isinstance(item, _UnavailableExecutor)))
        return cls(root, releases, MappingProxyType(executor_map), blocked)

    @classmethod
    def builtin(
        cls, repository: Path, *, mcp_hub: AuditedMcpHub | None = None, mcp_token: str = "",
        metrics: EfficiencyMetricsStore | None = None,
    ) -> AgentExecutionRegistry:
        capabilities = {
            "calc.create": ("repository.read", "repository.write", "airflow.validate", "lineage.read"),
            "workflow.debug": ("repository.read", "airflow.read"),
            "table.freshness": ("repository.read", "warehouse.metadata.read", "airflow.read"),
            "lineage.upstream": ("repository.read", "lineage.read", "warehouse.metadata.read"),
            "lineage.downstream": ("repository.read", "lineage.read", "warehouse.metadata.read"),
            "review.changed-files": ("repository.read",),
            "review.targeted-closure": ("repository.read",),
            "calc.attribute": ("repository.read", "repository.write", "airflow.validate", "lineage.read"),
            "mail.integration": ("repository.read", "repository.write", "airflow.validate"),
            "confluence.search": ("confluence.read",),
            "confluence.read": ("confluence.read",),
            "jira.search": ("jira.read",),
            "jira.read": ("jira.read",),
            "documentation.sync": ("repository.read", "repository.write", "docs.generate"),
            "confluence.snapshot": ("confluence.read", "docs.snapshot"),
            "documentation.from-snapshot": (
                "repository.read", "repository.write", "docs.generate", "docs.snapshot.read",
            ),
        }
        mcp_specs = {
            "workflow.debug": ("airflow.list_dag_runs", ("dag_id", "limit")),
            "table.freshness": ("airflow.list_dags", ("limit",)),
            "confluence.search": ("confluence.search_pages", ("query", "space_key", "limit")),
            "confluence.read": ("confluence.get_page", ("space_key", "page_id")),
            "jira.search": ("jira.search_issues", ("project_key", "query", "limit")),
            "jira.read": ("jira.get_issue", ("issue_key",)),
        }
        executors: list[AgentExecutor] = []
        for task_kind, required in capabilities.items():
            if task_kind == "calc.create":
                executor: AgentExecutor = RepositoryMutationExecutor.calc_create()
            elif task_kind == "documentation.sync":
                executor = DocumentationSyncExecutor()
            elif task_kind == "confluence.snapshot":
                executor = _UnavailableExecutor(task_kind, required) if mcp_hub is None else ConfluenceSnapshotExecutor(
                    mcp_hub, mcp_token,
                )
            elif task_kind == "documentation.from-snapshot":
                executor = DocumentationFromSnapshotExecutor()
            elif task_kind in {"calc.attribute", "mail.integration"}:
                executor = RepositoryMutationExecutor(task_kind, required, frozenset())
            elif task_kind in mcp_specs:
                if mcp_hub is None:
                    executor = _UnavailableExecutor(task_kind, required)
                else:
                    capability_id, argument_names = mcp_specs[task_kind]
                    executor = AuthenticatedMcpReadExecutor(
                        task_kind, required, mcp_hub, mcp_token, capability_id, argument_names,
                    )
            elif task_kind == "review.changed-files":
                executor = _UnavailableExecutor(task_kind, required)
            elif task_kind == "review.targeted-closure":
                executor = ReviewTargetedClosureAgentExecutor()
            else:
                executor = RepositoryEvidenceExecutor(task_kind, required)
            executors.append(executor)
        registry = cls.from_repository(
            repository,
            tuple(executors),
        )
        return cls(registry.repository, registry.releases, registry.executors, registry.blocked_task_kinds, metrics)

    @property
    def task_kinds(self) -> tuple[str, ...]:
        return tuple(sorted(self.executors))

    def execute(
        self,
        request: AgentExecutionRequest,
        context: AgentExecutionContext,
    ) -> AgentExecutionResult:
        if request.task_kind != context.route.task_kind:
            raise PermissionError("agent execution task does not match route")
        executor = self.executors.get(request.task_kind)
        if executor is None:
            raise PermissionError("agent executor is not registered")
        if tuple(executor.required_capabilities) != tuple(context.route.required_capabilities):
            raise PermissionError("agent executor capability drift")
        release = None
        if context.route.skills:
            if len(context.route.skills) != 1:
                raise PermissionError("agent execution requires one approved skill")
            release = self.releases.get(context.route.skills[0])
            if release is None or release.status != "approved" or not release.integrity_verified:
                raise PermissionError("agent execution skill is not approved")
            self._validate_inputs(release, request.inputs)
        elif load_project_profile(self.repository / "project-profile.yaml").skill_approvals is not None:
            raise PermissionError("agent execution requires one approved skill")
        result = executor.execute(request, context)
        expected_skill_ref = context.route.skills[0] if context.route.skills else ""
        if result.task_kind != request.task_kind or result.skill_ref != expected_skill_ref:
            raise RuntimeError("agent executor returned unbound result")
        if result.side_effect and not executor.mutates_repository:
            raise RuntimeError("agent executor side effect contract mismatch")
        if (
            executor.mutates_repository and result.status == "completed" and not result.side_effect
            and result.reason_code not in {"documentation_current", "documentation_snapshot_current"}
        ):
            raise RuntimeError("completed mutation returned no changed paths")
        if self.metrics is not None:
            findings = _count_review_findings(result.output)
            self.metrics.append(EfficiencyMetricEvent(
                agents_invoked=1, skills_invoked=1 if context.route.skills else 0, review_findings=findings, runs=1,
                first_run_successes=1 if result.status == "completed" else 0,
            ))
        return result

    def _validate_inputs(self, release: SkillRelease, inputs: Mapping[str, object]) -> None:
        package = load_project_profile(self.repository / "project-profile.yaml").skills_root / release.id
        schema_path = (package / release.inputs_schema).resolve(strict=True)
        if not schema_path.is_relative_to(package) or schema_path.is_symlink():
            raise ValueError("agent input schema path is unsafe")
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        if not _validate_value(schema, inputs):
            raise ValueError("agent execution inputs do not match skill schema")


def _count_review_findings(value: object) -> int:
    if isinstance(value, Mapping):
        total = 0
        for key, item in value.items():
            if key == "finding_counts" and isinstance(item, Mapping):
                total += sum(counter for counter in item.values() if isinstance(counter, int) and counter >= 0)
            else:
                total += _count_review_findings(item)
        return total
    if isinstance(value, (list, tuple)):
        return sum(_count_review_findings(item) for item in value)
    return 0


def _validate_value(schema: object, value: object) -> bool:
    if not isinstance(schema, Mapping):
        return False
    value_type = schema.get("type")
    if value_type == "object":
        if not isinstance(value, Mapping):
            return False
        properties, required = schema.get("properties"), schema.get("required")
        if not isinstance(properties, Mapping) or not isinstance(required, list):
            return False
        if set(value) - set(properties) or any(item not in value for item in required):
            return False
        return all(_validate_value(properties[key], item) for key, item in value.items())
    if value_type == "string":
        if not isinstance(value, str):
            return False
        if not schema.get("minLength", 0) <= len(value) <= schema.get("maxLength", len(value)):
            return False
        pattern = schema.get("pattern")
        return pattern is None or isinstance(pattern, str) and re.fullmatch(pattern, value) is not None
    if value_type == "integer":
        return bool(
            isinstance(value, int)
            and not isinstance(value, bool)
            and schema.get("minimum", value) <= value <= schema.get("maximum", value)
        )
    if value_type == "array":
        if not isinstance(value, (list, tuple)):
            return False
        if not schema.get("minItems", 0) <= len(value) <= schema.get("maxItems", len(value)):
            return False
        return all(_validate_value(schema.get("items"), item) for item in value)
    if "enum" in schema:
        return value in schema["enum"]
    return False
