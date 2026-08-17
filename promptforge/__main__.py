"""Локальная demo-точка входа PromptForge Platform."""

from __future__ import annotations

import getpass
import hashlib
import hmac
import json
import os
import re
import secrets
import stat
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace

from promptforge.platform.auth import (
    AuthentikAuthenticator, EmbeddedRoleRegistry, EmbeddedSessionAuthenticator, FakeOIDCTokenVerifier, OIDCClaims,
    embedded_auth_key_from_env,
)
from promptforge.platform.catalog import builtin_skill_catalog, catalog_from_project_profile, catalog_from_skill_library
from promptforge.platform.contracts import ModelRequest, PolicyRequest, Principal
from promptforge.platform.gateway import (
    FakeProviderAdapter,
    GatewayReceipt,
    LogicalModel,
    ModelEndpoint,
    ModelGateway,
    ModelRegistry,
)
from promptforge.platform.health import health_payload
from promptforge.platform.policy import PolicyEngine
from promptforge.platform.privacy import PrivacyContext, PrivacyPipeline, ScopedMappingVault
from promptforge.platform.mcp_hub import (
    ApprovalStore,
    FakeMcpAdapter,
    McpAdapterCall,
    McpCapability,
    McpHub,
    McpRegistry,
    McpRequest,
)
from promptforge.platform.integrations import (
    AirflowMcpAdapter,
    capabilities_for_project_profile,
    ConfluenceMcpAdapter,
    JiraMcpAdapter,
    integration_capabilities,
)
from promptforge.platform.local_inference import LocalInferenceDeployment
from promptforge.platform.local_audit import AuditEvent, LocalAuditStore, local_audit_key_from_env
from promptforge.platform.audit_runtime import AuditedMcpHub
from promptforge.platform.secure_runtime import build_secure_runtime, load_embedded_registry
from promptforge.platform.secure_runtime import build_production_mcp_hub
from promptforge.platform.integration_backends import IntegrationBackendConfig
from promptforge.platform.integration_setup import IntegrationSetupInput, LocalIntegrationProfile, ServiceSetupInput
from promptforge.platform.pilot import build_offline_pilot
from promptforge.platform.changed_review import ChangedFilesReviewRunner
from promptforge.platform.docs_automation import DocumentationAutomation
from promptforge.platform.token_efficiency import ContextItem, TokenBudget, TokenEfficiencyRuntime
from promptforge.platform.token_usage_store import TokenUsageStore
from promptforge.platform.optimized_runtime import OptimizedModelRuntime
from promptforge.platform.operations import LocalKillSwitch, LocalStateCleaner, OperationsConfig
from promptforge.platform.operational_acceptance import OperationalAcceptanceRunner
from promptforge.platform.efficiency_metrics import EfficiencyMetricEvent, EfficiencyMetricsStore
from promptforge.platform.final_evidence import FinalEvidenceRunner
from promptforge.platform.release_candidate import MergeRequestScopeChecker, ReleaseCandidateRunner
from promptforge.platform.git_identity import GitIdentityResolver
from promptforge.platform.release_signing import (
    DetachedReleaseSignature,
    generate_owner_keypair,
    load_json_object,
    sign_release_candidate,
    verify_release_candidate,
    write_private_json,
)
from promptforge.platform.skill_signatures import SkillSigningKeyRegistry
from promptforge.platform.execution_boundary import AuthenticatedExecutionBoundary
from promptforge.platform.neutrality import NeutralityGate, repository_neutrality_extras
from promptforge.platform.governance import GovernancePolicy
from promptforge.platform.model_admission import (
    ModelAdmissionAuthority, ModelAdmissionManifest, ModelEvalMetrics, ModelEvalProvenance,
)
from promptforge.platform.model_admission_workflow import InMemoryApprovalConsumptionStore, ModelAdmissionWorkflow
from promptforge.platform.model_eval import FixtureEvalModel, ModelEvalRunner, ModelEvalSuite
from promptforge.platform.review import (
    CheckEvidence,
    ChangedFile,
    FakeReviewEvidenceVerifier,
    ReviewEngine,
    ReviewRequest,
    diff_digest,
    review_fixture,
)
from promptforge.platform.review_provenance import DurableReviewFoundation, ReviewProvenanceStore
from promptforge.platform.review_evidence_loop import ReviewEvidenceLoop, documentation_evidence_digest
from promptforge.platform.review_closure import ReviewClosureContextStore, WorktreeBaseline
from promptforge.platform.security import inspect_text
from promptforge.platform.skill_library import RepositorySkillApprovalRegistry, load_skill_library, require_skill_evals
from promptforge.core.project_profile import load_project_profile
from promptforge.core.repository_index import RepositoryIndexer
from promptforge.platform.task_router import TaskEnvelope, TaskRouter, load_agent_catalog
from promptforge.platform.unified_ux import UnifiedWorkCoordinator, WorkRequest, WorkResult
from promptforge.platform.production_docs import ProductionDocumentationGate
from promptforge.platform.agent_execution import (
    AgentExecutionContext, AgentExecutionRegistry, AgentExecutionRequest, GeneratedFile, MCP_READ_TASK_KINDS,
    MUTATION_TASK_KINDS,
)
from promptforge.platform.mutation_patch import MutationPatch, MutationSpec
from promptforge.platform.workspace import WorkspaceLifecycle
from promptforge.platform.task_intake import TaskIntake


def _demo() -> dict[str, object]:
    fake_secret = "sk-proj-FAKE-DO-NOT-USE-12345678901234567890"
    engineer = Principal("demo-engineer", "engineer", "promptforge-demo")
    analyst = Principal("demo-analyst", "analyst", "promptforge-demo")
    catalog = builtin_skill_catalog()
    finding = review_fixture(path="validation-assets/example.py", diff=f'+unsafe_value = "{fake_secret}"')
    return {
        "status": "ok",
        "service": "promptforge-platform",
        "catalogs": {
            "engineer": [skill.id for skill in catalog.for_role(engineer.role)],
            "analyst": [skill.id for skill in catalog.for_role(analyst.role)],
        },
        "security": {
            "secret": inspect_text(fake_secret).outcome,
            "synthetic_pii": inspect_text("ivan.testov@example.com +1-202-555-0147").outcome,
        },
        "review": {"findings": len(finding), "severity": finding[0].severity},
    }


def _check() -> dict[str, object]:
    root = Path(__file__).resolve().parents[1]
    schemas = list((root / "schemas" / "v1").glob("*.json"))
    fixtures = json.loads((root / "validation-assets" / "security.json").read_text(encoding="utf-8"))
    if len(schemas) != 66 or not fixtures:
        raise RuntimeError("platform assets are incomplete")
    return {"status": "ok", "schemas": len(schemas), "fixtures": len(fixtures)}


def _project_profile_check() -> dict[str, object]:
    root = Path(__file__).resolve().parents[1]
    profile = load_project_profile(root / "project-profile.yaml")
    configured = frozenset(profile.pack.integrations)
    enabled_capabilities = capabilities_for_project_profile(profile)
    if profile.skill_approvals is None:
        approved = 0
    else:
        registry = RepositorySkillApprovalRegistry.from_file(profile.skill_approvals)
        if registry.ordered_skill_ids != profile.pack.approved_skill_order:
            raise RuntimeError("project pack skill approval order drift")
        approved = len(registry.ordered_skill_ids)
    return {
        "schema_version": "1.0", "status": "ok", "profile_version": "1.0",
        "integrations": len(frozenset(item.server for item in enabled_capabilities)),
        "skills": len(tuple(profile.skills_root.iterdir())),
        "approved_skills": approved, "network_used": False,
    }


def _portable_pack_check() -> dict[str, object]:
    root = Path(__file__).resolve().parents[1]
    profile = load_project_profile(root / "packs" / "core" / "project-profile.yaml")
    catalog = load_agent_catalog(profile)
    route = TaskRouter(profile.project_key, catalog).route(
        TaskEnvelope(
            profile.project_key,
            Principal("portable-engineer", "engineer", profile.project_key),
            "review.changed-files",
            "portable-pack-check",
        )
    )
    if (
        profile.skill_approvals is not None
        or profile.pack.approved_skill_order
        or len(catalog_from_project_profile(profile).skills) != 0
        or route.outcome != "selected"
        or route.reason_code != "exact_task_role_match"
    ):
        raise RuntimeError("portable core pack gate failed")
    return {
        "schema_version": "1.0", "status": "ok", "profile_id": profile.profile_id,
        "project_key": profile.project_key, "agents": len(catalog.agents), "distributed_skills": 0,
        "route_reason": route.reason_code, "network_used": False,
    }


def _repository_index(write: bool = False) -> dict[str, object]:
    product_root = Path(__file__).resolve().parents[1]
    profile = load_project_profile(product_root / "project-profile.yaml")
    repository = product_root.parent
    indexer = RepositoryIndexer(repository, profile.pack.repository_index, profile.project_key)
    index = indexer.build()
    if write:
        indexer.write(index)
    payload = index.to_payload()
    return {
        "schema_version": "1.0",
        "status": "ok",
        "mode": "write" if write else "check",
        "indexed_files": payload["summary"]["files"],
        "indexed_bytes": payload["summary"]["bytes"],
        "index_digest": payload["index_digest"],
        "network_used": False,
    }


def _task_router_check() -> dict[str, object]:
    root = Path(__file__).resolve().parents[1]
    profile = load_project_profile(root / "project-profile.yaml")
    catalog = load_agent_catalog(profile)
    router = TaskRouter(profile.project_key, catalog)
    fixture = json.loads((root / "validation-assets" / "task-routing-v1.json").read_text(encoding="utf-8"))
    if fixture.get("schema_version") != "1.0" or fixture.get("catalog_version") != catalog.version:
        raise RuntimeError("task routing fixture version mismatch")
    routes = []
    for case in fixture["cases"]:
        principal = Principal(case["principal_id"], case["role"], profile.project_key)
        route = router.route(TaskEnvelope(profile.project_key, principal, case["task_kind"], case["trace_id"]))
        actual = (
            route.outcome, route.reason_code, route.primary_agent_id, route.primary_agent_version,
            list(route.skill_refs), list(route.required_capabilities), route.review_agent_id,
        )
        expected = (
            case["expected_outcome"], case["expected_reason_code"], case["expected_agent_id"],
            case["expected_agent_version"], case["expected_skill_refs"], case["expected_capabilities"],
            case["expected_review_agent_id"],
        )
        if actual != expected:
            raise RuntimeError("task routing fixture mismatch")
        routes.append(route)
    return {
        "schema_version": "1.0",
        "status": "ok",
        "catalog_version": catalog.version,
        "catalog_digest": catalog.digest,
        "agents": len(catalog.agents),
        "cases": len(routes),
        "selected": sum(route.outcome == "selected" for route in routes),
        "denied": sum(route.outcome == "denied" for route in routes),
        "network_used": False,
    }


def _routing_preview_check() -> dict[str, object]:
    root = Path(__file__).resolve().parents[1]
    coordinator = UnifiedWorkCoordinator.from_repository(root)
    principals = {
        "owner": "owner-local", "maintainer": "maintainer-local",
        "engineer": "engineer-local", "analyst": "analyst-local",
    }
    combinations = 0
    digests: set[str] = set()
    for agent in coordinator.catalog.agents:
        for task_kind in agent.task_kinds:
            for role in agent.roles:
                result = coordinator.plan(WorkRequest(
                    principals[role], task_kind, f"preview-{agent.id}-{role}",
                ))
                payload = result.to_payload()
                unsigned = {key: value for key, value in payload.items() if key != "plan_digest"}
                expected_plan_digest = "sha256:" + hashlib.sha256(json.dumps(
                    unsigned, ensure_ascii=True, separators=(",", ":"), sort_keys=True,
                ).encode("utf-8")).hexdigest()
                if (
                    result.status != "ready" or result.agent_id != agent.id
                    or payload["catalog_version"] != coordinator.catalog.version
                    or payload["catalog_digest"] != coordinator.catalog.digest
                    or not re.fullmatch(r"sha256:[0-9a-f]{64}", str(payload["plan_digest"]))
                    or payload["plan_digest"] != expected_plan_digest
                ):
                    raise RuntimeError("routing preview coverage mismatch")
                combinations += 1
                digests.add(str(payload["plan_digest"]))
    return {
        "schema_version": "1.0", "status": "ok", "catalog_version": coordinator.catalog.version,
        "catalog_digest": coordinator.catalog.digest, "agents": len(coordinator.catalog.agents),
        "route_combinations": combinations, "unique_plan_digests": len(digests), "network_used": False,
    }


def _execution_boundary_check() -> dict[str, object]:
    """Exercises signed-session, plan-binding and governance denial paths offline."""

    root = Path(__file__).resolve().parents[1]
    registry = load_embedded_registry(root)
    clock_value = 1_800_000_000
    key = bytes.fromhex("31" * 32)
    authenticator = EmbeddedSessionAuthenticator(
        registry, key, clock=lambda: clock_value, nonce_factory=lambda: "ac" * 16,
    )
    boundary = AuthenticatedExecutionBoundary.from_repository(root, authenticator)
    coordinator = UnifiedWorkCoordinator.from_repository(root)

    def plan(principal_id: str, task_kind: str) -> WorkResult:
        return coordinator.plan(WorkRequest(
            principal_id, task_kind, "execution-boundary-check", mode="execute", inputs_present=True,
        ))

    engineer_plan = plan("engineer-local", "confluence.search")
    cases = [
        boundary.authorize(authenticator.issue("engineer-local"), "engineer-local", engineer_plan),
        boundary.authorize("", "engineer-local", engineer_plan),
        boundary.authorize(authenticator.issue("engineer-local") + "x", "engineer-local", engineer_plan),
        boundary.authorize(authenticator.issue("analyst-local"), "engineer-local", engineer_plan),
        boundary.authorize(
            authenticator.issue("engineer-local"), "engineer-local",
            coordinator.plan(WorkRequest("engineer-local", "confluence.search", "preview-not-execute")),
        ),
        boundary.authorize(
            authenticator.issue("owner-local"), "owner-local", plan("owner-local", "documentation.sync"),
        ),
        boundary.authorize(
            authenticator.issue("maintainer-local"), "maintainer-local", plan("maintainer-local", "documentation.sync"),
        ),
    ]
    payloads = [item.to_payload() for item in cases]
    allowed = sum(item.status == "allowed" for item in cases)
    denied = len(cases) - allowed
    valid = (
        allowed == 3 and denied == 4
        and all(item["authorization_digest"] == "sha256:" + hashlib.sha256(json.dumps(
            {key: value for key, value in item.items() if key != "authorization_digest"},
            ensure_ascii=True, separators=(",", ":"), sort_keys=True,
        ).encode()).hexdigest() for item in payloads)
    )
    return {
        "schema_version": "1.0", "boundary_version": "1.0.0", "status": "ok" if valid else "error",
        "cases": len(cases), "allowed": allowed, "denied": denied, "network_calls": 0,
    }


def _task_intake_check() -> dict[str, object]:
    root = Path(__file__).resolve().parents[1]
    fixture = json.loads((root / "validation-assets" / "task-intake-v1.json").read_text(encoding="utf-8"))
    intake = TaskIntake.from_product(root)
    checked = 0
    for case in fixture["cases"]:
        payload = intake.plan(case["principal_id"], f"intake-{case['id']}", case["task"]).to_payload()
        if (
            payload["status"] != case["expected_status"]
            or payload["reason_code"] != case["expected_reason_code"]
            or payload["task_kind"] != case["expected_task_kind"]
            or payload["privacy"]["outcome"] != case["expected_privacy_outcome"]
            or payload["network_used"] is not False
        ):
            raise RuntimeError(f"task intake fixture mismatch for {case['id']}")
        checked += 1
    return {
        "schema_version": "1.0",
        "status": "ok",
        "intake_version": fixture["intake_version"],
        "cases": checked,
        "network_used": False,
    }


def _policy_check() -> dict[str, object]:
    root = Path(__file__).resolve().parents[1]
    fixture = json.loads((root / "validation-assets" / "policy-v1.json").read_text(encoding="utf-8"))
    engine = PolicyEngine()
    decisions = [engine.decide(PolicyRequest.from_payload(case["request"])) for case in fixture["cases"]]
    actual = [decision.outcome for decision in decisions]
    actual_reasons = [decision.reason_code for decision in decisions]
    for case, decision in zip(fixture["cases"], decisions, strict=True):
        if decision.outcome != case["expected_outcome"]:
            raise RuntimeError(f"policy outcome mismatch for {case['id']}")
        if decision.reason_code != case["expected_reason_code"]:
            raise RuntimeError(f"policy reason-code mismatch for {case['id']}")
        if list(decision.constraints) != case["expected_constraints"]:
            raise RuntimeError(f"policy constraints mismatch for {case['id']}")
        if list(decision.required_transforms) != case["expected_required_transforms"]:
            raise RuntimeError(f"policy transforms mismatch for {case['id']}")
        if decision.ttl_seconds != case["expected_ttl_seconds"]:
            raise RuntimeError(f"policy ttl mismatch for {case['id']}")
    return {
        "status": "ok",
        "policy_version": fixture["policy_version"],
        "cases": len(decisions),
        "outcomes": {outcome: actual.count(outcome) for outcome in sorted(set(actual))},
        "reason_codes": {
            reason_code: actual_reasons.count(reason_code)
            for reason_code in sorted(set(actual_reasons))
        },
    }


def _governance_check() -> dict[str, object]:
    policy = GovernancePolicy.from_repository(Path(__file__).resolve().parents[1])
    generic = Principal("maintainer-local", "maintainer", policy.project_id)
    if any(policy.allows(generic, capability) for capability in policy.capabilities):
        raise RuntimeError("generic maintainer received administrative capability")
    return {
        "schema_version": "1.0",
        "status": "ok",
        "policy_version": policy.policy_version,
        "administrators": len(policy.administrators),
        "capabilities": len(policy.capabilities),
        "generic_maintainer_admin": False,
        "network_used": False,
    }


def _privacy_check() -> dict[str, object]:
    root = Path(__file__).resolve().parents[1]
    fixture = json.loads((root / "validation-assets" / "privacy-v1.json").read_text(encoding="utf-8"))
    outcomes: list[str] = []
    for case in fixture["cases"]:
        context = PrivacyContext(
            project_id="promptforge",
            execution_id=f"fixture-{case['id']}",
            principal_id="fixture-engineer",
            purpose="privacy-fixture",
            destination=case["context"]["destination"],
            synthetic=case["context"]["synthetic"],
            ttl_seconds=3600,
        )
        result = PrivacyPipeline(
            ScopedMappingVault(), frozenset({context.scope}),
        ).transform(
            case["content"], case["declared_classification"], context,
        )
        expected = case["expected_outcome"], case["expected_classification"]
        if (result.outcome, result.effective_classification) != expected:
            raise RuntimeError(f"privacy fixture mismatch for {case['id']}")
        outcomes.append(result.outcome)
    return {
        "status": "ok",
        "privacy_version": fixture["privacy_version"],
        "cases": len(outcomes),
        "outcomes": {outcome: outcomes.count(outcome) for outcome in sorted(set(outcomes))},
    }


def _model_gateway_check() -> dict[str, object]:
    root = Path(__file__).resolve().parents[1]
    fixture = json.loads((root / "validation-assets" / "model-gateway-v1.json").read_text(encoding="utf-8"))
    results = []
    for case in fixture["cases"]:
        context = PrivacyContext(
            "promptforge", f"gateway-{case['id']}", "fixture-engineer", "engineering-change", "external", True, 3600,
        )
        primary = FakeProviderAdapter("Synthetic primary response.", fail=case["primary_fail"])
        fallback = FakeProviderAdapter("Synthetic fallback response.")
        registry = ModelRegistry(
            (
                ModelEndpoint("cloud-primary", "provider-a", "model-a", "eu", "internal", "no_training", 4096, 1024),
                ModelEndpoint("cloud-fallback", "provider-b", "model-b", "eu", "internal", "no_training", 4096, 1024),
            ),
            (LogicalModel("balanced", ("cloud-primary", "cloud-fallback")),),
        )
        gateway = ModelGateway(
            registry,
            {"provider-a": primary, "provider-b": fallback},
            PolicyEngine(),
            PrivacyPipeline(ScopedMappingVault(), frozenset({context.scope})),
            frozenset({"eu"}),
        )
        request = ModelRequest(
            "promptforge", "engineering-change", case["classification"], case["content"], "external",
            case["classification"] == "internal", "balanced", f"trace-{case['id']}", 256,
        )
        result = gateway._invoke_trusted(Principal("fixture-engineer", "engineer", "promptforge"), request, context)
        if (result.status, result.receipt.endpoint_id) != (case["expected_status"], case["expected_endpoint"]):
            raise RuntimeError(f"model gateway fixture mismatch for {case['id']}")
        results.append(result)
    return {
        "status": "ok",
        "gateway_version": fixture["gateway_version"],
        "cases": len(results),
        "statuses": {status: sum(result.status == status for result in results) for status in ("ok", "deny")},
    }


def _secure_runtime_check() -> dict[str, object]:
    root = Path(__file__).resolve().parents[1]
    registry_payload = json.loads((root / "config" / "local-auth.json").read_text(encoding="utf-8"))
    bootstrap_auth = EmbeddedSessionAuthenticator(
        EmbeddedRoleRegistry.from_payload(registry_payload), secrets.token_bytes(32),
    )
    endpoint = ModelEndpoint(
        "synthetic", "synthetic-provider", "synthetic-model", "local", "internal", "no_training", 4096, 256,
    )
    gateway = ModelGateway(
        ModelRegistry((endpoint,), (LogicalModel("balanced", ("synthetic",)),)),
        {"synthetic-provider": FakeProviderAdapter("Synthetic response.")}, PolicyEngine(),
        PrivacyPipeline(ScopedMappingVault()), frozenset({"local"}),
    )
    schema = {"type": "object", "properties": {}, "required": [], "additionalProperties": False}
    capability = McpCapability.attested(
        "synthetic.read", "resource", "synthetic", "1.0.0", "Synthetic read.", "read", "low",
        ("owner", "maintainer", "engineer", "analyst"), "promptforge", schema, schema,
    )
    hub = McpHub(
        bootstrap_auth, McpRegistry((capability,)), {"synthetic": FakeMcpAdapter({})}, PolicyEngine(),
        PrivacyPipeline(ScopedMappingVault()), ApprovalStore(),
    )
    environment = {
        "PF_EMBEDDED_AUTH_KEY_HEX": secrets.token_bytes(32).hex(),
        "PF_LOCAL_AUDIT_KEY_HEX": secrets.token_bytes(32).hex(),
    }
    with tempfile.TemporaryDirectory() as directory:
        runtime = build_secure_runtime(root, Path(directory).resolve(), environment, gateway, hub)
        verification = runtime.audit.verify()
        return {
            "status": "ok", "audited_models": runtime.models.is_audited,
            "audited_mcp": isinstance(runtime.mcp, AuditedMcpHub), "audit_chain_valid": verification.valid,
            "token_optimization": isinstance(runtime.models, OptimizedModelRuntime),
            "budget_digest": runtime.models.budget.digest,
            "network_used": False,
        }


def _pilot_check() -> dict[str, object]:
    root = Path(__file__).resolve().parents[1]
    environment = {
        "PF_EMBEDDED_AUTH_KEY_HEX": secrets.token_bytes(32).hex(),
        "PF_LOCAL_AUDIT_KEY_HEX": secrets.token_bytes(32).hex(),
    }
    with tempfile.TemporaryDirectory() as directory:
        runner = build_offline_pilot(root, Path(directory).resolve(), environment)
        return runner.run().to_payload()


def _final_evidence_check() -> dict[str, object]:
    root = Path(__file__).resolve().parents[1]
    return FinalEvidenceRunner(root).run().to_payload()


def _release_candidate_check(arguments: list[str]) -> dict[str, object]:
    root = Path(__file__).resolve().parents[1]
    if not arguments:
        iterations = 100
    elif len(arguments) == 2 and arguments[0] == "--iterations" and arguments[1].isdigit():
        iterations = int(arguments[1])
    else:
        raise ValueError("release candidate arguments are invalid")
    return ReleaseCandidateRunner(root, evidence_iterations=iterations).run().to_payload()


def _mr_scope_check(arguments: list[str]) -> dict[str, object]:
    values = _exact_options(arguments, frozenset({"--base-ref"}))
    root = Path(__file__).resolve().parents[1]
    return MergeRequestScopeChecker(root, values["--base-ref"]).run().to_payload()


def _exact_options(arguments: list[str], allowed: frozenset[str]) -> dict[str, str]:
    if len(arguments) % 2:
        raise ValueError("command options are invalid")
    values: dict[str, str] = {}
    for index in range(0, len(arguments), 2):
        option, value = arguments[index:index + 2]
        if option not in allowed or option in values or not value:
            raise ValueError("command options are invalid")
        values[option] = value
    if set(values) != allowed:
        raise ValueError("command options are incomplete")
    return values


def _identity_check(arguments: list[str]) -> dict[str, object]:
    root = Path(__file__).resolve().parents[1]
    if not arguments:
        repository = root.parent
    elif len(arguments) == 2 and arguments[0] == "--repository":
        repository = Path(arguments[1])
    else:
        raise ValueError("identity check arguments are invalid")
    return GitIdentityResolver(repository, root / "config" / "local-auth.json").resolve().to_payload()


def _owner_keygen(arguments: list[str]) -> dict[str, object]:
    values = _exact_options(arguments, frozenset({"--private-key", "--public-key"}))
    generate_owner_keypair(Path(values["--private-key"]), Path(values["--public-key"]))
    return {"schema_version": "1.0", "status": "created", "private_key_exported": False, "network_used": False}


def _release_sign(arguments: list[str]) -> dict[str, object]:
    values = _exact_options(arguments, frozenset({
        "--manifest", "--signature", "--private-key", "--signer", "--key-id",
    }))
    root = Path(__file__).resolve().parents[1]
    registry = SkillSigningKeyRegistry.from_file(root / "config" / "skill-signing-keys.json")
    signature = sign_release_candidate(
        load_json_object(Path(values["--manifest"])), values["--signer"], values["--key-id"],
        Path(values["--private-key"]), registry,
    )
    write_private_json(Path(values["--signature"]), signature.to_payload())
    return {
        "schema_version": "1.0", "status": "signed", "signer_id": signature.signer_id,
        "key_id": signature.key_id, "manifest_digest": signature.manifest_digest,
        "expires_at": signature.expires_at, "network_used": False,
    }


def _release_verify(arguments: list[str]) -> dict[str, object]:
    values = _exact_options(arguments, frozenset({"--manifest", "--signature"}))
    root = Path(__file__).resolve().parents[1]
    manifest = load_json_object(Path(values["--manifest"]))
    signature = DetachedReleaseSignature.from_payload(load_json_object(Path(values["--signature"])))
    registry = SkillSigningKeyRegistry.from_file(root / "config" / "skill-signing-keys.json")
    verified = verify_release_candidate(manifest, signature, registry)
    return {
        "schema_version": "1.0", "status": "verified" if verified else "denied",
        "reason_code": "signature_valid" if verified else "signature_invalid", "network_used": False,
    }


def _production_docs_check() -> dict[str, object]:
    root = Path(__file__).resolve().parents[1]
    return ProductionDocumentationGate.from_repository(root).inspect().to_payload()


def _neutrality_check() -> dict[str, object]:
    root = Path(__file__).resolve().parents[1]
    report = NeutralityGate(root, repository_neutrality_extras(root)).inspect()
    if report.status != "passed":
        raise RuntimeError("neutrality policy blocked product surface")
    return report.to_payload()


def _changed_review(
    arguments: list[str], principal_id: str | None = None, repository: Path | None = None,
) -> dict[str, object]:
    paths: list[str] = []
    deploy: list[str] = []
    state_root: Path | None = None
    index = 0
    while index < len(arguments):
        option = arguments[index]
        if option not in {"--path", "--deploy", "--state-root"} or index + 1 >= len(arguments):
            raise ValueError("changed review arguments are invalid")
        target = arguments[index + 1]
        if option == "--state-root":
            if state_root is not None:
                raise ValueError("changed review state root is duplicated")
            state_root = Path(target)
        else:
            (paths if option == "--path" else deploy).append(target)
        index += 2
    if not paths or len(paths) != len(set(paths)) or len(deploy) != len(set(deploy)):
        raise ValueError("changed review paths are invalid")
    review_root = Path(repository or Path.cwd()).resolve(strict=True)
    runner = ChangedFilesReviewRunner(review_root, secrets.token_bytes(32))
    request, result = runner.review_context(frozenset(paths), frozenset(deploy))
    payload = {
        "schema_version": "1.0", "status": "ok", "selected_files": len(paths), "review": result.to_payload(),
    }
    if state_root is not None:
        product_root = Path(__file__).resolve().parents[1]
        profile = load_project_profile(product_root / "project-profile.yaml")
        catalog = load_agent_catalog(profile)
        key = local_audit_key_from_env()
        metrics_key = hmac.new(key, b"promptforge-efficiency-metrics-v1", hashlib.sha256).digest()
        docs = DocumentationAutomation.from_repository(product_root).check_all().to_payload()
        docs_digest = documentation_evidence_digest(docs)
        evidence = ReviewEvidenceLoop(state_root, key).record(
            request, result, catalog.digest,
            Principal(principal_id or "review-local", "engineer", profile.project_key),
            "retained" if result.receipt.status == "passed" else "rolled-back", docs_digest,
        )
        EfficiencyMetricsStore(state_root / "efficiency-metrics.sqlite3", metrics_key).append(
            EfficiencyMetricEvent(
                agents_invoked=1, skills_invoked=1, review_findings=sum(result.receipt.finding_counts), runs=1,
                first_run_successes=1 if result.receipt.status == "passed" else 0,
            )
        )
        receipt = evidence.provenance
        payload = {
            **payload, "provenance_receipt": receipt.to_payload(),
            "documentation_impact": docs, "evidence_receipt": evidence.to_payload(),
        }
        if principal_id is not None:
            baseline = WorktreeBaseline.capture_tree(review_root, key)
            bindings_digest = "sha256:" + hashlib.sha256(json.dumps({
                "spec_version": request.spec_version, "policy_version": request.policy_version,
                "skill_versions": request.skill_versions,
            }, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
            closure = ReviewClosureContextStore(state_root, key).register(
                request.trace_id, principal_id, request.project_id, baseline, result.receipt.open_finding_keys,
                catalog.digest, bindings_digest, receipt.record_digest,
            )
            payload = {**payload, "closure_context": closure.to_payload()}
    return payload


def _docs_check() -> dict[str, object]:
    return DocumentationAutomation.from_repository(Path(__file__).resolve().parents[1]).check_all().to_payload()


def _work_principal(repository: Path, actor_id: str) -> Principal:
    registry = load_embedded_registry(repository)
    token = os.environ.get("PF_WORK_SESSION", "")
    authentication = EmbeddedSessionAuthenticator(registry, embedded_auth_key_from_env()).authenticate(token)
    principal = authentication.principal
    if principal is None:
        raise PermissionError("work authentication denied")
    if principal.id != actor_id:
        raise PermissionError("work principal mismatch")
    return principal


def _load_work_input(input_path: Path, state_root: Path) -> dict[str, object]:
    """Read one private task-input object from its already-approved state root."""

    root = state_root.resolve(strict=True)
    candidate = Path(input_path)
    if not candidate.is_absolute() or candidate.is_symlink():
        raise ValueError("work input must be an absolute non-symlink path")
    resolved = candidate.resolve(strict=True)
    if not resolved.is_relative_to(root):
        raise ValueError("work input must stay inside state root")
    descriptor = -1
    try:
        descriptor = os.open(candidate, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_mode & 0o077
            or metadata.st_uid != os.getuid()
            or metadata.st_size > 1_000_000
        ):
            raise ValueError("work input must be a private bounded regular file")

        def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
            result: dict[str, object] = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError("work input contains duplicate fields")
                result = {**result, key: value}
            return result

        with os.fdopen(descriptor, "r", encoding="utf-8") as stream:
            descriptor = -1
            payload = json.load(stream, object_pairs_hook=reject_duplicates)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ValueError("work input must be valid private JSON") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if not isinstance(payload, dict):
        raise ValueError("work input JSON must be an object")
    return payload


_WORK_EXTERNAL_TASKS = frozenset({
    "workflow.debug", "table.freshness", "confluence.search", "confluence.read",
    "jira.search", "jira.read", "confluence.snapshot",
})


def _work_roots() -> tuple[Path, Path]:
    """Returns pinned product configuration root and enclosing repository workspace root."""

    product_root = Path(__file__).resolve().parents[1]
    workspace_root = product_root.parent.resolve(strict=True)
    if product_root.is_symlink() or workspace_root.is_symlink() or product_root.parent != workspace_root:
        raise ValueError("work roots are invalid")
    return product_root, workspace_root


def _resolve_work_mcp_hub(
    product_root: Path,
    state_root: Path,
    task_kind: str,
    injected_hub: AuditedMcpHub | None,
) -> AuditedMcpHub | None:
    """Resolves the only allowed authenticated MCP Hub for external read tasks."""

    if injected_hub is not None:
        return injected_hub
    if task_kind not in _WORK_EXTERNAL_TASKS:
        return None
    try:
        return build_production_mcp_hub(product_root, state_root, os.environ)
    except (OSError, PermissionError, RuntimeError, ValueError):
        return None


def _seal_work_payload(payload: dict[str, object]) -> dict[str, object]:
    """Recomputes the canonical digest after an execution-state transition."""

    unsigned = {key: value for key, value in payload.items() if key != "plan_digest"}
    execution = unsigned.get("execution")
    unsigned["network_used"] = bool(isinstance(execution, dict) and execution.get("network_used", False))
    encoded = json.dumps(unsigned, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return {**unsigned, "plan_digest": "sha256:" + hashlib.sha256(encoded).hexdigest()}


def _governance_principal(actor_id: str, capability: str) -> Principal:
    root = Path(__file__).resolve().parents[1]
    registry = EmbeddedRoleRegistry.from_payload(json.loads(
        (root / "config" / "local-auth.json").read_text(encoding="utf-8")
    ))
    token = os.environ.get("PF_GOVERNANCE_SESSION", "")
    authentication = EmbeddedSessionAuthenticator(registry, embedded_auth_key_from_env()).authenticate(token)
    principal = authentication.principal
    if principal is None or principal.id != actor_id:
        raise PermissionError("governance authentication denied")
    GovernancePolicy.from_repository(root).require(principal, capability)
    return principal


def _docs_sync(arguments: list[str]) -> dict[str, object]:
    raise PermissionError("legacy documentation mutation is disabled; use authenticated work lifecycle")


def _token_efficiency_check() -> dict[str, object]:
    root = Path(__file__).resolve().parents[1]
    payload = json.loads((root / "config" / "token-budget.json").read_text(encoding="utf-8"))
    if set(payload) != {"schema_version", "max_input", "reserved_mandatory", "reserved_output", "overflow"}:
        raise ValueError("token budget config is invalid")
    budget = TokenBudget(
        payload["max_input"], payload["reserved_mandatory"], payload["reserved_output"], payload["overflow"],
    )
    trusted_identity = "synthetic-gateway-attestation"
    runtime = TokenEfficiencyRuntime(
        secrets.token_bytes(32), lambda receipt: receipt.identity_attestation == trusted_identity,
    )
    plan = runtime.prepare(
        "promptforge", "engineer-local", "trace-token-efficiency-check", budget,
        (
            ContextItem("policy", "mandatory policy and security rules", True),
            ContextItem("acceptance", "acceptance criteria", True),
            ContextItem("source-a", "shared schema context", False),
            ContextItem("source-b", "shared schema context", False),
        ),
    )
    gateway_receipt = GatewayReceipt(
        "ok", "completed", plan.trace_id, "balanced", "synthetic", "fake", "fake-model", "allow", "1.0",
        "allow", 0, plan.selected_input_tokens, min(8, budget.reserved_output), trusted_identity,
    )
    receipt = runtime.issue_receipt(plan, gateway_receipt)
    compact_plan = runtime.prepare(
        "promptforge", "engineer-local", "trace-token-compaction-check", TokenBudget(8, 4, 8, "compact"),
        (
            ContextItem("policy", "mandatory-policy", True), ContextItem("optional-a", "optional context a"),
            ContextItem("optional-b", "optional context b"),
        ),
    )
    receipt_digest = "sha256:" + hashlib.sha256(json.dumps(
        receipt.to_payload(), ensure_ascii=True, sort_keys=True, separators=(",", ":"),
    ).encode("utf-8")).hexdigest()
    with tempfile.TemporaryDirectory() as directory:
        state_root = Path(directory).resolve()
        store_key = secrets.token_bytes(32)
        store = TokenUsageStore(state_root / "token-usage.sqlite3", store_key, clock=lambda: 1_800_000_000)
        durable = store.append_digest(receipt.project_id, receipt.principal_id, receipt.trace_id, receipt_digest)
        restart_verified = TokenUsageStore(state_root / "token-usage.sqlite3", store_key).verify().valid
        try:
            store.append_digest(
                receipt.project_id, receipt.principal_id, receipt.trace_id, "sha256:" + "1" * 64,
            )
        except ValueError:
            replay_denied = True
        else:
            replay_denied = False
        import sqlite3
        connection = sqlite3.connect(state_root / "token-usage.sqlite3")
        connection.execute("UPDATE token_usage SET receipt_digest=? WHERE sequence=1", ("sha256:" + "0" * 64,))
        connection.commit()
        connection.close()
        tamper_detected = not store.verify().valid
    return {
        "schema_version": "1.0", "status": "ok", "plan": plan.to_payload(),
        "receipt": receipt.to_payload(), "receipt_verified": runtime.verify_receipt(receipt),
        "compaction_verified": compact_plan.status == "ready" and compact_plan.reason_code == "context_compacted",
        "durable_receipt": durable.to_payload(), "restart_verified": restart_verified,
        "replay_denied": replay_denied, "tamper_detected": tamper_detected, "network_used": False,
    }


def _operations_check() -> dict[str, object]:
    root = Path(__file__).resolve().parents[1]
    config = OperationsConfig.from_repository(root)
    with tempfile.TemporaryDirectory() as directory:
        state_root = Path(directory).resolve()
        switch = LocalKillSwitch(state_root, secrets.token_bytes(32), clock=lambda: 1_800_000_000)
        owner = Principal("owner-local", "owner", "promptforge")
        engaged = switch.set_state(True, owner, "synthetic-check")
        for name in ("placeholder-mappings.sqlite3", "context-cache.sqlite3"):
            path = state_root / name
            path.write_text("synthetic", encoding="utf-8")
            path.chmod(0o600)
        cleaner = LocalStateCleaner(state_root, config, switch, clock=lambda: 1_800_000_000)
        planned = cleaner.cleanup("ephemeral", owner, "PURGE promptforge", dry_run=True)
        completed = cleaner.cleanup("ephemeral", owner, "PURGE promptforge", dry_run=False)
        return {
            "schema_version": "1.0", "status": "ok", "kill_switch_verified": engaged.engaged,
            "cleanup_verified": planned.status == "planned" and completed.removed_files == 2,
            "removed_files": completed.removed_files, "network_used": False,
        }


def _kill_switch_command(arguments: list[str]) -> dict[str, object]:
    if (
        len(arguments) != 7 or arguments[0] != "--state-root" or arguments[2] not in {"--engage", "--release"}
        or arguments[3] != "--approve-owner" or arguments[5] != "--reason"
    ):
        raise ValueError("kill switch arguments are invalid")
    state_root, action, owner, reason = arguments[1], arguments[2], arguments[4], arguments[6]
    principal = _governance_principal(owner, "operations.manage")
    switch = LocalKillSwitch(Path(state_root), local_audit_key_from_env())
    state = switch.set_state(action == "--engage", principal, reason)
    return {"schema_version": "1.0", "status": "ok", "state": state.to_payload(), "network_used": False}


def _state_cleanup_command(arguments: list[str]) -> dict[str, object]:
    if (
        len(arguments) != 9 or arguments[0] != "--state-root" or arguments[2] != "--scope"
        or arguments[4] != "--approve-owner" or arguments[6] != "--confirm"
        or arguments[8] not in {"--dry-run", "--execute"}
    ):
        raise ValueError("state cleanup arguments are invalid")
    state_root, scope, owner, confirmation = Path(arguments[1]), arguments[3], arguments[5], arguments[7]
    key = local_audit_key_from_env()
    switch = LocalKillSwitch(state_root, key)
    config = OperationsConfig.from_repository(Path(__file__).resolve().parents[1])
    principal = _governance_principal(owner, "operations.manage")
    receipt = LocalStateCleaner(state_root, config, switch).cleanup(
        scope, principal, confirmation, dry_run=arguments[8] == "--dry-run",
    )
    return {"schema_version": "1.0", "status": "ok", "cleanup": receipt.to_payload(), "network_used": False}


def _local_inference_check() -> dict[str, object]:
    root = Path(__file__).resolve().parents[1]
    payload = json.loads((root / "config" / "local-inference.json").read_text(encoding="utf-8"))
    deployment = LocalInferenceDeployment.from_payload(payload)
    endpoint = deployment.endpoint()
    return {
        "status": "ok",
        "schema_version": payload["schema_version"],
        "logical_model": deployment.logical_model,
        "provider": endpoint.provider,
        "destination": endpoint.destination,
        "network_used": False,
    }


def _model_admission_check() -> dict[str, object]:
    root = Path(__file__).resolve().parents[1]
    payload = json.loads((root / "config" / "local-model-admission.json").read_text(encoding="utf-8"))
    manifest = ModelAdmissionManifest.from_payload(payload)
    return {
        "status": "ok",
        "schema_version": payload["schema_version"],
        "model_id": manifest.model_id,
        "admission_status": manifest.status,
        "runtime_allowed": manifest.is_admittable,
        "network_used": False,
    }


def _model_eval_check() -> dict[str, object]:
    root = Path(__file__).resolve().parents[1]
    payload = json.loads((root / "validation-assets" / "local-model-eval-v1.json").read_text(encoding="utf-8"))
    report = ModelEvalRunner().run(ModelEvalSuite.from_payload(payload), FixtureEvalModel.from_payload(payload))
    return {
        "status": "ok",
        "eval_version": payload["eval_version"],
        "cases": report.metrics.total,
        "passed": report.metrics.passed,
        "unsafe_findings": report.metrics.unsafe_findings,
        "corpus_sha256": report.provenance.corpus_sha256,
        "suite_sha256": report.provenance.suite_sha256,
        "network_used": False,
    }


def _model_admission_workflow_check() -> dict[str, object]:
    root = Path(__file__).resolve().parents[1]
    repository_payload = json.loads((root / "config" / "local-model-admission.json").read_text(encoding="utf-8"))
    repository_manifest = ModelAdmissionManifest.from_payload(repository_payload)
    now = 1_000
    authority = ModelAdmissionAuthority(secrets.token_bytes(32), clock=lambda: now)
    workflow = ModelAdmissionWorkflow(
        authority, secrets.token_bytes(32), frozenset({"owner-local", "maintainer-local"}), "promptforge",
        InMemoryApprovalConsumptionStore(clock=lambda: now), clock=lambda: now,
    )
    review_manifest = ModelAdmissionManifest(
        "synthetic-local-model", "synthetic-revision", "a" * 64, "Apache-2.0",
        "https://models.example.invalid/synthetic-local-model", "review", "synthetic-eval-v1", 1.0, 0,
    )
    evidence = authority.attest(
        review_manifest, ModelEvalMetrics(1, 1, 0),
        ModelEvalProvenance("promptforge-eval", "b" * 64, "c" * 64, "1.0", now),
    )
    approval = workflow.approve(Principal("owner-local", "owner", "promptforge"), review_manifest, evidence)
    release = workflow.release(review_manifest, evidence, approval)
    return {
        "status": "ok", "release_status": release.decision.status,
        "repository_manifest_status": repository_manifest.status, "owner_required": True, "network_used": False,
    }


def _auth_check() -> dict[str, object]:
    root = Path(__file__).resolve().parents[1]
    fixture = json.loads((root / "validation-assets" / "auth-v1.json").read_text(encoding="utf-8"))
    tokens = {}
    for case in fixture["cases"]:
        tokens[case["id"]] = OIDCClaims(
            fixture["issuer"] if case["issuer_ok"] else "https://invalid.example/",
            (fixture["audience"],), case["subject"], case["expires_at"], fixture["now"] - 10, True,
            tuple(case["groups"]), fixture["project_id"],
        )
    authenticator = AuthentikAuthenticator(
        FakeOIDCTokenVerifier(tokens), fixture["issuer"], fixture["audience"], fixture["project_id"],
        {
            "promptforge-owner": "owner", "promptforge-maintainer": "maintainer",
            "promptforge-engineer": "engineer", "promptforge-analyst": "analyst",
        },
        frozenset({"owner-local"}),
        clock=lambda: fixture["now"],
    )
    results = [authenticator.authenticate(case["id"]) for case in fixture["cases"]]
    for case, result in zip(fixture["cases"], results, strict=True):
        actual_role = result.principal.role if result.principal else ""
        if (result.status, actual_role) != (case["expected_status"], case["expected_role"]):
            raise RuntimeError(f"auth fixture mismatch for {case['id']}")
    return {
        "status": "ok", "auth_version": fixture["auth_version"], "cases": len(results),
        "statuses": {status: sum(result.status == status for result in results) for status in ("allow", "deny")},
    }


def _embedded_auth_check() -> dict[str, object]:
    root = Path(__file__).resolve().parents[1]
    payload = json.loads((root / "config" / "local-auth.json").read_text(encoding="utf-8"))
    registry = EmbeddedRoleRegistry.from_payload(payload)
    authenticator = EmbeddedSessionAuthenticator(registry, secrets.token_bytes(32), clock=lambda: 1_800_000_000)
    results = [authenticator.authenticate(authenticator.issue(item.id)) for item in registry.principals]
    results.append(authenticator.authenticate("invalid-session"))
    return {
        "status": "ok", "auth_version": registry.auth_version, "cases": len(results),
        "statuses": {status: sum(result.status == status for result in results) for status in ("allow", "deny")},
        "network_used": False,
    }


def _trusted_executors_check() -> dict[str, object]:
    root = Path(__file__).resolve().parents[1]
    product_root, workspace_root = _work_roots()
    registry = load_embedded_registry(root)
    auth_key = secrets.token_bytes(32)
    owner_token = EmbeddedSessionAuthenticator(registry, auth_key).issue("owner-local")
    engineer_token = EmbeddedSessionAuthenticator(registry, auth_key).issue("engineer-local")

    class _FakeReceipt:
        operation = "read"
        reason_code = "completed"

        @staticmethod
        def to_payload() -> dict[str, object]:
            return {
                "schema_version": "1.0", "status": "ok", "reason_code": "completed",
                "trace_id": "trusted-executors-check", "project_id": "promptforge",
                "capability_id": "confluence.search_pages", "capability_version": "1.0.0",
                "server": "confluence", "kind": "resource", "operation": "read",
                "policy_outcome": "allow", "policy_version": "1.0", "privacy_outcome": "allow",
                "approval_id": "", "side_effect": False, "registry_version": "1.0",
            }

    class _FakeHubResult:
        status = "ok"
        data = {"pages": []}
        receipt = _FakeReceipt()

    class _FakeHub:
        def __init__(self) -> None:
            self.calls = 0

        def execute(self, token: str, request: object, context: object) -> object:
            self.calls += 1
            return _FakeHubResult()

    fake_hub = _FakeHub()
    builder_calls: list[tuple[Path, Path]] = []

    def fake_builder(repo_root: Path, state_root: Path, environment: dict[str, str]) -> _FakeHub:
        builder_calls.append((Path(repo_root), Path(state_root)))
        return fake_hub

    builder_before = globals()["build_production_mcp_hub"]
    env_before = {
        key: os.environ.get(key)
        for key in ("PF_EMBEDDED_AUTH_KEY_HEX", "PF_WORK_SESSION", "PF_LOCAL_AUDIT_KEY_HEX")
    }
    cwd_before = Path.cwd()
    try:
        globals()["build_production_mcp_hub"] = fake_builder
        os.environ["PF_EMBEDDED_AUTH_KEY_HEX"] = auth_key.hex()
        os.environ["PF_LOCAL_AUDIT_KEY_HEX"] = secrets.token_bytes(32).hex()
        os.chdir(root.parent)
        preview = execute_work(["--principal-id", "engineer-local", "--task-kind", "confluence.search"])
        with tempfile.TemporaryDirectory() as directory:
            state_root = Path(directory).resolve()
            state_root.chmod(0o700)
            search_input = state_root / "search-input.json"
            search_input.write_text(
                json.dumps({"query": "calc236", "space_key": "DATA", "limit": 1}), encoding="utf-8",
            )
            search_input.chmod(0o600)
            docs_input = state_root / "docs-input.json"
            docs_input.write_text(
                json.dumps({"document_id": "promptforge.pilot-evidence.api"}), encoding="utf-8",
            )
            docs_input.chmod(0o600)
            os.environ["PF_WORK_SESSION"] = engineer_token
            external = execute_work([
                "--execute", "--principal-id", "engineer-local", "--task-kind", "confluence.search",
                "--state-root", str(state_root), "--input-json", str(search_input),
            ])
            globals()["build_production_mcp_hub"] = lambda *_args, **_kwargs: None
            denied = execute_work([
                "--execute", "--principal-id", "engineer-local", "--task-kind", "confluence.search",
                "--state-root", str(state_root), "--input-json", str(search_input),
            ])
            os.environ["PF_WORK_SESSION"] = owner_token
            documentation = execute_work([
                "--execute", "--principal-id", "owner-local", "--task-kind", "documentation.sync",
                "--state-root", str(state_root), "--input-json", str(docs_input),
            ])
    finally:
        os.chdir(cwd_before)
        globals()["build_production_mcp_hub"] = builder_before
        for key, value in env_before.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
    profile = load_project_profile(root / "project-profile.yaml")
    catalog = load_agent_catalog(profile)
    executor_registry = AgentExecutionRegistry.builtin(root)
    catalog_tasks = frozenset(task for agent in catalog.agents for task in agent.task_kinds)
    registered_tasks = frozenset(executor_registry.task_kinds)
    expected_blocked = MCP_READ_TASK_KINDS | {"confluence.snapshot", "review.changed-files"}
    calc_executor = executor_registry.executors["calc.create"]
    mutation_probe = calc_executor.mutation_patch(
        {"calc_id": "calc999"},
        SimpleNamespace(repository=workspace_root, state_root=workspace_root / ".promptforge"),
        (GeneratedFile("etl/airflow2/pyspark/calc999/calc.py", "production", "VALUE = 1\n"),),
    )
    mutation_target = mutation_probe.repository / mutation_probe.specs[0].path
    expected_mutation_target = workspace_root / "etl/airflow2/pyspark/calc999/calc.py"
    with tempfile.TemporaryDirectory() as directory:
        isolated_root = Path(directory).resolve()
        nested_patch = MutationPatch(
            isolated_root, (MutationSpec("new/deep/file.txt", "production", "VALUE = 1\n", None),),
        )
        nested_patch.validate()
        validate_side_effect_free = not (isolated_root / "new").exists()
        isolated_applied = nested_patch.apply()
        isolated_applied.rollback()
        rollback_side_effect_free = not (isolated_root / "new").exists()
    if (
        preview["status"] != "ready"
        or external["status"] != "completed"
        or external["execution"]["reason_code"] != "authenticated_mcp_read"
        or denied["status"] != "blocked"
        or denied["reason_code"] != "runtime_adapter_unavailable"
        or documentation["status"] != "completed"
        or documentation["execution"]["reason_code"] != "documentation_current"
        or not builder_calls
        or builder_calls[0][0] != root
        or external["network_used"] is not True
        or not catalog_tasks <= registered_tasks
        or frozenset(executor_registry.blocked_task_kinds) != expected_blocked
        or product_root == workspace_root
        or mutation_probe.repository != workspace_root
        or mutation_target != expected_mutation_target
        or not validate_side_effect_free
        or not rollback_side_effect_free
    ):
        raise RuntimeError("trusted executors regression detected")
    return {
        "schema_version": "1.0",
        "executor_version": "1.0.0",
        "status": "ok",
        "checks": 6,
        "builder_calls": len(builder_calls),
        "external_hub_calls": fake_hub.calls,
        "catalog_task_kinds": len(catalog_tasks),
        "registered_task_kinds": len(registered_tasks),
        "mcp_read_task_kinds": len(MCP_READ_TASK_KINDS),
        "mutation_task_kinds": len(MUTATION_TASK_KINDS),
        "blocked_without_adapter": len(executor_registry.blocked_task_kinds),
        "synthetic_fallback_forbidden": True,
        "product_workspace_separated": True,
        "mutation_workspace_bound": mutation_probe.repository == workspace_root,
        "mutation_target_bound": mutation_target == expected_mutation_target,
        "mutation_validate_side_effect_free": validate_side_effect_free,
        "mutation_rollback_side_effect_free": rollback_side_effect_free,
        "network_calls": 0,
        "network_used": False,
    }


def _audit_check() -> dict[str, object]:
    now = 1_800_000_000
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory).resolve() / "audit.sqlite3"
        store = LocalAuditStore(path, secrets.token_bytes(32), clock=lambda: now)
        store.append(AuditEvent(
            "audit-trace-1", "engineer-local", "promptforge", "model.invoke", "model:balanced",
            "allow", "policy_allowed", "1.0", now,
        ))
        store.append(AuditEvent(
            "audit-trace-2", "analyst-local", "promptforge", "mcp.write", "mcp:tool",
            "deny", "role_write_denied", "1.0", now,
        ))
        verification = store.verify()
    return {
        "status": "ok", "events": verification.events, "chain_valid": verification.valid,
        "network_used": False,
    }


def _mcp_hub_check() -> dict[str, object]:
    root = Path(__file__).resolve().parents[1]
    fixture = json.loads((root / "validation-assets" / "mcp-hub-v1.json").read_text(encoding="utf-8"))
    now = 1_800_000_000
    issuer = "https://auth.example/application/o/promptforge/"
    tokens = {
        role: OIDCClaims(
            issuer, ("promptforge",), "maintainer-local" if role == "maintainer" else f"{role}-1",
            now + 300, now - 10, True,
            (f"promptforge-{role}",), "promptforge",
        )
        for role in ("maintainer", "engineer", "analyst")
    }
    authenticator = AuthentikAuthenticator(
        FakeOIDCTokenVerifier(tokens), issuer, "promptforge", "promptforge",
        {
            "promptforge-owner": "owner", "promptforge-maintainer": "maintainer",
            "promptforge-engineer": "engineer", "promptforge-analyst": "analyst",
        },
        frozenset({"owner-local"}), clock=lambda: now,
    )
    empty_input = {"type": "object", "properties": {}, "required": [], "additionalProperties": False}
    dag_input = {
        "type": "object", "properties": {"dag_id": {"type": "string"}},
        "required": ["dag_id"], "additionalProperties": False,
    }
    any_object = {"type": "object", "properties": {}, "required": [], "additionalProperties": True}
    read = McpCapability.attested(
        "confluence.search", "resource", "confluence", "1.0.0", "Search approved pages.", "read", "low",
        ("owner", "maintainer", "engineer", "analyst"), "promptforge", empty_input, any_object,
    )
    write = McpCapability.attested(
        "airflow.trigger_dag", "tool", "airflow", "1.0.0", "Trigger an approved DAG.", "execute", "high",
        ("owner", "maintainer", "engineer"), "promptforge", dag_input, any_object,
    )
    hub = McpHub(
        authenticator, McpRegistry((read, write)),
        {
            "confluence": FakeMcpAdapter({"pages": ["Synthetic page"]}),
            "airflow": FakeMcpAdapter({"run_id": "synthetic-run"}, side_effect=True),
        },
        PolicyEngine(), PrivacyPipeline(ScopedMappingVault(clock=lambda: now)),
        ApprovalStore(clock=lambda: now), clock=lambda: now,
    )
    read_request = McpRequest(
        "promptforge", "engineering-change", read.id, read.version, {}, "public", "trace-mcp-read",
    )
    write_request = McpRequest(
        "promptforge", "engineering-change", write.id, write.version,
        {"dag_id": "synthetic_dag"}, "public", "trace-mcp-write",
    )
    analyst_context = PrivacyContext(
        "promptforge", "mcp-read", "analyst-1", "engineering-change", "local", False, 3600,
    )
    engineer_context = PrivacyContext(
        "promptforge", "mcp-write", "engineer-1", "engineering-change", "local", False, 3600,
    )
    approval_id = hub.approve("maintainer", "engineer", write_request, engineer_context, 60)
    statuses = {
        "analyst-discovery": hub.discover("analyst", "promptforge", "engineering-change").status,
        "analyst-read": hub.execute("analyst", read_request, analyst_context).status,
        "analyst-write-denied": hub.execute("analyst", write_request, analyst_context).status,
        "engineer-approved-write": hub.execute(
            "engineer", write_request.with_approval(approval_id), engineer_context,
        ).status,
        "invalid-token": hub.execute("invalid", read_request, analyst_context).status,
    }
    for case in fixture["cases"]:
        if statuses[case["id"]] != case["expected_status"]:
            raise RuntimeError(f"MCP Hub fixture mismatch for {case['id']}")
    return {
        "status": "ok", "hub_version": fixture["hub_version"], "cases": len(statuses),
        "statuses": {status: list(statuses.values()).count(status) for status in ("ok", "deny")},
    }


def _integrations_check() -> dict[str, object]:
    """Проверяет pinned adapters на synthetic backends без сети и credentials."""

    class ConfluenceFixture:
        def search_pages(self, query: str, space_key: str | None, limit: int) -> dict[str, object]:
            return {"results": [{"id": "101", "title": query, "space_key": space_key or "", "version": 1}]}

        def get_page(self, space_key: str, page_id: str) -> dict[str, object]:
            return {"id": page_id, "title": "Synthetic", "space_key": space_key, "version": 1, "text": "Body"}

    class JiraFixture:
        def search_issues(self, project_key: str, query: str, limit: int) -> dict[str, object]:
            return {"issues": [{"key": f"{project_key}-1", "summary": query, "status": "Open"}]}

        def get_issue(self, issue_key: str) -> dict[str, object]:
            return {"key": issue_key, "summary": "Synthetic", "status": "Open", "description": "Body"}

    class AirflowFixture:
        def list_dags(self, limit: int) -> dict[str, object]:
            return {"dags": [{"dag_id": "synthetic_dag", "is_paused": False}]}

        def list_dag_runs(self, dag_id: str, limit: int) -> dict[str, object]:
            return {"dag_runs": [{"dag_id": dag_id, "run_id": "manual__1", "state": "success"}]}

    adapters = {
        "confluence": ConfluenceMcpAdapter(
            ConfluenceFixture(), "https://confluence.example", frozenset({"DATA"}),
        ),
        "jira": JiraMcpAdapter(JiraFixture(), "https://jira.example", frozenset({"DATA"})),
        "airflow": AirflowMcpAdapter(AirflowFixture(), frozenset({"synthetic_dag"})),
    }
    calls = (
        McpAdapterCall(
            "confluence.search_pages", "1.0.0", "read",
            {"query": "calc", "space_key": "DATA", "limit": 1}, "c1",
        ),
        McpAdapterCall(
            "confluence.get_page", "1.0.0", "read", {"space_key": "DATA", "page_id": "101"}, "c2",
        ),
        McpAdapterCall(
            "jira.search_issues", "1.0.0", "read",
            {"project_key": "DATA", "query": "calc", "limit": 1}, "j1",
        ),
        McpAdapterCall("jira.get_issue", "1.0.0", "read", {"issue_key": "DATA-1"}, "j2"),
        McpAdapterCall("airflow.list_dags", "1.0.0", "read", {"limit": 1}, "a1"),
        McpAdapterCall(
            "airflow.list_dag_runs", "1.0.0", "read", {"dag_id": "synthetic_dag", "limit": 1}, "a2",
        ),
    )
    for call in calls:
        adapters[call.capability_id.split(".", 1)[0]].invoke(call)
    counts = {
        server: sum(capability.server == server for capability in integration_capabilities())
        for server in adapters
    }
    return {"status": "ok", "integration_version": "1.0", "capabilities": counts, "network_used": False}


def _integration_readiness_check() -> dict[str, object]:
    """Validates production integration config without exposing values or making network calls."""

    return IntegrationBackendConfig.from_env(os.environ).readiness_receipt()


def _prompt_value(label: str, default: str = "") -> str:
    suffix = f" [{default}]" if default else ""
    print(f"{label}{suffix}: ", end="", file=sys.stderr, flush=True)
    value = sys.stdin.readline()
    if value == "":
        raise ValueError("integration setup input ended unexpectedly")
    result = value.rstrip("\r\n") or default
    if not result or len(result) > 8_192 or any(ord(char) < 0x20 or ord(char) == 0x7F for char in result):
        raise ValueError("integration setup input is invalid")
    return result


def _integration_setup(arguments: list[str]) -> dict[str, object]:
    """Collects credentials interactively and creates owner-private local state."""

    options = _exact_options(arguments, frozenset({"--state-root"}))
    if "--state-root" not in options or not sys.stdin.isatty():
        raise ValueError("integration setup requires an interactive terminal and exact state root")
    product_root = Path(__file__).resolve().parents[1]
    state_root = Path(options["--state-root"])
    identity = GitIdentityResolver(
        product_root.parent, product_root / "config" / "local-auth.json",
    ).resolve()
    if identity.status != "recognized":
        raise PermissionError("integration setup Git identity is unknown")
    ca_file = Path(_prompt_value("Trusted CA absolute path"))
    definitions = (
        ("confluence", "Confluence base URL", "Confluence technical space key", "exact"),
        ("jira", "Jira base URL", "Jira smoke project key", "account-visible-read-only"),
        ("airflow", "Airflow base URL", "Airflow smoke DAG id", "account-visible-read-only"),
    )
    services: list[ServiceSetupInput] = []
    credentials: dict[str, str] = {}
    for service, url_label, smoke_label, scope_mode in definitions:
        url = _prompt_value(url_label)
        auth_mode = _prompt_value(f"{service} auth mode", "session-cookie-file")
        if auth_mode not in {"basic", "session-cookie-file", "bearer-token"} \
                or auth_mode == "bearer-token" and service != "jira":
            raise ValueError("integration setup authentication mode is invalid")
        username = _prompt_value(f"{service} username") if auth_mode == "basic" else ""
        credential = getpass.getpass(
            f"{service} " + (
                "password/token" if auth_mode == "basic"
                else "API token" if auth_mode == "bearer-token" else "Cookie header value"
            ) + ": ",
        )
        smoke_resource = _prompt_value(smoke_label)
        allowed = (smoke_resource,) if service == "confluence" else ()
        services.append(ServiceSetupInput(service, url, auth_mode, username, scope_mode, allowed, smoke_resource))
        credentials[service] = credential
    profile = LocalIntegrationProfile(product_root, state_root)
    return profile.configure(IntegrationSetupInput(identity.principal_id, ca_file, tuple(services)), credentials)


def _integration_credential_update(arguments: list[str]) -> dict[str, object]:
    """Rotates one Jira PAT from hidden input under an authorized Git identity."""

    options = _exact_options(arguments, frozenset({"--state-root", "--service", "--auth-mode"}))
    if set(options) != {"--state-root", "--service", "--auth-mode"} or not sys.stdin.isatty():
        raise ValueError("integration credential update requires an interactive terminal and exact options")
    if options["--service"] != "jira" or options["--auth-mode"] != "bearer-token":
        raise ValueError("integration credential update supports only Jira bearer token")
    product_root = Path(__file__).resolve().parents[1]
    identity = GitIdentityResolver(
        product_root.parent, product_root / "config" / "local-auth.json",
    ).resolve()
    if identity.status != "recognized" or identity.principal_id not in {"owner-local", "maintainer-local"}:
        raise PermissionError("integration credential update identity is not authorized")
    credential = getpass.getpass("Jira API token: ")
    return LocalIntegrationProfile(product_root, Path(options["--state-root"])).rotate_credential(
        "jira", "bearer-token", credential,
    )


def _integration_smoke(arguments: list[str]) -> dict[str, object]:
    """Runs one explicit authenticated read per integration; never falls back to fixtures."""

    options = _exact_options(arguments, frozenset({"--state-root", "--jira-project", "--airflow-dag"}))
    if "--state-root" not in options:
        raise ValueError("integration smoke requires exact state root")
    root, supplied_state = Path(__file__).resolve().parents[1], Path(options["--state-root"])
    if supplied_state.is_symlink() or supplied_state.resolve(strict=True) != supplied_state:
        raise ValueError("integration smoke state root is unsafe")
    state = supplied_state
    environment = dict(os.environ)
    token = environment.get("PF_WORK_SESSION", "")
    local_runtime = None
    if not token and not any(key.startswith("PF_INTEGRATION_") for key in environment):
        local_runtime = LocalIntegrationProfile(root, state).load()
        environment.update(local_runtime.environment)
        token = local_runtime.work_session
    if not token:
        raise PermissionError("integration smoke requires authenticated work session")
    hub = build_production_mcp_hub(root, state, environment)
    config = IntegrationBackendConfig.from_env(environment)
    actor = hub.hub.authenticator.authenticate(token).principal
    if actor is None:
        raise PermissionError("integration smoke authentication denied")
    jira_default = local_runtime.jira_project if local_runtime is not None else None
    airflow_default = local_runtime.airflow_dag if local_runtime is not None else None
    jira_project = config.jira.smoke_resource(options.get("--jira-project", jira_default))
    airflow_dag = config.airflow.smoke_resource(options.get("--airflow-dag", airflow_default))
    probes = (
        ("confluence.search_pages", {
            "query": "readiness", "space_key": config.confluence.smoke_resource(None), "limit": 1,
        }),
        ("jira.search_issues", {
            "project_key": jira_project, "query": "readiness", "limit": 1,
        }),
        ("airflow.list_dag_runs", {
            "dag_id": airflow_dag, "limit": 1,
        }),
    )
    statuses = []
    for index, (capability, arguments_payload) in enumerate(probes, start=1):
        trace_id = f"integration-smoke-{index}"
        result = hub.execute(token, McpRequest(
            actor.project_id, "engineering-change", capability, "1.0.0", arguments_payload,
            "internal", trace_id,
        ), PrivacyContext(actor.project_id, trace_id, actor.id, "engineering-change", "local", False, 300))
        statuses.append({"capability": capability, "status": result.status, "reason_code": result.receipt.reason_code})
    status = "passed" if all(item["status"] == "ok" for item in statuses) else "failed"
    return {"schema_version": "1.0", "status": status, "probes": statuses, "network_used": True}


def _pilot_acceptance(arguments: list[str]) -> dict[str, object]:
    """Runs the closed Sprint 5 pilot without returning task or integration data."""

    options = _exact_options(arguments, frozenset({"--state-root"}))
    if set(options) != {"--state-root"}:
        raise ValueError("pilot acceptance requires exact state root")
    cases = (
        ("engineer-local", "confluence.search"),
        ("analyst-local", "jira.read"),
        ("owner-local", "documentation.sync"),
        ("owner-local", "confluence.snapshot"),
    )
    previews = tuple(execute_work([
        "--principal-id", principal_id, "--task-kind", task_kind,
        "--trace-id", f"pilot-{index}",
    ]) for index, (principal_id, task_kind) in enumerate(cases, start=1))
    if any(item.get("status") != "ready" for item in previews):
        raise RuntimeError("pilot representative preview failed")

    routing = _routing_preview_check()
    boundary = _execution_boundary_check()
    executors = _trusted_executors_check()
    lifecycle = _pilot_check()
    review = _review_evidence_loop_check()
    token = _token_efficiency_check()
    smoke = _integration_smoke(["--state-root", options["--state-root"]])
    probes = smoke.get("probes")
    expected_capabilities = {
        "confluence.search_pages", "jira.search_issues", "airflow.list_dag_runs",
    }
    valid_probes = (
        isinstance(probes, list)
        and len(probes) == 3
        and {item.get("capability") for item in probes if isinstance(item, dict)} == expected_capabilities
        and all(
            isinstance(item, dict) and item.get("status") == "ok" and item.get("reason_code") == "completed"
            for item in probes
        )
    )
    if not (
        routing.get("status") == "ok"
        and routing.get("route_combinations") == routing.get("unique_plan_digests")
        and boundary.get("status") == "ok"
        and executors.get("status") == "ok"
        and executors.get("catalog_task_kinds") == executors.get("registered_task_kinds")
        and executors.get("synthetic_fallback_forbidden") is True
        and lifecycle.get("status") == "ok"
        and review.get("status") == "ok"
        and token.get("status") == "ok"
        and smoke.get("status") == "passed"
        and smoke.get("network_used") is True
        and valid_probes
    ):
        raise RuntimeError("pilot acceptance gate failed")
    return {
        "schema_version": "1.0",
        "status": "passed",
        "route_combinations": routing["route_combinations"],
        "catalog_task_kinds": executors["catalog_task_kinds"],
        "registered_task_kinds": executors["registered_task_kinds"],
        "representative_previews": len(previews),
        "engineer_previews": 1,
        "analyst_previews": 1,
        "administrative_previews": 2,
        "role_authorization_cases": boundary["cases"],
        "live_principals": 1,
        "offline_lifecycle": "passed",
        "review_evidence": "passed",
        "token_evidence": "passed",
        "live_probes": len(probes),
        "mutations_executed": 0,
        "synthetic_fallback_forbidden": True,
        "network_used": True,
    }


def _exact_options(arguments: list[str], allowed: frozenset[str]) -> dict[str, str]:
    """Parses closed key/value CLI options and rejects duplicates or positional values."""

    if len(arguments) % 2:
        raise ValueError("integration smoke options are invalid")
    result: dict[str, str] = {}
    for index in range(0, len(arguments), 2):
        key, value = arguments[index:index + 2]
        if key not in allowed or key in result or not value:
            raise ValueError("integration smoke options are invalid")
        result[key] = value
    return result


def _skills_check() -> dict[str, object]:
    root = Path(__file__).resolve().parents[1]
    profile = load_project_profile(root / "project-profile.yaml")
    if profile.skill_approvals is None:
        if profile.pack.approved_skill_order:
            raise RuntimeError("active project pack has no skill approval registry")
        return {
            "status": "ok", "library_version": "1.0", "packages": 0,
            "approved": 0, "in_review": 0, "lifecycle_order": [],
            "distributed": 0, "eval_cases": 0, "eval_passed": 0, "network_calls": 0,
        }
    registry = RepositorySkillApprovalRegistry.from_file(profile.skill_approvals)
    library = load_skill_library(profile.skills_root, registry.verify)
    approved = sum(release.status == "approved" and release.integrity_verified for release in library.releases)
    in_review = sum(release.status == "review" and release.integrity_verified for release in library.releases)
    eval_results = tuple(
        require_skill_evals(profile.skills_root / release.id, release)
        for release in library.releases if release.status == "approved"
    )
    catalog = catalog_from_skill_library(library, registry.ordered_skill_ids)
    return {
        "status": "ok", "library_version": "1.0", "packages": len(library.releases),
        "approved": approved, "in_review": in_review, "lifecycle_order": list(registry.ordered_skill_ids),
        "distributed": len(catalog.skills), "eval_cases": sum(total for total, _ in eval_results),
        "eval_passed": sum(passed for _, passed in eval_results),
        "network_calls": 0,
    }


def _review_check() -> dict[str, object]:
    root = Path(__file__).resolve().parents[1]
    fixture = json.loads((root / "validation-assets" / "review-v1.json").read_text(encoding="utf-8"))
    checks = tuple(
        CheckEvidence(check_id, "passed", f"receipt:{check_id}:fixture123")
        for check_id in ("syntax", "tests", "contracts", "security", "deploy_safety")
    )
    outcomes: list[tuple[bool, bool]] = []
    for case in fixture["cases"]:
        changed = ChangedFile(case["path"], case["diff"], case["deploy_candidate"])
        review_request = ReviewRequest(
            "promptforge", "engineering-change", diff_digest((changed,)), (changed,), checks, True,
            "draft-0.1", "1.0", ("review-engine:1.0.0",), "deterministic-only", f"review-{case['id']}",
            (), (),
        )
        receipts = frozenset(
            (check.check_id, check.status, check.evidence, review_request.diff_digest) for check in checks
        )
        blocking = ReviewEngine(FakeReviewEvidenceVerifier(receipts)).review(
            review_request
        ).receipt.status == "changes_requested"
        outcomes.append((bool(case["expected_blocking"]), blocking))
    positives = sum(expected for expected, _ in outcomes)
    negatives = len(outcomes) - positives
    recall = sum(expected and actual for expected, actual in outcomes) / positives if positives else 1.0
    false_positive_rate = (
        sum(not expected and actual for expected, actual in outcomes) / negatives if negatives else 0.0
    )
    return {
        "status": "ok", "review_version": fixture["review_version"], "cases": len(outcomes),
        "blocking_recall": recall, "blocking_false_positive_rate": false_positive_rate, "network_calls": 0,
    }


def _review_provenance_check() -> dict[str, object]:
    """Проверяет durable review chain локально, без постоянного state и сети."""

    changed = ChangedFile("src/fixture.py", "+VALUE = 1", False)
    request = ReviewRequest(
        "promptforge", "engineering-change", diff_digest((changed,)), (changed,), (), True,
        "draft-0.1", "1.0", ("review-engine:2.0.0",), "deterministic-only", "review-v2-check",
    )
    result = ReviewEngine().review(request)
    catalog_digest = "sha256:" + "a" * 64
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory).resolve() / "review-provenance.sqlite3"
        key = secrets.token_bytes(32)
        first = ReviewProvenanceStore(path, key)
        DurableReviewFoundation(first).record(request, result, agent_catalog_digest=catalog_digest)
        reopened = ReviewProvenanceStore(path, key)
        restart_verified = reopened.verify().valid
        try:
            DurableReviewFoundation(reopened).record(request, result, agent_catalog_digest=catalog_digest)
        except ValueError:
            replay_denied = True
        else:
            replay_denied = False
        import sqlite3
        connection = sqlite3.connect(path)
        connection.execute("UPDATE review_provenance SET status='passed' WHERE sequence=1")
        connection.commit()
        connection.close()
        tamper_detected = not reopened.verify().valid
    return {
        "status": "ok" if restart_verified and replay_denied and tamper_detected else "error",
        "review_version": "2.0", "records": 1, "restart_verified": restart_verified,
        "replay_denied": replay_denied, "tamper_detected": tamper_detected, "network_used": False,
    }


def _review_evidence_loop_check() -> dict[str, object]:
    """Verifies approved/blocked persistence, restart checks and tamper detection offline."""

    import sqlite3
    from dataclasses import replace

    changed = ChangedFile("src/evidence.py", "+VALUE = 1", False)
    key = bytes.fromhex("52" * 32)
    clock = lambda: 1_800_000_000
    with tempfile.TemporaryDirectory() as directory:
        state = Path(directory).resolve()
        state.chmod(0o700)
        loop = ReviewEvidenceLoop(state, key, clock=clock)
        outcomes = []
        for suffix, contract_reviewed in (("approved", True), ("blocked", False)):
            request = ReviewRequest(
                "promptforge", "engineering-change", diff_digest((changed,)), (changed,), (), contract_reviewed,
                "draft-0.1", "1.0", ("review-engine:1.0.0",), "deterministic-only", f"evidence-{suffix}",
            )
            result = ReviewEngine().review(request)
            result = replace(result, receipt=replace(
                result.receipt, status="passed" if suffix == "approved" else "changes_requested",
            ))
            outcome = "retained" if result.receipt.status == "passed" else "rolled-back"
            receipt = loop.record(
                request, result, "sha256:" + "a" * 64,
                Principal("engineer-local", "engineer", "promptforge"), outcome,
                "sha256:" + ("1" if outcome == "retained" else "2") * 64,
            )
            outcomes.append(receipt.final_outcome)
        provenance = ReviewProvenanceStore(state / "review-provenance.sqlite3", key, clock=clock).verify()
        audit_store = LocalAuditStore(state / "audit.sqlite3", key, clock=clock)
        audit = audit_store.verify()
        restart_verified = provenance.valid and provenance.records == 2 and audit.valid and audit.events == 2
        connection = sqlite3.connect(state / "audit.sqlite3")
        connection.execute("UPDATE audit_events SET reason_code='retained' WHERE sequence=2")
        connection.commit()
        connection.close()
        tamper_detected = not audit_store.verify().valid
    valid = outcomes == ["retained", "rolled-back"] and restart_verified and tamper_detected
    return {
        "schema_version": "1.0", "loop_version": "1.0.0", "status": "ok" if valid else "error",
        "outcomes_recorded": len(outcomes), "restart_verified": restart_verified,
        "tamper_detected": tamper_detected, "network_calls": 0,
    }


def execute_work(arguments: list[str], *, mcp_hub: AuditedMcpHub | None = None) -> dict[str, object]:
    """Public embedding boundary for one authenticated work lifecycle."""

    values: dict[str, str] = {}
    paths: list[str] = []
    deploy: list[str] = []
    execute = False
    index = 0
    while index < len(arguments):
        option = arguments[index]
        if option == "--execute":
            if execute:
                raise ValueError("work execute option is duplicated")
            execute = True
            index += 1
            continue
        if option not in {
            "--principal-id", "--task-kind", "--trace-id", "--path", "--deploy", "--state-root", "--mode",
            "--input-json",
        }:
            raise ValueError("work option is unknown")
        if index + 1 >= len(arguments):
            raise ValueError("work option value is missing")
        value = arguments[index + 1]
        if option == "--path":
            paths.append(value)
        elif option == "--deploy":
            deploy.append(value)
        else:
            if option in values:
                raise ValueError("work option is duplicated")
            values[option] = value
        index += 2
    principal_id = values.get("--principal-id")
    if principal_id is None:
        raise ValueError("work principal is required")
    explicit_mode = values.get("--mode")
    if explicit_mode not in {None, "preview", "execute"} or execute and explicit_mode == "preview":
        raise ValueError("work mode is invalid or ambiguous")
    execute = execute or explicit_mode == "execute"
    trace_id = values.get("--trace-id", f"work-{secrets.token_hex(8)}")
    input_path_value = values.get("--input-json")
    task_inputs: dict[str, object] | None = None
    if input_path_value is not None:
        state_root_value = values.get("--state-root")
        if state_root_value is None:
            raise ValueError("work input requires state root")
        task_inputs = _load_work_input(Path(input_path_value), Path(state_root_value))
    request = WorkRequest(
        principal_id, values.get("--task-kind"), trace_id, tuple(paths), tuple(deploy),
        "execute" if execute else "preview", task_inputs is not None,
    )
    product_root, workspace_root = _work_roots()
    plan = UnifiedWorkCoordinator.from_repository(product_root).plan(request)
    payload = plan.to_payload()
    if not execute or plan.status != "ready":
        return payload
    token = os.environ.get("PF_WORK_SESSION", "")
    try:
        authenticator = EmbeddedSessionAuthenticator(
            load_embedded_registry(product_root), embedded_auth_key_from_env(),
        )
        boundary = AuthenticatedExecutionBoundary.from_repository(product_root, authenticator)
        authorization = boundary.authorize(token, principal_id, plan)
    except (OSError, PermissionError, ValueError):
        authorization = None
    if authorization is None or authorization.status != "allowed":
        denial_reason = (
            "authenticated_session_required"
            if authorization is None or authorization.reason_code == "missing_or_invalid_session"
            else authorization.reason_code
        )
        stages = [
            {
                **stage,
                "status": "denied" if stage["id"] == "resolve-identity" else "blocked" if stage["status"] != "not-applicable"
                else "not-applicable",
            }
            for stage in payload["stages"]
        ]
        return _seal_work_payload({
            **payload, "status": "denied",
            "reason_code": denial_reason,
            "stages": stages, "authorization": None if authorization is None else authorization.to_payload(),
        })
    try:
        principal = _work_principal(product_root, principal_id)
    except (PermissionError, ValueError):
        stages = [
            {
                **stage,
                "status": "denied" if stage["id"] == "resolve-identity" else "blocked"
                if stage["status"] != "not-applicable" else "not-applicable",
            }
            for stage in payload["stages"]
        ]
        return _seal_work_payload({
            **payload, "status": "denied", "reason_code": "authenticated_session_required", "stages": stages,
            "authorization": authorization.to_payload(),
        })
    if principal.role != payload["role"]:
        stages = [
            {
                **stage,
                "status": "denied" if stage["id"] in {"resolve-identity", "route"} else "blocked"
                if stage["status"] != "not-applicable" else "not-applicable",
            }
            for stage in payload["stages"]
        ]
        return _seal_work_payload({
            **payload, "status": "denied", "reason_code": "authenticated_principal_mismatch", "stages": stages,
            "authorization": authorization.to_payload(),
        })
    state_root = values.get("--state-root")
    if state_root is None:
        raise ValueError("work execute requires durable state root")
    if plan.task_kind != "review.changed-files":
        resolved_state_root = Path(state_root)
        if task_inputs is None:
            raise ValueError("work execute requires task input JSON")
        resolved_hub = _resolve_work_mcp_hub(product_root, resolved_state_root, plan.task_kind, mcp_hub)
        metrics_key = hmac.new(
            local_audit_key_from_env(), b"promptforge-efficiency-metrics-v1", hashlib.sha256,
        ).digest()
        metrics = EfficiencyMetricsStore(resolved_state_root / "efficiency-metrics.sqlite3", metrics_key)
        execution = AgentExecutionRegistry.builtin(
            product_root, mcp_hub=resolved_hub, mcp_token=os.environ.get("PF_WORK_SESSION", ""),
            metrics=metrics,
        ).execute(
            AgentExecutionRequest(plan.task_kind, trace_id, task_inputs),
            AgentExecutionContext(
                workspace_root, resolved_state_root, principal, plan, boundary.governance, product_root,
            ),
        )
        stages = [
            {
                **stage,
                "status": "complete" if stage["id"] in {"resolve-identity", "route", "execute-skill", "evidence"}
                else "not-applicable",
            }
            for stage in payload["stages"]
        ]
        result = execution.to_payload()
        if execution.status == "blocked":
            blocked_stages = [
                {
                    **stage,
                    "status": "complete" if stage["id"] in {"resolve-identity", "route"}
                    else "not-applicable" if stage["status"] == "not-applicable" else "blocked",
                }
                for stage in payload["stages"]
            ]
            return _seal_work_payload({
                **payload, "status": "blocked", "reason_code": execution.reason_code,
                "stages": blocked_stages, "required_inputs": [], "execution": result,
                "authorization": authorization.to_payload(),
            })
        return _seal_work_payload({
            **payload, "status": "completed", "reason_code": "skill_completed", "execution": result,
            "stages": stages, "required_inputs": [], "authorization": authorization.to_payload(),
        })
    changed_arguments = [item for path in paths for item in ("--path", path)]
    changed_arguments.extend(item for path in deploy for item in ("--deploy", path))
    changed_arguments.extend(("--state-root", state_root))
    execution = _changed_review(changed_arguments, principal.id, workspace_root)
    stages = [
        {
            **stage,
            "status": (
                "complete"
                if stage["id"] in {"resolve-identity", "route", "execute-skill", "changed-files-review", "evidence"}
                else "not-applicable" if stage["id"] == "documentation" else stage["status"]
            ),
        }
        for stage in payload["stages"]
    ]
    return _seal_work_payload({
        **payload, "status": "completed", "reason_code": "review_completed", "execution": execution,
        "stages": stages, "required_inputs": [], "authorization": authorization.to_payload(),
    })


def main() -> int:
    command = sys.argv[1] if len(sys.argv) > 1 else "health"
    if command in {"identity-check", "owner-keygen", "release-sign", "release-verify"}:
        try:
            handlers = {
                "identity-check": _identity_check, "owner-keygen": _owner_keygen,
                "release-sign": _release_sign, "release-verify": _release_verify,
            }
            payload = handlers[command](sys.argv[2:])
        except (OSError, PermissionError, RuntimeError, ValueError):
            print(json.dumps({
                "schema_version": "1.0", "status": "error", "reason_code": "identity_signing_failed",
                "network_used": False,
            }))
            return 1
        print(json.dumps(payload, ensure_ascii=False, sort_keys=True))
        return 0 if payload["status"] not in {"denied", "error"} else 1
    if command in {"ask", "intake"}:
        arguments = sys.argv[2:]
        try:
            values: dict[str, str] = {}
            index = 0
            while index < len(arguments):
                option = arguments[index]
                if option not in {"--principal-id", "--trace-id", "--state-root"}:
                    raise ValueError("ask arguments are invalid")
                if index + 1 >= len(arguments) or option in values:
                    raise ValueError("ask arguments are invalid")
                values[option] = arguments[index + 1]
                index += 2
            principal_id = values.get("--principal-id")
            if principal_id is None:
                raise ValueError("ask requires principal id")
            trace_id = values.get("--trace-id", f"intake-{secrets.token_hex(8)}")
            raw = sys.stdin.buffer.read(16_385)
            if len(raw) > 16_384:
                raise ValueError("task input is oversized")
            content = raw.decode("utf-8", errors="strict")
            product_root = Path(__file__).resolve().parents[1]
            lifecycle = WorkspaceLifecycle.from_product(
                product_root,
                Path(values["--state-root"]) if "--state-root" in values else None,
            )
            if not lifecycle.status()["running"]:
                raise RuntimeError("workspace runtime is not running")
            payload = TaskIntake.from_product(product_root).plan(principal_id, trace_id, content).to_payload()
        except (OSError, PermissionError, RuntimeError, UnicodeError, ValueError):
            print(json.dumps({
                "schema_version": "1.0", "intake_version": "1.0.0", "status": "error",
                "reason_code": "task_intake_failed", "network_used": False,
            }))
            return 1
        print(json.dumps(payload, ensure_ascii=False, sort_keys=True))
        return 0 if payload["status"] == "ready" else 1
    if command in {"setup", "start", "status", "doctor", "stop"}:
        arguments = sys.argv[2:]
        try:
            if not arguments:
                state_root = None
            elif len(arguments) == 2 and arguments[0] == "--state-root":
                state_root = Path(arguments[1])
            else:
                raise ValueError("invalid workspace lifecycle arguments")
            lifecycle = WorkspaceLifecycle.from_product(Path(__file__).resolve().parents[1], state_root)
            payload = getattr(lifecycle, command)()
        except (OSError, PermissionError, RuntimeError, ValueError):
            print(json.dumps({
                "schema_version": "1.0", "command": command, "status": "error",
                "code": "workspace_lifecycle_failed", "network_used": False,
            }))
            return 1
        print(json.dumps(payload, ensure_ascii=False, sort_keys=True))
        return 0 if payload["status"] not in {"blocked", "error"} else 1
    if command == "work":
        try:
            payload = execute_work(sys.argv[2:])
        except (OSError, PermissionError, RuntimeError, ValueError):
            print(json.dumps({"status": "error", "code": "work_failed"}))
            return 1
        print(json.dumps(payload, ensure_ascii=False, sort_keys=True))
        return 0 if payload["status"] in {"ready", "completed"} else 1
    if command == "changed-review":
        try:
            payload = _changed_review(sys.argv[2:])
        except (OSError, RuntimeError, ValueError):
            print(json.dumps({"status": "error", "code": "changed_review_failed"}))
            return 1
        print(json.dumps(payload, ensure_ascii=False, sort_keys=True))
        return 0
    if command == "docs-sync":
        try:
            payload = _docs_sync(sys.argv[2:])
        except (OSError, PermissionError, RuntimeError, ValueError):
            print(json.dumps({"status": "error", "code": "docs_sync_failed"}))
            return 1
        print(json.dumps(payload, ensure_ascii=False, sort_keys=True))
        return 0
    if command in {"kill-switch", "state-cleanup"}:
        try:
            payload = (
                _kill_switch_command(sys.argv[2:]) if command == "kill-switch"
                else _state_cleanup_command(sys.argv[2:])
            )
        except (OSError, PermissionError, RuntimeError, ValueError):
            print(json.dumps({"status": "error", "code": "operations_command_failed"}))
            return 1
        print(json.dumps(payload, ensure_ascii=False, sort_keys=True))
        return 0
    if command == "neutrality-check":
        try:
            payload = _neutrality_check()
        except (OSError, RuntimeError, ValueError):
            print(json.dumps({"status": "error", "code": "neutrality_check_failed"}))
            return 1
        print(json.dumps(payload, ensure_ascii=False, sort_keys=True))
        return 0
    if command == "production-docs-check":
        try:
            payload = _production_docs_check()
        except (OSError, RuntimeError, ValueError):
            print(json.dumps({"status": "error", "code": "production_docs_failed"}))
            return 1
        print(json.dumps(payload, ensure_ascii=False, sort_keys=True))
        return 0 if payload["status"] == "passed" else 1
    if command == "release-candidate-check":
        try:
            payload = _release_candidate_check(sys.argv[2:])
        except (OSError, PermissionError, RuntimeError, ValueError):
            print(json.dumps({"status": "error", "code": "release_candidate_failed"}))
            return 1
        print(json.dumps(payload, ensure_ascii=False, sort_keys=True))
        return 0 if payload["status"] == "accepted" else 1
    if command == "mr-scope-check":
        try:
            payload = _mr_scope_check(sys.argv[2:])
        except (OSError, PermissionError, RuntimeError, ValueError):
            print(json.dumps({"schema_version": "1.0", "status": "error", "code": "mr_scope_check_failed"}))
            return 1
        print(json.dumps(payload, ensure_ascii=False, sort_keys=True))
        return 0 if payload["status"] == "passed" else 1
    if command == "integration-setup":
        try:
            payload = _integration_setup(sys.argv[2:])
        except (EOFError, OSError, PermissionError, RuntimeError, ValueError):
            print(json.dumps({"status": "error", "code": "integration_setup_failed"}))
            return 1
        print(json.dumps(payload, ensure_ascii=False, sort_keys=True))
        return 0
    if command == "integration-credential-update":
        try:
            payload = _integration_credential_update(sys.argv[2:])
        except (EOFError, OSError, PermissionError, RuntimeError, ValueError):
            print(json.dumps({"status": "error", "code": "integration_credential_update_failed"}))
            return 1
        print(json.dumps(payload, ensure_ascii=False, sort_keys=True))
        return 0
    if command == "integration-smoke":
        try:
            payload = _integration_smoke(sys.argv[2:])
        except (OSError, PermissionError, RuntimeError, ValueError):
            print(json.dumps({"status": "error", "code": "integration_smoke_failed"}))
            return 1
        print(json.dumps(payload, ensure_ascii=False, sort_keys=True))
        return 0 if payload["status"] == "passed" else 1
    if command == "pilot-acceptance":
        try:
            payload = _pilot_acceptance(sys.argv[2:])
        except (OSError, PermissionError, RuntimeError, ValueError):
            print(json.dumps({
                "schema_version": "1.0", "status": "error", "code": "pilot_acceptance_failed",
                "network_used": True,
            }))
            return 1
        print(json.dumps(payload, ensure_ascii=False, sort_keys=True))
        return 0
    if command == "operations-acceptance":
        try:
            payload = OperationalAcceptanceRunner(Path(__file__).resolve().parents[1]).run()
        except (OSError, PermissionError, RuntimeError, ValueError):
            print(json.dumps({
                "schema_version": "1.0", "acceptance_version": "operations-v1", "status": "error",
                "scenarios": 9, "passed": 0, "failed": 9, "results": [], "isolated": True,
                "real_state_touched": False, "network_used": False,
            }))
            return 1
        print(json.dumps(payload, ensure_ascii=False, sort_keys=True))
        return 0 if payload["status"] == "passed" else 1
    if command == "metrics-summary":
        try:
            options = _exact_options(sys.argv[2:], frozenset({"--state-root"}))
            key = hmac.new(
                local_audit_key_from_env(), b"promptforge-efficiency-metrics-v1", hashlib.sha256,
            ).digest()
            payload = EfficiencyMetricsStore(
                Path(options["--state-root"]) / "efficiency-metrics.sqlite3", key,
            ).summary()
        except (OSError, PermissionError, RuntimeError, ValueError):
            print(json.dumps({
                "schema_version": "1.0", "metrics_version": "efficiency-v1", "status": "error",
                "network_used": False,
            }))
            return 1
        print(json.dumps(payload, ensure_ascii=False, sort_keys=True))
        return 0
    if command == "integration-readiness-check":
        try:
            payload = _integration_readiness_check()
        except (OSError, RuntimeError, ValueError):
            print(json.dumps({"status": "error", "code": "integration_readiness_failed"}))
            return 1
        print(json.dumps(payload, ensure_ascii=False, sort_keys=True))
        return 0
    commands = {
        "health": health_payload,
        "demo": _demo,
        "check": _check,
        "policy-check": _policy_check,
        "project-profile-check": _project_profile_check,
        "portable-pack-check": _portable_pack_check,
        "repository-index-check": _repository_index,
        "repository-index-build": lambda: _repository_index(write=True),
        "task-router-check": _task_router_check,
        "routing-preview-check": _routing_preview_check,
        "execution-boundary-check": _execution_boundary_check,
        "trusted-executors-check": _trusted_executors_check,
        "task-intake-check": _task_intake_check,
        "governance-check": _governance_check,
        "privacy-check": _privacy_check,
        "model-gateway-check": _model_gateway_check,
        "secure-runtime-check": _secure_runtime_check,
        "pilot-check": _pilot_check,
        "final-evidence-check": _final_evidence_check,
        "docs-check": _docs_check,
        "token-efficiency-check": _token_efficiency_check,
        "operations-check": _operations_check,
        "local-inference-check": _local_inference_check,
        "model-admission-check": _model_admission_check,
        "model-eval-check": _model_eval_check,
        "model-admission-workflow-check": _model_admission_workflow_check,
        "auth-check": _auth_check,
        "embedded-auth-check": _embedded_auth_check,
        "audit-check": _audit_check,
        "mcp-hub-check": _mcp_hub_check,
        "integrations-check": _integrations_check,
        "skills-check": _skills_check,
        "review-check": _review_check,
        "review-provenance-check": _review_provenance_check,
        "review-evidence-loop-check": _review_evidence_loop_check,
    }
    if command not in commands:
        print(json.dumps({"status": "error", "code": "unknown_command"}))
        return 2
    print(json.dumps(commands[command](), ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
