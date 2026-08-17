"""Контракты и минимальный runtime PromptForge Platform."""

from promptforge.platform.auth import (
    AuthentikAuthenticator, EmbeddedRoleRegistry, EmbeddedSessionAuthenticator, OIDCClaims,
)
from promptforge.platform.audit_runtime import AuditedMcpHub, AuditedModelGateway
from promptforge.platform.catalog import SkillCatalog, builtin_skill_catalog
from promptforge.platform.contracts import (
    ModelRequest,
    PolicyDecision,
    PolicyRequest,
    Principal,
    ReviewFinding,
    SkillSpec,
)
from promptforge.platform.policy import PolicyEngine
from promptforge.platform.gateway import ModelRegistry
from promptforge.platform.privacy import PrivacyContext, PrivacyPipeline, ScopedMappingVault
from promptforge.platform.secure_runtime import SecureRuntime, build_secure_runtime
from promptforge.platform.pilot import OfflinePilotRunner, PilotEvidence, build_offline_pilot
from promptforge.platform.changed_review import ChangedFilesReviewRunner
from promptforge.platform.docs_automation import DocumentationAutomation, DocumentationImpactReport, DocumentationPlan
from promptforge.platform.token_efficiency import ContextItem, TokenBudget, TokenEfficiencyRuntime, UsageReceipt
from promptforge.platform.token_usage_store import DurableUsageReceipt, TokenUsageStore, TokenUsageVerification
from promptforge.platform.optimized_runtime import OptimizedGatewayResult, OptimizedModelRuntime
from promptforge.platform.skill_library import RepositorySkillApprovalRegistry, SkillLifecycle
from promptforge.platform.operations import LocalKillSwitch, LocalStateCleaner, OperationsConfig
from promptforge.platform.final_evidence import FinalEvidence, FinalEvidenceRunner
from promptforge.platform.release_candidate import ReleaseCandidate, ReleaseCandidateRunner
from promptforge.platform.git_identity import GitIdentityClaim, GitIdentityResolver
from promptforge.platform.release_signing import DetachedReleaseSignature
from promptforge.platform.neutrality import NeutralityGate, NeutralityReport
from promptforge.platform.governance import GovernanceActor, GovernancePolicy
from promptforge.platform.unified_ux import UnifiedWorkCoordinator, WorkRequest, WorkResult
from promptforge.platform.production_docs import ProductionDocumentationGate, ProductionDocumentationReport
from promptforge.platform.agent_execution import (
    AgentExecutionContext,
    AgentExecutionRegistry,
    AgentExecutionRequest,
    AgentExecutionResult,
    AgentExecutor,
)

__all__ = [
    "AuthentikAuthenticator",
    "AuditedModelGateway",
    "AuditedMcpHub",
    "ChangedFilesReviewRunner",
    "DocumentationAutomation",
    "DocumentationImpactReport",
    "DocumentationPlan",
    "ContextItem",
    "EmbeddedRoleRegistry",
    "EmbeddedSessionAuthenticator",
    "LocalKillSwitch",
    "LocalStateCleaner",
    "ModelRequest",
    "ModelRegistry",
    "OIDCClaims",
    "OfflinePilotRunner",
    "OperationsConfig",
    "OptimizedGatewayResult",
    "OptimizedModelRuntime",
    "FinalEvidence",
    "FinalEvidenceRunner",
    "ReleaseCandidate",
    "ReleaseCandidateRunner",
    "DetachedReleaseSignature",
    "GitIdentityClaim",
    "GitIdentityResolver",
    "GovernanceActor",
    "GovernancePolicy",
    "NeutralityGate",
    "NeutralityReport",
    "PolicyDecision",
    "PolicyEngine",
    "PrivacyContext",
    "PrivacyPipeline",
    "PolicyRequest",
    "PilotEvidence",
    "Principal",
    "RepositorySkillApprovalRegistry",
    "ReviewFinding",
    "SkillCatalog",
    "SkillSpec",
    "SkillLifecycle",
    "TokenBudget",
    "TokenEfficiencyRuntime",
    "UsageReceipt",
    "DurableUsageReceipt",
    "TokenUsageStore",
    "TokenUsageVerification",
    "UnifiedWorkCoordinator",
    "WorkRequest",
    "WorkResult",
    "ProductionDocumentationGate",
    "ProductionDocumentationReport",
    "AgentExecutionContext",
    "AgentExecutionRegistry",
    "AgentExecutionRequest",
    "AgentExecutionResult",
    "AgentExecutor",
    "ScopedMappingVault",
    "SecureRuntime",
    "build_secure_runtime",
    "build_offline_pilot",
    "builtin_skill_catalog",
]
