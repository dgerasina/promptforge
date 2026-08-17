"""Единая fail-closed сборка repository-only runtime PromptForge."""

from __future__ import annotations

from dataclasses import dataclass, replace
import json
import hmac
import hashlib
import os
from pathlib import Path
import stat
import time
from typing import Callable, Mapping

from promptforge.platform.auth import (
    AuthenticatedModelGateway,
    EmbeddedRoleRegistry,
    EmbeddedSessionAuthenticator,
    embedded_auth_key_from_env,
)
from promptforge.platform.audit_runtime import AuditedMcpHub, AuditedModelGateway
from promptforge.platform.gateway import ModelGateway
from promptforge.platform.local_audit import LocalAuditStore, local_audit_key_from_env
from promptforge.platform.mcp_hub import ApprovalStore, McpHub
from promptforge.platform.mcp_hub import McpRegistry
from promptforge.platform.integration_backends import IntegrationBackendBundle
from promptforge.platform.integrations import capabilities_for_project_profile
from promptforge.platform.policy import PolicyEngine
from promptforge.platform.secure_filesystem import SECURE_FILESYSTEM
from promptforge.platform.privacy import PrivacyPipeline, ScopedMappingVault
from promptforge.core.project_profile import load_project_profile
from promptforge.platform.operations import LocalKillSwitch
from promptforge.platform.optimized_runtime import OptimizedModelRuntime, load_token_budget
from promptforge.platform.token_efficiency import TokenBudget, TokenEfficiencyRuntime
from promptforge.platform.token_usage_store import TokenUsageStore
from promptforge.platform.governance import GovernancePolicy
from promptforge.platform.efficiency_metrics import EfficiencyMetricsStore


@dataclass(frozen=True)
class SecureRuntime:
    """Предоставляет control-plane state и только аудируемые execution-границы."""

    authenticator: EmbeddedSessionAuthenticator
    audit: LocalAuditStore
    models: OptimizedModelRuntime
    mcp: AuditedMcpHub
    kill_switch: LocalKillSwitch
    metrics: EfficiencyMetricsStore


def build_production_mcp_hub(
    repo_root: Path, state_root: Path, environment: Mapping[str, str], *,
    clock: Callable[[], float] = time.time,
) -> AuditedMcpHub:
    """Builds the only supported real read-only integration Hub from injected environment."""

    root = Path(repo_root).resolve(strict=True)
    private_state = _validate_state_root(state_root)
    profile = load_project_profile(root / "project-profile.yaml")
    bundle = IntegrationBackendBundle.from_env(environment)
    registry = load_embedded_registry(root)
    authenticator = EmbeddedSessionAuthenticator(registry, embedded_auth_key_from_env(environment), clock=clock)
    audit_key = local_audit_key_from_env(environment)
    audit = LocalAuditStore(private_state / "audit.sqlite3", audit_key, clock=clock)
    metrics_key = hmac.new(audit_key, b"promptforge-efficiency-metrics-v1", hashlib.sha256).digest()
    metrics = EfficiencyMetricsStore(private_state / "efficiency-metrics.sqlite3", metrics_key)
    switch = LocalKillSwitch(private_state, audit_key, clock=clock)
    switch.status()
    hub = McpHub(
        authenticator,
        McpRegistry(capabilities_for_project_profile(profile)),
        {
            "confluence": bundle.confluence_adapter,
            "jira": bundle.jira_adapter,
            "airflow": bundle.airflow_adapter,
        },
        PolicyEngine(), PrivacyPipeline(ScopedMappingVault(clock=clock)),
        ApprovalStore(clock=clock, governance=GovernancePolicy.from_repository(root), metrics=metrics),
        clock=clock, metrics=metrics,
    )
    return AuditedMcpHub(hub, audit, clock=clock, availability_check=lambda: not switch.status().engaged)


def _strict_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON field: {key}")
        result[key] = value
    return result


def load_embedded_registry(repo_root: Path) -> EmbeddedRoleRegistry:
    root = Path(repo_root)
    if not root.is_absolute() or not root.is_dir() or root.is_symlink() or root.resolve() != root:
        raise ValueError("repository root must be an absolute regular directory")
    path = root / "config" / "local-auth.json"
    descriptor = -1
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        metadata = os.fstat(descriptor)
        owner_ok = not hasattr(os, "getuid") or metadata.st_uid == os.getuid()
        if (
            not stat.S_ISREG(metadata.st_mode) or metadata.st_size > 100_000
            or not owner_ok or stat.S_IMODE(metadata.st_mode) & 0o022
        ):
            raise ValueError("embedded auth config must be a bounded private repository file")
        with os.fdopen(descriptor, "r", encoding="utf-8") as stream:
            descriptor = -1
            payload = json.load(stream, object_pairs_hook=_strict_object)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ValueError("embedded auth config is invalid") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    return EmbeddedRoleRegistry.from_payload(payload)


def _validate_state_root(state_root: Path) -> Path:
    path = Path(state_root)
    try:
        SECURE_FILESYSTEM.require_private_directory(path)
    except (PermissionError, ValueError) as error:
        raise ValueError("runtime state root must be owner-private") from error
    return path


def build_secure_runtime(
    repo_root: Path,
    state_root: Path,
    environment: Mapping[str, str],
    model_gateway: ModelGateway,
    mcp_hub: McpHub,
    *,
    clock: Callable[[], float] = time.time,
    token_budget: TokenBudget | None = None,
) -> SecureRuntime:
    """Собирает shared auth/audit и не возвращает неаудируемые фасады."""

    registry = load_embedded_registry(repo_root)
    governance = GovernancePolicy.from_repository(repo_root)
    private_state = _validate_state_root(state_root)
    authenticator = EmbeddedSessionAuthenticator(registry, embedded_auth_key_from_env(environment), clock=clock)
    audit_key = local_audit_key_from_env(environment)
    kill_switch = LocalKillSwitch(private_state, audit_key, clock=clock)
    kill_switch.status()
    audit = LocalAuditStore(private_state / "audit.sqlite3", audit_key, clock=clock)
    secured_gateway = model_gateway
    availability_check = lambda: not kill_switch.status().engaged
    audited_models = AuditedModelGateway(
        AuthenticatedModelGateway(authenticator, secured_gateway), audit, clock=clock,
        availability_check=availability_check,
    )
    usage_key = hmac.new(audit_key, b"promptforge-token-efficiency-v1", hashlib.sha256).digest()
    metrics_key = hmac.new(audit_key, b"promptforge-efficiency-metrics-v1", hashlib.sha256).digest()
    optimizer = TokenEfficiencyRuntime(usage_key, secured_gateway.verify_identity)
    usage_store = TokenUsageStore(private_state / "token-usage.sqlite3", usage_key, clock=clock)
    metrics = EfficiencyMetricsStore(private_state / "efficiency-metrics.sqlite3", metrics_key)
    if not usage_store.verify().valid:
        raise RuntimeError("token usage chain verification failed")
    models = OptimizedModelRuntime(
        audited_models, optimizer, token_budget or load_token_budget(repo_root), usage_store, metrics,
    )
    secured_hub = replace(
        mcp_hub, authenticator=authenticator,
        approvals=ApprovalStore(clock=clock, governance=governance, metrics=metrics),
        enabled=mcp_hub.enabled, metrics=metrics,
    )
    mcp = AuditedMcpHub(secured_hub, audit, clock=clock, availability_check=availability_check)
    return SecureRuntime(authenticator, audit, models, mcp, kill_switch, metrics)
