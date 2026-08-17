"""Fail-closed audit hooks для runtime boundaries PromptForge."""

from __future__ import annotations

from dataclasses import dataclass, field
import time
from typing import Callable

from promptforge.platform.auth import AuthenticatedModelGateway
from promptforge.platform.contracts import ModelRequest
from promptforge.platform.gateway import GatewayResult
from promptforge.platform.local_audit import AuditEvent, AuditSink
from promptforge.platform.mcp_hub import McpHub, McpRequest, McpResult
from promptforge.platform.privacy import PrivacyContext


@dataclass(frozen=True)
class AuditedModelGateway:
    """Блокирует model invocation, если обязательный pre-audit недоступен."""

    facade: AuthenticatedModelGateway
    audit: AuditSink
    clock: Callable[[], float] = field(default=time.time, repr=False, compare=False)
    availability_check: Callable[[], bool] = field(default=lambda: True, repr=False, compare=False)

    def invoke(self, token: str, request: ModelRequest, context: PrivacyContext) -> GatewayResult:
        authentication = self.facade.authenticator.authenticate(token)
        principal = authentication.principal
        if principal is None:
            self._append_best_effort(
                request, "anonymous", "deny", "authentication_required", "1.0",
            )
            return self.facade.gateway._deny(request, "authentication_required")
        if not self._available():
            self._append_best_effort(request, principal.id, "deny", "kill_switch_engaged", "1.0")
            return self.facade.gateway._deny(request, "kill_switch_engaged")
        try:
            self.audit.append(self._event(request, principal.id, "ok", "request_started", "1.0"))
        except Exception:
            return self.facade.gateway._deny(request, "audit_unavailable")
        result = self.facade.gateway._invoke_trusted(principal, request, context)
        try:
            self.audit.append(self._event(
                request, principal.id, result.status, result.receipt.reason_code, result.receipt.policy_version,
            ))
        except Exception:
            return self.facade.gateway._deny(request, "audit_unavailable")
        return result

    def _available(self) -> bool:
        try:
            return self.availability_check() is True
        except Exception:
            return False

    def _append_best_effort(
        self, request: ModelRequest, principal_id: str, outcome: str, reason_code: str, policy_version: str,
    ) -> None:
        try:
            self.audit.append(self._event(request, principal_id, outcome, reason_code, policy_version))
        except Exception:
            return

    def _event(
        self, request: ModelRequest, principal_id: str, outcome: str, reason_code: str, policy_version: str,
    ) -> AuditEvent:
        return AuditEvent(
            request.trace_id, principal_id, request.project_id, "model.invoke", f"model:{request.logical_model}",
            outcome, reason_code, policy_version, int(self.clock()),
        )


@dataclass(frozen=True)
class AuditedMcpHub:
    """Блокирует MCP execution, если обязательный pre-audit недоступен."""

    hub: McpHub
    audit: AuditSink
    clock: Callable[[], float] = field(default=time.time, repr=False, compare=False)
    availability_check: Callable[[], bool] = field(default=lambda: True, repr=False, compare=False)

    def execute(self, token: str, request: McpRequest, context: PrivacyContext) -> McpResult:
        authentication = self.hub.authenticator.authenticate(token)
        principal = authentication.principal
        if principal is None:
            self._append_best_effort(request, "anonymous", "deny", "authentication_required", "1.0")
            return self.hub._deny(request, "authentication_required")
        if not self._available():
            self._append_best_effort(request, principal.id, "deny", "kill_switch_engaged", "1.0")
            return self.hub._deny(request, "kill_switch_engaged")
        try:
            self.audit.append(self._event(request, principal.id, "ok", "request_started", "1.0"))
        except Exception:
            return self.hub._deny(request, "audit_unavailable")
        result = self.hub.execute(token, request, context)
        try:
            self.audit.append(self._event(
                request, principal.id, result.status, result.receipt.reason_code, result.receipt.policy_version,
            ))
        except Exception:
            return self.hub._deny(request, "audit_unavailable")
        return result

    def _available(self) -> bool:
        try:
            return self.availability_check() is True
        except Exception:
            return False

    def _append_best_effort(
        self, request: McpRequest, principal_id: str, outcome: str, reason_code: str, policy_version: str,
    ) -> None:
        try:
            self.audit.append(self._event(request, principal_id, outcome, reason_code, policy_version))
        except Exception:
            return

    def _event(
        self, request: McpRequest, principal_id: str, outcome: str, reason_code: str, policy_version: str,
    ) -> AuditEvent:
        capability = self.hub.registry.resolve(request.capability_id, request.capability_version)
        if capability is None:
            action, resource = "mcp.execute", "mcp:unknown"
        else:
            action = "mcp.read" if capability.operation == "read" else "mcp.write"
            resource = "mcp:resource" if capability.kind == "resource" else "mcp:tool"
        return AuditEvent(
            request.trace_id, principal_id, request.project_id, action, resource, outcome, reason_code,
            policy_version, int(self.clock()),
        )
