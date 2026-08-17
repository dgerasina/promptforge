"""Fail-closed authorization boundary for one deterministic work execution."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re
from typing import Mapping

from promptforge.platform.auth import Authenticator
from promptforge.platform.governance import GovernancePolicy
from promptforge.platform.unified_ux import WorkResult


_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_GOVERNED_TASKS = {
    "documentation.sync": "docs.sync",
    "confluence.snapshot": "docs.sync",
    "documentation.from-snapshot": "docs.sync",
}


def _digest(value: object) -> str:
    encoded = json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


@dataclass(frozen=True)
class ExecutionAuthorizationReceipt:
    """Metadata-only evidence binding authentication and governance to an exact plan."""

    status: str
    reason_code: str
    principal_id: str
    role: str
    project_id: str
    task_kind: str
    plan_digest: str
    catalog_digest: str
    auth_version: str
    auth_expires_at: int
    governance_version: str
    governance_capability: str

    def __post_init__(self) -> None:
        if self.status not in {"allowed", "denied"} or not self.reason_code:
            raise ValueError("execution authorization outcome is invalid")
        if not _DIGEST.fullmatch(self.plan_digest) or not _DIGEST.fullmatch(self.catalog_digest):
            raise ValueError("execution authorization binding is invalid")
        if self.status == "allowed" and (not self.principal_id or not self.role or self.auth_expires_at <= 0):
            raise ValueError("allowed execution authorization is incomplete")
        if bool(self.governance_capability) != (self.task_kind in _GOVERNED_TASKS):
            raise ValueError("execution governance binding is invalid")

    def to_payload(self) -> dict[str, object]:
        unsigned = {
            "schema_version": "1.0",
            "boundary_version": "1.0.0",
            "status": self.status,
            "reason_code": self.reason_code,
            "principal_id": self.principal_id,
            "role": self.role,
            "project_id": self.project_id,
            "task_kind": self.task_kind,
            "plan_digest": self.plan_digest,
            "catalog_digest": self.catalog_digest,
            "auth_version": self.auth_version,
            "auth_expires_at": self.auth_expires_at,
            "governance_version": self.governance_version,
            "governance_capability": self.governance_capability,
            "network_used": False,
        }
        return {**unsigned, "authorization_digest": _digest(unsigned)}


@dataclass(frozen=True)
class AuthenticatedExecutionBoundary:
    """Re-authenticates every execute request and applies exact governance policy."""

    authenticator: Authenticator
    governance: GovernancePolicy

    @classmethod
    def from_repository(
        cls, repository: Path, authenticator: Authenticator,
    ) -> AuthenticatedExecutionBoundary:
        return cls(authenticator, GovernancePolicy.from_repository(Path(repository).resolve(strict=True)))

    def authorize(self, token: str, requested_principal: str, plan: WorkResult) -> ExecutionAuthorizationReceipt:
        plan_payload = plan.to_payload()
        plan_digest = str(plan_payload["plan_digest"])
        capability = _GOVERNED_TASKS.get(plan.task_kind, "")
        authentication = self.authenticator.authenticate(token)
        principal = authentication.principal
        reason = authentication.receipt.reason_code
        allowed = authentication.status == "allow" and principal is not None
        if allowed and (plan.mode != "execute" or plan.status != "ready"):
            allowed, reason = False, "execution_plan_not_ready"
        if allowed and (
            principal.id != requested_principal or principal.id != plan.principal_id or principal.role != plan.role
            or principal.project_id != self.governance.project_id
        ):
            allowed, reason = False, "authenticated_principal_mismatch"
        if allowed and capability and not self.governance.allows(principal, capability):
            allowed, reason = False, "governance_capability_denied"
        return ExecutionAuthorizationReceipt(
            "allowed" if allowed else "denied",
            "execution_authorized" if allowed else reason,
            principal.id if principal is not None else requested_principal,
            principal.role if principal is not None else "",
            self.governance.project_id,
            plan.task_kind,
            plan_digest,
            plan.catalog_digest,
            authentication.receipt.auth_version,
            authentication.receipt.expires_at,
            self.governance.policy_version,
            capability,
        )
