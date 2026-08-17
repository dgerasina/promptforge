"""Обязательная token-optimization граница для всех runtime model calls."""

from __future__ import annotations

from dataclasses import dataclass, field, replace
import hashlib
import json
from pathlib import Path
import time
from typing import Callable, Iterable

from promptforge.platform.audit_runtime import AuditedModelGateway
from promptforge.platform.contracts import ModelRequest
from promptforge.platform.gateway import GatewayReceipt
from promptforge.platform.privacy import PrivacyContext
from promptforge.platform.token_efficiency import (
    ContextItem,
    ContextPlan,
    TokenBudget,
    TokenEfficiencyRuntime,
    UsageReceipt,
)
from promptforge.platform.token_usage_store import DurableUsageReceipt, TokenUsageStore
from promptforge.platform.efficiency_metrics import EfficiencyMetricEvent, EfficiencyMetricsStore


_BUDGET_FIELDS = frozenset({"schema_version", "max_input", "reserved_mandatory", "reserved_output", "overflow"})
_CLASSIFICATION_RANK = {"public": 0, "internal": 1, "confidential": 2, "restricted": 3, "regulated": 4}


def load_token_budget(repository: Path) -> TokenBudget:
    """Загружает единственный repository-owned budget без permissive defaults."""

    path = Path(repository) / "config" / "token-budget.json"
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 100_000:
        raise ValueError("token budget must be a bounded regular file")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ValueError("token budget is invalid") from error
    if not isinstance(payload, dict) or set(payload) != _BUDGET_FIELDS or payload.get("schema_version") != "1.0":
        raise ValueError("token budget fields or schema version mismatch")
    return TokenBudget(
        payload["max_input"], payload["reserved_mandatory"], payload["reserved_output"], payload["overflow"],
    )


@dataclass(frozen=True)
class OptimizedGatewayResult:
    """Совмещает обычный gateway result с metadata-only optimization evidence."""

    status: str
    content: str = field(repr=False)
    receipt: GatewayReceipt
    context_plan: ContextPlan | None = field(default=None, repr=False)
    usage_receipt: UsageReceipt | None = None
    durable_usage_receipt: DurableUsageReceipt | None = None


@dataclass(frozen=True)
class OptimizedModelRuntime:
    """Не позволяет runtime model call обойти budget, dedup и usage settlement."""

    _gateway: AuditedModelGateway = field(repr=False)
    optimizer: TokenEfficiencyRuntime
    budget: TokenBudget
    usage_store: TokenUsageStore = field(repr=False)
    metrics: EfficiencyMetricsStore = field(repr=False)
    clock: Callable[[], float] = field(default=time.perf_counter, repr=False, compare=False)

    @property
    def authenticator(self):
        """Возвращает authenticator без публикации raw execution facade."""

        return self._gateway.facade.authenticator

    @property
    def audit(self):
        """Возвращает общий audit sink без отдельного execution path."""

        return self._gateway.audit

    @property
    def is_audited(self) -> bool:
        return isinstance(self._gateway, AuditedModelGateway)

    def verify_gateway_receipt(self, receipt: GatewayReceipt) -> bool:
        """Проверяет provider identity, не раскрывая raw gateway invoke."""

        return self._gateway.facade.gateway.verify_identity(receipt)

    def invoke(
        self,
        token: str,
        request: ModelRequest,
        context: PrivacyContext,
        *,
        context_items: Iterable[ContextItem] = (),
    ) -> OptimizedGatewayResult:
        started = self.clock()

        def finish(result, plan=None, usage=None, durable=None):
            wrapped = self._wrap(result, plan, usage, durable)
            candidate = usage.candidate_input_tokens if usage is not None else plan.candidate_input_tokens if plan else 0
            selected = usage.selected_input_tokens if usage is not None else plan.selected_input_tokens if plan else 0
            cache_hits = usage.cache_read_tokens if usage is not None else 0
            billed = usage.billed_input_tokens if usage is not None else result.receipt.input_tokens
            self.metrics.append(EfficiencyMetricEvent(
                input_tokens=result.receipt.input_tokens, output_tokens=result.receipt.output_tokens,
                candidate_input_tokens=candidate, selected_input_tokens=selected,
                model_calls=result.model_calls, latency_ms=max(0, round((self.clock() - started) * 1000)),
                cache_hits=cache_hits, cache_lookups=cache_hits + billed,
                dedup_hits=usage.deduplicated_items if usage is not None else 0,
                dedup_lookups=usage.candidate_items if usage is not None else 0,
                privacy_redactions=result.privacy_redactions,
                policy_denials=1 if result.receipt.policy_outcome == "deny" else 0,
            ))
            return wrapped

        authentication = self._gateway.facade.authenticator.authenticate(token)
        principal = authentication.principal
        if principal is None:
            return finish(self._gateway.invoke(token, request, context))
        supplied = tuple(context_items)
        if any(not isinstance(item, ContextItem) for item in supplied):
            raise ValueError("runtime context items are invalid")
        if any(
            _CLASSIFICATION_RANK[item.classification] > _CLASSIFICATION_RANK[request.data_classification]
            for item in supplied
        ):
            self._gateway._append_best_effort(
                request, principal.id, "deny", "context_classification_mismatch", "1.0",
            )
            denied = self._gateway.facade.gateway._deny(request, "context_classification_mismatch")
            return finish(denied)
        items = (
            ContextItem("runtime-request", request.content, True, request.data_classification),
            *supplied,
        )
        plan = self.optimizer.prepare(request.project_id, principal.id, request.trace_id, self.budget, items)
        if plan.status != "ready" or request.max_output_tokens > self.budget.reserved_output:
            self._gateway._append_best_effort(request, principal.id, "deny", "token_budget_exceeded", "1.0")
            denied = self._gateway.facade.gateway._deny(request, "token_budget_exceeded")
            return finish(denied, plan)
        reservation_digest = "sha256:" + hashlib.sha256(json.dumps({
            "schema_version": "1.0", "binding": "model-invocation-reservation", "trace_id": plan.trace_id,
            "context_digest": plan.context_digest, "budget_digest": plan.budget.digest,
            "max_output_tokens": request.max_output_tokens,
        }, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
        reservation_id = "reservation-" + hashlib.sha256(plan.trace_id.encode("utf-8")).hexdigest()
        try:
            self.usage_store.append_digest(plan.project_id, plan.principal_id, reservation_id, reservation_digest)
        except (OSError, PermissionError, RuntimeError, ValueError):
            self._gateway._append_best_effort(request, principal.id, "deny", "token_usage_reservation_failed", "1.0")
            denied = self._gateway.facade.gateway._deny(request, "token_usage_reservation_failed")
            return finish(denied, plan)
        optimized_request = replace(request, content="\n".join(item.content for item in plan.selected_items))
        result = self._gateway.invoke(token, optimized_request, context)
        if result.status != "ok":
            return finish(result, plan)
        try:
            usage = self.optimizer.issue_receipt(plan, result.receipt)
        except (PermissionError, ValueError):
            self._gateway._append_best_effort(request, principal.id, "deny", "token_usage_invalid", "1.0")
            denied = self._gateway.facade.gateway._deny(request, "token_usage_invalid")
            return finish(denied, plan)
        try:
            receipt_digest = "sha256:" + hashlib.sha256(json.dumps(
                usage.to_payload(), ensure_ascii=True, sort_keys=True, separators=(",", ":"),
            ).encode("utf-8")).hexdigest()
            durable = self.usage_store.append_digest(
                usage.project_id, usage.principal_id, usage.trace_id, receipt_digest,
            )
        except (OSError, PermissionError, RuntimeError, ValueError):
            self._gateway._append_best_effort(request, principal.id, "deny", "token_usage_store_failed", "1.0")
            denied = self._gateway.facade.gateway._deny(request, "token_usage_store_failed")
            return finish(denied, plan)
        return finish(result, plan, usage, durable)

    @staticmethod
    def _wrap(
        result, plan: ContextPlan | None = None, usage: UsageReceipt | None = None,
        durable: DurableUsageReceipt | None = None,
    ) -> OptimizedGatewayResult:
        return OptimizedGatewayResult(result.status, result.content, result.receipt, plan, usage, durable)
