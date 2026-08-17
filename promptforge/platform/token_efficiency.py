"""Локальные token budgets, content-addressed dedup и подписанные usage receipts."""

from __future__ import annotations

from dataclasses import dataclass, field, replace
import hashlib
import hmac
import json
import re
from typing import Callable, Iterable

from promptforge.platform.contracts import SCHEMA_VERSION
from promptforge.platform.gateway import GatewayReceipt


_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_OVERFLOW = frozenset({"compact", "request-more-context", "stop"})
_CLASSIFICATIONS = frozenset({"public", "internal", "confidential", "restricted", "regulated"})
_MAX_CONTEXT_ITEMS = 128
_MAX_CONTEXT_ITEM_BYTES = 256 * 1024
_MAX_CONTEXT_BYTES = 1024 * 1024


def _positive_integer(value: object, name: str, *, allow_zero: bool = False) -> int:
    minimum = 0 if allow_zero else 1
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise ValueError(f"{name} must be an integer >= {minimum}")
    return value


def _token_count(content: str) -> int:
    """Локально и детерминированно оценивает tokens."""

    return max(1, (len(content.encode("utf-8")) + 3) // 4)


@dataclass(frozen=True)
class TokenBudget:
    """Ограничивает input, mandatory reserve и output одного workflow step."""

    max_input: int
    reserved_mandatory: int
    reserved_output: int
    overflow: str

    def __post_init__(self) -> None:
        _positive_integer(self.max_input, "max_input")
        _positive_integer(self.reserved_mandatory, "reserved_mandatory")
        _positive_integer(self.reserved_output, "reserved_output")
        if self.reserved_mandatory > self.max_input:
            raise ValueError("reserved_mandatory exceeds max_input")
        if self.overflow not in _OVERFLOW:
            raise ValueError("unsupported token overflow strategy")

    @property
    def digest(self) -> str:
        payload = {
            "max_input": self.max_input, "reserved_mandatory": self.reserved_mandatory,
            "reserved_output": self.reserved_output, "overflow": self.overflow,
        }
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return "sha256:" + hashlib.sha256(encoded).hexdigest()


@dataclass(frozen=True)
class ContextItem:
    """Описывает один локальный context fragment до дедупликации."""

    source_id: str
    content: str = field(repr=False, compare=False)
    mandatory: bool = False
    classification: str = "internal"

    def __post_init__(self) -> None:
        if not isinstance(self.source_id, str) or not _SAFE_ID.fullmatch(self.source_id):
            raise ValueError("context source id is invalid")
        if (
            not isinstance(self.content, str) or not self.content
            or len(self.content.encode("utf-8")) > _MAX_CONTEXT_ITEM_BYTES
        ):
            raise ValueError("context content must be non-empty")
        if not isinstance(self.mandatory, bool):
            raise ValueError("context mandatory flag must be boolean")
        if self.classification not in _CLASSIFICATIONS:
            raise ValueError("context classification is invalid")

    @property
    def content_digest(self) -> str:
        return "sha256:" + hashlib.sha256(self.content.encode("utf-8")).hexdigest()

    @property
    def tokens(self) -> int:
        return _token_count(self.content)


@dataclass(frozen=True)
class ContextPlan:
    """Хранит context внутри процесса, наружу отдаёт metadata."""

    status: str
    reason_code: str
    project_id: str
    principal_id: str
    trace_id: str
    budget: TokenBudget
    candidate_input_tokens: int
    selected_input_tokens: int
    mandatory_tokens: int
    candidate_items: int
    selected_items: tuple[ContextItem, ...] = field(repr=False, compare=False)
    deduplicated_items: int = 0
    context_digest: str = ""
    plan_attestation: str = field(default="", repr=False, compare=False)

    @property
    def overflow_strategy(self) -> str:
        return self.budget.overflow

    def to_payload(self) -> dict[str, object]:
        return {
            "schema_version": SCHEMA_VERSION,
            "status": self.status,
            "reason_code": self.reason_code,
            "project_id": self.project_id,
            "principal_id": self.principal_id,
            "trace_id": self.trace_id,
            "candidate_input_tokens": self.candidate_input_tokens,
            "selected_input_tokens": self.selected_input_tokens,
            "mandatory_tokens": self.mandatory_tokens,
            "candidate_items": self.candidate_items,
            "selected_items": len(self.selected_items),
            "deduplicated_items": self.deduplicated_items,
            "context_digest": self.context_digest,
            "overflow_strategy": self.overflow_strategy,
        }


@dataclass(frozen=True)
class UsageReceipt:
    """Фиксирует budget/dedup/provider usage без исходного контента."""

    project_id: str
    principal_id: str
    trace_id: str
    context_digest: str
    budget_digest: str
    gateway_receipt_digest: str
    candidate_input_tokens: int
    selected_input_tokens: int
    billed_input_tokens: int
    cache_read_tokens: int
    cache_write_tokens: int
    output_tokens: int
    mandatory_tokens: int
    candidate_items: int
    selected_items: int
    deduplicated_items: int
    token_saving_ratio: float
    deduplication_ratio: float
    overflow_strategy: str
    privacy_reduction_tokens: int = 0
    transformation_overhead_tokens: int = 0
    attestation: str = ""

    def to_payload(self) -> dict[str, object]:
        return {"schema_version": SCHEMA_VERSION, **self.__dict__}


@dataclass(frozen=True)
class TokenEfficiencyRuntime:
    """Планирует контекст и выпускает tamper-evident usage receipts."""

    attestation_key: bytes = field(repr=False, compare=False)
    gateway_receipt_verifier: Callable[[GatewayReceipt], bool] = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        if not isinstance(self.attestation_key, bytes) or len(self.attestation_key) < 32:
            raise ValueError("usage attestation key must contain at least 32 bytes")
        if not callable(self.gateway_receipt_verifier):
            raise ValueError("gateway receipt verifier is required")

    def prepare(
        self,
        project_id: str,
        principal_id: str,
        trace_id: str,
        budget: TokenBudget,
        items: Iterable[ContextItem],
    ) -> ContextPlan:
        """Дедуплицирует и выбирает контекст, не удаляя mandatory items."""

        self._identity(project_id, "project_id")
        self._identity(principal_id, "principal_id")
        self._identity(trace_id, "trace_id")
        candidates = tuple(items)
        if (
            not candidates or len(candidates) > _MAX_CONTEXT_ITEMS
            or any(not isinstance(item, ContextItem) for item in candidates)
            or sum(len(item.content.encode("utf-8")) for item in candidates) > _MAX_CONTEXT_BYTES
        ):
            raise ValueError("context items must be a non-empty ContextItem collection")
        candidate_tokens = sum(item.tokens for item in candidates)
        unique = self._deduplicate(candidates)
        mandatory = tuple(item for item in unique if item.mandatory)
        optional = tuple(item for item in unique if not item.mandatory)
        if not mandatory:
            raise ValueError("mandatory context is required")
        mandatory_tokens = sum(item.tokens for item in mandatory)
        if mandatory_tokens > budget.max_input:
            return self._plan(
                "overflow", "mandatory_context_exceeds_budget", project_id, principal_id, trace_id, budget, candidates,
                (), candidate_tokens, mandatory_tokens, len(candidates) - len(unique),
            )
        optional_limit = budget.max_input - max(mandatory_tokens, budget.reserved_mandatory)
        selected_optional: list[ContextItem] = []
        used_optional = 0
        for item in optional:
            if used_optional + item.tokens <= optional_limit:
                selected_optional = [*selected_optional, item]
                used_optional += item.tokens
        selected = (*mandatory, *selected_optional)
        omitted = len(selected_optional) != len(optional)
        compacted = omitted and budget.overflow == "compact"
        return self._plan(
            "ready" if not omitted or compacted else "overflow",
            "context_compacted" if compacted else "optional_context_exceeds_budget" if omitted else "within_budget",
            project_id, principal_id, trace_id, budget, candidates, selected, candidate_tokens, mandatory_tokens,
            len(candidates) - len(unique),
        )

    def issue_receipt(
        self,
        plan: ContextPlan,
        gateway_receipt: GatewayReceipt,
        *,
        cache_read_tokens: int = 0,
        cache_write_tokens: int = 0,
    ) -> UsageReceipt:
        """Проверяет actual usage и подписывает metadata-only receipt."""

        if (
            not isinstance(plan, ContextPlan)
            or plan.status != "ready"
            or not hmac.compare_digest(plan.plan_attestation, self._attest_plan(plan))
        ):
            raise PermissionError("usage receipt requires a ready context plan")
        if (
            not isinstance(gateway_receipt, GatewayReceipt)
            or gateway_receipt.status != "ok"
            or gateway_receipt.reason_code != "completed"
            or gateway_receipt.trace_id != plan.trace_id
            or not self.gateway_receipt_verifier(gateway_receipt)
        ):
            raise PermissionError("trusted gateway receipt is required")
        billed = _positive_integer(gateway_receipt.input_tokens, "billed_input_tokens", allow_zero=True)
        output = _positive_integer(gateway_receipt.output_tokens, "output_tokens", allow_zero=True)
        cache_read = _positive_integer(cache_read_tokens, "cache_read_tokens", allow_zero=True)
        cache_write = _positive_integer(cache_write_tokens, "cache_write_tokens", allow_zero=True)
        transformation_overhead = max(0, billed - plan.selected_input_tokens)
        privacy_reduction = max(0, plan.selected_input_tokens - billed)
        if transformation_overhead and gateway_receipt.privacy_outcome != "allow_with_transform":
            raise ValueError("billed input exceeds selected token budget")
        if billed > plan.budget.max_input:
            raise ValueError("billed input exceeds runtime token budget")
        if output > plan.budget.reserved_output:
            raise ValueError("output exceeds reserved token budget")
        gateway_digest = "sha256:" + hashlib.sha256(json.dumps(
            gateway_receipt.to_payload(), sort_keys=True, separators=(",", ":"),
        ).encode("utf-8")).hexdigest()
        unsigned = UsageReceipt(
            plan.project_id, plan.principal_id, plan.trace_id, plan.context_digest, plan.budget.digest,
            gateway_digest, plan.candidate_input_tokens,
            plan.selected_input_tokens, billed,
            cache_read, cache_write, output, plan.mandatory_tokens, plan.candidate_items, len(plan.selected_items),
            plan.deduplicated_items, round(1 - plan.selected_input_tokens / plan.candidate_input_tokens, 6),
            round(plan.deduplicated_items / plan.candidate_items, 6), plan.overflow_strategy,
            privacy_reduction,
            transformation_overhead,
        )
        return UsageReceipt(**{**unsigned.__dict__, "attestation": self._attest(unsigned)})

    def verify_receipt(self, receipt: UsageReceipt) -> bool:
        """Проверяет exact HMAC binding receipt."""

        if not isinstance(receipt, UsageReceipt) or not receipt.attestation:
            return False
        unsigned = UsageReceipt(**{**receipt.__dict__, "attestation": ""})
        return hmac.compare_digest(receipt.attestation, self._attest(unsigned))

    @staticmethod
    def _identity(value: str, name: str) -> None:
        if not isinstance(value, str) or not _SAFE_ID.fullmatch(value):
            raise ValueError(f"{name} is invalid")

    @staticmethod
    def _deduplicate(items: tuple[ContextItem, ...]) -> tuple[ContextItem, ...]:
        ordered = sorted(items, key=lambda item: (not item.mandatory, item.source_id, item.content_digest))
        by_digest: dict[str, ContextItem] = {}
        for item in ordered:
            if item.content_digest not in by_digest:
                by_digest = {**by_digest, item.content_digest: item}
        return tuple(sorted(by_digest.values(), key=lambda item: (not item.mandatory, item.source_id)))

    def _plan(
        self,
        status: str,
        reason: str,
        project_id: str,
        principal_id: str,
        trace_id: str,
        budget: TokenBudget,
        candidates: tuple[ContextItem, ...],
        selected: tuple[ContextItem, ...],
        candidate_tokens: int,
        mandatory_tokens: int,
        deduplicated_items: int,
    ) -> ContextPlan:
        digest_material = "\n".join(item.content_digest for item in selected).encode("ascii")
        context_digest = "sha256:" + hashlib.sha256(digest_material).hexdigest()
        unsigned = ContextPlan(
            status, reason, project_id, principal_id, trace_id, budget, candidate_tokens,
            sum(item.tokens for item in selected), mandatory_tokens, len(candidates), selected,
            deduplicated_items, context_digest,
        )
        return replace(unsigned, plan_attestation=self._attest_plan(unsigned))

    def _attest_plan(self, plan: ContextPlan) -> str:
        material = {
            **plan.to_payload(),
            "budget": {
                "max_input": plan.budget.max_input,
                "reserved_mandatory": plan.budget.reserved_mandatory,
                "reserved_output": plan.budget.reserved_output,
                "overflow": plan.budget.overflow,
            },
            "selected_content_digests": [item.content_digest for item in plan.selected_items],
        }
        encoded = json.dumps(material, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hmac.new(self.attestation_key, encoded, hashlib.sha256).hexdigest()

    def _attest(self, receipt: UsageReceipt) -> str:
        payload = {key: value for key, value in receipt.to_payload().items() if key != "attestation"}
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hmac.new(self.attestation_key, encoded, hashlib.sha256).hexdigest()
