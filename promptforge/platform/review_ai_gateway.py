"""Trusted Model Gateway adapters для AI candidate и verifier passes."""

from __future__ import annotations

from dataclasses import dataclass, field
import json
import secrets
from typing import Callable, Mapping, Protocol

from promptforge.platform.contracts import ModelRequest
from promptforge.platform.gateway import GatewayResult
from promptforge.platform.optimized_runtime import OptimizedModelRuntime
from promptforge.platform.privacy import PrivacyContext
from promptforge.platform.review import ReviewRequest
from promptforge.platform.token_efficiency import ContextItem
from promptforge.platform.review_ai import (
    AiCandidate, AiCandidateBatch, DiffEvidenceRef, VerificationBatch, VerificationVerdict,
    candidate_id, review_binding,
)


@dataclass(frozen=True)
class GatewayInvocation:
    content: str
    classification: str
    logical_model: str
    trace_id: str
    max_output_tokens: int
    context: PrivacyContext
    context_items: tuple[ContextItem, ...] = ()


class GatewayInvocationClient(Protocol):
    def invoke(self, invocation: GatewayInvocation) -> GatewayResult: ...

    def verify_identity(self, result: GatewayResult) -> bool: ...


@dataclass(frozen=True)
class AuthenticatedGatewayInvocationClient:
    """Проводит AI review только через audited и token-optimized runtime."""

    gateway: OptimizedModelRuntime
    token_supplier: Callable[[], str] = field(repr=False)

    def invoke(self, invocation: GatewayInvocation) -> GatewayResult:
        request = ModelRequest(
            invocation.context.project_id, invocation.context.purpose, invocation.classification,
            invocation.content, invocation.context.destination,
            invocation.context.destination == "external" and invocation.classification == "internal",
            invocation.logical_model, invocation.trace_id,
            invocation.max_output_tokens,
        )
        return self.gateway.invoke(
            self.token_supplier(), request, invocation.context, context_items=invocation.context_items,
        )

    def verify_identity(self, result: GatewayResult) -> bool:
        return bool(
            result.usage_receipt is not None
            and self.gateway.optimizer.verify_receipt(result.usage_receipt)
            and self.gateway.verify_gateway_receipt(result.receipt)
        )


@dataclass
class _GatewayAdapterBase:
    client: GatewayInvocationClient
    context: PrivacyContext
    logical_model: str
    prompt_version: str
    expected_provider: str
    expected_endpoint: str
    expected_provider_model: str
    max_response_bytes: int
    max_output_tokens: int = 2048
    nonce_supplier: Callable[[], str] = lambda: secrets.token_hex(16)
    _trust_domain: str = field(default="", init=False, repr=False)

    def __post_init__(self) -> None:
        text = (
            self.logical_model, self.prompt_version, self.expected_provider, self.expected_endpoint,
            self.expected_provider_model,
        )
        if any(not isinstance(item, str) or not item.strip() for item in text):
            raise ValueError("trusted AI gateway adapter metadata is invalid")
        limits = (self.max_response_bytes, self.max_output_tokens)
        if any(not isinstance(item, int) or isinstance(item, bool) or item <= 0 for item in limits):
            raise ValueError("trusted AI gateway adapter limits are invalid")
        if self.context.destination not in {"external", "local"}:
            raise ValueError("trusted AI adapter requires a supported privacy context")

    @property
    def trust_domain(self) -> str:
        if not self._trust_domain:
            raise ValueError("gateway identity is not attested")
        return self._trust_domain

    def _invoke(self, request: ReviewRequest, content: str, context_items: tuple[ContextItem, ...] | None = None) -> str:
        if len(content) > 100_000:
            raise ValueError("AI review prompt is too large")
        result = self.client.invoke(GatewayInvocation(
            content, "internal", self.logical_model, request.trace_id, self.max_output_tokens, self.context,
            self._context_items(request, content) if context_items is None else context_items,
        ))
        receipt = result.receipt
        if result.status != "ok" or receipt.status != "ok":
            raise ValueError("Model Gateway denied AI review invocation")
        if not self.client.verify_identity(result):
            raise ValueError("Model Gateway identity attestation is invalid")
        if (
            receipt.trace_id != request.trace_id or receipt.logical_model != self.logical_model
            or receipt.provider != self.expected_provider
            or receipt.endpoint_id != self.expected_endpoint or receipt.provider_model != self.expected_provider_model
            or receipt.destination != self.context.destination
            or receipt.fallback_count != 0
        ):
            raise ValueError("Model Gateway identity does not match pinned AI review endpoint")
        if not isinstance(result.content, str) or len(result.content.encode("utf-8")) > self.max_response_bytes:
            raise ValueError("AI review response exceeds actual content limit")
        self._trust_domain = receipt.provider
        return result.content

    def _context_items(self, request: ReviewRequest, content: str) -> tuple[ContextItem, ...]:
        return (
            ContextItem("review-binding", content, True, "internal"),
            *self._additional_context_items(request),
        )

    def _additional_context_items(self, request: ReviewRequest) -> tuple[ContextItem, ...]:
        raise NotImplementedError

    @staticmethod
    def _object(value: object, fields: frozenset[str], name: str) -> Mapping[str, object]:
        if not isinstance(value, dict) or set(value) != fields:
            raise ValueError(f"{name} must be a strict object")
        return value

    def _json(self, content: str, root_field: str, nonce: str) -> tuple[object, ...]:
        def strict_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
            if len({key for key, _ in pairs}) != len(pairs):
                raise ValueError("AI review JSON contains duplicate keys")
            return dict(pairs)

        try:
            payload = json.loads(content, object_pairs_hook=strict_object)
        except (json.JSONDecodeError, RecursionError, ValueError) as error:
            raise ValueError("AI review response is not valid JSON") from error
        root = self._object(payload, frozenset({root_field, "invocation_nonce"}), "AI review response")
        if root["invocation_nonce"] != nonce:
            raise ValueError("AI review response challenge does not match invocation")
        values = root[root_field]
        if not isinstance(values, list) or len(values) > 20:
            raise ValueError("AI review response list is invalid or too large")
        return tuple(values)


@dataclass
class GatewayCandidateGenerator(_GatewayAdapterBase):
    """Парсит candidate JSON только после Gateway policy/privacy и identity checks."""

    def generate(self, request: ReviewRequest) -> AiCandidateBatch:
        binding = review_binding(request)
        nonce = self.nonce_supplier()
        prompt = json.dumps({
            "instruction": "Use attached context items. Return strict candidate JSON only.",
            "prompt_version": self.prompt_version, "review_binding": binding,
            "invocation_nonce": nonce,
        }, ensure_ascii=True, sort_keys=True)
        raw_items = self._json(self._invoke(request, prompt), "candidates", nonce)
        candidates = tuple(self._candidate(binding, value) for value in raw_items)
        return AiCandidateBatch(binding, self.prompt_version, self.logical_model, candidates)

    def _additional_context_items(self, request: ReviewRequest) -> tuple[ContextItem, ...]:
        return tuple(
            ContextItem(
                f"changed-file-{index:04d}",
                json.dumps({"changed_file": item.to_payload()}, ensure_ascii=True, sort_keys=True),
                False,
                "internal",
            )
            for index, item in enumerate(request.files, 1)
        )

    def _candidate(self, binding: str, value: object) -> AiCandidate:
        fields = frozenset({
            "severity", "category", "claim", "impact", "remediation", "confidence", "evidence_refs",
        })
        payload = self._object(value, fields, "AI candidate")
        raw_refs = payload["evidence_refs"]
        if not isinstance(raw_refs, list):
            raise ValueError("AI candidate evidence must be an array")
        refs = tuple(self._evidence_ref(value) for value in raw_refs)
        severity, category, claim = payload["severity"], payload["category"], payload["claim"]
        identifier = candidate_id(binding, severity, category, claim, refs)
        return AiCandidate(
            identifier, severity, category, claim, payload["impact"], payload["remediation"], refs,
            payload["confidence"],
        )

    def _evidence_ref(self, value: object) -> DiffEvidenceRef:
        payload = self._object(
            value, frozenset({"path", "diff_line", "line_digest"}), "AI evidence reference",
        )
        return DiffEvidenceRef(payload["path"], payload["diff_line"], payload["line_digest"])


@dataclass
class GatewayCandidateVerifier(_GatewayAdapterBase):
    """Выполняет отдельный gateway invocation и парсит verdicts exact candidate set."""

    def verify(self, request: ReviewRequest, batch: AiCandidateBatch) -> VerificationBatch:
        nonce = self.nonce_supplier()
        prompt = json.dumps({
            "instruction": "Use attached context items. Independently verify candidates. Return strict verdict JSON only.",
            "prompt_version": self.prompt_version, "review_binding": batch.review_binding,
            "invocation_nonce": nonce,
        }, ensure_ascii=True, sort_keys=True)
        verdicts = tuple(
            self._verdict(value) for value in self._json(
                self._invoke(request, prompt, self._context_items(request, prompt, batch)), "verdicts", nonce,
            )
        )
        return VerificationBatch(batch.review_binding, self.prompt_version, self.logical_model, verdicts)

    def _context_items(
        self,
        request: ReviewRequest,
        content: str,
        batch: AiCandidateBatch,
    ) -> tuple[ContextItem, ...]:
        return (
            ContextItem(
                "review-binding",
                json.dumps({"review_binding": review_binding(request), "request": json.loads(content)}, ensure_ascii=True, sort_keys=True),
                True,
                "internal",
            ),
            *tuple(
                ContextItem(
                    f"candidate-{index:04d}",
                    json.dumps({"candidate": self._candidate_payload(item)}, ensure_ascii=True, sort_keys=True),
                    False,
                    "internal",
                )
                for index, item in enumerate(batch.candidates, 1)
            ),
            *tuple(
                ContextItem(
                    f"changed-file-{index:04d}",
                    json.dumps({"changed_file": item.to_payload()}, ensure_ascii=True, sort_keys=True),
                    False,
                    "internal",
                )
                for index, item in enumerate(request.files, 1)
            ),
        )

    @staticmethod
    def _candidate_payload(item: AiCandidate) -> dict[str, object]:
        return {
            "candidate_id": item.candidate_id, "severity": item.severity, "category": item.category,
            "claim": item.claim,
            "evidence_refs": [
                {"path": ref.path, "diff_line": ref.diff_line, "line_digest": ref.line_digest}
                for ref in item.evidence_refs
            ],
        }

    def _verdict(self, value: object) -> VerificationVerdict:
        payload = self._object(
            value, frozenset({"candidate_id", "verdict", "confidence", "reason_code"}), "AI verdict",
        )
        return VerificationVerdict(
            payload["candidate_id"], payload["verdict"], payload["confidence"], payload["reason_code"],
        )
