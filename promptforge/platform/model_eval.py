"""Детерминированная оценка локальной модели без raw-content receipts."""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json
import time
from typing import Any, Callable, Mapping, Protocol

from promptforge.platform.gateway import ProviderCall
from promptforge.platform.local_inference import LocalChatAdapter
from promptforge.platform.model_admission import (
    ModelAdmissionAuthority, ModelAdmissionManifest, ModelEvalEvidence, ModelEvalMetrics, ModelEvalProvenance,
)
from promptforge.platform.security import inspect_text


_ROOT_FIELDS = frozenset({"eval_version", "synthetic", "owner", "cases", "synthetic_responses"})
_CASE_FIELDS = frozenset({
    "id", "category", "input", "required_substrings", "forbidden_substrings", "max_output_bytes",
})
_CATEGORIES = frozenset({"quality", "security", "contract"})
_MAX_CASES = 256
_MAX_INPUT_BYTES = 10_000
_MAX_OUTPUT_BYTES = 100_000
_MAX_FIXTURE_RESPONSES_BYTES = 1_000_000


def _non_empty(value: object, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be non-empty")
    return value


def _canonical_digest(payload: object) -> str:
    encoded = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


@dataclass(frozen=True)
class ModelEvalCase:
    """Описывает bounded synthetic case и его детерминированные проверки."""

    id: str
    category: str
    input: str
    required_substrings: tuple[str, ...]
    forbidden_substrings: tuple[str, ...]
    max_output_bytes: int

    def __post_init__(self) -> None:
        _non_empty(self.id, "eval case id")
        if self.category not in _CATEGORIES:
            raise ValueError("unsupported eval category")
        _non_empty(self.input, "eval input")
        if len(self.input.encode("utf-8")) > _MAX_INPUT_BYTES or inspect_text(self.input).outcome == "deny":
            raise ValueError("eval input is unsafe or oversized")
        if not self.required_substrings:
            raise ValueError("eval case must have required substrings")
        for value in (*self.required_substrings, *self.forbidden_substrings):
            _non_empty(value, "eval substring")
        if (
            not isinstance(self.max_output_bytes, int) or isinstance(self.max_output_bytes, bool)
            or not 1 <= self.max_output_bytes <= _MAX_OUTPUT_BYTES
        ):
            raise ValueError("eval output limit is invalid")

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> ModelEvalCase:
        if not isinstance(payload, Mapping) or set(payload) != _CASE_FIELDS:
            raise ValueError("eval case fields mismatch")
        required = payload["required_substrings"]
        forbidden = payload["forbidden_substrings"]
        if not isinstance(required, list) or not isinstance(forbidden, list):
            raise ValueError("eval substring rules must be arrays")
        return cls(
            payload["id"], payload["category"], payload["input"], tuple(required), tuple(forbidden),
            payload["max_output_bytes"],
        )


@dataclass(frozen=True)
class ModelEvalSuite:
    """Хранит validated suite и вычисляет независимые corpus/scoring digests."""

    eval_version: str
    owner: str
    cases: tuple[ModelEvalCase, ...]

    def __post_init__(self) -> None:
        _non_empty(self.eval_version, "eval version")
        _non_empty(self.owner, "eval owner")
        if not self.cases or len(self.cases) > _MAX_CASES:
            raise ValueError("eval case count is invalid")
        ids = tuple(case.id for case in self.cases)
        if len(ids) != len(set(ids)):
            raise ValueError("eval case ids must be unique")

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> ModelEvalSuite:
        if not isinstance(payload, Mapping) or set(payload) != _ROOT_FIELDS:
            raise ValueError("model eval fixture fields mismatch")
        if payload["synthetic"] is not True or not isinstance(payload["cases"], list):
            raise ValueError("model eval fixture must be synthetic")
        responses = payload["synthetic_responses"]
        if not isinstance(responses, Mapping) or any(not isinstance(key, str) or not isinstance(value, str)
                                                     for key, value in responses.items()):
            raise ValueError("synthetic responses are invalid")
        cases = tuple(ModelEvalCase.from_payload(case) for case in payload["cases"])
        limits = {case.id: case.max_output_bytes for case in cases}
        if set(responses) != set(limits):
            raise ValueError("synthetic response ids must match eval cases")
        response_sizes = {case_id: len(response.encode("utf-8")) for case_id, response in responses.items()}
        if (
            sum(response_sizes.values()) > _MAX_FIXTURE_RESPONSES_BYTES
            or any(response_sizes[case_id] > limits[case_id] for case_id in responses)
            or any(inspect_text(response).outcome != "allow" for response in responses.values())
        ):
            raise ValueError("synthetic responses are unsafe or oversized")
        return cls(payload["eval_version"], payload["owner"], cases)

    def corpus_sha256(self) -> str:
        return _canonical_digest({
            "eval_version": self.eval_version,
            "cases": [{"id": case.id, "category": case.category, "input": case.input} for case in self.cases],
        })

    def suite_sha256(self) -> str:
        return _canonical_digest({
            "verifier_version": "1.0",
            "cases": [{
                "id": case.id,
                "required_substrings": case.required_substrings,
                "forbidden_substrings": case.forbidden_substrings,
                "max_output_bytes": case.max_output_bytes,
            } for case in self.cases],
        })


class EvalModel(Protocol):
    """Минимальная граница model invocation для eval runner."""

    def generate(self, case_id: str, content: str, max_output_bytes: int) -> str:
        """Возвращает ответ модели для одного case."""


@dataclass(frozen=True)
class FixtureEvalModel:
    """Offline-only adapter с заранее заданными synthetic responses."""

    responses: Mapping[str, str]

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> FixtureEvalModel:
        ModelEvalSuite.from_payload(payload)
        responses = payload.get("synthetic_responses")
        if not isinstance(responses, Mapping):
            raise ValueError("synthetic responses are missing")
        return cls(dict(responses))

    def generate(self, case_id: str, content: str, max_output_bytes: int) -> str:
        del content
        try:
            response = self.responses[case_id]
        except KeyError as error:
            raise RuntimeError("synthetic response is missing") from error
        if not isinstance(response, str):
            raise RuntimeError("synthetic response is invalid")
        return response


@dataclass(frozen=True)
class LocalInferenceEvalModel:
    """Адаптирует readiness-attested local inference к eval protocol."""

    adapter: LocalChatAdapter
    model: str
    timeout_seconds: int
    max_output_tokens: int

    def __post_init__(self) -> None:
        _non_empty(self.model, "eval model")
        if (
            not isinstance(self.timeout_seconds, int) or isinstance(self.timeout_seconds, bool)
            or not 1 <= self.timeout_seconds <= 300
        ):
            raise ValueError("eval timeout is invalid")
        if (
            not isinstance(self.max_output_tokens, int) or isinstance(self.max_output_tokens, bool)
            or not 1 <= self.max_output_tokens <= 100_000
        ):
            raise ValueError("eval token limit is invalid")
        if self.adapter.readiness is None or self.adapter.readiness.model != self.model:
            raise PermissionError("local eval model is not readiness-attested")

    def generate(self, case_id: str, content: str, max_output_bytes: int) -> str:
        if max_output_bytes > self.adapter.config.max_response_bytes:
            raise ValueError("eval case output limit exceeds local adapter limit")
        trace_suffix = hashlib.sha256(case_id.encode("utf-8")).hexdigest()[:16]
        response = self.adapter.invoke(ProviderCall(
            self.model, content, f"model-eval-{trace_suffix}", self.timeout_seconds, self.max_output_tokens,
        ))
        return response.content


@dataclass(frozen=True)
class ModelEvalReport:
    """Возвращает только агрегаты и cryptographic provenance."""

    metrics: ModelEvalMetrics
    provenance: ModelEvalProvenance

    def to_payload(self) -> dict[str, object]:
        return {
            "total": self.metrics.total,
            "passed": self.metrics.passed,
            "unsafe_findings": self.metrics.unsafe_findings,
            "evaluator_id": self.provenance.evaluator_id,
            "corpus_sha256": self.provenance.corpus_sha256,
            "suite_sha256": self.provenance.suite_sha256,
            "verifier_version": self.provenance.verifier_version,
            "evaluated_at": self.provenance.evaluated_at,
        }


@dataclass(frozen=True)
class ModelEvalRunner:
    """Считает pass/fail fail-closed, не сохраняя inputs и outputs."""

    evaluator_id: str = "promptforge-eval"
    verifier_version: str = "1.0"
    clock: Callable[[], float] = field(default=time.time, repr=False, compare=False)

    def run(self, suite: ModelEvalSuite, model: EvalModel) -> ModelEvalReport:
        passed = 0
        unsafe_findings = 0
        for case in suite.cases:
            try:
                output = model.generate(case.id, case.input, case.max_output_bytes)
                if not isinstance(output, str) or len(output.encode("utf-8")) > case.max_output_bytes:
                    continue
                inspection = inspect_text(output)
                if inspection.outcome == "deny":
                    unsafe_findings += 1
                    continue
                normalized = output.casefold()
                required = all(value.casefold() in normalized for value in case.required_substrings)
                forbidden = any(value.casefold() in normalized for value in case.forbidden_substrings)
                passed += int(required and not forbidden)
            except Exception:
                # Любой adapter failure означает failed case.
                # Raw exception может содержать model output, поэтому не логируется.
                continue
        metrics = ModelEvalMetrics(len(suite.cases), passed, unsafe_findings)
        provenance = ModelEvalProvenance(
            self.evaluator_id, suite.corpus_sha256(), suite.suite_sha256(), self.verifier_version,
            int(self.clock()),
        )
        return ModelEvalReport(metrics, provenance)


def attest_local_model_eval(
    suite: ModelEvalSuite,
    model: LocalInferenceEvalModel,
    manifest: ModelAdmissionManifest,
    authority: ModelAdmissionAuthority,
    runner: ModelEvalRunner | None = None,
) -> tuple[ModelEvalReport, ModelEvalEvidence]:
    """Запускает exact local model и выпускает metadata-only eval evidence."""

    readiness = model.adapter.readiness
    exact_identity = bool(
        readiness is not None
        and readiness.model == manifest.model_id == model.model
        and readiness.revision == manifest.revision
        and readiness.artifact_sha256 == manifest.artifact_sha256
        and model.adapter.clock() < readiness.expires_at
    )
    if (
        manifest.status not in {"review", "approved"}
        or manifest.evaluation_suite_version != suite.eval_version
        or not exact_identity
    ):
        raise PermissionError("local model eval identity or suite binding is invalid")
    report = (runner or ModelEvalRunner()).run(suite, model)
    if model.adapter.clock() >= readiness.expires_at:
        raise PermissionError("local model readiness expired during eval")
    return report, authority.attest(manifest, report.metrics, report.provenance)
