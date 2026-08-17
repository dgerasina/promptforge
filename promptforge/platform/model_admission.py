"""Fail-closed admission gate для локальных model artifacts и eval evidence."""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import hmac
import re
import time
from typing import Any, Callable, Mapping
from urllib.parse import urlsplit


_STATUSES = frozenset({"candidate", "review", "approved", "revoked"})
_LICENSES = frozenset({"Apache-2.0", "MIT"})
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_MANIFEST_FIELDS = frozenset({
    "schema_version", "model_id", "revision", "artifact_sha256", "license_id", "source_uri", "status",
    "evaluation_suite_version", "minimum_pass_rate", "maximum_unsafe_findings",
})
_EVIDENCE_FIELDS = frozenset({
    "schema_version", "manifest_binding", "total", "passed", "unsafe_findings", "evaluator_id",
    "corpus_sha256", "suite_sha256", "verifier_version", "evaluated_at", "expires_at", "attestation",
})


def _text(value: object, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be non-empty")
    return value


@dataclass(frozen=True)
class ModelAdmissionManifest:
    """Описывает provenance и admission thresholds одного immutable model revision."""

    model_id: str
    revision: str
    artifact_sha256: str
    license_id: str
    source_uri: str
    status: str
    evaluation_suite_version: str
    minimum_pass_rate: float
    maximum_unsafe_findings: int

    def __post_init__(self) -> None:
        for value, name in (
            (self.model_id, "model id"), (self.revision, "revision"),
            (self.evaluation_suite_version, "evaluation suite version"),
        ):
            _text(value, name)
        if self.status not in _STATUSES:
            raise ValueError("unsupported model admission status")
        if self.license_id not in _LICENSES and self.status != "candidate":
            raise ValueError("model license is not allowlisted")
        source = urlsplit(self.source_uri)
        if (
            source.scheme != "https" or not source.netloc or source.username or source.password
            or source.query or source.fragment
        ):
            raise ValueError("model source must be credential-free HTTPS")
        if self.status in {"review", "approved"} and not _DIGEST.fullmatch(self.artifact_sha256):
            raise ValueError("reviewed model requires an artifact SHA-256 digest")
        if self.artifact_sha256 and not _DIGEST.fullmatch(self.artifact_sha256):
            raise ValueError("model artifact digest is invalid")
        if not isinstance(self.minimum_pass_rate, (int, float)) or isinstance(self.minimum_pass_rate, bool):
            raise ValueError("minimum pass rate is invalid")
        if not 0.0 <= float(self.minimum_pass_rate) <= 1.0:
            raise ValueError("minimum pass rate is invalid")
        if (
            not isinstance(self.maximum_unsafe_findings, int)
            or isinstance(self.maximum_unsafe_findings, bool)
            or self.maximum_unsafe_findings < 0
        ):
            raise ValueError("maximum unsafe findings is invalid")

    @property
    def is_admittable(self) -> bool:
        return self.status == "approved" and bool(_DIGEST.fullmatch(self.artifact_sha256))

    def to_payload(self) -> dict[str, object]:
        return {
            "schema_version": "1.0", "model_id": self.model_id, "revision": self.revision,
            "artifact_sha256": self.artifact_sha256, "license_id": self.license_id, "source_uri": self.source_uri,
            "status": self.status, "evaluation_suite_version": self.evaluation_suite_version,
            "minimum_pass_rate": self.minimum_pass_rate,
            "maximum_unsafe_findings": self.maximum_unsafe_findings,
        }

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> ModelAdmissionManifest:
        if not isinstance(payload, Mapping) or set(payload) != _MANIFEST_FIELDS:
            raise ValueError("model admission manifest fields mismatch")
        if payload.get("schema_version") != "1.0":
            raise ValueError("unsupported model admission schema")
        return cls(**{key: value for key, value in payload.items() if key != "schema_version"})

    def binding(self) -> str:
        canonical = "\0".join((
            self.model_id, self.revision, self.artifact_sha256, self.license_id, self.source_uri,
            self.evaluation_suite_version, str(self.minimum_pass_rate), str(self.maximum_unsafe_findings),
        ))
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class ModelEvalMetrics:
    """Содержит только агрегированные eval metrics без prompts/responses."""

    total: int
    passed: int
    unsafe_findings: int

    def __post_init__(self) -> None:
        values = (self.total, self.passed, self.unsafe_findings)
        if any(not isinstance(value, int) or isinstance(value, bool) or value < 0 for value in values):
            raise ValueError("model eval metrics are invalid")
        if self.total <= 0 or self.passed > self.total:
            raise ValueError("model eval metrics are inconsistent")


@dataclass(frozen=True)
class ModelEvalProvenance:
    """Связывает eval metrics с trusted harness и immutable corpus/suite."""

    evaluator_id: str
    corpus_sha256: str
    suite_sha256: str
    verifier_version: str
    evaluated_at: int

    def __post_init__(self) -> None:
        for value, name in ((self.evaluator_id, "evaluator id"), (self.verifier_version, "verifier version")):
            _text(value, name)
        if not _DIGEST.fullmatch(self.corpus_sha256) or not _DIGEST.fullmatch(self.suite_sha256):
            raise ValueError("eval provenance digests are invalid")
        if not isinstance(self.evaluated_at, int) or isinstance(self.evaluated_at, bool) or self.evaluated_at < 0:
            raise ValueError("eval timestamp is invalid")


@dataclass(frozen=True)
class ModelEvalEvidence:
    manifest_binding: str
    total: int
    passed: int
    unsafe_findings: int
    evaluator_id: str
    corpus_sha256: str
    suite_sha256: str
    verifier_version: str
    evaluated_at: int
    expires_at: int
    attestation: str

    def __post_init__(self) -> None:
        if not _DIGEST.fullmatch(self.manifest_binding):
            raise ValueError("eval evidence manifest binding is invalid")
        ModelEvalMetrics(self.total, self.passed, self.unsafe_findings)
        ModelEvalProvenance(
            self.evaluator_id, self.corpus_sha256, self.suite_sha256, self.verifier_version, self.evaluated_at,
        )
        if (
            not isinstance(self.expires_at, int) or isinstance(self.expires_at, bool)
            or self.expires_at <= self.evaluated_at
        ):
            raise ValueError("eval evidence expiry is invalid")
        if not re.fullmatch(r"hmac-sha256:[0-9a-f]{64}", self.attestation):
            raise ValueError("eval evidence attestation is invalid")

    def to_payload(self) -> dict[str, object]:
        return {"schema_version": "1.0", **self.__dict__}

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> ModelEvalEvidence:
        if not isinstance(payload, Mapping) or set(payload) != _EVIDENCE_FIELDS:
            raise ValueError("model eval evidence fields mismatch")
        if payload.get("schema_version") != "1.0":
            raise ValueError("unsupported model eval evidence schema")
        return cls(**{key: value for key, value in payload.items() if key != "schema_version"})


@dataclass(frozen=True)
class ModelAdmissionDecision:
    status: str
    reason_code: str
    model_id: str
    revision: str
    artifact_sha256: str
    evaluation_suite_version: str
    pass_rate: float
    unsafe_findings: int
    manifest_binding: str
    evaluator_id: str
    corpus_sha256: str
    suite_sha256: str
    verifier_version: str
    evaluated_at: int
    issued_at: int
    expires_at: int
    attestation: str

    def to_payload(self) -> dict[str, object]:
        return dict(self.__dict__)


@dataclass(frozen=True)
class ModelAdmissionAuthority:
    """Проверяет signed eval evidence и выпускает model admission decision."""

    key: bytes
    allowed_evaluators: frozenset[str] = frozenset({"promptforge-eval"})
    allowed_verifier_versions: frozenset[str] = frozenset({"1.0"})
    evidence_ttl_seconds: int = 86_400
    decision_ttl_seconds: int = 3_600
    clock: Callable[[], float] = field(default=time.time, repr=False, compare=False)

    def __post_init__(self) -> None:
        if not isinstance(self.key, bytes) or len(self.key) < 32:
            raise ValueError("model admission key must contain at least 32 bytes")
        if not self.allowed_evaluators or not self.allowed_verifier_versions:
            raise ValueError("model admission verifier allowlists must not be empty")
        limits = (self.evidence_ttl_seconds, self.decision_ttl_seconds)
        if any(not isinstance(value, int) or isinstance(value, bool) or value <= 0 for value in limits):
            raise ValueError("model admission TTL is invalid")

    def attest(
        self, manifest: ModelAdmissionManifest, metrics: ModelEvalMetrics, provenance: ModelEvalProvenance,
    ) -> ModelEvalEvidence:
        if (
            provenance.evaluator_id not in self.allowed_evaluators
            or provenance.verifier_version not in self.allowed_verifier_versions
        ):
            raise PermissionError("eval provenance is not allowlisted")
        expires_at = provenance.evaluated_at + self.evidence_ttl_seconds
        values = (
            manifest.binding(), metrics.total, metrics.passed, metrics.unsafe_findings,
            provenance.evaluator_id, provenance.corpus_sha256, provenance.suite_sha256,
            provenance.verifier_version, provenance.evaluated_at, expires_at,
        )
        message = self._evidence_message(*values)
        return ModelEvalEvidence(
            *values, self._sign(message),
        )

    def decide(self, manifest: ModelAdmissionManifest, evidence: ModelEvalEvidence) -> ModelAdmissionDecision:
        expected = self._sign(self._evidence_message(
            evidence.manifest_binding, evidence.total, evidence.passed, evidence.unsafe_findings,
            evidence.evaluator_id, evidence.corpus_sha256, evidence.suite_sha256, evidence.verifier_version,
            evidence.evaluated_at, evidence.expires_at,
        ))
        now = int(self.clock())
        valid = (
            manifest.status in {"review", "approved"}
            and evidence.manifest_binding == manifest.binding()
            and hmac.compare_digest(expected, evidence.attestation)
            and evidence.total > 0
            and 0 <= evidence.passed <= evidence.total
            and evidence.unsafe_findings >= 0
            and evidence.evaluator_id in self.allowed_evaluators
            and evidence.verifier_version in self.allowed_verifier_versions
            and evidence.evaluated_at <= now
            and now < evidence.expires_at
        )
        pass_rate = evidence.passed / evidence.total if evidence.total > 0 else 0.0
        approved = (
            valid
            and pass_rate >= manifest.minimum_pass_rate
            and evidence.unsafe_findings <= manifest.maximum_unsafe_findings
        )
        status, reason = ("approved", "model_admission_passed") if approved else ("deny", "model_admission_denied")
        expires_at = min(evidence.expires_at, now + self.decision_ttl_seconds)
        unsigned = ModelAdmissionDecision(
            status, reason, manifest.model_id, manifest.revision, manifest.artifact_sha256,
            manifest.evaluation_suite_version, pass_rate, evidence.unsafe_findings, manifest.binding(),
            evidence.evaluator_id, evidence.corpus_sha256, evidence.suite_sha256, evidence.verifier_version,
            evidence.evaluated_at, now, expires_at, "",
        )
        signed = {**unsigned.__dict__, "attestation": self._sign(self._decision_message(unsigned))}
        return ModelAdmissionDecision(**signed)

    def verify(self, decision: ModelAdmissionDecision, manifest: ModelAdmissionManifest) -> bool:
        return bool(
            decision.status == "approved"
            and manifest.status == "approved"
            and decision.manifest_binding == manifest.binding()
            and decision.model_id == manifest.model_id
            and decision.revision == manifest.revision
            and decision.artifact_sha256 == manifest.artifact_sha256
            and decision.evaluator_id in self.allowed_evaluators
            and decision.verifier_version in self.allowed_verifier_versions
            and int(self.clock()) < decision.expires_at
            and hmac.compare_digest(decision.attestation, self._sign(self._decision_message(decision)))
        )

    @staticmethod
    def _evidence_message(*values: object) -> str:
        return "\0".join(str(value) for value in values)

    @staticmethod
    def _decision_message(decision: ModelAdmissionDecision) -> str:
        return "\0".join((
            decision.status, decision.reason_code, decision.model_id, decision.revision, decision.artifact_sha256,
            decision.evaluation_suite_version, repr(decision.pass_rate), str(decision.unsafe_findings),
            decision.manifest_binding, decision.evaluator_id, decision.corpus_sha256, decision.suite_sha256,
            decision.verifier_version, str(decision.evaluated_at), str(decision.issued_at), str(decision.expires_at),
        ))

    def _sign(self, message: str) -> str:
        return "hmac-sha256:" + hmac.new(self.key, message.encode("utf-8"), hashlib.sha256).hexdigest()
