"""Недоверенные AI candidates и независимая локальная promotion-проверка."""

from __future__ import annotations

from dataclasses import dataclass, replace
import hashlib
import hmac
import math
import re
import secrets
from time import time
from typing import Callable
from typing import Protocol

from promptforge.platform.contracts import ReviewFinding, SCHEMA_VERSION
from promptforge.platform.review import ReviewEngine, ReviewRequest, ReviewResult
from promptforge.platform.review_runtime import review_evidence_binding
from promptforge.platform.security import inspect_text


_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_VERDICTS = frozenset({"confirmed", "rejected", "abstain"})
_MAX_CANDIDATES = 20


@dataclass(frozen=True)
class DiffEvidenceRef:
    path: str
    diff_line: int
    line_digest: str

    def __post_init__(self) -> None:
        if not isinstance(self.path, str) or not self.path or len(self.path) > 512:
            raise ValueError("AI evidence path is invalid")
        if not isinstance(self.diff_line, int) or isinstance(self.diff_line, bool) or self.diff_line < 1:
            raise ValueError("AI evidence line is invalid")
        if not isinstance(self.line_digest, str) or not _DIGEST.fullmatch(self.line_digest):
            raise ValueError("AI evidence digest is invalid")


@dataclass(frozen=True)
class AiCandidate:
    candidate_id: str
    severity: str
    category: str
    claim: str
    impact: str
    remediation: str
    evidence_refs: tuple[DiffEvidenceRef, ...]
    confidence: float

    def __post_init__(self) -> None:
        if not _SAFE_ID.fullmatch(self.candidate_id) or self.severity not in {"high", "medium", "low"}:
            raise ValueError("AI candidate id or severity is invalid")
        texts = (self.category, self.claim, self.impact, self.remediation)
        if any(not isinstance(item, str) or not item.strip() or len(item) > 500 for item in texts):
            raise ValueError("AI candidate text is invalid")
        refs = tuple(self.evidence_refs)
        if not refs or len(refs) > 5:
            raise ValueError("AI candidate requires bounded evidence")
        if not isinstance(self.confidence, (int, float)) or isinstance(self.confidence, bool):
            raise ValueError("AI candidate confidence is invalid")
        if not math.isfinite(self.confidence) or not 0 <= self.confidence <= 1:
            raise ValueError("AI candidate confidence is invalid")
        object.__setattr__(self, "evidence_refs", refs)


@dataclass(frozen=True)
class AiCandidateBatch:
    review_binding: str
    prompt_version: str
    route: str
    candidates: tuple[AiCandidate, ...]

    def __post_init__(self) -> None:
        candidates = tuple(self.candidates)
        if not _DIGEST.fullmatch(self.review_binding):
            raise ValueError("AI candidate binding is invalid")
        if not _SAFE_ID.fullmatch(self.prompt_version) or not _SAFE_ID.fullmatch(self.route):
            raise ValueError("AI candidate metadata is invalid")
        if len(candidates) > _MAX_CANDIDATES or len({item.candidate_id for item in candidates}) != len(candidates):
            raise ValueError("AI candidate batch is ambiguous or too large")
        object.__setattr__(self, "candidates", candidates)


@dataclass(frozen=True)
class VerificationVerdict:
    candidate_id: str
    verdict: str
    confidence: float
    reason_code: str

    def __post_init__(self) -> None:
        if not _SAFE_ID.fullmatch(self.candidate_id) or self.verdict not in _VERDICTS:
            raise ValueError("AI verification verdict is invalid")
        if not _SAFE_ID.fullmatch(self.reason_code):
            raise ValueError("AI verification reason is invalid")
        if not isinstance(self.confidence, (int, float)) or isinstance(self.confidence, bool):
            raise ValueError("AI verification confidence is invalid")
        if not math.isfinite(self.confidence) or not 0 <= self.confidence <= 1:
            raise ValueError("AI verification confidence is invalid")


@dataclass(frozen=True)
class VerificationBatch:
    review_binding: str
    prompt_version: str
    route: str
    verdicts: tuple[VerificationVerdict, ...]

    def __post_init__(self) -> None:
        verdicts = tuple(self.verdicts)
        if not _DIGEST.fullmatch(self.review_binding):
            raise ValueError("AI verification binding is invalid")
        if not _SAFE_ID.fullmatch(self.prompt_version) or not _SAFE_ID.fullmatch(self.route):
            raise ValueError("AI verification metadata is invalid")
        if len(verdicts) > _MAX_CANDIDATES or len({item.candidate_id for item in verdicts}) != len(verdicts):
            raise ValueError("AI verification batch is ambiguous or too large")
        object.__setattr__(self, "verdicts", verdicts)


class CandidateGenerator(Protocol):
    trust_domain: str

    def generate(self, request: ReviewRequest) -> AiCandidateBatch: ...


class CandidateVerifier(Protocol):
    trust_domain: str

    def verify(self, request: ReviewRequest, batch: AiCandidateBatch) -> VerificationBatch: ...


@dataclass(frozen=True)
class FakeCandidateGenerator:
    batch: AiCandidateBatch | None = None
    error: Exception | None = None
    trust_domain: str = "candidate-domain"

    def generate(self, request: ReviewRequest) -> AiCandidateBatch:
        if self.error is not None:
            raise self.error
        if self.batch is None:
            raise ValueError("fake candidate batch is missing")
        return self.batch


@dataclass(frozen=True)
class FakeCandidateVerifier:
    batch: VerificationBatch | None = None
    error: Exception | None = None
    trust_domain: str = "verifier-domain"

    def verify(self, request: ReviewRequest, candidates: AiCandidateBatch) -> VerificationBatch:
        if self.error is not None:
            raise self.error
        if self.batch is None:
            raise ValueError("fake verification batch is missing")
        return self.batch


@dataclass(frozen=True)
class AiReviewPolicy:
    candidate_route: str
    verifier_route: str
    candidate_prompt_version: str
    verifier_prompt_version: str
    min_confidence: float = 0.8
    required: bool = True

    def __post_init__(self) -> None:
        identifiers = (
            self.candidate_route, self.verifier_route, self.candidate_prompt_version, self.verifier_prompt_version,
        )
        if any(not _SAFE_ID.fullmatch(item) for item in identifiers):
            raise ValueError("AI review policy identifier is invalid")
        if not isinstance(self.required, bool) or not 0 <= self.min_confidence <= 1:
            raise ValueError("AI review policy is invalid")


@dataclass(frozen=True)
class AiReviewReceipt:
    status: str
    reason_code: str
    review_binding: str
    candidate_count: int
    verified_count: int
    rejected_count: int
    abstained_count: int
    candidate_route: str
    verifier_route: str
    candidate_prompt_version: str
    verifier_prompt_version: str
    independence_verified: bool
    candidate_digest: str
    verification_digest: str
    expires_at: float
    verification_receipt: str

    def to_payload(self) -> dict[str, object]:
        return {
            "schema_version": SCHEMA_VERSION, "status": self.status, "reason_code": self.reason_code,
            "review_binding": self.review_binding, "candidate_count": self.candidate_count,
            "verified_count": self.verified_count, "rejected_count": self.rejected_count,
            "abstained_count": self.abstained_count, "candidate_route": self.candidate_route,
            "verifier_route": self.verifier_route, "candidate_prompt_version": self.candidate_prompt_version,
            "verifier_prompt_version": self.verifier_prompt_version,
            "independence_verified": self.independence_verified, "candidate_digest": self.candidate_digest,
            "verification_digest": self.verification_digest, "expires_at": self.expires_at,
            "verification_receipt": self.verification_receipt,
        }


@dataclass(frozen=True)
class AiReviewResult:
    review: ReviewResult
    receipt: AiReviewReceipt

    def to_payload(self) -> dict[str, object]:
        return {"schema_version": SCHEMA_VERSION, "review": self.review.to_payload(), "ai_receipt": self.receipt.to_payload()}


class AiReviewOrchestrator:
    """Повышает только локально grounded и независимо подтверждённые candidates."""

    def __init__(
        self, engine: ReviewEngine, generator: CandidateGenerator, verifier: CandidateVerifier,
        policy: AiReviewPolicy, signing_key: bytes, clock: Callable[[], float] = time,
    ) -> None:
        if not isinstance(signing_key, bytes) or len(signing_key) < 32:
            raise ValueError("AI verification key must contain at least 32 bytes")
        self._engine = engine
        self._generator = generator
        self._verifier = verifier
        self._policy = policy
        self._key = signing_key
        self._clock = clock

    def review(self, request: ReviewRequest) -> AiReviewResult:
        baseline = self._engine.review(request)
        binding = review_binding(request)
        try:
            batch = self._generator.generate(request)
            self._validate_candidate_batch(request, batch, binding)
            verification = self._verifier.verify(request, batch)
            self._validate_verification(batch, verification, binding)
            independence = (
                self._generator is not self._verifier
                and self._policy.candidate_route != self._policy.verifier_route
                and _SAFE_ID.fullmatch(self._generator.trust_domain) is not None
                and _SAFE_ID.fullmatch(self._verifier.trust_domain) is not None
                and self._generator.trust_domain != self._verifier.trust_domain
            )
            if not independence:
                raise ValueError("AI review routes are not independent")
            promoted, rejected, abstained = self._promote(batch, verification)
        except Exception:
            return self._failed_result(baseline, binding)
        merged = self._merge_findings(baseline, promoted, request)
        candidate_digest = self._candidate_digest(batch)
        verification_digest = self._verification_digest(verification)
        expires_at = self._clock() + 300
        counts = (len(batch.candidates), len(promoted), rejected, abstained)
        receipt_id = self._sign_receipt(
            "verified", "ai_verification_complete", binding, candidate_digest, verification_digest,
            expires_at, counts, True,
        )
        receipt = AiReviewReceipt(
            "verified", "ai_verification_complete", binding, len(batch.candidates), len(promoted), rejected,
            abstained, self._policy.candidate_route, self._policy.verifier_route,
            self._policy.candidate_prompt_version, self._policy.verifier_prompt_version, True,
            candidate_digest, verification_digest, expires_at, receipt_id,
        )
        return AiReviewResult(merged, receipt)

    def _validate_candidate_batch(self, request: ReviewRequest, batch: AiCandidateBatch, binding: str) -> None:
        if (
            batch.review_binding != binding or batch.route != self._policy.candidate_route
            or batch.prompt_version != self._policy.candidate_prompt_version
        ):
            raise ValueError("AI candidate context does not match review")
        files = {item.path: item for item in request.files}
        for item in batch.candidates:
            if any(inspect_text(text).outcome != "allow" for text in (
                item.category, item.claim, item.impact, item.remediation,
            )):
                raise ValueError("AI candidate text failed content inspection")
            if item.candidate_id != candidate_id(
                binding, item.severity, item.category, item.claim, item.evidence_refs,
            ):
                raise ValueError("AI candidate id is not bound to canonical content")
            for ref in item.evidence_refs:
                changed = files.get(ref.path)
                lines = changed.diff.splitlines() if changed is not None else ()
                if (
                    changed is None or ref.diff_line > len(lines) or not lines[ref.diff_line - 1].startswith("+")
                    or lines[ref.diff_line - 1].startswith("+++ ")
                    or line_digest(lines[ref.diff_line - 1]) != ref.line_digest
                ):
                    raise ValueError("AI candidate evidence is not grounded in an added line")

    def _validate_verification(
        self, candidates: AiCandidateBatch, verification: VerificationBatch, binding: str,
    ) -> None:
        if (
            verification.review_binding != binding or verification.route != self._policy.verifier_route
            or verification.prompt_version != self._policy.verifier_prompt_version
            or {item.candidate_id for item in verification.verdicts}
            != {item.candidate_id for item in candidates.candidates}
        ):
            raise ValueError("AI verification context or candidate set does not match")

    def _promote(
        self, candidates: AiCandidateBatch, verification: VerificationBatch,
    ) -> tuple[tuple[ReviewFinding, ...], int, int]:
        verdicts = {item.candidate_id: item for item in verification.verdicts}
        findings: list[ReviewFinding] = []
        for item in candidates.candidates:
            verdict = verdicts[item.candidate_id]
            if verdict.verdict == "confirmed" and verdict.confidence >= self._policy.min_confidence:
                ref = item.evidence_refs[0]
                findings.append(ReviewFinding(
                    item.severity, item.category, f"{ref.path}:{ref.diff_line}", item.claim,
                    (f"ai-verification:{verdict.reason_code}:{item.candidate_id}",), item.impact,
                    item.remediation, min(item.confidence, verdict.confidence),
                ))
        rejected = sum(item.verdict == "rejected" for item in verification.verdicts)
        abstained = sum(
            item.verdict == "abstain" or (item.verdict == "confirmed" and item.confidence < self._policy.min_confidence)
            for item in verification.verdicts
        )
        return tuple(findings), rejected, abstained

    @staticmethod
    def _merge_findings(
        baseline: ReviewResult, promoted: tuple[ReviewFinding, ...], request: ReviewRequest,
    ) -> ReviewResult:
        findings_by_key = {ReviewEngine._finding_key(item): item for item in promoted}
        findings_by_key.update({ReviewEngine._finding_key(item): item for item in baseline.findings})
        findings = tuple(sorted(
            findings_by_key.values(),
            key=lambda item: ({"high": 0, "medium": 1, "low": 2}[item.severity], item.location, item.category),
        ))
        blocking = any(item.severity in {"high", "medium"} for item in findings)
        status = "changes_requested" if blocking else baseline.receipt.status
        reason = "blocking_findings" if blocking else baseline.receipt.reason_code
        counts = tuple(sum(item.severity == severity for item in findings) for severity in ("high", "medium", "low"))
        open_keys = tuple(ReviewEngine._finding_key(item) for item in findings)
        closed_keys = tuple(sorted(set(request.prior_finding_keys) - set(open_keys))) if request.targeted_paths else ()
        receipt = replace(
            baseline.receipt, status=status, reason_code=reason, finding_counts=counts,
            open_finding_keys=open_keys, closed_finding_keys=closed_keys,
        )
        return ReviewResult(findings, baseline.affected_surface, receipt)

    def _failed_result(self, baseline: ReviewResult, binding: str) -> AiReviewResult:
        review = baseline
        if self._policy.required and baseline.receipt.status == "passed":
            review = ReviewResult(
                baseline.findings, baseline.affected_surface,
                replace(baseline.receipt, status="incomplete", reason_code="evidence_incomplete"),
            )
        empty_digest = "sha256:" + hashlib.sha256(b"").hexdigest()
        receipt = AiReviewReceipt(
            "failed", "ai_verification_incomplete", binding, 0, 0, 0, 0,
            self._policy.candidate_route, self._policy.verifier_route,
            self._policy.candidate_prompt_version, self._policy.verifier_prompt_version,
            False, empty_digest, empty_digest, self._clock(), "",
        )
        return AiReviewResult(review, receipt)

    @staticmethod
    def _candidate_digest(batch: AiCandidateBatch) -> str:
        canonical = "\0".join(
            f"{item.candidate_id}:{item.severity}:{item.category}:{item.claim}:{item.impact}:"
            f"{item.remediation}:{item.confidence}:"
            + ",".join(f"{ref.path}:{ref.diff_line}:{ref.line_digest}" for ref in item.evidence_refs)
            for item in sorted(batch.candidates, key=lambda value: value.candidate_id)
        )
        return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    @staticmethod
    def _verification_digest(verification: VerificationBatch) -> str:
        canonical = "\0".join(
            f"{item.candidate_id}:{item.verdict}:{item.confidence}:{item.reason_code}"
            for item in sorted(verification.verdicts, key=lambda value: value.candidate_id)
        )
        return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def _sign_receipt(
        self, status: str, reason_code: str, binding: str, candidate_digest: str,
        verification_digest: str, expires_at: float, counts: tuple[int, int, int, int], independence: bool,
    ) -> str:
        nonce = secrets.token_hex(16)
        message = self._receipt_message(
            status, reason_code, binding, candidate_digest, verification_digest, expires_at, counts, independence, nonce,
            self._policy.candidate_route, self._policy.verifier_route,
            self._policy.candidate_prompt_version, self._policy.verifier_prompt_version,
        )
        signature = hmac.new(self._key, message, hashlib.sha256).hexdigest()
        return f"receipt:ai_verification:{nonce}{signature}"

    def verify_receipt(self, receipt: AiReviewReceipt) -> bool:
        if receipt.status != "verified" or receipt.expires_at <= self._clock():
            return False
        token = receipt.verification_receipt.rsplit(":", 1)[-1]
        if len(token) != 96:
            return False
        nonce, signature = token[:32], token[32:]
        message = self._receipt_message(
            receipt.status, receipt.reason_code, receipt.review_binding, receipt.candidate_digest,
            receipt.verification_digest, receipt.expires_at,
            (receipt.candidate_count, receipt.verified_count, receipt.rejected_count, receipt.abstained_count),
            receipt.independence_verified, nonce,
            receipt.candidate_route, receipt.verifier_route,
            receipt.candidate_prompt_version, receipt.verifier_prompt_version,
        )
        return hmac.compare_digest(signature, hmac.new(self._key, message, hashlib.sha256).hexdigest())

    def _receipt_message(
        self, status: str, reason_code: str, binding: str, candidate_digest: str,
        verification_digest: str, expires_at: float, counts: tuple[int, int, int, int],
        independence: bool, nonce: str, candidate_route: str, verifier_route: str,
        candidate_prompt_version: str, verifier_prompt_version: str,
    ) -> bytes:
        return "\0".join((
            status, reason_code, binding, candidate_digest, verification_digest,
            candidate_route, verifier_route, candidate_prompt_version, verifier_prompt_version,
            *(str(item) for item in counts), str(independence), str(expires_at), nonce,
        )).encode("utf-8")


def line_digest(line: str) -> str:
    return "sha256:" + hashlib.sha256(line.encode("utf-8")).hexdigest()


def review_binding(request: ReviewRequest) -> str:
    return review_evidence_binding(request)


def candidate_id(
    binding: str, severity: str, category: str, claim: str, evidence_refs: tuple[DiffEvidenceRef, ...],
) -> str:
    canonical = "\0".join((
        binding, severity, category, " ".join(claim.lower().split()),
        *(f"{ref.path}:{ref.diff_line}:{ref.line_digest}" for ref in evidence_refs),
    ))
    return "candidate:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()
