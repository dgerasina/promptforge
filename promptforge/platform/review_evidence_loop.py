"""Durable metadata-only binding for review, documentation impact and audit."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re
from time import time
from typing import Callable

from promptforge.platform.contracts import Principal
from promptforge.platform.local_audit import AuditEvent, AuditReceipt, LocalAuditStore
from promptforge.platform.review import ReviewRequest, ReviewResult
from promptforge.platform.review_provenance import (
    DurableReviewFoundation, ReviewProvenanceReceipt, ReviewProvenanceStore,
)


_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")


def _canonical_digest(value: object) -> str:
    encoded = json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def documentation_evidence_payload(report: dict[str, object]) -> dict[str, object]:
    """Return the closed, versioned subset attested by the review loop."""
    required = {"schema_version", "status", "targets", "current", "drift", "blocked", "documents", "network_used"}
    if set(report) != required or report.get("schema_version") != "1.0" or report.get("status") != "ok":
        raise ValueError("documentation impact report fields mismatch")
    documents = report.get("documents")
    if not isinstance(documents, list):
        raise ValueError("documentation impact documents are invalid")
    bindings: list[dict[str, object]] = []
    for document in documents:
        if not isinstance(document, dict):
            raise ValueError("documentation impact document is invalid")
        bindings.append({
            "document_id": document.get("document_id"), "status": document.get("status"),
            "source_digest": document.get("source_digest"), "document_digest": document.get("document_digest"),
            "patch_digest": document.get("patch_digest"), "reason_codes": document.get("reason_codes"),
        })
    return {
        "schema_version": "1.0", "evidence_version": "1.0.0", "targets": report["targets"],
        "current": report["current"], "drift": report["drift"], "blocked": report["blocked"],
        "network_used": report["network_used"], "documents": bindings,
    }


def documentation_evidence_digest(report: dict[str, object]) -> str:
    return _canonical_digest(documentation_evidence_payload(report))


@dataclass(frozen=True)
class ReviewEvidenceReceipt:
    """Binds durable provenance and audit to the final repository decision."""

    provenance: ReviewProvenanceReceipt
    audit: AuditReceipt
    documentation_digest: str
    final_outcome: str

    def __post_init__(self) -> None:
        if not _DIGEST.fullmatch(self.documentation_digest) or self.final_outcome not in {"retained", "rolled-back"}:
            raise ValueError("review evidence decision is invalid")

    def to_payload(self) -> dict[str, object]:
        unsigned = {
            "schema_version": "1.0", "loop_version": "1.0.0",
            "provenance_receipt": self.provenance.to_payload(), "audit_receipt": self.audit.to_payload(),
            "documentation_digest": self.documentation_digest, "final_outcome": self.final_outcome,
        }
        return {**unsigned, "evidence_digest": _canonical_digest(unsigned)}


@dataclass(frozen=True)
class ReviewEvidenceLoop:
    """Appends both approved and blocked decisions to restart-verifiable chains."""

    state_root: Path
    key: bytes
    clock: Callable[[], float] = time

    def __post_init__(self) -> None:
        root = Path(self.state_root).resolve(strict=True)
        if not root.is_dir() or root.is_symlink():
            raise ValueError("review evidence state root is invalid")
        object.__setattr__(self, "state_root", root)

    def record(
        self, request: ReviewRequest, result: ReviewResult, catalog_digest: str, principal: Principal,
        final_outcome: str, documentation_digest: str,
    ) -> ReviewEvidenceReceipt:
        expected = "retained" if result.receipt.status == "passed" else "rolled-back"
        if final_outcome != expected or not _DIGEST.fullmatch(documentation_digest):
            raise ValueError("review evidence outcome does not match review")
        provenance = DurableReviewFoundation(ReviewProvenanceStore(
            self.state_root / "review-provenance.sqlite3", self.key, clock=self.clock,
        )).record(request, result, agent_catalog_digest=catalog_digest)
        audit = LocalAuditStore(
            self.state_root / "audit.sqlite3", self.key, clock=self.clock,
        ).append(AuditEvent(
            request.trace_id, principal.id, principal.project_id, "review.evidence", provenance.record_digest,
            "ok" if final_outcome == "retained" else "error", final_outcome, request.policy_version,
            int(self.clock()),
        ))
        return ReviewEvidenceReceipt(provenance, audit, documentation_digest, final_outcome)
