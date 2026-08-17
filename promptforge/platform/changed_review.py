"""Реальный changed-files review с локальными exact-diff evidence receipts."""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path
import secrets
from time import time
from typing import Callable

from promptforge.platform.review import (
    ChangedFile,
    ReviewRequest,
    ReviewResult,
    diff_digest,
    is_non_prod_deploy_artifact,
)
from promptforge.platform.review_runtime import (
    GitReviewCollector,
    HmacReviewEvidenceService,
    review_evidence_binding,
)
from promptforge.platform.security import inspect_text
from promptforge.platform.review_checks import run_review_check


_CHECK_IDS = ("syntax", "tests", "contracts", "security", "deploy_safety")


@dataclass(frozen=True)
class ChangedFilesReviewRunner:
    """Проверяет выбранный реальный Git diff фиксированным локальным check set."""

    repository: Path
    evidence_key: bytes = field(repr=False, compare=False)
    clock: Callable[[], float] = field(default=time, repr=False, compare=False)

    def __post_init__(self) -> None:
        repository = Path(self.repository).resolve(strict=True)
        if not repository.is_dir():
            raise ValueError("changed review repository must be a directory")
        object.__setattr__(self, "repository", repository)
        HmacReviewEvidenceService(self.evidence_key, clock=self.clock)

    def review(
        self, selected_paths: frozenset[str], deploy_candidates: frozenset[str],
    ) -> ReviewResult:
        return self.review_context(selected_paths, deploy_candidates)[1]

    def review_context(
        self, selected_paths: frozenset[str], deploy_candidates: frozenset[str],
    ) -> tuple[ReviewRequest, ReviewResult]:
        """Возвращает exact request вместе с результатом для durable provenance binding."""

        files = GitReviewCollector(self.repository).collect_selected(selected_paths, deploy_candidates)
        statuses = self._check_statuses(files)
        trace_id = f"changed-review-{secrets.token_hex(8)}"
        base = ReviewRequest(
            "promptforge", "engineering-change", diff_digest(files), files, (), statuses["contracts"] == "passed",
            "draft-0.1", "1.0", ("review-engine:1.0.0",), "deterministic-only", trace_id,
        )
        evidence = HmacReviewEvidenceService(self.evidence_key, clock=self.clock)
        binding = review_evidence_binding(base)
        checks = tuple(evidence.issue(check_id, statuses[check_id], binding, 300) for check_id in _CHECK_IDS)
        request = ReviewRequest(
            base.project_id, base.purpose, base.diff_digest, base.files, checks, base.contract_reviewed,
            base.spec_version, base.policy_version, base.skill_versions, base.model_route, base.trace_id,
        )
        return request, evidence.review(request)

    def review_targeted_context(
        self, selected_paths: frozenset[str], deploy_candidates: frozenset[str], prior_finding_keys: tuple[str, ...],
    ) -> tuple[ReviewRequest, ReviewResult]:
        """Runs a fresh exact-diff review bound to verified prior finding keys."""

        files = GitReviewCollector(self.repository).collect_selected(selected_paths, deploy_candidates)
        statuses = self._check_statuses(files)
        trace_id = f"targeted-review-{secrets.token_hex(8)}"
        paths = tuple(sorted(selected_paths))
        base = ReviewRequest(
            "promptforge", "targeted-closure", diff_digest(files), files, (), statuses["contracts"] == "passed",
            "draft-0.1", "1.0", ("review-engine:1.0.0",), "deterministic-only", trace_id,
            paths, tuple(prior_finding_keys),
        )
        evidence = HmacReviewEvidenceService(self.evidence_key, clock=self.clock)
        evidence.authorize_prior_findings(tuple(prior_finding_keys), base.project_id, paths)
        binding = review_evidence_binding(base)
        checks = tuple(evidence.issue(check_id, statuses[check_id], binding, 300) for check_id in _CHECK_IDS)
        request = ReviewRequest(
            base.project_id, base.purpose, base.diff_digest, base.files, checks, base.contract_reviewed,
            base.spec_version, base.policy_version, base.skill_versions, base.model_route, base.trace_id,
            base.targeted_paths, base.prior_finding_keys,
        )
        return request, evidence.review(request)

    def _check_statuses(self, files: tuple[ChangedFile, ...]) -> dict[str, str]:
        return {
            "syntax": self._syntax_status(files),
            "tests": self._embedded_status("behavior"),
            "contracts": self._embedded_status("contracts"),
            "security": self._security_status(files),
            "deploy_safety": self._deploy_status(files),
        }

    def _syntax_status(self, files: tuple[ChangedFile, ...]) -> str:
        try:
            for changed in files:
                path = self.repository / changed.path
                if path.suffix == ".py" and path.exists():
                    ast.parse(path.read_text(encoding="utf-8"), filename=changed.path)
        except (OSError, UnicodeError, SyntaxError):
            return "failed"
        return "passed"

    @staticmethod
    def _embedded_status(check_id: str) -> str:
        try:
            passed = run_review_check(check_id)
        except (OSError, RuntimeError, ValueError):
            return "failed"
        return "passed" if passed else "failed"

    @staticmethod
    def _security_status(files: tuple[ChangedFile, ...]) -> str:
        for changed in files:
            inspection = inspect_text(changed.diff)
            if "provider_api_key" in inspection.detections:
                return "failed"
        return "passed"

    @staticmethod
    def _deploy_status(files: tuple[ChangedFile, ...]) -> str:
        for changed in files:
            if changed.deploy_candidate and is_non_prod_deploy_artifact(changed):
                return "failed"
        return "passed"
