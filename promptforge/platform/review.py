"""Changed-files scoped Automated Review Engine с проверяемым evidence."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
from pathlib import Path
import re
from typing import Protocol

from promptforge.core.project_profile import ReviewRules, load_project_profile
from promptforge.platform.contracts import ReviewFinding, SCHEMA_VERSION
from promptforge.platform.security import inspect_text


_SAFE_PATH = re.compile(r"^[A-Za-z0-9._/-]{1,512}$")
_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_EVIDENCE = re.compile(r"^receipt:[a-z][a-z0-9_-]{0,31}:[a-z0-9]{6,128}$")
_CHECKS = frozenset({"syntax", "tests", "contracts", "security", "deploy_safety"})


def _active_review_rules() -> ReviewRules:
    root = Path(__file__).resolve().parents[2]
    return load_project_profile(root / "project-profile.yaml").pack.review


@dataclass(frozen=True)
class ChangedFile:
    """Описывает один changed-file diff и намерение включить его в deploy."""

    path: str
    diff: str
    deploy_candidate: bool

    def __post_init__(self) -> None:
        if (
            not isinstance(self.path, str) or not _SAFE_PATH.fullmatch(self.path)
            or self.path.startswith(("/", "../")) or "/../" in self.path
        ):
            raise ValueError("review file path is unsafe")
        if not isinstance(self.diff, str) or not self.diff or len(self.diff) > 200_000:
            raise ValueError("review diff must be non-empty and bounded")
        if not _is_diff_fragment(self.diff):
            raise ValueError("review input must be a unified diff fragment")
        if not isinstance(self.deploy_candidate, bool):
            raise ValueError("deploy_candidate must be a boolean")

    def to_payload(self) -> dict[str, object]:
        return {"path": self.path, "diff": self.diff, "deploy_candidate": self.deploy_candidate}


@dataclass(frozen=True)
class CheckEvidence:
    """Фиксирует metadata receipt реально выполненной deterministic проверки."""

    check_id: str
    status: str
    evidence: str

    def __post_init__(self) -> None:
        if self.check_id not in _CHECKS or self.status not in {"passed", "failed"}:
            raise ValueError("review check id or status is invalid")
        if not isinstance(self.evidence, str) or not _EVIDENCE.fullmatch(self.evidence):
            raise ValueError("review check evidence must be a safe receipt id")

    def to_payload(self) -> dict[str, str]:
        return {"check_id": self.check_id, "status": self.status, "evidence": self.evidence}


class ReviewEvidenceVerifier(Protocol):
    def verify(self, check: CheckEvidence, request: ReviewRequest) -> bool:
        """Проверяет receipt для exact review context."""

    def verify_prior_findings(
        self, finding_keys: tuple[str, ...], project_id: str, targeted_paths: tuple[str, ...],
    ) -> bool:
        """Проверяет provenance findings из предыдущего review receipt."""


@dataclass(frozen=True)
class FakeReviewEvidenceVerifier:
    """Детерминированный verifier только для synthetic validation contexts."""

    receipts: frozenset[tuple[str, str, str, str]]
    prior_scopes: frozenset[tuple[tuple[str, ...], str, tuple[str, ...]]] = frozenset()

    def verify(self, check: CheckEvidence, request: ReviewRequest) -> bool:
        return (check.check_id, check.status, check.evidence, request.diff_digest) in self.receipts

    def verify_prior_findings(
        self, finding_keys: tuple[str, ...], project_id: str, targeted_paths: tuple[str, ...],
    ) -> bool:
        return (finding_keys, project_id, targeted_paths) in self.prior_scopes


@dataclass(frozen=True)
class ReviewRequest:
    """Связывает exact diff с spec/policy/toolchain evidence."""

    project_id: str
    purpose: str
    diff_digest: str
    files: tuple[ChangedFile, ...]
    checks: tuple[CheckEvidence, ...]
    contract_reviewed: bool
    spec_version: str
    policy_version: str
    skill_versions: tuple[str, ...]
    model_route: str
    trace_id: str
    targeted_paths: tuple[str, ...] = ()
    prior_finding_keys: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        files, checks = tuple(self.files), tuple(self.checks)
        targeted_paths, skill_versions = tuple(self.targeted_paths), tuple(self.skill_versions)
        prior_finding_keys = tuple(self.prior_finding_keys)
        identifiers = (
            self.project_id, self.purpose, self.spec_version, self.policy_version, self.model_route, self.trace_id,
        )
        if any(not isinstance(item, str) or not _SAFE_ID.fullmatch(item) for item in identifiers):
            raise ValueError("review request identifiers are unsafe")
        if not _DIGEST.fullmatch(self.diff_digest) or not files:
            raise ValueError("review request requires files and a SHA-256 digest")
        if self.diff_digest != diff_digest(files):
            raise ValueError("review diff digest does not match changed files")
        if len({item.path for item in files}) != len(files) or len({item.check_id for item in checks}) != len(checks):
            raise ValueError("review request contains duplicate files or checks")
        if not isinstance(self.contract_reviewed, bool):
            raise ValueError("contract_reviewed must be a boolean")
        if any(not _SAFE_ID.fullmatch(item) for item in skill_versions):
            raise ValueError("skill version identifier is unsafe")
        if any(path not in {item.path for item in files} for path in targeted_paths):
            raise ValueError("targeted review path is outside changed files")
        if targeted_paths and any(item.path not in targeted_paths for item in files):
            raise ValueError("targeted re-review contains files outside requested scope")
        if any(not _DIGEST.fullmatch(item) for item in prior_finding_keys):
            raise ValueError("prior finding key is invalid")
        object.__setattr__(self, "files", files)
        object.__setattr__(self, "checks", checks)
        object.__setattr__(self, "targeted_paths", targeted_paths)
        object.__setattr__(self, "skill_versions", skill_versions)
        object.__setattr__(self, "prior_finding_keys", prior_finding_keys)

    def to_payload(self) -> dict[str, object]:
        return {
            "schema_version": SCHEMA_VERSION, "project_id": self.project_id, "purpose": self.purpose,
            "diff_digest": self.diff_digest, "files": [item.to_payload() for item in self.files],
            "checks": [item.to_payload() for item in self.checks], "contract_reviewed": self.contract_reviewed,
            "spec_version": self.spec_version, "policy_version": self.policy_version,
            "skill_versions": list(self.skill_versions), "model_route": self.model_route, "trace_id": self.trace_id,
            "targeted_paths": list(self.targeted_paths),
            "prior_finding_keys": list(self.prior_finding_keys),
        }


@dataclass(frozen=True)
class ReviewReceipt:
    """Metadata-only evidence результата review."""

    status: str
    reason_code: str
    trace_id: str
    project_id: str
    diff_digest: str
    affected_surface: tuple[str, ...]
    finding_counts: tuple[int, int, int]
    checks_passed: tuple[str, ...]
    checks_failed: tuple[str, ...]
    contract_reviewed: bool
    spec_version: str
    policy_version: str
    targeted: bool
    open_finding_keys: tuple[str, ...]
    closed_finding_keys: tuple[str, ...]
    review_version: str = "1.0"

    def to_payload(self) -> dict[str, object]:
        high, medium, low = self.finding_counts
        return {
            "schema_version": SCHEMA_VERSION, "status": self.status, "reason_code": self.reason_code,
            "trace_id": self.trace_id, "project_id": self.project_id, "diff_digest": self.diff_digest,
            "affected_surface": list(self.affected_surface),
            "finding_counts": {"high": high, "medium": medium, "low": low},
            "checks_passed": list(self.checks_passed), "checks_failed": list(self.checks_failed),
            "contract_reviewed": self.contract_reviewed, "spec_version": self.spec_version,
            "policy_version": self.policy_version, "targeted": self.targeted, "review_version": self.review_version,
            "open_finding_keys": list(self.open_finding_keys),
            "closed_finding_keys": list(self.closed_finding_keys),
        }


@dataclass(frozen=True)
class ReviewResult:
    findings: tuple[ReviewFinding, ...]
    affected_surface: tuple[str, ...]
    receipt: ReviewReceipt

    def to_payload(self) -> dict[str, object]:
        return {
            "schema_version": SCHEMA_VERSION, "affected_surface": list(self.affected_surface),
            "findings": [finding.to_payload() for finding in self.findings], "receipt": self.receipt.to_payload(),
        }


class ReviewEngine:
    """Объединяет deterministic diff checks с externally verified contract evidence."""

    def __init__(
        self, evidence_verifier: ReviewEvidenceVerifier | None = None, rules: ReviewRules | None = None,
    ) -> None:
        self._evidence_verifier = evidence_verifier
        self._rules = rules or _active_review_rules()

    def review(self, request: ReviewRequest) -> ReviewResult:
        if request.prior_finding_keys and (
            not request.targeted_paths or self._evidence_verifier is None
            or not self._evidence_verifier.verify_prior_findings(
                request.prior_finding_keys, request.project_id, request.targeted_paths,
            )
        ):
            raise ValueError("prior review findings are not verified")
        findings = tuple(
            sorted(
                (
                    *(finding for changed in request.files for finding in self._review_file(changed)),
                    *(self._failed_check_finding(check) for check in request.checks if check.status == "failed"),
                ),
                key=lambda item: ({"high": 0, "medium": 1, "low": 2}[item.severity], item.location, item.category),
            )
        )
        surface = self._affected_surface(request.files)
        checks = {check.check_id: check for check in request.checks}
        verified_passed = tuple(
            sorted(
                check.check_id for check in checks.values()
                if check.status == "passed" and self._evidence_verifier is not None
                and self._evidence_verifier.verify(check, request)
            )
        )
        checks_complete = (
            frozenset(checks) == _CHECKS and frozenset(verified_passed) == _CHECKS
        )
        blocking = any(finding.severity in {"high", "medium"} for finding in findings)
        if blocking:
            status, reason = "changes_requested", "blocking_findings"
        elif not checks_complete or not request.contract_reviewed:
            status, reason = "incomplete", "evidence_incomplete"
        else:
            status, reason = "passed", "review_passed"
        counts = tuple(
            sum(finding.severity == severity for finding in findings) for severity in ("high", "medium", "low")
        )
        open_keys = tuple(self._finding_key(finding) for finding in findings)
        closed_keys = tuple(sorted(set(request.prior_finding_keys) - set(open_keys))) if request.targeted_paths else ()
        receipt = ReviewReceipt(
            status, reason, request.trace_id, request.project_id, request.diff_digest, surface, counts,
            verified_passed,
            tuple(sorted(check.check_id for check in request.checks if check.status == "failed")),
            request.contract_reviewed, request.spec_version, request.policy_version, bool(request.targeted_paths),
            open_keys, closed_keys,
        )
        return ReviewResult(findings, surface, receipt)

    def _review_file(self, changed: ChangedFile) -> tuple[ReviewFinding, ...]:
        added = tuple(
            (line_number, line[1:]) for line_number, line in enumerate(changed.diff.splitlines(), 1)
            if line.startswith("+") and not line.startswith("+++ ") and line[1:].strip()
        )
        findings: list[ReviewFinding] = []
        for line_number, content in added:
            inspection = inspect_text(content)
            if "provider_api_key" in inspection.detections or "private_key" in inspection.detections:
                findings.append(self._secret_finding(changed.path, line_number, inspection.detections))
        if changed.deploy_candidate and self._is_non_prod_artifact(changed, added):
            findings.append(self._deploy_finding(changed.path))
        return tuple(findings)

    @staticmethod
    def _secret_finding(path: str, line: int, detections: tuple[str, ...]) -> ReviewFinding:
        return ReviewFinding(
            "high", "security", f"{path}:{line}", "Secret-like material is present in an added line.",
            tuple(f"detector:{item}" for item in detections),
            "The value could be committed or leave the trusted boundary.",
            "Remove the value and use an approved secret source.", 1.0,
        )

    @staticmethod
    def _deploy_finding(path: str) -> ReviewFinding:
        return ReviewFinding(
            "high", "deploy", f"{path}:1", "A test/history/sandbox artifact is marked for production deploy.",
            ("project-rule:non-prod-artifacts-excluded",),
            "Non-production code or data targets could be activated in production.",
            "Remove the artifact from the production deploy list.", 1.0,
        )

    @staticmethod
    def _failed_check_finding(check: CheckEvidence) -> ReviewFinding:
        return ReviewFinding(
            "high", "validation", f"checks/{check.check_id}", f"Deterministic check {check.check_id} failed.",
            (check.evidence,), "A required validation gate did not pass.",
            "Fix the failure and attach a new trusted check receipt.", 1.0,
        )

    @staticmethod
    def _finding_key(finding: ReviewFinding) -> str:
        canonical = "\0".join((finding.category, finding.location, " ".join(finding.claim.lower().split())))
        return f"sha256:{hashlib.sha256(canonical.encode()).hexdigest()}"

    def _is_non_prod_artifact(self, changed: ChangedFile, added: tuple[tuple[int, str], ...]) -> bool:
        return is_non_prod_deploy_artifact(changed, tuple(line for _, line in added), rules=self._rules)

    def _affected_surface(self, files: tuple[ChangedFile, ...]) -> tuple[str, ...]:
        found: set[str] = set()
        for changed in files:
            path = changed.path.lower()
            for surface in self._rules.surfaces:
                if path.endswith(surface.extensions) or any(marker.lower() in path for marker in surface.path_markers):
                    found.add(surface.id)
        return tuple(surface.id for surface in self._rules.surfaces if surface.id in found)


def is_non_prod_deploy_artifact(
    changed: ChangedFile,
    added_lines: tuple[str, ...] | None = None,
    *,
    rules: ReviewRules | None = None,
) -> bool:
    """Отличает deploy target от безопасного упоминания sandbox внутри detector source."""

    stem = changed.path.rsplit("/", 1)[-1].rsplit(".", 1)[0]
    active_rules = rules or _active_review_rules()
    if stem.endswith(active_rules.non_prod_suffixes):
        return True
    lines = added_lines or tuple(
        line[1:] for line in changed.diff.splitlines()
        if line.startswith("+") and not line.startswith("+++ ") and line[1:].strip()
    )
    sandbox_lines = tuple(line for line in lines if any(name in line for name in active_rules.sandbox_names))
    suffix = changed.path.rsplit(".", 1)[-1].lower() if "." in changed.path else ""
    if suffix in {"sql", "ddl", "hql", "yaml", "yml", "json", "toml"}:
        return bool(sandbox_lines)
    if not active_rules.sandbox_target_fields or not active_rules.sandbox_names:
        return False
    fields = "|".join(re.escape(item) for item in active_rules.sandbox_target_fields)
    sandboxes = "|".join(re.escape(item) for item in active_rules.sandbox_names)
    target = re.compile(rf"\b(?:{fields})(?:\b|_).{{0,120}}\b(?:{sandboxes})\b", re.IGNORECASE)
    return any(target.search(line) for line in sandbox_lines)


def review_fixture(*, path: str, diff: str) -> tuple[ReviewFinding, ...]:
    """Сохраняет совместимость синтетического fixture API."""

    if not path.strip() or not diff.strip():
        raise ValueError("review path and diff must be non-empty")
    changed = ChangedFile(path, diff, False)
    return ReviewEngine()._review_file(changed)


def diff_digest(files: tuple[ChangedFile, ...]) -> str:
    """Возвращает canonical digest changed-files snapshot без сохранения diff."""

    digest = hashlib.sha256()
    for changed in sorted(files, key=lambda item: item.path):
        deploy_intent = b"deploy" if changed.deploy_candidate else b"exclude"
        digest.update(changed.path.encode() + b"\0" + changed.diff.encode() + b"\0" + deploy_intent + b"\0")
    return f"sha256:{digest.hexdigest()}"


def _is_diff_fragment(value: str) -> bool:
    lines = value.splitlines()
    if not lines or not any(line.startswith(("+", "-")) for line in lines):
        return False
    prefixes = ("+", "-", " ", "@@", "diff ", "index ", "new file ", "deleted file ", "\\ No newline")
    return all(bool(line) and line.startswith(prefixes) for line in lines)
