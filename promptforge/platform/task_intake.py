"""Privacy-first deterministic intake for natural-language repository tasks."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import stat
from types import MappingProxyType
from typing import Mapping
import unicodedata

from promptforge.platform.privacy import PrivacyContext, PrivacyPipeline, ScopedMappingVault
from promptforge.platform.unified_ux import UnifiedWorkCoordinator, WorkRequest
from promptforge.core.project_profile import load_project_profile


_MAX_TASK_BYTES = 16_384
_TASK_KIND = re.compile(r"^[a-z][a-z0-9-]*(?:\.[a-z0-9-]+)+$")
_VERSION = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_FIELDS = frozenset({"schema_version", "intake_version", "rules", "intent_digest"})
_RULE_FIELDS = frozenset({"task_kind", "phrases"})
_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def _digest(value: object) -> str:
    return "sha256:" + hashlib.sha256(_canonical(value)).hexdigest()


def _strict_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("task intent config contains duplicate fields")
        result = {**result, key: value}
    return result


def _normalize(value: str) -> str:
    normalized = " ".join(unicodedata.normalize("NFKC", value).casefold().split())
    if not normalized or len(value.encode("utf-8")) > _MAX_TASK_BYTES or any(ord(item) < 32 for item in normalized):
        raise ValueError("task content is empty, oversized or contains controls")
    return normalized


@dataclass(frozen=True)
class IntentRule:
    task_kind: str
    phrases: tuple[str, ...]


@dataclass(frozen=True)
class IntakeResult:
    status: str
    reason_code: str
    task_kind: str | None
    task_digest: str
    intent_digest: str
    candidate_task_kinds: tuple[str, ...]
    privacy: Mapping[str, object]
    plan: Mapping[str, object] | None

    def to_payload(self) -> dict[str, object]:
        return {
            "schema_version": "1.0", "intake_version": "1.0.0", "status": self.status,
            "reason_code": self.reason_code, "task_kind": self.task_kind, "task_digest": self.task_digest,
            "intent_digest": self.intent_digest, "candidate_task_kinds": list(self.candidate_task_kinds),
            "privacy": dict(self.privacy),
            "plan": None if self.plan is None else dict(self.plan), "network_used": False,
        }


@dataclass(frozen=True)
class TaskIntake:
    product_root: Path
    coordinator: UnifiedWorkCoordinator
    rules: tuple[IntentRule, ...]
    intent_digest: str

    @classmethod
    def from_product(cls, product_root: Path) -> TaskIntake:
        root = Path(product_root).resolve(strict=True)
        profile = load_project_profile(root / "project-profile.yaml")
        return cls.from_config(root, profile.pack.task_intents)

    @classmethod
    def from_config(cls, product_root: Path, config_path: Path) -> TaskIntake:
        root = Path(product_root).resolve(strict=True)
        source = Path(config_path)
        descriptor = os.open(source, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > 65_536:
                raise ValueError("task intent config must be a bounded regular file")
            with os.fdopen(descriptor, "r", encoding="utf-8") as stream:
                descriptor = -1
                payload = json.load(stream, object_pairs_hook=_strict_object)
        finally:
            if descriptor >= 0:
                os.close(descriptor)
        if not isinstance(payload, dict) or set(payload) != _FIELDS or payload.get("schema_version") != "1.0":
            raise ValueError("task intent config fields are invalid")
        unsigned = {key: value for key, value in payload.items() if key != "intent_digest"}
        if payload["intent_digest"] != _digest(unsigned) or not _DIGEST.fullmatch(str(payload["intent_digest"])):
            raise ValueError("task intent config integrity failed")
        if not _VERSION.fullmatch(str(payload.get("intake_version"))) or not isinstance(payload.get("rules"), list):
            raise ValueError("task intent config version or rules are invalid")
        rules = tuple(cls._rule(item) for item in payload["rules"])
        if not rules or len({rule.task_kind for rule in rules}) != len(rules):
            raise ValueError("task intent rules are empty or duplicated")
        coordinator = UnifiedWorkCoordinator.from_repository(root)
        catalog_tasks = {kind for agent in coordinator.catalog.agents for kind in agent.task_kinds}
        if any(rule.task_kind not in catalog_tasks for rule in rules):
            raise ValueError("task intent rule is not present in agent catalog")
        return cls(root, coordinator, rules, payload["intent_digest"])

    @staticmethod
    def _rule(payload: object) -> IntentRule:
        if not isinstance(payload, dict) or set(payload) != _RULE_FIELDS or not _TASK_KIND.fullmatch(str(payload.get("task_kind"))):
            raise ValueError("task intent rule fields are invalid")
        phrases = payload.get("phrases")
        if not isinstance(phrases, list) or not phrases or any(not isinstance(item, str) for item in phrases):
            raise ValueError("task intent phrases are invalid")
        normalized = tuple(_normalize(item) for item in phrases)
        if len(set(normalized)) != len(normalized):
            raise ValueError("task intent phrases are duplicated")
        return IntentRule(payload["task_kind"], normalized)

    def plan(self, principal_id: str, trace_id: str, content: str) -> IntakeResult:
        if not _SAFE_ID.fullmatch(principal_id) or not _SAFE_ID.fullmatch(trace_id):
            raise ValueError("task intake identity or trace is invalid")
        normalized = _normalize(content)
        privacy = PrivacyPipeline(ScopedMappingVault()).transform(
            normalized, "internal", PrivacyContext(
                self.coordinator.profile.project_key, trace_id, principal_id, "task-intake", "local", False, 300,
            ),
        )
        task_digest = "sha256:" + hashlib.sha256(privacy.safe_content.encode("utf-8")).hexdigest()
        privacy_payload = MappingProxyType(privacy.receipt.to_payload())
        if privacy.outcome == "deny":
            return IntakeResult(
                "denied", "sensitive_content_detected", None, task_digest, self.intent_digest, (), privacy_payload, None,
            )
        safe_content = _normalize(privacy.safe_content)
        matches = tuple(
            rule.task_kind for rule in self.rules if any(phrase in safe_content for phrase in rule.phrases)
        )
        if len(matches) != 1:
            reason = "task_unknown" if not matches else "task_ambiguous"
            return IntakeResult(
                "blocked", reason, None, task_digest, self.intent_digest, tuple(sorted(set(matches))), privacy_payload, None,
            )
        work = self.coordinator.plan(WorkRequest(principal_id, matches[0], trace_id))
        return IntakeResult(
            work.status, work.reason_code, matches[0], task_digest, self.intent_digest,
            (matches[0],), privacy_payload, MappingProxyType(work.to_payload()),
        )
