"""Tamper-evident aggregate efficiency metrics without workflow content or identity."""

from __future__ import annotations

from dataclasses import dataclass, field, fields
import hashlib
import hmac
import json
from pathlib import Path
import sqlite3
from typing import Mapping

from promptforge.platform.secure_filesystem import SECURE_FILESYSTEM


_COUNTERS = (
    "input_tokens", "output_tokens", "candidate_input_tokens", "selected_input_tokens", "model_calls",
    "latency_ms", "agents_invoked", "skills_invoked", "cache_hits", "cache_lookups", "dedup_hits",
    "dedup_lookups", "privacy_redactions", "policy_denials", "review_findings", "manual_approvals", "runs",
    "first_run_successes",
)
_SCHEMA_SQL = (
    "CREATE TABLE efficiency_metrics (sequence INTEGER PRIMARY KEY AUTOINCREMENT,"
    + ",".join(f"{name} INTEGER NOT NULL" for name in _COUNTERS)
    + ",previous_hash TEXT NOT NULL,event_hash TEXT NOT NULL,attestation TEXT NOT NULL)"
)
_ZERO_HASH = "0" * 64


@dataclass(frozen=True)
class EfficiencyMetricEvent:
    """One numeric-only delta; no string field can carry task content or identifiers."""

    input_tokens: int = 0
    output_tokens: int = 0
    candidate_input_tokens: int = 0
    selected_input_tokens: int = 0
    model_calls: int = 0
    latency_ms: int = 0
    agents_invoked: int = 0
    skills_invoked: int = 0
    cache_hits: int = 0
    cache_lookups: int = 0
    dedup_hits: int = 0
    dedup_lookups: int = 0
    privacy_redactions: int = 0
    policy_denials: int = 0
    review_findings: int = 0
    manual_approvals: int = 0
    runs: int = 0
    first_run_successes: int = 0

    def __post_init__(self) -> None:
        values = tuple(getattr(self, item.name) for item in fields(self))
        if any(not isinstance(value, int) or isinstance(value, bool) or value < 0 for value in values):
            raise ValueError("efficiency metric counters must be non-negative integers")
        if (
            self.selected_input_tokens > self.candidate_input_tokens
            or self.cache_hits > self.cache_lookups
            or self.dedup_hits > self.dedup_lookups
            or self.first_run_successes > self.runs
        ):
            raise ValueError("efficiency metric counters are inconsistent")

    def values(self) -> tuple[int, ...]:
        return tuple(getattr(self, name) for name in _COUNTERS)


@dataclass(frozen=True)
class MetricsVerification:
    valid: bool
    samples: int
    last_hash: str


@dataclass(frozen=True)
class EfficiencyMetricsStore:
    """Owner-private SQLite chain containing only numeric metric deltas."""

    path: Path
    key: bytes = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        path = Path(self.path)
        if not path.is_absolute() or path.name != "efficiency-metrics.sqlite3" or not path.parent.is_dir():
            raise ValueError("efficiency metrics path is invalid")
        if not isinstance(self.key, bytes) or len(self.key) < 32:
            raise ValueError("efficiency metrics key is invalid")
        SECURE_FILESYSTEM.require_private_directory(path.parent)
        created = False
        if not path.exists():
            SECURE_FILESYSTEM.write_new_private(path, b"")
            created = True
        SECURE_FILESYSTEM.require_private_file(path, 100_000_000, allow_empty=created)
        object.__setattr__(self, "path", path)
        connection = sqlite3.connect(path)
        try:
            if created:
                connection.execute(_SCHEMA_SQL)
                connection.execute("PRAGMA user_version=1")
                connection.commit()
            schema = connection.execute(
                "SELECT sql FROM sqlite_master WHERE type='table' AND name='efficiency_metrics'"
            ).fetchone()
            version = connection.execute("PRAGMA user_version").fetchone()
            if schema != (_SCHEMA_SQL,) or version != (1,):
                raise RuntimeError("efficiency metrics schema mismatch")
        finally:
            connection.close()

    def append(self, event: EfficiencyMetricEvent) -> None:
        if not isinstance(event, EfficiencyMetricEvent):
            raise ValueError("efficiency metric event is invalid")
        connection = sqlite3.connect(self.path, timeout=30, isolation_level=None)
        try:
            connection.execute("BEGIN IMMEDIATE")
            verification = self._verify(connection)
            if not verification.valid:
                raise RuntimeError("efficiency metrics chain verification failed")
            event_hash = self._event_hash(verification.samples + 1, event, verification.last_hash)
            columns = ",".join((*_COUNTERS, "previous_hash", "event_hash", "attestation"))
            placeholders = ",".join("?" for _ in range(len(_COUNTERS) + 3))
            connection.execute(
                f"INSERT INTO efficiency_metrics ({columns}) VALUES ({placeholders})",
                (*event.values(), verification.last_hash, event_hash, self._attest(event_hash)),
            )
            connection.commit()
        except sqlite3.Error as error:
            connection.rollback()
            raise RuntimeError("efficiency metrics append failed") from error
        finally:
            connection.close()

    def verify(self) -> MetricsVerification:
        connection = sqlite3.connect(self.path)
        try:
            return self._verify(connection)
        except sqlite3.Error as error:
            raise RuntimeError("efficiency metrics verification failed") from error
        finally:
            connection.close()

    def summary(self) -> dict[str, object]:
        connection = sqlite3.connect(self.path)
        try:
            verification = self._verify(connection)
            if not verification.valid:
                raise RuntimeError("efficiency metrics chain verification failed")
            row = connection.execute(
                "SELECT " + ",".join(f"COALESCE(SUM({name}),0)" for name in _COUNTERS)
                + " FROM efficiency_metrics"
            ).fetchone()
        finally:
            connection.close()
        totals = dict(zip(_COUNTERS, row, strict=True))
        candidate = totals["candidate_input_tokens"]
        selected = totals["selected_input_tokens"]
        return {
            "schema_version": "1.0", "metrics_version": "efficiency-v1", "status": "ok",
            "samples": verification.samples,
            "input_tokens": totals["input_tokens"], "output_tokens": totals["output_tokens"],
            "token_saving_ratio": self._ratio(candidate - selected, candidate),
            "model_calls": totals["model_calls"],
            "latency_ms": self._average(totals["latency_ms"], totals["model_calls"]),
            "agents_invoked": totals["agents_invoked"], "skills_invoked": totals["skills_invoked"],
            "cache_hit_rate": self._ratio(totals["cache_hits"], totals["cache_lookups"]),
            "dedup_hit_rate": self._ratio(totals["dedup_hits"], totals["dedup_lookups"]),
            "privacy_redactions": totals["privacy_redactions"], "policy_denials": totals["policy_denials"],
            "review_findings": totals["review_findings"], "manual_approvals": totals["manual_approvals"],
            "first_run_success_rate": self._ratio(totals["first_run_successes"], totals["runs"]),
            "integrity_verified": True, "network_used": False,
        }

    def _verify(self, connection: sqlite3.Connection) -> MetricsVerification:
        rows = connection.execute(
            "SELECT sequence," + ",".join(_COUNTERS)
            + ",previous_hash,event_hash,attestation FROM efficiency_metrics ORDER BY sequence"
        ).fetchall()
        previous = _ZERO_HASH
        for expected, row in enumerate(rows, start=1):
            sequence, *values, stored_previous, event_hash, attestation = row
            try:
                event = EfficiencyMetricEvent(**dict(zip(_COUNTERS, values, strict=True)))
            except (TypeError, ValueError):
                return MetricsVerification(False, len(rows), previous)
            expected_hash = self._event_hash(sequence, event, previous)
            if not (
                sequence == expected and stored_previous == previous
                and hmac.compare_digest(event_hash, expected_hash)
                and hmac.compare_digest(attestation, self._attest(event_hash))
            ):
                return MetricsVerification(False, len(rows), previous)
            previous = event_hash
        return MetricsVerification(True, len(rows), previous)

    @staticmethod
    def _ratio(numerator: int, denominator: int) -> float:
        return round(numerator / denominator, 6) if denominator else 0.0

    @staticmethod
    def _average(total: int, count: int) -> float:
        return round(total / count, 3) if count else 0.0

    def _event_hash(self, sequence: int, event: EfficiencyMetricEvent, previous: str) -> str:
        payload: Mapping[str, object] = {
            "sequence": sequence, **dict(zip(_COUNTERS, event.values(), strict=True)), "previous_hash": previous,
        }
        return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()

    def _attest(self, event_hash: str) -> str:
        return "hmac-sha256:" + hmac.new(self.key, event_hash.encode("ascii"), hashlib.sha256).hexdigest()
