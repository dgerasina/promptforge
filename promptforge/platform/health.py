"""Безопасный health-контракт PromptForge Platform."""

from __future__ import annotations


def health_payload() -> dict[str, str]:
    """Возвращает версионированный статус без runtime-секретов."""

    return {"schema_version": "1.0", "service": "promptforge-platform", "status": "ok"}
