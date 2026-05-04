"""Protocols and shared types for the local-model layer."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Awaitable, Optional, Protocol, runtime_checkable

from ..types import AuditPrompt, Match, RawJudgement


@dataclass
class LocalRedactionResult:
    """Output shape for ``LocalRedactor.redact``.

    ``mapping`` is a list of ``(placeholder, original)`` tuples — used for
    reversible redaction via the protector's ``RedactionVault``.
    """

    redacted_text: str
    matches: list[Match] = field(default_factory=list)
    mapping: list[tuple[str, str]] = field(default_factory=list)


@runtime_checkable
class LocalRedactor(Protocol):
    """Strips sensitive information from text before it reaches a cloud model."""

    name: str

    def redact(self, text: str) -> LocalRedactionResult: ...


@runtime_checkable
class LocalAuditor(Protocol):
    """An auditor whose model runs in-process or on the local host."""

    name: str
    model: str

    async def judge(self, prompt: AuditPrompt) -> RawJudgement: ...


@runtime_checkable
class RedactionVault(Protocol):
    """Stores per-request placeholder→original mappings for reversible redaction."""

    def put(self, vault_id: str, mapping: list[tuple[str, str]]) -> None: ...

    def get(self, vault_id: str) -> list[tuple[str, str]]: ...

    def delete(self, vault_id: str) -> None: ...


__all__ = [
    "LocalAuditor",
    "LocalRedactionResult",
    "LocalRedactor",
    "RedactionVault",
]
