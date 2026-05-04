"""Backend protocols.

A protector talks to one or more ``Auditor``s through this interface.
Backends translate the neutral ``AuditPrompt`` into their provider's
message shape and return a ``RawJudgement``. Policy (timeouts, retries,
failure mode) lives in the protector, not in backends.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from ..types import AuditPrompt, RawJudgement


@runtime_checkable
class Auditor(Protocol):
    """Single-rule judge. Judges one ``(text, rule)`` pair at a time."""

    name: str
    model: str

    async def judge(self, prompt: AuditPrompt) -> RawJudgement: ...


@runtime_checkable
class BatchAuditor(Auditor, Protocol):
    """Optional capability: judge many rules in a single call.

    Backends that don't implement this fall back to N parallel ``judge``
    calls in the protector.
    """

    async def judge_batch(
        self,
        text: str,
        rules: list[str],
        system_instructions: str,
    ) -> list[RawJudgement]: ...


class MissingDependencyError(ImportError):
    """Raised when a backend's optional extra is not installed."""

    def __init__(self, backend: str, extra: str, package: str) -> None:
        super().__init__(
            f"{backend} requires the {package!r} package. "
            f"Install with: pip install prompt-protector[{extra}]"
        )
        self.backend = backend
        self.extra = extra
        self.package = package


__all__ = ["Auditor", "BatchAuditor", "MissingDependencyError"]
