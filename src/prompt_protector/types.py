"""Core types for prompt_protector.

All public dataclasses and enums live here so backends, heuristics, and the
protector itself can depend on a single import without cycles.
"""

from __future__ import annotations

import enum
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any


class FailureMode(str, enum.Enum):
    """How the protector behaves when its judges are unavailable.

    FAIL_CLOSED is the default because a safety layer that silently passes
    traffic when broken is worse than one that returns a graceful refusal.
    """

    FAIL_CLOSED = "fail_closed"
    FAIL_OPEN = "fail_open"


class Category(str, enum.Enum):
    PII = "pii"
    PROMPT_INJECTION = "prompt_injection"
    SECRETS = "secrets"
    NSFW = "nsfw"
    OFF_TOPIC = "off_topic"
    SCHEMA = "schema"
    TOXIC = "toxic"
    OTHER = "other"


class Action(str, enum.Enum):
    BLOCK = "block"
    REDACT = "redact"
    LOG = "log"


class Direction(str, enum.Enum):
    INPUT = "input"
    OUTPUT = "output"


@dataclass(frozen=True)
class Mode:
    """Enforcement mode for a protector call.

    ENFORCE blocks. SHADOW audits and logs without blocking. SAMPLE audits a
    fraction of traffic and passes the rest through unaudited.
    """

    kind: str = "enforce"  # enforce | shadow | sample
    sample_rate: float = 1.0

    @classmethod
    def enforce(cls) -> Mode:
        return cls(kind="enforce", sample_rate=1.0)

    @classmethod
    def shadow(cls) -> Mode:
        return cls(kind="shadow", sample_rate=1.0)

    @classmethod
    def sample(cls, p: float) -> Mode:
        if not 0.0 <= p <= 1.0:
            raise ValueError(f"sample rate must be in [0,1], got {p}")
        return cls(kind="sample", sample_rate=p)


# Default singletons for ergonomic imports.
ENFORCE = Mode.enforce()
SHADOW = Mode.shadow()


@dataclass(frozen=True)
class Match:
    """A heuristic / detector hit on a span of text."""

    detector: str
    category: Category
    span: tuple[int, int]
    original: str
    replacement: str | None = None
    score: float = 1.0


@dataclass(frozen=True)
class Turn:
    """A single conversation turn for history-aware audits."""

    role: str  # "user" | "assistant" | "system"
    content: str


@dataclass
class AuditResult:
    """Final verdict returned by the protector."""

    passed: bool
    score: float = 0.0
    category: Category | None = None
    rationale: str = ""
    rule_id: str | None = None
    matches: list[Match] = field(default_factory=list)
    redacted_text: str | None = None
    vault_id: str | None = None
    provider: str = ""
    model: str = ""
    latency_ms: int = 0
    degraded: bool = False
    trace_id: str | None = None
    verdicts: list[StageVerdict] = field(default_factory=list)


@dataclass(frozen=True)
class StageVerdict:
    """One stage of the pipeline's contribution to the final result.

    Lets callers see which detector / model in the chain triggered the verdict.
    """

    stage: str
    passed: bool
    category: Category | None
    rationale: str
    score: float = 0.0
    latency_ms: int = 0


@dataclass(frozen=True)
class AuditEvent:
    """Structured event emitted to the on_event hook."""

    kind: str  # "input" | "output" | "stream" | "config_reload"
    passed: bool
    category: Category | None
    rule_id: str | None
    provider: str
    model: str
    latency_ms: int
    degraded: bool
    trace_id: str | None
    error: str | None = None
    timestamp: float = field(default_factory=time.time)
    event_id: str = field(default_factory=lambda: uuid.uuid4().hex)


# Hook signature used by the protector.
EventHook = Callable[[AuditEvent], None]


@dataclass(frozen=True)
class AuditPrompt:
    """The neutral request shape the protector hands to a backend.

    Backends translate this into their provider-specific message shape.
    """

    text: str
    rule: str
    system_instructions: str
    history: tuple[Turn, ...] = ()


@dataclass(frozen=True)
class RawJudgement:
    """Raw structured response from a backend before policy is applied."""

    passed: bool
    rationale: str
    score: float = 0.0
    raw_response: Any = None


def make_match(
    detector: str,
    category: Category,
    span: tuple[int, int],
    original: str,
    replacement: str | None = None,
    score: float = 1.0,
) -> Match:
    return Match(
        detector=detector,
        category=category,
        span=span,
        original=original,
        replacement=replacement,
        score=score,
    )


__all__ = [
    "Action",
    "AuditEvent",
    "AuditPrompt",
    "AuditResult",
    "Category",
    "Direction",
    "ENFORCE",
    "EventHook",
    "FailureMode",
    "Match",
    "Mode",
    "RawJudgement",
    "SHADOW",
    "StageVerdict",
    "Turn",
    "make_match",
]
