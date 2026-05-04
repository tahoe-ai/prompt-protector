"""Typed-placeholder redaction built on the heuristics layer.

Two output styles:

* ``RedactionStyle.LABELED`` — ``[REDACTED:SSN]`` (reusable across
  occurrences; cheap; no vault needed).
* ``RedactionStyle.NUMBERED`` — ``[SSN_1]``, ``[SSN_2]`` (stable per-request
  mapping; required for reversible redaction via vault).

Replacement is span-based and right-to-left so spans never shift.
"""

from __future__ import annotations

import enum
import re
from dataclasses import dataclass, field
from typing import Iterable, Optional

from .heuristics import DetectorRegistry, default_registry
from .types import Category, Match


class RedactionStyle(str, enum.Enum):
    LABELED = "labeled"
    NUMBERED = "numbered"


@dataclass
class RedactionResult:
    """Result of a redaction pass.

    ``mapping`` is a list of ``(placeholder, original)`` tuples in the order
    redactions were applied. Suitable to hand to a ``RedactionVault``.
    """

    redacted_text: str
    matches: list[Match]
    mapping: list[tuple[str, str]] = field(default_factory=list)


def redact(
    text: str,
    *,
    registry: Optional[DetectorRegistry] = None,
    style: RedactionStyle = RedactionStyle.LABELED,
    categories: Optional[Iterable[Category]] = None,
    detectors: Optional[Iterable[str]] = None,
) -> RedactionResult:
    """Run detectors and replace each hit with a placeholder.

    ``categories`` / ``detectors`` filter what the registry returns, so
    callers can request "PII only" or "credit_card only".
    """
    reg = registry or default_registry()
    matches = reg.scan(text)
    if categories is not None:
        cats = set(categories)
        matches = [m for m in matches if m.category in cats]
    if detectors is not None:
        names = set(detectors)
        matches = [m for m in matches if m.detector in names]

    matches = _dedupe_overlapping(matches)

    if not matches:
        return RedactionResult(redacted_text=text, matches=[], mapping=[])

    # _dedupe_overlapping already returns non-overlapping spans; sort by start
    # so we can rebuild the string in one left-to-right pass.
    matches_sorted = sorted(matches, key=lambda m: m.span[0])
    counters: dict[str, int] = {}
    mapping: list[tuple[str, str]] = []
    pieces: list[str] = []
    cursor = 0
    rebuilt_matches: list[Match] = []

    for m in matches_sorted:
        start, end = m.span
        pieces.append(text[cursor:start])
        if style is RedactionStyle.NUMBERED:
            counters[m.detector] = counters.get(m.detector, 0) + 1
            placeholder = f"[{m.detector.upper()}_{counters[m.detector]}]"
        else:
            placeholder = m.replacement or f"[REDACTED:{m.detector.upper()}]"
        pieces.append(placeholder)
        mapping.append((placeholder, text[start:end]))
        rebuilt_matches.append(
            Match(
                detector=m.detector,
                category=m.category,
                span=m.span,
                original=text[start:end],
                replacement=placeholder,
                score=m.score,
            )
        )
        cursor = end
    pieces.append(text[cursor:])

    return RedactionResult(
        redacted_text="".join(pieces),
        matches=rebuilt_matches,
        mapping=mapping,
    )


def _dedupe_overlapping(matches: list[Match]) -> list[Match]:
    """Resolve overlapping detector hits.

    Priority: higher score first; on ties, longer span wins; on ties again,
    leftmost. We then accept candidates that don't overlap any already-
    accepted match (interval scheduling with priorities).
    """
    if not matches:
        return matches
    candidates = sorted(
        matches,
        key=lambda m: (-m.score, -(m.span[1] - m.span[0]), m.span[0]),
    )
    accepted: list[Match] = []
    for m in candidates:
        if not any(
            m.span[0] < a.span[1] and a.span[0] < m.span[1] for a in accepted
        ):
            accepted.append(m)
    accepted.sort(key=lambda m: m.span[0])
    return accepted


def restore(text: str, mapping: list[tuple[str, str]]) -> str:
    """Reverse a redaction in a single linear pass.

    Builds one regex from the placeholders sorted longest-first so
    ``[SSN_11]`` always wins over ``[SSN_1]`` and same-length placeholders
    can't accidentally consume each other's prefixes. Substitution is one
    pass over the text, vs the previous N×len(text) ``str.replace`` chain.
    """
    if not mapping:
        return text
    # De-dup placeholders first; if the same placeholder appears with
    # different originals, last-write-wins (matches the legacy str.replace
    # ordering, since `restore` was always called on a single request's map).
    lookup: dict[str, str] = {}
    for placeholder, original in mapping:
        lookup[placeholder] = original
    ordered = sorted(lookup.keys(), key=len, reverse=True)
    pattern = re.compile("|".join(re.escape(p) for p in ordered))
    return pattern.sub(lambda m: lookup[m.group(0)], text)


__all__ = ["RedactionResult", "RedactionStyle", "redact", "restore"]
