"""Local fast-path detectors.

Run before any LLM call: cheap, deterministic, and covers the well-known
cases (PII formats, secret tokens, common injection phrases, HTML
injection, homoglyph density). A heuristic hit short-circuits to
``passed=False``; a miss falls through to the LLM auditor.
"""

from __future__ import annotations

import logging
import re
import unicodedata
from collections import Counter
from dataclasses import dataclass, field
from math import log2
from typing import Callable, Iterable, Optional, Pattern

from .types import Category, Match, make_match

log = logging.getLogger("prompt_protector")


# ---------------------------------------------------------------------------
# Detector primitives
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Detector:
    """A single named detector."""

    name: str
    category: Category
    fn: Callable[[str], list[Match]]
    score: float = 1.0
    enabled: bool = True


@dataclass
class DetectorRegistry:
    """Composable set of detectors."""

    detectors: list[Detector] = field(default_factory=list)

    def add(self, detector: Detector) -> "DetectorRegistry":
        self.detectors.append(detector)
        return self

    def remove(self, name: str) -> None:
        self.detectors = [d for d in self.detectors if d.name != name]

    def scan(self, text: str) -> list[Match]:
        out: list[Match] = []
        for d in self.detectors:
            if not d.enabled:
                continue
            try:
                out.extend(d.fn(text))
            except re.error as exc:
                # User-supplied regex blew up — keep going but make it loud.
                log.warning("detector_regex_error", extra={"detector": d.name, "error": str(exc)})
            except Exception:
                # Anything else is a programmer error — surface it loudly so it
                # doesn't sit silent in production.
                log.exception("detector_failed", extra={"detector": d.name})
                raise
        return out


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _matches_from_pattern(
    pattern: Pattern[str],
    text: str,
    detector: str,
    category: Category,
    score: float = 1.0,
    validator: Optional[Callable[[str], bool]] = None,
    replacement_template: Optional[str] = None,
) -> list[Match]:
    out: list[Match] = []
    for m in pattern.finditer(text):
        candidate = m.group(0)
        if validator is not None and not validator(candidate):
            continue
        replacement = (replacement_template or f"[REDACTED:{detector.upper()}]")
        out.append(
            make_match(
                detector=detector,
                category=category,
                span=(m.start(), m.end()),
                original=candidate,
                replacement=replacement,
                score=score,
            )
        )
    return out


def _luhn_valid(number: str) -> bool:
    digits = [int(c) for c in number if c.isdigit()]
    if not 13 <= len(digits) <= 19:
        return False
    checksum = 0
    parity = len(digits) % 2
    for i, d in enumerate(digits):
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


# ---------------------------------------------------------------------------
# PII detectors
# ---------------------------------------------------------------------------

# US SSN. Excludes obviously-invalid groupings (000, 666, 9XX area; 00 group; 0000 serial).
_SSN_RE = re.compile(
    # Area: 001-665 or 667-899, but never 000 / 666 / 9XX. The (?!000) lookahead
    # excludes the 000 area that the original [0-6]\d{2} alternative permitted.
    r"(?<!\d)"
    r"(?!000|666|9\d{2})"
    r"\d{3}-"
    r"(?!00)\d{2}-"
    r"(?!0000)\d{4}"
    r"(?!\d)"
)
# Stricter card patterns — must look like a real card layout, not a digit run.
# Boundaries are non-digit / non-dash so we don't bleed into adjacent numbers.
_CREDIT_CARD_RE = re.compile(
    r"(?<![\d\-])"
    r"(?:"
    r"\d{4}[ \-]\d{4}[ \-]\d{4}[ \-]\d{1,4}"      # 13-, 14-, 15- or 16-digit, separators required
    r"|\d{4}[ \-]\d{6}[ \-]\d{5}"                  # Amex 15-digit (4-6-5)
    r"|\d{13,19}"                                   # plain unspaced 13-19 digit run
    r")"
    r"(?![\d\-])"
)
_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
# US-format phone (NANP) with optional +1; deliberately conservative to avoid
# eating arbitrary digit runs.
_PHONE_RE = re.compile(
    r"(?<![\w\-])"
    r"(?:\+1[\s.\-]?)?"                                # optional +1
    r"(?:\(\d{3}\)\s?|\d{3}[\s.\-])"                   # NPA: (415) or 415-
    r"\d{3}[\s.\-]?\d{4}"                              # exchange + line
    r"(?!\d)"
)
_IPV4_RE = re.compile(r"(?<!\d)(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?!\d)")


def detect_ssn(text: str) -> list[Match]:
    return _matches_from_pattern(_SSN_RE, text, "ssn", Category.PII)


def detect_credit_card(text: str) -> list[Match]:
    return _matches_from_pattern(
        _CREDIT_CARD_RE,
        text,
        "credit_card",
        Category.PII,
        validator=_luhn_valid,
    )


def detect_email(text: str) -> list[Match]:
    return _matches_from_pattern(_EMAIL_RE, text, "email", Category.PII)


def detect_phone(text: str) -> list[Match]:
    return _matches_from_pattern(_PHONE_RE, text, "phone", Category.PII)


def detect_ipv4(text: str) -> list[Match]:
    return _matches_from_pattern(_IPV4_RE, text, "ipv4", Category.PII)


# ---------------------------------------------------------------------------
# Secret detectors
# ---------------------------------------------------------------------------

_AWS_ACCESS_KEY_RE = re.compile(r"(?<![A-Z0-9])(AKIA|ASIA|AROA|AIDA)[A-Z0-9]{16}(?![A-Z0-9])")
_GITHUB_PAT_RE = re.compile(r"(?<![A-Za-z0-9_])(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,}")
_GITHUB_FINE_PAT_RE = re.compile(r"(?<![A-Za-z0-9_])github_pat_[A-Za-z0-9_]{60,}")
_SLACK_TOKEN_RE = re.compile(r"xox[abprs]-[A-Za-z0-9-]{10,}")
_OPENAI_KEY_RE = re.compile(r"(?<![A-Za-z0-9_])sk-(?:proj-)?[A-Za-z0-9_\-]{20,}")
_ANTHROPIC_KEY_RE = re.compile(r"(?<![A-Za-z0-9_])sk-ant-[A-Za-z0-9_\-]{20,}")
_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b")
_PRIVATE_KEY_RE = re.compile(
    r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----"
)
_GENERIC_HIGH_ENTROPY_RE = re.compile(r"(?<![A-Za-z0-9_])[A-Za-z0-9+/]{40,}={0,2}(?![A-Za-z0-9])")


def detect_aws_access_key(text: str) -> list[Match]:
    return _matches_from_pattern(_AWS_ACCESS_KEY_RE, text, "aws_access_key", Category.SECRETS)


def detect_github_token(text: str) -> list[Match]:
    a = _matches_from_pattern(_GITHUB_PAT_RE, text, "github_token", Category.SECRETS)
    b = _matches_from_pattern(_GITHUB_FINE_PAT_RE, text, "github_token", Category.SECRETS)
    return a + b


def detect_slack_token(text: str) -> list[Match]:
    return _matches_from_pattern(_SLACK_TOKEN_RE, text, "slack_token", Category.SECRETS)


def detect_openai_key(text: str) -> list[Match]:
    return _matches_from_pattern(_OPENAI_KEY_RE, text, "openai_key", Category.SECRETS)


def detect_anthropic_key(text: str) -> list[Match]:
    return _matches_from_pattern(_ANTHROPIC_KEY_RE, text, "anthropic_key", Category.SECRETS)


def detect_jwt(text: str) -> list[Match]:
    return _matches_from_pattern(_JWT_RE, text, "jwt", Category.SECRETS, score=0.7)


def detect_private_key(text: str) -> list[Match]:
    out: list[Match] = []
    for m in _PRIVATE_KEY_RE.finditer(text):
        end = text.find("-----END", m.end())
        end_idx = end + 80 if end != -1 else len(text)
        out.append(
            make_match(
                detector="ssh_private_key",
                category=Category.SECRETS,
                span=(m.start(), end_idx),
                original=text[m.start() : end_idx],
                replacement="[REDACTED:PRIVATE_KEY]",
                score=1.0,
            )
        )
    return out


def detect_generic_high_entropy(text: str) -> list[Match]:
    """Catch base64-ish blobs that are likely tokens. Lower confidence."""
    out: list[Match] = []
    for m in _GENERIC_HIGH_ENTROPY_RE.finditer(text):
        s = m.group(0)
        if _shannon_entropy(s) < 4.0:
            continue
        out.append(
            make_match(
                detector="generic_high_entropy",
                category=Category.SECRETS,
                span=(m.start(), m.end()),
                original=s,
                replacement="[REDACTED:SECRET]",
                score=0.5,
            )
        )
    return out


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    n = len(s)
    return -sum((c / n) * log2(c / n) for c in Counter(s).values())


# ---------------------------------------------------------------------------
# Prompt-injection / jailbreak phrase detector
# ---------------------------------------------------------------------------

DEFAULT_INJECTION_PHRASES: tuple[str, ...] = (
    "ignore previous instructions",
    "ignore all previous instructions",
    "ignore the above",
    "disregard prior instructions",
    "forget your instructions",
    "you are now",
    "act as if",
    "pretend to be",
    "developer mode",
    "you are dan",
    "do anything now",
    "jailbreak",
    "system prompt",
    "reveal your prompt",
    "show me your system prompt",
    "print your instructions",
    "repeat the words above",
    "output the rules",
    "bypass the rules",
    "without restrictions",
)


def make_injection_detector(
    extra_phrases: Iterable[str] = (),
    *,
    name: str = "prompt_injection_phrases",
) -> Detector:
    phrases = list(DEFAULT_INJECTION_PHRASES) + list(extra_phrases)
    if not phrases:
        return Detector(name=name, category=Category.PROMPT_INJECTION, fn=lambda _t: [])
    # One compiled alternation regex; longest first so longer phrases win on
    # overlap. Single linear pass per request beats N text.lower().find() calls.
    phrases.sort(key=len, reverse=True)
    pattern = re.compile("|".join(re.escape(p) for p in phrases), re.IGNORECASE)

    def fn(text: str) -> list[Match]:
        return [
            make_match(
                detector="injection_phrase",
                category=Category.PROMPT_INJECTION,
                span=(m.start(), m.end()),
                original=m.group(0),
                replacement="[REDACTED:INJECTION]",
                score=0.85,
            )
            for m in pattern.finditer(text)
        ]

    return Detector(name=name, category=Category.PROMPT_INJECTION, fn=fn)


# ---------------------------------------------------------------------------
# HTML / script injection (mostly an output-side concern)
# ---------------------------------------------------------------------------

_HTML_DANGEROUS_RE = re.compile(
    r"<\s*(script|iframe|object|embed|svg|style)[\s>]"
    r"|javascript:"
    r"|on(?:load|click|error|mouseover)\s*=",
    re.IGNORECASE,
)


def detect_html_injection(text: str) -> list[Match]:
    out: list[Match] = []
    for m in _HTML_DANGEROUS_RE.finditer(text):
        out.append(
            make_match(
                detector="html_injection",
                category=Category.OTHER,
                span=(m.start(), m.end()),
                original=m.group(0),
                replacement="[REDACTED:HTML]",
                score=0.7,
            )
        )
    return out


# ---------------------------------------------------------------------------
# Unicode confusable / homoglyph density
# ---------------------------------------------------------------------------


def detect_homoglyphs(text: str) -> list[Match]:
    """Flag text with high confusable / non-ASCII letter density.

    Cheap approximation: count letters in non-Latin scripts inside what
    looks like an English-ish run. Used as a signal, not a bright line.
    """
    if not text:
        return []
    letters = [c for c in text if c.isalpha()]
    if len(letters) < 16:
        return []
    suspicious = 0
    for c in letters:
        try:
            name = unicodedata.name(c, "")
        except ValueError:
            continue
        if "CYRILLIC" in name or "GREEK" in name or "MATHEMATICAL" in name:
            suspicious += 1
    ratio = suspicious / max(1, len(letters))
    if ratio < 0.15:
        return []
    return [
        make_match(
            detector="homoglyphs",
            category=Category.OTHER,
            span=(0, len(text)),
            original=text[:64],
            replacement=None,
            score=min(1.0, ratio * 3),
        )
    ]


# ---------------------------------------------------------------------------
# Default registry
# ---------------------------------------------------------------------------


def default_registry(*, injection_phrases: Iterable[str] = ()) -> DetectorRegistry:
    reg = DetectorRegistry()
    reg.add(Detector("ssn", Category.PII, detect_ssn))
    reg.add(Detector("credit_card", Category.PII, detect_credit_card))
    reg.add(Detector("email", Category.PII, detect_email))
    reg.add(Detector("phone", Category.PII, detect_phone))
    reg.add(Detector("ipv4", Category.PII, detect_ipv4, score=0.5))
    reg.add(Detector("aws_access_key", Category.SECRETS, detect_aws_access_key))
    reg.add(Detector("github_token", Category.SECRETS, detect_github_token))
    reg.add(Detector("slack_token", Category.SECRETS, detect_slack_token))
    reg.add(Detector("openai_key", Category.SECRETS, detect_openai_key))
    reg.add(Detector("anthropic_key", Category.SECRETS, detect_anthropic_key))
    reg.add(Detector("jwt", Category.SECRETS, detect_jwt, score=0.7))
    reg.add(Detector("ssh_private_key", Category.SECRETS, detect_private_key))
    reg.add(Detector("generic_high_entropy", Category.SECRETS, detect_generic_high_entropy, score=0.4))
    reg.add(make_injection_detector(injection_phrases))
    reg.add(Detector("html_injection", Category.OTHER, detect_html_injection, score=0.7))
    reg.add(Detector("homoglyphs", Category.OTHER, detect_homoglyphs, score=0.6))
    return reg


__all__ = [
    "DEFAULT_INJECTION_PHRASES",
    "Detector",
    "DetectorRegistry",
    "default_registry",
    "detect_anthropic_key",
    "detect_aws_access_key",
    "detect_credit_card",
    "detect_email",
    "detect_generic_high_entropy",
    "detect_github_token",
    "detect_homoglyphs",
    "detect_html_injection",
    "detect_ipv4",
    "detect_jwt",
    "detect_openai_key",
    "detect_phone",
    "detect_private_key",
    "detect_slack_token",
    "detect_ssn",
    "make_injection_detector",
]
