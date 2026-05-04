"""Redaction round-trip and dedup tests."""

from __future__ import annotations

from prompt_protector import default_registry
from prompt_protector.redaction import RedactionStyle, redact, restore


def test_redact_labeled():
    r = redact("send 4111 1111 1111 1111 and SSN 078-05-1120 to jane@example.com")
    assert "[REDACTED:CREDIT_CARD]" in r.redacted_text
    assert "[REDACTED:SSN]" in r.redacted_text
    assert "[REDACTED:EMAIL]" in r.redacted_text
    rescan = default_registry().scan(r.redacted_text)
    # After redaction, the redacted text should have no surviving PII matches.
    assert not [m for m in rescan if m.detector in {"ssn", "credit_card", "email"}]


def test_redact_numbered_round_trip():
    text = "first jane@example.com then bob@example.com again jane@example.com"
    r = redact(text, style=RedactionStyle.NUMBERED)
    assert "[EMAIL_1]" in r.redacted_text
    assert "[EMAIL_2]" in r.redacted_text
    assert "[EMAIL_3]" in r.redacted_text
    restored = restore(r.redacted_text, r.mapping)
    assert restored == text


def test_redact_overlapping_dedup():
    # SSN and phone could both match 078-05-1120 — dedup should pick one.
    r = redact("number 078-05-1120 here")
    assert r.redacted_text.count("[REDACTED:") == 1


def test_redact_no_matches_returns_unchanged():
    text = "nothing sensitive in here at all"
    r = redact(text)
    assert r.redacted_text == text
    assert r.matches == []
    assert r.mapping == []
