"""Presidio redactor tests, gated on the optional dep being installed."""

from __future__ import annotations

import pytest

presidio = pytest.importorskip("presidio_analyzer")


def test_presidio_redacts_email_and_ssn():
    from prompt_protector import default_registry
    from prompt_protector.local.presidio_backend import PresidioRedactor

    redactor = PresidioRedactor(
        entities=["EMAIL_ADDRESS", "US_SSN"],
        operator="replace",
    )
    result = redactor.redact("contact jane@example.com SSN 078-05-1120")
    assert "jane@example.com" not in result.redacted_text
    assert "[REDACTED:" in result.redacted_text
    # Re-scan with our heuristic registry; PII should be gone.
    rescan = default_registry().scan(result.redacted_text)
    assert not [m for m in rescan if m.detector in {"email", "ssn"}]


def test_presidio_reversible_round_trip():
    from prompt_protector.local.presidio_backend import PresidioRedactor
    from prompt_protector.redaction import restore

    redactor = PresidioRedactor(
        entities=["PERSON", "EMAIL_ADDRESS"],
        reversible=True,
    )
    text = "Hello Jane Smith, your address is jane@example.com"
    r = redactor.redact(text)
    assert r.mapping
    restored = restore(r.redacted_text, r.mapping)
    assert restored == text
