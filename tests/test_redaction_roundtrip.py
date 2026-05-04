"""Reversible-redaction vault round-trip."""

from __future__ import annotations

import pytest

from prompt_protector import MockAuditor, PromptProtector
from prompt_protector.local.base import LocalRedactionResult
from prompt_protector.local.vault import InMemoryVault


class StubReversibleRedactor:
    name = "stub_reversible"

    def redact(self, text: str) -> LocalRedactionResult:
        out = text
        mapping: list[tuple[str, str]] = []
        if "Jane Smith" in out:
            out = out.replace("Jane Smith", "[PERSON_1]", 1)
            mapping.append(("[PERSON_1]", "Jane Smith"))
        return LocalRedactionResult(redacted_text=out, mapping=mapping)


@pytest.mark.asyncio
async def test_unredact_round_trip():
    vault = InMemoryVault()
    p = PromptProtector(
        auditor=MockAuditor(),
        pre_redactors=[StubReversibleRedactor()],
        vault=vault,
        forward_redacted=True,
    )
    r = await p.sanitize_input("Hello, my name is Jane Smith")
    assert r.passed is True
    assert r.redacted_text and "[PERSON_1]" in r.redacted_text
    assert r.vault_id is not None

    downstream_response = "Welcome [PERSON_1], your appointment is confirmed."
    restored = p.unredact(downstream_response, r.vault_id)
    assert restored == "Welcome Jane Smith, your appointment is confirmed."


def test_vault_ttl_expiry(monkeypatch):
    import time as t

    real_time = t.time
    v = InMemoryVault(ttl_seconds=1.0)
    v.put("abc", [("[PERSON_1]", "Jane")])
    fake_now = real_time() + 5
    monkeypatch.setattr(t, "time", lambda: fake_now)
    assert v.get("abc") == []
