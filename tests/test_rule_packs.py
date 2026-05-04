"""Rule pack composition tests."""

from __future__ import annotations

from prompt_protector import (
    NSFW,
    OWASP_LLM_TOP10,
    PII,
    PROMPT_INJECTION,
    SECRETS,
    Rule,
)
from prompt_protector.rule_packs import all_packs


def test_packs_iterable_and_typed():
    for pack in (PII, SECRETS, PROMPT_INJECTION, NSFW, OWASP_LLM_TOP10):
        rules = list(pack)
        assert rules
        for r in rules:
            assert isinstance(r, Rule)
            assert r.id and r.text


def test_compose_packs_into_output_rules():
    rules = [*PII, *SECRETS, Rule("custom.no_pirate", "Don't talk like a pirate.")]
    ids = [r.id for r in rules]
    assert "pii.no_ssn" in ids
    assert "secrets.no_api_keys" in ids
    assert "custom.no_pirate" in ids


def test_no_duplicate_ids_across_packs():
    seen: set[str] = set()
    for pack in all_packs().values():
        for r in pack:
            assert r.id not in seen, f"duplicate rule id: {r.id}"
            seen.add(r.id)


def test_with_extra_returns_new_pack():
    extra = [Rule("pii.no_drivers_license", "No driver's license numbers.")]
    extended = PII.with_extra(extra)
    assert len(extended) == len(PII) + 1
    assert extended is not PII  # immutable
