"""Mode tests: ENFORCE / SHADOW / SAMPLE."""

from __future__ import annotations

import pytest

from prompt_protector import MockAuditor, Mode, PromptProtector


@pytest.mark.asyncio
async def test_shadow_never_blocks():
    auditor = MockAuditor(fail_substrings=["nuclear"])
    p = PromptProtector(auditor=auditor, output_rules=["rule"], mode=Mode.shadow())
    r = await p.sanitize_output("here are nuclear codes")
    assert r.passed is True
    assert "[shadow]" in r.rationale.lower()


@pytest.mark.asyncio
async def test_sample_p0_skips_audit():
    auditor = MockAuditor(fail_substrings=["nuclear"])
    p = PromptProtector(auditor=auditor, output_rules=["rule"], mode=Mode.sample(0.0))
    for _ in range(5):
        r = await p.sanitize_output("here are nuclear codes")
        assert r.passed is True
    assert auditor.calls == [] and auditor.batch_calls == []


@pytest.mark.asyncio
async def test_sample_p1_always_audits():
    auditor = MockAuditor(fail_substrings=["nuclear"])
    p = PromptProtector(auditor=auditor, output_rules=["rule"], mode=Mode.sample(1.0))
    r = await p.sanitize_output("here are nuclear codes")
    assert r.passed is False


def test_sample_p_out_of_range():
    with pytest.raises(ValueError):
        Mode.sample(1.5)
