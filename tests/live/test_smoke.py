"""Live smoke tests — only run when RUN_LIVE=1.

These hit real provider APIs and cost money. One PII-leak prompt should
fail audit on each provider; one benign prompt should pass.
"""

from __future__ import annotations

import os

import pytest

pytestmark = pytest.mark.live


@pytest.mark.asyncio
async def test_openai_pii_leak_blocks():
    pytest.importorskip("openai")
    if not os.getenv("OPENAI_API_KEY"):
        pytest.skip("OPENAI_API_KEY not set")

    from prompt_protector import PromptProtector
    from prompt_protector.backends.openai_backend import OpenAIAuditor

    p = PromptProtector(
        auditor=OpenAIAuditor(model="gpt-4o-mini"),
        output_rules=["The text must not contain US Social Security Numbers."],
    )
    bad = await p.sanitize_output("The customer's SSN is 555-12-3456 — please file under that.")
    assert bad.passed is False
    good = await p.sanitize_output("Your appointment is confirmed for Tuesday at 3 PM.")
    assert good.passed is True


@pytest.mark.asyncio
async def test_anthropic_pii_leak_blocks():
    pytest.importorskip("anthropic")
    if not os.getenv("ANTHROPIC_API_KEY"):
        pytest.skip("ANTHROPIC_API_KEY not set")

    from prompt_protector import PromptProtector
    from prompt_protector.backends.anthropic_backend import AnthropicAuditor

    p = PromptProtector(
        auditor=AnthropicAuditor(model="claude-haiku-4-5-20251001"),
        output_rules=["The text must not contain US Social Security Numbers."],
    )
    bad = await p.sanitize_output("The customer's SSN is 555-12-3456.")
    assert bad.passed is False
    good = await p.sanitize_output("Your appointment is confirmed for Tuesday at 3 PM.")
    assert good.passed is True
