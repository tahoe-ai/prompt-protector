"""Streaming output audit."""

from __future__ import annotations

import pytest

from prompt_protector import MockAuditor, PromptProtector
from prompt_protector.streaming import StreamViolation, sanitize_stream


async def gen_chunks(chunks):
    for c in chunks:
        yield c


@pytest.mark.asyncio
async def test_clean_stream_passes_through():
    p = PromptProtector(auditor=MockAuditor())
    out = []
    async for item in sanitize_stream(p, gen_chunks(["hello ", "world", "!"])):
        out.append(item)
    assert "".join(x for x in out if isinstance(x, str)) == "hello world!"
    assert not any(isinstance(x, StreamViolation) for x in out)


@pytest.mark.asyncio
async def test_heuristic_violation_aborts_stream():
    p = PromptProtector(auditor=MockAuditor())
    chunks = ["nothing yet ", "but here ", "is an SSN 078-05-1120 ", "trailing chunk"]
    saw_violation = False
    delivered = ""
    async for item in sanitize_stream(p, gen_chunks(chunks)):
        if isinstance(item, StreamViolation):
            saw_violation = True
            break
        delivered += item
    assert saw_violation
    assert "trailing chunk" not in delivered
