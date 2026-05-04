"""Cache + protector integration tests."""

from __future__ import annotations

import pytest

from prompt_protector import MockAuditor, PromptProtector
from prompt_protector.cache import InMemoryLRUCache


@pytest.mark.asyncio
async def test_lru_eviction():
    c = InMemoryLRUCache(max_entries=2, ttl_seconds=60)
    from prompt_protector.types import AuditResult

    await c.set("a", AuditResult(passed=True))
    await c.set("b", AuditResult(passed=True))
    await c.set("c", AuditResult(passed=True))
    assert len(c) == 2
    assert await c.get("a") is None
    assert (await c.get("b")) is not None
    assert (await c.get("c")) is not None


@pytest.mark.asyncio
async def test_ttl_expiry(monkeypatch):
    import time

    real_time = time.time
    c = InMemoryLRUCache(max_entries=10, ttl_seconds=1)
    from prompt_protector.types import AuditResult

    await c.set("a", AuditResult(passed=True))
    fake_now = real_time() + 5
    monkeypatch.setattr(time, "time", lambda: fake_now)
    assert await c.get("a") is None


@pytest.mark.asyncio
async def test_cache_short_circuits_auditor():
    auditor = MockAuditor()
    cache = InMemoryLRUCache()
    p = PromptProtector(auditor=auditor, output_rules=["rule"], cache=cache)
    await p.sanitize_output("clean text that should be cached")
    n_first = len(auditor.calls) + len(auditor.batch_calls)
    await p.sanitize_output("clean text that should be cached")
    n_second = len(auditor.calls) + len(auditor.batch_calls)
    assert n_first == n_second, "cached call should not invoke the auditor"
