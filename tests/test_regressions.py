"""Regression tests for the post-review fixes.

Each test pins a specific bug or behavior the reviewer flagged so the
fixes don't quietly regress.
"""

from __future__ import annotations

import asyncio

import pytest

from prompt_protector import (
    AuditResult,
    Category,
    FailureMode,
    MockAuditor,
    PromptProtector,
    Rule,
)
from prompt_protector.cache import (
    InMemoryLRUCache,
    _deserialize_result,
    _serialize_result,
)
from prompt_protector.heuristics import detect_credit_card, detect_ssn
from prompt_protector.redaction import RedactionStyle, redact, restore
from prompt_protector.types import Match, StageVerdict


# ---------------------------------------------------------------------------
# Bug 1 — CancelledError must propagate, not be swallowed into AuditResult.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_cancellation_propagates_through_protector():
    class HangingAuditor:
        name = "hanging"
        model = "h"

        async def judge(self, prompt):
            await asyncio.sleep(60)

    protector = PromptProtector(auditor=HangingAuditor())

    task = asyncio.create_task(protector.sanitize_input("hi"))
    await asyncio.sleep(0.01)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task


# ---------------------------------------------------------------------------
# Bug 2 / Speed — InMemoryLRUCache uses threading.Lock, safe across loops.
# ---------------------------------------------------------------------------


def test_cache_works_across_loops():
    cache = InMemoryLRUCache(max_entries=4, ttl_seconds=60)

    async def write():
        await cache.set("k", AuditResult(passed=True, provider="x"))

    async def read():
        return await cache.get("k")

    asyncio.run(write())
    got = asyncio.run(read())
    assert got is not None and got.passed


# ---------------------------------------------------------------------------
# Bug 3 — _run_sync bounded wait.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_sync_wrapper_inside_loop_does_not_deadlock():
    p = PromptProtector(auditor=MockAuditor())
    r = await asyncio.to_thread(p.sanitize_input_sync, "hello there")
    assert r.passed is True


# ---------------------------------------------------------------------------
# Bug 4 — RedisCache JSON round-trip preserves typed structure.
# ---------------------------------------------------------------------------


def test_redis_serdes_round_trip():
    original = AuditResult(
        passed=False,
        score=0.7,
        category=Category.PII,
        rationale="ssn",
        rule_id="pii.no_ssn",
        matches=[Match("ssn", Category.PII, (0, 11), "078-05-1120", "[REDACTED:SSN]", 0.95)],
        provider="mock",
        model="m1",
        latency_ms=12,
        verdicts=[StageVerdict("heuristics", False, Category.PII, "ssn", 0.95, 1)],
    )
    blob = _serialize_result(original)
    restored = _deserialize_result(blob)
    assert restored.category is Category.PII
    assert restored.matches[0].category is Category.PII
    assert restored.matches[0].span == (0, 11)
    assert restored.verdicts[0].stage == "heuristics"


# ---------------------------------------------------------------------------
# Bug 5 — cache.get errors must not break a request.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_cache_get_failure_does_not_break_request():
    class BrokenCache:
        async def get(self, key):
            raise RuntimeError("redis down")

        async def set(self, key, value):
            return None

    p = PromptProtector(
        auditor=MockAuditor(),
        output_rules=["check"],
        cache=BrokenCache(),
    )
    r = await p.sanitize_output("benign text that does not match anything")
    assert r.passed is True


# ---------------------------------------------------------------------------
# Bug 7/8 — SSN excludes 000-area; credit-card 13/14-digit unspaced runs.
# ---------------------------------------------------------------------------


def test_ssn_000_area_rejected():
    assert detect_ssn("000-12-3456") == []


def test_credit_card_13_digit_unspaced():
    # Diners Club test number: 30569309025904 (Luhn-valid 14-digit)
    assert detect_credit_card("card 30569309025904 here")
    # 13-digit Visa: 4222222222222 — Luhn-valid
    assert detect_credit_card("legacy card 4222222222222 here")


# ---------------------------------------------------------------------------
# Bug 12 — restore must not collide on placeholder prefixes.
# ---------------------------------------------------------------------------


def test_restore_handles_prefix_collision():
    text = "11 emails: " + " ".join(f"x{i}@example.com" for i in range(1, 12))
    r = redact(text, style=RedactionStyle.NUMBERED)
    # Sanity: there should be 11 numbered placeholders.
    assert "[EMAIL_11]" in r.redacted_text
    assert "[EMAIL_1]" in r.redacted_text
    # Round-trip must restore every original exactly.
    assert restore(r.redacted_text, r.mapping) == text


# ---------------------------------------------------------------------------
# Bug 14 — when most rules judge cleanly but one rule's judge crashes,
# the protector returns passed=True with degraded=True (not fail-closed).
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_partial_judge_failure_returns_degraded_pass():
    calls = {"n": 0}

    class FlakyAuditor:
        name = "flaky"
        model = "f"

        async def judge(self, prompt):
            calls["n"] += 1
            if "fail-this-rule" in prompt.rule:
                from prompt_protector._json import JSONParseError

                raise JSONParseError("model returned garbage for this rule")
            from prompt_protector.types import RawJudgement

            return RawJudgement(passed=True, rationale="", score=0.0)

    p = PromptProtector(
        auditor=FlakyAuditor(),
        output_rules=[
            Rule("rule.a", "ordinary rule a"),
            Rule("rule.b", "fail-this-rule b"),
            Rule("rule.c", "ordinary rule c"),
        ],
        batch_rules=False,
        max_retries=0,
    )
    r = await p.sanitize_output("benign content with no heuristic hits")
    assert r.passed is True
    assert r.degraded is True


@pytest.mark.asyncio
async def test_all_rules_failing_falls_closed():
    """If literally every rule judge crashes, fail_closed kicks in."""
    auditor = MockAuditor(raise_on_call=RuntimeError("model down"))
    p = PromptProtector(
        auditor=auditor,
        output_rules=[Rule("a", "rule a"), Rule("b", "rule b")],
        batch_rules=False,
        failure_mode=FailureMode.FAIL_CLOSED,
        max_retries=0,
    )
    r = await p.sanitize_output("benign text")
    assert r.passed is False
    assert r.degraded is True


# ---------------------------------------------------------------------------
# Speed / Bug 6 — cache hit returns stale redacted_text only when the current
# pass actually produced one.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_cache_hit_drops_stale_redacted_text():
    cache = InMemoryLRUCache()
    auditor = MockAuditor()
    p = PromptProtector(auditor=auditor, output_rules=["rule"], cache=cache)
    text = "absolutely benign output, nothing to detect"
    r1 = await p.sanitize_output(text)
    assert r1.redacted_text is None
    r2 = await p.sanitize_output(text)
    assert r2.redacted_text is None  # stale value from any prior request must not bleed in


# ---------------------------------------------------------------------------
# Speed — cache hit short-circuits the auditor (regression of test_cache).
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_cache_hit_does_not_invoke_auditor():
    auditor = MockAuditor()
    cache = InMemoryLRUCache()
    p = PromptProtector(auditor=auditor, output_rules=["rule"], cache=cache)
    await p.sanitize_output("clean text")
    n_first = len(auditor.calls) + len(auditor.batch_calls)
    await p.sanitize_output("clean text")
    n_second = len(auditor.calls) + len(auditor.batch_calls)
    assert n_first == n_second


# ---------------------------------------------------------------------------
# Cleanup — concurrency cap is enforced when many rules.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_concurrency_cap_on_per_rule_fanout():
    in_flight = {"now": 0, "peak": 0}

    class TrackingAuditor:
        name = "track"
        model = "t"

        async def judge(self, prompt):
            in_flight["now"] += 1
            in_flight["peak"] = max(in_flight["peak"], in_flight["now"])
            try:
                await asyncio.sleep(0.01)
            finally:
                in_flight["now"] -= 1
            from prompt_protector.types import RawJudgement

            return RawJudgement(passed=True, rationale="")

    rules = [Rule(f"r{i}", f"rule {i}") for i in range(20)]
    p = PromptProtector(
        auditor=TrackingAuditor(),
        output_rules=rules,
        batch_rules=False,
        max_concurrent_judges=4,
    )
    await p.sanitize_output("benign")
    assert in_flight["peak"] <= 4
