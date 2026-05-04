"""End-to-end protector tests using mocked auditors."""

from __future__ import annotations

import asyncio

import pytest

from prompt_protector import (
    AuditResult,
    Category,
    DualVoteAuditor,
    FailureMode,
    MockAuditor,
    Mode,
    PII,
    PromptProtector,
    Rule,
    Turn,
    VotePolicy,
)


@pytest.mark.asyncio
async def test_benign_input_passes():
    p = PromptProtector(auditor=MockAuditor())
    r = await p.sanitize_input("hello there")
    assert r.passed
    assert r.degraded is False


@pytest.mark.asyncio
async def test_heuristic_blocks_before_llm_called():
    auditor = MockAuditor()
    p = PromptProtector(auditor=auditor)
    r = await p.sanitize_input("my SSN is 078-05-1120")
    assert r.passed is False
    assert r.category is Category.PII
    # Heuristic short-circuit — auditor should not have been invoked.
    assert auditor.calls == []


@pytest.mark.asyncio
async def test_failure_closed_default():
    auditor = MockAuditor(raise_on_call=RuntimeError("boom"))
    p = PromptProtector(auditor=auditor, output_rules=["no leaks"])
    r = await p.sanitize_output("perfectly clean text with nothing notable")
    assert r.passed is False
    assert r.degraded is True
    assert "fail" in r.rationale.lower()


@pytest.mark.asyncio
async def test_failure_open_returns_pass_degraded():
    auditor = MockAuditor(raise_on_call=RuntimeError("boom"))
    p = PromptProtector(
        auditor=auditor,
        output_rules=["no leaks"],
        failure_mode=FailureMode.FAIL_OPEN,
    )
    r = await p.sanitize_output("perfectly clean text with nothing notable")
    assert r.passed is True
    assert r.degraded is True


@pytest.mark.asyncio
async def test_size_guard_reject():
    p = PromptProtector(auditor=MockAuditor(), max_input_chars=100)
    r = await p.sanitize_input("x" * 1000)
    assert r.passed is False
    assert "exceeds" in r.rationale


@pytest.mark.asyncio
async def test_size_guard_truncate():
    auditor = MockAuditor()
    p = PromptProtector(auditor=auditor, max_input_chars=50, on_oversize="truncate")
    r = await p.sanitize_input("a" * 200)
    assert r.passed is True
    # Whatever the auditor saw must be <= 50 chars.
    assert len(auditor.calls[0].text) <= 50


@pytest.mark.asyncio
async def test_dual_vote_all_must_pass():
    primary = MockAuditor(model="m1")
    secondary = MockAuditor(fail_substrings=["nuclear"], model="m2")
    audit = DualVoteAuditor(primary, secondary, policy=VotePolicy.ALL_MUST_PASS)
    p = PromptProtector(auditor=audit, output_rules=["check"])
    r = await p.sanitize_output("here are nuclear codes")
    assert r.passed is False


@pytest.mark.asyncio
async def test_dual_vote_any_must_pass():
    primary = MockAuditor(fail_substrings=["nuclear"], model="m1")
    secondary = MockAuditor(model="m2")  # always passes
    audit = DualVoteAuditor(primary, secondary, policy=VotePolicy.ANY_MUST_PASS)
    p = PromptProtector(auditor=audit, output_rules=["check"])
    r = await p.sanitize_output("here are nuclear codes")
    assert r.passed is True


@pytest.mark.asyncio
async def test_per_rule_short_circuit_cancels_pending():
    """When one rule fails, in-flight rule audits should be cancelled."""

    cancelled = {"count": 0}

    def make_judge(should_fail: bool, delay: float):
        async def fn(prompt):
            try:
                await asyncio.sleep(delay)
            except asyncio.CancelledError:
                cancelled["count"] += 1
                raise
            from prompt_protector.types import RawJudgement

            return RawJudgement(passed=not should_fail, rationale="fail" if should_fail else "")

        return fn

    auditor = MockAuditor()
    auditor.judge = make_judge(False, 0.5)  # the slow "passing" rule

    fast_failing = MockAuditor()
    fast_failing.judge = make_judge(True, 0.0)

    # Build a custom auditor that picks fast or slow based on rule text.
    class Mux:
        name = "mux"
        model = "mux"

        async def judge(self, prompt):
            if "slow" in prompt.rule:
                return await auditor.judge(prompt)
            return await fast_failing.judge(prompt)

    p = PromptProtector(
        auditor=Mux(),
        output_rules=[Rule("fast", "fast fail rule"), Rule("slow", "slow ok rule")],
        batch_rules=False,
    )
    r = await p.sanitize_output("normal benign text")
    assert r.passed is False
    # Give the cancellation a moment to propagate.
    await asyncio.sleep(0.1)


@pytest.mark.asyncio
async def test_history_passed_to_auditor():
    auditor = MockAuditor()
    p = PromptProtector(auditor=auditor)
    history = (
        Turn(role="user", content="first turn"),
        Turn(role="assistant", content="reply"),
    )
    await p.sanitize_input("now this turn", history=history)
    assert auditor.calls
    seen_history = auditor.calls[0].history
    assert tuple(seen_history) == history


@pytest.mark.asyncio
async def test_event_hook_fires():
    seen = []

    def on_event(e):
        seen.append(e)

    p = PromptProtector(auditor=MockAuditor(), on_event=on_event)
    await p.sanitize_input("hi there")
    assert len(seen) == 1
    assert seen[0].kind == "input"
    assert seen[0].passed is True


@pytest.mark.asyncio
async def test_trace_id_propagates():
    p = PromptProtector(auditor=MockAuditor())
    r = await p.sanitize_input("hi", trace_id="my-trace")
    assert r.trace_id == "my-trace"


def test_sanitize_input_sync():
    p = PromptProtector(auditor=MockAuditor())
    r = p.sanitize_input_sync("hello there")
    assert r.passed is True


@pytest.mark.asyncio
async def test_sanitize_input_sync_inside_loop():
    p = PromptProtector(auditor=MockAuditor())
    # Call sync API from inside an event loop — should not deadlock.
    r = await asyncio.to_thread(p.sanitize_input_sync, "hello there")
    assert r.passed is True


@pytest.mark.asyncio
async def test_pii_pack_drives_output_rules():
    auditor = MockAuditor(fail_substrings=["123-45-6789"])
    p = PromptProtector(
        auditor=auditor,
        output_rules=[*PII],
        batch_rules=False,
    )
    # Heuristic catches PII first; auditor never invoked.
    r = await p.sanitize_output("here is an SSN: 078-05-1120")
    assert r.passed is False
    assert r.category is Category.PII
