"""Deterministic mock auditor for tests.

Two construction modes:

1. Pass a callable ``judge_fn(prompt) -> RawJudgement | dict`` for full
   control.
2. Pass ``fail_substrings`` for a quick "judge says fail when this string
   appears in the text" stub.
"""

from __future__ import annotations

from typing import Any, Callable, Optional

from ..types import AuditPrompt, RawJudgement


class MockAuditor:
    name = "mock"

    def __init__(
        self,
        *,
        judge_fn: Optional[Callable[[AuditPrompt], Any]] = None,
        fail_substrings: Optional[list[str]] = None,
        model: str = "mock-1",
        raise_on_call: Optional[BaseException] = None,
        delay_s: float = 0.0,
    ) -> None:
        self.model = model
        self._judge_fn = judge_fn
        self._fail_substrings = [s.lower() for s in (fail_substrings or [])]
        self._raise_on_call = raise_on_call
        self._delay_s = delay_s
        self.calls: list[AuditPrompt] = []
        self.batch_calls: list[tuple[str, list[str]]] = []

    async def judge(self, prompt: AuditPrompt) -> RawJudgement:
        self.calls.append(prompt)
        if self._raise_on_call is not None:
            raise self._raise_on_call
        if self._delay_s:
            import asyncio

            await asyncio.sleep(self._delay_s)
        if self._judge_fn is not None:
            result = self._judge_fn(prompt)
            if isinstance(result, RawJudgement):
                return result
            if isinstance(result, dict):
                return RawJudgement(
                    passed=bool(result.get("pass", False)),
                    rationale=str(result.get("rationale", "")),
                    score=float(result.get("score", 0.0)),
                )
            raise TypeError(f"judge_fn returned unexpected type {type(result)}")
        haystack = (prompt.text or "").lower()
        for needle in self._fail_substrings:
            if needle in haystack:
                return RawJudgement(passed=False, rationale=f"matched {needle!r}", score=1.0)
        return RawJudgement(passed=True, rationale="", score=0.0)

    async def judge_batch(
        self,
        text: str,
        rules: list[str],
        system_instructions: str,
    ) -> list[RawJudgement]:
        self.batch_calls.append((text, list(rules)))
        results: list[RawJudgement] = []
        for rule in rules:
            results.append(
                await self.judge(
                    AuditPrompt(text=text, rule=rule, system_instructions=system_instructions)
                )
            )
        return results


__all__ = ["MockAuditor"]
