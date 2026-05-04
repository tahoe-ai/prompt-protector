"""Composite backends: dual-vote, fallback, etc."""

from __future__ import annotations

import asyncio
import enum

from ..types import AuditPrompt, RawJudgement
from .base import Auditor


class VotePolicy(str, enum.Enum):
    ANY_MUST_PASS = "any_must_pass"  # OR — if either says pass, we pass
    ALL_MUST_PASS = "all_must_pass"  # AND — both must say pass


class DualVoteAuditor:
    """Run two auditors in parallel and combine their verdicts.

    ALL_MUST_PASS is the right default for safety: any auditor saying
    "violation" blocks. ANY_MUST_PASS is permissive — useful when you only
    want the union of fail-modes (e.g. one auditor is provider X,
    the other is a local classifier with low recall).
    """

    name = "dual_vote"

    def __init__(
        self,
        primary: Auditor,
        secondary: Auditor,
        *,
        policy: VotePolicy = VotePolicy.ALL_MUST_PASS,
    ) -> None:
        self._primary = primary
        self._secondary = secondary
        self._policy = policy
        self.model = f"{primary.model}+{secondary.model}"

    async def judge(self, prompt: AuditPrompt) -> RawJudgement:
        a, b = await asyncio.gather(
            self._primary.judge(prompt),
            self._secondary.judge(prompt),
        )
        if self._policy is VotePolicy.ALL_MUST_PASS:
            passed = a.passed and b.passed
        else:
            passed = a.passed or b.passed
        score = max(a.score, b.score) if not passed else min(a.score, b.score)
        rationale = " | ".join(filter(None, [a.rationale, b.rationale]))
        return RawJudgement(
            passed=passed,
            rationale=rationale,
            score=score,
            raw_response={"primary": a.raw_response, "secondary": b.raw_response},
        )


__all__ = ["DualVoteAuditor", "VotePolicy"]
