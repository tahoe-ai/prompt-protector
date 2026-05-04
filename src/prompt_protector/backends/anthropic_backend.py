"""Anthropic backend using AsyncAnthropic.

Anthropic has no JSON-mode flag like OpenAI's, so we lean on a strict system
prompt + a JSON-prefilled assistant turn (Anthropic's recommended pattern
for structured output).
"""

from __future__ import annotations

import os
from typing import Any, Optional

from .._json import parse_json_object
from ..prompts import (
    BATCHED_JSON_RESPONSE_FORMAT,
    BATCHED_OUTPUT_AUDITOR_SYSTEM,
    JSON_RESPONSE_FORMAT,
)
from ..types import AuditPrompt, RawJudgement
from .base import MissingDependencyError

try:
    from anthropic import AsyncAnthropic  # type: ignore
except ImportError:  # pragma: no cover
    AsyncAnthropic = None  # type: ignore


class AnthropicAuditor:
    name = "anthropic"

    def __init__(
        self,
        api_key: Optional[str] = None,
        *,
        model: str = "claude-haiku-4-5-20251001",
        max_tokens: int = 512,
        temperature: float = 0.0,
        client: Any = None,
    ) -> None:
        if AsyncAnthropic is None:
            raise MissingDependencyError("AnthropicAuditor", "anthropic", "anthropic")
        self.model = model
        self._max_tokens = max_tokens
        self._temperature = temperature
        self._client = client or AsyncAnthropic(
            api_key=api_key or os.getenv("ANTHROPIC_API_KEY"),
        )

    async def judge(self, prompt: AuditPrompt) -> RawJudgement:
        system = "\n".join(
            [
                prompt.system_instructions,
                JSON_RESPONSE_FORMAT,
                f"The rule is: {prompt.rule}",
            ]
        )
        messages: list[dict[str, str]] = []
        for turn in prompt.history:
            role = "assistant" if turn.role == "assistant" else "user"
            messages.append({"role": role, "content": turn.content})
        messages.append({"role": "user", "content": f"Text to audit:\n{prompt.text}"})
        # Prefill assistant with "{" so Claude commits to JSON structure.
        messages.append({"role": "assistant", "content": "{"})

        resp = await self._client.messages.create(
            model=self.model,
            max_tokens=self._max_tokens,
            temperature=self._temperature,
            system=system,
            messages=messages,
        )
        text = "{" + _extract_text(resp)
        data = parse_json_object(text)
        return _judgement_from_dict(data, raw=resp)

    async def judge_batch(
        self,
        text: str,
        rules: list[str],
        system_instructions: str,
    ) -> list[RawJudgement]:
        numbered = "\n".join(f"{i}. {r}" for i, r in enumerate(rules))
        system = "\n".join(
            [
                system_instructions or BATCHED_OUTPUT_AUDITOR_SYSTEM,
                BATCHED_JSON_RESPONSE_FORMAT,
                f"Rules:\n{numbered}",
            ]
        )
        resp = await self._client.messages.create(
            model=self.model,
            max_tokens=self._max_tokens,
            temperature=self._temperature,
            system=system,
            messages=[
                {"role": "user", "content": f"Text to audit:\n{text}"},
                {"role": "assistant", "content": "{"},
            ],
        )
        body = "{" + _extract_text(resp)
        data = parse_json_object(body)
        verdicts = data.get("verdicts") or []
        out: list[RawJudgement] = []
        for i, _ in enumerate(rules):
            entry = verdicts[i] if i < len(verdicts) else {"pass": False, "rationale": "missing verdict"}
            out.append(_judgement_from_dict(entry, raw=resp))
        return out


def _extract_text(resp: Any) -> str:
    blocks = getattr(resp, "content", None) or []
    parts: list[str] = []
    for block in blocks:
        text = getattr(block, "text", None)
        if isinstance(text, str):
            parts.append(text)
    return "".join(parts)


def _judgement_from_dict(data: dict, *, raw: Any) -> RawJudgement:
    passed = bool(data.get("pass", False))
    rationale = str(data.get("rationale") or "")
    score_raw = data.get("score", 0.0 if passed else 1.0)
    try:
        score = float(score_raw)
    except (TypeError, ValueError):
        score = 0.0 if passed else 1.0
    score = max(0.0, min(1.0, score))
    return RawJudgement(passed=passed, rationale=rationale, score=score, raw_response=raw)


__all__ = ["AnthropicAuditor"]
