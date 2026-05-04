"""OpenAI backend using the per-instance AsyncOpenAI client.

Never mutates ``openai.api_key`` (process-global) — each backend owns its
own client. Uses ``response_format={"type": "json_object"}`` so the model
sticks to JSON output reliably.
"""

from __future__ import annotations

import os
from typing import Any

from .._json import parse_json_object
from ..prompts import (
    BATCHED_JSON_RESPONSE_FORMAT,
    BATCHED_OUTPUT_AUDITOR_SYSTEM,
    JSON_RESPONSE_FORMAT,
)
from ..types import AuditPrompt, RawJudgement
from .base import MissingDependencyError

try:
    from openai import AsyncOpenAI  # type: ignore
except ImportError:  # pragma: no cover
    AsyncOpenAI = None  # type: ignore


class OpenAIAuditor:
    name = "openai"

    def __init__(
        self,
        api_key: str | None = None,
        *,
        model: str = "gpt-4o-mini",
        temperature: float = 0.0,
        max_tokens: int = 512,
        client: Any = None,
        base_url: str | None = None,
    ) -> None:
        if AsyncOpenAI is None:
            raise MissingDependencyError("OpenAIAuditor", "openai", "openai")
        self.model = model
        self._temperature = temperature
        self._max_tokens = max_tokens
        if client is not None:
            self._client = client
        else:
            self._client = AsyncOpenAI(
                api_key=api_key or os.getenv("OPENAI_API_KEY"),
                base_url=base_url,
            )

    async def judge(self, prompt: AuditPrompt) -> RawJudgement:
        messages = self._build_messages(
            system=prompt.system_instructions,
            history=prompt.history,
            rule=prompt.rule,
            text=prompt.text,
        )
        resp = await self._client.chat.completions.create(
            model=self.model,
            messages=messages,
            temperature=self._temperature,
            max_tokens=self._max_tokens,
            response_format={"type": "json_object"},
        )
        content = resp.choices[0].message.content or ""
        data = parse_json_object(content)
        return _judgement_from_dict(data, raw=resp)

    async def judge_batch(
        self,
        text: str,
        rules: list[str],
        system_instructions: str,
    ) -> list[RawJudgement]:
        numbered = "\n".join(f"{i}. {r}" for i, r in enumerate(rules))
        messages = [
            {"role": "system", "content": system_instructions or BATCHED_OUTPUT_AUDITOR_SYSTEM},
            {"role": "system", "content": BATCHED_JSON_RESPONSE_FORMAT},
            {"role": "system", "content": f"Rules:\n{numbered}"},
            {"role": "user", "content": f"Text to audit:\n{text}"},
        ]
        resp = await self._client.chat.completions.create(
            model=self.model,
            messages=messages,
            temperature=self._temperature,
            max_tokens=self._max_tokens,
            response_format={"type": "json_object"},
        )
        content = resp.choices[0].message.content or ""
        data = parse_json_object(content)
        verdicts = data.get("verdicts") or []
        out: list[RawJudgement] = []
        for i, _ in enumerate(rules):
            entry = verdicts[i] if i < len(verdicts) else {"pass": False, "rationale": "missing verdict"}
            out.append(_judgement_from_dict(entry, raw=resp))
        return out

    @staticmethod
    def _build_messages(
        *,
        system: str,
        history: tuple,
        rule: str,
        text: str,
    ) -> list[dict[str, str]]:
        messages: list[dict[str, str]] = [
            {"role": "system", "content": system},
            {"role": "system", "content": JSON_RESPONSE_FORMAT},
        ]
        for turn in history:
            messages.append({"role": turn.role, "content": turn.content})
        messages.append({"role": "system", "content": f"The rule is: {rule}"})
        messages.append({"role": "user", "content": f"Text to audit:\n{text}"})
        return messages


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


__all__ = ["OpenAIAuditor"]
