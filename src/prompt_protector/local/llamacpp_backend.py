"""llama.cpp local LLM auditor (in-process via llama-cpp-python)."""

from __future__ import annotations

import asyncio
from typing import Any

from .._json import parse_json_object
from ..backends.base import MissingDependencyError
from ..prompts import JSON_RESPONSE_FORMAT
from ..types import AuditPrompt, RawJudgement


class LlamaCppAuditor:
    name = "llamacpp"

    def __init__(
        self,
        model_path: str,
        *,
        n_ctx: int = 4096,
        max_tokens: int = 256,
        temperature: float = 0.0,
        llm: Any = None,
    ) -> None:
        self.model = model_path
        self._max_tokens = max_tokens
        self._temperature = temperature
        if llm is not None:
            self._llm = llm
            return
        try:
            from llama_cpp import Llama  # type: ignore
        except ImportError as exc:  # pragma: no cover
            raise MissingDependencyError("LlamaCppAuditor", "llamacpp", "llama-cpp-python") from exc
        self._llm = Llama(model_path=model_path, n_ctx=n_ctx, verbose=False)

    async def judge(self, prompt: AuditPrompt) -> RawJudgement:
        return await asyncio.to_thread(self._judge_sync, prompt)

    def _judge_sync(self, prompt: AuditPrompt) -> RawJudgement:
        system = "\n".join(
            [
                prompt.system_instructions,
                JSON_RESPONSE_FORMAT,
                f"The rule is: {prompt.rule}",
            ]
        )
        messages = [
            {"role": "system", "content": system},
            *[{"role": t.role, "content": t.content} for t in prompt.history],
            {"role": "user", "content": f"Text to audit:\n{prompt.text}"},
        ]
        resp = self._llm.create_chat_completion(
            messages=messages,
            max_tokens=self._max_tokens,
            temperature=self._temperature,
            response_format={"type": "json_object"},
        )
        content = resp["choices"][0]["message"]["content"]
        data = parse_json_object(content)
        passed = bool(data.get("pass", False))
        rationale = str(data.get("rationale") or "")
        try:
            score = float(data.get("score", 0.0 if passed else 1.0))
        except (TypeError, ValueError):
            score = 0.0 if passed else 1.0
        score = max(0.0, min(1.0, score))
        return RawJudgement(passed=passed, rationale=rationale, score=score, raw_response=resp)


__all__ = ["LlamaCppAuditor"]
