"""Ollama-backed local LLM auditor.

Talks to a local Ollama server (default ``http://localhost:11434``). Any
model the user has pulled is fair game (``llama-guard3``, ``granite3-
guardian``, custom). Network-local only — no internet egress.
"""

from __future__ import annotations

from typing import Any

from .._json import parse_json_object
from ..backends.base import MissingDependencyError
from ..prompts import JSON_RESPONSE_FORMAT
from ..types import AuditPrompt, RawJudgement


class OllamaAuditor:
    name = "ollama"

    def __init__(
        self,
        model: str,
        *,
        host: str = "http://localhost:11434",
        timeout_s: float = 30.0,
        client: Any = None,
        options: dict | None = None,
    ) -> None:
        self.model = model
        self._host = host.rstrip("/")
        self._timeout_s = timeout_s
        self._options = options or {"temperature": 0.0}
        if client is not None:
            self._client = client
        else:
            try:
                import httpx  # type: ignore
            except ImportError as exc:  # pragma: no cover
                raise MissingDependencyError("OllamaAuditor", "ollama", "httpx") from exc
            self._client = httpx.AsyncClient(timeout=timeout_s)

    async def judge(self, prompt: AuditPrompt) -> RawJudgement:
        system = "\n".join(
            [
                prompt.system_instructions,
                JSON_RESPONSE_FORMAT,
                f"The rule is: {prompt.rule}",
            ]
        )
        body = {
            "model": self.model,
            "stream": False,
            "format": "json",
            "options": self._options,
            "messages": [
                {"role": "system", "content": system},
                *[{"role": t.role, "content": t.content} for t in prompt.history],
                {"role": "user", "content": f"Text to audit:\n{prompt.text}"},
            ],
        }
        resp = await self._client.post(f"{self._host}/api/chat", json=body)
        resp.raise_for_status()
        payload = resp.json()
        content = payload.get("message", {}).get("content") or payload.get("response") or ""
        data = parse_json_object(content)
        passed = bool(data.get("pass", False))
        rationale = str(data.get("rationale") or "")
        try:
            score = float(data.get("score", 0.0 if passed else 1.0))
        except (TypeError, ValueError):
            score = 0.0 if passed else 1.0
        score = max(0.0, min(1.0, score))
        return RawJudgement(passed=passed, rationale=rationale, score=score, raw_response=payload)


__all__ = ["OllamaAuditor"]
