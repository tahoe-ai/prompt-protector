"""Ollama auditor tests with a stub HTTP client (no real Ollama)."""

from __future__ import annotations

import pytest


@pytest.mark.asyncio
async def test_ollama_judge_with_stub_client():
    from prompt_protector.local.ollama_backend import OllamaAuditor
    from prompt_protector.types import AuditPrompt

    class StubResp:
        status_code = 200

        def raise_for_status(self):
            pass

        def json(self):
            return {"message": {"content": '{"pass": false, "rationale": "bad", "score": 0.95}'}}

    class StubClient:
        def __init__(self):
            self.calls = []

        async def post(self, url, json):
            self.calls.append((url, json))
            return StubResp()

    auditor = OllamaAuditor("llama-guard3", client=StubClient())
    j = await auditor.judge(AuditPrompt(text="bad text", rule="no bad text", system_instructions="audit"))
    assert j.passed is False
    assert j.score == pytest.approx(0.95, abs=0.01)
