# `prompt_protector.backends` — cloud and composite auditors

An `Auditor` is anything that can take an `AuditPrompt` and return a
`RawJudgement`. The protector handles policy (timeouts, retries, failure
mode); backends just translate to a provider's message shape and hand
back a structured verdict.

## What's here

| File | Role |
|------|------|
| `base.py` | `Auditor` protocol, `BatchAuditor` (optional N-rule batched verdict), `MissingDependencyError` |
| `openai_backend.py` | `OpenAIAuditor` — `openai.AsyncOpenAI` with `response_format={"type": "json_object"}` |
| `anthropic_backend.py` | `AnthropicAuditor` — `anthropic.AsyncAnthropic` with JSON prefill |
| `composite.py` | `DualVoteAuditor(primary, secondary, policy=ANY|ALL)` for defense in depth |
| `mock.py` | `MockAuditor` — deterministic stub for tests |

Local-model auditors (transformers, ONNX, Ollama, llama.cpp) live in
`../local/`, not here, because they have very different failure modes
(model load, GPU OOM) and dependency surface.

## Using a single backend

```python
from prompt_protector import PromptProtector
from prompt_protector.backends.openai_backend import OpenAIAuditor

p = PromptProtector(auditor=OpenAIAuditor(model="gpt-4o-mini"))
```

## Dual-vote (defense in depth)

```python
from prompt_protector.backends import DualVoteAuditor, VotePolicy
from prompt_protector.backends.openai_backend import OpenAIAuditor
from prompt_protector.backends.anthropic_backend import AnthropicAuditor

audit = DualVoteAuditor(
    OpenAIAuditor(model="gpt-4o-mini"),
    AnthropicAuditor(model="claude-haiku-4-5-20251001"),
    policy=VotePolicy.ALL_MUST_PASS,   # safety default — either says fail, we fail
)
```

`ANY_MUST_PASS` is the OR variant — useful when one judge is a high-recall
local classifier you don't fully trust.

## Writing your own

```python
from prompt_protector.types import AuditPrompt, RawJudgement

class MyAuditor:
    name = "my"
    model = "v1"

    async def judge(self, prompt: AuditPrompt) -> RawJudgement:
        verdict = await my_provider_call(prompt.text, prompt.rule)
        return RawJudgement(
            passed=verdict.is_safe,
            rationale=verdict.reason,
            score=verdict.confidence,
        )
```

If your backend can score N rules in a single call, also implement:

```python
async def judge_batch(self, text, rules, system_instructions) -> list[RawJudgement]:
    ...
```

The protector will use the batched path automatically when
`batch_rules=True` (default) and there's more than one output rule.

## Optional dependencies

| Backend | Extra | `pip install` |
|---------|-------|---------------|
| `OpenAIAuditor` | `openai` | `pip install 'prompt-protector[openai]'` |
| `AnthropicAuditor` | `anthropic` | `pip install 'prompt-protector[anthropic]'` |
| `DualVoteAuditor`, `MockAuditor` | — | included in core |

A backend whose extra isn't installed raises `MissingDependencyError` at
construction time with the exact `pip` command, never silently at request
time.
