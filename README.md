# prompt-protector

[![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)](CHANGELOG.md)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](pyproject.toml)

People leak PII into LLMs constantly. They paste customer records into
chat windows, feed support transcripts into summarizers, send internal
docs to whichever model is open. As companies wire LLMs into more
internal systems (CRMs, ticketing, codebases, data warehouses) the
surface area for accidental exfil grows. GDPR, HIPAA, SOC 2, and pretty
much every compliance framework you might be subject to says this
isn't okay.

prompt-protector sits between your users and your model. It catches
PII, secrets, prompt injection, schema violations, and policy breaches
before they cross the wire. Cheap local heuristics catch the obvious
cases. Anything heuristics can't decide goes to a judge model: cloud
(OpenAI, Anthropic) or local (Llama-Guard, Granite Guardian, Presidio,
etc.). The framework is extensible, so the same plumbing handles
internal data exfil and external attacks like prompt injection.

The design borrows from black boxes on airplanes: redundant recorders
that don't all fail at the same time on the same input. Two judge
models from the same vendor share training data and RLHF, so they tend
to fail on the same inputs, especially adversarial ones. Two from
different vendors (OpenAI and Anthropic, say) were trained by
different teams on different data mixes with different safety stacks.
A jailbreak that lands on one is meaningfully less likely to land on
the other. If one has a 1% miss rate and the other's failures aren't
perfectly correlated, requiring both to agree pushes the joint miss
rate toward 0.01%. That's what `DualVoteAuditor` does, with
`ANY_MUST_PASS` and `ALL_MUST_PASS` policies. Point it at OpenAI plus
Anthropic, or a cloud model plus a local Llama-Guard.

Fail-closed by default. Configurable in YAML. The cloud model never
has to see raw PII if you don't want it to.

## Install

```bash
pip install prompt-protector                 # core: heuristics + redaction
pip install 'prompt-protector[openai]'       # OpenAI judge
pip install 'prompt-protector[anthropic]'    # Anthropic judge
pip install 'prompt-protector[presidio]'     # local PII redaction
pip install 'prompt-protector[transformers]' # local classifier judge
pip install 'prompt-protector[local-all]'    # all local backends
pip install 'prompt-protector[all]'          # everything
```

The library imports without any LLM SDK installed. Backends raise
`MissingDependencyError` at construction with the exact `pip` command
if their extra is missing.

## Quickstart

```python
import asyncio
from prompt_protector import PromptProtector, PII, PROMPT_INJECTION
from prompt_protector.backends.openai_backend import OpenAIAuditor

protector = PromptProtector(
    auditor=OpenAIAuditor(model="gpt-4o-mini"),
    input_rules=[*PROMPT_INJECTION],
    output_rules=[*PII, "Output must relate to home insurance products."],
)

async def chat(user_text: str) -> str:
    inp = await protector.sanitize_input(user_text)
    if not inp.passed:
        return f"[blocked: {inp.rationale}]"
    bot = await your_llm(user_text)
    out = await protector.sanitize_output(bot)
    if not out.passed:
        return f"[blocked: {out.rationale}]"
    return bot

asyncio.run(chat("hi"))
```

## How it works

Every request runs through this pipeline:

```
text in
  -> size guard
  -> heuristics            (regex, Luhn, entropy, injection phrases)
  -> local pre-redactors   (Presidio / spaCy / regex pack)
  -> cache lookup
  -> LLM judge             (cloud or local)
  -> cache store
  -> AuditResult
```

Stages can short-circuit. A heuristic hit (PII pattern, API key, known
injection phrase) blocks before any LLM call. A cache hit returns
immediately. If the judge is unavailable, the failure mode kicks in
and the result is marked `degraded=True`.

### What it catches

Heuristics: SSN, Luhn-checked credit cards, email, US phone, AWS /
GitHub / Slack / OpenAI / Anthropic keys, JWTs, SSH private keys,
prompt-injection signature phrases, HTML / script / iframe injection,
Unicode confusable density.

Rule packs (composable): `PII`, `SECRETS`, `PROMPT_INJECTION`, `NSFW`,
`OWASP_LLM_TOP10`.

Optional schema validation against a `pydantic` model or a JSON Schema
dict.

### Backends

Cloud: `OpenAIAuditor`, `AnthropicAuditor`. Each takes its own client;
nothing mutates global state.

Local: `PresidioRedactor` (free MIT OSS, runs locally),
`SpacyNERRedactor`, `TransformersClassifierAuditor` (wraps any
HuggingFace text-classification model: Llama-Guard, Granite Guardian,
ProtectAI prompt-injection, BERT toxicity), `ONNXClassifierAuditor`,
`OllamaAuditor`, `LlamaCppAuditor`.

Composite: `DualVoteAuditor(primary, secondary, policy=ANY|ALL)` runs
two judges in parallel and combines verdicts.

### Failure mode and modes

`failure_mode=FAIL_CLOSED` is the default. The judge being down means
the result blocks. Switch to `FAIL_OPEN` to pass through instead.
Either way the result has `degraded=True` when this kicks in, so
callers can tell.

`mode=Mode.ENFORCE | Mode.SHADOW | Mode.SAMPLE(p)`. SHADOW logs
verdicts without blocking. SAMPLE audits a fraction of traffic. Both
useful for rolling out a new rule without breaking traffic if it
false-positives.

## Privacy: keep PII off the wire

```python
from prompt_protector.local import PresidioRedactor, InMemoryVault

protector = PromptProtector(
    pre_redactors=[PresidioRedactor(reversible=True)],
    auditor=OpenAIAuditor(model="gpt-4o-mini"),
    vault=InMemoryVault(),
    forward_redacted=True,
)

result = await protector.sanitize_input("Hello, I'm Jane Smith")
# result.redacted_text -> "Hello, I'm [PERSON_1]"
# Send result.redacted_text to your LLM. After it responds:
restored = protector.unredact(llm_response, result.vault_id)
```

With `forward_redacted=True`, the cloud LLM never sees raw PII. The
vault holds the placeholder-to-original mapping for round-trip
restoration.

## Conversation history

Some injections span multiple turns: an earlier benign-looking turn
primes the model, a later one slips past. Pass the prior turns:

```python
from prompt_protector import Turn

await protector.sanitize_input(
    user_text,
    history=[
        Turn(role="user", content="Earlier turn the attacker primed."),
        Turn(role="assistant", content="The model's earlier reply."),
    ],
)
```

## Streaming

Stop bad output before the user sees it instead of after:

```python
from prompt_protector.streaming import sanitize_stream, StreamViolation

async for item in sanitize_stream(protector, my_llm.stream(user_text)):
    if isinstance(item, StreamViolation):
        await render_block(item.rationale)
        break
    await render_chunk(item)
```

## Declarative config

Same surface, in YAML. Strict validation; misconfiguration fails at
construction time, never at request time.

```yaml
version: 1

defaults:
  failure_mode: fail_closed
  mode: enforce
  forward_redacted: true

auditor:
  primary:
    kind: openai
    model: gpt-4o-mini
    api_key_env: OPENAI_API_KEY
  secondary:
    kind: transformers
    model: ProtectAI/deberta-v3-base-prompt-injection-v2
    device: cpu
  policy: any_must_pass

pre_redactors:
  - kind: presidio
    entities: [US_SSN, CREDIT_CARD, EMAIL_ADDRESS, PHONE_NUMBER, PERSON]
    operator: replace
  - kind: regex_pack

prevent:
  pii:
    enabled: true
    types: [ssn, credit_card, email, phone, postal_address, date_of_birth]
    action: redact
    apply_to: [input, output]
  secrets:
    enabled: true
    action: block
  prompt_injection:
    enabled: true
    apply_to: [input]
    extra_phrases: ["ignore the rules above"]
  custom_regex:
    - name: internal_ticket_id
      pattern: "INC-\\d{6}"
      action: redact
      replacement: "[REDACTED:TICKET]"

cache:
  enabled: true
  backend: memory
  ttl_seconds: 600
```

```python
protector = PromptProtector.from_config("protector.yaml")
```

See `examples/protector.yaml`, `examples/protector_local_only.yaml`,
and `examples/protector_hybrid.yaml`.

## Result shape

```python
@dataclass
class AuditResult:
    passed: bool
    score: float                 # 0.0 (clean) .. 1.0 (clearly violating)
    category: Category | None    # PII / PROMPT_INJECTION / SECRETS / NSFW / SCHEMA / OTHER
    rationale: str
    rule_id: str | None
    matches: list[Match]         # heuristic hits with span and replacement
    redacted_text: str | None    # set when pre-redactors fired
    vault_id: str | None         # for unredact()
    provider: str
    model: str
    latency_ms: int
    degraded: bool               # True when failure-mode kicked in
    trace_id: str | None
    verdicts: list[StageVerdict] # per-stage breakdown
```

## CLI

```bash
prompt-protector check --rules pii,injection - < message.txt
prompt-protector redact --numbered            - < message.txt
```

Heuristics and redaction only. No LLM calls, no tokens burned. Useful
for offline triage.

## Docker

```bash
docker compose up --build                    # cloud judge on :8000
docker compose --profile local-only up       # fully on-prem with Ollama on :8001
```

The image runs a small REST API: `/v1/sanitize/input`,
`/v1/sanitize/output`, `/v1/redact`, `/v1/healthz`, `/v1/reload`. See
[`docs/DOCKER.md`](docs/DOCKER.md) for build flavors, hardening, and
reload semantics.

## Tests

```bash
pytest tests/                            # 77 offline mocked tests
RUN_LIVE=1 pytest tests/live/            # real OpenAI / Anthropic
```

## Changelog

See [`CHANGELOG.md`](CHANGELOG.md).

## License

MIT.
