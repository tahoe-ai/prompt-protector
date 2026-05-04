# `prompt_protector` — package internals

This is the source root. If you're using the library, you want the
top-level `README.md`. If you're contributing or curious how it's wired
together, read on.

## Pipeline at a glance

```
text
 → size guard          (max_input_chars; reject or truncate)
 → heuristics          (regex / Luhn / entropy / phrases)
 → local pre-redactors (Presidio, spaCy, regex pack — see ./local/)
 → cache lookup        (InMemoryLRUCache or RedisCache)
 → LLM auditor         (cloud or local — see ./backends/ and ./local/)
 → cache store
 → on_event + result
```

Stages can short-circuit. Auditor failures degrade per `failure_mode`.

## File map

| File | Role |
|------|------|
| `protector.py` | `PromptProtector` — the public façade, owns the pipeline |
| `types.py` | `AuditResult`, `Match`, `FailureMode`, `Mode`, `Category`, `Turn`, etc. |
| `prompts.py` | System-prompt strings shared by cloud backends |
| `heuristics.py` | All regex / Luhn / entropy / phrase detectors + `DetectorRegistry` |
| `redaction.py` | Span-based placeholder substitution; LABELED + NUMBERED styles |
| `rule_packs.py` | Curated `RulePack`s: `PII`, `SECRETS`, `PROMPT_INJECTION`, `NSFW`, `OWASP_LLM_TOP10` |
| `cache.py` | `Cache` protocol + `InMemoryLRUCache` + `RedisCache` |
| `streaming.py` | `sanitize_stream()` for token-stream auditing |
| `schema.py` | Output JSON-schema / pydantic validation |
| `config.py` | YAML/TOML/JSON loader + `build_protector(cfg)` |
| `cli.py` | `prompt-protector` console script |
| `settings.py` | Env-var fallbacks (`OPENAI_API_KEY`, `ANTHROPIC_API_KEY`) |
| `backends/` | Cloud + composite auditors (see `./backends/README.md`) |
| `local/` | On-prem redactors and auditors (see `./local/README.md`) |
| `_retry.py` | Transient-error classifier + exponential backoff |
| `_json.py` | Tolerant JSON object extraction |
| `_otel.py` | Soft-dep OpenTelemetry hooks |

Underscore-prefixed modules are private and can change between minor
versions.

## Adding a detector

```python
from prompt_protector.heuristics import default_registry, Detector
from prompt_protector.types import Category, make_match

def detect_iban(text):
    import re
    pat = re.compile(r"[A-Z]{2}\d{2}[A-Z0-9]{11,30}")
    return [make_match("iban", Category.PII, (m.start(), m.end()), m.group(0),
                       replacement="[REDACTED:IBAN]") for m in pat.finditer(text)]

registry = default_registry()
registry.add(Detector("iban", Category.PII, detect_iban))
protector = PromptProtector(auditor=..., detector_registry=registry)
```

## Adding a backend

Implement the `Auditor` protocol from `backends/base.py`:

```python
class MyAuditor:
    name = "my"
    model = "v1"

    async def judge(self, prompt: AuditPrompt) -> RawJudgement:
        ...   # return RawJudgement(passed=..., rationale=..., score=...)
```

Optionally implement `judge_batch()` for the `BatchAuditor` protocol if
your backend can score N rules in one call.

## Conventions

- All public APIs that touch the network are async. Sync wrappers exist
  on `PromptProtector` for the common cases.
- Backends never mutate global state (no `openai.api_key = ...`).
- Failure-mode policy lives in `protector.py`, not in backends. A backend
  raises on failure; the protector decides whether that means
  fail-closed or fail-open.
- Exceptions: `MissingDependencyError` (backend optional dep), `JSONParseError` (cloud
  judge returned non-JSON), `ConfigError` (invalid YAML).
- Caches must never break a request — `_cache_store` swallows errors and
  logs.

## Tests

See `../../tests/`. Offline-only by default; live tests are gated on
`RUN_LIVE=1`.
