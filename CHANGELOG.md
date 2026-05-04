# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.0] — 2026-05-03

Ground-up rewrite. The 1.0 release breaks the 0.x API surface; see
[Migration](#migration-from-0x) below.

### Added

- **Async-first `PromptProtector`** with sync wrappers
  (`sanitize_input_sync`, `sanitize_output_sync`) that detect a running
  event loop and dispatch to a long-lived background worker — no more
  `asyncio.run` crashes inside FastAPI handlers.
- **Pluggable backend protocol** (`Auditor`, `BatchAuditor`):
  - `OpenAIAuditor` (uses `openai.AsyncOpenAI`, JSON mode, default
    `gpt-4o-mini`).
  - `AnthropicAuditor` (uses `anthropic.AsyncAnthropic`, JSON-prefilled,
    default `claude-haiku-4-5-20251001`).
  - `MockAuditor` for deterministic offline tests.
  - `DualVoteAuditor` for defense-in-depth across two judges
    (`ANY_MUST_PASS` / `ALL_MUST_PASS`).
- **Heuristic fast-path** (`heuristics.py`): SSN, Luhn-validated credit
  cards, email, US phone, IPv4, AWS / GitHub / Slack / OpenAI /
  Anthropic / SSH keys, JWTs, prompt-injection signature phrases (one
  compiled alternation regex), HTML / script / iframe injection,
  Unicode confusable density.
- **Curated rule packs**: `PII`, `SECRETS`, `PROMPT_INJECTION`, `NSFW`,
  `OWASP_LLM_TOP10`. Composable as
  `output_rules=[*PII, *SECRETS, "no pirate speak"]`.
- **Local-model layer** (all opt-in, raise `MissingDependencyError` if
  the optional extra is not installed):
  - `PresidioRedactor` (Microsoft Presidio — free MIT OSS, runs locally).
  - `SpacyNERRedactor`.
  - `TransformersClassifierAuditor` (any HuggingFace `text-classification`
    model — Llama-Guard, Granite Guardian, ProtectAI prompt-injection,
    BERT toxicity).
  - `ONNXClassifierAuditor`.
  - `OllamaAuditor`.
  - `LlamaCppAuditor`.
- **Reversible redaction** with numbered placeholders (`[PERSON_1]`),
  process-local `InMemoryVault`, and Fernet-encrypted on-disk
  `EncryptedFileVault`. `protector.unredact(text, vault_id)` round-trips.
- **`forward_redacted` flag** so the cloud LLM only ever sees the
  pre-redacted text.
- **Conversation-history-aware audits** via
  `sanitize_input(text, history=[Turn(role, content), ...])` for
  multi-turn injection detection.
- **Failure mode**: `FAIL_CLOSED` (default) returns
  `passed=False, degraded=True` when the auditor is fully unavailable;
  `FAIL_OPEN` passes through and degrades. Partial coverage (some
  rules judged, others crashed) returns `passed=True, degraded=True`.
- **Modes**: `ENFORCE`, `SHADOW` (audit and log without blocking),
  `SAMPLE(p)` (audit a fraction of traffic).
- **Caching**: `Cache` protocol, `InMemoryLRUCache` (LRU + TTL,
  `threading.Lock` safe across event loops), `RedisCache` with typed
  JSON round-trip. Cache key is
  `sha256(kind, provider, model, rules_signature, text)`; the
  rules-signature portion is memoized at construction, only the text
  is hashed per request.
- **Streaming output audit**: `sanitize_stream` consumes an upstream
  chunk iterator, runs heuristics on a rolling buffer per chunk, runs
  sliding-window LLM audits in the background, and aborts upstream the
  moment a violation is detected.
- **Schema validation**: validate JSON output against a `pydantic`
  model or JSON Schema as part of the audit step (both deps optional).
- **Bounded concurrency** for per-rule fan-out via
  `asyncio.Semaphore(max_concurrent_judges)` (default 8); a request
  with N rules now spawns at most N concurrent LLM calls (and at most
  `max_concurrent_judges` simultaneously).
- **Resilience layer**: `asyncio.wait_for` timeouts, `tenacity`-style
  exponential backoff with jitter for transient errors only (5xx, 429,
  network), tolerant JSON extraction, `JSONParseError` → failure-mode
  policy.
- **Observability**:
  - Structured `on_event` hook receiving `AuditEvent(kind, passed,
    category, rule_id, provider, model, latency_ms, degraded,
    trace_id, error)`.
  - `trace_id` parameter on every `sanitize_*` call.
  - `_otel.span()` soft-dep integration emits real OpenTelemetry spans
    when `opentelemetry-api` is installed; no-op otherwise.
- **Declarative YAML / TOML / JSON config** (`config.py`):
  `PromptProtector.from_config(path)` /
  `PromptProtector.from_config_dict(...)` /
  `PromptProtector.from_config_env(env_var)`. Mirrors the programmatic
  API; strict validation rejects unknown PII / secret types and bad
  enums at load time.
- **CLI** (`prompt-protector`):
  `prompt-protector check --rules pii,injection - < input.txt` and
  `prompt-protector redact --numbered - < input.txt` for offline
  triage without burning tokens.
- **FastAPI HTTP gateway** (`prompt-protector-server` console script,
  `prompt_protector.server`): `/v1/sanitize/input`,
  `/v1/sanitize/output`, `/v1/redact`, `/v1/healthz`, `/v1/readyz`,
  `/v1/reload`.
- **Container**: multi-stage `Dockerfile` (slim base, non-root user,
  healthcheck), `docker-compose.yml` with `default` (cloud) and
  `local-only` (Ollama) profiles, build-arg `PROTECTOR_EXTRAS` to pick
  which optional extras get baked in.
- **Test suite**: 77 mocked offline tests (`tests/`) plus a live smoke
  test (`tests/live/`) gated on `RUN_LIVE=1`.
- **Per-package READMEs** under `src/prompt_protector/`,
  `src/prompt_protector/backends/`, `src/prompt_protector/local/`,
  `tests/`, and `examples/`.
- **`docs/DOCKER.md`** with build flavors, image-size table,
  hardening notes, and reload semantics.

### Changed

- **Modernized package metadata**: replaced `setup.py` with
  `pyproject.toml` (PEP 621). Pinned `openai>=1.40` and
  `anthropic>=0.40`; dropped the redundant `asyncio` install dep.
  Optional extras: `openai`, `anthropic`, `presidio`, `spacy`,
  `transformers`, `onnx`, `ollama`, `llamacpp`, `redis`, `vault`,
  `otel`, `server`, `yaml`, `schema`, `local-all`, `all`, `dev`.
- **No more global state mutation**: each backend owns its own
  `AsyncOpenAI` / `AsyncAnthropic` client; the library never writes to
  `openai.api_key`.
- **Failure mode is explicit**: a safety layer that silently passes
  traffic when broken is worse than one that returns a graceful
  refusal. `FAIL_CLOSED` is the default; opt into `FAIL_OPEN`
  explicitly.
- **JSON parsing is tolerant**: cloud LLMs that return malformed JSON
  are first retried, then fall through to fail-mode policy with
  `degraded=True` — never an unhandled `JSONDecodeError`.
- **Async / sync API is consistent**: all I/O methods are `async`.
  Sync convenience methods exist on `PromptProtector` only and handle
  being called from inside a running event loop without crashing.

### Removed

- **`chat_gpt.py`** — chatbot helper that did not belong in the
  library.
- **Datastore helpers** (`store_message_in_db`, `retrieve_last_message`)
  and the hard `google-cloud-datastore` dependency.
- **`tests/auditor_test.py`** — non-pytest, hit real OpenAI, replaced
  by the new mocked suite.
- **`setup.py`** — superseded by `pyproject.toml`.

### Fixed

The following defects from a post-implementation code review were fixed
before 1.0.0 shipped:

- `protector.py`: `except BaseException` was swallowing
  `asyncio.CancelledError` and `KeyboardInterrupt`, breaking shutdown
  and cancellation. Narrowed to `except Exception` so cancellation
  propagates.
- `protector.py`: the sync wrapper joined its worker thread with no
  timeout; a stuck auditor would hang the calling thread forever.
  Replaced with a single long-lived background loop and a bounded
  `future.result(timeout=…)`.
- `protector.py`: cache `get` errors were not swallowed (only `set`
  was), so a flaky cache could break requests despite the contract
  saying it shouldn't.
- `protector.py`: a single rule whose JSON judge failed used to fail
  the whole batch closed even when other rules already returned pass.
  Now: partial coverage returns `passed=True, degraded=True`; only
  total auditor failure triggers fail-closed.
- `protector.py`: cache key was always sha256'd even when no cache was
  configured. Short-circuited; the rules-signature portion is now
  memoized at construction.
- `protector.py`: per-rule fan-out had no concurrency cap. Bounded with
  `asyncio.Semaphore(max_concurrent_judges)`, default 8.
- `cache.py`: `InMemoryLRUCache` used `asyncio.Lock`, which lazy-binds
  to the first event loop and raises across loops on Python 3.12+.
  Switched to `threading.Lock`.
- `cache.py`: `RedisCache` round-trip was broken — `Match`, `Category`,
  and `StageVerdict` got serialized to plain dicts/strings but
  reconstructed as if they were typed objects. Added explicit
  serializers + deserializers.
- `cache.py`: every `get`/`set` deep-copied the result under the lock.
  Replaced with a one-time freeze-to-tuples on `set`; `get` returns the
  shared immutable snapshot.
- `heuristics.py`: SSN regex permitted `000-` area despite the comment
  claiming it didn't. Tightened the lookahead.
- `heuristics.py`: credit-card regex missed unspaced 13- and 14-digit
  cards (Diners Club, legacy Visa). Widened the unspaced alternative
  to 13–19 digits.
- `heuristics.py`: injection-phrase detector did N
  `text.lower().find()` passes per request. Replaced with one compiled
  alternation regex (longest-first to handle phrase overlap).
- `heuristics.py`: `_shannon_entropy` lazy-imported `log2` and
  rebuilt a Python `dict` per call. Hoisted the import; switched to
  `collections.Counter`.
- `heuristics.py`: detector exceptions were silently swallowed,
  hiding programmer errors forever. Now logs and re-raises non-regex
  failures.
- `redaction.py`: `restore` did N independent `str.replace` passes,
  could collide on placeholder prefixes (`[SSN_1]` matching inside
  `[SSN_11]`), and was O(N × len(text)). Replaced with a single
  longest-first regex `sub` — correct and linear.
- `redaction.py`: removed dead `if start < cursor` path
  (`_dedupe_overlapping` already guarantees non-overlap).
- `streaming.py`: a finished audit task's `.result()` inside
  `except Exception` could leak `CancelledError`. Replaced with
  explicit `task.cancelled() / task.exception()` handling.
- `streaming.py`: per-chunk `"".join(accumulated)` was quadratic over
  the stream. Replaced with a bounded `_RollingBuffer` using a
  `collections.deque`.
- `local/transformers_backend.py`: HuggingFace pipelines are not
  thread-safe; concurrent `asyncio.to_thread` calls into the same
  pipe would race. Serialized pipeline access with a
  `threading.Lock`.
- `local/vault.py`: `EncryptedFileVault.get` called `delete` outside
  its own lock, racing on expired keys. Refactored with an internal
  `_delete_locked` so both paths hold the same lock.
- `cli.py`: `_filter_registry` mutated the input registry in place.
  Now returns a fresh `DetectorRegistry`.
- `_otel.py`: `span()` built a fresh generator and `**attrs` dict on
  every audit even when OTel was disabled. Returns a shared
  `nullcontext()` singleton on the disabled path.

### Migration from 0.x

The 1.0 API is intentionally a clean break. Notable shifts:

- `protector.sanitize_input(...)` and `sanitize_output(...)` are now
  `async`. Replace `protector.sanitize_input(text)` with
  `await protector.sanitize_input(text)`, or with
  `protector.sanitize_input_sync(text)` from sync callers.
- Construction takes a backend instance, not just an API key. The 0.x
  pattern `PromptProtector(api_key=..., output_rules=[...])` becomes:
  ```python
  from prompt_protector import PromptProtector
  from prompt_protector.backends.openai_backend import OpenAIAuditor

  protector = PromptProtector(
      auditor=OpenAIAuditor(api_key=..., model="gpt-4o-mini"),
      output_rules=[...],
  )
  ```
- Return shape changed from `{"pass": bool, "rationale": str}` to
  `AuditResult` (typed dataclass with `passed`, `score`, `category`,
  `rationale`, `rule_id`, `matches`, `redacted_text`, `vault_id`,
  `provider`, `model`, `latency_ms`, `degraded`, `trace_id`,
  `verdicts`).
- The `OPEN_AI_KEY` env var is still read as a fallback; the modern
  `OPENAI_API_KEY` takes precedence.
- The Datastore / `chat_gpt.py` chatbot helpers were removed; if you
  were using them, port that logic into your own service.
- 0.x crashed on auditor failure. 1.0 returns
  `passed=False, degraded=True` (FAIL_CLOSED, default) or
  `passed=True, degraded=True` (FAIL_OPEN). Check `result.degraded`
  to detect graceful degradation.

[Unreleased]: https://github.com/tahoe-ai/prompt-protector/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/tahoe-ai/prompt-protector/releases/tag/v1.0.0
