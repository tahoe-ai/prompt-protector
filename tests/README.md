# Tests

Offline-first. The default `pytest tests/` invocation runs nothing that
touches the network or requires API keys.

## Layout

| File | Covers |
|------|--------|
| `conftest.py` | Adds `src/` to `sys.path`, gates `tests/live/` on `RUN_LIVE=1`, mock fixtures |
| `test_protector.py` | End-to-end protector behavior with `MockAuditor` (failure mode, dual vote, history, hooks, batching, size guard) |
| `test_heuristics.py` | Each detector's known-good / known-bad fixtures |
| `test_redaction.py` | Span replacement, dedup, labeled vs numbered styles |
| `test_redaction_roundtrip.py` | Vault round-trip via `unredact()` |
| `test_rule_packs.py` | Pack composition, no duplicate rule IDs |
| `test_cache.py` | LRU eviction, TTL expiry, "cache hit short-circuits the auditor" |
| `test_modes.py` | `ENFORCE` / `SHADOW` / `SAMPLE(p)` semantics |
| `test_streaming.py` | Stream pass-through + violation aborts upstream |
| `test_config.py` | YAML loader, schema validation, equivalence with programmatic API |
| `test_local_presidio.py` | Presidio (gated `pytest.importorskip("presidio_analyzer")`) |
| `test_local_transformers.py` | Transformers classifier with stub pipeline |
| `test_local_ollama.py` | Ollama backend with stub HTTP client |
| `live/test_smoke.py` | Real OpenAI / Anthropic — only runs with `RUN_LIVE=1` |

## Running

```bash
pip install -e '.[dev]'
pytest tests/                            # offline (default — 64 tests, no network)
RUN_LIVE=1 pytest tests/live/            # against real OpenAI + Anthropic
pytest tests/ -k 'cache or modes'        # subset
pytest tests/ --tb=short                 # quieter tracebacks
```

Live tests require `OPENAI_API_KEY` and `ANTHROPIC_API_KEY` and will
make real billed API calls — one PII-leak prompt and one benign prompt
per provider.

## Adding a test

- Use `MockAuditor` for any protector-level test — it's deterministic
  and never hits the network.
- For backend tests that genuinely need an HTTP layer, mock with `respx`
  rather than spinning up real services.
- For local-model backends, use `pytest.importorskip(...)` so the test
  is skipped (not failed) when the optional extra isn't installed.
- New event-driven tests should assert `on_event` was called with the
  expected `AuditEvent` shape; that's the public contract for
  observability hooks.

## Markers

- `live` — gated on `RUN_LIVE=1`, defined in `pyproject.toml`. Mark any
  test that needs real provider credentials.
