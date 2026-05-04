# Contributing

Thanks for the interest. Notes on getting set up, what we expect from
PRs, and how to add common things without reading the whole codebase.

## Setting up

```bash
git clone https://github.com/tahoe-ai/prompt-protector
cd prompt-protector
python3 -m venv .venv
source .venv/bin/activate
pip install -e '.[dev,yaml,schema]'
```

To run the offline test suite:

```bash
pytest tests/                         # 77 mocked tests, no network
ruff check src/ tests/
mypy src/prompt_protector/            # advisory for now
```

To run the live smoke tests against real providers:

```bash
RUN_LIVE=1 OPENAI_API_KEY=... ANTHROPIC_API_KEY=... pytest tests/live/
```

To smoke-test the HTTP gateway in Docker:

```bash
docker compose up --build
curl -s http://localhost:8000/v1/healthz
```

## PR conventions

- Open PRs against `master`. Branch protection requires CI to pass
  before merge.
- Keep PRs scoped to one feature or fix. Smaller is better; a
  20-line PR gets reviewed faster than a 2000-line one.
- Commits should each be coherent on their own. Squash-and-merge is
  fine for small PRs; merge-commit is fine for larger ones with
  meaningful per-feature history (the v1.0 PR is an example).
- New behavior needs a test. Bug fixes need a regression test that
  pins the bug.
- Add an entry under `## [Unreleased]` in `CHANGELOG.md` for anything
  user-visible. Use the `Added`, `Changed`, `Removed`, `Fixed`
  subsections.

## Style

- `ruff check` must pass. Run `ruff check --fix` for autofixable
  issues.
- Follow the conventions already in the codebase. The existing
  per-package READMEs (`src/prompt_protector/README.md`,
  `backends/README.md`, `local/README.md`) describe the patterns.
- Public APIs are async. Sync wrappers only on `PromptProtector`.
- Backends never mutate global state.
- Failure-mode policy lives in `protector.py`, not in backends. A
  backend raises on failure; the protector decides what that means.
- Type hints are encouraged but not required. Mypy is advisory until
  the codebase is fully typed.

## Adding a new heuristic detector

```python
from prompt_protector.heuristics import default_registry, Detector
from prompt_protector.types import Category, make_match
import re

def detect_iban(text):
    pat = re.compile(r"[A-Z]{2}\d{2}[A-Z0-9]{11,30}")
    return [
        make_match(
            "iban",
            Category.PII,
            (m.start(), m.end()),
            m.group(0),
            replacement="[REDACTED:IBAN]",
        )
        for m in pat.finditer(text)
    ]

registry = default_registry()
registry.add(Detector("iban", Category.PII, detect_iban))
```

If your detector applies to most users, propose adding it to
`default_registry`. Include a golden test in `tests/test_heuristics.py`.

## Adding a new backend

Implement the `Auditor` protocol from `backends/base.py`:

```python
class MyAuditor:
    name = "my"
    model = "v1"

    async def judge(self, prompt: AuditPrompt) -> RawJudgement:
        ...
```

If your backend has heavy optional dependencies, add an entry to
`pyproject.toml`'s `[project.optional-dependencies]` and gate the
import in `backends/__init__.py` (or `local/__init__.py`) with a lazy
`__getattr__`.

If the backend can score N rules in one call, also implement
`judge_batch()` for the `BatchAuditor` protocol so the protector
takes the batched path automatically.

## Adding a new rule pack

Add a `RulePack` to `rule_packs.py` and re-export it from
`__init__.py`. Each rule needs a unique `id` (no duplicates across
packs) and a clear `text` description that the LLM judge can read.

## Reporting bugs

Open an issue with:

- The version (`pip show prompt-protector`).
- A minimal reproduction. If it involves a real LLM, include the
  provider, model, and the exact prompt + input.
- The full `AuditResult` (or just `result.verdicts`) so we can see
  which stage in the pipeline made the call.

## Reporting security issues

Don't open a public issue. See `SECURITY.md`.

## Code of conduct

Be respectful. We follow the
[Contributor Covenant](https://www.contributor-covenant.org/version/2/1/code_of_conduct/).

## License

By submitting a contribution, you agree it will be licensed under the
same MIT license as the rest of the project.
