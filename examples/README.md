# Examples

Three reference YAML configs that exercise different deployment shapes.
All are loadable with `PromptProtector.from_config(path)`.

| File | Shape | When to start here |
|------|-------|--------------------|
| `protector.yaml` | Cloud-primary, optional secondary, local pre-redactors | The default — most teams begin here |
| `protector_local_only.yaml` | Fully on-prem, no cloud auditor at all | Air-gapped / sovereign-cloud / pre-prod with no API keys |
| `protector_hybrid.yaml` | Local classifier + cloud second opinion, dual-vote | Highest assurance — pays for both judges and forwards only redacted text |

## Picking a config

Decision tree:

```
Are you allowed to send raw user data to a third-party API?
├── No  → protector_local_only.yaml
└── Yes
    ├── Is this a regulated workload (PII, PHI, financial)?
    │   ├── Yes → protector_hybrid.yaml  (forward_redacted: true)
    │   └── No  → protector.yaml
```

## Running an example offline

The example configs reference cloud providers. To smoke-test without
keys, swap the `auditor:` block for:

```yaml
auditor:
  primary:
    kind: mock
    fail_substrings: ["nuclear", "leak"]
```

Or use `example.py` at the repo root:

```bash
python example.py --offline
```

## Editing safely

The config loader validates strictly:

- Unknown PII types or secret types raise `ConfigError` with the list of
  valid values.
- `failure_mode`, `mode`, `on_oversize`, `action`, `apply_to` values are
  enumerated and checked at load.
- Misconfiguration fails at construction time, never at request time.

So you can freely iterate: a typo in `pii.types: [...]` will tell you
exactly what's wrong before any traffic flows.
