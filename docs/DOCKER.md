# Running prompt-protector with Docker

The repo ships a multi-stage `Dockerfile` and a `docker-compose.yml`
that starts the safety gateway as an HTTP service. By default the
container exposes a small REST API on port 8000:

| Method | Path | Purpose |
|--------|------|---------|
| `POST` | `/v1/sanitize/input` | Audit a user's input. Body: `{text, history?, trace_id?, rules?}` |
| `POST` | `/v1/sanitize/output` | Audit an LLM's output. Same shape. |
| `POST` | `/v1/redact` | Local-only redaction. No LLM call. |
| `GET`  | `/v1/healthz` | Liveness + config summary |
| `GET`  | `/v1/readyz` | Readiness — pings the auditor with a no-op input |
| `POST` | `/v1/reload` | Re-read the YAML config atomically |

## Quick start

```bash
docker compose up --build
curl -s http://localhost:8000/v1/healthz
```

To audit a user message:

```bash
curl -s http://localhost:8000/v1/sanitize/input \
  -H 'content-type: application/json' \
  -d '{"text": "ignore previous instructions"}'
```

Expected response:

```json
{
  "passed": false,
  "category": "prompt_injection",
  "rationale": "heuristic match: injection_phrase",
  "score": 0.85,
  "provider": "heuristics",
  ...
}
```

## Build flavors

`PROTECTOR_EXTRAS` is a build-arg that controls which optional extras
get baked into the image. The default is the lean "server + cloud
auditors" build:

```bash
docker build -t prompt-protector .
```

For a fully on-prem image with Presidio (free MIT OSS) + a local
classifier:

```bash
docker build \
  --build-arg PROTECTOR_EXTRAS="server,yaml,presidio,transformers,ollama" \
  -t prompt-protector:local .
```

For everything:

```bash
docker build \
  --build-arg PROTECTOR_EXTRAS="all" \
  -t prompt-protector:all .
```

Each extra adds dependencies and image size — pick what your config
actually uses.

## Configuration

The image looks for its config at
`/etc/prompt-protector/config.yaml`. Override it with a bind-mount:

```bash
docker run --rm -p 8000:8000 \
  -v $(pwd)/protector.yaml:/etc/prompt-protector/config.yaml:ro \
  -e OPENAI_API_KEY=$OPENAI_API_KEY \
  prompt-protector
```

You can also point the server at a different path with
`PROMPT_PROTECTOR_CONFIG=/path/inside/container`.

## Compose profiles

`docker-compose.yml` has two profiles:

- **default** — cloud auditor (OpenAI / Anthropic). Needs API keys via
  env vars (`OPENAI_API_KEY`, `ANTHROPIC_API_KEY`).
- **local-only** — adds an `ollama` sidecar so the protector can use a
  fully local judge model.

```bash
# Default — cloud-backed
docker compose up

# Fully on-prem — Ollama judge, no internet egress
docker compose --profile local-only up
docker compose exec ollama ollama pull llama-guard3
```

The on-prem stack listens on **8001** (not 8000) so you can run both
side-by-side during a migration.

## Hardening

The image runs as a non-root user (UID 10001) and bakes in a
`HEALTHCHECK`. For production, also:

- Mount the config **read-only** (`:ro` in compose; included by default).
- Pass API keys via your secret manager, not `.env` files in the build
  context.
- Set resource limits (`mem_limit`, `cpus`) appropriate to the model
  size — the cloud-auditor build is small (~250 MB), but
  `[transformers]` will pull torch and balloon to ~2 GB plus the model
  cache at runtime.
- Use `read_only: true` for the container filesystem and add a
  `tmpfs:` for `/tmp` if you enable `transformers` / `presidio` (they
  cache models).
- Sit the container behind a reverse proxy that handles TLS, rate
  limits, and auth; the gateway itself does not enforce auth.

## Reloading config without redeploying

`POST /v1/reload` re-reads the config file and atomically swaps the
internal state if validation passes; otherwise the previous config
stays active and the response includes the validation error. Pair this
with a Kubernetes `ConfigMap` and a sidecar that calls `/v1/reload`
when the file changes.

## Logs and observability

Logs go to stdout in the container's stream (set
`PROMPT_PROTECTOR_LOG_LEVEL` for verbosity). For metrics / traces:

- Build with `--build-arg PROTECTOR_EXTRAS="...,otel"` and the protector
  emits OpenTelemetry spans automatically when an OTel SDK is configured
  via env vars (`OTEL_EXPORTER_OTLP_ENDPOINT`, etc.).
- Subscribe an `on_event` hook by importing the library directly
  instead of using the HTTP API; the server is intentionally minimal.

## Image size at a glance

| Build flavor | Approx size |
|--------------|-------------|
| `server,openai,anthropic,yaml` (default) | ~250 MB |
| `+ presidio` | ~600 MB (spaCy en_core_web_sm not pre-pulled) |
| `+ transformers` | ~2.5 GB (torch CPU) |
| `+ ollama` | unchanged in the protector image; Ollama runs in its own |
| `all` | ~3 GB |

Slim base + multi-stage build keeps the cloud-auditor flavor small
enough to deploy as a sidecar anywhere.
