# syntax=docker/dockerfile:1.6
#
# Multi-stage build:
#   1. builder — installs deps + builds the wheel
#   2. runtime — slim image with just the wheel + chosen extras
#
# Build args let you pick which optional extras get baked in. Default is
# the lean "server + cloud auditors" image. For local-model deployments,
# build with --build-arg PROTECTOR_EXTRAS="server,openai,anthropic,presidio,transformers,ollama".
#
# Examples:
#   docker build -t prompt-protector .
#   docker build --build-arg PROTECTOR_EXTRAS="server,openai,anthropic,presidio" -t prompt-protector:presidio .
#
# Run:
#   docker run --rm -p 8000:8000 -v $(pwd)/examples/protector.yaml:/etc/prompt-protector/config.yaml:ro \
#     -e OPENAI_API_KEY=sk-... prompt-protector

ARG PYTHON_VERSION=3.12

# ---------------------------------------------------------------------------
# Builder
# ---------------------------------------------------------------------------
FROM python:${PYTHON_VERSION}-slim AS builder

ARG PROTECTOR_EXTRAS="server,openai,anthropic,yaml"

ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /build

# Build deps for any C-extension extras (presidio's spaCy, transformers' torch, etc.).
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        gcc \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md ./
COPY src/ ./src/

RUN pip install --upgrade pip wheel build \
    && pip wheel --wheel-dir /wheels ".[${PROTECTOR_EXTRAS}]"

# ---------------------------------------------------------------------------
# Runtime
# ---------------------------------------------------------------------------
FROM python:${PYTHON_VERSION}-slim AS runtime

ARG PROTECTOR_EXTRAS="server,openai,anthropic,yaml"

ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PROMPT_PROTECTOR_CONFIG=/etc/prompt-protector/config.yaml \
    PROMPT_PROTECTOR_HOST=0.0.0.0 \
    PROMPT_PROTECTOR_PORT=8000 \
    PROMPT_PROTECTOR_LOG_LEVEL=info

# Non-root user; container runs as UID 10001.
RUN groupadd --system --gid 10001 protector \
    && useradd  --system --uid 10001 --gid protector --home /app --shell /bin/false protector \
    && mkdir -p /etc/prompt-protector /app \
    && chown -R protector:protector /etc/prompt-protector /app

WORKDIR /app

COPY --from=builder /wheels /wheels
RUN pip install --no-index --find-links=/wheels "prompt-protector[${PROTECTOR_EXTRAS}]" \
    && rm -rf /wheels

# Default config — overridden by a bind-mount in production.
COPY examples/protector.yaml /etc/prompt-protector/config.yaml

USER protector

EXPOSE 8000

# Healthcheck hits the readiness endpoint — fails the container if the
# auditor isn't responding.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request,sys; \
        sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/v1/healthz', timeout=3).status==200 else 1)"

ENTRYPOINT ["prompt-protector-server"]
