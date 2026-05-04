"""FastAPI safety-gateway server.

Run as ``prompt-protector-server`` (after ``pip install -e '.[server]'``)
or via the Docker image. Loads a YAML config from
``$PROMPT_PROTECTOR_CONFIG`` (default ``/etc/prompt-protector/config.yaml``)
and exposes:

* ``POST /v1/sanitize/input``   — body ``{text, history?, trace_id?}``
* ``POST /v1/sanitize/output``  — body ``{text, history?, trace_id?}``
* ``POST /v1/redact``           — local-only redaction (no LLM call)
* ``GET  /v1/healthz``          — liveness; returns config summary
* ``GET  /v1/readyz``           — readiness; pings auditor with a no-op text
* ``POST /v1/reload``           — re-read the config file (atomic)

This module is intentionally small. For anything beyond a sidecar safety
gateway, use the library directly from your own service.
"""

from __future__ import annotations

import logging
import os
from dataclasses import asdict

try:
    from fastapi import FastAPI, HTTPException
    from pydantic import BaseModel, Field
except ImportError as _exc:  # pragma: no cover
    raise ImportError(
        "prompt_protector.server requires FastAPI and pydantic. "
        "Install with: pip install 'prompt-protector[server]'"
    ) from _exc

from . import __version__
from .config import build_protector, load_config_file
from .protector import PromptProtector
from .types import Turn

log = logging.getLogger("prompt_protector.server")


# ---------------------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------------------


class TurnIn(BaseModel):
    role: str = Field(..., pattern="^(system|user|assistant)$")
    content: str


class SanitizeRequest(BaseModel):
    text: str
    history: list[TurnIn] = Field(default_factory=list)
    trace_id: str | None = None
    rules: list[str] | None = None


class RedactRequest(BaseModel):
    text: str


class ReloadResponse(BaseModel):
    reloaded: bool
    error: str | None = None


# ---------------------------------------------------------------------------
# App factory
# ---------------------------------------------------------------------------


def _config_path() -> str:
    return os.getenv("PROMPT_PROTECTOR_CONFIG", "/etc/prompt-protector/config.yaml")


class _ProtectorHolder:
    """Mutable holder so /v1/reload can swap atomically."""

    def __init__(self, protector: PromptProtector) -> None:
        self.protector = protector


def create_app() -> FastAPI:
    path = _config_path()
    cfg = load_config_file(path) if os.path.exists(path) else None
    if cfg is None:
        log.warning("config_not_found", extra={"path": path})
        from .backends import MockAuditor

        protector = PromptProtector(auditor=MockAuditor())
    else:
        protector = build_protector(cfg)
    holder = _ProtectorHolder(protector)

    app = FastAPI(
        title="prompt-protector",
        version=__version__,
        description="LLM safety gateway. POST text in; pass/fail + optional redacted text out.",
    )

    @app.get("/v1/healthz")
    def healthz():
        return {
            "status": "ok",
            "version": __version__,
            "config_path": path,
            "config_loaded": cfg is not None,
        }

    @app.get("/v1/readyz")
    async def readyz():
        try:
            await holder.protector.sanitize_input(".")
            return {"status": "ready"}
        except Exception as exc:  # noqa: BLE001
            raise HTTPException(status_code=503, detail=str(exc)) from exc

    @app.post("/v1/sanitize/input")
    async def sanitize_input(req: SanitizeRequest):
        result = await holder.protector.sanitize_input(
            req.text,
            history=tuple(Turn(role=t.role, content=t.content) for t in req.history),
            rules=req.rules,
            trace_id=req.trace_id,
        )
        return _result_to_dict(result)

    @app.post("/v1/sanitize/output")
    async def sanitize_output(req: SanitizeRequest):
        result = await holder.protector.sanitize_output(
            req.text,
            history=tuple(Turn(role=t.role, content=t.content) for t in req.history),
            rules=req.rules,
            trace_id=req.trace_id,
        )
        return _result_to_dict(result)

    @app.post("/v1/redact")
    def redact_endpoint(req: RedactRequest):
        r = holder.protector.redact(req.text)
        return {
            "redacted_text": r.redacted_text,
            "matches": [
                {
                    "detector": m.detector,
                    "category": m.category.value,
                    "span": list(m.span),
                    "replacement": m.replacement,
                    "score": m.score,
                }
                for m in r.matches
            ],
        }

    @app.post("/v1/reload", response_model=ReloadResponse)
    def reload_config_endpoint():
        try:
            new_cfg = load_config_file(path)
            holder.protector = build_protector(new_cfg)
            return ReloadResponse(reloaded=True)
        except Exception as exc:  # noqa: BLE001
            log.exception("config_reload_failed")
            return ReloadResponse(reloaded=False, error=str(exc))

    return app


def _result_to_dict(result) -> dict:
    out = asdict(result)
    if out.get("category") is not None:
        out["category"] = result.category.value if result.category else None
    out["matches"] = [
        {
            "detector": m.detector,
            "category": m.category.value,
            "span": list(m.span),
            "original": m.original if len(m.original) <= 64 else m.original[:64] + "...",
            "replacement": m.replacement,
            "score": m.score,
        }
        for m in result.matches
    ]
    out["verdicts"] = [
        {
            "stage": v.stage,
            "passed": v.passed,
            "category": v.category.value if v.category else None,
            "rationale": v.rationale,
            "score": v.score,
            "latency_ms": v.latency_ms,
        }
        for v in result.verdicts
    ]
    return out


def main() -> None:  # pragma: no cover
    """Entry point for ``prompt-protector-server`` console script."""
    import uvicorn

    host = os.getenv("PROMPT_PROTECTOR_HOST", "0.0.0.0")  # noqa: S104 — container default
    port = int(os.getenv("PROMPT_PROTECTOR_PORT", "8000"))
    uvicorn.run(
        "prompt_protector.server:create_app",
        factory=True,
        host=host,
        port=port,
        log_level=os.getenv("PROMPT_PROTECTOR_LOG_LEVEL", "info"),
    )


__all__ = ["create_app", "main"]
