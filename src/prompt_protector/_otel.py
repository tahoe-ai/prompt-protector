"""Soft-dep OpenTelemetry integration.

If ``opentelemetry-api`` is importable, ``span(name)`` emits a real span.
Otherwise it returns a no-op context manager. Hard-import-free at runtime
so users without OTel pay no cost.
"""

from __future__ import annotations

import contextlib
from typing import Iterator, Optional

try:
    from opentelemetry import trace as _otel_trace  # type: ignore

    _tracer = _otel_trace.get_tracer("prompt_protector")
    _ENABLED = True
except ImportError:  # pragma: no cover
    _tracer = None
    _ENABLED = False


# Reused for the disabled path so we don't pay the cost of building a fresh
# generator for every audit when OTel isn't installed.
_NULL = contextlib.nullcontext()


def span(name: str, *, trace_id: Optional[str] = None):
    if not _ENABLED or _tracer is None:
        return _NULL
    return _real_span(name, trace_id=trace_id)


@contextlib.contextmanager
def _real_span(name: str, *, trace_id: Optional[str]) -> Iterator[None]:  # pragma: no cover
    with _tracer.start_as_current_span(name) as s:  # type: ignore[union-attr]
        if trace_id:
            s.set_attribute("prompt_protector.trace_id", trace_id)
        yield


__all__ = ["span"]
