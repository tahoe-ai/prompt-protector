"""Streaming output audit.

Wraps an upstream async iterator of text chunks. Heuristics run on every
chunk in real time. The accumulated text is audited periodically on a
sliding window. On detection, the upstream iterator is cancelled and the
caller receives a ``StreamViolation`` sentinel.

Usage:

    async for chunk in protector.sanitize_stream(upstream):
        if isinstance(chunk, StreamViolation):
            await render_block_message()
            break
        await render(chunk)
"""

from __future__ import annotations

import asyncio
from collections import deque
from collections.abc import AsyncIterable, AsyncIterator, Sequence
from dataclasses import dataclass

from .heuristics import DetectorRegistry
from .protector import PromptProtector
from .types import AuditResult, Category, Match, Turn


@dataclass(frozen=True)
class StreamViolation:
    """Yielded once when the protector decides to abort a stream."""

    rationale: str
    category: Category | None
    matches: list[Match]
    audited_so_far: str


class _RollingBuffer:
    """Fixed-window rolling buffer of recent stream chunks.

    Keeps the most recent ``window`` characters available without
    rebuilding the joined string on every chunk. Bounded; old characters
    are discarded once the window is full.
    """

    __slots__ = ("_window", "_chunks", "_total")

    def __init__(self, window: int) -> None:
        self._window = window
        self._chunks: deque[str] = deque()
        self._total = 0

    def append(self, chunk: str) -> None:
        self._chunks.append(chunk)
        self._total += len(chunk)
        # Trim oldest chunks while the front one is fully outside the window.
        while self._chunks and self._total - len(self._chunks[0]) >= self._window:
            self._total -= len(self._chunks.popleft())

    def view(self) -> str:
        if len(self._chunks) == 1:
            return self._chunks[0][-self._window :] if self._total > self._window else self._chunks[0]
        joined = "".join(self._chunks)
        return joined[-self._window :] if len(joined) > self._window else joined

    def __len__(self) -> int:
        return self._total


async def sanitize_stream(
    protector: PromptProtector,
    upstream: AsyncIterable[str],
    *,
    rules: Sequence | None = None,
    history: Sequence[Turn] = (),
    audit_every_chars: int = 256,
    sliding_window_chars: int = 1024,
    registry: DetectorRegistry | None = None,
    trace_id: str | None = None,
) -> AsyncIterator[str | StreamViolation]:
    """Pass-through chunks while running heuristics + sliding-window audits.

    Heuristic hits abort immediately. LLM audits run in the background on
    a sliding window so they never block streaming throughput; if the
    background audit returns a fail verdict, the next yielded item is the
    violation sentinel and the upstream iterator is closed.
    """
    reg = registry or protector._registry  # noqa: SLF001 — same package
    # Two windows: a heuristics buffer (slightly larger to catch matches that
    # straddle a chunk boundary), and an audit buffer (the LLM context).
    heur_buf = _RollingBuffer(sliding_window_chars * 2)
    audit_buf = _RollingBuffer(sliding_window_chars)
    full_text: list[str] = []  # only kept for the final audit + violation context
    chars_since_audit = 0
    pending_audit: asyncio.Task[AuditResult] | None = None

    upstream_iter = upstream.__aiter__()

    try:
        while True:
            try:
                chunk = await upstream_iter.__anext__()
            except StopAsyncIteration:
                break

            heur_buf.append(chunk)
            audit_buf.append(chunk)
            full_text.append(chunk)
            chars_since_audit += len(chunk)

            # Heuristic check — cheapest, run on every chunk over a fixed window.
            heur = reg.scan(heur_buf.view())
            blocking = [m for m in heur if m.score >= 0.85]
            if blocking:
                yield StreamViolation(
                    rationale=f"heuristic match: {blocking[0].detector}",
                    category=blocking[0].category,
                    matches=heur,
                    audited_so_far="".join(full_text),
                )
                if pending_audit is not None and not pending_audit.done():
                    pending_audit.cancel()
                if hasattr(upstream_iter, "aclose"):
                    await upstream_iter.aclose()
                return

            # If a previous background audit finished, check it.
            if pending_audit is not None and pending_audit.done():
                audit = _consume_audit_task(pending_audit)
                pending_audit = None
                if audit is not None and not audit.passed:
                    yield StreamViolation(
                        rationale=audit.rationale,
                        category=audit.category,
                        matches=list(audit.matches),
                        audited_so_far="".join(full_text),
                    )
                    if hasattr(upstream_iter, "aclose"):
                        await upstream_iter.aclose()
                    return

            # Yield the chunk through to the caller.
            yield chunk

            # Kick off a sliding-window LLM audit periodically.
            if chars_since_audit >= audit_every_chars and pending_audit is None:
                pending_audit = asyncio.create_task(
                    protector.sanitize_output(
                        audit_buf.view(),
                        rules=rules,
                        history=history,
                        trace_id=trace_id,
                    )
                )
                chars_since_audit = 0

        # Stream ended — wait on any in-flight audit.
        if pending_audit is not None:
            try:
                audit = await pending_audit
            except asyncio.CancelledError:
                raise
            except Exception:  # noqa: BLE001
                audit = None
            pending_audit = None
            if audit is not None and not audit.passed:
                yield StreamViolation(
                    rationale=audit.rationale,
                    category=audit.category,
                    matches=list(audit.matches),
                    audited_so_far="".join(full_text),
                )
                return

        # Final audit on the full text once the stream completes.
        final_text = "".join(full_text)
        if final_text:
            final = await protector.sanitize_output(
                final_text, rules=rules, history=history, trace_id=trace_id
            )
            if not final.passed:
                yield StreamViolation(
                    rationale=final.rationale,
                    category=final.category,
                    matches=list(final.matches),
                    audited_so_far=final_text,
                )
    finally:
        if pending_audit is not None and not pending_audit.done():
            pending_audit.cancel()


def _consume_audit_task(task: asyncio.Task[AuditResult]) -> AuditResult | None:
    """Read a finished audit task without leaking CancelledError.

    A task that finished by being cancelled is not a real "verdict" — treat
    it as no-result and let the surrounding pipeline keep streaming.
    """
    if task.cancelled():
        return None
    exc = task.exception()
    if exc is not None:
        return None
    return task.result()


__all__ = ["StreamViolation", "sanitize_stream"]
