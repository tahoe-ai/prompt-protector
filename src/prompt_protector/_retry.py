"""Retry helpers scoped to transient errors only.

We never retry on auth/quota/4xx-client errors — those are caller bugs and
retrying them just costs money. Transient = network / timeout / 5xx / 429.
"""

from __future__ import annotations

import asyncio
import logging
import random
from collections.abc import Awaitable, Callable
from typing import TypeVar

T = TypeVar("T")

log = logging.getLogger("prompt_protector")


_TRANSIENT_EXC_NAMES = {
    "APIConnectionError",
    "APITimeoutError",
    "RateLimitError",
    "InternalServerError",
    "ServiceUnavailableError",
    "ConnectionError",
    "TimeoutError",
    "ClientConnectionError",
    "ServerDisconnectedError",
    "ClientPayloadError",
}


def is_transient(exc: BaseException) -> bool:
    """Best-effort check that doesn't hard-import every provider's SDK."""
    if isinstance(exc, asyncio.TimeoutError):
        return True
    name = type(exc).__name__
    if name in _TRANSIENT_EXC_NAMES:
        return True
    status = getattr(exc, "status_code", None) or getattr(exc, "status", None)
    return isinstance(status, int) and (status >= 500 or status == 429)


async def retry_async(
    fn: Callable[[], Awaitable[T]],
    *,
    max_retries: int = 3,
    base_delay_s: float = 0.25,
    max_delay_s: float = 4.0,
) -> T:
    """Run ``fn`` with exponential backoff on transient errors.

    Returns the successful result. Raises the last transient exception once
    retries are exhausted, or any non-transient exception immediately.
    """
    attempt = 0
    while True:
        try:
            return await fn()
        except BaseException as exc:  # noqa: BLE001 — we re-raise non-transient
            if not is_transient(exc) or attempt >= max_retries:
                raise
            delay = min(max_delay_s, base_delay_s * (2 ** attempt))
            delay = delay * (0.5 + random.random())  # full jitter
            log.warning(
                "transient_error_retrying",
                extra={"attempt": attempt + 1, "delay_s": round(delay, 3), "error": repr(exc)},
            )
            await asyncio.sleep(delay)
            attempt += 1
