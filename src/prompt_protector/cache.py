"""Audit-result caches.

Caches are keyed by ``sha256(kind, provider, model, rules, text)`` so a
change to any of those invalidates entries automatically. Values are
``AuditResult`` objects; on ``set`` we freeze the ``matches`` and
``verdicts`` lists to tuples so callers can safely share the same object
without copying on every ``get``.
"""

from __future__ import annotations

import json
import logging
import threading
import time
from collections import OrderedDict
from dataclasses import asdict, replace
from typing import Any, Optional, Protocol, runtime_checkable

from .types import (
    AuditResult,
    Category,
    Match,
    StageVerdict,
)

log = logging.getLogger("prompt_protector")


@runtime_checkable
class Cache(Protocol):
    async def get(self, key: str) -> Optional[AuditResult]: ...

    async def set(self, key: str, value: AuditResult) -> None: ...


class InMemoryLRUCache:
    """Thread-safe LRU cache with per-entry TTL.

    Uses a ``threading.Lock`` rather than ``asyncio.Lock`` so the same
    cache instance can be safely shared across event loops (e.g. when a
    sync caller invokes ``PromptProtector.sanitize_input_sync`` from
    inside a running loop and the worker thread spins its own loop).
    Operations are O(1) and the lock-hold time is microseconds.
    """

    def __init__(self, *, max_entries: int = 10_000, ttl_seconds: float = 600.0) -> None:
        self._max = max_entries
        self._ttl = ttl_seconds
        self._items: "OrderedDict[str, tuple[float, AuditResult]]" = OrderedDict()
        self._lock = threading.Lock()

    async def get(self, key: str) -> Optional[AuditResult]:
        with self._lock:
            entry = self._items.get(key)
            if entry is None:
                return None
            expires_at, value = entry
            if expires_at < time.time():
                self._items.pop(key, None)
                return None
            self._items.move_to_end(key)
            return value  # frozen on set; safe to share

    async def set(self, key: str, value: AuditResult) -> None:
        frozen = _freeze_result(value)
        with self._lock:
            self._items[key] = (time.time() + self._ttl, frozen)
            self._items.move_to_end(key)
            while len(self._items) > self._max:
                self._items.popitem(last=False)

    async def clear(self) -> None:
        with self._lock:
            self._items.clear()

    def __len__(self) -> int:
        return len(self._items)


class RedisCache:
    """Redis-backed cache.

    Serializes ``AuditResult`` to JSON with custom handling for nested
    dataclasses and the ``Category`` enum, then reconstructs the typed
    object on ``get``. Construction validates that the ``redis`` package
    is available; the connection is lazy.
    """

    def __init__(
        self,
        url: str = "redis://localhost:6379/0",
        *,
        prefix: str = "promptprotector:",
        ttl_seconds: float = 600.0,
    ) -> None:
        try:
            import redis.asyncio as redis  # type: ignore
        except ImportError as exc:  # pragma: no cover
            raise ImportError(
                "RedisCache requires the 'redis' package. "
                "Install with: pip install prompt-protector[redis]"
            ) from exc
        self._redis = redis.from_url(url)
        self._prefix = prefix
        self._ttl = ttl_seconds

    async def get(self, key: str) -> Optional[AuditResult]:  # pragma: no cover - integration
        raw = await self._redis.get(self._prefix + key)
        if raw is None:
            return None
        try:
            return _deserialize_result(json.loads(raw))
        except Exception:  # noqa: BLE001
            log.warning("redis_deserialize_failed", extra={"key": key[:8]})
            return None

    async def set(self, key: str, value: AuditResult) -> None:  # pragma: no cover - integration
        payload = json.dumps(_serialize_result(value))
        await self._redis.set(self._prefix + key, payload, ex=int(self._ttl))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _freeze_result(value: AuditResult) -> AuditResult:
    """Return an AuditResult whose mutable lists are tuples.

    Cached entries are shared by reference; freezing prevents one caller
    accidentally mutating the entry that future callers will see. Cheaper
    than a deep copy on every get/set.
    """
    return replace(
        value,
        matches=tuple(value.matches),  # type: ignore[arg-type]
        verdicts=tuple(value.verdicts),  # type: ignore[arg-type]
    )


def _serialize_result(value: AuditResult) -> dict:
    data = asdict(value)
    if value.category is not None:
        data["category"] = value.category.value
    data["matches"] = [_serialize_match(m) for m in value.matches]
    data["verdicts"] = [_serialize_verdict(v) for v in value.verdicts]
    return data


def _serialize_match(m: Match) -> dict:
    return {
        "detector": m.detector,
        "category": m.category.value,
        "span": list(m.span),
        "original": m.original,
        "replacement": m.replacement,
        "score": m.score,
    }


def _serialize_verdict(v: StageVerdict) -> dict:
    return {
        "stage": v.stage,
        "passed": v.passed,
        "category": v.category.value if v.category else None,
        "rationale": v.rationale,
        "score": v.score,
        "latency_ms": v.latency_ms,
    }


def _deserialize_result(data: dict) -> AuditResult:
    cat = data.get("category")
    return AuditResult(
        passed=bool(data.get("passed", False)),
        score=float(data.get("score", 0.0)),
        category=Category(cat) if cat else None,
        rationale=str(data.get("rationale", "")),
        rule_id=data.get("rule_id"),
        matches=tuple(_deserialize_match(m) for m in data.get("matches", [])),  # type: ignore[arg-type]
        redacted_text=data.get("redacted_text"),
        vault_id=data.get("vault_id"),
        provider=str(data.get("provider", "")),
        model=str(data.get("model", "")),
        latency_ms=int(data.get("latency_ms", 0)),
        degraded=bool(data.get("degraded", False)),
        trace_id=data.get("trace_id"),
        verdicts=tuple(_deserialize_verdict(v) for v in data.get("verdicts", [])),  # type: ignore[arg-type]
    )


def _deserialize_match(data: dict) -> Match:
    return Match(
        detector=data["detector"],
        category=Category(data["category"]),
        span=tuple(data["span"]),  # type: ignore[arg-type]
        original=data.get("original", ""),
        replacement=data.get("replacement"),
        score=float(data.get("score", 1.0)),
    )


def _deserialize_verdict(data: dict) -> StageVerdict:
    cat = data.get("category")
    return StageVerdict(
        stage=data["stage"],
        passed=bool(data.get("passed", False)),
        category=Category(cat) if cat else None,
        rationale=str(data.get("rationale", "")),
        score=float(data.get("score", 0.0)),
        latency_ms=int(data.get("latency_ms", 0)),
    )


__all__ = ["Cache", "InMemoryLRUCache", "RedisCache"]
