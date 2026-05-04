"""PromptProtector — the public façade.

Pipeline (per request):

    text in
      → size guard
      → heuristics (sync, no network)
      → local pre-redactors (optional, e.g. Presidio / spaCy)
      → cache lookup (optional)
      → cloud / local LLM auditor (with timeout, retries, fail-mode)
      → cache store
      → final AuditResult

Stages can short-circuit. Failures degrade per ``failure_mode``.
"""

from __future__ import annotations

import asyncio
import atexit
import concurrent.futures
import hashlib
import logging
import random
import threading
import time
import uuid
from dataclasses import replace
from typing import Any, Iterable, Optional, Sequence

from . import _otel
from ._json import JSONParseError
from ._retry import retry_async
from .backends.base import Auditor, BatchAuditor
from .heuristics import DetectorRegistry, default_registry
from .prompts import (
    BATCHED_OUTPUT_AUDITOR_SYSTEM,
    INPUT_AUDITOR_SYSTEM,
    OUTPUT_AUDITOR_SYSTEM,
)
from .redaction import RedactionResult, redact, restore
from .rule_packs import Rule
from .types import (
    AuditEvent,
    AuditPrompt,
    AuditResult,
    Category,
    ENFORCE,
    EventHook,
    FailureMode,
    Match,
    Mode,
    StageVerdict,
    Turn,
)

log = logging.getLogger("prompt_protector")


_DEFAULT_MAX_CONCURRENT_JUDGES = 8


class PromptProtector:
    """Async-first safety layer between a user and an LLM.

    Construct with at minimum an ``auditor``; everything else has sensible
    defaults. To configure declaratively, see ``PromptProtector.from_config``.
    """

    def __init__(
        self,
        *,
        auditor: Optional[Auditor] = None,
        cloud_auditor: Optional[Auditor] = None,
        pre_redactors: Sequence[Any] = (),
        input_rules: Sequence[Any] = (),
        output_rules: Sequence[Any] = (),
        failure_mode: FailureMode = FailureMode.FAIL_CLOSED,
        mode: Mode = ENFORCE,
        timeout_s: float = 10.0,
        max_retries: int = 3,
        max_input_chars: int = 8000,
        on_oversize: str = "reject",  # "reject" | "truncate"
        batch_rules: bool = True,
        max_concurrent_judges: int = _DEFAULT_MAX_CONCURRENT_JUDGES,
        cache: Any = None,
        on_event: Optional[EventHook] = None,
        forward_redacted: bool = False,
        vault: Any = None,
        injection_phrases: Iterable[str] = (),
        detector_registry: Optional[DetectorRegistry] = None,
    ) -> None:
        if auditor is None and cloud_auditor is None and not pre_redactors:
            raise ValueError(
                "PromptProtector needs at least one of: auditor, cloud_auditor, pre_redactors"
            )
        self._auditor = auditor
        self._cloud_auditor = cloud_auditor
        self._pre_redactors = list(pre_redactors)
        self._input_rules = _normalize_rules(input_rules)
        self._output_rules = _normalize_rules(output_rules)
        self._failure_mode = failure_mode
        self._mode = mode
        self._timeout_s = timeout_s
        self._max_retries = max_retries
        self._max_input_chars = max_input_chars
        self._on_oversize = on_oversize
        self._batch_rules = batch_rules
        self._max_concurrent_judges = max(1, max_concurrent_judges)
        self._cache = cache
        self._on_event = on_event
        self._forward_redacted = forward_redacted
        self._vault = vault
        self._registry = detector_registry or default_registry(
            injection_phrases=injection_phrases
        )

        # Memoize the rules-portion of cache keys so we only hash the text per
        # request. Recomputed lazily for per-call rule overrides.
        active = self._auditor or self._cloud_auditor
        provider = getattr(active, "name", "")
        model = getattr(active, "model", "")
        self._cache_key_prefix_input = self._compute_key_prefix("input", provider, model, self._input_rules)
        self._cache_key_prefix_output = self._compute_key_prefix("output", provider, model, self._output_rules)
        self._provider = provider
        self._model = model

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def sanitize_input(
        self,
        text: str,
        *,
        history: Sequence[Turn] = (),
        rules: Optional[Sequence[Any]] = None,
        trace_id: Optional[str] = None,
    ) -> AuditResult:
        return await self._sanitize(
            text=text,
            kind="input",
            history=tuple(history),
            rules=_normalize_rules(rules) if rules is not None else self._input_rules,
            rules_overridden=rules is not None,
            system=INPUT_AUDITOR_SYSTEM,
            trace_id=trace_id,
        )

    async def sanitize_output(
        self,
        text: str,
        *,
        history: Sequence[Turn] = (),
        rules: Optional[Sequence[Any]] = None,
        trace_id: Optional[str] = None,
    ) -> AuditResult:
        return await self._sanitize(
            text=text,
            kind="output",
            history=tuple(history),
            rules=_normalize_rules(rules) if rules is not None else self._output_rules,
            rules_overridden=rules is not None,
            system=OUTPUT_AUDITOR_SYSTEM,
            trace_id=trace_id,
        )

    def sanitize_input_sync(self, text: str, **kwargs: Any) -> AuditResult:
        return _run_sync(self.sanitize_input(text, **kwargs), self._timeout_s)

    def sanitize_output_sync(self, text: str, **kwargs: Any) -> AuditResult:
        return _run_sync(self.sanitize_output(text, **kwargs), self._timeout_s)

    def redact(self, text: str) -> RedactionResult:
        """Run heuristic redaction without any LLM call."""
        return redact(text, registry=self._registry)

    def unredact(self, text: str, vault_id: str) -> str:
        if self._vault is None:
            raise RuntimeError("no vault configured; cannot unredact")
        mapping = self._vault.get(vault_id)
        return restore(text, mapping)

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    async def _sanitize(
        self,
        *,
        text: str,
        kind: str,
        history: tuple[Turn, ...],
        rules: list[Rule],
        rules_overridden: bool,
        system: str,
        trace_id: Optional[str],
    ) -> AuditResult:
        trace_id = trace_id or uuid.uuid4().hex
        start = time.monotonic()
        verdicts: list[StageVerdict] = []

        # --- 0. sample-out gate
        if self._mode.kind == "sample" and random.random() > self._mode.sample_rate:
            return self._build_result(
                passed=True,
                rationale="sampled out",
                verdicts=verdicts,
                start=start,
                trace_id=trace_id,
                provider="sampler",
            )

        # --- 1. size guard
        if len(text) > self._max_input_chars:
            if self._on_oversize == "reject":
                result = self._build_result(
                    passed=False,
                    score=1.0,
                    category=Category.OTHER,
                    rationale=f"input exceeds {self._max_input_chars} chars",
                    verdicts=verdicts,
                    start=start,
                    trace_id=trace_id,
                    provider="size_guard",
                )
                result = self._maybe_shadow(result)
                self._emit(kind, result)
                return result
            text = text[: self._max_input_chars]

        # --- 2. heuristics
        heur_matches = self._registry.scan(text)
        heur_block = _consider_heuristic_block(heur_matches)
        if heur_block is not None:
            result = self._build_result(
                passed=False,
                score=heur_block.score,
                category=heur_block.category,
                rationale=f"heuristic match: {heur_block.detector}",
                matches=heur_matches,
                verdicts=verdicts + [
                    StageVerdict(
                        stage="heuristics",
                        passed=False,
                        category=heur_block.category,
                        rationale=heur_block.detector,
                        score=heur_block.score,
                    )
                ],
                start=start,
                trace_id=trace_id,
                provider="heuristics",
            )
            result = self._maybe_shadow(result)
            self._emit(kind, result)
            return result
        verdicts.append(
            StageVerdict(stage="heuristics", passed=True, category=None, rationale="", score=0.0)
        )

        # --- 3. local pre-redactors
        redacted_text = text
        all_matches: list[Match] = list(heur_matches)
        vault_id: Optional[str] = None
        for redactor in self._pre_redactors:
            r = redactor.redact(redacted_text)
            redacted_text = r.redacted_text
            all_matches.extend(r.matches)
            if r.mapping and self._vault is not None:
                vault_id = vault_id or uuid.uuid4().hex
                self._vault.put(vault_id, r.mapping)
            verdicts.append(
                StageVerdict(
                    stage=f"redactor:{getattr(redactor, 'name', type(redactor).__name__)}",
                    passed=True,
                    category=Category.PII if r.matches else None,
                    rationale=f"{len(r.matches)} matches",
                    score=0.0,
                )
            )

        text_changed = redacted_text != text
        text_for_audit = redacted_text if self._forward_redacted else text

        # --- 4. cache lookup (only when caching is configured)
        cache_key: Optional[str] = None
        if self._cache is not None:
            cache_key = self._cache_key(kind, text_for_audit, rules, rules_overridden)
            try:
                cached = await self._cache.get(cache_key)
            except Exception:  # noqa: BLE001 — cache must never break a request
                log.warning("cache_get_failed", extra={"key": cache_key[:8]})
                cached = None
            if cached is not None:
                cached = replace(
                    cached,
                    trace_id=trace_id,
                    latency_ms=int((time.monotonic() - start) * 1000),
                    verdicts=list(verdicts) + list(cached.verdicts),
                    redacted_text=redacted_text if text_changed else None,
                    vault_id=vault_id,
                )
                cached = self._maybe_shadow(cached)
                self._emit(kind, cached)
                return cached

        # --- 5. LLM auditor stage
        active_auditor = self._auditor or self._cloud_auditor
        if active_auditor is None:
            result = self._build_result(
                passed=True,
                rationale="no auditor; heuristics-only verdict",
                matches=all_matches,
                redacted_text=redacted_text if text_changed else None,
                vault_id=vault_id,
                verdicts=verdicts,
                start=start,
                trace_id=trace_id,
                provider="local_only",
            )
            await self._cache_store(cache_key, result)
            result = self._maybe_shadow(result)
            self._emit(kind, result)
            return result

        try:
            with _otel.span("prompt_protector.sanitize_" + kind, trace_id=trace_id):
                judgement = await self._run_auditor(
                    auditor=active_auditor,
                    kind=kind,
                    text=text_for_audit,
                    history=history,
                    rules=rules,
                    system=system,
                )
        except _AuditorFailure as fail:
            result = self._apply_failure_mode(
                fail,
                matches=all_matches,
                redacted_text=redacted_text if text_changed else None,
                vault_id=vault_id,
                verdicts=verdicts,
                start=start,
                trace_id=trace_id,
            )
            result = self._maybe_shadow(result)
            self._emit(kind, result, error=str(fail.cause))
            return result

        verdicts.append(
            StageVerdict(
                stage=f"auditor:{judgement.provider}",
                passed=judgement.result.passed,
                category=judgement.result.category,
                rationale=judgement.result.rationale,
                score=judgement.result.score,
            )
        )
        result = judgement.result
        result.matches = list(all_matches) + list(result.matches)
        result.redacted_text = redacted_text if text_changed else None
        result.vault_id = vault_id
        result.verdicts = verdicts
        result.trace_id = trace_id
        result.latency_ms = int((time.monotonic() - start) * 1000)
        if judgement.degraded:
            result.degraded = True

        await self._cache_store(cache_key, result)
        result = self._maybe_shadow(result)
        self._emit(kind, result)
        return result

    # --- auditor orchestration -----------------------------------------

    async def _run_auditor(
        self,
        *,
        auditor: Auditor,
        kind: str,
        text: str,
        history: tuple[Turn, ...],
        rules: list[Rule],
        system: str,
    ) -> "_Judgement":
        try:
            if not rules:
                judged = await self._call_with_policy(
                    lambda: auditor.judge(
                        AuditPrompt(
                            text=text,
                            rule="(no specific rule — apply your default policy)",
                            system_instructions=system,
                            history=history,
                        )
                    )
                )
                return _Judgement(
                    provider=auditor.name,
                    result=AuditResult(
                        passed=judged.passed,
                        score=judged.score,
                        category=None if judged.passed else Category.OTHER,
                        rationale=judged.rationale,
                        provider=auditor.name,
                        model=auditor.model,
                    ),
                )

            if (
                kind == "output"
                and self._batch_rules
                and isinstance(auditor, BatchAuditor)
                and len(rules) > 1
            ):
                judgements = await self._call_with_policy(
                    lambda: auditor.judge_batch(
                        text=text,
                        rules=[r.text for r in rules],
                        system_instructions=BATCHED_OUTPUT_AUDITOR_SYSTEM,
                    )
                )
                for rule, j in zip(rules, judgements):
                    if not j.passed:
                        return _Judgement(
                            provider=auditor.name,
                            result=AuditResult(
                                passed=False,
                                score=j.score or 1.0,
                                category=rule.category,
                                rationale=j.rationale,
                                rule_id=rule.id,
                                provider=auditor.name,
                                model=auditor.model,
                            ),
                        )
                return _Judgement(
                    provider=auditor.name,
                    result=AuditResult(passed=True, provider=auditor.name, model=auditor.model),
                )

            return await self._judge_per_rule(auditor, rules, text, history, system)

        except Exception as exc:
            # CancelledError / KeyboardInterrupt are BaseException — they
            # propagate naturally and shutdown isn't swallowed.
            raise _AuditorFailure(cause=exc) from exc

    async def _judge_per_rule(
        self,
        auditor: Auditor,
        rules: list[Rule],
        text: str,
        history: tuple[Turn, ...],
        system: str,
    ) -> "_Judgement":
        sem = asyncio.Semaphore(self._max_concurrent_judges)
        succeeded = 0
        last_exc: Optional[BaseException] = None

        async def judge_one(rule: Rule):
            async with sem:
                try:
                    j = await self._call_with_policy(
                        lambda: auditor.judge(
                            AuditPrompt(
                                text=text,
                                rule=rule.text,
                                system_instructions=system,
                                history=history,
                            )
                        )
                    )
                except asyncio.CancelledError:
                    raise
                except Exception as exc:
                    log.warning(
                        "rule_judge_failed",
                        extra={"rule_id": rule.id, "error": repr(exc)},
                    )
                    return rule, None, exc
                return rule, j, None

        tasks = [asyncio.create_task(judge_one(r)) for r in rules]
        try:
            for fut in asyncio.as_completed(tasks):
                rule, j, exc = await fut
                if j is None:
                    last_exc = exc
                    continue
                succeeded += 1
                if not j.passed:
                    return _Judgement(
                        provider=auditor.name,
                        result=AuditResult(
                            passed=False,
                            score=j.score or 1.0,
                            category=rule.category,
                            rationale=j.rationale,
                            rule_id=rule.id,
                            provider=auditor.name,
                            model=auditor.model,
                        ),
                        degraded=succeeded < len(rules),
                    )
        finally:
            for t in tasks:
                if not t.done():
                    t.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)

        # If literally no rule's judge succeeded, treat it as a complete
        # auditor failure so the outer failure-mode policy (FAIL_CLOSED by
        # default) kicks in. Otherwise, if at least one rule passed, we
        # return passed=True with degraded=True — partial coverage is
        # better than no coverage.
        if succeeded == 0:
            raise _AuditorFailure(cause=last_exc or RuntimeError("all rule judgements failed"))
        return _Judgement(
            provider=auditor.name,
            result=AuditResult(passed=True, provider=auditor.name, model=auditor.model),
            degraded=succeeded < len(rules),
        )

    async def _call_with_policy(self, awaitable_factory) -> Any:
        """Run an async call with timeout + retry on transient errors."""
        return await retry_async(
            lambda: asyncio.wait_for(awaitable_factory(), timeout=self._timeout_s),
            max_retries=self._max_retries,
        )

    # --- failure mode + shadow + result builder ------------------------

    def _apply_failure_mode(
        self,
        fail: "_AuditorFailure",
        *,
        matches: list[Match],
        redacted_text: Optional[str],
        vault_id: Optional[str],
        verdicts: list[StageVerdict],
        start: float,
        trace_id: str,
    ) -> AuditResult:
        log.warning(
            "auditor_failed",
            extra={
                "error": repr(fail.cause),
                "failure_mode": self._failure_mode.value,
                "trace_id": trace_id,
            },
        )
        passed = self._failure_mode is FailureMode.FAIL_OPEN
        rationale = (
            "auditor unavailable; failing open"
            if passed
            else "auditor unavailable; failing closed"
        )
        return self._build_result(
            passed=passed,
            score=0.0 if passed else 0.5,
            category=None if passed else Category.OTHER,
            rationale=rationale,
            matches=matches,
            redacted_text=redacted_text,
            vault_id=vault_id,
            verdicts=verdicts + [
                StageVerdict(
                    stage="auditor",
                    passed=passed,
                    category=None if passed else Category.OTHER,
                    rationale=rationale,
                    score=0.0,
                )
            ],
            start=start,
            trace_id=trace_id,
            provider="failure_mode",
            degraded=True,
        )

    def _maybe_shadow(self, result: AuditResult) -> AuditResult:
        if self._mode.kind != "shadow":
            return result
        if not result.passed:
            log.info(
                "shadow_violation",
                extra={
                    "category": result.category.value if result.category else None,
                    "rule_id": result.rule_id,
                    "rationale": result.rationale,
                    "trace_id": result.trace_id,
                },
            )
            return replace(
                result,
                passed=True,
                rationale=f"[shadow] would-block: {result.rationale}",
            )
        return result

    def _build_result(
        self,
        *,
        passed: bool,
        rationale: str,
        verdicts: list[StageVerdict],
        start: float,
        trace_id: str,
        provider: str,
        score: float = 0.0,
        category: Optional[Category] = None,
        matches: Optional[list[Match]] = None,
        redacted_text: Optional[str] = None,
        vault_id: Optional[str] = None,
        degraded: bool = False,
    ) -> AuditResult:
        return AuditResult(
            passed=passed,
            score=score,
            category=category,
            rationale=rationale,
            matches=list(matches or []),
            redacted_text=redacted_text,
            vault_id=vault_id,
            provider=provider,
            model=self._model,
            latency_ms=int((time.monotonic() - start) * 1000),
            degraded=degraded,
            trace_id=trace_id,
            verdicts=list(verdicts),
        )

    # --- caching helpers -----------------------------------------------

    def _compute_key_prefix(
        self,
        kind: str,
        provider: str,
        model: str,
        rules: list[Rule],
    ) -> str:
        rules_repr = "|".join(sorted(r.id + ":" + r.text for r in rules))
        return f"{kind}\x1f{provider}\x1f{model}\x1f{rules_repr}\x1f"

    def _cache_key(
        self,
        kind: str,
        text: str,
        rules: list[Rule],
        rules_overridden: bool,
    ) -> str:
        if rules_overridden:
            prefix = self._compute_key_prefix(kind, self._provider, self._model, rules)
        else:
            prefix = (
                self._cache_key_prefix_input
                if kind == "input"
                else self._cache_key_prefix_output
            )
        return hashlib.sha256((prefix + text).encode("utf-8")).hexdigest()

    async def _cache_store(self, key: Optional[str], result: AuditResult) -> None:
        if key is None or self._cache is None:
            return
        try:
            await self._cache.set(key, result)
        except Exception:  # noqa: BLE001 — cache must never break a request
            log.warning("cache_set_failed", extra={"key": key[:8]})

    # --- event emission ------------------------------------------------

    def _emit(self, kind: str, result: AuditResult, error: Optional[str] = None) -> None:
        if self._on_event is None:
            return
        try:
            self._on_event(
                AuditEvent(
                    kind=kind,
                    passed=result.passed,
                    category=result.category,
                    rule_id=result.rule_id,
                    provider=result.provider,
                    model=result.model,
                    latency_ms=result.latency_ms,
                    degraded=result.degraded,
                    trace_id=result.trace_id,
                    error=error,
                )
            )
        except Exception:  # noqa: BLE001 — never let observability break the request
            log.exception("on_event hook raised")

    # ------------------------------------------------------------------
    # Convenience constructors
    # ------------------------------------------------------------------

    @classmethod
    def from_config(cls, path: str) -> "PromptProtector":
        from .config import build_protector, load_config_file

        cfg = load_config_file(path)
        return build_protector(cfg)

    @classmethod
    def from_config_dict(cls, data: dict) -> "PromptProtector":
        from .config import build_protector, load_config_dict

        cfg = load_config_dict(data)
        return build_protector(cfg)

    @classmethod
    def from_config_env(cls, env_var: str = "PROMPT_PROTECTOR_CONFIG") -> "PromptProtector":
        import json
        import os

        raw = os.getenv(env_var)
        if not raw:
            raise RuntimeError(f"env var {env_var} not set")
        if raw.strip().startswith("{"):
            return cls.from_config_dict(json.loads(raw))
        return cls.from_config(raw)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class _AuditorFailure(Exception):
    def __init__(self, cause: BaseException) -> None:
        super().__init__(repr(cause))
        self.cause = cause


class _Judgement:
    __slots__ = ("provider", "result", "degraded")

    def __init__(
        self,
        *,
        provider: str,
        result: AuditResult,
        degraded: bool = False,
    ) -> None:
        self.provider = provider
        self.result = result
        self.degraded = degraded


def _normalize_rules(rules: Optional[Sequence[Any]]) -> list[Rule]:
    if not rules:
        return []
    out: list[Rule] = []
    for item in rules:
        if isinstance(item, Rule):
            out.append(item)
        elif isinstance(item, str):
            out.append(Rule(id=f"rule.{len(out)}", text=item))
        else:
            try:
                out.extend(_normalize_rules(list(item)))
            except TypeError:
                raise TypeError(f"unsupported rule type: {type(item).__name__}")
    return out


def _consider_heuristic_block(matches: list[Match]) -> Optional[Match]:
    if not matches:
        return None
    blocking = [m for m in matches if m.score >= 0.85]
    if not blocking:
        return None
    return max(blocking, key=lambda m: m.score)


# ---------------------------------------------------------------------------
# Sync-from-async runner
# ---------------------------------------------------------------------------


class _SyncRunner:
    """One long-lived event loop in a worker thread.

    Reused across ``sanitize_input_sync`` / ``sanitize_output_sync`` calls
    so we don't pay the cost of creating + tearing down a fresh loop per
    invocation. Started lazily on first use, shut down at process exit.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._thread: Optional[threading.Thread] = None

    def submit(self, coro, timeout: float):
        loop = self._ensure_loop()
        future = asyncio.run_coroutine_threadsafe(coro, loop)
        try:
            return future.result(timeout=timeout + 1.0)
        except concurrent.futures.TimeoutError as exc:
            future.cancel()
            raise TimeoutError(
                f"sync wrapper timed out after {timeout + 1.0}s waiting on background loop"
            ) from exc

    def _ensure_loop(self) -> asyncio.AbstractEventLoop:
        with self._lock:
            if self._loop is not None and self._loop.is_running():
                return self._loop
            self._loop = asyncio.new_event_loop()
            self._thread = threading.Thread(
                target=self._loop.run_forever,
                name="prompt-protector-sync-runner",
                daemon=True,
            )
            self._thread.start()
            atexit.register(self._shutdown)
            return self._loop

    def _shutdown(self) -> None:
        loop = self._loop
        if loop is None or not loop.is_running():
            return
        loop.call_soon_threadsafe(loop.stop)
        if self._thread is not None:
            self._thread.join(timeout=2.0)


_SYNC_RUNNER = _SyncRunner()


def _run_sync(coro, timeout: float):
    """Run an async coroutine from a sync caller, even from inside an event loop.

    Outside any event loop: just ``asyncio.run``.
    Inside a running loop: dispatch to a long-lived background loop with a
    bounded wait so a stuck auditor can't hang the calling thread forever.
    """
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)
    return _SYNC_RUNNER.submit(coro, timeout)


__all__ = ["PromptProtector"]
