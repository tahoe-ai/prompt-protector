"""HuggingFace transformers-backed local classifier auditor.

Wraps any ``text-classification`` model (e.g. ``ProtectAI/deberta-v3-
base-prompt-injection-v2``, Meta Llama-Guard, IBM Granite Guardian, BERT
toxicity). The pipeline is built once and reused.

Inference runs in a thread (`asyncio.to_thread`) so the event loop isn't
blocked on a synchronous PyTorch forward pass.
"""

from __future__ import annotations

import asyncio
import threading
from typing import Any

from ..backends.base import MissingDependencyError
from ..types import AuditPrompt, RawJudgement


class TransformersClassifierAuditor:
    name = "transformers"

    def __init__(
        self,
        model: str,
        *,
        device: str = "cpu",
        threshold: float = 0.5,
        unsafe_label: str | None = None,
        pipeline: Any = None,
    ) -> None:
        self.model = model
        self._threshold = threshold
        self._unsafe_label = unsafe_label
        # HuggingFace pipelines are not safe under concurrent access
        # (shared tokenizer / model state). Serialize calls so the same
        # pipeline can be reused across requests without crashes or
        # silently-wrong scores.
        self._pipe_lock = threading.Lock()
        if pipeline is not None:
            self._pipe = pipeline
            return
        try:
            from transformers import pipeline as hf_pipeline  # type: ignore
        except ImportError as exc:  # pragma: no cover
            raise MissingDependencyError(
                "TransformersClassifierAuditor", "transformers", "transformers"
            ) from exc
        self._pipe = hf_pipeline(
            "text-classification",
            model=model,
            device=device,
            top_k=None,
        )

    async def judge(self, prompt: AuditPrompt) -> RawJudgement:
        return await asyncio.to_thread(self._judge_sync, prompt.text)

    def _judge_sync(self, text: str) -> RawJudgement:
        with self._pipe_lock:
            results = self._pipe(text)
        # transformers returns either list[dict] or list[list[dict]] depending on top_k.
        scores = results[0] if results and isinstance(results[0], list) else results

        # Determine "unsafe" score. If a specific label is configured use it;
        # otherwise pick the max score among labels that look like negative
        # signals.
        unsafe_score = 0.0
        if self._unsafe_label:
            for s in scores:
                if str(s.get("label", "")).lower() == self._unsafe_label.lower():
                    unsafe_score = float(s.get("score", 0.0))
                    break
        else:
            negative_keywords = ("inject", "unsafe", "toxic", "harmful", "hate", "label_1", "1")
            for s in scores:
                label = str(s.get("label", "")).lower()
                if any(k in label for k in negative_keywords):
                    unsafe_score = max(unsafe_score, float(s.get("score", 0.0)))

        passed = unsafe_score < self._threshold
        rationale = "" if passed else f"local classifier flagged (score={unsafe_score:.2f})"
        return RawJudgement(
            passed=passed,
            rationale=rationale,
            score=unsafe_score,
            raw_response=scores,
        )


__all__ = ["TransformersClassifierAuditor"]
