"""ONNX-runtime classifier auditor.

For users who want CPU inference with no torch dependency. Bring your own
``.onnx`` file plus a pluggable tokenizer (callable returning input_ids /
attention_mask).
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from typing import Any

from ..backends.base import MissingDependencyError
from ..types import AuditPrompt, RawJudgement

Tokenizer = Callable[[str], dict[str, Any]]


class ONNXClassifierAuditor:
    name = "onnx"

    def __init__(
        self,
        model_path: str,
        tokenizer: Tokenizer,
        *,
        threshold: float = 0.5,
        unsafe_index: int = 1,
        providers: list[str] | None = None,
        session: Any = None,
    ) -> None:
        self.model = model_path
        self._tokenizer = tokenizer
        self._threshold = threshold
        self._unsafe_index = unsafe_index
        if session is not None:
            self._session = session
            return
        try:
            import onnxruntime as ort  # type: ignore
        except ImportError as exc:  # pragma: no cover
            raise MissingDependencyError("ONNXClassifierAuditor", "onnx", "onnxruntime") from exc
        self._session = ort.InferenceSession(
            model_path,
            providers=providers or ["CPUExecutionProvider"],
        )

    async def judge(self, prompt: AuditPrompt) -> RawJudgement:
        return await asyncio.to_thread(self._judge_sync, prompt.text)

    def _judge_sync(self, text: str) -> RawJudgement:
        inputs = self._tokenizer(text)
        outputs = self._session.run(None, inputs)
        logits = outputs[0]
        # Softmax for binary or multi-class output.
        import math

        flat = list(logits[0]) if hasattr(logits, "__getitem__") else list(logits)
        m = max(flat)
        exps = [math.exp(x - m) for x in flat]
        s = sum(exps)
        probs = [e / s for e in exps]
        unsafe_score = probs[self._unsafe_index] if self._unsafe_index < len(probs) else 0.0
        passed = unsafe_score < self._threshold
        rationale = "" if passed else f"onnx classifier flagged (score={unsafe_score:.2f})"
        return RawJudgement(passed=passed, rationale=rationale, score=unsafe_score, raw_response=probs)


__all__ = ["ONNXClassifierAuditor"]
