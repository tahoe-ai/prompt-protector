"""Lightweight spaCy NER redactor for PERSON / ORG / GPE / LOC."""

from __future__ import annotations

from collections.abc import Iterable

from ..backends.base import MissingDependencyError
from ..types import Category, Match
from .base import LocalRedactionResult


class SpacyNERRedactor:
    name = "spacy_ner"

    def __init__(
        self,
        *,
        model: str = "en_core_web_sm",
        entities: Iterable[str] = ("PERSON", "ORG", "GPE", "LOC"),
        nlp: object | None = None,
    ) -> None:
        if nlp is not None:
            self._nlp = nlp
        else:
            try:
                import spacy  # type: ignore
            except ImportError as exc:  # pragma: no cover
                raise MissingDependencyError("SpacyNERRedactor", "spacy", "spacy") from exc
            try:
                self._nlp = spacy.load(model)
            except OSError as exc:  # pragma: no cover
                raise RuntimeError(
                    f"spaCy model {model!r} is not installed. "
                    f"Install with: python -m spacy download {model}"
                ) from exc
        self._entities = set(e.upper() for e in entities)

    def redact(self, text: str) -> LocalRedactionResult:
        if not text:
            return LocalRedactionResult(redacted_text=text)
        doc = self._nlp(text)
        matches: list[Match] = []
        for ent in doc.ents:
            if ent.label_ not in self._entities:
                continue
            matches.append(
                Match(
                    detector=f"spacy:{ent.label_.lower()}",
                    category=Category.PII,
                    span=(ent.start_char, ent.end_char),
                    original=ent.text,
                    replacement=f"[REDACTED:{ent.label_}]",
                    score=0.85,
                )
            )
        if not matches:
            return LocalRedactionResult(redacted_text=text, matches=[])

        # Right-to-left replace.
        out = list(text)
        for m in reversed(sorted(matches, key=lambda x: x.span[0])):
            out[m.span[0] : m.span[1]] = m.replacement or "[REDACTED]"
        return LocalRedactionResult(redacted_text="".join(out), matches=matches)


__all__ = ["SpacyNERRedactor"]
