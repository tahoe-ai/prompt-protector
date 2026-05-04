"""Microsoft Presidio (free, MIT-licensed OSS) PII redactor.

Runs entirely locally — no calls to Microsoft. Wraps ``presidio-analyzer``
+ ``presidio-anonymizer`` and translates back into our ``Match`` shape.
"""

from __future__ import annotations

from typing import Iterable, Optional

from ..types import Category, Match
from ..backends.base import MissingDependencyError
from .base import LocalRedactionResult


_DEFAULT_ENTITIES = (
    "PERSON",
    "EMAIL_ADDRESS",
    "PHONE_NUMBER",
    "CREDIT_CARD",
    "US_SSN",
    "IP_ADDRESS",
    "LOCATION",
    "DATE_TIME",
    "URL",
)


class PresidioRedactor:
    name = "presidio"

    def __init__(
        self,
        *,
        entities: Iterable[str] = _DEFAULT_ENTITIES,
        operator: str = "replace",
        score_threshold: float = 0.4,
        language: str = "en",
        reversible: bool = False,
        analyzer: object = None,
        anonymizer: object = None,
        custom_recognizers: Optional[list[dict]] = None,
    ) -> None:
        try:
            from presidio_analyzer import AnalyzerEngine, PatternRecognizer, Pattern  # type: ignore
            from presidio_anonymizer import AnonymizerEngine  # type: ignore
            from presidio_anonymizer.entities import OperatorConfig  # type: ignore
        except ImportError as exc:  # pragma: no cover
            raise MissingDependencyError("PresidioRedactor", "presidio", "presidio-analyzer") from exc

        self._entities = list(entities)
        self._operator_name = operator
        self._score_threshold = score_threshold
        self._language = language
        self._reversible = reversible
        self._OperatorConfig = OperatorConfig
        self._analyzer = analyzer or AnalyzerEngine()
        self._anonymizer = anonymizer or AnonymizerEngine()

        for spec in custom_recognizers or []:
            patterns = [Pattern(name=spec["name"], regex=spec["pattern"], score=spec.get("score", 0.85))]
            recognizer = PatternRecognizer(
                supported_entity=spec.get("entity", spec["name"].upper()),
                patterns=patterns,
            )
            self._analyzer.registry.add_recognizer(recognizer)
            entity = spec.get("entity", spec["name"].upper())
            if entity not in self._entities:
                self._entities.append(entity)

    def redact(self, text: str) -> LocalRedactionResult:
        if not text:
            return LocalRedactionResult(redacted_text=text)

        analysis = self._analyzer.analyze(
            text=text,
            language=self._language,
            entities=self._entities,
            score_threshold=self._score_threshold,
        )
        if not analysis:
            return LocalRedactionResult(redacted_text=text)

        # Build operator config keyed per entity. For numbered/reversible mode we
        # post-process the anonymizer output ourselves so we can keep a mapping.
        if self._reversible:
            return self._reversible_redact(text, analysis)

        operators = {entity: self._OperatorConfig(self._operator_name, {}) for entity in self._entities}
        if self._operator_name == "replace":
            operators = {
                entity: self._OperatorConfig("replace", {"new_value": f"[REDACTED:{entity}]"})
                for entity in self._entities
            }
        result = self._anonymizer.anonymize(
            text=text,
            analyzer_results=analysis,
            operators=operators,
        )
        matches = [
            Match(
                detector=f"presidio:{r.entity_type.lower()}",
                category=_entity_category(r.entity_type),
                span=(r.start, r.end),
                original=text[r.start : r.end],
                replacement=f"[REDACTED:{r.entity_type}]",
                score=float(r.score),
            )
            for r in analysis
        ]
        return LocalRedactionResult(redacted_text=result.text, matches=matches)

    def _reversible_redact(self, text: str, analysis) -> LocalRedactionResult:
        """Replace right-to-left so spans don't shift; build numbered placeholders."""
        ordered = sorted(analysis, key=lambda r: r.start)
        # Filter overlaps — keep the first.
        filtered = []
        last_end = -1
        for r in ordered:
            if r.start >= last_end:
                filtered.append(r)
                last_end = r.end

        counters: dict[str, int] = {}
        mapping: list[tuple[str, str]] = []
        matches: list[Match] = []
        # Build right-to-left.
        out = list(text)
        for r in reversed(filtered):
            counters[r.entity_type] = counters.get(r.entity_type, 0) + 1
            placeholder = f"[{r.entity_type}_{counters[r.entity_type]}]"
            original = text[r.start : r.end]
            mapping.append((placeholder, original))
            matches.append(
                Match(
                    detector=f"presidio:{r.entity_type.lower()}",
                    category=_entity_category(r.entity_type),
                    span=(r.start, r.end),
                    original=original,
                    replacement=placeholder,
                    score=float(r.score),
                )
            )
            out[r.start : r.end] = placeholder
        mapping.reverse()
        matches.reverse()
        return LocalRedactionResult(redacted_text="".join(out), matches=matches, mapping=mapping)


def _entity_category(entity_type: str) -> Category:
    et = entity_type.upper()
    if et in {"US_SSN", "EMAIL_ADDRESS", "PHONE_NUMBER", "CREDIT_CARD", "PERSON",
              "LOCATION", "DATE_TIME", "IP_ADDRESS", "US_DRIVER_LICENSE", "US_PASSPORT",
              "US_BANK_NUMBER", "MEDICAL_LICENSE", "URL"}:
        return Category.PII
    return Category.OTHER


__all__ = ["PresidioRedactor"]
