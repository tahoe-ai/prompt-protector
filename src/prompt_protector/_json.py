"""Tolerant JSON extraction.

Cloud LLMs are pretty good at returning JSON when asked, but not perfect —
especially smaller / older models. We try strict parse first, then fall back
to extracting the first balanced ``{...}`` block. If both fail, we raise so
the caller can apply its failure-mode policy.
"""

from __future__ import annotations

import json
from typing import Any


class JSONParseError(ValueError):
    """Raised when neither strict nor tolerant parsing succeeds."""


def parse_json_object(text: str) -> dict[str, Any]:
    text = (text or "").strip()
    if not text:
        raise JSONParseError("empty response")

    try:
        obj = json.loads(text)
    except json.JSONDecodeError:
        obj = _extract_balanced(text)

    if not isinstance(obj, dict):
        raise JSONParseError(f"expected JSON object, got {type(obj).__name__}")
    return obj


def _extract_balanced(text: str) -> Any:
    """Return the first balanced ``{...}`` substring parsed as JSON."""
    start = text.find("{")
    if start < 0:
        raise JSONParseError("no JSON object found in response")
    depth = 0
    in_string = False
    escape = False
    for i in range(start, len(text)):
        ch = text[i]
        if escape:
            escape = False
            continue
        if ch == "\\":
            escape = True
            continue
        if ch == '"':
            in_string = not in_string
            continue
        if in_string:
            continue
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                snippet = text[start : i + 1]
                try:
                    return json.loads(snippet)
                except json.JSONDecodeError as e:
                    raise JSONParseError(f"unbalanced JSON: {e}") from e
    raise JSONParseError("unterminated JSON object")
