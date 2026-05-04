"""Output-schema validation.

For LLMs that produce structured output, validate the response against a
schema in the same audit step. Two backends are supported and tried in
order: pydantic (``BaseModel`` subclass) and jsonschema (dict). Both are
optional — only the backend you use needs to be installed.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class SchemaCheckResult:
    passed: bool
    error: str | None = None


SchemaLike = dict | type | Any


def check_output_schema(text: str, schema: SchemaLike) -> SchemaCheckResult:
    """Validate ``text`` is JSON conforming to ``schema``.

    ``schema`` may be:
    * a pydantic ``BaseModel`` subclass — uses ``model_validate_json``.
    * a JSON Schema ``dict`` — uses ``jsonschema``.

    Returns ``passed=False`` with an error string when validation fails or
    the requested backend isn't installed.
    """
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        return SchemaCheckResult(passed=False, error=f"not valid JSON: {exc.msg}")

    if isinstance(schema, dict):
        try:
            import jsonschema  # type: ignore
        except ImportError:
            return SchemaCheckResult(
                passed=False,
                error="schema is a dict but jsonschema is not installed (pip install jsonschema)",
            )
        try:
            jsonschema.validate(instance=data, schema=schema)
        except jsonschema.ValidationError as exc:  # type: ignore
            return SchemaCheckResult(passed=False, error=f"schema mismatch: {exc.message}")
        return SchemaCheckResult(passed=True)

    if isinstance(schema, type):
        try:
            from pydantic import BaseModel  # type: ignore
        except ImportError:
            return SchemaCheckResult(
                passed=False,
                error="schema is a class but pydantic is not installed (pip install pydantic)",
            )
        if issubclass(schema, BaseModel):
            try:
                schema.model_validate(data)
            except Exception as exc:  # noqa: BLE001
                return SchemaCheckResult(passed=False, error=f"pydantic validation failed: {exc}")
            return SchemaCheckResult(passed=True)

    return SchemaCheckResult(passed=False, error=f"unsupported schema type: {type(schema)}")


__all__ = ["SchemaCheckResult", "check_output_schema"]
