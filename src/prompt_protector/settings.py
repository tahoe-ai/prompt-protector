"""Environment-derived defaults.

Used only as fallbacks when an explicit value isn't passed to the backend
or protector. The old ``OPEN_AI_KEY`` name is retained as a compatibility
alias because some 0.x deployments still use it.
"""

from __future__ import annotations

import os


def _first_env(*names: str) -> str | None:
    for name in names:
        value = os.getenv(name)
        if value:
            return value
    return None


OPENAI_API_KEY = _first_env("OPENAI_API_KEY", "OPEN_AI_KEY")
ANTHROPIC_API_KEY = _first_env("ANTHROPIC_API_KEY")


def reload_env() -> None:
    """Refresh module-level keys from the current process environment."""
    global OPENAI_API_KEY, ANTHROPIC_API_KEY
    OPENAI_API_KEY = _first_env("OPENAI_API_KEY", "OPEN_AI_KEY")
    ANTHROPIC_API_KEY = _first_env("ANTHROPIC_API_KEY")


__all__ = ["ANTHROPIC_API_KEY", "OPENAI_API_KEY", "reload_env"]
