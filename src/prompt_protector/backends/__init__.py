from .base import Auditor, BatchAuditor
from .composite import DualVoteAuditor, VotePolicy
from .mock import MockAuditor

__all__ = [
    "Auditor",
    "BatchAuditor",
    "DualVoteAuditor",
    "MockAuditor",
    "VotePolicy",
]


def __getattr__(name: str):
    """Lazy-import optional cloud backends so users without those SDKs still get the package."""
    if name == "OpenAIAuditor":
        from .openai_backend import OpenAIAuditor

        return OpenAIAuditor
    if name == "AnthropicAuditor":
        from .anthropic_backend import AnthropicAuditor

        return AnthropicAuditor
    raise AttributeError(name)
