"""prompt_protector — async-first LLM input/output safety layer."""

from .backends import (
    Auditor,
    BatchAuditor,
    DualVoteAuditor,
    MockAuditor,
    VotePolicy,
)
from .heuristics import DetectorRegistry, default_registry
from .protector import PromptProtector
from .redaction import RedactionResult, RedactionStyle, redact, restore
from .rule_packs import (
    NSFW,
    OWASP_LLM_TOP10,
    PII,
    PROMPT_INJECTION,
    SECRETS,
    Rule,
    RulePack,
)
from .types import (
    ENFORCE,
    SHADOW,
    Action,
    AuditEvent,
    AuditResult,
    Category,
    Direction,
    FailureMode,
    Match,
    Mode,
    StageVerdict,
    Turn,
)

__version__ = "1.0.0"


def __getattr__(name: str):
    """Lazy access to optional cloud backends."""
    if name == "OpenAIAuditor":
        from .backends.openai_backend import OpenAIAuditor

        return OpenAIAuditor
    if name == "AnthropicAuditor":
        from .backends.anthropic_backend import AnthropicAuditor

        return AnthropicAuditor
    raise AttributeError(name)


__all__ = [
    "Action",
    "Auditor",
    "AuditEvent",
    "AuditResult",
    "BatchAuditor",
    "Category",
    "DetectorRegistry",
    "Direction",
    "DualVoteAuditor",
    "ENFORCE",
    "FailureMode",
    "Match",
    "MockAuditor",
    "Mode",
    "NSFW",
    "OWASP_LLM_TOP10",
    "PII",
    "PROMPT_INJECTION",
    "PromptProtector",
    "RedactionResult",
    "RedactionStyle",
    "Rule",
    "RulePack",
    "SECRETS",
    "SHADOW",
    "StageVerdict",
    "Turn",
    "VotePolicy",
    "default_registry",
    "redact",
    "restore",
    "__version__",
]
