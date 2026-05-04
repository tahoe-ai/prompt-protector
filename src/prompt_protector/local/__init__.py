"""Local-model layer: redactors and auditors that run in-process.

Every backend below is an *optional extra* — importing the class will
raise ``MissingDependencyError`` with the exact ``pip install`` command if
the optional dependency is missing.
"""

from .base import (
    LocalAuditor,
    LocalRedactor,
    LocalRedactionResult,
    RedactionVault,
)
from .vault import EncryptedFileVault, InMemoryVault

__all__ = [
    "EncryptedFileVault",
    "InMemoryVault",
    "LocalAuditor",
    "LocalRedactor",
    "LocalRedactionResult",
    "RedactionVault",
]


def __getattr__(name: str):
    if name == "PresidioRedactor":
        from .presidio_backend import PresidioRedactor

        return PresidioRedactor
    if name == "SpacyNERRedactor":
        from .spacy_backend import SpacyNERRedactor

        return SpacyNERRedactor
    if name == "TransformersClassifierAuditor":
        from .transformers_backend import TransformersClassifierAuditor

        return TransformersClassifierAuditor
    if name == "ONNXClassifierAuditor":
        from .onnx_backend import ONNXClassifierAuditor

        return ONNXClassifierAuditor
    if name == "OllamaAuditor":
        from .ollama_backend import OllamaAuditor

        return OllamaAuditor
    if name == "LlamaCppAuditor":
        from .llamacpp_backend import LlamaCppAuditor

        return LlamaCppAuditor
    raise AttributeError(name)
