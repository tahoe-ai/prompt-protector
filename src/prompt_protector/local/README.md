# `prompt_protector.local` — on-prem redactors and auditors

Everything in this package runs locally. No internet egress, no third-
party API calls. Use this layer when you need to keep sensitive data on
your hosts and / or want a fast, cheap first-pass before hitting a cloud
LLM judge.

## What's here

| File | Role |
|------|------|
| `base.py` | `LocalRedactor`, `LocalAuditor`, `RedactionVault` protocols + `LocalRedactionResult` |
| `presidio_backend.py` | `PresidioRedactor` — Microsoft Presidio (free MIT OSS, runs locally) |
| `spacy_backend.py` | `SpacyNERRedactor` — pure spaCy NER for PERSON/ORG/GPE/LOC |
| `transformers_backend.py` | `TransformersClassifierAuditor` — any HuggingFace text-classification model |
| `onnx_backend.py` | `ONNXClassifierAuditor` — quantized models on CPU via onnxruntime |
| `ollama_backend.py` | `OllamaAuditor` — talk to a local Ollama server |
| `llamacpp_backend.py` | `LlamaCppAuditor` — in-process via `llama-cpp-python` |
| `vault.py` | `InMemoryVault` + `EncryptedFileVault` for reversible redaction |

## Pipeline placement

```
text in
 → heuristics (built-in regex)
 → LOCAL pre-redactors  ← redactors here, e.g. PresidioRedactor
 → LOCAL classifier     ← LocalAuditors here, e.g. TransformersClassifierAuditor
 → cloud auditor        (optional second opinion)
 → enforce / redact / log
```

With `forward_redacted=True` the cloud LLM only ever sees the redacted
text, not the originals.

## Privacy-preserving redaction (the core use case)

```python
from prompt_protector import PromptProtector
from prompt_protector.local import PresidioRedactor, InMemoryVault
from prompt_protector.backends.openai_backend import OpenAIAuditor

protector = PromptProtector(
    pre_redactors=[
        PresidioRedactor(
            entities=["US_SSN", "CREDIT_CARD", "EMAIL_ADDRESS", "PHONE_NUMBER", "PERSON"],
            operator="replace",
            reversible=True,                  # keep a placeholder→original mapping
        ),
    ],
    auditor=OpenAIAuditor(model="gpt-4o-mini"),
    vault=InMemoryVault(ttl_seconds=3600),
    forward_redacted=True,                    # downstream LLM never sees raw PII
)

result = await protector.sanitize_input("Hello, my name is Jane Smith")
# result.redacted_text     -> "Hello, my name is [PERSON_1]"
# result.vault_id          -> "8f3c..." (handed back when calling unredact)

# After your real LLM responds with text containing [PERSON_1]:
restored = protector.unredact(llm_response, result.vault_id)
# "Welcome Jane Smith, your appointment is confirmed."
```

## Fully local auditor (no cloud at all)

```python
from prompt_protector import PromptProtector
from prompt_protector.local.transformers_backend import TransformersClassifierAuditor

protector = PromptProtector(
    auditor=TransformersClassifierAuditor(
        "ProtectAI/deberta-v3-base-prompt-injection-v2",
        device="cpu",
        threshold=0.85,
    ),
)
```

Or via Ollama:

```python
from prompt_protector.local.ollama_backend import OllamaAuditor

OllamaAuditor("llama-guard3", host="http://localhost:11434")
```

## Optional dependencies

Each backend is opt-in. Importing the class will raise
`MissingDependencyError` immediately at construction time if its extra
isn't installed.

| Backend | Extra | `pip install` |
|---------|-------|---------------|
| `PresidioRedactor` | `presidio` | `pip install 'prompt-protector[presidio]'` |
| `SpacyNERRedactor` | `spacy` | `pip install 'prompt-protector[spacy]'` |
| `TransformersClassifierAuditor` | `transformers` | `pip install 'prompt-protector[transformers]'` |
| `ONNXClassifierAuditor` | `onnx` | `pip install 'prompt-protector[onnx]'` |
| `OllamaAuditor` | `ollama` | `pip install 'prompt-protector[ollama]'` |
| `LlamaCppAuditor` | `llamacpp` | `pip install 'prompt-protector[llamacpp]'` |
| `EncryptedFileVault` | `vault` | `pip install 'prompt-protector[vault]'` |
| All of the above | `local-all` | `pip install 'prompt-protector[local-all]'` |

## Recommended models

- **Prompt-injection classifier**: `ProtectAI/deberta-v3-base-prompt-injection-v2` (small, CPU-friendly, Apache-2.0).
- **Multi-category safety**: `meta-llama/Llama-Guard-3-1B` (fast) or `Llama-Guard-3-8B` (more accurate, needs GPU).
- **Harm classifier**: `ibm-granite/granite-guardian-3.1-2b` (Apache-2.0).
- **Toxicity**: `unitary/toxic-bert`.
- **Multilingual NER for non-English PII**: `Davlan/distilbert-base-multilingual-cased-ner-hrl`.

## Vaults

`InMemoryVault` is fine for a single-process server. For cross-process or
on-disk persistence (with TTL and encryption), use `EncryptedFileVault`:

```python
from cryptography.fernet import Fernet
from prompt_protector.local.vault import EncryptedFileVault

vault = EncryptedFileVault("/var/lib/prompt-protector/vault", key=Fernet.generate_key())
```

The Fernet key should come from a KMS / secret manager in production.
