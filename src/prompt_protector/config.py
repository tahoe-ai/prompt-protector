"""Declarative config — turn a YAML/TOML/JSON file into a PromptProtector.

The schema mirrors the programmatic API. Anything you can pass to
``PromptProtector(...)`` you can declare here; anything you can declare
here round-trips back through the programmatic API.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Any, Optional


# ---------------------------------------------------------------------------
# Config dataclasses
# ---------------------------------------------------------------------------


@dataclass
class ProviderConfig:
    kind: str  # "openai" | "anthropic" | "ollama" | "transformers" | "llamacpp" | "onnx" | "mock"
    model: Optional[str] = None
    api_key_env: Optional[str] = None
    api_key: Optional[str] = None
    host: Optional[str] = None
    device: str = "cpu"
    threshold: float = 0.5
    extras: dict[str, Any] = field(default_factory=dict)


@dataclass
class ProvidersConfig:
    primary: Optional[ProviderConfig] = None
    secondary: Optional[ProviderConfig] = None
    fallback: Optional[ProviderConfig] = None
    policy: str = "primary_only"  # primary_only | any_must_pass | all_must_pass


@dataclass
class PreventCategory:
    enabled: bool = True
    types: list[str] = field(default_factory=list)
    action: str = "block"  # block | redact | log
    apply_to: list[str] = field(default_factory=lambda: ["input", "output"])
    severity_threshold: float = 0.5
    extra_phrases: list[str] = field(default_factory=list)
    rules: list[str] = field(default_factory=list)


@dataclass
class CustomRegexRule:
    name: str
    pattern: str
    action: str = "redact"
    apply_to: list[str] = field(default_factory=lambda: ["input", "output"])
    replacement: Optional[str] = None


@dataclass
class OutputSchemaConfig:
    enabled: bool = False
    schema_path: Optional[str] = None


@dataclass
class PreventConfig:
    pii: PreventCategory = field(default_factory=PreventCategory)
    secrets: PreventCategory = field(default_factory=PreventCategory)
    prompt_injection: PreventCategory = field(default_factory=PreventCategory)
    nsfw: PreventCategory = field(default_factory=lambda: PreventCategory(enabled=False))
    off_topic: PreventCategory = field(default_factory=lambda: PreventCategory(enabled=False))
    custom_regex: list[CustomRegexRule] = field(default_factory=list)
    output_schema: OutputSchemaConfig = field(default_factory=OutputSchemaConfig)


@dataclass
class CacheConfig:
    enabled: bool = False
    backend: str = "memory"  # memory | redis
    ttl_seconds: float = 600.0
    max_entries: int = 10_000
    redis_url: str = "redis://localhost:6379/0"


@dataclass
class LoggingConfig:
    level: str = "INFO"
    audit_log_path: Optional[str] = None


@dataclass
class PreRedactorConfig:
    kind: str  # presidio | spacy | regex_pack
    extras: dict[str, Any] = field(default_factory=dict)


@dataclass
class ProtectorConfig:
    version: int = 1
    failure_mode: str = "fail_closed"
    mode: str = "enforce"
    sample_rate: float = 1.0
    max_input_chars: int = 8000
    on_oversize: str = "reject"
    forward_redacted: bool = False
    batch_rules: bool = True
    timeout_s: float = 10.0
    max_retries: int = 3

    providers: ProvidersConfig = field(default_factory=ProvidersConfig)
    auditor: ProvidersConfig = field(default_factory=ProvidersConfig)
    pre_redactors: list[PreRedactorConfig] = field(default_factory=list)
    prevent: PreventConfig = field(default_factory=PreventConfig)
    cache: CacheConfig = field(default_factory=CacheConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)


# ---------------------------------------------------------------------------
# Loaders
# ---------------------------------------------------------------------------


_VALID_PII_TYPES = {
    "ssn",
    "credit_card",
    "email",
    "phone",
    "postal_address",
    "date_of_birth",
    "ip_address",
    "person_name",
}
_VALID_SECRET_TYPES = {
    "aws_access_key",
    "github_token",
    "slack_token",
    "jwt",
    "openai_key",
    "anthropic_key",
    "ssh_private_key",
    "generic_high_entropy",
}


class ConfigError(ValueError):
    """Raised when config is invalid."""


def load_config_file(path: str) -> ProtectorConfig:
    with open(path, "rb") as fh:
        raw = fh.read()
    suffix = os.path.splitext(path)[1].lower()
    if suffix in (".yaml", ".yml"):
        try:
            import yaml  # type: ignore
        except ImportError as exc:
            raise ConfigError("PyYAML is required for YAML configs (pip install pyyaml)") from exc
        data = yaml.safe_load(raw)
    elif suffix == ".toml":
        try:
            import tomllib  # type: ignore
        except ImportError:  # pragma: no cover — Python 3.10
            import tomli as tomllib  # type: ignore
        data = tomllib.loads(raw.decode("utf-8"))
    elif suffix == ".json":
        data = json.loads(raw)
    else:
        raise ConfigError(f"unsupported config extension: {suffix}")
    return load_config_dict(data)


def load_config_dict(data: dict) -> ProtectorConfig:
    if not isinstance(data, dict):
        raise ConfigError("config root must be a mapping")
    cfg = ProtectorConfig()

    _set_simple(
        cfg,
        data,
        keys=(
            "version",
            "failure_mode",
            "mode",
            "sample_rate",
            "max_input_chars",
            "on_oversize",
            "forward_redacted",
            "batch_rules",
            "timeout_s",
            "max_retries",
        ),
    )

    if "defaults" in data:
        _set_simple(
            cfg,
            data["defaults"],
            keys=(
                "failure_mode",
                "mode",
                "sample_rate",
                "max_input_chars",
                "on_oversize",
                "forward_redacted",
                "batch_rules",
                "timeout_s",
                "max_retries",
            ),
        )

    if "providers" in data:
        cfg.providers = _parse_providers(data["providers"])
    if "auditor" in data:
        cfg.auditor = _parse_providers(data["auditor"])

    if "pre_redactors" in data:
        cfg.pre_redactors = [
            PreRedactorConfig(
                kind=item["kind"],
                extras={k: v for k, v in item.items() if k != "kind"},
            )
            for item in data["pre_redactors"]
        ]

    if "prevent" in data:
        cfg.prevent = _parse_prevent(data["prevent"])

    if "cache" in data:
        cfg.cache = CacheConfig(**{k: v for k, v in data["cache"].items() if k in CacheConfig.__dataclass_fields__})

    if "logging" in data:
        cfg.logging = LoggingConfig(
            **{k: v for k, v in data["logging"].items() if k in LoggingConfig.__dataclass_fields__}
        )

    _validate(cfg)
    return cfg


def _set_simple(cfg: ProtectorConfig, src: dict, *, keys: tuple) -> None:
    for k in keys:
        if k in src:
            setattr(cfg, k, src[k])


def _parse_providers(data: dict) -> ProvidersConfig:
    out = ProvidersConfig()
    if "primary" in data:
        out.primary = _parse_provider(data["primary"])
    if "secondary" in data:
        out.secondary = _parse_provider(data["secondary"])
    if "fallback" in data:
        out.fallback = _parse_provider(data["fallback"])
    if "policy" in data:
        out.policy = data["policy"]
    return out


def _parse_provider(data: dict) -> ProviderConfig:
    known = {"kind", "model", "api_key_env", "api_key", "host", "device", "threshold"}
    extras = {k: v for k, v in data.items() if k not in known}
    return ProviderConfig(
        kind=data["kind"],
        model=data.get("model"),
        api_key_env=data.get("api_key_env"),
        api_key=data.get("api_key"),
        host=data.get("host"),
        device=data.get("device", "cpu"),
        threshold=float(data.get("threshold", 0.5)),
        extras=extras,
    )


def _parse_prevent(data: dict) -> PreventConfig:
    out = PreventConfig()
    for key in ("pii", "secrets", "prompt_injection", "nsfw", "off_topic"):
        if key in data:
            entry = data[key]
            cat = PreventCategory(
                enabled=bool(entry.get("enabled", True)),
                types=list(entry.get("types", [])),
                action=str(entry.get("action", "block")),
                apply_to=list(entry.get("apply_to", ["input", "output"])),
                severity_threshold=float(entry.get("severity_threshold", 0.5)),
                extra_phrases=list(entry.get("extra_phrases", [])),
                rules=list(entry.get("rules", [])),
            )
            setattr(out, key, cat)

    for entry in data.get("custom_regex", []) or []:
        out.custom_regex.append(
            CustomRegexRule(
                name=entry["name"],
                pattern=entry["pattern"],
                action=entry.get("action", "redact"),
                apply_to=list(entry.get("apply_to", ["input", "output"])),
                replacement=entry.get("replacement"),
            )
        )

    if "output_schema" in data:
        sd = data["output_schema"]
        out.output_schema = OutputSchemaConfig(
            enabled=bool(sd.get("enabled", False)),
            schema_path=sd.get("schema_path"),
        )

    return out


def _validate(cfg: ProtectorConfig) -> None:
    if cfg.failure_mode not in ("fail_closed", "fail_open"):
        raise ConfigError(f"failure_mode must be fail_closed|fail_open, got {cfg.failure_mode!r}")
    if cfg.mode not in ("enforce", "shadow", "sample"):
        raise ConfigError(f"mode must be enforce|shadow|sample, got {cfg.mode!r}")
    if cfg.on_oversize not in ("reject", "truncate"):
        raise ConfigError(f"on_oversize must be reject|truncate, got {cfg.on_oversize!r}")

    bad = [t for t in cfg.prevent.pii.types if t not in _VALID_PII_TYPES]
    if bad:
        raise ConfigError(
            f"unknown PII types: {bad}. Valid: {sorted(_VALID_PII_TYPES)}"
        )
    bad = [t for t in cfg.prevent.secrets.types if t not in _VALID_SECRET_TYPES]
    if bad:
        raise ConfigError(
            f"unknown secret types: {bad}. Valid: {sorted(_VALID_SECRET_TYPES)}"
        )

    for cat_name in ("pii", "secrets", "prompt_injection", "nsfw", "off_topic"):
        cat = getattr(cfg.prevent, cat_name)
        if cat.action not in ("block", "redact", "log"):
            raise ConfigError(f"prevent.{cat_name}.action must be block|redact|log, got {cat.action!r}")
        for d in cat.apply_to:
            if d not in ("input", "output"):
                raise ConfigError(f"prevent.{cat_name}.apply_to entries must be input|output, got {d!r}")


# ---------------------------------------------------------------------------
# Build a PromptProtector from a ProtectorConfig
# ---------------------------------------------------------------------------


def build_protector(cfg: ProtectorConfig):
    from . import rule_packs as packs
    from .backends import DualVoteAuditor, VotePolicy
    from .cache import InMemoryLRUCache, RedisCache
    from .heuristics import Detector, default_registry
    from .protector import PromptProtector
    from .rule_packs import Rule
    from .types import Category, FailureMode, Mode

    # Build rules from prevent: blocks
    output_rules: list = []
    input_rules: list = []
    if cfg.prevent.pii.enabled:
        for r in packs.PII:
            _route(r, cfg.prevent.pii.apply_to, input_rules, output_rules)
    if cfg.prevent.secrets.enabled:
        for r in packs.SECRETS:
            _route(r, cfg.prevent.secrets.apply_to, input_rules, output_rules)
    if cfg.prevent.prompt_injection.enabled:
        for r in packs.PROMPT_INJECTION:
            _route(r, cfg.prevent.prompt_injection.apply_to, input_rules, output_rules)
    if cfg.prevent.nsfw.enabled:
        for r in packs.NSFW:
            _route(r, cfg.prevent.nsfw.apply_to, input_rules, output_rules)
    if cfg.prevent.off_topic.enabled:
        for i, text in enumerate(cfg.prevent.off_topic.rules):
            r = Rule(id=f"off_topic.{i}", text=text)
            _route(r, cfg.prevent.off_topic.apply_to, input_rules, output_rules)

    # Auditor (cloud / local)
    src = cfg.auditor if cfg.auditor.primary else cfg.providers
    auditor = _build_auditor(src.primary)
    secondary = _build_auditor(src.secondary)
    if auditor and secondary:
        policy = VotePolicy.ALL_MUST_PASS if src.policy == "all_must_pass" else VotePolicy.ANY_MUST_PASS
        auditor = DualVoteAuditor(auditor, secondary, policy=policy)

    # Pre-redactors
    pre_redactors = [_build_pre_redactor(p) for p in cfg.pre_redactors]

    # Cache
    cache = None
    if cfg.cache.enabled:
        if cfg.cache.backend == "redis":
            cache = RedisCache(cfg.cache.redis_url, ttl_seconds=cfg.cache.ttl_seconds)
        else:
            cache = InMemoryLRUCache(
                max_entries=cfg.cache.max_entries,
                ttl_seconds=cfg.cache.ttl_seconds,
            )

    # Mode
    if cfg.mode == "shadow":
        mode = Mode.shadow()
    elif cfg.mode == "sample":
        mode = Mode.sample(cfg.sample_rate)
    else:
        mode = Mode.enforce()

    # Apply logging level globally for the prompt_protector logger.
    import logging as _log

    _log.getLogger("prompt_protector").setLevel(cfg.logging.level)

    extra_phrases = list(cfg.prevent.prompt_injection.extra_phrases)
    registry = default_registry(injection_phrases=extra_phrases)

    # Custom regex from prevent.custom_regex — register them as a single detector.
    if cfg.prevent.custom_regex:
        registry.add(
            Detector(
                name="custom_regex",
                category=Category.OTHER,
                fn=_custom_regex_fn(cfg.prevent.custom_regex),
                score=0.9,
            )
        )

    return PromptProtector(
        auditor=auditor,
        pre_redactors=pre_redactors,
        input_rules=input_rules,
        output_rules=output_rules,
        failure_mode=FailureMode(cfg.failure_mode),
        mode=mode,
        timeout_s=cfg.timeout_s,
        max_retries=cfg.max_retries,
        max_input_chars=cfg.max_input_chars,
        on_oversize=cfg.on_oversize,
        batch_rules=cfg.batch_rules,
        cache=cache,
        forward_redacted=cfg.forward_redacted,
        injection_phrases=extra_phrases,
        detector_registry=registry,
    )


def _custom_regex_fn(rules: list[CustomRegexRule]):
    """Build a single detector function over compiled custom regexes."""
    import re

    from .types import Category, make_match

    compiled = [(re.compile(r.pattern), r) for r in rules]

    def fn(text: str):
        out = []
        for pat, r in compiled:
            for m in pat.finditer(text):
                out.append(
                    make_match(
                        detector=r.name,
                        category=Category.OTHER,
                        span=(m.start(), m.end()),
                        original=m.group(0),
                        replacement=r.replacement or f"[REDACTED:{r.name.upper()}]",
                        score=0.95 if r.action == "block" else 0.7,
                    )
                )
        return out

    return fn


def _route(rule, apply_to: list[str], input_rules: list, output_rules: list) -> None:
    if "input" in apply_to:
        input_rules.append(rule)
    if "output" in apply_to:
        output_rules.append(rule)


def _build_auditor(p: Optional[ProviderConfig]):
    if p is None:
        return None
    api_key = p.api_key
    if not api_key and p.api_key_env:
        api_key = os.getenv(p.api_key_env)

    if p.kind == "openai":
        from .backends.openai_backend import OpenAIAuditor

        return OpenAIAuditor(api_key=api_key, model=p.model or "gpt-4o-mini")
    if p.kind == "anthropic":
        from .backends.anthropic_backend import AnthropicAuditor

        return AnthropicAuditor(api_key=api_key, model=p.model or "claude-haiku-4-5-20251001")
    if p.kind == "ollama":
        from .local.ollama_backend import OllamaAuditor

        return OllamaAuditor(model=p.model or "llama-guard3", host=p.host or "http://localhost:11434")
    if p.kind == "transformers":
        from .local.transformers_backend import TransformersClassifierAuditor

        return TransformersClassifierAuditor(p.model or "ProtectAI/deberta-v3-base-prompt-injection-v2", device=p.device, threshold=p.threshold)
    if p.kind == "mock":
        from .backends.mock import MockAuditor

        return MockAuditor(fail_substrings=p.extras.get("fail_substrings"))
    raise ConfigError(f"unknown provider kind: {p.kind!r}")


def _build_pre_redactor(p: PreRedactorConfig):
    if p.kind == "presidio":
        from .local.presidio_backend import PresidioRedactor

        return PresidioRedactor(**p.extras)
    if p.kind == "spacy":
        from .local.spacy_backend import SpacyNERRedactor

        return SpacyNERRedactor(**p.extras)
    if p.kind == "regex_pack":
        # Built-in heuristics already handle this; return a thin adapter.
        from .heuristics import default_registry
        from .redaction import redact as redact_fn
        from .local.base import LocalRedactionResult

        class _RegexAdapter:
            name = "regex_pack"

            def __init__(self) -> None:
                self._reg = default_registry()

            def redact(self, text: str) -> LocalRedactionResult:
                r = redact_fn(text, registry=self._reg)
                return LocalRedactionResult(
                    redacted_text=r.redacted_text,
                    matches=r.matches,
                    mapping=r.mapping,
                )

        return _RegexAdapter()
    raise ConfigError(f"unknown pre_redactor kind: {p.kind!r}")


__all__ = [
    "CacheConfig",
    "ConfigError",
    "CustomRegexRule",
    "LoggingConfig",
    "OutputSchemaConfig",
    "PreRedactorConfig",
    "PreventCategory",
    "PreventConfig",
    "ProtectorConfig",
    "ProviderConfig",
    "ProvidersConfig",
    "build_protector",
    "load_config_dict",
    "load_config_file",
]
