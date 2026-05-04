"""Declarative config validation and build tests."""

from __future__ import annotations

import pytest

from prompt_protector import PromptProtector
from prompt_protector.config import (
    ConfigError,
    build_protector,
    load_config_dict,
)


def test_minimal_config():
    cfg = load_config_dict(
        {
            "auditor": {"primary": {"kind": "mock"}},
            "prevent": {"pii": {"enabled": True, "apply_to": ["input", "output"]}},
        }
    )
    p = build_protector(cfg)
    assert isinstance(p, PromptProtector)


def test_invalid_failure_mode():
    with pytest.raises(ConfigError):
        load_config_dict({"failure_mode": "ignore_everything"})


def test_invalid_pii_type():
    with pytest.raises(ConfigError) as exc:
        load_config_dict(
            {
                "prevent": {
                    "pii": {"enabled": True, "types": ["passport"]},
                }
            }
        )
    assert "passport" in str(exc.value)


def test_invalid_secret_type():
    with pytest.raises(ConfigError):
        load_config_dict({"prevent": {"secrets": {"types": ["bitcoin_wallet"]}}})


def test_apply_to_validation():
    with pytest.raises(ConfigError):
        load_config_dict({"prevent": {"pii": {"apply_to": ["sideways"]}}})


def test_action_validation():
    with pytest.raises(ConfigError):
        load_config_dict({"prevent": {"pii": {"action": "shrug"}}})


def test_extra_phrases_routed_to_registry():
    cfg = load_config_dict(
        {
            "auditor": {"primary": {"kind": "mock"}},
            "prevent": {
                "prompt_injection": {
                    "enabled": True,
                    "apply_to": ["input"],
                    "extra_phrases": ["zugzwang activate"],
                }
            },
        }
    )
    p = build_protector(cfg)
    # The registry inside the protector should pick up the extra phrase.
    matches = p._registry.scan("zugzwang activate now")  # noqa: SLF001
    assert any("zugzwang" in m.original.lower() for m in matches)


def test_custom_regex_redaction(tmp_path):
    cfg = load_config_dict(
        {
            "auditor": {"primary": {"kind": "mock"}},
            "prevent": {
                "custom_regex": [
                    {
                        "name": "ticket",
                        "pattern": r"INC-\d{6}",
                        "action": "redact",
                        "apply_to": ["output"],
                        "replacement": "[REDACTED:TICKET]",
                    }
                ]
            },
        }
    )
    p = build_protector(cfg)
    r = p.redact("see ticket INC-123456 for details")
    assert "[REDACTED:TICKET]" in r.redacted_text


def test_yaml_loader_round_trip(tmp_path):
    yaml = pytest.importorskip("yaml")
    path = tmp_path / "cfg.yaml"
    path.write_text(
        yaml.safe_dump(
            {
                "failure_mode": "fail_closed",
                "auditor": {"primary": {"kind": "mock"}},
                "prevent": {"pii": {"enabled": True}},
            }
        )
    )
    p = PromptProtector.from_config(str(path))
    assert isinstance(p, PromptProtector)
