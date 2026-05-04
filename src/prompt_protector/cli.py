"""Tiny offline CLI for ops/security teams.

Reads text from stdin (or ``--text``) and runs the heuristics + redaction
layer locally. Cloud auditors are not invoked — this is intended for
quick triage of suspect content without touching the request path.

Examples:

    prompt-protector check --rules pii,injection -      < message.txt
    prompt-protector redact -                            < message.txt
    prompt-protector check --config protector.yaml -     < message.txt
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence

from .heuristics import DetectorRegistry, default_registry
from .redaction import RedactionStyle, redact


def _read_input(text_arg: str | None) -> str:
    if text_arg:
        return text_arg
    return sys.stdin.read()


def _filter_registry(reg: DetectorRegistry, rules_csv: str | None) -> DetectorRegistry:
    if not rules_csv:
        return reg
    wanted = {r.strip().lower() for r in rules_csv.split(",") if r.strip()}
    keep_categories = {
        "pii": "pii",
        "secrets": "secrets",
        "injection": "prompt_injection",
        "prompt_injection": "prompt_injection",
        "html": "other",
    }
    cats = {keep_categories[w] for w in wanted if w in keep_categories}
    if not cats:
        return reg
    # Don't mutate the input — return a new registry.
    return DetectorRegistry(
        detectors=[d for d in reg.detectors if d.category.value in cats]
    )


def cmd_check(args: argparse.Namespace) -> int:
    text = _read_input(args.text)
    reg = default_registry()
    reg = _filter_registry(reg, args.rules)
    matches = reg.scan(text)
    out = {
        "passed": not any(m.score >= 0.85 for m in matches),
        "matches": [
            {
                "detector": m.detector,
                "category": m.category.value,
                "span": list(m.span),
                "original": m.original,
                "score": m.score,
            }
            for m in matches
        ],
    }
    json.dump(out, sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 0 if out["passed"] else 1


def cmd_redact(args: argparse.Namespace) -> int:
    text = _read_input(args.text)
    style = RedactionStyle.NUMBERED if args.numbered else RedactionStyle.LABELED
    result = redact(text, style=style)
    sys.stdout.write(result.redacted_text)
    if not result.redacted_text.endswith("\n"):
        sys.stdout.write("\n")
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="prompt-protector")
    sub = p.add_subparsers(dest="cmd", required=True)

    chk = sub.add_parser("check", help="run heuristics and report matches as JSON")
    chk.add_argument("--text", help="literal text (instead of stdin)")
    chk.add_argument("--rules", help="comma-separated categories: pii,secrets,injection,html")
    chk.add_argument("input", nargs="?", help="ignored; use stdin or --text")
    chk.set_defaults(func=cmd_check)

    rd = sub.add_parser("redact", help="redact PII/secrets and print sanitized text")
    rd.add_argument("--text", help="literal text (instead of stdin)")
    rd.add_argument("--numbered", action="store_true", help="use [PII_1] style placeholders")
    rd.add_argument("input", nargs="?", help="ignored; use stdin or --text")
    rd.set_defaults(func=cmd_redact)

    args = p.parse_args(list(argv) if argv is not None else None)
    return args.func(args)


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
