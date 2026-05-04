# Security policy

prompt-protector is a security tool. Vulnerabilities here can mean PII
leaking past redaction, prompt-injection blocks failing open, or the
fail-mode policy being bypassed. Treat reports here as time-sensitive.

## Supported versions

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | Yes                |
| 0.x     | No (please upgrade)|

Patch releases for security fixes go onto the most recent minor line.
Older minors are not backported.

## Reporting a vulnerability

**Do not open a public GitHub issue for security reports.**

Use GitHub's private security advisories, which is the primary
channel for this project:

  https://github.com/tahoe-ai/prompt-protector/security/advisories/new

A draft advisory there is private to maintainers. We can iterate on
the report and publish a CVE from the same flow once a fix lands.

If you can't use GitHub for some reason, encrypted email also works:

  security@tahoe-ai.org

## What to include

- Affected version(s) and the install command you used.
- A minimal reproduction. A short script that demonstrates the issue
  is far more useful than a paragraph describing it.
- Severity from your perspective: data leak, bypass, denial of
  service, supply-chain, etc.
- Whether the vulnerability is already public.

## Disclosure timeline

- Acknowledgement within 3 business days.
- Initial assessment within 7 business days.
- Coordinated disclosure once a fix is available, typically 30 to
  90 days depending on severity.
- We credit reporters in the release notes unless you'd rather stay
  anonymous.

## Out of scope

- Issues in optional dependencies (Presidio, transformers, Ollama,
  etc.). Report those upstream. We'll happily pin a known-bad version
  range in `pyproject.toml` once an upstream fix is available.
- Misuse where the caller passed `forward_redacted=False` and a cloud
  LLM saw raw PII. That flag is opt-in by design; the cloud judge
  needing the original text to make a verdict is a real use case.
- The cloud judge being wrong on a single adversarial input. Use
  `DualVoteAuditor` if you need a redundant verdict.
- Performance issues that aren't security-relevant.
