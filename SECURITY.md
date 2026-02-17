# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in Sentinel, please report it responsibly.

**Do NOT open a public GitHub issue for security vulnerabilities.**

Instead, use [GitHub Security Advisories](https://github.com/anthropics/sentinel/security/advisories/new) to report vulnerabilities privately. If the advisories link is unavailable, open a private security report via the repository's "Security" tab.

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if you have one)

You should receive an acknowledgement within 48 hours. We aim to provide a fix or mitigation plan within 7 days of confirmed vulnerabilities.

## Scope

The following are in scope for security reports:

- Bypasses of the 10-layer security pipeline
- Prompt injection that produces genuinely dangerous output (not just "escaped" — see our [triage methodology](docs/assessments/v3-security-analysis.md))
- Air-gap violations (any way for the worker LLM to reach the internet)
- Authentication bypasses (PIN auth, CSRF protection)
- Trust laundering (untrusted data reaching dangerous operations without scanning)
- Memory injection (poisoned memory content influencing orchestrator behaviour)
- Routine manipulation (crafting routines that bypass security controls)
- MCP tool abuse (using MCP tools to circumvent approval gates or access controls)
- WASM sandbox escape (breaking out of the Wasmtime sandbox)
- Session manipulation or replay attacks
- Vulnerabilities in the controller, policy engine, or scan pipeline

The following are **out of scope**:

- Issues requiring physical access to the host
- Social engineering of the human operator (the approval gate is intentionally human-dependent)
- Denial of service via API rate limiting (already mitigated with slowapi)
- Self-signed certificate warnings (expected for local deployment)

## Security Architecture

Sentinel's security model is documented in detail:

- [Security Model](docs/security-model.md) — full description of the 10-layer pipeline, CaMeL trust model, and threat model
- [v3 Security Analysis](docs/assessments/v3-security-analysis.md) — results from 811 adversarial prompts across 21+ attack categories
- [Expert Report](docs/assessments/v3-expert-report.md) — independent assessment of the v3 benchmark

## Supported Versions

| Version | Supported |
|---------|-----------|
| Current (`main` branch) | Yes |
| Older commits | No |

This project is in active development and does not yet use semantic versioning. Security fixes are applied to `main` only.
