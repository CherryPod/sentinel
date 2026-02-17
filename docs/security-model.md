# Security Model

Sentinel's security is built on the [CaMeL architecture](https://arxiv.org/abs/2503.18813) — a framework for building LLM applications that remain safe even when the worker LLM is fully compromised.

## Core Principle

**Qwen is assumed compromised at all times.** It only receives text and returns text. The controller scans every output before the system acts on it. No prompt injection, jailbreak, or adversarial input should be able to cause the system to execute dangerous operations.

## The Air Gap

The worker LLM (`sentinel-qwen`) runs on an air-gapped network (`sentinel_internal`, `internal: true`). It has:

- **No internet access** — cannot phone home, exfiltrate data, or fetch remote payloads
- **No host ports** — not accessible from outside the container network
- **No tools** — cannot read files, write files, or execute commands
- **No context** — receives only the prompt for the current step, not conversation history

This means a compromised worker can only influence the system through its text output, which passes through the full scan pipeline.

## 10 Security Layers

### Layer 1: PIN Authentication

ASGI middleware on the controller. All endpoints except `/health` require an `X-Sentinel-Pin` header. The PIN is stored as a Podman secret (never in source code).

- Constant-time comparison (`hmac.compare_digest`) — prevents timing attacks
- Per-IP lockout after 5 failures (60s cooldown) — prevents brute force

### Layer 2: Policy Engine

Deterministic YAML-driven rules that cannot be bypassed by prompt injection. The policy engine runs entirely in Python with no LLM involvement.

**File access:** Only `/workspace/**` is writable. Blocked: `/etc/**`, `.ssh/`, `.gnupg/`, `*.env`, `*.key`, `*.pem`, `wallet.dat`, `.bitcoin/`

**Commands:** Explicit allowlist (`ls`, `cat`, `mkdir`, `cp`, `head`, `tail`, `wc`, `grep`, `find` with path constraints). Blocked: `rm -rf`, `curl`, `wget`, `ssh`, `python -c`, `bash -c`, `eval`, `exec`, pipe to shell, `chmod`, `systemctl`.

**Network:** Qwen outbound = none. Controller allowed: `api.anthropic.com:443`, `mosquitto:1883`, `sentinel-qwen:11434`.

**Path traversal:** Relative paths resolved against `/workspace` before validation. URL-encoded paths, null bytes, and symlinks are detected.

**Command chaining:** `&&`, `||`, bare `|` injection patterns are blocked. `find -exec` and `-execdir` are blocked.

### Layer 3: Spotlighting

Zero-cost string manipulation defence against prompt injection:

- **Dynamic markers** — 4 random characters from `~!@#%*+=|;:` prepended to every word in untrusted data (10,000 permutations per request). The marker changes every request, so adversaries can't craft payloads that include the marker
- **Structural tags** — `<UNTRUSTED_DATA>` / `</UNTRUSTED_DATA>` XML-style boundaries
- **Sandwich defence** — security reminder appended after untrusted data (exploits LLM recency bias)
- **Chain-safe substitution** — when one step's output feeds into the next step's prompt, the output is wrapped with markers + tags + reminder

### Layer 4: Prompt Guard 2

86M parameter BERT classifier from Meta. Detects prompt injection attempts with ~67% catch rate. Runs on CPU (no GPU contention).

- 512-token scanning window with chunking for longer inputs
- Fail-closed: if Prompt Guard is unavailable, requests are blocked (not silently skipped)

### Layer 5: CodeShield

Semgrep-based static analysis from Meta's PurpleLlama. Scans ALL Qwen output (not just code-flagged steps) for:

- `os.system()`, `eval()`, `exec()`
- SQL injection patterns
- Path traversal in code
- Reverse shells
- Weak cryptography
- Other CWE patterns

Fail-closed: if CodeShield is unavailable, requests are blocked.

### Layer 6: CommandPatternScanner

Regex patterns detecting dangerous shell commands in prose (not just code blocks):

- Pipe-to-shell (`curl | bash`, `wget | sh`)
- Reverse shells (`/dev/tcp`, `nc -e`, `mkfifo`)
- Base64 decode + exec chains
- `nohup` backgrounding

### Layer 7: ConversationAnalyzer

Multi-turn heuristic analysis with 8 rules and cumulative scoring:

1. **Retry after block** — detects rephrased retries (similarity > 0.45)
2. **Capability escalation** — tracks observe → read → write → execute → persist → exfiltrate
3. **Sensitive topic acceleration** — first sensitive request after benign turns
4. **Instruction override** — "ignore instructions", "from now on", DAN patterns
5. **Violation accumulation** — 1.5 points per prior block
6. **Context building** — "as I mentioned" + sensitive content
7. **Reconnaissance** — systematic directory/file listing
8. **Topic shift** — benign to sensitive within a session

Scoring: allow < 3.0, warn 3.0-4.99, block >= 5.0. Sessions lock after block threshold.

**Layer 2b: Claude-assisted chain review** — conversation history is injected into the planner prompt, so Claude assesses multi-turn escalation patterns using its existing call (no extra API cost).

### Layer 8: VulnerabilityEchoScanner

Detects code injection via the "review/test/debug" framing attack:

- 14 fingerprint patterns (`eval()`, `exec()`, `os.system()`, `pickle`, `yaml.load`, `innerHTML`, SQL injection, etc.)
- Compares vulnerability fingerprints between user input and Qwen output
- "Review this eval() code" → Qwen reproduces eval() → echo detected → blocked
- "Fix this eval() code" → Qwen removes eval() → no echo → passes

Only checks code regions (fenced blocks or 4+ space indent), not educational prose.

### Layer 9: Script Gate

Deterministic backstop for cross-model bilingual injection:

- Expanded allowlist: ASCII + Latin Extended + typographic symbols (smart quotes, em-dashes, math operators, currency, arrows, box drawing, dingbats)
- Always checks the planner-constructed `prompt` (not `untrusted_data`, which is protected by spotlighting)
- Blocks CJK, Cyrillic, Arabic, Hangul, and other non-Latin scripts that Qwen might follow as instructions

Works alongside the planner's language safety rule (which tells Claude to translate everything to English before constructing worker prompts).

### Layer 10: CaMeL Provenance

The architectural guarantee. Every data item is tagged with source and trust level. Trust inherits through derivation chains — anything derived from untrusted data stays untrusted.

- **Provenance trust gate** — called before every tool execution. Checks the provenance chain of all variable references in tool call arguments
- **File provenance registry** — tracks which data wrote each file. `file_read` inherits trust from the writer
- **Trust laundering prevention** — blocks the write (trust gate) AND blocks the read (provenance inheritance)

## Threat Model

### In scope
- Prompt injection (direct, indirect, multi-turn, encoded)
- Jailbreak attempts (persona, hypothetical, multilingual)
- Code injection (vulnerable code echo, reverse shells, supply chain)
- Data exfiltration via tool misuse
- Trust escalation via filesystem
- Session manipulation and replay

### Mitigated but not eliminated
- Multi-turn gradual escalation (ConversationAnalyzer + Claude review help, but sophisticated slow-burn attacks may evade)
- Novel encoding schemes (6 decoders cover common cases, but new encodings could bypass)
- Adversarial code that passes CodeShield's Semgrep rules

### Out of scope
- Physical access to the host
- Social engineering of the human operator
- Compromise of the Claude API itself
- Supply chain attacks on container base images (mitigated by pinned digests)

## Multi-Channel Security

All communication channels (WebSocket, SSE, HTTP, MCP, Signal) route through the same CaMeL security pipeline. No channel bypasses scanning, provenance tracking, or approval gates.

| Channel | Authentication | Dangerous Operations |
|---------|---------------|---------------------|
| HTTP REST | PIN header (`X-Sentinel-Pin`) | Full CaMeL pipeline |
| WebSocket | First-message PIN auth + failure lockout | Full CaMeL pipeline via ChannelRouter |
| SSE | PIN header (existing middleware) | Read-only event stream |
| MCP | Transport-level (exempt from PIN middleware) | `run_task` tool → full CaMeL pipeline |
| Signal | Phone number (not yet registered) | Full CaMeL pipeline via ChannelRouter |

**Trust tiering:** The trust router classifies operations as SAFE (memory search, health check, session info) or DANGEROUS (everything else). SAFE operations execute directly. DANGEROUS operations route through the full CaMeL pipeline with scanning, planning, approval, and provenance tracking.

**Event bus isolation:** Each task gets a unique UUID. Channels subscribe only to events for their active task. No cross-task or cross-channel event leakage.

## Known Limitations

- **False positive rate:** ~4.7% estimated after script gate reform (was 18.8% — the old strict-ASCII gate caused 75% of FPs)
- **Script gate allowlist:** permits Latin Extended + typographic Unicode but blocks non-Latin scripts; genuine non-English content still needs translation by the planner
- **Single-user:** no multi-tenant isolation (planned for future phases)
- **No Llama Guard:** content safety model (violence, hate, weapons) was intentionally skipped — not the primary threat model
- **MCP auth:** currently exempt from PIN middleware — relies on transport-level auth. Will need strengthening for remote access
