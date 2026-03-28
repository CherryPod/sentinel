# Sentinel

A defence-in-depth AI assistant built on the [CaMeL architecture](https://arxiv.org/abs/2503.18813). A frontier model (Claude) plans tasks, an air-gapped local LLM (Qwen 3) executes them, and a Python/FastAPI controller enforces 10 layers of security scanning between every step. The worker LLM is assumed compromised at all times.

Built with [Claude](https://claude.ai) (Anthropic) as the trusted planner and [Qwen 3](https://huggingface.co/Qwen) (Alibaba) as the air-gapped worker. Security scanning by [Prompt Guard 2](https://huggingface.co/meta-llama/Prompt-Guard-2-86M) (Meta) and [Semgrep](https://semgrep.dev/) (r2c).

![Sentinel](ui/social-preview-v3.png)

**[Follow the build journey](https://cherrypod-sentinel.duckdns.org/)** — one developer, one GPU, building an AI security platform from scratch.

---

## Tested and Verified

Sentinel has been through continuous adversarial testing since day one. These are the results from the most recent comprehensive validation — a 38-hour unattended run covering every layer of the system.

### Unit Tests

| Metric | Value |
|--------|-------|
| Python tests | 5,252 |
| Rust tests (WASM sidecar) | 50 |
| **Total unit tests** | **5,302** |
| Test-to-source ratio | **1.55:1** (64K test LOC / 41K source LOC) |

### Adversarial Benchmark (1,136 prompts)

801 adversarial prompts across 20 attack categories — direct injection, encoding obfuscation, social engineering, path traversal, credential exfiltration, multi-turn escalation, OWASP LLM top 10, and more. Plus 335 genuine capability prompts to measure false positives.

| Metric | Value |
|--------|-------|
| Scanner defence rate | **93.6%** (750/801 adversarial prompts caught) |
| Zero-escape categories | **13 of 20** (including direct injection: 116 prompts, 100% blocked) |
| False positive rate | **5.7%** (19/335 genuine prompts incorrectly blocked) |
| Genuine completion rate | 88.7% (297/335) |
| Privacy boundary violations | **0** |

The 6.4% of adversarial prompts that passed the scanners were all contained by defence-in-depth: sandbox isolation (no network, read-only filesystem, no secrets) prevented any actual harm. Multi-turn session attacks accounted for 67% of scanner bypasses — a known limitation of single-turn scanning that is being actively addressed.

### Red Team (392 probes, 6 threat models)

| Threat Model | Probes | What It Tests | Exploits |
|--------------|--------|---------------|----------|
| Adversarial user | 81 | AI attacker (Claude Sonnet 4.5) runs adaptive campaigns | **0** |
| Data channel injection | 32 | Payloads via search results, messaging, email | **0** |
| Compromised planner | 64 | Malicious plans submitted directly, bypassing Claude | **0** |
| Container perimeter | 41 | Air gap, DNS side-channels, GPU isolation, container escape | **0** |
| Sandbox escape | 90 | 90 exploit techniques against the WASM sandbox | **0** |
| Database security | 84 | SQL injection, RLS bypass, privilege escalation, audit integrity | **0** |
| **Total** | **392** | | **0 exploits** |

The compromised planner test is the most critical — it simulates the worst case where the trusted planning model is fully hijacked. The scanning pipeline caught 73% of malicious plans outright. The remaining 27% were all contained by sandbox isolation and network air gap. This validates the CaMeL architecture's core claim: even when the planner is compromised, the system remains secure.

### Injection Benchmark (AgentDojo-inspired)

Inspired by [AgentDojo](https://agentdojo.spylab.ai/) — an evaluation framework for testing whether adversarial payloads embedded in tool outputs can hijack an AI agent into performing unintended actions. Sentinel's benchmark adapts this methodology to test injection resistance across all supported tool channels on the live system (not a simulation).

| Metric | Value |
|--------|-------|
| Test cases | 130 |
| Attack vectors | 6 (file, email, calendar, Signal, Telegram, web) |
| Payloads | 13 unique injection patterns |
| **Exploits** | **0** |
| **Pass rate** | **100%** |

The benchmark scripts are included in [`scripts/injection_benchmark/`](scripts/injection_benchmark/) for reproducibility.

### Functionality Tests (60 scenarios)

Real-world capability verification across code generation, debugging, end-to-end workflows, plan decomposition, and dependency management.

| Suite | What It Tests | Pass Rate |
|-------|--------------|-----------|
| Build | Code generation across languages and complexity tiers | 61.5% |
| Debug | Error diagnosis and fix-cycle convergence | 88.9% |
| End-to-end | File ops, web search, container builds | 87.5% |
| Plan quality | Decomposition accuracy and step calibration | 61.5% |
| Dependencies | Missing package detection and graceful degradation | 100% |
| **Overall** | | **82%** |

Build and plan quality scores are lower due to worker LLM non-determinism on complex tasks and over-decomposition of plans — areas of active improvement. Debug and E2E scores improved significantly from earlier runs (debug: 72% → 89%, E2E: 62% → 88%) thanks to episodic learning and dynamic replanning. Subsequent targeted re-testing after pipeline fixes showed further improvement (E2E reaching 100% on the subset tested), though a full re-run has not been completed since these scores were recorded.

### Validation Summary

| Metric | Value |
|--------|-------|
| Total adversarial + capability prompts | **~1,600** |
| Total unit tests | **5,302** |
| Validation run duration | **38 hours** (unattended) |
| Successful exploits | **0** |
| Privacy boundary violations | **0** |
| Real-world false positive rate | **5.7%** |

---

## Why This Architecture

Most AI agent deployments trust their LLM implicitly — the model's output is the product. Sentinel inverts this. The worker LLM is treated as an adversarial component whose every output is scanned, constrained, and verified before any action is taken. This defence-in-depth approach means that even if an attacker successfully prompt-injects the worker, the scanning pipeline, sandbox isolation, and provenance tracking prevent the compromised output from causing harm.

The privacy boundary is equally strict: the planner (Claude) never sees user data, file contents, or worker output. It receives only sanitised summaries and opaque identifiers. Sensitive data never leaves the local machine, even when using a cloud API for planning.

**Key principles:**

- **Air-gapped worker** — the local LLM has zero network access. It cannot phone home, exfiltrate data, or fetch remote payloads
- **10-layer security pipeline** — no single scanner carries the load. Defence is distributed across deterministic rules, ML classifiers, static analysis, and provenance tracking
- **Tiered trust model** — capabilities unlock incrementally after red team validation at each level
- **Human approval gates** — every plan is shown to the user before execution. No autonomous action without consent
- **CaMeL provenance** — every data item is tagged with its source and trust level. Untrusted data cannot reach dangerous operations without scanning and approval

## Architecture

```
+-----------------------------------------------------------------+
|                    sentinel (Python/FastAPI)                     |
|                  HTTPS :8443 / HTTP :8080                       |
|                                                                 |
|  Static UI (/)  |  REST API (/api/*)  |  WebSocket (/ws)       |
|  SSE (/api/events)  |  MCP server (/mcp/)                      |
|                                                                 |
|  POST /task  -->  Input validation  -->  Conversation analysis  |
|              -->  Prompt Guard scan -->  Claude plans            |
|              -->  Human approval    -->  Per-step execution:     |
|                                                                 |
|     llm_task:  prompt gate -> Qwen -> CodeShield -> scan        |
|     tool_call: policy check -> execute -> tag provenance        |
|                                                                 |
|  10 security layers  |  Policy engine  |  Provenance store      |
|  PostgreSQL (RLS)    |  Event bus      |  Channel router        |
+-----------------------------+-----------------------------------+
                              | sentinel_internal (air-gapped)
+-----------------------------v-----------------------------------+
|              sentinel-ollama (Ollama, GPU)                       |
|                                                                 |
|     Qwen 3 14B Q4_K_M -- text in, text out (GPU)               |
|     nomic-embed-text -- embeddings for memory search (CPU)      |
|     No internet  |  No tools  |  No file access                 |
+-----------------------------------------------------------------+
```

| Component | Role | Trust Level | Network |
|-----------|------|-------------|---------|
| Claude API (Anthropic) | Privileged planner | Trusted | Internet (via sentinel) |
| Qwen 3 14B (Ollama) | Quarantined worker | **Never trusted** | Air-gapped only |
| Sentinel (FastAPI) | Security gateway + UI + channels | Deterministic | Both networks |

## Security Model

Sentinel assumes the worker LLM is adversarial. Every output passes through a 10-layer scan pipeline before the system acts on it:

| # | Layer | Type | What It Catches |
|---|-------|------|-----------------|
| 1 | JWT Authentication | ASGI middleware | Unauthenticated API access |
| 2 | Policy Engine | Deterministic YAML | File paths, commands, credentials, network |
| 3 | Spotlighting | String manipulation | Prompt injection (dynamic markers, sandwich defence) |
| 4 | Prompt Guard 2 | 86M BERT classifier | Injection detection |
| 5 | CodeShield | Semgrep static analysis | Malicious code patterns |
| 6 | CommandPatternScanner | Regex patterns | Dangerous shell patterns in prose |
| 7 | ConversationAnalyzer | Multi-turn heuristics | Memory poisoning, escalation, context building |
| 8 | VulnerabilityEchoScanner | Input/output fingerprinting | Code injection via "review this" framing |
| 9 | ASCII Prompt Gate | Regex allowlist | Cross-model bilingual injection |
| 10 | CaMeL Provenance | Data tagging | Untrusted data reaching dangerous operations |

## Features

- **Dynamic replanning** — when a step fails, the planner re-evaluates and adjusts the remaining plan rather than aborting
- **Episodic learning** — the system remembers outcomes from previous tasks and applies those lessons to future ones
- **File patching** — incremental file modifications using CSS-selector-style anchors for deterministic targeting (no LLM-generated diffs)
- **Multi-channel access** — WebSocket, SSE, MCP server, Signal, Telegram, email, CalDAV
- **Routine scheduling** — cron, event, and interval triggers for automated tasks
- **Contact registry** — opaque identifiers for messaging, so the planner never sees phone numbers or email addresses
- **WASM tool sandbox** — Rust sidecar with Wasmtime, capability model, and leak detection. Network disabled, read-only filesystem, no secrets
- **PostgreSQL with RLS** — row-level security, role separation, full audit logging
- **Router fast path** — simple single-tool requests bypass the planner entirely for lower latency and cost
- **Multi-user support** — JWT authentication, per-user workspaces, settings panel, admin user management
- **Goal verification** — planner-as-judge with 3-tier verification (tool output scan → assertion evaluation → planner judgement)
- **Anchor allocator** — deterministic structural anchors for file patching across 7 languages (Python, HTML, CSS, Shell, YAML, JSON, TOML)
- **Cross-language code fixer** — detects and repairs when the worker outputs code in the wrong language
- **Plan-outcome memory** — episodic records store full plan JSON and phase outcomes for learning from failures
- **Keyword classifier** — routes requests to the right handler before planning, reducing unnecessary API calls

## Quick Start

### Prerequisites

- [Podman](https://podman.io/) (rootless) + podman-compose
- NVIDIA GPU with 12GB+ VRAM (for Qwen 3 14B)
- [NVIDIA Container Toolkit](https://docs.nvidia.com/datacenter/cloud-native/container-toolkit/latest/install-guide.html) with CDI configured
- Anthropic API key (for Claude planner)
- HuggingFace token (for Prompt Guard model download during build — [get one here](https://huggingface.co/settings/tokens))

### 1. Clone and create secrets

```bash
git clone https://github.com/CherryPod/sentinel.git
cd sentinel

# Create the secrets directory (gitignored)
mkdir -p secrets

# Required: Anthropic API key for the Claude planner
echo "sk-ant-your-key-here" > secrets/claude_api_key.txt
chmod 600 secrets/claude_api_key.txt
```

### 2. Optional: Set a PIN

```bash
# Optional: set a 4-digit PIN to protect the UI
echo "1234" > secrets/sentinel_pin.txt
chmod 600 secrets/sentinel_pin.txt
```

### 3. Build the sentinel image

```bash
# Store your HuggingFace token somewhere outside the repo
echo "hf_your-token-here" > /tmp/hf_token.txt

# Build (takes a few minutes — installs PyTorch, transformers, downloads Prompt Guard)
podman build \
  --secret id=hf_token,src=/tmp/hf_token.txt \
  -t sentinel \
  -f container/Containerfile .

# Tag with the compose name (podman-compose looks for this)
podman tag sentinel sentinel_sentinel

# Clean up the token
rm /tmp/hf_token.txt
```

### 4. Start the stack

```bash
podman compose up -d
```

This starts two containers:
- **sentinel** — the security gateway, API, and UI (ports 3001 HTTPS, 3002 HTTP)
- **sentinel-ollama** — air-gapped Ollama instance with GPU access

### 5. Download the Qwen model

```bash
podman exec sentinel-ollama ollama pull qwen3:14b
```

This downloads ~8GB. The model is stored in a persistent volume — you only need to do this once.

### 6. Open the UI

Go to **https://localhost:3001** in your browser.

- Accept the self-signed certificate warning
- Enter the PIN if you set one
- Type a task and hit Send — Claude will plan it, you approve, Qwen executes

### Verify the stack

```bash
# Health check
curl -sk https://localhost:3001/health | python3 -m json.tool

# Smoke test
bash scripts/smoke_test.sh
```

## Running Tests

```bash
# Python tests
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev,mcp]"
pytest tests/

# Or run inside the container
podman exec sentinel pytest /app/tests/

# Rust sidecar tests
cargo test --manifest-path sidecar/Cargo.toml
```

## Project Structure

```
sentinel/
├── sentinel/                   Python package (security gateway + orchestrator)
│   ├── core/                   Config, database, event bus, models
│   ├── security/               Scanners, policy engine, pipeline
│   ├── planner/                Claude planner, orchestrator, trust router
│   ├── worker/                 Ollama/Qwen client, provider ABCs
│   ├── tools/                  Policy-checked tool executor + file_patch
│   ├── session/                Session + conversation tracking
│   ├── api/                    FastAPI app, auth, middleware
│   ├── audit/                  Structured JSON logging
│   ├── memory/                 Embeddings, chunks, RRF search
│   ├── channels/               WebSocket, SSE, MCP, Signal, Telegram, email
│   ├── contacts/               Contact registry (opaque ID resolution)
│   ├── integrations/           CalDAV, IMAP, email services
│   ├── analysis/               Metadata extraction
│   ├── router/                 Keyword classifier, fast path, templates
│   └── routines/               Scheduled task engine (cron, event, interval)
│
├── tests/                      5,252 unit tests
├── sidecar/                    Rust WASM tool sandbox (50 tests)
├── ui/                         Static chat UI (HTML/JS/CSS)
├── container/                  Containerfiles
├── policies/                   Deterministic security rules (YAML)
├── scripts/                    Test runners + injection benchmark
└── docs/                       Documentation + feature guides
```

## Current Status

**v0.5.0** — Multi-user auth, goal verification, anchor allocator, 17/17 security audit complete. Trust level 4 active (full tool execution with human approval gates).

See [CHANGELOG](docs/CHANGELOG.md) for version history.

## License

[Apache License 2.0](LICENSE)
