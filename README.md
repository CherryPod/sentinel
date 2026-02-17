# Sentinel

> **v0.1.0-alpha** — core architecture complete, container deployment in progress.

A defence-in-depth AI assistant built on the [CaMeL architecture](https://arxiv.org/abs/2503.18813). A frontier model (Claude) plans tasks, an air-gapped local LLM (Qwen) executes them, and a Python security gateway enforces 10 layers of scanning between every step. The worker LLM is assumed compromised at all times — it only receives text and returns text, and every output is scanned before the system acts on it.

## What Makes This Different

- **Air-gapped worker** — the local LLM has zero network access. It cannot phone home, exfiltrate data, or fetch remote payloads
- **10-layer security pipeline** — deterministic policy engine, spotlighting, Prompt Guard, CodeShield, command pattern scanner, encoding scanner, conversation analysis, vulnerability echo detection, ASCII prompt gate, and CaMeL provenance tracking
- **Tiered trust model** — the worker starts with zero trust (text in/out only). Capabilities unlock incrementally after red team passes at each level
- **Human approval gates** — every plan is shown to the user before execution. No autonomous action without consent
- **CaMeL provenance** — every data item is tagged with its source and trust level. Untrusted data cannot reach dangerous operations without scanning and approval

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    sentinel (Python/FastAPI)                  │
│                  HTTPS :8443 / HTTP :8080                     │
│                                                              │
│  Static UI (/)  │  REST API (/api/*)  │  WebSocket (/ws)     │
│  SSE (/api/events)  │  MCP server (/mcp/)                    │
│                                                              │
│  POST /task  ─→  Input validation  ─→  Conversation analysis │
│              ─→  Prompt Guard scan ─→  Claude plans          │
│              ─→  Human approval    ─→  Per-step execution:   │
│                                                              │
│     llm_task:  prompt gate → Qwen → CodeShield → scan       │
│     tool_call: policy check → execute → tag provenance       │
│                                                              │
│  10 security layers  │  Policy engine  │  Provenance store   │
│  Memory (SQLite+vec) │  Event bus      │  Channel router     │
└───────────────────────────┬─────────────────────────────────┘
                            │ sentinel_internal (air-gapped)
┌───────────────────────────▼─────────────────────────────────┐
│              sentinel-ollama (Ollama, GPU)                    │
│                                                              │
│     Qwen 3 14B Q4_K_M — text in, text out (GPU)             │
│     nomic-embed-text — embeddings for memory search (CPU)    │
│     No internet  │  No tools  │  No file access              │
└─────────────────────────────────────────────────────────────┘
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
| 1 | PIN Authentication | ASGI middleware | Unauthenticated API access |
| 2 | Policy Engine | Deterministic YAML | File paths, commands, credentials, network |
| 3 | Spotlighting | String manipulation | Prompt injection (dynamic markers, sandwich defence) |
| 4 | Prompt Guard 2 | 86M BERT classifier | Injection detection |
| 5 | CodeShield | Semgrep static analysis | Malicious code patterns |
| 6 | CommandPatternScanner | Regex patterns | Dangerous shell patterns in prose |
| 7 | ConversationAnalyzer | Multi-turn heuristics | Memory poisoning, escalation, context building |
| 8 | VulnerabilityEchoScanner | Input/output fingerprinting | Code injection via "review this" framing |
| 9 | ASCII Prompt Gate | Regex allowlist | Cross-model bilingual injection |
| 10 | CaMeL Provenance | Data tagging | Untrusted data reaching dangerous operations |

For details, see [docs/security-model.md](docs/security-model.md).

## Benchmark Results

**Stress test v3** — 1,136 prompts (314 genuine + 788 adversarial + 34 benchmark), 21+ adversarial attack categories:

| Metric | Result |
|--------|--------|
| Real risk rate | **0.12%** (1/811 adversarial prompts) |
| Raw escape rate | 25.8% (209/811) |
| After triage | 70% planner-defused, 22% benign, 5% educational |
| Genuine pass rate | 79.7% |

The raw escape rate is misleading — most "escapes" are cases where Claude or Qwen refused the adversarial request. After manual triage, only 1 prompt out of 811 adversarial produced genuinely dangerous output.

Analysis scripts are in [`scripts/`](scripts/).

## Quick Start

### Prerequisites

- [Podman](https://podman.io/) (rootless) + podman-compose
- NVIDIA GPU with 12GB+ VRAM (for Qwen 3 14B)
- [NVIDIA Container Toolkit](https://docs.nvidia.com/datacenter/cloud-native/container-toolkit/latest/install-guide.html) with CDI configured
- Anthropic API key (for Claude planner)
- HuggingFace token (for Prompt Guard 2 model download at build time)

### Setup

```bash
# Clone
git clone https://github.com/CherryPod/sentinel.git
cd sentinel

# Create secrets directory
mkdir -p secrets
echo "your-anthropic-api-key" > secrets/claude_api_key.txt
echo "your-pin-code" > secrets/sentinel_pin.txt
chmod 600 secrets/*.txt

# Create Podman secrets
podman secret create claude_api_key secrets/claude_api_key.txt
podman secret create sentinel_pin secrets/sentinel_pin.txt

# Build (needs HuggingFace token for Prompt Guard model)
echo "your-hf-token" > secrets/hf_token.txt
podman build \
  --secret id=hf_token,src=secrets/hf_token.txt \
  -t sentinel:latest \
  -f container/Containerfile .

# Start
podman compose up -d

# Pull the Qwen model into Ollama (first run only)
podman exec sentinel-ollama ollama pull qwen3:14b

# Verify
curl -sk https://localhost:3001/api/health | python3 -m json.tool
```

Open `https://localhost:3001` in a browser (accept the self-signed certificate warning). Enter your PIN to authenticate.

For detailed deployment instructions, see [docs/deployment.md](docs/deployment.md).

## Project Structure

```
sentinel/
├── README.md                   This file
├── LICENSE                     Apache-2.0
├── CONTRIBUTING.md             Contributor guide
├── SECURITY.md                 Vulnerability reporting
├── pyproject.toml              Python package config
│
├── sentinel/                   Python package (security gateway + orchestrator)
│   ├── core/                   Config, database, event bus, models
│   ├── security/               Scanners, policy engine, pipeline
│   ├── planner/                Claude planner, orchestrator, trust router
│   ├── worker/                 Provider ABCs, Ollama/Qwen client, factory
│   ├── tools/                  Policy-checked tool executor + WASM sidecar client
│   ├── session/                Session + conversation tracking
│   ├── api/                    FastAPI app, auth, middleware
│   ├── audit/                  Structured JSON logging
│   ├── memory/                 Embeddings, chunks, RRF hybrid search
│   ├── channels/               WebSocket, SSE, MCP, Signal
│   └── routines/               Cron, event, interval scheduling
│
├── tests/                      1006 Python tests
├── ui/                         Static chat UI (HTML/JS/CSS)
│
├── sidecar/                    Rust WASM tool sandbox (Wasmtime, 41 tests)
├── container/                  Containerfile + TLS config
├── podman-compose.yaml         2-container deployment
├── policies/                   Deterministic security rules (YAML)
├── scripts/                    Stress test runner + analysis
│
└── docs/
    ├── architecture.md         Technical reference
    ├── security-model.md       Security deep dive
    ├── deployment.md           Operations guide
    ├── codebase-map.md         Developer navigation reference
    └── CHANGELOG.md            Version history
```

## Documentation

| Document | Description |
|----------|-------------|
| [Architecture](docs/architecture.md) | Container specs, network topology, API endpoints, data flow |
| [Security Model](docs/security-model.md) | CaMeL trust model, 10 security layers, threat model |
| [Deployment](docs/deployment.md) | Prerequisites, setup, rebuild procedures, troubleshooting |
| [Codebase Map](docs/codebase-map.md) | Module responsibilities, key classes, cross-dependencies |
| [Changelog](docs/CHANGELOG.md) | Full version history with decision rationale |

## Current Status

**v0.1.0-alpha** — core architecture complete, not yet validated in production.

- 1006 Python tests + 41 Rust tests passing (1047 total)
- Stress tested with 1,136 prompts (0.12% real risk rate)
- 10-layer security pipeline with 6 hardening passes
- Persistent memory with RRF hybrid search (FTS5 + sqlite-vec)
- Multi-channel access: REST, WebSocket, SSE, MCP server, Signal
- WASM tool sandbox (Wasmtime sidecar with capability model)
- Background routines (cron, event, interval triggers)
- Multi-provider LLM abstraction (config-driven factory)
- Trust level 0 (text in/out only — no file writes or tool execution by the worker)

## License

[Apache License 2.0](LICENSE)

## Credits

Built with [Claude](https://claude.ai) (Anthropic) as the trusted planner and [Qwen 3](https://huggingface.co/Qwen) (Alibaba) as the air-gapped worker. Security scanning by [Prompt Guard 2](https://huggingface.co/meta-llama/Prompt-Guard-2-86M) (Meta) and [CodeShield](https://github.com/meta-llama/PurpleLlama/tree/main/CodeShield) (Meta/Semgrep).
