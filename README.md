# Sentinel

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
│                     sentinel-ui (nginx)                      │
│                   HTTPS :3001 / HTTP :3002                   │
│              Static chat UI + reverse proxy to API           │
└───────────────────────────┬─────────────────────────────────┘
                            │ /api/* → :8000
┌───────────────────────────▼─────────────────────────────────┐
│               sentinel-controller (Python/FastAPI)           │
│                                                              │
│  POST /task  ─→  Input validation  ─→  Conversation analysis │
│              ─→  Prompt Guard scan ─→  Claude plans          │
│              ─→  Human approval    ─→  Per-step execution:   │
│                                                              │
│     llm_task:  prompt gate → Qwen → CodeShield → scan       │
│     tool_call: policy check → execute → tag provenance       │
│                                                              │
│  10 security layers  │  Policy engine  │  Provenance store   │
└───────────────────────────┬─────────────────────────────────┘
                            │ sentinel_internal (air-gapped)
┌───────────────────────────▼─────────────────────────────────┐
│                sentinel-qwen (Ollama, GPU)                    │
│                                                              │
│           Qwen 3 14B Q4_K_M — text in, text out             │
│           No internet  │  No tools  │  No file access        │
└─────────────────────────────────────────────────────────────┘
```

| Component | Role | Trust Level | Network |
|-----------|------|-------------|---------|
| Claude API (Anthropic) | Privileged planner | Trusted | Internet (via controller) |
| Qwen 3 14B (Ollama) | Quarantined worker | **Never trusted** | Air-gapped only |
| Controller (FastAPI) | Security gateway | Deterministic | Both networks |
| UI (nginx) | Chat interface | Static files | Egress only |

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

Full benchmark data and analysis scripts are in [`benchmarks/`](benchmarks/). Assessment reports are in [`docs/assessments/`](docs/assessments/).

## Quick Start

### Prerequisites

- [Podman](https://podman.io/) (rootless) + podman-compose
- NVIDIA GPU with 12GB+ VRAM (for Qwen 3 14B)
- [NVIDIA Container Toolkit](https://docs.nvidia.com/datacenter/cloud-native/container-toolkit/latest/install-guide.html) with CDI configured
- Anthropic API key (for Claude planner)

### Setup

```bash
# Clone
git clone https://github.com/yourusername/sentinel.git
cd sentinel

# Create secrets
mkdir -p ~/.secrets
echo "your-anthropic-api-key" > ~/.secrets/claude_api_key.txt
echo "your-pin-code" > ~/.secrets/sentinel_pin.txt
chmod 600 ~/.secrets/*.txt

# Create Podman secrets
podman secret create claude_api_key ~/.secrets/claude_api_key.txt
podman secret create sentinel_pin ~/.secrets/sentinel_pin.txt

# Build the controller (needs HuggingFace token for Prompt Guard model)
echo "your-hf-token" > ~/.secrets/hf_token.txt
podman build \
  --secret id=hf_token,src=$HOME/.secrets/hf_token.txt \
  -t sentinel-controller:latest \
  -t sentinel_sentinel-controller:latest \
  -f controller/Dockerfile controller/

# Start all containers
podman compose up -d

# Verify
curl -sf http://localhost:8000/health | python3 -m json.tool
```

Open `https://your-host:3001` in a browser (accept the self-signed certificate warning).

For detailed deployment instructions, see [docs/deployment.md](docs/deployment.md).

## Project Structure

```
sentinel/
├── README.md                   This file
├── LICENSE                     Apache-2.0
├── CONTRIBUTING.md             Contributor guide
├── SECURITY.md                 Vulnerability reporting
├── podman-compose.yaml         Container orchestration
├── CLAUDE.md                   Claude Code project instructions
│
├── controller/                 Python security gateway + orchestrator
│   ├── app/                    20 source modules (FastAPI)
│   ├── tests/                  21 test files (435 unit tests)
│   ├── Dockerfile
│   └── requirements.txt
│
├── gateway/                    WebUI (nginx + static files)
│   ├── static/                 HTML/JS/CSS chat interface
│   ├── Dockerfile
│   └── nginx.conf
│
├── policies/                   Deterministic security rules
│   └── sentinel-policy.yaml
│
├── benchmarks/                 Stress test data + analysis
│   ├── v3-results.jsonl        1,136-prompt benchmark (6.9MB)
│   └── v3-runner.log
│
├── scripts/                    Test runners + analysis
│   ├── analyse_v3_results.py   Benchmark analysis script
│   ├── stress_test_v3.py       Adversarial prompt generator
│   └── run_stress_test_v3.sh   Unattended test runner
│
└── docs/                       Documentation
    ├── architecture.md         Technical reference
    ├── security-model.md       Security deep dive
    ├── deployment.md           Operations guide
    ├── roadmap.md              Planned features
    ├── CHANGELOG.md            Version history
    ├── design/                 Active design documents
    └── assessments/            Benchmark reports + audits
```

## Documentation

| Document | Description |
|----------|-------------|
| [Architecture](docs/architecture.md) | Container specs, network topology, API endpoints, data flow |
| [Security Model](docs/security-model.md) | CaMeL trust model, 10 security layers, threat model |
| [Deployment](docs/deployment.md) | Prerequisites, setup, rebuild procedures, troubleshooting |
| [Roadmap](docs/roadmap.md) | Planned features and evolution path |
| [Changelog](docs/CHANGELOG.md) | Full version history with decision rationale |
| [Benchmarks](benchmarks/) | v3 stress test data and analysis tools |

## Current Status

**Phase 5+ complete.** All 4 development tiers delivered, all 15 code review issues closed. The system is operational with:

- 435 unit tests passing
- v3 stress test benchmarked (1,136 prompts, 0.12% real risk rate)
- Infrastructure hardened (TLS, CSP, CSRF, resource limits, read-only FS, pinned images, health checks)
- Trust level 0 (text in/out only — no file writes or tool execution by the worker)

Next steps: code restructuring (Phase 0), memory system, multi-channel access (Signal, Telegram), WASM tool sandbox. See [docs/roadmap.md](docs/roadmap.md).

## License

[Apache License 2.0](LICENSE)

## Credits

Built with [Claude](https://claude.ai) (Anthropic) as the trusted planner and [Qwen 3](https://huggingface.co/Qwen) (Alibaba) as the air-gapped worker. Security scanning by [Prompt Guard 2](https://huggingface.co/meta-llama/Prompt-Guard-2-86M) (Meta) and [CodeShield](https://github.com/meta-llama/PurpleLlama/tree/main/CodeShield) (Meta/Semgrep).
