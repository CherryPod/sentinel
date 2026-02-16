# Architecture

Technical reference for Sentinel's CaMeL defence-in-depth architecture.

## Overview

Sentinel uses three containers connected by two networks. A frontier model (Claude API) plans tasks, an air-gapped local LLM (Qwen 3 14B) executes text work, and a Python/FastAPI controller enforces security between them.

```
                        Internet
                           │
              ┌────────────┼────────────────────────┐
              │     sentinel_egress network          │
              │            │                         │
              │   ┌────────▼────────┐                │
              │   │   sentinel-ui   │                │
              │   │  nginx :8443    │                │
              │   │  HTTPS + proxy  │                │
              │   └────────┬────────┘                │
              │            │ /api/*                   │
              │   ┌────────▼────────────────┐        │
              │   │  sentinel-controller    │        │
              │   │  FastAPI :8000          │──── Claude API
              │   │  Security pipeline      │──── MQTT (host)
              │   └────────┬────────────────┘        │
              └────────────┼────────────────────────┘
              ┌────────────┼────────────────────────┐
              │   sentinel_internal (air-gapped)     │
              │            │                         │
              │   ┌────────▼────────┐                │
              │   │  sentinel-qwen  │                │
              │   │  Ollama :11434  │                │
              │   │  Qwen 3 14B    │                │
              │   │  GPU (12GB)     │                │
              │   └─────────────────┘                │
              │   NO external routing                │
              └──────────────────────────────────────┘
```

## Containers

### sentinel-controller

The security gateway and orchestrator. All requests pass through here.

| Setting | Value |
|---------|-------|
| Image | Custom (Python 3.12-slim, pinned digest) |
| Networks | `sentinel_internal` + `sentinel_egress` |
| Port | 8000 (internal, proxied by UI) |
| Resources | 4GB RAM (1GB reserved), 4 CPU |
| Filesystem | Read-only (tmpfs for /tmp, 100M, noexec) |
| Secrets | `claude_api_key`, `sentinel_pin` via Podman secrets |
| Volumes | `sentinel-workspace:/workspace`, `./policies:/policies:ro`, `./logs:/logs` |
| Health check | Python urllib to `/health`, 30s interval, 60s start_period |

**Key environment:**
- `SENTINEL_OLLAMA_URL=http://sentinel-qwen:11434`
- `SENTINEL_OLLAMA_MODEL=qwen3:14b`
- `SENTINEL_PIN_REQUIRED=true`
- `SENTINEL_ALLOWED_ORIGINS` — CSRF origin allowlist

### sentinel-qwen

The air-gapped worker LLM. Has zero internet access by design.

| Setting | Value |
|---------|-------|
| Image | `ollama/ollama` (pinned sha256 digest) |
| Networks | `sentinel_internal` ONLY |
| Port | None exposed to host |
| GPU | RTX 3060 12GB via CDI (`nvidia.com/gpu=all`) |
| Resources | 14GB RAM, 4 CPU |
| Volume | `sentinel-ollama-data:/root/.ollama` |
| Health check | Bash TCP to port 11434, 30s interval, 30s start_period |

**Key environment:**
- `OLLAMA_KEEP_ALIVE=5m` — releases GPU VRAM after 5 minutes idle

### sentinel-ui

Static chat interface with reverse proxy to the controller.

| Setting | Value |
|---------|-------|
| Image | `nginx:alpine` (pinned digest) |
| Networks | `sentinel_egress` |
| Ports | `3001:8443` (HTTPS), `3002:8080` (HTTP redirect) |
| Resources | 128MB RAM, 1 CPU |
| Filesystem | Read-only (tmpfs for /tmp, /var/cache/nginx, /run) |
| TLS | Self-signed cert generated at build time |
| Health check | wget to `https://localhost:8443/`, 30s interval, 5s start_period |

**Security headers:** CSP, HSTS, X-Frame-Options DENY, nosniff, XSS-Protection, Referrer-Policy.

## Networks

| Network | Type | Purpose |
|---------|------|---------|
| `sentinel_internal` | bridge, `internal: true` | Air gap — Qwen <-> Controller only. Subnet `172.30.0.0/24`. No external routing |
| `sentinel_egress` | bridge | Controller internet access (Claude API, MQTT via host) |

## API Endpoints

All endpoints except `/health` require the `X-Sentinel-Pin` header when PIN auth is enabled.

| Method | Path | Purpose |
|--------|------|---------|
| `GET` | `/health` | Status check — component health, PIN auth exempt |
| `GET` | `/validate/path?path=...&operation=read` | Policy check for file path |
| `GET` | `/validate/command?command=...` | Policy check for shell command |
| `POST` | `/scan` | Run all scanners on text `{"text": "..."}` |
| `POST` | `/process` | Qwen pipeline: scan -> spotlight -> Qwen -> scan |
| `POST` | `/task` | Full CaMeL pipeline (see Task Flow below) |
| `GET` | `/approval/{id}` | Check approval status (includes step details) |
| `POST` | `/approve/{id}` | Submit approval decision `{"granted": true/false, "reason": "..."}` |
| `GET` | `/session/{id}` | Debug: view session state and conversation history |

## Task Flow (POST /task)

```
User request
  → Input validation (Pydantic: strip, NFC normalize, length check)
  → Conversation analysis (8 heuristic rules + cumulative risk scoring)
  → Prompt Guard scan (injection detection)
  → Claude plans (with conversation history + chain-level assessment)
  → Human approval gate
  → For each step:
      llm_task:  resolve vars → prompt length gate (100K)
                 → ASCII prompt gate → Qwen generates
                 → CodeShield → output scan → vulnerability echo scan
      tool_call: resolve vars → policy check → execute → tag as TRUSTED
  → TaskResult returned (includes conversation info)
```

In `full` approval mode, `/task` returns `{"status": "awaiting_approval", "approval_id": "..."}`. Poll `/approval/{id}` then submit via `/approve/{id}`.

## Provenance Tracking

Every data item is tagged with:

| Field | Purpose |
|-------|---------|
| `trust_level` | "trusted" (user/Claude) or "untrusted" (Qwen/web/file) |
| `source` | user, claude, qwen, web, file, tool |
| `scan_results` | Output from all scanners |
| `derived_from` | Parent data IDs (provenance chain) |

**Rules:** Untrusted data cannot reach shell commands or network tools without scanning + approval. Trust level inherits — anything derived from untrusted stays untrusted.

## Trust Levels

| Level | Qwen Can Do | Approval Mode | Progression Criteria |
|-------|-------------|---------------|---------------------|
| 0 | Text in/out only | All plans require human approval | Starting point |
| 1 | Text in/out only | Auto-approve whitelisted actions | 50+ tasks, zero incidents |
| 2 | + Read-only file access | As Level 1 | Red team passes at L1 |
| 3 | + Write to /workspace | /workspace writes auto-approved | Red team passes at L2 |
| 4 | + Sandboxed shell (bubblewrap) | Restricted shell in sandbox | Only if needed |

**Current level: 0** — the worker can only generate text. File writes and tool execution are blocked by the provenance trust gate.

## Key Dependencies

```
fastapi>=0.115.0          uvicorn>=0.34.0
httpx>=0.28.0             pyyaml>=6.0
pydantic>=2.10.0          pydantic-settings>=2.7.0
python-json-logger>=3.0.0
transformers>=4.47.0      torch>=2.5.0 (CPU-only)
anthropic>=0.42.0         codeshield>=0.1.0 (includes semgrep)
slowapi                   pytest>=8.3.0
pytest-asyncio>=0.25.0
```
