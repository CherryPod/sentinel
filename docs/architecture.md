# Architecture

Technical reference for Sentinel's CaMeL defence-in-depth architecture.

## Overview

Sentinel uses two containers connected by two networks. A frontier model (Claude API) plans tasks, an air-gapped local LLM (Qwen 3 14B) executes text work, and a Python/FastAPI controller enforces security between them. The controller also serves the static UI, handles WebSocket/SSE connections, and hosts the MCP server.

```
                        Internet
                           │
              ┌────────────┼────────────────────────┐
              │     sentinel_egress network          │
              │            │                         │
              │   ┌────────▼─────────────────┐      │
              │   │       sentinel           │      │
              │   │  FastAPI + uvicorn       │      │
              │   │  HTTPS :8443 / HTTP :8080│      │
              │   │                          │      │
              │   │  Static UI (/)           │      │
              │   │  REST API (/api/*)       │──── Claude API
              │   │  WebSocket (/ws)         │      │
              │   │  SSE (/api/events)       │      │
              │   │  MCP server (/mcp/)      │      │
              │   │  Security pipeline       │      │
              │   │  Memory (SQLite+vec)     │      │
              │   └────────┬─────────────────┘      │
              └────────────┼────────────────────────┘
              ┌────────────┼────────────────────────┐
              │   sentinel_internal (air-gapped)     │
              │            │                         │
              │   ┌────────▼────────┐                │
              │   │  sentinel-ollama│                │
              │   │  Ollama :11434  │                │
              │   │  Qwen 3 14B    │                │
              │   │  + nomic-embed │                │
              │   │  GPU (12GB)     │                │
              │   └─────────────────┘                │
              │   NO external routing                │
              └──────────────────────────────────────┘
```

## Containers

### sentinel

The security gateway, orchestrator, UI, and all communication channels. All requests pass through here.

| Setting | Value |
|---------|-------|
| Image | Custom (Python 3.12-slim, pinned digest) |
| Networks | `sentinel_internal` + `sentinel_egress` |
| Ports | `3003:8443` (HTTPS), `3004:8080` (HTTP redirect) |
| Resources | 4GB RAM (1GB reserved), 4 CPU |
| Filesystem | Read-only (tmpfs for /tmp, 100M, noexec) |
| Secrets | `claude_api_key`, `sentinel_pin` via Podman secrets |
| Volumes | `sentinel-workspace:/workspace`, `./policies:/policies:ro`, `./logs:/logs` |
| Health check | Python urllib to `/health`, 30s interval, 60s start_period |
| TLS | Self-signed cert generated at build time |

**Key environment:**
- `SENTINEL_OLLAMA_URL=http://sentinel-ollama:11434`
- `SENTINEL_OLLAMA_MODEL=qwen3:14b`
- `SENTINEL_PIN_REQUIRED=true`
- `SENTINEL_ALLOWED_ORIGINS` — CSRF origin allowlist
- `SENTINEL_MCP_ENABLED=true`
- `SENTINEL_SIGNAL_ENABLED=false`

### sentinel-ollama

The air-gapped worker LLM and embedding model. Has zero internet access by design.

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

**Models served:**
- `qwen3:14b` (Q4_K_M) — worker LLM, GPU
- `nomic-embed-text` — embedding model for memory search, CPU

## Networks

| Network | Type | Purpose |
|---------|------|---------|
| `sentinel_internal` | bridge, `internal: true` | Air gap — Ollama <-> Sentinel only. No external routing |
| `sentinel_egress` | bridge | Sentinel internet access (Claude API) |

## API Endpoints

All endpoints except `/health`, `/ws`, and `/mcp/*` require the `X-Sentinel-Pin` header when PIN auth is enabled. WebSocket handles its own PIN auth (first-message protocol). MCP uses transport-level auth.

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
| `WS` | `/ws` | WebSocket — real-time task execution with PIN auth |
| `GET` | `/api/events?task_id=...` | SSE stream — real-time task event updates |
| `POST` | `/api/memory` | Store text in memory |
| `GET` | `/api/memory` | List memory chunks |
| `DELETE` | `/api/memory/{id}` | Delete a memory chunk |
| `GET` | `/api/memory/search?q=...` | Hybrid search (FTS5 + vector RRF) |
| `ASGI` | `/mcp/*` | MCP server (4 tools: search_memory, store_memory, run_task, health_check) |

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

## Communication Channels

All channels route through the same CaMeL security pipeline. The `ChannelRouter` handles message routing and event bus subscription.

| Channel | Transport | Auth | Status |
|---------|-----------|------|--------|
| Web (HTTP) | REST polling | PIN header | Active |
| Web (WebSocket) | `/ws` JSON protocol | First-message PIN | Active |
| Web (SSE) | `/api/events` stream | PIN header | Active |
| MCP | `/mcp/` ASGI mount | Transport-level | Active |
| Signal | signal-cli JSON-RPC subprocess | Phone number | Code ready, not registered |

**WebSocket protocol:** Client sends `{"type": "auth", "pin": "..."}` as first message, then `{"type": "task", "request": "..."}` for tasks or `{"type": "approval", ...}` for approval decisions. Server sends typed events: `auth_ok`, `task.started`, `task.planned`, `task.step_completed`, `task.completed`, `error`.

**UI transport cascade:** Browser tries WebSocket first, falls back to SSE, then HTTP polling. Auto-reconnection with exponential backoff.

**Event bus:** Orchestrator publishes 5 lifecycle events per task (`started`, `planned`, `approval_requested`, `step_completed`, `completed`). Channels subscribe via `EventBus` for real-time delivery.

## Key Dependencies

```
fastapi>=0.115.0          uvicorn>=0.34.0
httpx>=0.28.0             pyyaml>=6.0
pydantic>=2.10.0          pydantic-settings>=2.7.0
python-json-logger>=3.0.0 sse-starlette>=2.0.0
transformers>=4.47.0      torch>=2.5.0 (CPU-only)
anthropic>=0.42.0         codeshield>=0.1.0 (includes semgrep)
slowapi                   sqlite-vec (optional)
pytest>=8.3.0             pytest-asyncio>=0.25.0
mcp>=1.0.0 (optional)
```
