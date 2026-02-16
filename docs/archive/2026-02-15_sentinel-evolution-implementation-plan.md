# Sentinel Evolution: Implementation Plan

**Date:** 2026-02-15
**Status:** Approved plan — implementation not yet started
**Prerequisite:** Stress test v3 must complete and results reviewed before Phase 1
**Related:** `2026-02-15_ironclaw-sentinel-combined-architecture.md` (full analysis)

---

## Context

Sentinel is a CaMeL-based security gateway (10-layer scan pipeline, air-gapped Qwen worker, human approval gate) that currently has no assistant features — no channels, no memory, no tools beyond basic shell execution. IronClaw (nearai/ironclaw, Apache-2.0) is a Rust AI assistant with excellent WASM tool sandboxing, multi-channel access, and persistent memory, but weak security depth.

The goal is to combine both: restructure Sentinel in-place, add IronClaw-inspired features (channels, memory, WASM tool sandbox, routines, MCP), and ship to GitHub as a hardened AI helper with a unique tiered trust model — fast-path safe ops, gate dangerous ops through CaMeL.

No existing product combines all of: full assistant features, formal trust propagation (CaMeL provenance), air-gapped local worker, 10-layer adversarial defence, human-in-the-loop approval, sandboxed tool ecosystem, and persistent semantic memory.

---

## Key Decisions

- **Restructure ~/sentinel/ in-place** (not on GitHub yet, no public history to preserve)
- **Two containers**: sentinel (everything) + ollama (air-gapped, any Ollama model)
- **Rust WASM sidecar from day one** — no intermediate Python sandbox
- **SQLite + sqlite-vec** for persistence (no PostgreSQL)
- **FastAPI serves UI** (no nginx container)
- **signal-cli as managed subprocess** (no separate container)
- **Internal asyncio pub/sub** (no MQTT broker)
- **Single-user with user_id column from day one** (cheap now, painful to retrofit)
- **Any Ollama model** — user configurable via env var, not locked to Qwen
- **Static allowlist for safe/dangerous boundary** — LLM does NOT classify its own operations
- **Embeddings via Ollama on CPU** (nomic-embed-text) — avoids VRAM contention with worker LLM

---

## Final Architecture

```
┌──────────────────────────────────────────────────────┐
│              sentinel (single container)               │
│                                                        │
│  FastAPI (uvicorn, TLS)                               │
│  ├── /api/*        → security pipeline + CaMeL        │
│  ├── /ws           → WebSocket channels                │
│  ├── /sse          → Server-Sent Events                │
│  ├── /webhooks/*   → Telegram, Slack, Signal           │
│  ├── /*            → static UI files                   │
│  │                                                     │
│  ├── CaMeL pipeline (Claude planner + approval)        │
│  ├── 10 security layers (preserved from Sentinel)      │
│  ├── Policy engine (YAML rules)                        │
│  ├── Provenance tagging                                │
│  │                                                     │
│  ├── Memory (SQLite + sqlite-vec, RRF hybrid search)   │
│  ├── Secrets (AES-256-GCM encrypted in SQLite)         │
│  │                                                     │
│  ├── Routine engine (cron + event triggers)             │
│  ├── Tiered trust router (safe → fast, dangerous → CaMeL)│
│  ├── MCP client (Python mcp library)                   │
│  │                                                     │
│  ├── signal-cli (managed subprocess, JSON-RPC)          │
│  └── Rust WASM sidecar (managed subprocess, Unix socket)│
│                                                        │
│  Volume: /data (SQLite, workspace, config)             │
└───────────────────┬────────────────────────────────────┘
                    │ sentinel_internal (air-gapped)
┌───────────────────▼────────────────────────────────────┐
│              ollama (single container)                   │
│                                                        │
│  Worker LLM (any model, GPU, air-gapped)               │
│  Embedding model (nomic-embed-text, CPU)                │
│  Only accepts connections from sentinel container       │
└────────────────────────────────────────────────────────┘
```

### Tiered Trust Model (The Key Innovation)

```
User message arrives via any channel
    │
    ├── Safe operation? (memory search, status queries, etc.)
    │   └── Execute directly via WASM sandbox → fast response
    │
    └── Dangerous operation? (everything else, by default)
        └── Route through CaMeL pipeline:
            1. Claude plans the execution
            2. Human approves the plan
            3. Each step scanned by 10 security layers
            4. Air-gapped LLM executes
            5. Output scanned before returning
```

---

## Phase 0: Foundation (Can Start Immediately)

**Goal**: Project restructure, database schema, Rust sidecar skeleton, event bus. Preparatory work that doesn't touch running containers.

**Dependencies**: None (stress test can still be running)

### 0.1 — Restructure to Python package

Move from `controller/app/*.py` flat layout to a proper `sentinel/` Python package:

```
sentinel/
├── core/           # config.py, models.py, db.py (NEW), bus.py (NEW)
├── security/       # pipeline, scanner, prompt_guard, codeshield, spotlighting,
│                   # conversation, provenance, policy_engine, leak_detector (NEW)
├── planner/        # planner.py, orchestrator.py, trust_router.py (NEW)
├── worker/         # ollama.py (from worker.py), provider.py (NEW)
├── tools/          # executor.py (from tools.py), registry.py (NEW), sidecar.py (NEW)
├── memory/         # store.py, chunks.py, search.py, embeddings.py (ALL NEW)
├── channels/       # base.py, web.py, signal_channel.py, mcp_channel.py (ALL NEW)
├── routines/       # engine.py, store.py (ALL NEW)
├── session/        # store.py (from session.py, evolves to SQLite)
├── api/            # app.py, middleware.py, auth.py, routes/ (split from main.py)
└── audit/          # logger.py (from audit.py)
```

Also:
- `pyproject.toml` replaces `requirements.txt`
- `tests/` moves from `controller/tests/`, reorganised to mirror package
- `ui/` moves from `gateway/static/`
- All 562 existing tests must pass after restructure (imports updated)

**Critical files**: `controller/app/main.py` (split into `api/app.py` + `api/routes/`), all test files (import path updates)

### 0.2 — SQLite + sqlite-vec database

File: `sentinel/core/db.py`

Currently everything is in-memory (SessionStore dict, provenance dict, approval dict). Add SQLite tables for:

- **sessions** + **conversation_turns** (replaces in-memory SessionStore)
- **provenance** + **file_provenance** (replaces in-memory dicts in provenance.py)
- **approvals** (replaces in-memory ApprovalManager._pending)
- **memory_chunks** + FTS5 index + sqlite-vec virtual table (NEW)
- **routines** (NEW)
- **audit_log** (structured supplement to JSONL files)

All tables include `user_id TEXT DEFAULT 'default'` from day one.

### 0.3 — Rust WASM sidecar skeleton

Directory: `sidecar/`

```
sidecar/
├── Cargo.toml      # wasmtime, tokio, serde, serde_json
└── src/
    ├── main.rs         # Unix socket listener (/tmp/sentinel-sidecar.sock)
    ├── protocol.rs     # JSON request/response types
    ├── sandbox.rs      # Wasmtime engine, capability enforcement, resource limits
    ├── registry.rs     # Tool metadata, WASM binary checksums
    ├── capabilities.rs # Deny-by-default capability model
    └── config.rs       # Resource limits, allowlists
```

Skeleton that compiles and accepts/returns JSON over Unix socket. Full WASM execution logic comes in Phase 4.

### 0.4 — Internal event bus

File: `sentinel/core/bus.py`

`asyncio`-based pub/sub replacing MQTT. Topics: `task.*`, `approval.*`, `session.*`, `channel.*`, `routine.*`, `memory.*`

### Verification
- `pytest tests/` — all 562 tests pass with updated imports
- `python -c "from sentinel.core.db import init_db; init_db(':memory:')"` — creates all tables
- `cargo check` in `sidecar/` — compiles clean
- Event bus unit tests pass

---

## Phase 1: Infrastructure Consolidation (After Stress Test)

**Goal**: 3 containers → 2. Merge UI into controller, migrate in-memory stores to SQLite, add tiered trust router.

**Depends on**: Phase 0 complete, stress test results reviewed

### 1.1 — Eliminate nginx container

- FastAPI serves `ui/` static files via `StaticFiles(directory="ui", html=True)`
- Replicate nginx security headers as FastAPI middleware:
  - `X-Frame-Options: DENY`
  - `X-Content-Type-Options: nosniff`
  - `Strict-Transport-Security: max-age=31536000; includeSubDomains`
  - `Content-Security-Policy: default-src 'self'; ...`
  - `Referrer-Policy: strict-origin-when-cross-origin`
- TLS: uvicorn with `--ssl-keyfile`/`--ssl-certfile` (self-signed cert generated at build time)
- Remove `sentinel-ui` service from compose
- sentinel container gets ports 3001 (HTTPS) + 3002 (HTTP redirect)

**Critical**: Test all security headers explicitly — missing one is a regression.

### 1.2 — Migrate in-memory stores to SQLite

One store at a time, same API surface, SQLite backend:

1. **SessionStore** — `dict` + `Lock` → SQLite sessions/turns tables. TTL eviction becomes periodic `DELETE WHERE last_active < ...`
2. **Provenance store** — `_store` dict → provenance/file_provenance tables
3. **ApprovalManager** — `_pending` dict → approvals table

Each migrated independently, tested independently. Existing test assertions unchanged.

### 1.3 — Tiered trust router

File: `sentinel/planner/trust_router.py`

Conservative static allowlist for safe operations. **Everything else is dangerous by default.** The LLM does NOT classify its own operations — that's a circular trust problem.

```python
SAFE_OPS = frozenset({"memory_search", "memory_list", "routine_list",
                       "routine_status", "health_check", "session_info"})
```

Safe ops bypass CaMeL planning/approval but still go through basic auth and the WASM sandbox. Dangerous ops get the full pipeline: Claude plans → human approves → 10-layer scan → air-gapped LLM executes → output scanned.

### 1.4 — Two-container compose file

```yaml
services:
  sentinel:
    build: {context: ., dockerfile: container/Containerfile}
    container_name: sentinel
    networks: [sentinel_internal, sentinel_egress]
    ports: ["3001:8443", "3002:8080"]
    volumes:
      - sentinel-data:/data
      - ./policies:/policies:ro
      - ./logs:/logs
    secrets: [claude_api_key, sentinel_pin]
    read_only: true
    tmpfs: ["/tmp:size=100M,noexec"]
    mem_limit: 4G
    cpus: 4.0

  ollama:
    image: docker.io/ollama/ollama@sha256:<pinned>
    container_name: sentinel-ollama
    networks: [sentinel_internal]
    devices: [nvidia.com/gpu=all]
    volumes: [sentinel-ollama-data:/root/.ollama]
    mem_limit: 14G
    cpus: 4.0

networks:
  sentinel_internal: {driver: bridge, internal: true}
  sentinel_egress: {driver: bridge}
```

Air-gapped topology preserved. Multi-stage Containerfile: Rust build stage → Python stage → final image with both.

### 1.5 — Config updates

Add to `sentinel/core/config.py`:
- `db_path`, `sidecar_socket`, `static_dir`, `tls_cert_file`, `tls_key_file`
- `embeddings_model` (default: `nomic-embed-text`)
- `ollama_model` configurable to any model (not hardcoded to Qwen)
- `user_id` (default: `default`)
- Remove MQTT settings

### Verification
- `podman compose up` starts 2 containers (not 3)
- UI loads at `https://localhost:3001/`
- API works at `https://localhost:3001/api/health`
- All security headers present (test explicitly)
- SQLite persists across container restarts
- Sessions, provenance, approvals survive restart
- Trust router classifies correctly (unit tests)

---

## Phase 2: Persistent Memory

**Goal**: Hybrid search memory system — store context, search with RRF.

**Depends on**: Phase 1 (SQLite, Ollama config)

### 2.1 — Embedding pipeline

File: `sentinel/memory/embeddings.py`

`nomic-embed-text` via Ollama on CPU (768 dimensions). Pull model into Ollama container alongside worker model — Ollama manages load/unload automatically.

### 2.2 — Chunk management

File: `sentinel/memory/chunks.py`

Store, update, delete memory chunks. Split large texts on paragraph/sentence boundaries (512 token target, 50 token overlap). Sync FTS5 index and vector embeddings on write.

**Note**: The embedding pipeline, chunk management, and FTS5 sync are where the real work is — not the RRF algorithm itself. Budget accordingly.

### 2.3 — RRF hybrid search

File: `sentinel/memory/search.py`

```
score(doc) = Σ 1/(k + rank)  for each search method where doc appears
```

FTS5 for keyword matching + sqlite-vec for semantic similarity, fused with k=60.

### 2.4 — Memory API + auto-memory

Endpoints: `POST /memory`, `GET /memory/search`, `GET /memory/{id}`, `DELETE /memory/{id}`

Auto-memory: after successful task completion, store conversation summary as a memory chunk (configurable via `auto_memory: bool`).

### Verification
- Store/search/delete roundtrip works
- FTS5 returns keyword matches, vector returns semantic matches
- RRF fusion produces better results than either alone
- `nomic-embed-text` runs on CPU without impacting worker LLM GPU inference

---

## Phase 3: Multi-Channel Access

**Goal**: WebSocket/SSE web upgrade, Signal messaging, MCP server.

**Depends on**: Phase 1 (event bus), Phase 2 (memory for contextual conversations)

### 3.1 — Channel abstraction

File: `sentinel/channels/base.py`

ABC: `receive()` → `AsyncIterator[IncomingMessage]`, `send()`, `start()`, `stop()`

`ChannelRouter` merges all channels into a single `asyncio.Queue`, routes responses back to originating channel.

### 3.2 — Web channel upgrade

File: `sentinel/channels/web.py`

WebSocket at `/ws` + SSE fallback at `/events`. Update `ui/app.js` (~100 lines added) to prefer WebSocket, fall back to SSE, fall back to HTTP polling.

### 3.3 — Signal channel

File: `sentinel/channels/signal_channel.py`

signal-cli as managed subprocess in JSON-RPC mode (`asyncio.create_subprocess_exec`). Crash recovery with exponential backoff. Registration is a one-time setup script, not runtime code.

**Note**: signal-cli adds ~200MB (JRE + JAR). Consider making it an optional Containerfile layer.

### 3.4 — MCP server

File: `sentinel/channels/mcp_channel.py`

Expose Sentinel tools to MCP clients (Claude Desktop, etc.) via the Python `mcp` library. All requests route through trust router + security pipeline.

### Verification
- WebSocket streams responses in real-time
- SSE fallback works when WebSocket unavailable
- Signal: send message → get response
- MCP: Claude Desktop connects and can use Sentinel tools
- All channels go through trust router + security pipeline

---

## Phase 4: WASM Tool Sandbox (Parallel with Phases 2-3)

**Goal**: Rust sidecar with Wasmtime for sandboxed tool execution.

**Depends on**: Phase 0 (sidecar skeleton). Fully independent of Python phases — can be built in parallel.

### 4.1 — Wasmtime integration

File: `sidecar/src/sandbox.rs`

- Fresh Wasmtime instance per execution (no state persistence between calls)
- Fuel metering (CPU limit), memory cap (10MB default), epoch-based timeout (500ms tick)
- Deny-by-default: zero host functions linked unless capabilities grant them

### 4.2 — Capability model

File: `sidecar/src/capabilities.rs`

Capabilities: `ReadFile{paths}`, `WriteFile{paths}`, `HttpRequest{allowlist}`, `UseCredential{name}`, `InvokeTool{alias}`

Each tool declares required capabilities in its registry entry. Sidecar verifies before linking host functions.

### 4.3 — Credential injection + leak detection

- Python tells sidecar which credentials a tool needs per execution
- Sidecar provides them via host function at the WASM boundary
- Tool never sees raw credential values directly
- Leak detector (Aho-Corasick, 20+ patterns) scans all tool output before returning
- Patterns include: AWS keys (AKIA), GitHub PATs (ghp_), Slack tokens (xox), OpenAI keys (sk-), PEM keys, Bearer tokens, high-entropy hex

### 4.4 — HTTP allowlist + SSRF protection

Validate URLs against per-tool allowlist. After allowlist passes, resolve DNS and reject private IP ranges (127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16). Prevents DNS rebinding attacks. Require HTTPS by default.

### 4.5 — Python client

File: `sentinel/tools/sidecar.py`

`SidecarClient` communicates over Unix socket. Handles timeout, crash recovery, sidecar process restart.

### 4.6 — V1 tool set (deliberately small and well-audited)

5 tools: `file_read`, `file_write`, `shell_exec`, `http_fetch`, `memory_search`

Security enforcement is in the sidecar's capability model, not the tools themselves.

### Verification
- Sidecar starts, listens on Unix socket
- `file_read` can read `/workspace/test.txt` but NOT `/etc/shadow`
- `shell_exec` can run `ls` but NOT `curl`
- `http_fetch` can reach allowed URLs but NOT private IPs
- Credential injection works, credential wiped after execution
- Leak detector catches `AKIA...`, `ghp_...` in output
- Fuel limit stops infinite loops, memory limit prevents OOM
- `cargo test` passes

---

## Phase 5: Routines + Multi-Provider LLM

**Goal**: Background automation and model flexibility.

**Depends on**: Phases 1-4

### 5.1 — Routine engine

File: `sentinel/routines/engine.py`

Cron + event triggers. Persistent state in SQLite. Guardrails: cooldown period, max concurrent runs, global capacity limit. Routines go through the same trust router + security pipeline as user requests.

### 5.2 — Routine API

`POST/GET/PUT/DELETE /routines`, `POST /routines/{id}/run` (manual trigger)

### 5.3 — Multi-provider LLM abstraction

File: `sentinel/worker/provider.py`

`LLMProvider` ABC with `OllamaProvider` and `ClaudeProvider`. Config-driven: swap worker model freely (Qwen, Mistral, Llama, etc.). Planner and worker can use different providers.

### Verification
- Cron routine runs on schedule
- Event routine triggers on memory store
- Manual trigger works
- Swap Ollama model from Qwen to another, verify full pipeline still works

---

## Phase 6: Hardening + Open Source Release

**Goal**: Security audit, documentation, GitHub push.

**Depends on**: All previous phases

### Tasks
- **Test suite**: Target 800+ tests covering memory, channels, WASM, routines, trust router, end-to-end flows
- **Security audit**: Memory injection, routine manipulation, WASM escape, MCP injection, Signal injection
- **New attack surfaces**: Memory search results treated as untrusted (spotlighting + scanning). Routine creation requires approval. All MCP requests through trust router
- **Documentation**: README, SECURITY.md, CONTRIBUTING.md, ARCHITECTURE.md, WASM_TOOLS.md
- **Sanitise**: No personal paths, IPs, hostnames, secrets
- **CI**: GitHub Actions for pytest, cargo test, cargo clippy
- **License**: TBD (Apache-2.0 or MIT)
- **Credit**: IronClaw (Apache-2.0) credited in README + NOTICE file
- **Smoke test**: `podman compose up` from a clean clone works end-to-end

---

## Phase Dependency Graph

```
Phase 0 (foundation — can start immediately)
    │
    ├─────────────────────────┐
    ▼                         ▼
Phase 1 (consolidation)   Phase 4 (Rust WASM sidecar)
    │                         │
    ▼                         │
Phase 2 (memory)              │
    │                         │
    ▼                         │
Phase 3 (channels)            │
    │                         │
    ├─────────────────────────┘
    ▼
Phase 5 (routines + multi-provider)
    │
    ▼
Phase 6 (hardening + release)
```

Phase 4 (Rust sidecar) is fully independent and can be built in parallel with Phases 1-3.

---

## Risks to Watch

| Risk | Impact | Mitigation |
|------|--------|------------|
| sqlite-vec compatibility | Memory search won't work | Fallback: faiss-cpu with SQLite for metadata |
| signal-cli container size | +200MB image bloat | Optional Containerfile layer |
| WASI preview2 maturity | Complex tools won't compile to WASM | Keep v1 tool set simple, well-tested |
| Ollama concurrent models | Embedding + worker LLM contention | nomic-embed-text on CPU, worker on GPU |
| Test migration (562 tests) | Broken tests block all work | Careful batch rename, verify incrementally |
| Security header regression | nginx → FastAPI gap | Test every header explicitly in CI |
| Stress test results | May reveal new security gaps | Review results before starting Phase 1 |

---

## Open Questions (To Resolve During Implementation)

1. **Project name** — what to call the combined product for GitHub?
2. **License** — Apache-2.0 (matches IronClaw) or MIT (matches repo-scout)?
3. **Tool sandboxing v1 specifics** — exact WASI target version, WIT interface design
4. **Multi-user** — single-user v1 with user_id column ready for future multi-user
5. **IronClaw credit format** — NOTICE file, README section, or both?
6. **GPU sharing verification** — need to test nomic-embed-text (CPU) + Qwen (GPU) concurrent Ollama serving

---

*Plan created 2026-02-15 during IronClaw analysis session. IronClaw repository inspected: nearai/ironclaw (Apache-2.0). Sentinel state at time of planning: Phase 5+, 562 tests passing, stress test v3 in progress.*
