# Sentinel Infrastructure Overhaul Plan

**Date:** 2026-02-15
**Author:** Infrastructure review agent (Claude Opus 4.6)
**Status:** DRAFT — pending human review
**Source documents:**
- `evolution-plan.md` (approved plan, authoritative, in this directory)
- `combined-architecture.md` (analysis, supplementary, in this directory)

---

## 4.1 — Executive Summary

### Current State

Sentinel is a production-hardened CaMeL-based AI security gateway running as 3 Podman containers on a home server ("thebeast"). It chains Claude (Anthropic API) as a privileged planner with an air-gapped Qwen 3 14B worker (via Ollama), defended by a 10-layer deterministic + ML security pipeline. The system has 562+ passing tests and has survived two rounds of adversarial stress testing (976 prompts, 5.5% escape rate).

The codebase is a flat Python module layout (`controller/app/*.py`) with all state held in memory. There is no persistence, no persistent memory, no multi-channel access, no tool sandboxing beyond policy-gated shell execution, and no background automation. The UI is a separate nginx container serving static files.

### Target State

A consolidated 2-container architecture (sentinel + ollama) that adds IronClaw-inspired features — persistent semantic memory with hybrid search, multi-channel access (WebSocket, SSE, Signal, MCP), a Rust WASM tool sandbox, routine automation, and a tiered trust router — while preserving every security layer, the air-gapped topology, and the CaMeL pipeline.

### Scope of Changes

- **Restructure**: Flat `controller/app/` → proper `sentinel/` Python package (~19 files relocated, all import paths updated)
- **Consolidate**: 3 containers → 2 (eliminate nginx, FastAPI serves UI directly)
- **Persist**: In-memory dicts → SQLite + sqlite-vec (sessions, provenance, approvals, memory)
- **Build new**: Memory system, channel abstraction, WASM sidecar, routine engine, trust router, event bus, multi-provider LLM, MCP client, Signal channel
- **Harden**: New attack surfaces for memory injection, routine manipulation, WASM escape, MCP/Signal injection

### Key Risks

1. **Package restructure** (Phase 0): Every import path changes. 562+ tests must pass. Highest regression risk.
2. **nginx elimination** (Phase 1): Security headers, TLS termination, reverse proxy must be replicated exactly.
3. **Rust WASM sidecar** (Phase 4): New language, new build pipeline, new process communication. Longest learning curve.
4. **Open-source sanitisation** (Phase 6): Personal paths (`/home/kifterz`), IPs, hostnames throughout codebase.

---

## 4.2 — Current State Assessment

### Container Topology

```
                        ┌─────────────────────────────────────┐
                        │  sentinel_egress (bridge, internet)  │
                        │                                      │
                        │  ┌─────────────────┐  ┌───────────┐ │
                        │  │sentinel-controller│  │sentinel-ui│ │
                        │  │  port 8000       │  │ 3001:8443 │ │
                        │  │  4GB / 4CPU      │  │ 3002:8080 │ │
                        │  │  read-only FS    │  │ 128MB/1CPU│ │
                        │  └────────┬─────────┘  └───────────┘ │
                        └───────────┼──────────────────────────┘
                                    │
                        ┌───────────┼──────────────────────────┐
                        │  sentinel_internal (air-gapped)       │
                        │           │                           │
                        │  ┌────────▼──────────┐               │
                        │  │   sentinel-qwen    │               │
                        │  │   Ollama/Qwen 14B  │               │
                        │  │   GPU (RTX 3060)   │               │
                        │  │   14GB / 4CPU      │               │
                        │  │   NO internet      │               │
                        │  └───────────────────┘               │
                        └──────────────────────────────────────┘
```

### File Layout

```
~/sentinel/
├── CLAUDE.md                        # Project rules (58 lines)
├── podman-compose.yaml              # 3 services, 2 networks, 2 secrets, 2 volumes
├── controller/
│   ├── Dockerfile                   # Python 3.12, torch CPU, Prompt Guard, semgrep
│   ├── requirements.txt             # 13 dependencies
│   ├── app/
│   │   ├── __init__.py              # Empty
│   │   ├── main.py                  # FastAPI app + all endpoints (543 lines)
│   │   ├── orchestrator.py          # CaMeL execution loop (695 lines)
│   │   ├── planner.py               # Claude API + plan generation (466 lines)
│   │   ├── pipeline.py              # Scan orchestrator (449 lines)
│   │   ├── scanner.py               # 4 scanner classes (512 lines)
│   │   ├── conversation.py          # 8-rule multi-turn analyzer (493 lines)
│   │   ├── policy_engine.py         # YAML policy validator (288 lines)
│   │   ├── worker.py                # Ollama async client (143 lines)
│   │   ├── tools.py                 # Tool executor + 7 tools (462 lines)
│   │   ├── session.py               # In-memory session store (142 lines)
│   │   ├── approval.py              # In-memory approval manager (192 lines)
│   │   ├── provenance.py            # In-memory trust tagging (115 lines)
│   │   ├── spotlighting.py          # Per-word data marking (33 lines)
│   │   ├── codeshield.py            # CodeShield/semgrep wrapper (136 lines)
│   │   ├── prompt_guard.py          # Prompt Guard 2 ML scanner (~100 lines)
│   │   ├── auth.py                  # PIN auth middleware (131 lines)
│   │   ├── config.py                # Pydantic settings (76 lines)
│   │   ├── models.py                # Pydantic data models (108 lines)
│   │   └── audit.py                 # JSON structured logger (~50 lines)
│   └── tests/
│       ├── conftest.py              # Shared fixtures
│       ├── adversarial_prompts.py   # Stress test prompt library
│       └── test_*.py                # 23 test files
├── gateway/
│   ├── Dockerfile                   # nginx:alpine + self-signed TLS
│   ├── nginx.conf                   # Security headers + reverse proxy
│   ├── static/
│   │   ├── index.html               # Chat UI
│   │   ├── app.js                   # UI logic (21KB)
│   │   └── style.css                # Styles (8KB)
│   └── app/                         # Empty directory
├── policies/
│   └── sentinel-policy.yaml         # 136 lines of deterministic rules
├── scripts/
│   ├── stress_test.py               # v2 test runner (194KB)
│   ├── stress_test_v3.py            # v3 test runner (284KB)
│   ├── run_stress_test.sh           # v2 runner script
│   └── run_stress_test_v3.sh        # v3 runner script
├── docs/
│   └── archive/                     # Historical documents
├── logs/                            # Runtime logs
├── secrets/                         # Local dev secrets (gitignored)
└── .venv/                           # Local development virtualenv
```

### Security Pipeline (10 Layers — All Must Be Preserved)

| Layer | Module | Type | What It Does |
|-------|--------|------|-------------|
| 1 | `auth.py` | Deterministic | PIN authentication + per-IP lockout |
| 2 | `policy_engine.py` | Deterministic | YAML rules: file paths, commands, networks |
| 3 | `spotlighting.py` | Deterministic | Per-word markers on untrusted data |
| 4 | `prompt_guard.py` | ML | BERT-based injection detection |
| 5 | `codeshield.py` | Static analysis | Semgrep rules for insecure code |
| 6 | `scanner.py:CommandPatternScanner` | Deterministic | Reverse shells, pipe-to-shell, encoded payloads |
| 7 | `scanner.py:CredentialScanner` | Deterministic | 12 regex patterns for secrets |
| 8 | `scanner.py:SensitivePathScanner` | Deterministic | Context-aware path scanning |
| 9 | `conversation.py` | Heuristic | 8 multi-turn attack detection rules |
| 10 | `provenance.py` | Formal | CaMeL trust tagging + chain walking |

**Additional hardening layers:**
- `scanner.py:VulnerabilityEchoScanner` — detects reproduced vulnerable code
- `scanner.py:EncodingNormalizationScanner` — decodes base64/hex/URL/ROT13/HTML/char-splitting
- ASCII Prompt Gate — blocks non-ASCII in worker prompts
- Prompt Length Gate — rejects prompts > 100K chars
- Sandwich defence — UNTRUSTED_DATA tags + post-data reminder
- Dynamic spotlighting marker — random per-request from symbol pool

### In-Memory State (Must Migrate to SQLite)

| Store | Location | Data Structure | Current Size Limit |
|-------|----------|---------------|-------------------|
| Sessions | `session.py:SessionStore._sessions` | `dict[str, Session]` | 1,000 sessions, 1hr TTL |
| Provenance | `provenance.py:_store` | `dict[str, TaggedData]` | 10,000 entries |
| File provenance | `provenance.py:_file_provenance` | `dict[str, str]` | 10,000 entries |
| Approvals | `approval.py:ApprovalManager._pending` | `dict[str, PendingApproval]` | No limit (TTL cleanup) |

### API Surface

| Method | Path | Handler | Notes |
|--------|------|---------|-------|
| GET | `/health` | `health()` | PIN-exempt |
| GET | `/validate/path` | `validate_path()` | Policy check |
| GET | `/validate/command` | `validate_command()` | Policy check |
| POST | `/scan` | `scan_text()` | Full pipeline scan |
| POST | `/process` | `process_text()` | Qwen pipeline |
| POST | `/task` | `handle_task()` | Full CaMeL (rate limited 10/min) |
| GET | `/approval/{id}` | `check_approval()` | Status check |
| POST | `/approve/{id}` | `submit_approval()` | Decision + execute |
| GET | `/session/{id}` | `get_session()` | Debug endpoint |

### What's Working Well

1. **Security pipeline is battle-tested** — 976 adversarial prompts, 93.3% combined catch rate
2. **CaMeL provenance is formally correct** — trust inheritance, chain walking, trust gates all work
3. **Air-gapped topology is sound** — sentinel_internal network has `internal: true`
4. **Test coverage is comprehensive** — 562+ tests across 23 files
5. **Planner system prompt is heavily hardened** — language safety, spotlighting awareness, anti-manipulation
6. **Fail-closed design** — Prompt Guard and CodeShield block when unavailable

### What's Fragile or Missing

1. **All state is in-memory** — container restart loses everything
2. **No persistence** — no database, no disk-backed storage
3. **Flat module layout** — 19 files in one directory, no logical grouping
4. **nginx as separate container** — unnecessary complexity for single-user tool
5. **MQTT references in config** — dead code, never implemented
6. **No real-time communication** — HTTP polling only, no WebSocket/SSE
7. **No memory system** — each conversation starts from scratch
8. **Tool sandbox is weak** — `subprocess.run()` with policy checks, no isolation
9. **Single LLM provider** — hardcoded to Ollama, model name in config
10. **No background automation** — no routines, no scheduling
11. **Personal paths hardcoded** — `/home/kifterz/.secrets/` in compose file

---

## 4.3 — Target State Architecture

### Two-Container Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                 sentinel (single container)                        │
│                                                                   │
│  FastAPI (uvicorn, TLS via --ssl-keyfile/--ssl-certfile)         │
│  ├── /api/*          → security pipeline + CaMeL                 │
│  ├── /ws             → WebSocket (bidirectional)                 │
│  ├── /events         → Server-Sent Events (streaming)            │
│  ├── /webhooks/*     → Telegram, Slack, Signal                   │
│  ├── /memory/*       → Memory CRUD + search                     │
│  ├── /routines/*     → Routine CRUD + triggers                  │
│  ├── /*              → Static UI files (index.html, app.js)     │
│  │                                                               │
│  ├── CaMeL pipeline (Claude planner + human approval gate)       │
│  ├── 10 security layers (fully preserved)                        │
│  ├── Policy engine (YAML rules)                                  │
│  ├── Provenance tagging (CaMeL trust propagation)               │
│  ├── Tiered trust router:                                        │
│  │   ├── Safe ops → WASM sandbox → fast response                │
│  │   └── Dangerous ops → full CaMeL pipeline → approved exec    │
│  │                                                               │
│  ├── Memory (SQLite + sqlite-vec, RRF hybrid search)            │
│  ├── Secrets (AES-256-GCM encrypted in SQLite)                  │
│  ├── Routine engine (cron + event triggers)                      │
│  ├── MCP client (Python mcp library)                            │
│  │                                                               │
│  ├── signal-cli (managed subprocess, JSON-RPC)                   │
│  └── Rust WASM sidecar (managed subprocess, Unix socket)        │
│                                                                   │
│  Volume: /data (SQLite DB, workspace, config, TLS certs)        │
│  Ports: 3001 (HTTPS), 3002 (HTTP redirect)                      │
│  Networks: sentinel_internal + sentinel_egress                   │
│  Resources: 4GB RAM, 4 CPU, read-only FS + /tmp tmpfs           │
└──────────────────────┬───────────────────────────────────────────┘
                       │ sentinel_internal (bridge, internal: true)
┌──────────────────────▼───────────────────────────────────────────┐
│                 ollama (single container)                          │
│                                                                   │
│  Worker LLM: configurable (default: qwen3:14b), GPU              │
│  Embedding model: nomic-embed-text, CPU                          │
│  Air-gapped: sentinel_internal network ONLY                      │
│  Resources: 14GB RAM, 4 CPU, RTX 3060 12GB                      │
└──────────────────────────────────────────────────────────────────┘
```

### Data Flow (Tiered Trust Model)

```
User message (any channel: Web/Signal/Telegram/MCP)
    │
    ├── PIN authentication (layer 1)
    │
    ├── Input scan (layers 4, 6, 7, 8, encoding scanner)
    │
    ├── Trust router classification
    │   │
    │   ├── SAFE operation (static allowlist)
    │   │   │  memory_search, memory_list, routine_list,
    │   │   │  routine_status, health_check, session_info
    │   │   │
    │   │   └── Execute via WASM sandbox → response
    │   │
    │   └── DANGEROUS operation (everything else, default)
    │       │
    │       ├── Conversation analysis (layer 9)
    │       ├── Claude planner creates JSON plan
    │       ├── Human approval gate
    │       ├── For each step:
    │       │   ├── Spotlighting (layer 3)
    │       │   ├── ASCII gate + prompt length gate
    │       │   ├── Air-gapped Qwen generates text
    │       │   ├── Output scan (layers 4-8, encoding scanner)
    │       │   ├── CodeShield (layer 5)
    │       │   ├── Vulnerability echo scan
    │       │   └── Provenance tagging (layer 10)
    │       │
    │       └── Scanned result → response via originating channel
    │
    └── Memory auto-save (if enabled)
```

### Package Structure (Target)

```
sentinel/                            # Python package root
├── __init__.py
├── core/
│   ├── config.py                    # Pydantic settings (evolved from controller/app/config.py)
│   ├── models.py                    # Data models (from controller/app/models.py)
│   ├── db.py                        # SQLite + sqlite-vec initialization + migrations
│   └── bus.py                       # asyncio pub/sub event bus
├── security/
│   ├── pipeline.py                  # Scan orchestrator (from pipeline.py)
│   ├── scanner.py                   # All scanner classes (from scanner.py)
│   ├── prompt_guard.py              # ML injection detection (from prompt_guard.py)
│   ├── codeshield.py                # Static code analysis (from codeshield.py)
│   ├── spotlighting.py              # Data marking (from spotlighting.py)
│   ├── conversation.py              # Multi-turn analyzer (from conversation.py)
│   ├── provenance.py                # Trust tagging (from provenance.py → SQLite-backed)
│   └── policy_engine.py             # YAML rules (from policy_engine.py)
├── planner/
│   ├── planner.py                   # Claude API client (from planner.py)
│   ├── orchestrator.py              # CaMeL execution loop (from orchestrator.py)
│   └── trust_router.py             # NEW: safe/dangerous classification
├── worker/
│   ├── ollama.py                    # Ollama client (from worker.py)
│   └── provider.py                  # NEW: multi-provider LLM abstraction
├── tools/
│   ├── executor.py                  # Tool executor (from tools.py)
│   ├── registry.py                  # NEW: tool metadata + discovery
│   └── sidecar.py                   # NEW: Rust WASM sidecar client
├── memory/
│   ├── store.py                     # NEW: CRUD operations
│   ├── chunks.py                    # NEW: text splitting + chunk management
│   ├── search.py                    # NEW: RRF hybrid search
│   └── embeddings.py                # NEW: Ollama embedding pipeline
├── channels/
│   ├── base.py                      # NEW: channel ABC + router
│   ├── web.py                       # NEW: WebSocket + SSE + HTTP
│   ├── signal_channel.py            # NEW: signal-cli subprocess
│   └── mcp_channel.py              # NEW: MCP server
├── routines/
│   ├── engine.py                    # NEW: cron + event triggers
│   └── store.py                     # NEW: SQLite-backed routine persistence
├── session/
│   └── store.py                     # Session store (from session.py → SQLite-backed)
├── api/
│   ├── app.py                       # FastAPI app creation + lifespan (from main.py)
│   ├── middleware.py                 # CSRF, size limit, security headers (from main.py)
│   ├── auth.py                      # PIN auth (from auth.py)
│   └── routes/
│       ├── health.py                # Health endpoint
│       ├── task.py                  # CaMeL task endpoints
│       ├── approval.py              # Approval endpoints
│       ├── scan.py                  # Scan/process endpoints
│       ├── validate.py              # Policy validation endpoints
│       ├── memory.py                # NEW: memory CRUD
│       ├── routines.py              # NEW: routine CRUD
│       └── session.py               # Session debug
└── audit/
    └── logger.py                    # Structured logging (from audit.py)
```

---

## 4.4 — Gap Analysis Results

### Preserve (No Changes to Logic)

These components are battle-tested and must be preserved exactly as-is during restructure. Only import paths change.

| Component | Current File | Target File | Notes |
|-----------|-------------|-------------|-------|
| CaMeL orchestrator logic | `orchestrator.py` | `planner/orchestrator.py` | Core execution loop unchanged |
| Claude planner | `planner.py` | `planner/planner.py` | System prompt + plan validation |
| Scan pipeline | `pipeline.py` | `security/pipeline.py` | All scanner orchestration |
| All 4 scanner classes | `scanner.py` | `security/scanner.py` | Credential, path, command, echo, encoding |
| Conversation analyzer | `conversation.py` | `security/conversation.py` | 8 heuristic rules |
| Policy engine | `policy_engine.py` | `security/policy_engine.py` | YAML validation logic |
| Spotlighting | `spotlighting.py` | `security/spotlighting.py` | Per-word marking |
| CodeShield wrapper | `codeshield.py` | `security/codeshield.py` | Semgrep patch + scan |
| Prompt Guard wrapper | `prompt_guard.py` | `security/prompt_guard.py` | BERT classifier |
| Provenance logic | `provenance.py` | `security/provenance.py` | Trust inheritance + chain walking |
| PIN auth | `auth.py` | `api/auth.py` | Constant-time comparison + lockout |
| Tool executor | `tools.py` | `tools/executor.py` | Policy-gated tool execution |
| Pydantic models | `models.py` | `core/models.py` | All data models |
| Policy YAML | `sentinel-policy.yaml` | Same location | Rules unchanged |
| Worker system prompt | `worker.py` | `worker/ollama.py` | Qwen prompt template |
| Planner system prompt | `planner.py:12` | `planner/planner.py` | Claude prompt template |

### Restructure (Same Logic, New Location/Backend)

| Component | Current | Target | Change |
|-----------|---------|--------|--------|
| Session store | In-memory dict + Lock | SQLite sessions + turns tables | Same API, SQLite backend |
| Provenance store | In-memory dict | SQLite provenance table | Same API, SQLite backend |
| Approval manager | In-memory dict | SQLite approvals table | Same API, SQLite backend |
| Config | Pydantic settings | Same + new fields | Add db_path, sidecar_socket, etc. |
| main.py | Monolithic (543 lines) | Split into api/app.py + routes/ | Same endpoints, modular structure |
| Dockerfile | controller/Dockerfile | container/Containerfile | Multi-stage, add Rust sidecar |
| compose | podman-compose.yaml | Same file, 2 services | Remove sentinel-ui |
| UI files | gateway/static/ | ui/ (served by FastAPI) | Same files, different host |

### Eliminate

| Component | Current Location | Reason |
|-----------|-----------------|--------|
| nginx container | `gateway/Dockerfile` + `nginx.conf` | FastAPI serves static files + TLS directly |
| sentinel-ui service | `podman-compose.yaml` lines 74-101 | Consolidated into sentinel container |
| MQTT config | `config.py` lines 43-48 | Never implemented; replaced by asyncio event bus |
| gateway/app/ | Empty directory | Dead code |
| `secrets/` directory | Project root | Should use `~/.secrets/` per CLAUDE.md |

### Build New

| Component | Target File(s) | Phase | Complexity |
|-----------|---------------|-------|------------|
| SQLite + sqlite-vec DB | `core/db.py` | 0 | Medium |
| asyncio event bus | `core/bus.py` | 0 | Low |
| Rust WASM sidecar skeleton | `sidecar/` | 0 | High |
| Trust router | `planner/trust_router.py` | 1 | Low |
| Security headers middleware | `api/middleware.py` | 1 | Low |
| TLS configuration | Containerfile + uvicorn config | 1 | Low |
| Embedding pipeline | `memory/embeddings.py` | 2 | Medium |
| Chunk management | `memory/chunks.py` | 2 | Medium |
| RRF hybrid search | `memory/search.py` | 2 | Medium |
| Memory store | `memory/store.py` | 2 | Low |
| Channel abstraction | `channels/base.py` | 3 | Medium |
| WebSocket + SSE | `channels/web.py` | 3 | Medium |
| Signal channel | `channels/signal_channel.py` | 3 | High |
| MCP server | `channels/mcp_channel.py` | 3 | Medium |
| Wasmtime integration | `sidecar/src/sandbox.rs` | 4 | High |
| Capability model | `sidecar/src/capabilities.rs` | 4 | High |
| Credential injection | Sidecar host functions | 4 | High |
| SSRF protection | Sidecar DNS resolution | 4 | Medium |
| Python sidecar client | `tools/sidecar.py` | 4 | Low |
| WASM tool set | 5 WASM tools | 4 | High |
| Routine engine | `routines/engine.py` | 5 | Medium |
| Multi-provider LLM | `worker/provider.py` | 5 | Medium |
| Leak detector (Aho-Corasick) | `security/scanner.py` | 4 | Low |
| Test suite expansion | `tests/` | 6 | High |
| Documentation | `docs/` | 6 | Medium |
| CI pipeline | `.github/workflows/` | 6 | Medium |

---

## 4.5 — Phased Implementation Plan

### Phase 0: Foundation (Can Start Immediately)

**Objective:** Restructure codebase into a proper Python package, create the SQLite database layer, scaffold the Rust sidecar, and build the internal event bus. This is pure preparation — no running containers are modified.

**Prerequisites:** None. Stress test can still be running.

---

#### Task 0.1 — Restructure to Python Package

**Files affected:**
- Create: `sentinel/__init__.py`, `sentinel/core/__init__.py`, `sentinel/security/__init__.py`, `sentinel/planner/__init__.py`, `sentinel/worker/__init__.py`, `sentinel/tools/__init__.py`, `sentinel/session/__init__.py`, `sentinel/api/__init__.py`, `sentinel/api/routes/__init__.py`, `sentinel/audit/__init__.py`
- Move: All 19 files from `controller/app/` to their target locations (see package structure in 4.3)
- Move: `controller/tests/` → `tests/` (project root)
- Move: `gateway/static/` → `ui/`
- Create: `pyproject.toml` (replaces `controller/requirements.txt`)
- Update: Every import in every source file and every test file

**What changes and why:**
The flat layout makes it impossible to add memory, channels, routines, and WASM modules without creating an unmanageable single directory. A package structure provides logical grouping, explicit public APIs per subpackage, and cleaner imports.

**Security implications:** None — this is a pure rename/restructure operation. No logic changes.

**Exact rename/move sequence:**

```
# Step 1: Create package directories
mkdir -p sentinel/{core,security,planner,worker,tools,memory,channels,routines,session,api/routes,audit}
touch sentinel/__init__.py
touch sentinel/{core,security,planner,worker,tools,memory,channels,routines,session,api,api/routes,audit}/__init__.py

# Step 2: Move files (one logical group at a time, test after each)
# -- Core
cp controller/app/config.py sentinel/core/config.py
cp controller/app/models.py sentinel/core/models.py

# -- Security
cp controller/app/pipeline.py sentinel/security/pipeline.py
cp controller/app/scanner.py sentinel/security/scanner.py
cp controller/app/conversation.py sentinel/security/conversation.py
cp controller/app/policy_engine.py sentinel/security/policy_engine.py
cp controller/app/spotlighting.py sentinel/security/spotlighting.py
cp controller/app/codeshield.py sentinel/security/codeshield.py
cp controller/app/prompt_guard.py sentinel/security/prompt_guard.py
cp controller/app/provenance.py sentinel/security/provenance.py

# -- Planner
cp controller/app/planner.py sentinel/planner/planner.py
cp controller/app/orchestrator.py sentinel/planner/orchestrator.py

# -- Worker
cp controller/app/worker.py sentinel/worker/ollama.py

# -- Tools
cp controller/app/tools.py sentinel/tools/executor.py

# -- Session
cp controller/app/session.py sentinel/session/store.py

# -- API
# main.py gets SPLIT (see Task 0.1b)
cp controller/app/auth.py sentinel/api/auth.py
cp controller/app/approval.py sentinel/api/approval.py

# -- Audit
cp controller/app/audit.py sentinel/audit/logger.py

# Step 3: Update imports in every moved file
# Step 4: Move tests
cp -r controller/tests/ tests/
# Step 5: Update test imports
# Step 6: Move UI
cp -r gateway/static/ ui/
```

**Critical detail — import path mapping:**

| Old Import | New Import |
|-----------|------------|
| `from .config import settings` | `from sentinel.core.config import settings` |
| `from .models import ...` | `from sentinel.core.models import ...` |
| `from .pipeline import ...` | `from sentinel.security.pipeline import ...` |
| `from .scanner import ...` | `from sentinel.security.scanner import ...` |
| `from .planner import ...` | `from sentinel.planner.planner import ...` |
| `from .orchestrator import ...` | `from sentinel.planner.orchestrator import ...` |
| `from .worker import ...` | `from sentinel.worker.ollama import ...` |
| `from .tools import ...` | `from sentinel.tools.executor import ...` |
| `from .session import ...` | `from sentinel.session.store import ...` |
| `from .provenance import ...` | `from sentinel.security.provenance import ...` |
| `from .conversation import ...` | `from sentinel.security.conversation import ...` |
| `from .spotlighting import ...` | `from sentinel.security.spotlighting import ...` |
| `from . import codeshield` | `from sentinel.security import codeshield` |
| `from . import prompt_guard` | `from sentinel.security import prompt_guard` |
| `from .auth import ...` | `from sentinel.api.auth import ...` |
| `from .approval import ...` | `from sentinel.api.approval import ...` |
| `from .audit import ...` | `from sentinel.audit.logger import ...` |

**Task 0.1b — Split main.py:**

`main.py` (543 lines) needs to be split into:
- `sentinel/api/app.py` — FastAPI app creation, lifespan, middleware registration
- `sentinel/api/middleware.py` — CSRFMiddleware, RequestSizeLimitMiddleware, input validation helpers
- `sentinel/api/routes/health.py` — `/health`
- `sentinel/api/routes/validate.py` — `/validate/path`, `/validate/command`
- `sentinel/api/routes/scan.py` — `/scan`, `/process` (with request models)
- `sentinel/api/routes/task.py` — `/task`, `/approval/{id}`, `/approve/{id}` (with request models)
- `sentinel/api/routes/session.py` — `/session/{id}`

**How to verify:** `pytest tests/ -x` — all 562+ tests pass with updated imports.

**Estimated complexity:** HIGH (touches every file, highest regression risk)

**Rollback strategy:** git branch before starting. If tests break, `git checkout .` and try again incrementally.

---

#### Task 0.2 — Create pyproject.toml

**Files affected:** Create `pyproject.toml`, delete `controller/requirements.txt`

**Content:**

```toml
[build-system]
requires = ["setuptools>=69.0"]
build-backend = "setuptools.backends._legacy:_Backend"

[project]
name = "sentinel"
version = "0.1.0"
requires-python = ">=3.12"
dependencies = [
    "fastapi>=0.115.0,<1.0.0",
    "uvicorn>=0.34.0,<1.0.0",
    "httpx>=0.28.0,<1.0.0",
    "pyyaml>=6.0,<7.0",
    "pydantic>=2.10.0,<3.0.0",
    "pydantic-settings>=2.7.0,<3.0.0",
    "python-json-logger>=3.0.0,<4.0.0",
    "transformers>=4.47.0,<5.0.0",
    "anthropic>=0.42.0,<1.0.0",
    "llamafirewall>=0.1.0,<2.0.0",
    "slowapi>=0.1.9,<1.0.0",
    "aiosqlite>=0.20.0,<1.0.0",
    "sqlite-vec>=0.1.0",
]

[project.optional-dependencies]
test = [
    "pytest>=8.3.0,<9.0.0",
    "pytest-asyncio>=0.25.0,<1.0.0",
]
signal = [
    # signal-cli runtime dependency — JRE installed in container
]

[tool.pytest.ini_options]
asyncio_mode = "auto"
testpaths = ["tests"]
```

**Security implications:** None.

**Estimated complexity:** LOW

---

#### Task 0.3 — SQLite + sqlite-vec Database Layer

**Files affected:** Create `sentinel/core/db.py`

**What changes and why:**
All in-memory state will be backed by SQLite. This task creates the schema and initialization logic. The actual migration of each store happens in Phase 1.

**Schema:**

```sql
-- Sessions
CREATE TABLE sessions (
    session_id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL DEFAULT 'default',
    source TEXT NOT NULL DEFAULT '',
    cumulative_risk REAL NOT NULL DEFAULT 0.0,
    violation_count INTEGER NOT NULL DEFAULT 0,
    is_locked INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    last_active TEXT NOT NULL
);

CREATE TABLE conversation_turns (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL REFERENCES sessions(session_id),
    request_text TEXT NOT NULL,
    result_status TEXT NOT NULL DEFAULT '',
    blocked_by TEXT NOT NULL DEFAULT '[]',  -- JSON array
    risk_score REAL NOT NULL DEFAULT 0.0,
    plan_summary TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL
);
CREATE INDEX idx_turns_session ON conversation_turns(session_id);

-- Provenance
CREATE TABLE provenance (
    id TEXT PRIMARY KEY,
    content TEXT NOT NULL,
    trust_level TEXT NOT NULL,
    source TEXT NOT NULL,
    originated_from TEXT NOT NULL DEFAULT '',
    derived_from TEXT NOT NULL DEFAULT '[]',  -- JSON array
    scan_results TEXT NOT NULL DEFAULT '{}',  -- JSON object
    created_at TEXT NOT NULL
);

CREATE TABLE file_provenance (
    path TEXT PRIMARY KEY,
    data_id TEXT NOT NULL REFERENCES provenance(id),
    created_at TEXT NOT NULL
);

-- Approvals
CREATE TABLE approvals (
    approval_id TEXT PRIMARY KEY,
    plan_json TEXT NOT NULL,
    source_key TEXT NOT NULL DEFAULT '',
    user_request TEXT NOT NULL DEFAULT '',
    result_granted INTEGER,  -- NULL = pending, 0 = denied, 1 = granted
    result_reason TEXT NOT NULL DEFAULT '',
    result_approved_by TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    decided_at TEXT
);

-- Memory chunks (Phase 2)
CREATE TABLE memory_chunks (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL DEFAULT 'default',
    content TEXT NOT NULL,
    metadata TEXT NOT NULL DEFAULT '{}',  -- JSON
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE VIRTUAL TABLE memory_fts USING fts5(content, content=memory_chunks, content_rowid=rowid);
-- sqlite-vec virtual table created at runtime after extension load

-- Routines (Phase 5)
CREATE TABLE routines (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL DEFAULT 'default',
    name TEXT NOT NULL,
    trigger_type TEXT NOT NULL,  -- 'cron', 'event', 'manual'
    trigger_config TEXT NOT NULL DEFAULT '{}',  -- JSON
    prompt TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    cooldown_seconds INTEGER NOT NULL DEFAULT 0,
    max_concurrent INTEGER NOT NULL DEFAULT 1,
    last_run TEXT,
    consecutive_failures INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

-- Audit log
CREATE TABLE audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event TEXT NOT NULL,
    level TEXT NOT NULL,
    message TEXT NOT NULL,
    data TEXT NOT NULL DEFAULT '{}',  -- JSON
    created_at TEXT NOT NULL
);
CREATE INDEX idx_audit_event ON audit_log(event);
CREATE INDEX idx_audit_created ON audit_log(created_at);
```

**Security implications:**
- SQLite file must be on a named volume, not in the read-only filesystem
- WAL mode recommended for concurrent reads during async operations
- `user_id` column on all tables prepares for multi-user without schema changes

**How to verify:** `python -c "from sentinel.core.db import init_db; init_db(':memory:')"` creates all tables without error.

**Estimated complexity:** MEDIUM

---

#### Task 0.4 — Internal Event Bus

**Files affected:** Create `sentinel/core/bus.py`

**What changes and why:**
The MQTT broker references in config.py were never implemented. An internal asyncio pub/sub replaces them with zero infrastructure dependency. Topics: `task.*`, `approval.*`, `session.*`, `channel.*`, `routine.*`, `memory.*`

**Implementation:**

```python
# Core pattern: asyncio event bus with typed topics
class EventBus:
    def __init__(self):
        self._subscribers: dict[str, list[asyncio.Queue]] = defaultdict(list)

    async def publish(self, topic: str, data: dict) -> None:
        for queue in self._subscribers.get(topic, []):
            await queue.put(data)
        # Wildcard matching: task.completed matches task.*
        for pattern, queues in self._subscribers.items():
            if pattern.endswith(".*") and topic.startswith(pattern[:-1]):
                for queue in queues:
                    await queue.put(data)

    def subscribe(self, topic: str) -> asyncio.Queue:
        queue = asyncio.Queue()
        self._subscribers[topic].append(queue)
        return queue

    def unsubscribe(self, topic: str, queue: asyncio.Queue) -> None:
        if topic in self._subscribers:
            self._subscribers[topic].remove(queue)
```

**Security implications:** Internal only — never exposed over the network. Messages are in-process, no serialization boundary.

**How to verify:** Unit tests for publish/subscribe/wildcard matching.

**Estimated complexity:** LOW

---

#### Task 0.5 — Rust WASM Sidecar Skeleton

**Files affected:** Create `sidecar/` directory tree

```
sidecar/
├── Cargo.toml
└── src/
    ├── main.rs          # Unix socket listener
    ├── protocol.rs      # JSON request/response types
    ├── sandbox.rs       # Wasmtime engine stub
    ├── registry.rs      # Tool metadata
    ├── capabilities.rs  # Deny-by-default model
    └── config.rs        # Resource limits
```

**What changes and why:**
Phase 4 requires a compiled Rust binary. The skeleton can be started now — it compiles, listens on a Unix socket, and returns stub responses. Full WASM execution logic is Phase 4.

**Security implications:**
- Unix socket at `/tmp/sentinel-sidecar.sock` — only accessible from within the container
- The sidecar has no network access — it only communicates with the Python process

**How to verify:** `cargo check` in `sidecar/` compiles clean. `cargo test` passes.

**Estimated complexity:** HIGH (Rust learning curve, Wasmtime API)

---

#### Phase 0 Completion Criteria

- [ ] All files relocated to `sentinel/` package structure
- [ ] `pyproject.toml` created with all dependencies
- [ ] All 562+ existing tests pass with updated imports (`pytest tests/ -x`)
- [ ] `sentinel/core/db.py` creates all SQLite tables in memory
- [ ] `sentinel/core/bus.py` passes pub/sub unit tests
- [ ] `sidecar/` compiles with `cargo check`
- [ ] No logic changes to any security component

#### Phase 0 Security Checkpoint

- [ ] All 10 security layers still function (no import regression)
- [ ] No new files introduced outside `sentinel/`, `tests/`, `ui/`, `sidecar/`
- [ ] MQTT config fields marked as deprecated but not yet removed
- [ ] Provenance store still in-memory (migration is Phase 1)

---

### Phase 1: Infrastructure Consolidation

**Objective:** Reduce from 3 containers to 2. Merge UI into the controller, migrate in-memory stores to SQLite, add the tiered trust router.

**Prerequisites:** Phase 0 complete, stress test v3 results reviewed.

---

#### Task 1.1 — Eliminate nginx Container

**Files affected:**
- Modify: `sentinel/api/app.py` (add `StaticFiles` mount)
- Create: `sentinel/api/middleware.py:SecurityHeadersMiddleware`
- Modify: `podman-compose.yaml` (remove sentinel-ui service, update sentinel ports)
- Modify: Containerfile (add TLS cert generation, copy UI files)

**What changes and why:**
The nginx container only serves static files and adds security headers. FastAPI can do both. This removes an entire container and simplifies the architecture.

**Security headers to replicate (from `gateway/nginx.conf` lines 27-32):**

```python
class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        response = await call_next(request)
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; "
            "style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
            "connect-src 'self'; frame-ancestors 'none';"
        )
        response.headers["Strict-Transport-Security"] = (
            "max-age=31536000; includeSubDomains"
        )
        return response
```

**TLS:** Generate self-signed cert at build time (same as current gateway/Dockerfile), run uvicorn with `--ssl-keyfile` and `--ssl-certfile`.

**HTTP redirect:** Add a startup task that binds port 8080 and returns 301 redirects to HTTPS. (Or: use a simple middleware that checks scheme.)

**nginx-specific behavior to replicate:**
- `error_page 497` (plain HTTP to HTTPS port) → FastAPI equivalent: detect non-TLS request and redirect
- `proxy_read_timeout 300s` → no longer needed (FastAPI talks to itself)
- `client_max_body_size 1m` → already handled by `RequestSizeLimitMiddleware`
- `try_files $uri $uri/ /index.html` → `StaticFiles(html=True)` handles this

**Security implications:**
- **CRITICAL:** Every security header must be tested explicitly. A missing header is a regression.
- **CRITICAL:** CSP must include `connect-src 'self' wss:` when WebSocket is added in Phase 3.
- The `/api/` prefix stripping done by nginx (`location /api/ { proxy_pass .../; }`) means the UI currently uses `/api/task` but the controller expects `/task`. When eliminating nginx, either: (a) keep the `/api/` prefix and update controller routes, or (b) update `ui/app.js` to use direct paths. **Recommendation: (a) — add `/api` prefix to all routes. This is cleaner for future API versioning.**

**How to verify:**

```bash
# Check each security header explicitly
curl -kI https://localhost:3001/ | grep -i "x-frame-options"
curl -kI https://localhost:3001/ | grep -i "x-content-type-options"
curl -kI https://localhost:3001/ | grep -i "strict-transport-security"
curl -kI https://localhost:3001/ | grep -i "content-security-policy"
curl -kI https://localhost:3001/ | grep -i "referrer-policy"
# Check HTTP redirect
curl -I http://localhost:3002/ | grep "301"
# Check static files
curl -ks https://localhost:3001/ | grep "<title>"
# Check API still works
curl -ks -H "X-Sentinel-Pin: xxx" https://localhost:3001/api/health
```

**Estimated complexity:** MEDIUM

**Rollback:** Keep the old compose file and gateway directory until verified. Can re-enable the nginx container.

---

#### Task 1.2 — Migrate Session Store to SQLite

**Files affected:**
- Modify: `sentinel/session/store.py`
- Modify: `sentinel/core/db.py` (if needed)

**What changes and why:**
`SessionStore._sessions` is a `dict[str, Session]` with a `threading.Lock`. Container restarts lose all session state, including conversation history needed for multi-turn attack detection.

Migration strategy: **Same public API, SQLite backend.** The `get_or_create()`, `get()`, `add_turn()`, `lock()` methods keep their signatures. Internal implementation switches from dict operations to SQL queries.

**Key considerations:**
- Use `aiosqlite` for async access (FastAPI is async)
- TTL eviction: `DELETE FROM sessions WHERE last_active < datetime('now', '-1 hour')`
- Thread safety: aiosqlite handles this via its connection pool
- `ConversationTurn` stored in `conversation_turns` table with JSON `blocked_by` field

**Security implications:** Session data persists across restarts. Need to add periodic cleanup to prevent unbounded growth.

**How to verify:** Existing session-related tests pass without modification (same API surface).

**Estimated complexity:** MEDIUM

---

#### Task 1.3 — Migrate Provenance Store to SQLite

**Files affected:**
- Modify: `sentinel/security/provenance.py`

**What changes and why:**
`_store` is a `dict[str, TaggedData]` limited to 10,000 entries. Container restarts lose all provenance history. The trust chain walking (`get_provenance_chain`) and execution safety checks (`is_trust_safe_for_execution`) must work across restarts.

**Key considerations:**
- `TaggedData` has a `scan_results` field that's a `dict[str, ScanResult]` — serialize as JSON
- `derived_from` is a `list[str]` — serialize as JSON array
- `get_provenance_chain()` does BFS through `derived_from` — needs to be async or use sync SQLite
- The eviction strategy changes from "delete oldest by insertion order" to "delete entries older than N hours"

**Security implications:** Provenance data is security-critical — trust levels must never be accidentally upgraded. The migration must preserve the invariant: if any ancestor is UNTRUSTED, the descendant is UNTRUSTED.

**How to verify:** All provenance-related tests pass. Specifically: `test_provenance.py` (10 tests).

**Estimated complexity:** MEDIUM

---

#### Task 1.4 — Migrate Approval Manager to SQLite

**Files affected:**
- Modify: `sentinel/api/approval.py`

**What changes and why:**
`ApprovalManager._pending` is a `dict[str, PendingApproval]` with TTL cleanup. Losing pending approvals on restart is a usability issue.

**Key considerations:**
- `PendingApproval.plan` is a `Plan` Pydantic model — serialize as JSON
- TTL cleanup: `DELETE FROM approvals WHERE created_at < datetime('now', '-5 minutes') AND result_granted IS NULL`
- The `Plan` object includes step details that could be large — use `TEXT` column

**Security implications:** None beyond what already exists. Approvals already expire via TTL.

**How to verify:** All approval-related tests pass. Specifically: `test_approval.py` (7 tests).

**Estimated complexity:** LOW

---

#### Task 1.5 — Tiered Trust Router

**Files affected:** Create `sentinel/planner/trust_router.py`

**What changes and why:**
Currently every request goes through the full CaMeL pipeline (Claude plans → human approves → Qwen executes). For safe operations like memory search or status queries, this is overkill. The trust router classifies operations and fast-paths safe ones.

**Implementation:**

```python
SAFE_OPS = frozenset({
    "memory_search", "memory_list", "routine_list",
    "routine_status", "health_check", "session_info",
})

class TrustRouter:
    def classify(self, operation: str) -> str:
        """Returns 'safe' or 'dangerous'."""
        if operation in SAFE_OPS:
            return "safe"
        return "dangerous"  # Default: dangerous
```

**Critical design decision:** The LLM does NOT classify its own operations. This is a static allowlist maintained by developers. The allowlist is conservative — everything is dangerous by default.

**Security implications:**
- Safe ops still go through PIN auth and basic input scanning
- Safe ops bypass CaMeL planning/approval — no Claude API call, no human approval
- If the allowlist is too permissive, attackers can bypass security checks
- **Recommendation:** Start with the smallest possible allowlist. Add operations only after security review.

**How to verify:** Unit tests: `classify("memory_search") == "safe"`, `classify("file_write") == "dangerous"`, `classify("unknown") == "dangerous"`.

**Estimated complexity:** LOW

---

#### Task 1.6 — Two-Container Compose File

**Files affected:** Modify `podman-compose.yaml`

**Target configuration:**

```yaml
services:
  sentinel:
    build:
      context: .
      dockerfile: container/Containerfile
    container_name: sentinel
    networks:
      - sentinel_internal
      - sentinel_egress
    ports:
      - "3001:8443"
      - "3002:8080"
    environment:
      - SENTINEL_POLICY_FILE=/policies/sentinel-policy.yaml
      - SENTINEL_WORKSPACE_PATH=/data/workspace
      - SENTINEL_LOG_DIR=/logs
      - SENTINEL_LOG_LEVEL=INFO
      - SENTINEL_DB_PATH=/data/sentinel.db
      - SENTINEL_STATIC_DIR=/app/ui
      - SENTINEL_OLLAMA_URL=http://sentinel-ollama:11434
      - SENTINEL_OLLAMA_MODEL=qwen3:14b
      - SENTINEL_EMBEDDINGS_MODEL=nomic-embed-text
    volumes:
      - sentinel-data:/data
      - ./policies:/policies:ro
      - ./logs:/logs
    secrets:
      - claude_api_key
      - sentinel_pin
    read_only: true
    tmpfs:
      - /tmp:size=100M,noexec
    mem_limit: 4G
    cpus: 4.0
    restart: always
    depends_on:
      - sentinel-ollama
    healthcheck:
      test: ["CMD-SHELL", "python -c 'import urllib.request; urllib.request.urlopen(\"https://localhost:8443/api/health\", context=__import__(\"ssl\").create_default_context())'"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 60s

  sentinel-ollama:
    image: docker.io/ollama/ollama@sha256:44893537fcc6f100b70ceb7f5c9fd8f787ba58f9f8ce73bf4a48a5b05fd8c422
    container_name: sentinel-ollama
    networks:
      - sentinel_internal
    environment:
      - OLLAMA_HOST=0.0.0.0:11434
      - OLLAMA_KEEP_ALIVE=5m
    volumes:
      - sentinel-ollama-data:/root/.ollama
    devices:
      - nvidia.com/gpu=all
    mem_limit: 14G
    cpus: 4.0
    restart: always
    healthcheck:
      test: ["CMD-SHELL", "bash -c 'echo -e \"GET /api/tags HTTP/1.0\\r\\nHost: localhost\\r\\n\\r\\n\" > /dev/tcp/localhost/11434'"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 30s

networks:
  sentinel_internal:
    driver: bridge
    internal: true
    ipam:
      config:
        - subnet: 172.30.0.0/24
  sentinel_egress:
    driver: bridge

secrets:
  claude_api_key:
    file: ${SENTINEL_SECRETS_DIR:-/home/kifterz/.secrets}/claude_api_key.txt
  sentinel_pin:
    file: ${SENTINEL_SECRETS_DIR:-/home/kifterz/.secrets}/sentinel_pin.txt

volumes:
  sentinel-data:
  sentinel-ollama-data:
```

**Notable changes:**
- `sentinel-qwen` renamed to `sentinel-ollama` (model-agnostic naming)
- `sentinel-ui` service removed entirely
- New `sentinel-data` volume for SQLite + workspace
- Secrets path uses environment variable (portable for open-source)
- Health check updated for HTTPS + new path prefix

**Security implications:** Air-gapped topology preserved. `sentinel_internal` network still has `internal: true`.

**How to verify:** `podman compose up` starts 2 containers. UI loads at `https://localhost:3001/`. API works at `https://localhost:3001/api/health`.

**Estimated complexity:** MEDIUM

---

#### Task 1.7 — Config Updates

**Files affected:** Modify `sentinel/core/config.py`

**New fields to add:**

```python
# Database
db_path: str = "/data/sentinel.db"

# Static files
static_dir: str = "/app/ui"

# TLS
tls_cert_file: str = "/data/tls/sentinel.crt"
tls_key_file: str = "/data/tls/sentinel.key"

# Sidecar
sidecar_socket: str = "/tmp/sentinel-sidecar.sock"

# Embeddings
embeddings_model: str = "nomic-embed-text"

# User ID (single-user for now, column exists for future multi-user)
user_id: str = "default"
```

**Fields to remove:**

```python
# MQTT (never implemented)
mqtt_broker, mqtt_port, mqtt_topic_in, mqtt_topic_out, mqtt_topic_approval
```

**Estimated complexity:** LOW

---

#### Phase 1 Completion Criteria

- [ ] `podman compose up` starts exactly 2 containers
- [ ] UI loads at `https://localhost:3001/`
- [ ] API responds at `https://localhost:3001/api/health`
- [ ] All 6 security headers present on every response
- [ ] HTTP redirect from port 3002 works
- [ ] Sessions persist across container restarts
- [ ] Provenance persists across container restarts
- [ ] Approvals persist across container restarts
- [ ] Trust router classifies all current operations as "dangerous" (no safe ops implemented yet)
- [ ] All 562+ tests pass
- [ ] MQTT config fields removed

#### Phase 1 Security Checkpoint

- [ ] All 10 security layers still function
- [ ] Security headers verified explicitly (test each one)
- [ ] CSP policy matches nginx configuration exactly
- [ ] Air-gapped network topology preserved
- [ ] No new network ports exposed
- [ ] SQLite file permissions: 600 (owner read/write only)

---

### Phase 2: Persistent Memory

**Objective:** Add hybrid search memory system — store context, search with RRF, embed with nomic-embed-text.

**Prerequisites:** Phase 1 complete (SQLite available, Ollama config supports multiple models).

---

#### Task 2.1 — Embedding Pipeline

**Files affected:** Create `sentinel/memory/embeddings.py`

**What it does:** Calls Ollama's `/api/embeddings` endpoint with `nomic-embed-text` model (768 dimensions). Runs on CPU to avoid VRAM contention with the worker LLM.

**Key considerations:**
- `nomic-embed-text` must be pulled into the Ollama container: `ollama pull nomic-embed-text`
- Ollama manages model load/unload automatically — CPU embedding model won't evict GPU worker model
- Embedding dimension: 768 (must match sqlite-vec column definition)
- Batch embedding for efficiency (up to 32 texts per request)

**Security implications:** Embedding requests go over `sentinel_internal` network — same as worker LLM calls. No new attack surface.

**How to verify:** Embed a test string, verify 768-dimensional vector returned.

**Estimated complexity:** MEDIUM

---

#### Task 2.2 — Chunk Management

**Files affected:** Create `sentinel/memory/chunks.py`

**What it does:** Split large texts into chunks (512 token target, 50 token overlap), store in SQLite, sync FTS5 index and vector embeddings on write.

**Key considerations:**
- Split on paragraph/sentence boundaries (not mid-word)
- FTS5 index must be kept in sync with the chunks table via triggers or explicit updates
- sqlite-vec virtual table for vector storage
- Deduplication: hash content before storing, skip if already exists

**Security implications:** Memory content is treated as **untrusted** when retrieved. Search results must go through spotlighting and scanning before being included in prompts.

**Estimated complexity:** MEDIUM

---

#### Task 2.3 — RRF Hybrid Search

**Files affected:** Create `sentinel/memory/search.py`

**Implementation:**

```python
def rrf_search(query: str, k: int = 60, top_n: int = 10) -> list[MemoryChunk]:
    # 1. FTS5 keyword search
    fts_results = fts5_search(query)  # ranked by BM25

    # 2. Vector semantic search
    query_embedding = embed(query)
    vec_results = vector_search(query_embedding)  # ranked by cosine similarity

    # 3. RRF fusion
    scores = defaultdict(float)
    for rank, chunk in enumerate(fts_results):
        scores[chunk.id] += 1.0 / (k + rank)
    for rank, chunk in enumerate(vec_results):
        scores[chunk.id] += 1.0 / (k + rank)

    # 4. Sort by fused score, return top N
    return sorted(scores.items(), key=lambda x: x[1], reverse=True)[:top_n]
```

**Security implications:** Search results are memory content that could have been stored from previous (potentially adversarial) conversations. They must be treated as untrusted data — wrapped in `<UNTRUSTED_DATA>` tags with spotlighting markers before being included in any prompt.

**Estimated complexity:** MEDIUM

---

#### Task 2.4 — Memory API

**Files affected:** Create `sentinel/api/routes/memory.py`, create `sentinel/memory/store.py`

**Endpoints:**
- `POST /api/memory` — store a memory chunk
- `GET /api/memory/search?q=...` — hybrid search
- `GET /api/memory/{id}` — retrieve by ID
- `DELETE /api/memory/{id}` — delete
- `GET /api/memory` — list recent

**Auto-memory:** After successful task completion, optionally store conversation summary as a memory chunk.

**Security implications:** Memory write endpoint must go through input scanning to prevent storing adversarial content.

**Estimated complexity:** LOW

---

#### Phase 2 Completion Criteria

- [ ] Store/search/delete roundtrip works
- [ ] FTS5 returns keyword matches
- [ ] sqlite-vec returns semantic matches
- [ ] RRF fusion produces better results than either alone
- [ ] `nomic-embed-text` runs on CPU without impacting worker LLM GPU inference
- [ ] Memory search results are treated as untrusted in prompts

#### Phase 2 Security Checkpoint

- [ ] Memory search results wrapped in `<UNTRUSTED_DATA>` tags with spotlighting
- [ ] Memory write endpoint requires PIN authentication
- [ ] No raw memory content included in prompts without scanning
- [ ] Memory injection test: store adversarial content, verify it doesn't execute when retrieved

---

### Phase 3: Multi-Channel Access

**Objective:** WebSocket/SSE web upgrade, Signal messaging, MCP server.

**Prerequisites:** Phase 1 (event bus), Phase 2 (memory for contextual conversations).

---

#### Task 3.1 — Channel Abstraction

**Files affected:** Create `sentinel/channels/base.py`

**ABC definition:**

```python
class Channel(ABC):
    @abstractmethod
    async def start(self) -> None: ...
    @abstractmethod
    async def stop(self) -> None: ...
    @abstractmethod
    def receive(self) -> AsyncIterator[IncomingMessage]: ...
    @abstractmethod
    async def send(self, message_id: str, response: str) -> None: ...

class ChannelRouter:
    """Merges all channels into a single asyncio.Queue."""
    def __init__(self):
        self._channels: list[Channel] = []
        self._queue: asyncio.Queue = asyncio.Queue()

    async def route(self, message: IncomingMessage) -> None:
        # PIN auth → input scan → trust router → execute → respond
        ...
```

**Estimated complexity:** MEDIUM

---

#### Task 3.2 — Web Channel Upgrade

**Files affected:** Create `sentinel/channels/web.py`, modify `ui/app.js`

**Adds:**
- WebSocket at `/ws` (bidirectional, real-time streaming)
- SSE at `/events` (server → client streaming, fallback)
- HTTP polling remains as final fallback

**UI changes (~100 lines):** Prefer WebSocket, fall back to SSE, fall back to HTTP polling. Display streaming responses as they arrive.

**Security implications:**
- WebSocket connections must require PIN authentication (via query param or first message)
- CSP must be updated: `connect-src 'self' wss:` to allow WebSocket connections
- WebSocket max connections per IP (prevent resource exhaustion)

**Estimated complexity:** MEDIUM

---

#### Task 3.3 — Signal Channel

**Files affected:** Create `sentinel/channels/signal_channel.py`

**What it does:** signal-cli as managed subprocess in JSON-RPC mode, crash recovery with exponential backoff.

**Key considerations:**
- signal-cli adds ~200MB to the container image (JRE + JAR)
- Registration is one-time setup, not runtime code
- Need a dedicated Signal number
- Make it an optional Containerfile layer

**Security implications:**
- Signal messages are untrusted user input — must go through full pipeline
- Phone number registration should be done out-of-band, not via API
- Message content could contain injection attempts — same treatment as HTTP input

**Estimated complexity:** HIGH (signal-cli setup, JRE dependency, crash recovery)

---

#### Task 3.4 — MCP Server

**Files affected:** Create `sentinel/channels/mcp_channel.py`

**What it does:** Expose Sentinel tools to MCP clients (Claude Desktop, etc.) via the Python `mcp` library.

**Security implications:**
- All MCP requests route through trust router + security pipeline
- MCP tool annotations: mark dangerous tools with `destructive_hint: true`
- Tool descriptions should not reveal internal architecture

**Estimated complexity:** MEDIUM

---

#### Phase 3 Completion Criteria

- [ ] WebSocket streams responses in real-time
- [ ] SSE fallback works when WebSocket unavailable
- [ ] Signal: send message → get response
- [ ] MCP: Claude Desktop connects and can use Sentinel tools
- [ ] All channels go through trust router + security pipeline
- [ ] All channels require authentication

#### Phase 3 Security Checkpoint

- [ ] WebSocket PIN auth verified
- [ ] Signal message content treated as untrusted
- [ ] MCP requests go through full pipeline
- [ ] CSP updated for WebSocket connections
- [ ] No channel bypasses security pipeline

---

### Phase 4: WASM Tool Sandbox (Parallel with Phases 1-3)

**Objective:** Rust sidecar with Wasmtime for sandboxed tool execution.

**Prerequisites:** Phase 0 (sidecar skeleton). Fully independent of Python phases.

**Note:** This is the most technically challenging phase. It requires Rust proficiency, understanding of the WASI component model, and careful capability design. Consider whether Phase 4 should be deferred to v2 (see Section 4.9 for recommendation).

---

#### Task 4.1 — Wasmtime Integration

**Files affected:** `sidecar/src/sandbox.rs`

**What it does:**
- Fresh Wasmtime instance per execution (no state persistence)
- Fuel metering: 10M instructions default
- Memory cap: 10MB default
- Epoch-based timeout: 500ms tick from background thread
- Deny-by-default: zero host functions linked unless capabilities grant them

**Estimated complexity:** HIGH

---

#### Task 4.2 — Capability Model

**Files affected:** `sidecar/src/capabilities.rs`

**Capabilities:** `ReadFile{paths}`, `WriteFile{paths}`, `HttpRequest{allowlist}`, `UseCredential{name}`, `InvokeTool{alias}`

**Estimated complexity:** HIGH

---

#### Task 4.3 — Credential Injection + Leak Detection

**Credential injection:** Python tells sidecar which credentials a tool needs. Sidecar provides them via host function at the WASM boundary. Tool never sees raw values.

**Leak detection:** Aho-Corasick automaton scanning all tool output. 20+ patterns: AWS keys (AKIA), GitHub PATs (ghp_), Slack tokens (xox), OpenAI keys (sk-), PEM keys, Bearer tokens, high-entropy hex.

**Estimated complexity:** HIGH

---

#### Task 4.4 — SSRF Protection

**Files affected:** `sidecar/src/` (HTTP host function implementation)

**What it does:** After URL allowlist validation, resolve DNS and reject private IP ranges (127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16). Prevents DNS rebinding.

**Estimated complexity:** MEDIUM

---

#### Task 4.5 — Python Sidecar Client

**Files affected:** Create `sentinel/tools/sidecar.py`

**What it does:** `SidecarClient` communicates over Unix socket. Handles timeout, crash recovery, sidecar process restart.

**Estimated complexity:** LOW

---

#### Task 4.6 — V1 Tool Set

5 tools: `file_read`, `file_write`, `shell_exec`, `http_fetch`, `memory_search`

**Estimated complexity:** HIGH (each tool needs WASM compilation + capability declaration)

---

#### Phase 4 Completion Criteria

- [ ] Sidecar starts and listens on Unix socket
- [ ] `file_read` can read `/data/workspace/test.txt` but NOT `/etc/shadow`
- [ ] `shell_exec` can run `ls` but NOT `curl`
- [ ] `http_fetch` can reach allowed URLs but NOT private IPs
- [ ] Credential injection works, credential wiped after execution
- [ ] Leak detector catches `AKIA...`, `ghp_...` in output
- [ ] Fuel limit stops infinite loops
- [ ] Memory limit prevents OOM
- [ ] `cargo test` passes

---

### Phase 5: Routines + Multi-Provider LLM

**Objective:** Background automation and model flexibility.

**Prerequisites:** Phases 1-4.

---

#### Task 5.1 — Routine Engine

**Files affected:** Create `sentinel/routines/engine.py`

**Trigger types:** Cron expressions, event patterns (regex on messages), manual.

**Guardrails:** Cooldown period, max concurrent runs, global capacity limit, consecutive failure tracking.

**Security implications:** Routines go through the same trust router + security pipeline as user requests. Routine creation requires human approval.

**Estimated complexity:** MEDIUM

---

#### Task 5.2 — Multi-Provider LLM Abstraction

**Files affected:** Create `sentinel/worker/provider.py`

**ABC:**

```python
class LLMProvider(ABC):
    @abstractmethod
    async def generate(self, prompt: str, system: str) -> str: ...

class OllamaProvider(LLMProvider):
    # Wraps existing OllamaWorker

class ClaudeProvider(LLMProvider):
    # For using Claude as a worker (alternative to planner role)
```

**What it enables:** Swap worker model freely (Qwen → Mistral → Llama) via environment variable.

**Estimated complexity:** MEDIUM

---

### Phase 6: Hardening + Open Source Release

**Objective:** Security audit, documentation, sanitisation, GitHub push.

**Prerequisites:** All previous phases.

---

#### Task 6.1 — Test Suite Expansion

Target: 800+ tests covering memory, channels, WASM, routines, trust router, end-to-end flows.

**New test categories:**
- Memory injection tests (adversarial content in search results)
- Routine manipulation tests (scheduling as attack vector)
- WASM escape tests (capability boundary violations)
- MCP injection tests (external tool server as untrusted)
- Signal injection tests (message content as untrusted)
- Channel authentication tests (every channel requires PIN)
- Trust router classification tests (exhaustive allowlist verification)

---

#### Task 6.2 — Security Audit

New attack surfaces to audit:
- Memory search results treated as untrusted (spotlighting + scanning)
- Routine creation requires approval
- All MCP requests through trust router
- WASM capability boundaries
- Signal message sanitisation
- WebSocket authentication

---

#### Task 6.3 — Sanitisation Checklist

**Personal data to remove before open-source release:**

| Pattern | Current Location | Replace With |
|---------|-----------------|-------------|
| `/home/kifterz` | `podman-compose.yaml` line 115-117 | `${SENTINEL_SECRETS_DIR}` |
| `thebeast` | `planner.py:17`, `config.py:69` | Generic hostname or remove |
| `192.168.0.40` | `config.py:69` | Remove or use `${SENTINEL_ALLOWED_ORIGINS}` |
| `100.103.25.16` | `config.py:69` (Tailscale IP) | Remove |
| `localhost:3001/3002` | `config.py:69` | Keep (generic) |
| AMD/RTX hardware details | `planner.py:18` | Generic or remove |
| Port 1883 | `sentinel-policy.yaml:88` | Remove MQTT reference |
| `mosquitto:1883` | `sentinel-policy.yaml:88` | Remove |

---

#### Task 6.4 — Documentation

- `README.md` — project overview, quick start, architecture diagram
- `SECURITY.md` — threat model, security layers, responsible disclosure
- `CONTRIBUTING.md` — development setup, test running, code style
- `ARCHITECTURE.md` — detailed system design
- `WASM_TOOLS.md` — how to build and register WASM tools
- `LICENSE` — Apache-2.0 or MIT (see Section 4.9)
- `NOTICE` — IronClaw (Apache-2.0) credit

---

#### Task 6.5 — CI Pipeline

```yaml
# .github/workflows/ci.yml
name: CI
on: [push, pull_request]
jobs:
  python-tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: pip install -e ".[test]"
      - run: pytest tests/ -x --tb=short

  rust-tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions-rust-lang/setup-rust-toolchain@v1
      - run: cd sidecar && cargo test
      - run: cd sidecar && cargo clippy -- -D warnings

  smoke-test:
    runs-on: ubuntu-latest
    needs: [python-tests, rust-tests]
    steps:
      - uses: actions/checkout@v4
      - run: podman compose up -d
      - run: sleep 30
      - run: curl -ks https://localhost:3001/api/health | jq .
```

---

#### Phase 6 Completion Criteria

- [ ] 800+ tests passing
- [ ] Security audit complete with no critical findings
- [ ] No personal paths, IPs, hostnames, or secrets in codebase
- [ ] Documentation complete
- [ ] CI pipeline green
- [ ] `podman compose up` from a clean clone works end-to-end
- [ ] IronClaw credited in README + NOTICE file
- [ ] License file present

---

## 4.6 — Parallel Work Streams

```
Week 1-2:  ┌─ Phase 0: Foundation ────────────────────────────┐
           │  Package restructure, pyproject.toml, DB schema  │
           │  Event bus, sidecar skeleton                      │
           └──────────────────────────────────────────────────┘
                 │                              │
                 ▼                              ▼
Week 3-4:  ┌─ Phase 1 ──────────────┐   ┌─ Phase 4 (Rust) ────────┐
           │ nginx elimination       │   │ Wasmtime integration    │
           │ SQLite migrations       │   │ Capability model         │
           │ Trust router            │   │ Credential injection     │
           │ 2-container compose     │   │ SSRF protection          │
           └─────────┬───────────────┘   │ Python client            │
                     │                   │ V1 tool set              │
                     ▼                   │                          │
Week 5-6:  ┌─ Phase 2 ──────────────┐   │                          │
           │ Embedding pipeline      │   │ (continues...)           │
           │ Chunk management        │   │                          │
           │ RRF hybrid search       │   │                          │
           │ Memory API              │   │                          │
           └─────────┬───────────────┘   └───────────┬─────────────┘
                     │                               │
                     ▼                               │
Week 7-8:  ┌─ Phase 3 ──────────────┐               │
           │ Channel abstraction     │               │
           │ WebSocket + SSE         │               │
           │ Signal channel          │               │
           │ MCP server              │               │
           └─────────┬───────────────┘               │
                     │                               │
                     ├───────────────────────────────┘
                     ▼
Week 9-10: ┌─ Phase 5 ──────────────────────────────────────────┐
           │ Routine engine, Multi-provider LLM                  │
           └─────────┬───────────────────────────────────────────┘
                     │
                     ▼
Week 11+:  ┌─ Phase 6 ──────────────────────────────────────────┐
           │ Hardening, security audit, docs, sanitisation, CI   │
           │ Open source release                                  │
           └──────────────────────────────────────────────────────┘
```

**Key parallel track:** Phase 4 (Rust WASM sidecar) is fully independent and can be developed simultaneously with Phases 1-3. This is the critical path for the most technically novel feature.

---

## 4.7 — Risk Register

| # | Risk | Likelihood | Impact | Mitigation | Owner Phase |
|---|------|-----------|--------|------------|-------------|
| R1 | Package restructure breaks imports in 562+ tests | HIGH | HIGH | Incremental migration (one module at a time), test after each move. Git branch for rollback. | Phase 0 |
| R2 | sqlite-vec compatibility issues | MEDIUM | HIGH | Fallback: faiss-cpu with SQLite for metadata only. Test sqlite-vec installation in container early. | Phase 2 |
| R3 | Security header regression during nginx elimination | MEDIUM | HIGH | Explicit header test for each of the 6 headers. Automated test in CI. | Phase 1 |
| R4 | VRAM contention between nomic-embed-text and Qwen | LOW | MEDIUM | nomic-embed-text runs on CPU (confirmed by Ollama docs). Test concurrent embedding + generation. | Phase 2 |
| R5 | signal-cli container size (+200MB) | LOW | LOW | Optional Containerfile layer. Users who don't need Signal can skip it. | Phase 3 |
| R6 | WASI preview2 maturity | MEDIUM | MEDIUM | Keep V1 tool set deliberately simple. Avoid complex WASI features. | Phase 4 |
| R7 | Rust learning curve | HIGH | MEDIUM | Phase 4 is independent and can be deferred to v2. Python bubblewrap/nsjail as interim alternative. | Phase 4 |
| R8 | Memory injection attacks | MEDIUM | HIGH | Search results always treated as untrusted. Spotlighting + scanning applied to all memory content before inclusion in prompts. | Phase 2 |
| R9 | Routine manipulation | MEDIUM | MEDIUM | Routine creation requires human approval. Routines go through full security pipeline. | Phase 5 |
| R10 | MCP injection from external tool servers | MEDIUM | HIGH | All MCP tool responses treated as untrusted. Full scanning before acting on results. | Phase 3 |
| R11 | Personal data leaks in open-source release | HIGH | MEDIUM | Automated grep for personal patterns in CI. Manual review checklist. | Phase 6 |
| R12 | `/api` prefix change breaks UI | HIGH | LOW | Update `ui/app.js` to use `/api/` prefix. Test all UI interactions. | Phase 1 |
| R13 | SQLite WAL mode + read-only filesystem | MEDIUM | MEDIUM | SQLite DB on named volume (`/data`), not on read-only root filesystem. WAL journal also on `/data`. | Phase 1 |
| R14 | Test conftest.py policy path resolution | HIGH | LOW | Update `tests/conftest.py` path resolution for new package layout. | Phase 0 |
| R15 | Ollama model pull for nomic-embed-text | LOW | LOW | Add to container startup script or document in README. | Phase 2 |

---

## 4.8 — Security Considerations

### New Attack Surfaces by Phase

#### Phase 1: Infrastructure Consolidation

- **FastAPI serves static files:** Misconfigured `StaticFiles` could serve source code. Mitigation: `StaticFiles(directory="ui")` only serves the `ui/` directory.
- **TLS termination moves from nginx to uvicorn:** Must verify cipher suites, protocol versions match current nginx config.
- **SQLite on persistent volume:** DB file accessible if volume is compromised. Mitigation: File permissions 600, consider encryption at rest.

#### Phase 2: Persistent Memory

- **Memory injection:** Adversary stores malicious content in memory, which is later retrieved and included in a prompt to Qwen. Mitigation: All memory search results are treated as UNTRUSTED data. They are wrapped in `<UNTRUSTED_DATA>` tags with spotlighting markers before inclusion in any prompt. The same 10-layer pipeline scans them.
- **Semantic search poisoning:** Adversary stores content with embeddings that are semantically similar to legitimate queries, causing poisoned results to surface. Mitigation: Relevance threshold on search results. User can review and delete suspicious memories.
- **Cross-session information leakage:** Memory is shared across sessions. Information from one conversation is retrievable in another. Mitigation: Acceptable for single-user system. For multi-user, `user_id` column isolates memories.

#### Phase 3: Multi-Channel Access

- **WebSocket authentication bypass:** If WebSocket doesn't require PIN auth, attacker can bypass security. Mitigation: PIN auth required on WebSocket handshake.
- **Signal message injection:** Signal messages are arbitrary text from any sender. Mitigation: Same input scanning pipeline as HTTP requests.
- **MCP tool server injection:** External MCP server could return malicious tool responses. Mitigation: All MCP responses treated as untrusted. Full scanning pipeline applied.
- **SSE connection exhaustion:** Attacker opens many SSE connections. Mitigation: Atomic connection counter with max limit (e.g., 100).

#### Phase 4: WASM Sidecar

- **WASM escape:** Vulnerability in Wasmtime allows tool to escape sandbox. Mitigation: Keep Wasmtime updated. Fuel metering, memory limits, epoch-based timeout as defense-in-depth. Fresh instance per execution.
- **Capability escalation:** Tool requests capabilities it shouldn't have. Mitigation: Capabilities declared in registry, verified by sidecar before linking host functions. Static allowlist, not LLM-classified.
- **Credential leakage:** Tool output contains injected credentials. Mitigation: Aho-Corasick leak detector scans all output. 20+ patterns.
- **SSRF via tool HTTP:** Tool fetches internal URLs. Mitigation: DNS rebinding protection — resolve DNS, reject private IP ranges.

#### Phase 5: Routines

- **Routine manipulation:** Attacker modifies a routine's prompt to execute malicious actions. Mitigation: Routine creation/modification requires human approval. Routines go through full CaMeL pipeline.
- **Schedule flooding:** Creating many routines to overwhelm the system. Mitigation: Global capacity limit, per-routine cooldown, max concurrent runs.

### Tiered Trust Model — Detailed Boundary

**SAFE operations (bypass CaMeL, execute directly):**

| Operation | Why It's Safe |
|-----------|--------------|
| `memory_search` | Read-only, returns existing data |
| `memory_list` | Read-only metadata query |
| `routine_list` | Read-only metadata query |
| `routine_status` | Read-only status check |
| `health_check` | No data access |
| `session_info` | Read-only, own session only |

**DANGEROUS operations (full CaMeL pipeline):**

Everything else, including but not limited to:
- Any file read/write
- Any shell command execution
- Any network request
- Memory write/delete
- Routine create/modify/delete
- Any LLM generation task
- Any tool execution

**Critical invariant:** The LLM does NOT classify its own operations. Classification is a static allowlist maintained by developers. The default is DANGEROUS.

### How Existing Pipeline Integrates with New Features

| New Feature | Input Scanning | Output Scanning | Spotlighting | Provenance | Approval |
|-------------|---------------|----------------|-------------|-----------|----------|
| Memory search results | N/A (read-only) | N/A | Yes (when included in prompts) | Tagged as UNTRUSTED | N/A |
| Memory write | Yes (content scanned) | N/A | N/A | Tagged data stored | N/A |
| Channel input | Yes (all channels) | N/A | N/A | N/A | Via trust router |
| Routine execution | Yes (prompt scanned) | Yes (output scanned) | Yes | Full tagging | Required for creation |
| MCP tool response | N/A | Yes (response scanned) | Yes (when included in prompts) | Tagged as UNTRUSTED | Via trust router |
| WASM tool output | N/A | Yes (leak detector + pipeline) | N/A | Tagged by capability level | Capability-gated |

---

## 4.9 — Open Questions & Recommendations

### Q1: Project Name for GitHub

**Recommendation:** Keep "Sentinel" unless there's a naming conflict. It's descriptive, memorable, and already established in the codebase. Check `github.com/sentinel` and similar repos for conflicts.

**Alternatives:** "Watchtower" (taken), "Aegis" (common), "Bastion" (descriptive), "CaMeL-Guard" (too specific).

### Q2: License Choice

**Recommendation: Apache-2.0.**

Reasoning:
- IronClaw is Apache-2.0 — using the same license is cleanest for attribution
- Apache-2.0 includes a patent grant (MIT does not) — relevant for AI/security software
- Apache-2.0 requires a NOTICE file for attribution — provides clear structure for IronClaw credit
- Most Anthropic open-source projects use Apache-2.0

### Q3: GPU Sharing Strategy

**Recommendation: nomic-embed-text on CPU + Qwen on GPU (as described in the implementation plan).**

Reasoning:
- nomic-embed-text is a small model (137M parameters) — runs efficiently on CPU
- Ollama manages model loading automatically — CPU model won't evict GPU model
- This avoids VRAM contention entirely
- **Verification needed:** Test concurrent embedding + generation in the Ollama container to confirm no conflicts

### Q4: Conflicts Between Reference Documents

The implementation plan (authoritative) and the architecture analysis (supplementary) have some differences:

| Topic | Implementation Plan | Architecture Analysis | Resolution |
|-------|-------------------|---------------------|-----------|
| Tool sandbox v1 | WASM sidecar from day one (Phase 4) | Python bubblewrap/nsjail for v1, WASM for v2 | **Architecture analysis is more realistic.** Phase 4 is high-risk due to Rust learning curve. Consider nsjail/bubblewrap as v1, WASM as v2. |
| Phase numbering | Phases 0-6 | Phases 1-7 (adds Phase 7 for Rust sidecar) | Use implementation plan's numbering (0-6) since it's authoritative |
| Container naming | `sentinel` + `ollama` | Same | Agreed |
| Embedding provider | Ollama on CPU (nomic-embed-text) | OpenAI or local model | Implementation plan is correct — local embeddings via Ollama |
| Tool sandbox specifics | WASI target, WIT interfaces | Not specified | **Open question — resolve during Phase 4 implementation** |

**Key recommendation from this analysis:** The architecture document's pragmatic suggestion of Python-only sandboxing for v1 (bubblewrap/nsjail) deserves serious consideration. Phase 4 (WASM sidecar) is the highest-risk phase due to the Rust learning curve. A phased approach — Python sandbox v1, WASM v2 — reduces risk while still delivering sandboxed tool execution.

### Q5: Risks Not Covered in Reference Documents

1. **`/api` prefix migration:** The nginx reverse proxy strips `/api/` prefix. When eliminating nginx, either the controller routes need `/api/` prefix or `ui/app.js` needs updating. This is not mentioned in either document but affects Phase 1.

2. **Test conftest.py path resolution:** The test configuration uses `Path(__file__).resolve().parent.parent.parent` to find `sentinel-policy.yaml`. Package restructure changes this path. Not mentioned in either document.

3. **Prompt Guard model download:** The Dockerfile uses `--mount=type=secret,id=hf_token` to download the model at build time. The new Containerfile must preserve this pattern.

4. **Semgrep symlink for read-only FS:** The Dockerfile pre-creates the `osemgrep -> semgrep-core` symlink. Must be preserved.

5. **Health check TLS:** Current health check uses HTTP on port 8000. New architecture serves HTTPS — health check must handle self-signed certs.

6. **podman-compose 1.0.6 limitations:** No `deploy.resources` — must use `mem_limit`/`cpus`. This is a known gotcha but not documented in the reference plans.

7. **UI API path mapping:** `gateway/static/app.js` currently calls `/api/task` which nginx proxies to `http://sentinel-controller:8000/task`. When nginx is removed, the routing needs to be explicitly handled.

### Q6: Suggested Additions Based on Codebase Review

1. **Rate limiter migration:** The current `slowapi` rate limiter uses in-memory storage. After SQLite migration, consider persisting rate limit counters to prevent reset-on-restart bypass.

2. **PIN auth failure tracker migration:** `auth.py:_FailureTracker` uses an in-memory dict. Should move to SQLite to persist lockouts across restarts.

3. **Config validation:** The `config.py` Settings class should validate new fields (e.g., `db_path` must be writable, `static_dir` must exist).

4. **Graceful shutdown:** When the WASM sidecar and signal-cli are managed subprocesses, the FastAPI shutdown handler must terminate them cleanly.

5. **Database migrations:** As the schema evolves across phases, a simple migration system (version table + SQL scripts) prevents manual schema management.

---

## 4.10 — Pre-Implementation Checklist

### Before Phase 0 Begins

- [ ] **Stress test v3 results reviewed** — any new gaps that affect this plan?
- [ ] **Reference documents re-read** — implementation plan is authoritative
- [ ] **Decision: Phase 4 approach** — WASM from day one (implementation plan) or Python sandbox v1 + WASM v2 (architecture analysis recommendation)?
- [ ] **Decision: Project name** — needed for package naming in pyproject.toml
- [ ] **Decision: License** — needed for LICENSE file creation
- [ ] **Backup current state** — `git tag pre-overhaul` on current commit
- [ ] **Development environment verified:**
  - [ ] Python 3.12 available locally
  - [ ] Rust toolchain installed (`rustup`, `cargo`) — if Phase 4 is v1
  - [ ] sqlite-vec installable: `pip install sqlite-vec` works
  - [ ] aiosqlite installable: `pip install aiosqlite` works
- [ ] **GPU sharing tested:**
  - [ ] `ollama pull nomic-embed-text` succeeds in the Ollama container
  - [ ] Concurrent embedding + Qwen generation works without VRAM conflict
- [ ] **Archive directory created:** `~/sentinel/archive/` exists
- [ ] **Existing containers documented:** `podman ps` output saved for reference

### Development Workflow

- [ ] Create feature branch: `git checkout -b overhaul/phase-0`
- [ ] Work incrementally — commit after each task, test after each commit
- [ ] Use conventional commits: `feat:`, `fix:`, `refactor:`, `docs:`
- [ ] Run full test suite after every file move
- [ ] No force-pushing to shared branches

---

## Appendix A: File-by-File Impact Assessment

| Current File | Lines | Target Location | Change Type | Phase |
|-------------|-------|----------------|-------------|-------|
| `controller/app/__init__.py` | 0 | `sentinel/__init__.py` | Move | 0 |
| `controller/app/main.py` | 543 | Split → `sentinel/api/{app,middleware,routes/}` | Split + Move | 0 |
| `controller/app/config.py` | 76 | `sentinel/core/config.py` | Move + Extend | 0+1 |
| `controller/app/models.py` | 108 | `sentinel/core/models.py` | Move + Extend | 0 |
| `controller/app/orchestrator.py` | 695 | `sentinel/planner/orchestrator.py` | Move | 0 |
| `controller/app/planner.py` | 466 | `sentinel/planner/planner.py` | Move | 0 |
| `controller/app/pipeline.py` | 449 | `sentinel/security/pipeline.py` | Move | 0 |
| `controller/app/scanner.py` | 512 | `sentinel/security/scanner.py` | Move | 0 |
| `controller/app/conversation.py` | 493 | `sentinel/security/conversation.py` | Move | 0 |
| `controller/app/policy_engine.py` | 288 | `sentinel/security/policy_engine.py` | Move | 0 |
| `controller/app/provenance.py` | 115 | `sentinel/security/provenance.py` | Move → SQLite | 0+1 |
| `controller/app/spotlighting.py` | 33 | `sentinel/security/spotlighting.py` | Move | 0 |
| `controller/app/codeshield.py` | 136 | `sentinel/security/codeshield.py` | Move | 0 |
| `controller/app/prompt_guard.py` | ~100 | `sentinel/security/prompt_guard.py` | Move | 0 |
| `controller/app/worker.py` | 143 | `sentinel/worker/ollama.py` | Move + Rename | 0 |
| `controller/app/tools.py` | 462 | `sentinel/tools/executor.py` | Move + Rename | 0 |
| `controller/app/session.py` | 142 | `sentinel/session/store.py` | Move → SQLite | 0+1 |
| `controller/app/approval.py` | 192 | `sentinel/api/approval.py` | Move → SQLite | 0+1 |
| `controller/app/auth.py` | 131 | `sentinel/api/auth.py` | Move | 0 |
| `controller/app/audit.py` | ~50 | `sentinel/audit/logger.py` | Move + Rename | 0 |
| `controller/Dockerfile` | 33 | `container/Containerfile` | Rewrite | 1 |
| `gateway/Dockerfile` | 13 | **DELETE** | Eliminated | 1 |
| `gateway/nginx.conf` | 54 | **DELETE** (headers → middleware) | Eliminated | 1 |
| `gateway/static/{html,js,css}` | ~30K | `ui/` | Move | 0 |
| `podman-compose.yaml` | 122 | Same (rewritten) | Modify | 1 |
| `policies/sentinel-policy.yaml` | 136 | Same | Minor cleanup | 6 |
| `controller/requirements.txt` | 13 | `pyproject.toml` | Replace | 0 |
| `controller/tests/*.py` | ~23 files | `tests/` | Move + Import update | 0 |
| `controller/tests/conftest.py` | 47 | `tests/conftest.py` | Move + Path fix | 0 |

---

## Summary

This plan describes a major but well-structured evolution of Sentinel from a 3-container security gateway to a 2-container hardened AI assistant. The key insight is that the restructure can be done incrementally — Phase 0 changes no behaviour, Phase 1 consolidates infrastructure, and subsequent phases add features on a stable foundation.

**Critical success factors:**
1. Phase 0 must not break any existing test
2. Phase 1 must replicate all nginx security headers exactly
3. All new features must route through the existing 10-layer security pipeline
4. The tiered trust model must default to DANGEROUS for everything
5. Personal data must be sanitised before open-source release

**Biggest risk:** Phase 4 (WASM sidecar) due to Rust learning curve. **Recommendation:** Consider deferring WASM to v2 and using Python-based sandboxing (nsjail/bubblewrap) for v1.

**Estimated timeline:** 11+ weeks with parallel tracks. Phase 0 can start immediately.

---

*Plan generated 2026-02-15 21:54 UTC by infrastructure review agent. Based on read-only analysis of the Sentinel codebase at commit `7120ce7` (master branch). No files were modified during this review.*
