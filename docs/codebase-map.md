# Codebase Map

Developer reference for navigating the Sentinel codebase. Module responsibilities, key classes/functions, important constants, and cross-dependencies.

> This file is for Claude Code context loading and contributor onboarding. Update when modules change significantly.

---

## Package Structure

```
sentinel/              # Main Python package
├── api/               # FastAPI app, auth middleware
├── audit/             # Structured logging
├── channels/          # Multi-channel access (WebSocket, SSE, Signal, MCP)
├── core/              # Config, models, approval, database, event bus
├── memory/            # Persistent memory (embeddings, chunks, hybrid search)
├── planner/           # Claude planner + CaMeL orchestrator
├── routines/          # Routine scheduling engine (cron, event, interval triggers)
├── security/          # All scanning, policy, provenance, spotlighting
├── session/           # Session store
├── tools/             # Tool executor (policy-checked)
└── worker/            # Provider ABCs, Ollama client, factory

tests/                 # All test files (project root)
sidecar/               # Rust WASM sidecar (Phase 4)
ui/                    # Frontend (HTML/JS/CSS)
policies/              # Security policy YAML
container/             # Containerfile for builds
```

---

## Source Modules (`sentinel/`)

### API & Configuration (`sentinel/api/`, `sentinel/core/`, `sentinel/audit/`)

| Module | Lines | Purpose |
|--------|-------|---------|
| `api/app.py` | ~900 | FastAPI app, `/api/` router, `/ws` WebSocket, `/api/events` SSE, `/mcp/` MCP mount, lifespan, Pydantic models |
| `api/auth.py` | ~131 | PIN authentication ASGI middleware, per-IP lockout (5 failures / 60s), exempts `/health` + `/api/health` |
| `api/middleware.py` | ~70 | SecurityHeadersMiddleware (6 headers), CSRFMiddleware, RequestSizeLimitMiddleware |
| `api/redirect.py` | ~35 | HTTPSRedirectApp — minimal ASGI app for HTTP→HTTPS 301 redirect |
| `core/config.py` | ~80 | Pydantic Settings — all config via `SENTINEL_*` env vars (db_path, TLS, ports, etc.) |
| `core/models.py` | ~150 | Data models: TrustLevel, DataSource, ScanResult, TaggedData, PlanStep, Plan, TaskResult, etc. |
| `core/approval.py` | ~230 | SQLite-backed approval queue with configurable TTL |
| `core/db.py` | ~170 | SQLite schema: sessions, turns, provenance, approvals, memory_chunks (FTS5 + sqlite-vec), routines, audit_log |
| `core/bus.py` | ~105 | Async pub/sub event bus with wildcard topic matching |
| `audit/logger.py` | ~52 | Structured JSON logging with daily rotation |

**Key constants:**
- `api/auth.py:14` — `_MAX_FAILED_ATTEMPTS = 5`, `_LOCKOUT_SECONDS = 60`
- `core/config.py` — all settings with defaults (approval_mode, thresholds, timeouts, etc.)

### Persistent Memory (`sentinel/memory/`)

| Module | Lines | Purpose |
|--------|-------|---------|
| `memory/embeddings.py` | ~120 | Async Ollama embedding client (`/api/embed`), nomic-embed-text 768-dim, retry logic |
| `memory/splitter.py` | ~95 | Text splitting: paragraph → sentence → word boundaries, configurable overlap |
| `memory/chunks.py` | ~260 | MemoryStore CRUD with FTS5 + sqlite-vec sync, dual-mode (SQLite / in-memory fallback) |
| `memory/search.py` | ~150 | RRF hybrid search: fts_search(), vec_search(), hybrid_search() with k=60 fusion |

**Key classes:**
- `chunks.MemoryStore` — CRUD + application-layer FTS5/vec sync, `_has_vec_table()` cached check
- `chunks.MemoryChunk` — dataclass: chunk_id, user_id, content, source, metadata, timestamps
- `embeddings.EmbeddingClient` — async embed()/embed_batch(), shares OllamaWorker error hierarchy
- `search.SearchResult` — dataclass: chunk_id, content, source, score, match_type

### Multi-Channel Access (`sentinel/channels/`)

| Module | Lines | Purpose |
|--------|-------|---------|
| `channels/base.py` | ~120 | Channel ABC (start, stop, send, receive), IncomingMessage, OutgoingMessage, ChannelRouter |
| `channels/web.py` | ~170 | WebSocketChannel (PIN auth, JSON protocol), SSEWriter (event bus → SSE stream) |
| `channels/mcp_server.py` | ~130 | FastMCP server: search_memory, store_memory, run_task, health_check tools |
| `channels/signal_channel.py` | ~200 | SignalChannel (signal-cli JSON-RPC subprocess), ExponentialBackoff, SignalConfig |

**Key classes:**
- `base.Channel` — ABC all transport backends implement
- `base.ChannelRouter` — routes messages to orchestrator, manages bus subscriptions
- `web.WebSocketChannel` — PIN auth + JSON protocol over WebSocket
- `web.SSEWriter` — event bus → SSE stream with keepalive and auto-cleanup
- `mcp_server.create_mcp_server()` — factory for FastMCP with Sentinel tools
- `signal_channel.SignalChannel` — signal-cli subprocess with crash recovery
- `signal_channel.ExponentialBackoff` — 1s, 2s, 4s, ... up to max_delay

### Security Pipeline (`sentinel/security/`)

| Module | Lines | Purpose |
|--------|-------|---------|
| `pipeline.py` | ~449 | Scan orchestration: input scan → script gate → length gate → spotlighting → Qwen → output scan → echo scan |
| `scanner.py` | ~512 | Regex scanners: CredentialScanner, SensitivePathScanner, CommandPatternScanner, VulnerabilityEchoScanner, EncodingNormalizationScanner |
| `policy_engine.py` | ~288 | YAML-driven deterministic rules: file paths, commands, traversal detection, injection patterns |
| `prompt_guard.py` | ~117 | Prompt Guard 2 (86M BERT) — injection/jailbreak detection, 2000-char chunking |
| `code_extractor.py` | ~120 | Fenced code block extraction, language tag mapping + heuristic detection, emoji stripping from code |
| `codeshield.py` | ~170 | CodeShield/Semgrep wrapper — `scan_blocks()` per-block scanning with language hints, fail-closed |
| `spotlighting.py` | ~33 | Per-word character prefix marking for untrusted data |
| `conversation.py` | ~493 | 8 heuristic rules for multi-turn attack detection (retry, escalation, recon, topic shift, etc.) |
| `provenance.py` | ~260 | ProvenanceStore class (SQLite/in-memory) + module-level wrappers, trust tagging, recursive CTE chain walking |

**Key constants:**
- `pipeline.py:24` — `_MARKER_POOL = "~!@#%*+=|;:"` (spotlighting alphabet)
- `pipeline.py:27-31` — `_SANDWICH_REMINDER` (post-data security reminder)
- `code_extractor.py` — `_LANGUAGE_MAP` (tag→canonical), `_EMOJI_RE` (Unicode ranges for stripping)
- `scanner.py` — 11 built-in command patterns, 16 vulnerability fingerprints, 6 encoding decoders
- `conversation.py:23-114` — capability tiers, 14 override patterns, sensitive topics, escalation language
- `policy_engine.py:32-39` — `_injection_patterns` (subshell, backtick, semicolon, pipe, chaining)

**Key classes:**
- `pipeline.SecurityViolation` — raised when any scan fails (stores scan_results, raw_response)
- `pipeline.ScanPipeline.process_with_qwen()` — the full input→Qwen→output pipeline
- `code_extractor.extract_code_blocks()` — returns `list[CodeBlock]` (code, language, start/end positions)
- `code_extractor.strip_emoji_from_code_blocks()` — removes emoji from code blocks, preserves prose
- `scanner.CredentialScanner` — 22+ regex patterns (inc. npm, PyPI, HF, Stripe, etc.), URI allowlist suppression
- `scanner.SensitivePathScanner.scan_output_text()` — context-aware (only flags in code/shell, not prose)
- `scanner.EncodingNormalizationScanner` — decodes base64/hex/URL/ROT13/HTML/char-split, re-scans

### Execution Engine (`sentinel/planner/`, `sentinel/tools/`)

| Module | Lines | Purpose |
|--------|-------|---------|
| `planner/orchestrator.py` | ~350 | CaMeL execution loop: plan → approve → per-step execute → scan. Variable substitution across steps |
| `planner/planner.py` | ~220 | Claude API client, JSON plan generation, validation, refusal detection |
| `planner/trust_router.py` | ~35 | Trust tier classification: static SAFE_OPS allowlist, everything else DANGEROUS (skeleton for Phase 2+) |
| `tools/executor.py` | ~462 | Tool executor: file_write/read, mkdir, shell, podman_build/run/stop — all policy-checked |

**Key constants:**
- `planner/planner.py:12-191` — `_PLANNER_SYSTEM_PROMPT_TEMPLATE` (Claude's full instructions)
- `planner/orchestrator.py` — `_FORMAT_INSTRUCTIONS`, `_CHAIN_REMINDER` (chained step safety text)
- `tools/executor.py:14-20` — `_DANGEROUS_PODMAN_FLAG_NAMES/VALUES` (blocked flags)

**Key functions:**
- `orchestrator.handle_task()` — main entry point from `/task` endpoint
- `orchestrator.execute_approved_plan()` — runs after human approval
- `orchestrator.ExecutionContext.resolve_text_safe()` — wraps variable content with UNTRUSTED_DATA tags + markers
- `planner.ClaudePlanner.create_plan()` — calls Claude API, validates JSON response
- `executor.ToolExecutor.execute()` — dispatches to tool handler with policy check

### Worker, Providers & State (`sentinel/worker/`, `sentinel/session/`)

| Module | Lines | Purpose |
|--------|-------|---------|
| `worker/base.py` | ~110 | Provider ABCs: WorkerBase, PlannerBase, EmbeddingBase + generic exceptions |
| `worker/ollama.py` | ~150 | Ollama/Qwen async HTTP client, retry logic (implements WorkerBase) |
| `worker/factory.py` | ~40 | Config-driven provider factory: create_worker/planner/embedding |
| `session/store.py` | ~305 | SQLite-backed session store (with in-memory fallback), write-through Session objects, TTL eviction |

**Key classes:**
- `base.WorkerBase` — ABC for text generation providers
- `base.PlannerBase` — ABC for task planning providers
- `base.EmbeddingBase` — ABC for vector embedding providers
- `base.ProviderError` → `ProviderConnectionError`, `ProviderTimeoutError`, `ProviderModelNotFound`
- `factory.create_worker()` / `create_planner()` / `create_embedding_client()` — config-driven construction

**Key constants:**
- `worker/ollama.py:12-35` — `QWEN_SYSTEM_PROMPT_TEMPLATE` (Qwen's system prompt with `{marker}` placeholder)

**Key functions:**
- `provenance.create_tagged_data()` — creates entry, inherits UNTRUSTED from any parent
- `provenance.is_trust_safe_for_execution()` — called before every tool execution (the CaMeL guarantee)
- `provenance.record_file_write()` / `get_file_writer()` — file trust inheritance
- `session.SessionStore.get_or_create()` — per-source sessions with TTL

### Routines (`sentinel/routines/`)

| Module | Lines | Purpose |
|--------|-------|---------|
| `routines/store.py` | ~230 | RoutineStore CRUD (SQLite + in-memory fallback), Routine dataclass |
| `routines/engine.py` | ~310 | Scheduler loop, event trigger subscriptions, execution management with asyncio tasks |
| `routines/cron.py` | ~60 | Cron expression validation (croniter), next_run calculation, trigger_config validation |

**Key classes:**
- `store.Routine` — dataclass: routine_id, user_id, name, trigger_type/config, action_config, enabled, cooldown_s
- `store.RoutineStore` — CRUD + list_due() + update_run_state(), dual-mode (SQLite/in-memory)
- `engine.RoutineEngine` — background scheduler, event bus subscriber, execution management

**Key functions:**
- `engine.RoutineEngine.start()` / `stop()` — lifecycle management (spawns asyncio task)
- `engine.RoutineEngine.trigger_manual()` — public API for manual routine execution
- `engine.RoutineEngine.get_execution_history()` — query routine_executions table
- `cron.validate_cron()` / `next_run()` / `validate_trigger_config()` — validation helpers

---

## Rust Sidecar (`sidecar/`)

WASM tool sandbox with Wasmtime. Executes tools in isolated WASM instances with deny-by-default capabilities, fuel metering, epoch timeouts, and Aho-Corasick leak detection.

| File | Purpose |
|------|---------|
| `src/main.rs` | Unix socket listener, config loading, graceful shutdown |
| `src/protocol.rs` | JSON request/response types (with credentials, timeout, fuel_consumed, leaked fields) |
| `src/sandbox.rs` | Wasmtime engine: fresh Store per execution, fuel metering, epoch timeout, spawn_blocking |
| `src/host_functions.rs` | `host_call` dispatcher: read_file, write_file, shell_exec, http_fetch, get_credential |
| `src/leak_detector.rs` | Aho-Corasick credential scanner (22 patterns + injected values), redaction |
| `src/http_client.rs` | URL validation, SSRF protection (private IP rejection, hostname allowlist), ureq client |
| `src/registry.rs` | TOML-based tool metadata registry (wasm_path, required_capabilities, http_allowlist) |
| `src/capabilities.rs` | Capability enum (6 variants) + CapabilitySet with from_strings/requires_all |
| `src/config.rs` | Resource limits + env var config (SENTINEL_SIDECAR_* prefix) |
| `tools/common/` | Guest-side library: IO_BUFFER (1MB), host_call wrapper, Op enum, stdin/stdout JSON helpers |
| `tools/file-read/` | WASM tool: reads file via Op::ReadFile host function |
| `tools/file-write/` | WASM tool: writes file via Op::WriteFile host function |
| `tools/shell-exec/` | WASM tool: runs command via Op::ShellExec host function |
| `tools/http-fetch/` | WASM tool: HTTP fetch via Op::HttpFetch + optional Op::GetCredential |
| `wasm/` | Compiled .wasm outputs + tool.toml metadata files (gitignored except .toml) |
| `tests/integration.rs` | Protocol serialization, registry TOML parsing, config defaults |

**Key constants:**
- `leak_detector.rs` — 22 built-in patterns (AWS, GitHub, Slack, OpenAI, Stripe, PEM, JWT, generic)
- `config.rs` — defaults: 64 MiB memory, 1B fuel, 30s timeout, /workspace allowed paths
- `sandbox.rs` — epoch ticker at 500ms intervals for timeout enforcement

**Python integration:**
- `sentinel/tools/sidecar.py` — SidecarClient (Unix socket, auto-start, crash recovery)
- `sentinel/tools/executor.py` — WASM_TOOLS set dispatches to sidecar when configured

---

## Test Files (`tests/`)

| File | Tests | Source Module(s) |
|------|-------|-----------------|
| `test_policy_engine.py` | ~60 | security/policy_engine (paths, commands, traversal, globs) |
| `test_scanner.py` | ~65 | security/scanner (credentials inc. 10 new patterns, paths, commands, echo) |
| `test_encoding_scanner.py` | ~25 | security/scanner (base64, hex, URL, ROT13, HTML, char-split) |
| `test_pipeline.py` | ~47 | security/pipeline (input/output scan, SecurityViolation, script gate, empty response retry) |
| `test_spotlighting.py` | ~10 | security/spotlighting (apply/remove markers) |
| `test_prompt_guard.py` | ~15 | security/prompt_guard (init, chunking, classification) |
| `test_code_extractor.py` | ~39 | security/code_extractor (block extraction, language detection, emoji stripping) |
| `test_codeshield.py` | ~19 | security/codeshield (init, scan parsing, scan_blocks with language hints) |
| `test_planner.py` | ~40 | planner/planner (plan creation, validation, refusals) |
| `test_orchestrator.py` | ~50 | planner/orchestrator (context, steps, trust gates, chain-safe) |
| `test_tools.py` | ~40 | tools/executor (file I/O, shell, Podman, flag deny-list) |
| `test_provenance.py` | ~20 | security/provenance (trust inheritance, chains, file tracking) |
| `test_approval.py` | ~15 | core/approval (lifecycle, TTL, submit) |
| `test_conversation.py` | ~57 | security/conversation (all 8 rules, combined scoring, FP prevention, first-turn override, authority patterns) |
| `test_pin_auth.py` | ~20 | api/auth (PIN validation, lockout, timing) |
| `test_hardening.py` | ~30 | Cross-module hardening regression tests |
| `test_input_validation.py` | ~15 | api/app Pydantic validators + pipeline length gate |
| `test_hostile.py` | ~50 | Cross-module adversarial attack simulations |
| `test_worker.py` | ~10 | worker/ollama (mocked Ollama connection/timeout) |
| `test_db.py` | 17 | core/db (schema creation, tables, constraints, FTS5) |
| `test_bus.py` | 19 | core/bus (subscribe, unsubscribe, publish, wildcards) |
| `test_middleware.py` | 12 | api/middleware (security headers, CSRF, request size limit) |
| `test_static_redirect.py` | 9 | api/redirect + static files (HTML/CSS/JS serving, 301 redirect) |
| `test_session_sqlite.py` | 13 | session/store SQLite (write-through, TTL, capacity, cascade) |
| `test_provenance_sqlite.py` | 17 | security/provenance SQLite (recursive CTE, trust inheritance, file prov) |
| `test_trust_router.py` | 10 | planner/trust_router (classify, allowlist immutability) |
| `test_splitter.py` | 19 | memory/splitter (paragraph, sentence, word splits, overlap, edge cases) |
| `test_embeddings.py` | 10 | memory/embeddings (mocked Ollama, batch, timeout, retry) |
| `test_memory_store.py` | 24 | memory/chunks (CRUD, FTS5 sync, vec, dual-mode, user isolation) |
| `test_memory_search.py` | 15 | memory/search (FTS5, RRF fusion, vec fallback, ranking) |
| `test_memory_api.py` | 13 | memory API endpoints (store, search, get, delete, validation) |
| `test_channels.py` | 19 | Channel ABC, ChannelRouter, event bus wiring in orchestrator |
| `test_websocket.py` | 12 | WebSocket auth, send, receive, endpoint integration |
| `test_sse.py` | 10 | SSEWriter stream, event delivery, endpoint tests |
| `test_mcp.py` | 16 | MCP tools, trust tiers, search/store/run_task/health |
| `test_signal_channel.py` | 17 | Signal subprocess, backoff, JSON-RPC protocol, crash recovery |
| `test_sidecar_client.py` | 29 | SidecarClient mock socket, ToolExecutor WASM dispatch, config |
| `test_provider_abc.py` | 24 | Provider ABCs, factory, isinstance checks, exception hierarchy |
| `test_routine_store.py` | 29 | RoutineStore CRUD, list filtering, cron validation, cascade delete |
| `test_routine_engine.py` | 21 | Scheduler loop, event/manual triggers, cooldown, timeout, bus emissions |
| `conftest.py` | — | Fixtures: engine, cred_scanner, path_scanner, cmd_scanner, encoding_scanner |

**Total: 1090 Python tests + 41 Rust tests passing** (`pytest tests/` + `cargo test` from project root)

---

## Frontend (`ui/`)

| File | Lines | Purpose |
|------|-------|---------|
| `index.html` | ~38 | Chat UI structure: header + status dot, message area, input form |
| `app.js` | ~450 | Task submission, PIN management (sessionStorage), approval flow, message history (localStorage, 100 max) |
| `style.css` | ~200 | Dark theme (GitHub-inspired), responsive layout |

**Key JS functions:** `submitTask()`, `submitApproval()`, `checkStatus()`, `buildStepsHtml()`, `bindStepToggles()`

> Note: `gateway/static/` still contains the originals used by the running nginx container. `ui/` is the canonical location going forward.

---

## Infrastructure

| File | Purpose |
|------|---------|
| `podman-compose.yaml` | Legacy 3 services (controller + qwen + ui), 2 networks, 2 secrets |
| `podman-compose.phase1.yaml` | Phase 1: 2 services (sentinel-v2 + sentinel-ollama-v2), ports 3003/3004 |
| `policies/sentinel-policy.yaml` | ~130 lines — file access, commands, network, credential patterns, sensitive paths |
| `container/Containerfile` | Python 3.12 + Prompt Guard + semgrep + TLS cert + UI static files |
| `controller/Dockerfile` | Legacy: used by currently running containers |
| `gateway/Dockerfile` | Legacy: nginx (to be eliminated after Phase 1 validation) |
| `pyproject.toml` | Package metadata, dependencies, pytest config |

---

## Cross-Module Data Flow

```
User → HTTPS (uvicorn TLS) or HTTP (redirect.HTTPSRedirectApp → 301)
     → api/middleware.SecurityHeadersMiddleware [6 headers]
     → api/middleware.RequestSizeLimitMiddleware [1MB gate]
     → api/middleware.CSRFMiddleware [origin check]
     → api/auth.PinAuthMiddleware [PIN + lockout; exempts /ws, /mcp]
     → Transport: /api/* (REST) | /ws (WebSocket) | /api/events (SSE) | /mcp/* (MCP)
       → planner/orchestrator.handle_task()
         → session/store.get_or_create() [SQLite write-through]
         → security/conversation.analyze() [8 rules]
         → security/pipeline.scan_input() [Prompt Guard + 4 scanners]
         → planner/planner.create_plan() [Claude API]
         → core/approval.request_plan_approval() [SQLite, if full mode]
         → for each step:
             llm_task → orchestrator._execute_llm_task()
                      → security/pipeline.process_with_qwen()
                        → security/pipeline._check_prompt_ascii()  # script gate
                        → security/spotlighting.apply_datamarking()
                        → worker/ollama.generate() → sentinel-qwen:11434
                        → security/provenance.create_tagged_data() [UNTRUSTED, SQLite]
                        → security/code_extractor.extract_code_blocks()
                        → security/codeshield.scan_blocks() [per-block with language hints]
                        → security/code_extractor.strip_emoji_from_code_blocks()
                        → security/pipeline.scan_output()
                        → security/scanner.VulnerabilityEchoScanner.scan()
             tool_call → security/provenance.is_trust_safe_for_execution() [recursive CTE]
                       → tools/executor.execute() → security/policy_engine.check_*()
       → TaskResult returned
     → api/app.py StaticFiles mount (/ catch-all for UI)
```

## Module Dependency Graph

```
sentinel/api/app.py [lifespan: init_db → SessionStore, ApprovalManager, ProvenanceStore, MemoryStore, EmbeddingClient, RoutineStore, RoutineEngine]
  ├── api/middleware.py (SecurityHeaders, CSRF, RequestSizeLimit)
  ├── api/auth.py (PinAuth middleware)
  ├── api/redirect.py (HTTPSRedirectApp — background uvicorn for HTTP→HTTPS)
  ├── core/config.py (settings)
  ├── core/db.py (init_db — SQLite schema, WAL mode, FK enforcement)
  ├── core/models.py (shared data types)
  ├── audit/logger.py (logging)
  ├── memory/chunks.py (MemoryStore — CRUD + FTS5/vec sync)
  ├── memory/embeddings.py (EmbeddingClient — Ollama /api/embed)
  ├── memory/search.py (hybrid_search — RRF fusion)
  ├── memory/splitter.py (split_text — paragraph/sentence/word)
  ├── planner/orchestrator.py
  │     ├── planner/planner.py → Claude API
  │     ├── planner/trust_router.py (skeleton — SAFE_OPS allowlist, Phase 2+)
  │     ├── memory/chunks.py + memory/embeddings.py (auto-memory after task completion)
  │     ├── security/pipeline.py
  │     │     ├── security/scanner.py (5 scanners)
  │     │     ├── security/prompt_guard.py → HuggingFace model
  │     │     ├── security/spotlighting.py
  │     │     └── worker/base.py (WorkerBase ABC) → worker/ollama.py → Ollama/Qwen
  │     ├── tools/executor.py
  │     │     ├── security/policy_engine.py → sentinel-policy.yaml
  │     │     └── security/provenance.py [ProvenanceStore — SQLite recursive CTE]
  │     ├── core/approval.py [SQLite-backed, configurable TTL]
  │     ├── session/store.py [SQLite write-through + in-memory fallback]
  │     ├── security/conversation.py
  │     ├── security/code_extractor.py (extract_code_blocks, strip_emoji_from_code_blocks)
  │     └── security/codeshield.py → semgrep (scan_blocks)
  ├── core/bus.py (event bus — wired to orchestrator + channels)
  ├── channels/base.py (Channel ABC, ChannelRouter)
  ├── channels/web.py (WebSocketChannel, SSEWriter)
  ├── channels/mcp_server.py (FastMCP server — mounted at /mcp/)
  ├── channels/signal_channel.py (SignalChannel — signal-cli subprocess)
  ├── routines/store.py (RoutineStore — CRUD, dual-mode)
  ├── routines/engine.py (RoutineEngine — scheduler + event triggers + execution)
  ├── routines/cron.py (croniter validation + next_run calculation)
  └── worker/factory.py (config-driven provider factory)
```
