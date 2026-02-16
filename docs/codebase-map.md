# Codebase Map

Developer reference for navigating the Sentinel codebase. Module responsibilities, key classes/functions, important constants, and cross-dependencies.

> This file is for Claude Code context loading and contributor onboarding. Update when modules change significantly.

---

## Package Structure

```
sentinel/              # Main Python package
├── api/               # FastAPI app, auth middleware
├── audit/             # Structured logging
├── core/              # Config, models, approval, database, event bus
├── memory/            # Persistent memory (embeddings, chunks, hybrid search)
├── planner/           # Claude planner + CaMeL orchestrator
├── security/          # All scanning, policy, provenance, spotlighting
├── session/           # Session store
├── tools/             # Tool executor (policy-checked)
└── worker/            # Ollama/Qwen client

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
| `api/app.py` | ~280 | FastAPI app, `/api/` router, lifespan (SQLite init), static file mount, Pydantic request models |
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

### Security Pipeline (`sentinel/security/`)

| Module | Lines | Purpose |
|--------|-------|---------|
| `pipeline.py` | ~449 | Scan orchestration: input scan → ASCII gate → length gate → spotlighting → Qwen → output scan → echo scan |
| `scanner.py` | ~512 | Regex scanners: CredentialScanner, SensitivePathScanner, CommandPatternScanner, VulnerabilityEchoScanner, EncodingNormalizationScanner |
| `policy_engine.py` | ~288 | YAML-driven deterministic rules: file paths, commands, traversal detection, injection patterns |
| `prompt_guard.py` | ~117 | Prompt Guard 2 (86M BERT) — injection/jailbreak detection, 2000-char chunking |
| `codeshield.py` | ~136 | CodeShield/Semgrep wrapper — insecure code detection, async, fail-closed |
| `spotlighting.py` | ~33 | Per-word character prefix marking for untrusted data |
| `conversation.py` | ~493 | 8 heuristic rules for multi-turn attack detection (retry, escalation, recon, topic shift, etc.) |
| `provenance.py` | ~260 | ProvenanceStore class (SQLite/in-memory) + module-level wrappers, trust tagging, recursive CTE chain walking |

**Key constants:**
- `pipeline.py:24` — `_MARKER_POOL = "~!@#%*+=|;:"` (spotlighting alphabet)
- `pipeline.py:27-31` — `_SANDWICH_REMINDER` (post-data security reminder)
- `scanner.py` — 11 built-in command patterns, 16 vulnerability fingerprints, 6 encoding decoders
- `conversation.py:23-114` — capability tiers, override patterns, sensitive topics, escalation language
- `policy_engine.py:32-39` — `_injection_patterns` (subshell, backtick, semicolon, pipe, chaining)

**Key classes:**
- `pipeline.SecurityViolation` — raised when any scan fails (stores scan_results, raw_response)
- `pipeline.ScanPipeline.process_with_qwen()` — the full input→Qwen→output pipeline
- `scanner.CredentialScanner` — 12+ regex patterns, URI allowlist suppression
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

### Worker & State (`sentinel/worker/`, `sentinel/session/`)

| Module | Lines | Purpose |
|--------|-------|---------|
| `worker/ollama.py` | ~143 | Ollama/Qwen async HTTP client, retry logic |
| `session/store.py` | ~305 | SQLite-backed session store (with in-memory fallback), write-through Session objects, TTL eviction |

**Key constants:**
- `worker/ollama.py:12-35` — `QWEN_SYSTEM_PROMPT_TEMPLATE` (Qwen's system prompt with `{marker}` placeholder)

**Key functions:**
- `provenance.create_tagged_data()` — creates entry, inherits UNTRUSTED from any parent
- `provenance.is_trust_safe_for_execution()` — called before every tool execution (the CaMeL guarantee)
- `provenance.record_file_write()` / `get_file_writer()` — file trust inheritance
- `session.SessionStore.get_or_create()` — per-source sessions with TTL

---

## Rust Sidecar (`sidecar/`)

Skeleton for Phase 4 WASM tool sandbox. Compiles and accepts JSON over Unix socket.

| File | Purpose |
|------|---------|
| `src/main.rs` | Unix socket listener, connection handler |
| `src/protocol.rs` | JSON request/response types (serde) |
| `src/sandbox.rs` | Wasmtime engine stub |
| `src/registry.rs` | Tool metadata stub |
| `src/capabilities.rs` | Capability model stub (ReadFile, WriteFile, HttpRequest, UseCredential, InvokeTool) |
| `src/config.rs` | Resource limits (memory, fuel, timeout) |

---

## Test Files (`tests/`)

| File | Tests | Source Module(s) |
|------|-------|-----------------|
| `test_policy_engine.py` | ~60 | security/policy_engine (paths, commands, traversal, globs) |
| `test_scanner.py` | ~50 | security/scanner (credentials, paths, commands, echo) |
| `test_encoding_scanner.py` | ~25 | security/scanner (base64, hex, URL, ROT13, HTML, char-split) |
| `test_pipeline.py` | ~30 | security/pipeline (input/output scan, SecurityViolation, ASCII gate) |
| `test_spotlighting.py` | ~10 | security/spotlighting (apply/remove markers) |
| `test_prompt_guard.py` | ~15 | security/prompt_guard (init, chunking, classification) |
| `test_codeshield.py` | ~10 | security/codeshield (init, scan parsing) |
| `test_planner.py` | ~40 | planner/planner (plan creation, validation, refusals) |
| `test_orchestrator.py` | ~50 | planner/orchestrator (context, steps, trust gates, chain-safe) |
| `test_tools.py` | ~40 | tools/executor (file I/O, shell, Podman, flag deny-list) |
| `test_provenance.py` | ~20 | security/provenance (trust inheritance, chains, file tracking) |
| `test_approval.py` | ~15 | core/approval (lifecycle, TTL, submit) |
| `test_conversation.py` | ~40 | security/conversation (all 8 rules, combined scoring, FP prevention) |
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
| `conftest.py` | — | Fixtures: engine, cred_scanner, path_scanner, cmd_scanner, encoding_scanner |

**Total: 752 tests passing** (`pytest tests/` from project root)

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
     → api/auth.PinAuthMiddleware [PIN + lockout]
     → api/app.py api_router (/api/* endpoints, Pydantic validation)
       → planner/orchestrator.handle_task()
         → session/store.get_or_create() [SQLite write-through]
         → security/conversation.analyze() [8 rules]
         → security/pipeline.scan_input() [Prompt Guard + 4 scanners]
         → planner/planner.create_plan() [Claude API]
         → core/approval.request_plan_approval() [SQLite, if full mode]
         → for each step:
             llm_task → orchestrator._execute_llm_task()
                      → security/pipeline.process_with_qwen()
                        → security/pipeline._check_prompt_ascii()
                        → security/spotlighting.apply_datamarking()
                        → worker/ollama.generate() → sentinel-qwen:11434
                        → security/provenance.create_tagged_data() [UNTRUSTED, SQLite]
                        → security/codeshield.scan()
                        → security/pipeline.scan_output()
                        → security/scanner.VulnerabilityEchoScanner.scan()
             tool_call → security/provenance.is_trust_safe_for_execution() [recursive CTE]
                       → tools/executor.execute() → security/policy_engine.check_*()
       → TaskResult returned
     → api/app.py StaticFiles mount (/ catch-all for UI)
```

## Module Dependency Graph

```
sentinel/api/app.py [lifespan: init_db → SessionStore, ApprovalManager, ProvenanceStore, MemoryStore, EmbeddingClient]
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
  │     │     └── worker/ollama.py → Ollama/Qwen
  │     ├── tools/executor.py
  │     │     ├── security/policy_engine.py → sentinel-policy.yaml
  │     │     └── security/provenance.py [ProvenanceStore — SQLite recursive CTE]
  │     ├── core/approval.py [SQLite-backed, configurable TTL]
  │     ├── session/store.py [SQLite write-through + in-memory fallback]
  │     ├── security/conversation.py
  │     └── security/codeshield.py → semgrep
  └── core/bus.py (event bus — not yet wired)
```
