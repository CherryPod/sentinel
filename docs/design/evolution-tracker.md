# Evolution Tracker

Progress checklist for the evolution plan. Design rationale lives in `evolution-plan.md` — this is just status.

**Started:** 2026-02-16
**Plan:** `evolution-plan.md` (this directory)

---

## Pre-requisites

- [x] Stress test v3 complete (1,136 prompts, 0.12% real risk)
- [x] Results reviewed (`docs/assessments/v3-security-analysis.md`)
- [x] Project restructured for open-source (`README.md`, `LICENSE`, docs reorganised)
- [ ] Resolve open questions (see below)

## Open Questions

1. **Project name** — what to call the combined product for GitHub?
2. ~~**License**~~ — Apache-2.0 (decided)
3. **Tool sandboxing v1** — exact WASI target version, WIT interface design
4. **Multi-user** — single-user v1 with `user_id` column ready for later
5. **IronClaw credit** — NOTICE file, README section, or both?
6. **GPU sharing** — test nomic-embed-text (CPU) + Qwen (GPU) concurrent Ollama serving

---

## Phase 0: Foundation — COMPLETE (2026-02-16)

> Goal: Package restructure, database schema, Rust sidecar skeleton, event bus. No running container changes.

- [x] **0.1 — Restructure to Python package**
  - [x] `controller/app/*.py` → `sentinel/` package (core, security, planner, worker, tools, api, audit)
  - [x] `pyproject.toml` replaces `requirements.txt`
  - [x] `tests/` moved to project root
  - [x] `ui/` copied from `gateway/static/`
  - [x] All 562 original tests pass with updated imports
- [x] **0.2 — SQLite + sqlite-vec database**
  - [x] `sentinel/core/db.py` — schema for sessions, turns, provenance, approvals, memory, routines, audit
  - [x] All tables include `user_id TEXT DEFAULT 'default'`
  - [x] FTS5 index on memory_chunks, sqlite-vec virtual table (optional, skipped if extension not loaded)
- [x] **0.3 — Rust WASM sidecar skeleton**
  - [x] `sidecar/` with Cargo.toml, main.rs, protocol.rs, sandbox.rs, registry.rs, capabilities.rs, config.rs
  - [x] Compiles, accepts/returns JSON over Unix socket
- [x] **0.4 — Internal event bus**
  - [x] `sentinel/core/bus.py` — asyncio pub/sub with wildcard matching
  - [x] Topics: task.*, approval.*, session.*, channel.*, routine.*, memory.*

**Verified:** 598 tests pass (562 original + 17 db + 19 bus), db schema creates in-memory, `cargo check` passes

---

## Phase 1: Infrastructure Consolidation — COMPLETE (2026-02-16)

> Goal: 3 containers → 2. Merge UI into controller, SQLite backends, tiered trust router.

- [x] **1.1 — Eliminate nginx container**
  - [x] FastAPI serves static files (`StaticFiles` at `/`)
  - [x] Security headers as middleware (CSP, HSTS, X-Frame-Options, etc.) — `sentinel/api/middleware.py`
  - [x] TLS via uvicorn (self-signed cert at build time)
  - [x] HTTP→HTTPS redirect via `HTTPSRedirectApp` — `sentinel/api/redirect.py`
  - [x] API router with `/api/` prefix — matches existing UI `fetch()` calls
- [x] **1.2 — Migrate in-memory stores to SQLite**
  - [x] SessionStore → SQLite (write-through Session objects, zero orchestrator changes)
  - [x] Provenance store → SQLite (`ProvenanceStore` class + module-level wrappers, zero caller changes)
  - [x] ApprovalManager → SQLite (returns dict from `get_pending` instead of dataclass)
- [x] **1.3 — Tiered trust router**
  - [x] Static allowlist skeleton (`health_check`, `session_info`) — `sentinel/planner/trust_router.py`
  - [x] `classify_operation()` → `TrustTier.SAFE` or `TrustTier.DANGEROUS`
  - [ ] Wiring into request flow (Phase 2+)
- [x] **1.4 — Two-container compose file**
  - [x] `podman-compose.phase1.yaml` — sentinel-v2 + sentinel-ollama-v2 (ports 3003/3004)
  - [x] Containerfile updated: `COPY ui/`, TLS cert, `EXPOSE 8443 8080`
- [x] **1.5 — Config updates**
  - [x] `db_path`, `static_dir`, `tls_cert_file`, `tls_key_file`, `https_port`, `http_port`, `external_https_port`, `redirect_enabled`
  - [x] `ollama_model` comment updated (user-configurable)
  - [x] MQTT settings removed

**Verified:** 662 tests pass (598 original + 64 new). Parallel deploy via `podman-compose.phase1.yaml` on ports 3003/3004.

---

## Phase 2: Persistent Memory — COMPLETE (2026-02-16)

> Goal: Hybrid search memory — store context, search with RRF.

- [x] **2.1 — Embedding pipeline** — `sentinel/memory/embeddings.py`, EmbeddingClient for Ollama /api/embed (nomic-embed-text, 768 dims)
- [x] **2.2 — Chunk management** — `sentinel/memory/chunks.py`, MemoryStore CRUD + FTS5/vec sync, `sentinel/memory/splitter.py` paragraph/sentence/word splitting
- [x] **2.3 — RRF hybrid search** — `sentinel/memory/search.py`, FTS5 + sqlite-vec with RRF fusion (k=60), graceful vec fallback
- [x] **2.4 — Memory API + auto-memory** — POST/GET/DELETE /api/memory, GET /api/memory/search, auto-store summaries after task completion

**Verified:** 90 new tests (752 total, all pass). Store/search/delete roundtrip, FTS5 sync on CRUD, graceful vec degradation, embedding fallback, RRF fusion scoring

---

## Phase 3: Multi-Channel Access — COMPLETE (2026-02-16)

> Goal: WebSocket/SSE web upgrade, Signal messaging, MCP server.

- [x] **3.1 — Channel abstraction** — ABC: receive, send, start, stop + ChannelRouter + event bus wiring in orchestrator (5 events)
- [x] **3.2 — Web channel upgrade** — WebSocket /ws + SSE /api/events + transport cascade UI (WS → SSE → HTTP polling)
- [x] **3.4 — MCP server** — FastMCP with 4 tools (search_memory, store_memory, run_task, health_check), mounted at /mcp/
- [x] **3.3 — Signal channel** — signal-cli subprocess (JSON-RPC), exponential backoff crash recovery, all tests mocked

**Verified:** 74 new tests (826 total, all pass). Channel ABC, bus wiring, WS auth/send/receive, SSE stream, MCP tools, Signal subprocess management

---

## Phase 4: WASM Tool Sandbox (parallel with 2-3)

> Goal: Rust sidecar with Wasmtime for sandboxed tool execution.

- [ ] **4.1 — Wasmtime integration** — fresh instance per exec, fuel metering, memory cap, epoch timeout
- [ ] **4.2 — Capability model** — ReadFile, WriteFile, HttpRequest, UseCredential, InvokeTool
- [ ] **4.3 — Credential injection + leak detection** — host function injection, Aho-Corasick output scan
- [ ] **4.4 — HTTP allowlist + SSRF protection** — URL validation, private IP rejection, DNS rebinding defence
- [ ] **4.5 — Python client** — SidecarClient over Unix socket with crash recovery
- [ ] **4.6 — V1 tool set** — file_read, file_write, shell_exec, http_fetch, memory_search

**Verify:** capability enforcement works, credentials injected/wiped, leak detector catches patterns, fuel/memory limits stop abuse

---

## Phase 5: Routines + Multi-Provider

> Goal: Background automation and model flexibility.

- [ ] **5.1 — Routine engine** — cron + event triggers, SQLite state, cooldowns, capacity limits
- [ ] **5.2 — Routine API** — CRUD + manual trigger
- [ ] **5.3 — Multi-provider LLM** — OllamaProvider + ClaudeProvider ABC, config-driven model swap

**Verify:** cron runs on schedule, events trigger, model swap works end-to-end

---

## Phase 6: Hardening + Open Source

> Goal: Security audit, documentation, GitHub push.

- [ ] Test suite: target 800+ tests
- [ ] Security audit: memory injection, routine manipulation, WASM escape, MCP/Signal injection
- [ ] New attack surfaces scanned (memory results as untrusted, routine creation requires approval)
- [ ] Documentation complete
- [ ] Sanitise: no personal paths, IPs, hostnames, secrets in repo
- [ ] CI: GitHub Actions (pytest, cargo test, cargo clippy)
- [ ] IronClaw credited (NOTICE file)
- [ ] Smoke test: clean clone → `podman compose up` → working end-to-end

---

## Blockers / Issues Encountered

_None currently blocking._

<!-- Format:
### [Phase.Task] Short description
**Status:** blocked / investigating / resolved
**Details:** What happened, what was tried
**Resolution:** How it was fixed (move to resolved section when done)
-->

## Resolved Issues

### [1.1] Security headers not applied on error responses
**Details:** `BaseHTTPMiddleware.call_next` doesn't catch exceptions — the exception handler runs outside the middleware chain, so 500 errors from unhandled exceptions don't get security headers.
**Resolution:** Not a real issue for production (FastAPI's exception handlers return proper responses). Test updated to use `JSONResponse(500)` instead of `raise ValueError`.

### [1.1] Starlette StaticFiles html=True doesn't do deep SPA fallback
**Details:** `StaticFiles(html=True)` serves `index.html` for directory paths but returns 404 for arbitrary deep paths like `/some/unknown/path`. Not true SPA catch-all.
**Resolution:** Acceptable for current UI (single-page, no client-side routing). Test changed from `test_spa_fallback` to `test_unknown_path_returns_404`.

### [1.2] Session TTL test patching time.monotonic on rewritten module
**Details:** `test_ttl_eviction` patched `sentinel.session.store.time.monotonic` which no longer exists after the SQLite rewrite (timestamps changed from `time.monotonic()` to ISO8601 strings).
**Resolution:** Changed test to backdate `session.last_active = "2020-01-01T00:00:00.000000Z"` directly instead of mocking time.

### [1.2] Provenance reset_store FK constraint failure
**Details:** `reset_store()` failed with `sqlite3.IntegrityError: FOREIGN KEY constraint failed` because `file_provenance.writer_data_id` references `provenance.data_id`.
**Resolution:** Changed `reset_store()` to delete from `file_provenance` first, then `provenance`.
