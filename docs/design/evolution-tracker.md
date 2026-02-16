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

## Phase 1: Infrastructure Consolidation

> Goal: 3 containers → 2. Merge UI into controller, SQLite backends, tiered trust router.

- [ ] **1.1 — Eliminate nginx container**
  - [ ] FastAPI serves static files (`StaticFiles`)
  - [ ] Security headers as middleware (CSP, HSTS, X-Frame-Options, etc.)
  - [ ] TLS via uvicorn (self-signed cert at build time)
  - [ ] Remove sentinel-ui from compose
- [ ] **1.2 — Migrate in-memory stores to SQLite**
  - [ ] SessionStore → SQLite
  - [ ] Provenance store → SQLite
  - [ ] ApprovalManager → SQLite
- [ ] **1.3 — Tiered trust router**
  - [ ] Static allowlist (memory_search, routine_list, health_check, etc.)
  - [ ] Safe ops bypass CaMeL, still go through auth + WASM sandbox
  - [ ] Everything else → full CaMeL pipeline
- [ ] **1.4 — Two-container compose file**
  - [ ] sentinel + ollama (air-gap preserved)
  - [ ] Multi-stage Containerfile (Rust build → Python → final)
- [ ] **1.5 — Config updates**
  - [ ] db_path, sidecar_socket, static_dir, tls, embeddings_model
  - [ ] ollama_model configurable (not hardcoded to Qwen)
  - [ ] Remove MQTT settings

**Verify:** 2 containers running, UI loads, API works, security headers present, SQLite persists across restarts

---

## Phase 2: Persistent Memory

> Goal: Hybrid search memory — store context, search with RRF.

- [ ] **2.1 — Embedding pipeline** — nomic-embed-text via Ollama on CPU
- [ ] **2.2 — Chunk management** — store/update/delete, paragraph splitting, FTS5 + vector sync
- [ ] **2.3 — RRF hybrid search** — FTS5 keyword + sqlite-vec semantic, k=60 fusion
- [ ] **2.4 — Memory API + auto-memory** — CRUD endpoints, auto-store conversation summaries

**Verify:** store/search/delete roundtrip, RRF better than either method alone, CPU embeddings don't impact GPU inference

---

## Phase 3: Multi-Channel Access

> Goal: WebSocket/SSE web upgrade, Signal messaging, MCP server.

- [ ] **3.1 — Channel abstraction** — ABC: receive, send, start, stop + ChannelRouter
- [ ] **3.2 — Web channel upgrade** — WebSocket /ws + SSE /events + polling fallback
- [ ] **3.3 — Signal channel** — signal-cli as managed subprocess (JSON-RPC)
- [ ] **3.4 — MCP server** — expose tools to MCP clients, all through trust router

**Verify:** WebSocket streams, SSE fallback works, Signal send/receive, MCP connects from Claude Desktop

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

_None yet — add entries as issues arise during implementation._

<!-- Format:
### [Phase.Task] Short description
**Status:** blocked / investigating / resolved
**Details:** What happened, what was tried
**Resolution:** How it was fixed (move to resolved section when done)
-->

## Resolved Issues

_Move resolved blockers here with their resolution._
