# Roadmap

Sentinel's evolution from a security gateway to a full AI assistant platform.

## Current Capabilities

- CaMeL defence-in-depth pipeline (Claude planner + Qwen worker + 10-layer scanning)
- Air-gapped worker LLM with zero trust
- WebUI chat interface with human approval flow (WebSocket + SSE + HTTP polling)
- PIN authentication + CSRF protection
- 826 unit tests, v3 stress test benchmarked (1,136 prompts, 0.12% real risk)
- Trust level 0 operational (text generation only)
- Proper `sentinel/` Python package with domain-driven sub-packages
- SQLite-backed stores (sessions, provenance, approvals)
- Persistent memory with RRF hybrid search (FTS5 + sqlite-vec)
- Multi-channel access: WebSocket, SSE, Signal (mocked), MCP server
- Rust WASM sidecar skeleton (Phase 4 implementation)
- Async event bus with orchestrator wiring (5 task lifecycle events)

## Planned Evolution

The evolution plan consolidates Sentinel from three containers to two, adds assistant features (memory, channels, tools), and prepares for open-source release. See [docs/design/evolution-plan.md](design/evolution-plan.md) for the full implementation plan.

### Phase 0: Foundation — COMPLETE

Project restructuring and infrastructure preparation. No running container changes.

- ~~Restructure `controller/app/` to `sentinel/` domain-driven packages~~ Done
- ~~SQLite + sqlite-vec database schema~~ Done (`sentinel/core/db.py`)
- ~~Rust WASM sidecar skeleton~~ Done (`sidecar/`)
- ~~Internal asyncio event bus~~ Done (`sentinel/core/bus.py`)

### Phase 1: Container Consolidation — COMPLETE

Merged `sentinel-controller` and `sentinel-ui` into a single `sentinel` container. FastAPI serves the static UI directly — no more nginx reverse proxy.

- ~~TLS handled by FastAPI/uvicorn~~ Done
- ~~Eliminates proxy timeout issues and simplifies deployment~~ Done
- ~~Two containers total: `sentinel` + `ollama`~~ Done
- ~~SQLite-backed stores (sessions, provenance, approvals)~~ Done
- ~~Security headers as middleware~~ Done
- ~~Trust router skeleton~~ Done

### Phase 2: Memory System — COMPLETE

Persistent semantic memory using SQLite + sqlite-vec.

- ~~Embedding pipeline via Ollama on CPU (nomic-embed-text)~~ Done
- ~~Chunk management with paragraph/sentence/word splitting~~ Done
- ~~RRF hybrid search (FTS5 keyword + sqlite-vec vector)~~ Done
- ~~Memory API (POST/GET/DELETE + search)~~ Done
- ~~Auto-memory (store summaries after task completion)~~ Done

### Phase 3: Multi-Channel Access — COMPLETE

Real-time communication channels — all messages route through the same security pipeline.

- ~~Channel abstraction (ABC + ChannelRouter + event bus wiring)~~ Done
- ~~WebSocket with PIN auth + SSE streaming~~ Done
- ~~MCP server (4 tools: search_memory, store_memory, run_task, health_check)~~ Done
- ~~Signal channel via signal-cli subprocess (mocked, not yet registered)~~ Done
- ~~UI transport cascade: WebSocket → SSE → HTTP polling~~ Done

### Phase 4: WASM Tool Sandbox

Sandboxed tool execution via a Rust sidecar using WebAssembly.

- Tools compiled to WASM with strict capability boundaries
- Tiered trust router: safe operations (memory search, status queries) execute directly via WASM, dangerous operations route through the full CaMeL pipeline
- MCP (Model Context Protocol) client for external tool integration

### Phase 5: Routines and Automation

Scheduled and event-triggered workflows.

- Cron-based scheduling
- Event triggers (message received, file changed, webhook)
- User-defined routines with approval gates

## Architecture Target

```
┌──────────────────────────────────────────────────────┐
│              sentinel (single container)               │
│                                                        │
│  FastAPI ─ API, WebSocket, SSE, webhooks, static UI    │
│  CaMeL pipeline ─ 10 security layers, provenance       │
│  Memory ─ SQLite + sqlite-vec, RRF hybrid search        │
│  Routine engine ─ cron + event triggers                 │
│  Tiered trust ─ safe → fast, dangerous → CaMeL          │
│  MCP client ─ external tool integration                  │
│  signal-cli ─ managed subprocess                         │
│  Rust WASM sidecar ─ sandboxed tools                     │
└───────────────────┬──────────────────────────────────┘
                    │ sentinel_internal (air-gapped)
┌───────────────────▼──────────────────────────────────┐
│              ollama (any model, GPU)                    │
│  Worker LLM + embedding model (CPU)                    │
└──────────────────────────────────────────────────────┘
```

## Contributing

Interested in contributing? See [CONTRIBUTING.md](../CONTRIBUTING.md). The areas with the most impact right now:

- **Scanner tuning** — reducing the 18.8% false positive rate without weakening security
- **Test coverage** — adversarial prompts for new attack categories
- **Documentation** — tutorials, examples, integration guides
