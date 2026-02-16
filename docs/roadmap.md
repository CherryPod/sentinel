# Roadmap

Sentinel's evolution from a security gateway to a full AI assistant platform.

## Current Capabilities

- CaMeL defence-in-depth pipeline (Claude planner + Qwen worker + 10-layer scanning)
- Air-gapped worker LLM with zero trust
- WebUI chat interface with human approval flow
- PIN authentication + CSRF protection
- 435 unit tests, v3 stress test benchmarked (1,136 prompts, 0.12% real risk)
- Trust level 0 operational (text generation only)

## Planned Evolution

The evolution plan consolidates Sentinel from three containers to two, adds assistant features (memory, channels, tools), and prepares for open-source release. See [docs/design/evolution-plan.md](design/evolution-plan.md) for the full implementation plan.

### Phase 0: Foundation

Project restructuring and infrastructure preparation. No running container changes.

- Restructure `controller/app/` from flat modules to domain-driven packages
- SQLite + sqlite-vec database schema (replacing in-memory stores)
- Rust WASM sidecar skeleton (tool sandbox)
- Internal asyncio pub/sub (replacing MQTT dependency)

### Phase 1: Container Consolidation

Merge `sentinel-controller` and `sentinel-ui` into a single `sentinel` container. FastAPI serves the static UI directly — no more nginx reverse proxy.

- TLS handled by FastAPI/uvicorn
- Eliminates proxy timeout issues and simplifies deployment
- Two containers total: `sentinel` + `ollama`

### Phase 2: Memory System

Persistent semantic memory using SQLite + sqlite-vec.

- Conversation memory (auto-summarised)
- Factual memory (user-correctable)
- Procedural memory (learned workflows)
- RRF hybrid search (keyword + vector)
- Embeddings via Ollama on CPU (nomic-embed-text, avoids VRAM contention)

### Phase 3: Multi-Channel Access

Connect Sentinel to messaging platforms. Each channel is a thin adapter — all messages route through the same security pipeline.

- **Signal** — via signal-cli as managed subprocess (JSON-RPC)
- **WebSocket** — real-time chat from the WebUI
- **Telegram / Slack** — webhook-based adapters

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
