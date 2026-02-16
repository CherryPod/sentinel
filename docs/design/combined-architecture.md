# IronClaw Analysis & Combined Architecture Plan

**Date:** 2026-02-15
**Status:** Research & Design (pre-implementation)
**Context:** Exploration of nearai/ironclaw to evaluate integration with Sentinel

---

## Table of Contents

1. [Background & Motivation](#1-background--motivation)
2. [What is OpenClaw / IronClaw](#2-what-is-openclaw--ironclaw)
3. [IronClaw Deep Dive — What It Does Well](#3-ironclaw-deep-dive--what-it-does-well)
4. [IronClaw — What It Doesn't Do Well](#4-ironclaw--what-it-doesnt-do-well)
5. [NEAR AI Analysis — The Privacy Reality](#5-near-ai-analysis--the-privacy-reality)
6. [Sentinel — Current State](#6-sentinel--current-state)
7. [Head-to-Head Comparison](#7-head-to-head-comparison)
8. [Integration Feasibility](#8-integration-feasibility)
9. [Architecture Options Considered](#9-architecture-options-considered)
10. [Container Consolidation](#10-container-consolidation)
11. [Final Architecture Decision](#11-final-architecture-decision)
12. [What to Take from IronClaw](#12-what-to-take-from-ironclaw)
13. [What Sentinel Already Does Better](#13-what-sentinel-already-does-better)
14. [The Combined Product Vision](#14-the-combined-product-vision)
15. [Implementation Phases](#15-implementation-phases)
16. [Open Questions](#16-open-questions)

---

## 1. Background & Motivation

Sentinel was built as a CaMeL-based defence-in-depth AI security system — a framework that chains Claude (Anthropic's frontier model) with a local, air-gapped Qwen 3 14B LLM, defended by a deterministic security gateway. The original plan was to add signal-cli for messaging and see what could be built.

During routine dependency scanning with repo-scout, the project `nearai/ironclaw` was discovered. IronClaw is an OpenClaw-inspired AI assistant built in Rust with a strong security focus. Initial analysis revealed that IronClaw and Sentinel are **complementary rather than competing** — IronClaw is a full-featured AI assistant with decent security, while Sentinel is a hardened security gateway with minimal assistant features.

This document captures the full analysis of both projects and the design for a combined product that takes the best of each: a **hardened AI helper** with production-grade security, multi-channel access, persistent memory, and a sandboxed tool ecosystem.

### repo-scout Scan Result

```
nearai/ironclaw — MINIMAL RISK
Stars: 1,428 | Forks: 128 | Contributors: 12
License: Apache-2.0 | Language: Rust | Size: 3.0 MB
Created: 2026-02-03 (12 days old at time of scan)
Findings: 0 red flags, 0 warnings, 1 info (very new repository)
```

---

## 2. What is OpenClaw / IronClaw

### OpenClaw

OpenClaw is the original open-source AI assistant project. IronClaw is a ground-up reimplementation inspired by OpenClaw, built in Rust by the NEAR AI team. The two are distinct projects — IronClaw is not a fork.

### IronClaw

**Repository:** https://github.com/nearai/ironclaw
**Language:** Rust (1.85+, 2024 edition)
**License:** Apache-2.0 (permissive — forking/adapting is fine)
**Contributors:** 12, including Illia Polosukhin (NEAR Protocol co-founder)

IronClaw is a self-expanding personal AI assistant that prioritises data privacy and defence against misuse. It provides:

- **Multi-channel access** — CLI (REPL), HTTP/webhooks, WebSocket, SSE, Telegram, Slack, WhatsApp
- **Sandboxed tool ecosystem** — WASM tools (Gmail, Google Drive, Slack, etc.), MCP server support, built-in tools, dynamic tool creation
- **Persistent memory** — filesystem-like workspace with hybrid BM25 + vector search
- **Background automation** — cron-scheduled routines, event triggers, webhook handlers
- **Self-repair** — automatic detection and LLM-driven repair of broken tools and stuck jobs
- **Security** — WASM sandboxing, encrypted secrets, prompt injection defence, leak detection

### IronClaw Tech Stack

| Layer | Technology |
|-------|------------|
| Language | Rust 1.85+ (2024 edition) |
| Async Runtime | Tokio (full features) |
| HTTP Server | Axum 0.8 |
| Database | PostgreSQL 15+ (primary) or libSQL/Turso (embedded) |
| Vector Search | pgvector + HNSW indexing |
| WASM Runtime | Wasmtime 28 (component model) |
| LLM Integration | rig-core (multi-provider abstraction) |
| Supported Models | NEAR AI, OpenAI, Anthropic, Ollama, OpenAI-compatible |
| Container Runtime | Docker/Podman via bollard |
| Secrets | AES-256-GCM encryption + system keychain |
| Distribution | Single binary via cargo-dist |

### IronClaw Project Structure

```
ironclaw/
├── src/
│   ├── agent/           # Core agent loop, routing, scheduling
│   ├── channels/        # Input channels (REPL, HTTP, WebSocket, WASM)
│   ├── tools/           # Tool system (registry, WASM sandbox, MCP, built-ins)
│   ├── workspace/       # Persistent memory with hybrid search
│   ├── orchestrator/    # Docker container job management
│   ├── safety/          # Prompt injection defence, leak detection
│   ├── secrets/         # Encrypted credential storage
│   ├── llm/             # Multi-provider LLM integration
│   ├── context/         # Job context and session management
│   ├── extensions/      # MCP servers and WASM tool discovery
│   ├── db/              # Database abstraction (PostgreSQL or libSQL)
│   ├── evaluation/      # Performance tracking
│   ├── estimation/      # Cost and time estimation
│   ├── history/         # Conversation and event logs
│   ├── setup/           # Onboarding wizard
│   ├── config.rs        # Configuration loading
│   ├── settings.rs      # Settings persistence
│   ├── main.rs          # CLI entry point
│   └── lib.rs           # Library entry point
├── tools-src/           # Pre-built WASM tools (Gmail, Slack, Google Drive, etc.)
├── channels-src/        # Pre-built WASM channels (Telegram, Slack, WhatsApp)
├── migrations/          # Database schema migrations
├── docker/              # Container configurations
└── Cargo.toml           # Dependencies manifest
```

---

## 3. IronClaw Deep Dive — What It Does Well

### 3.1 WASM Tool Sandbox (Standout Feature)

The WASM sandbox is IronClaw's most impressive feature. Each tool runs in complete isolation using Wasmtime's component model:

**How it works:**
- Each tool execution gets a **fresh Wasmtime instance** — no state persists between calls
- Tools are compiled once at registration and cached; instantiation takes ~1ms
- Deny-by-default capability model — tools have ZERO permissions unless explicitly granted

**Capability types:**

| Capability | What Tool Can Do | Enforcement |
|-----------|-----------------|-------------|
| Workspace | Read/write memory files | Path prefix whitelist + traversal validation |
| HTTP | Make web requests | Allowlist validator + leak detector + rate limit (50/exec) |
| Tool Invoke | Call other tools | Alias indirection (WASM never sees real tool names) + rate limit (20/exec) |
| Secrets | Check if a secret exists | Bool only — tool NEVER sees the actual secret value |

**Resource limits per tool:**
- Memory: 10MB default (configurable per tool)
- CPU: 10M fuel instructions (configurable)
- Timeout: 60s default + epoch-based hard limit (500ms tick from background thread)
- Logs: 1,000 entries max
- HTTP: 50 requests per execution, 30s timeout cap

**Credential injection at the host boundary:**
1. **Direct placeholders**: Tool passes `{GOOGLE_ACCESS_TOKEN}` in URLs/headers → host substitutes real value before sending
2. **Host-pattern matching**: Pre-configured credential mappings by hostname (e.g., `*.googleapis.com` → inject Bearer token)
3. **OAuth token refresh**: Transparent auto-refresh with 5-minute buffer, SSRF-protected (rejects private IPs after DNS resolution)

The tool never sees credential values — it only observes their effects. The leak detector scans all outbound requests and inbound responses for secret patterns (20+ built-in patterns including OpenAI keys, AWS keys, GitHub tokens, PEM keys, etc.).

**SSRF protection:** After allowlist validation passes, the system resolves DNS and blocks connections to private IP ranges (127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, etc.). This prevents DNS rebinding attacks where an allowed domain resolves to an internal IP.

**Why this matters for the combined product:** This is fundamentally different from container-per-tool isolation. WASM runs in-process — you can have 50+ tools executing without spawning a single container. The isolation is enforced by the Wasmtime runtime at the hardware level (memory protection), not by the OS kernel.

### 3.2 Self-Healing Tool Pipeline

When a WASM tool accumulates 5+ failures, the self-repair system automatically:

1. Detects the broken tool via failure count threshold
2. Creates a `BuildRequirement` containing the tool name, previous error, and failure count
3. Feeds this to the LLM-driven tool builder
4. The builder generates new source code, compiles to WASM, validates the interface
5. If successful, re-registers the tool and resets the failure counter
6. If it fails, increments repair attempts (max attempts before flagging for human intervention)

This is a genuine self-healing pipeline. The system can recover from bugs in dynamically-created tools without human intervention. Maximum repair attempts prevent infinite loops.

### 3.3 Dynamic Tool Building

Users can request "build me a Telegram tool" and the agent:

1. **Analyses** the request → extracts name, description, type, language
2. **Scaffolds** the project structure (Cargo.toml, src/lib.rs, WIT interface, capabilities.json)
3. **Implements** — LLM writes the code using file I/O tools
4. **Builds** — `cargo component build --release`
5. **Tests** — runs the test suite
6. **Fixes** — parses errors, modifies code, retries (up to 10 iterations)
7. **Validates** — for WASM tools, verifies interface compliance
8. **Registers** — copies artifact, registers with the tool registry

The builder injects extensive documentation about host functions, WIT interfaces, and capabilities when building WASM tools. The build_software tool requires approval (`requires_approval() = true`), preventing unauthorised tool creation.

### 3.4 Multi-Channel Architecture

Clean trait-based design with a unified `IncomingMessage` type:

```
Channel trait → start() returns MessageStream
             → respond(msg, response)
             → broadcast(user_id, response)
             → health_check()
             → shutdown()
```

The `ChannelManager` uses `futures::stream::select_all()` to merge streams from multiple channels into a single message stream without polling. Channels available:

| Channel | Type | Protocol |
|---------|------|----------|
| REPL | Bidirectional | Stdio |
| HTTP | Webhook | HTTP POST (with optional sync response via oneshot channel) |
| Telegram | WASM channel | MTProto via proxy |
| Slack | WASM channel | Slack API |
| WhatsApp | WASM channel | Cloud API |
| Web Gateway | Bidirectional | HTTP + SSE + WebSocket |

**Web Gateway details:**
- **SSE**: `tokio::sync::broadcast` for event fan-out, atomic connection counting (max 100), `CountedStream` wrapper that decrements on drop (handles abrupt disconnects), 30s keep-alive pings
- **WebSocket**: Split socket into sender/receiver tasks via `tokio::select!`, handles messages/approvals/auth tokens/pings, shares the same broadcast channel as SSE
- **OpenAI-compatible API**: Can be used with standard chat clients

### 3.5 Persistent Memory with Hybrid Search

Filesystem-like workspace API backed by PostgreSQL (or libSQL):

**Operations:** read, write, append, delete, list, search

**Hybrid search uses Reciprocal Rank Fusion (RRF):**
```
score(doc) = sum(1 / (k + rank)) for each search method where doc appears
```

Two search methods are combined:
1. **BM25 full-text search** — PostgreSQL's `ts_rank_cd()` with `plainto_tsquery('english', ...)`
2. **Vector semantic search** — pgvector cosine distance (`<=>` operator)

RRF merges the two ranked lists without needing score normalisation. Documents appearing in both lists get boosted. The `k` parameter (default 60) tunes relative importance. Configurable to use either method alone.

**Embedding providers:** OpenAI (`text-embedding-3-small`), NEAR AI, mock (for testing)

**Special workspace paths:** `MEMORY.md`, `daily/YYYY-MM-DD.md`, `HEARTBEAT.md`, `AGENTS.md`, `SOUL.md`, `IDENTITY.md`, `USER.md` — seeded on first access with sensible defaults.

### 3.6 Routine Engine

Supports four trigger types:
- **Cron**: Standard cron expressions (e.g., `0 9 * * MON-FRI`)
- **Event**: Regex pattern matching on incoming messages (in-memory cache for fast O(n) matching)
- **Webhook**: HTTP endpoint triggers with optional shared secret
- **Manual**: CLI/tool invocation only

**Guardrails per routine:**
- Cooldown period (minimum time between fires)
- Max concurrent runs
- Global capacity limit (atomic counter via `AtomicUsize`)
- Consecutive failure tracking

**Execution modes:**
- **Lightweight**: Single LLM call, no tools, no scheduler slot. Uses `ROUTINE_OK` sentinel string to signal "nothing to report"
- **FullJob**: Full agentic loop with tool access (noted as "pending scheduler integration" in code — currently falls back to lightweight)

**Persistent state:** Each routine can store runtime state in `routines/{name}/state.md` workspace file, loaded before execution and available for next run.

### 3.7 Agent Loop

The core reasoning loop with several clever features:

- **Tool-forcing heuristic**: If the model explains what it will do instead of calling tools (iteration < 3, no tools executed yet), the agent pushes back with "Please proceed and use the available tools"
- **Per-iteration tool refresh**: Newly built tools become visible immediately without restarting
- **Approval context checkpointing**: Full message history saved in `PendingApproval.context_messages` and resumed after approval with complete context intact
- **Auto-compaction**: When context usage exceeds 80%, old turns are summarised and compressed
- **Undo/redo**: Snapshot created before each turn starts
- **Max 10 tool calls per turn** (hardcoded)

### 3.8 MCP Integration

Full Model Context Protocol support via JSON-RPC 2.0 over HTTP:

- Tool discovery via `tools/list` method
- Tool execution via `tools/call` method
- Structured tool annotations: `destructive_hint`, `side_effects_hint`, `read_only_hint`, `execution_time_hint`
- **OAuth 2.1 with PKCE**: Full spec-compliant implementation including dynamic client registration, authorisation code flow, local callback server, automatic token refresh
- Session management with credential sharing across services (embeddings, MCP, LLM)

### 3.9 Secrets Management

- **AES-256-GCM** encryption with per-secret key derivation via HKDF-SHA256
- Per-secret random 32-byte salt → HKDF → derived key → AES-256-GCM
- Master key sources (priority order): OS keychain → environment variable → file
- WASM tools can only check `exists()` — never `get_decrypted()`
- Leak detector scans all tool outputs for accidental exposure

### 3.10 Scheduler & Parallel Jobs

- TOCTOU-safe job scheduling (write lock held for entire check-insert)
- Batch execution: spawns all tasks first, collects results in order (preserves ordering with true parallelism)
- Background cleanup tasks poll and remove finished jobs
- Graceful stop: channel message → 100ms grace → abort → persist cancelled state

---

## 4. IronClaw — What It Doesn't Do Well

### 4.1 Security Depth

IronClaw's security is focused on **tool isolation** (WASM sandbox), not **LLM threat mitigation**. It has:

- Pattern-based prompt injection detection (regex)
- HTML/XML sanitisation of tool outputs
- Configurable policy rules (block/warn/sanitise/review)
- Tool output truncation

What it **doesn't** have:

| Capability | IronClaw | Sentinel |
|-----------|----------|----------|
| Multi-layer scan pipeline | No (single pattern layer) | 10 layers |
| ML-based injection detection | No | Prompt Guard 2 (BERT) |
| Static code analysis | No | CodeShield (semgrep) |
| Reverse shell/pipes-to-shell detection | No | CommandPatternScanner |
| Multi-turn attack analysis | No | ConversationAnalyzer (8 heuristic rules) |
| Content safety classification | No | Llama Guard 4 (skipped for VRAM) |
| Data spotlighting | No | Per-word markers (~50% → <3% injection success) |
| Vulnerability echo detection | No | VulnerabilityEchoScanner |
| Non-ASCII prompt blocking | No | ASCII Prompt Gate |
| Formal trust propagation | No | CaMeL provenance tagging |
| Air-gapped worker | No (trusts cloud providers) | Qwen on isolated network |
| Human approval gate | Per-tool (optional) | Per-plan-step (mandatory for dangerous ops) |

### 4.2 Trust Model

IronClaw fundamentally **trusts its LLM provider**. Prompts go to NEAR AI / OpenAI / Anthropic cloud servers with no verification that the model isn't compromised or manipulated. There's no equivalent of Sentinel's "assume the worker is compromised" philosophy.

### 4.3 Local-First Claims vs Reality

The README claims "your data stays yours" and "all information is stored locally, encrypted, and never leaves your control." While local storage is real, every inference request is sent to cloud providers. The default model (Llama 4 Maverick) runs on Fireworks AI servers. See Section 5 for the full NEAR AI analysis.

### 4.4 Routine Engine Gaps

- **FullJob mode not implemented** — falls back to lightweight (single LLM call, no tools)
- Cron uses polling (query DB every N seconds) rather than precise scheduling
- No audit trail for routine executions beyond basic logging

### 4.5 No Deterministic Security Rules

IronClaw's security is primarily capability-based (what tools can do) rather than policy-based (what operations are allowed). There's no equivalent of Sentinel's YAML policy engine that deterministically blocks specific file paths, commands, or network destinations regardless of what the LLM requests.

### 4.6 Tool Builder Auto-Registration

The tool builder can auto-register newly built tools if `auto_register` is enabled. This means an LLM could theoretically build and deploy a tool without human review. In contrast, the combined product should route all tool creation through the approval gate and scan pipeline.

---

## 5. NEAR AI Analysis — The Privacy Reality

### What NEAR AI Actually Is

NEAR AI is **not** running proprietary models. It's a **proxy/aggregator** for third-party inference providers:

```
User prompt → IronClaw → NEAR AI (cloud-api.near.ai) → Fireworks / OpenAI / Anthropic → Response
```

- **Default model**: `fireworks::accounts/fireworks/models/llama4-maverick-instruct-basic` (Meta's Llama 4 Maverick on Fireworks AI)
- **Auth**: OAuth via GitHub or Google → session token stored at `~/.ironclaw/session.json`
- **API modes**: Responses API (`/v1/responses`) or OpenAI-compatible Chat Completions (`/v1/chat/completions`)

### Privacy Claims vs Reality

**What's genuinely private:**
- Conversation history stored locally in PostgreSQL
- Secrets encrypted at rest (AES-256-GCM)
- No telemetry or tracking in the client

**What's NOT private:**
- Every inference request sent to NEAR AI servers
- NEAR AI proxies to third-party providers (Fireworks, OpenAI, Anthropic)
- Your prompts are visible to NEAR AI and the downstream provider
- No end-to-end encryption of inference requests by default

### NEAR AI Private Inference (Exists, But Not Used by Default)

NEAR AI does have a documented [Private Inference](https://docs.near.ai/cloud/private-inference/) feature:

- Uses **Intel TDX** (Trust Domain Extensions) for confidential VMs
- Uses **NVIDIA TEE** for GPU-level isolation during inference
- Hardware enclaves where prompts/responses are encrypted end-to-end
- Cryptographic attestation verifies execution environment integrity

**However:** The IronClaw codebase contains **zero references** to TEE, enclave, private inference, or confidential computing. The default configuration hits the standard `cloud-api.near.ai` endpoint with no special privacy flags. Private Inference appears to be an opt-in NEAR AI Cloud feature, not something IronClaw leverages.

### Relevance to Combined Product

**NEAR AI adds nothing we don't already have.** Sentinel's architecture is more private:

| Aspect | NEAR AI (IronClaw default) | Sentinel |
|--------|---------------------------|----------|
| Inference location | Cloud (Fireworks/OpenAI) | Local (Qwen, air-gapped) |
| Prompt visibility | Visible to NEAR AI + provider | Never leaves the machine |
| Network requirement | Mandatory internet | Qwen: none. Claude: Anthropic API only |
| Trust model | Trust the cloud provider | Assume worker is compromised |

---

## 6. Sentinel — Current State

### What Sentinel Is

A CaMeL-based defence-in-depth AI security system that chains Claude (planner) with an air-gapped Qwen 3 14B (worker), defended by 10 deterministic + ML security layers.

### Architecture (Current)

Three containers:
- **sentinel-controller**: FastAPI security gateway + orchestrator
- **sentinel-qwen**: Ollama server (Qwen 3 14B, air-gapped on `sentinel_internal` network)
- **sentinel-ui**: Nginx WebUI + reverse proxy (HTTPS port 3001)

Two networks:
- **sentinel_internal**: Air-gapped bridge, no external routing (Qwen + Controller only)
- **sentinel_egress**: Controller internet access + MQTT + UI

### CaMeL Pipeline

```
User Request
    ↓
Claude Planner (creates JSON plan)
    ↓
Approval Gate (human reviews plan)
    ↓
For each step in plan:
  - llm_task → Qwen generates text → CodeShield scans → output scanning
  - tool_call → policy engine validates → execution
    ↓
Result with provenance tagging
```

### 10 Security Layers

1. **PIN Authentication** — ASGI middleware, X-Sentinel-Pin header
2. **Policy Engine** — YAML-based deterministic rules (file paths, commands, networks)
3. **Spotlighting** — Per-word markers on untrusted data (~50% → <3% injection success rate)
4. **Prompt Guard 2** — BERT classifier (~67% injection detection rate)
5. **Llama Guard 4** — Content safety (skipped Phase 5, VRAM conflict with Qwen)
6. **CodeShield** — Semgrep static analysis for malicious code patterns
7. **CommandPatternScanner** — Regex patterns for reverse shells, pipes-to-shell, etc.
8. **ConversationAnalyzer** — 8 heuristic rules for multi-turn attacks
9. **VulnerabilityEchoScanner** — Detects when Qwen reproduces vulnerable code instead of fixing it
10. **CaMeL Provenance** — Trust tagging ensures untrusted data can't reach dangerous operations

Additional hardening:
- **ASCII Prompt Gate** — Blocks non-ASCII in worker prompts (prevents cross-model injection)
- **Input Validation Gate** — Pydantic validators + 100K char pipeline length limit

### Current File Structure

```
~/sentinel/
├── controller/app/
│   ├── main.py              # FastAPI entry + all endpoints
│   ├── orchestrator.py      # CaMeL execution loop
│   ├── planner.py           # Claude API client + JSON plan generation
│   ├── worker.py            # Ollama/Qwen async client
│   ├── pipeline.py          # Security scan orchestrator
│   ├── scanner.py           # Credential + path + command scanners
│   ├── policy_engine.py     # YAML policy validator
│   ├── conversation.py      # 8-rule multi-turn heuristic analyser
│   ├── session.py           # Session store + turn tracking
│   ├── approval.py          # HTTP approval manager with TTL
│   ├── tools.py             # Tool executor with policy checks
│   ├── codeshield.py        # CodeShield async wrapper
│   ├── prompt_guard.py      # Prompt Guard 2 ML scanner
│   ├── provenance.py        # Trust tagging + chain walking
│   ├── spotlighting.py      # Data marking (per-word markers)
│   ├── auth.py              # PIN auth middleware
│   ├── config.py            # Pydantic settings
│   ├── audit.py             # JSON structured logging
│   └── models.py            # Pydantic data models
├── controller/tests/        # 562 tests (all passing)
├── gateway/                 # Nginx + static chat UI
├── scripts/                 # Stress tests
├── policies/
│   └── sentinel-policy.yaml # All deterministic security rules
├── podman-compose.yaml      # Container orchestration
└── CLAUDE.md                # Project rules
```

### Current API Endpoints

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/health` | Status check (exempt from PIN auth) |
| GET | `/validate/path` | Policy check for file operations |
| GET | `/validate/command` | Policy check for shell commands |
| POST | `/scan` | Run all scanners on text |
| POST | `/process` | Qwen pipeline: scan → spotlight → generate → scan |
| POST | `/task` | Full CaMeL: Claude plans → approve → Qwen executes → scanned |
| GET | `/approval/{id}` | Check approval status |
| POST | `/approve/{id}` | Submit approval decision |
| GET | `/session/{id}` | Debug: view conversation history + risk scores |

### MQTT Topics (Phase 4, paused)

- `sentinel/tasks` — incoming user requests
- `sentinel/results` — execution results
- `sentinel/approval` — approval decisions

### Current Maturity

- **Phase 1** (Controller + Policy Engine): Complete
- **Phase 2** (Qwen Worker): Complete
- **Phase 3** (Claude Planner + CaMeL): Complete
- **Phase 4** (Signal + WebUI): Signal paused, WebUI complete but not fully integrated
- **Phase 5** (Hardening): Complete (TLS, CSP, CSRF, resource limits, read-only FS, pinned images, health checks)

**Test suite:** 562 tests, all passing
**Known gaps:** Multi-turn escapes (27% success rate), conversation analyser under-tuned, 14% false positive rate, response latency (hardware-constrained)

---

## 7. Head-to-Head Comparison

### Feature Matrix

| Feature | IronClaw | Sentinel | Combined |
|---------|----------|----------|----------|
| **User Channels** | CLI, HTTP, WS, SSE, Telegram, Slack, WhatsApp | HTTP API + basic chat UI | All IronClaw channels |
| **Tool Sandbox** | WASM (in-process, <1ms startup, 10MB cap) | Podman shell executor | WASM sandbox |
| **Tool Ecosystem** | Gmail, Drive, Sheets, Slack, Telegram, MCP | Podman commands only | Full ecosystem |
| **Dynamic Tool Building** | LLM builds + compiles + registers tools | Not yet | Yes, through approval gate |
| **Self-Repair** | Detects broken tools, LLM fixes them | No | Yes |
| **Persistent Memory** | Hybrid search (BM25 + vector via RRF) | Session tracking only | Hybrid search |
| **Background Automation** | Cron + event triggers + webhooks | No | Yes |
| **Prompt Injection Defence** | Pattern-based (regex) | 10-layer pipeline (ML + deterministic) | 10-layer pipeline |
| **Code Analysis** | None | CodeShield (semgrep) | CodeShield |
| **Trust Propagation** | None (trusts LLM output) | CaMeL provenance tagging | CaMeL provenance |
| **Air-Gapped Worker** | No (cloud providers) | Qwen on isolated network | Air-gapped Qwen |
| **Human Approval** | Per-tool (optional) | Per-plan-step (mandatory for dangerous ops) | Tiered: safe ops fast-pathed, dangerous ops approved |
| **Deterministic Policy** | Capability declarations per tool | YAML policy engine | YAML policy engine |
| **Multi-Turn Defence** | None | ConversationAnalyzer (8 rules) | ConversationAnalyzer |
| **Data Spotlighting** | None | Per-word markers | Spotlighting |
| **Secrets Management** | AES-256-GCM + keychain | Podman secrets | AES-256-GCM in SQLite |
| **MCP Support** | Full (OAuth 2.1 + PKCE) | None | Full MCP |
| **Scheduling** | Cron + events + webhooks | None | Cron + events |

### Security Depth Comparison

| Security Layer | IronClaw | Sentinel |
|---------------|----------|----------|
| Tool capability enforcement | Strong (WASM) | Moderate (policy-gated shell) |
| Prompt injection detection | Weak (regex only) | Strong (ML + patterns + spotlighting) |
| Output scanning | Good (leak detector) | Strong (CodeShield + scanners) |
| Network isolation | None (trusts cloud) | Strong (air-gapped worker) |
| Trust model | Trust the LLM | Assume LLM is compromised |
| Policy enforcement | Per-tool capabilities | Centralised YAML rules |
| Multi-turn defence | None | 8 heuristic rules |
| Credential protection | Strong (host boundary injection) | Good (Podman secrets) |
| SSRF protection | Strong (DNS rebinding prevention) | N/A (no tool HTTP) |

---

## 8. Integration Feasibility

### Why They're Compatible

The two projects solve **different halves of the same problem:**

- **IronClaw** = great assistant with okay security
- **Sentinel** = great security with minimal assistant features

They don't overlap in their core value. IronClaw's security is focused on tool isolation (keeping WASM sandboxed). Sentinel's security is focused on LLM threat mitigation (keeping the model from doing harm). These are complementary concerns.

### Integration Points

Both expose HTTP APIs. Communication is straightforward:

1. IronClaw's channel layer receives user messages
2. For safe operations (memory search, read calendar, check weather): execute directly via WASM sandbox
3. For dangerous operations (run code, modify files, access APIs with credentials): POST to Sentinel's `/task` endpoint → CaMeL pipeline → approval → scanned execution

The tiered trust model is the key innovation: **fast-path safe ops, gate dangerous ops**.

### Licensing

IronClaw is Apache-2.0 (permissive). Adapting patterns, porting code, and building on their design is explicitly allowed. Credit should be given in the README/docs.

---

## 9. Architecture Options Considered

### Option A: Rewrite Sentinel in Rust

**Rejected.** Sentinel's 10 security layers are Python-ecosystem tools (CodeShield/semgrep, Prompt Guard 2/BERT, etc.). No Rust equivalents exist. Rewriting gains nothing — Sentinel isn't slow, it's GPU-bottlenecked on Qwen inference. Would lose 562 passing tests and months of hardening work.

### Option B: Rust Sidecar + Python Sentinel (Selected)

Best of both worlds:
- Rust for speed-sensitive, security-critical components (WASM sandbox, channels, memory)
- Python for ML-heavy security pipeline (scanning, provenance, policy)
- Communication via HTTP or Unix socket
- Clean separation of concerns

**Challenges:** Two languages to maintain, network hop latency between sidecar and Sentinel, requires learning Rust. Mitigated by starting with Python-only (Option C features) and adding the Rust sidecar in v2.

### Option C: Python for Everything, Steal IronClaw's Patterns

Fastest path to shipping:
- RRF search, channel architecture, routine engine — all trivially portable to Python
- FastAPI already handles SSE/WebSocket
- MCP has Python libraries
- Tool sandboxing via lightweight Linux sandboxing (nsjail/bubblewrap) instead of WASM

**Trade-off:** No WASM sandbox (Python's wasmtime bindings are immature). Container-per-tool or bubblewrap isolation instead. Acceptable for v1.

### Decision

**Start with Option C (Python-only) for v1, evolve to Option B (Rust sidecar) for v2.** This gets a working product shipped fastest while keeping the door open for the WASM sandbox later.

---

## 10. Container Consolidation

### Problem

The original Sentinel architecture (3 containers) plus planned additions (signal-cli, mosquitto, PostgreSQL, Rust sidecar) would create 6-7 services. This is too complex for open-source adoption.

### Analysis: What Can Be Eliminated

| Service | Current | Replace With | Why |
|---------|---------|-------------|-----|
| PostgreSQL | Separate server | SQLite + sqlite-vec | Zero-config, single file, pip-installable |
| Nginx | Separate container | FastAPI serves static files | Uvicorn handles TLS, no proxy needed for single-user tool |
| Mosquitto | Host service | asyncio.Queue | Internal pub/sub — MQTT was only needed for cross-process comms |
| signal-cli | Separate container | Managed subprocess | Launched and supervised by main app via asyncio.create_subprocess_exec() |
| Separate UI | Nginx container | Embedded static files | Just a directory served by FastAPI |

### Result: Two Containers

```yaml
# podman-compose.yaml
services:
  sentinel:
    build: .
    ports: ["3001:3001"]
    volumes: ["./data:/data"]    # SQLite DB, config, workspace
    networks: [egress, internal]

  ollama:
    image: ollama/ollama
    networks: [internal]         # air-gapped
    deploy:
      resources:
        reservations:
          devices: [{capabilities: [gpu]}]

networks:
  internal:
    internal: true               # no external routing
  egress: {}
```

The air-gapped security model is preserved. Users run `podman-compose up` and visit `https://localhost:3001`.

### How Multiple Services Run in One Container

The Python app (FastAPI) acts as the process supervisor:

```
sentinel container
├── Python (FastAPI/uvicorn) ← main process
│   ├── Controller + security pipeline
│   ├── Channels (Telegram, Slack, Signal, Web SSE/WS)
│   ├── Static UI files (FastAPI serves them directly)
│   ├── Memory (SQLite + sqlite-vec)
│   ├── Manages subprocesses:
│   │   ├── signal-cli (stdin/stdout pipe)
│   │   └── [v2] Rust WASM sidecar (Unix socket)
│   └── Internal pub/sub (replaces MQTT)
│
│   Volume: /data (SQLite DB, workspace files, config)
```

No supervisord or init system needed. FastAPI's async runtime manages subprocesses natively.

---

## 11. Final Architecture Decision

### Two-Container Architecture

```
┌──────────────────────────────────────────────────────┐
│              sentinel (single container)               │
│                                                        │
│  FastAPI (uvicorn)                                    │
│  ├── /api/*        → security pipeline + CaMeL        │
│  ├── /ws           → WebSocket channels                │
│  ├── /sse          → Server-Sent Events                │
│  ├── /webhooks/*   → Telegram, Slack, Signal           │
│  ├── /*            → static UI files                   │
│  │                                                     │
│  ├── CaMeL pipeline (Claude planner + approval)        │
│  ├── 10 security layers                                │
│  ├── Policy engine (YAML rules)                        │
│  ├── Provenance tagging                                │
│  │                                                     │
│  ├── Memory (SQLite + sqlite-vec, RRF hybrid search)   │
│  ├── Secrets (AES-256-GCM encrypted in SQLite)         │
│  │                                                     │
│  ├── Routine engine (cron + event triggers)             │
│  ├── Tool sandbox (bubblewrap/nsjail for v1, WASM v2)  │
│  ├── MCP client (Python mcp library)                   │
│  │                                                     │
│  ├── signal-cli (managed subprocess)                    │
│  └── [v2] Rust WASM sidecar (Unix socket)              │
│                                                        │
│  Volume: /data (SQLite, workspace, config)             │
└───────────────────┬────────────────────────────────────┘
                    │ sentinel_internal (air-gapped)
┌───────────────────▼────────────────────────────────────┐
│              ollama (single container)                   │
│                                                        │
│  Qwen 3 14B (GPU, air-gapped)                          │
│  Only accepts connections from sentinel container       │
└────────────────────────────────────────────────────────┘
```

### Tiered Trust Model (The Key Innovation)

```
User message arrives via any channel
    │
    ├── Safe operation? (memory search, read calendar, etc.)
    │   └── Execute directly via tool sandbox → fast response
    │
    └── Dangerous operation? (run code, modify files, use credentials)
        └── Route through CaMeL pipeline:
            1. Claude plans the execution
            2. Human approves the plan
            3. Each step scanned by 10 security layers
            4. Air-gapped Qwen executes
            5. Output scanned before returning
```

Nobody else does this. Existing AI assistants either trust the model completely (IronClaw, Claude Code, etc.) or restrict it so much it's barely useful. The tiered model gives you **speed for safe ops** and **security for dangerous ops**.

---

## 12. What to Take from IronClaw

### Directly Port (Design Patterns)

| Feature | IronClaw Source | Python Approach |
|---------|----------------|-----------------|
| **RRF hybrid search** | `src/workspace/search.rs` | ~15 lines of Python with SQLite FTS5 + sqlite-vec |
| **Channel trait architecture** | `src/channels/channel.rs` | ABC with asyncio, `asyncio.Queue` for merging |
| **Routine engine** | `src/agent/routine_engine.rs` | APScheduler or custom cron + asyncio |
| **Credential injection model** | `src/tools/wasm/credential_injector.rs` | Host-boundary pattern for any sandbox |
| **Leak detector patterns** | `src/safety/leak_detector.rs` | Aho-Corasick library for Python, same 20+ patterns |
| **MCP client** | `src/tools/mcp/` | Python `mcp` library (officially supported) |
| **Multi-provider LLM** | `src/llm/` | litellm or custom provider abstraction |
| **SSE/WebSocket gateway** | `src/channels/web/` | FastAPI + `sse-starlette` + `websockets` |

### Adapt for v2 (Rust Sidecar)

| Feature | Why Wait |
|---------|----------|
| WASM tool sandbox | Needs Rust; bubblewrap/nsjail suffices for v1 |
| Dynamic tool building | Needs WASM compilation pipeline; script-based tools for v1 |
| Self-healing tools | Depends on WASM sandbox; v1 tools are simpler |
| Epoch-based timeout | Wasmtime-specific; process timeout for v1 |

### Skip Entirely

| Feature | Why |
|---------|-----|
| NEAR AI integration | Adds nothing over Ollama + Claude |
| Docker orchestrator | We use Podman + air-gapped network |
| rig-core LLM abstraction | Python has simpler options (litellm) |
| NEAR OAuth session management | Specific to NEAR AI, not needed |
| Cost estimation module | Nice-to-have, not core |

---

## 13. What Sentinel Already Does Better

These features should be preserved as-is in the combined product:

1. **CaMeL provenance tagging** — formal trust propagation that prevents untrusted data from reaching dangerous operations. IronClaw has nothing equivalent.

2. **10-layer scan pipeline** — ML classifiers (Prompt Guard 2) + static analysis (CodeShield) + deterministic scanners + spotlighting. Far deeper than IronClaw's regex-based injection detection.

3. **Air-gapped worker** — Qwen on an isolated network with zero internet access. IronClaw trusts cloud providers entirely.

4. **YAML policy engine** — centralised deterministic rules that can't be bypassed by the LLM. IronClaw's per-tool capabilities are more granular but less centrally controlled.

5. **Human approval gate** — mandatory for dangerous operations, with full plan visibility. IronClaw's approval is per-tool and optional.

6. **ConversationAnalyzer** — 8 heuristic rules for detecting multi-turn attacks (memory poisoning, escalation, reconnaissance). IronClaw has no multi-turn awareness.

7. **Spotlighting** — per-word markers on untrusted data that reduce injection success from ~50% to <3%. Novel defence not seen elsewhere.

8. **CommandPatternScanner** — catches reverse shells, pipes-to-shell, encoded payloads. IronClaw's WASM tools can't run shell commands, but the combined product's tools might.

---

## 14. The Combined Product Vision

### Unique Selling Points

No existing product combines:

1. Full assistant features (channels, tools, memory, scheduling)
2. Formal trust propagation (CaMeL provenance)
3. Air-gapped local worker (no prompt visibility to cloud providers)
4. 10-layer adversarial defence (ML + deterministic + spotlighting)
5. Human-in-the-loop approval for dangerous operations
6. Sandboxed tool ecosystem with dynamic building
7. Persistent semantic memory with hybrid search

### Target Users

- Security-conscious developers who want an AI assistant but don't trust cloud providers
- Teams that need auditable AI tool execution
- Privacy-focused users who want local inference
- Power users who want multi-channel access (Telegram, Signal, Slack, web)

### Name

TBD — to be decided when the project is closer to shipping.

---

## 15. Implementation Phases

### Phase 1: Infrastructure Consolidation

- Migrate from PostgreSQL → SQLite + sqlite-vec
- Eliminate nginx container (FastAPI serves static files + TLS)
- Eliminate mosquitto (internal async pub/sub)
- signal-cli as managed subprocess
- Achieve 2-container architecture
- All existing tests passing

### Phase 2: Persistent Memory

- Implement workspace module (SQLite-backed filesystem API)
- RRF hybrid search (FTS5 + sqlite-vec)
- Embedding provider (OpenAI or local model)
- Cross-session context for CaMeL pipeline
- Memory tools for the agent

### Phase 3: Multi-Channel Access

- WebSocket support in FastAPI
- SSE streaming
- Telegram channel (python-telegram-bot or aiogram)
- Channel manager with unified message routing
- Signal integration via signal-cli subprocess

### Phase 4: Tool Ecosystem

- MCP client (Python mcp library)
- Tool registry and discovery
- Lightweight tool sandboxing (bubblewrap/nsjail)
- AI-assisted tool building (Qwen or Claude generates tool code → scan pipeline → approval → register)
- Self-repair pipeline (detect failures → regenerate → revalidate)

### Phase 5: Routine Engine

- Cron scheduling (APScheduler or custom)
- Event-triggered routines (regex matching on messages)
- Webhook triggers
- Persistent routine state in workspace
- Guardrails (cooldown, max concurrent, global capacity)

### Phase 6: Hardening & Open Source

- Security audit of new features
- Documentation (README, architecture guide, getting started)
- Containerfile + podman-compose.yaml
- GitHub Actions CI (tests, linting)
- Apache-2.0 or MIT license
- Credit IronClaw in docs

### Phase 7 (v2): Rust WASM Sidecar

- Rust binary with Wasmtime for WASM tool execution
- Communication with Sentinel via Unix socket
- Credential injection at host boundary
- WASM tool building pipeline
- Port selected IronClaw patterns to Rust sidecar

---

## 16. Open Questions

1. **Project name** — what to call the combined product?
2. **License choice** — Apache-2.0 (matches IronClaw) or MIT (matches Sentinel/repo-scout)?
3. **Embedding provider** — use OpenAI embeddings (requires API key) or local embeddings (e.g., sentence-transformers via Ollama)?
4. **Safe vs dangerous operation classification** — how to determine the boundary? Static rules? LLM-classified? Both?
5. **Slack/Telegram channels** — build custom or use existing Python libraries?
6. **Tool sandboxing v1** — bubblewrap, nsjail, or simple subprocess with seccomp?
7. **Multi-user support** — v1 single-user or plan for multi-user from the start?
8. **IronClaw credit** — how to appropriately credit the Apache-2.0 project (NOTICE file, README section, both)?
9. **GPU sharing** — if embedding model runs locally, it competes with Qwen for VRAM. Use CPU embeddings or time-share GPU via Ollama?
10. **Stress test results** — the v3 stress test running on Sentinel may reveal new gaps that affect this plan. Review results before finalising.

---

*Document generated during IronClaw analysis session, 2026-02-15. Source repository inspected: nearai/ironclaw (commit at time of clone). Sentinel state: Phase 5+, 562 tests passing, stress test v3 in progress.*
