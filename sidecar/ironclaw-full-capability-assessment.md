# IronClaw Full Capability Assessment

**Date:** 2026-02-17
**Codebase assessed:** `nearai/ironclaw` (commit from `~/tmp/ironclaw`, cloned 2025-02-15)
**Assessor:** Claude Opus 4.6 research agent
**Scope:** What could IronClaw do when connected to a frontier-level AI model?

---

## 1. Executive Summary

IronClaw is a Rust-based personal AI assistant framework by NEAR AI. It is designed as a **self-expanding, always-on agent** that can communicate across multiple channels, execute code in sandboxed environments, build its own new tools at runtime, and run autonomous background tasks on schedules. When connected to a frontier AI model, the system provides a near-complete personal computing assistant with remarkably few hard limitations.

The key architectural insight is the **layered capability model**: built-in tools handle filesystem, shell, HTTP, and memory; WASM sandboxed tools handle third-party integrations (Gmail, Calendar, Slack, Telegram); Docker containers provide full development environments; and the LLM-driven tool builder can create new WASM tools on the fly. This means IronClaw's capability ceiling is not fixed — it can extend itself.

---

## 2. Communication Capabilities

### 2.1 Currently Implemented Channels

| Channel | Protocol | Status | Entry Point |
|---------|----------|--------|-------------|
| **REPL** | stdin/stdout | Working | `src/channels/repl.rs` |
| **Web Gateway** | HTTP + SSE + WebSocket | Working | `src/channels/web/server.rs` |
| **Telegram** | MTProto over HTTPS (WASM) | Working | `channels-src/telegram/` |
| **Slack** | WASM tool via API | Working | `channels-src/slack/` + `tools-src/slack/` |
| **HTTP Webhook** | Inbound HTTP POST | Working | `src/channels/webhook_server.rs` |

**Why these work:** Each channel is a WASM component implementing the `sandboxed-channel` world defined in `wit/channel.wit`. Channels have four callbacks: `on-http-request`, `on-poll`, `on-respond`, and `on-status`. The host manages the event loop, so channels don't need long-running processes — they're invoked per-event.

### 2.2 Planned/Stubbed Channels

| Channel | Priority | Source |
|---------|----------|--------|
| **WhatsApp** | P1 | `channels-src/whatsapp/` (directory exists, Cloud API planned) |
| **Discord** | P2 | Listed in `FEATURE_PARITY.md` |
| **Signal** | P2 | Listed in `FEATURE_PARITY.md` |
| **iMessage** | P3 | Via BlueBubbles |
| **Matrix** | P3 | With E2EE support |
| **MS Teams, Google Chat, Twitch, Nostr** | P3 | All listed |
| **Voice Call** | P3 | Via Twilio/Telnyx |

**Why new channels are feasible:** The WASM channel interface (`wit/channel.wit`) is generic — any messaging platform that supports either webhooks or HTTP polling can be wrapped in a WASM component. The host handles HTTP routing, secret injection, and message delivery. A frontier model could potentially build new channel adapters at runtime using the tool builder system.

### 2.3 Proactive Communication

IronClaw can **send messages unprompted** via:
- **Cron routines** (`src/tools/builtin/routine.rs`): Scheduled tasks that fire on cron expressions (e.g., "every weekday at 9am"). These can trigger full agent jobs that produce output sent through any connected channel.
- **Event routines**: Regex-matched patterns on incoming messages trigger background jobs.
- **Webhook routines**: External systems trigger actions via HTTP POST.
- **Heartbeat system**: Periodic background execution for monitoring/maintenance (referenced in `FEATURE_PARITY.md` and workspace `HEARTBEAT.md`).

**Example:** A routine could be set up with `trigger_type: "cron"`, `schedule: "0 9 * * MON-FRI"`, and `prompt: "Check my calendar for today and send a Telegram summary"`. The routine engine fires the cron, the agent executes with full tool access, and the response routes through Telegram.

**Security constraint:** Routines use the same approval model as interactive sessions. A `full_job` routine has multi-turn tool access with a maximum of 10 iterations (`routine.rs:199`).

---

## 3. File & Filesystem Operations

### 3.1 Local Filesystem

| Tool | Capability | Approval | Entry Point |
|------|-----------|----------|-------------|
| `read_file` | Read any local file (up to 1MB) | Required | `src/tools/builtin/file.rs:169` |
| `write_file` | Write files (up to 5MB), auto-creates dirs | Required | `src/tools/builtin/file.rs:295` |
| `apply_patch` | Search/replace edits in existing files | Required | `src/tools/builtin/file.rs:603` |
| `list_dir` | Directory listing with recursive option | Required | `src/tools/builtin/file.rs:406` |

**Path sandboxing:** When `base_dir` is set, all paths are validated to prevent traversal attacks. The validation resolves symlinks and `..` components, then checks the canonical path stays within the sandbox (`file.rs:83-149`). Path traversal via non-existent parent directories is specifically handled.

**Workspace file protection:** The `write_file` tool rejects writes to workspace identity files (`HEARTBEAT.md`, `MEMORY.md`, `IDENTITY.md`, `SOUL.md`, `AGENTS.md`, `USER.md`, `README.md`) — these must go through `memory_write` instead, which stores them in PostgreSQL rather than on disk. This prevents prompt injection via filesystem overwrites (`file.rs:21-42`).

### 3.2 Workspace Memory (Database-Backed)

| Tool | Capability | Entry Point |
|------|-----------|-------------|
| `memory_search` | Hybrid FTS + semantic vector search across all memories | `src/tools/builtin/memory.rs:46` |
| `memory_write` | Persist facts, decisions, daily logs, heartbeat checklist | `src/tools/builtin/memory.rs:133` |
| `memory_read` | Read any workspace file by path | `src/tools/builtin/memory.rs:300` |
| `memory_tree` | View workspace structure hierarchically | `src/tools/builtin/memory.rs:358` |

**Why this matters:** The workspace gives the AI persistent memory across sessions. It uses pgvector for embeddings and full-text search (Reciprocal Rank Fusion). This means a frontier model connected to IronClaw would have long-term memory of user preferences, decisions, project context, and past conversations.

**Security constraint:** Identity files (`IDENTITY.md`, `SOUL.md`, `AGENTS.md`, `USER.md`) are protected from tool writes — they can only be edited by the user directly. This prevents prompt injection from poisoning the system prompt (`memory.rs:26-27`).

---

## 4. Shell & Code Execution

### 4.1 Direct Shell Execution

The `shell` tool (`src/tools/builtin/shell.rs`) provides arbitrary command execution:

- **Execution modes:** Docker sandbox (when enabled) or direct host execution (fallback)
- **Timeout:** Default 120 seconds, configurable per invocation
- **Output capture:** stdout + stderr, truncated at 64KB
- **Approval model:** Always requires user approval (`requires_approval: true`)

**Blocked commands** (hard blocklist, `shell.rs:42-56`):
- `rm -rf /`, fork bombs, `dd if=/dev/zero`, `mkfs`, `curl | sh`, `wget | bash`

**Dangerous patterns** (blocked unless `allow_dangerous` is true, `shell.rs:59-74`):
- `sudo`, `eval`, `$(curl`, `/etc/passwd`, `~/.ssh`, `id_rsa`

**Never auto-approve patterns** (always require per-invocation approval even with blanket approval, `shell.rs:80-116`):
- `rm -rf`, `chmod 777`, `shutdown`, `reboot`, `iptables`, `useradd`, `crontab`, `docker rm`, `git push --force`, `DROP TABLE`

**What this means for a frontier model:** With approval, IronClaw can: compile software, run tests, manage git repos, install packages, run scripts in any language, manage services, interact with databases via CLI, and essentially do anything a developer can do in a terminal.

**Security constraint:** When Docker sandbox is configured and enabled, the code is fail-closed — it will not silently fall through to unsandboxed execution (`shell.rs:346-352`). The sandbox routes all network traffic through a validating proxy.

### 4.2 Docker Sandbox Execution

The orchestrator (`src/orchestrator/`) manages containerised job execution:

| Component | Purpose | Entry Point |
|-----------|---------|-------------|
| `ContainerJobManager` | Create/monitor/stop containers | `src/orchestrator/job_manager.rs` |
| `OrchestratorApi` | Internal HTTP API for worker communication | `src/orchestrator/api.rs` |
| `TokenStore` | Per-job bearer tokens (in-memory) | `src/orchestrator/auth.rs` |

**Worker containers** get:
- Shell, file read/write, list_dir, and apply_patch tools
- LLM access via the orchestrator proxy (the worker calls back to the host for completions)
- A persistent project directory at `~/.ironclaw/projects/{job_id}/` (bind-mounted, survives container teardown)
- Per-job auth token (never shared between jobs)

**Two execution modes** (`job.rs:477-479`):
- `worker` — IronClaw's own sub-agent with limited tools
- `claude_code` — Claude Code CLI for full agentic software engineering

**Container security** (`src/sandbox/mod.rs:78-86`):
- No credentials in containers (injected by proxy at network boundary)
- All traffic routes through validating proxy (domain allowlist)
- Non-root execution (UID 1000)
- Read-only root filesystem (except workspace mount)
- All Linux capabilities dropped
- Auto-cleanup on exit

**What this means for a frontier model:** IronClaw can spin up isolated development environments, build software projects, run full test suites, and produce artifacts — all inside containers where mistakes are contained. The 10-minute timeout (`job.rs:208`) and project directory persistence mean iterative development workflows are supported.

---

## 5. Internet & API Access

### 5.1 Built-in HTTP Tool

The `http` tool (`src/tools/builtin/http.rs`) provides direct HTTPS requests:

- **Methods:** GET, POST, PUT, DELETE, PATCH
- **HTTPS only** — plain HTTP is rejected (`http.rs:39-43`)
- **SSRF protection:**
  - Localhost blocked (`http.rs:50-53`)
  - Private IPs blocked (RFC 1918, link-local, cloud metadata 169.254.169.254) (`http.rs:84-101`)
  - DNS rebinding protection — resolves hostnames and checks all IPs (`http.rs:68-79`)
  - Redirects blocked entirely to prevent SSRF chains (`http.rs:220-225`)
- **Leak detection:** Outbound requests are scanned for secret exfiltration (`http.rs:203-206`)
- **Response size limit:** 5MB (`http.rs:15`)
- **Requires user approval**

### 5.2 WASM Tool HTTP (Sandboxed)

WASM tools have a more restricted HTTP interface (`wit/tool.wit:56-80`):
- Only **allowlisted endpoints** (host/path patterns defined in tool capabilities)
- Credentials **injected by host** — WASM code never sees API keys
- Request and response scanned for secret leakage
- Rate-limited per tool
- Timeout capped at callback timeout

### 5.3 Sandbox Network Proxy

Docker sandbox containers route all traffic through `src/sandbox/proxy/`:
- **Domain allowlist** (`proxy/allowlist.rs`) — only approved hosts reachable
- **Credential injection** at proxy boundary
- **Request/response logging** for audit trail

**What this means for a frontier model:** The system can interact with any public HTTPS API (GitHub, cloud providers, SaaS platforms, REST APIs) via the built-in HTTP tool. For WASM tools, access is more restricted but still covers the configured integrations. The security layers prevent the model from using HTTP access to exfiltrate data or attack internal services.

---

## 6. Email Management

### 6.1 Gmail Tool (WASM)

Source: `tools-src/gmail/src/` (contains `api.rs`, `lib.rs`, `types.rs`)
Status: Implemented per `tools-src/TOOLS.md`

**Capabilities:**
- Search emails
- Read email content
- Send emails
- Create drafts
- Reply to emails

**Authentication:** Uses `google_oauth_token` — the OAuth token is stored in IronClaw's encrypted secrets store and injected at the WASM boundary. The WASM code can check if the secret exists (`secret-exists`) but can never read its value.

**What this means for a frontier model:** Full email management. The model could read incoming emails, draft responses, send emails on the user's behalf, search for specific messages, and manage drafts. Combined with cron routines, it could implement email triage, auto-responses, or daily email summaries.

**Security constraint:** The WASM sandbox prevents the Gmail tool from accessing any endpoint except Google's APIs (allowlist). Credentials are injected by the host — even if the WASM code is compromised, it can't exfiltrate the OAuth token.

---

## 7. Calendar Management

### 7.1 Google Calendar Tool (WASM)

Source: `tools-src/google-calendar/src/` (contains `api.rs`, `lib.rs`, `types.rs`)
Status: Implemented per `tools-src/TOOLS.md`

**Capabilities:**
- List events
- Create events
- Update events
- Delete events

**What this means for a frontier model:** Full calendar management. Schedule meetings, check availability, modify events, set reminders. Combined with communication channels, the model could coordinate meetings by checking calendar availability and sending invites through email or messaging.

---

## 8. Document & Spreadsheet Management

### 8.1 Google Drive (WASM)
Source: `tools-src/google-drive/src/`

**Capabilities:** Search, access, upload, share files. Supports both org and personal drives.

### 8.2 Google Sheets (WASM)
Source: `tools-src/google-sheets/src/`

**Capabilities:** Create spreadsheets, read/write/append values, manage sheets, format cells.

### 8.3 Google Docs (WASM)
Source: `tools-src/google-docs/src/`

**Capabilities:** Create, read, edit documents. Text formatting, paragraphs, tables, lists.

### 8.4 Google Slides (WASM)
Source: `tools-src/google-slides/src/`

**Capabilities:** Create, read, edit presentations. Shapes, images, text formatting, thumbnails, templates.

**What this means for a frontier model:** Full G Suite productivity. Create reports in Docs, analyse data in Sheets, build presentations in Slides, organise files in Drive. A routine could, for example, pull data from an API every morning, update a spreadsheet, and generate a summary document.

---

## 9. Programme/Software Creation & Management

### 9.1 LLM-Driven Software Builder

Source: `src/tools/builder/core.rs`
This is IronClaw's **self-expanding capability** — the ability to create new software on demand.

**Build loop:**
1. Analyse requirement → determine project type, language, structure
2. Generate scaffold → create initial project files
3. Implement code → write the actual implementation
4. Build/compile → run build commands (cargo, npm, etc.)
5. Fix errors → parse errors, modify code, retry
6. Test → run tests, fix failures
7. Validate → for WASM tools, verify interface compliance
8. Package → produce final artifact

**Software types supported** (`core.rs:74`):
- `WasmTool` — new tools for the agent itself
- `CliBinary` — standalone command-line applications
- `Library` — reusable code libraries

**Languages supported:** Rust (for WASM tools), plus whatever the build system supports (via shell tool in Docker containers).

**What this means for a frontier model:** When asked to do something IronClaw can't currently do, the model can **build a new tool** for it. Need to parse PDFs? Build a WASM tool. Need to interact with a custom API? Build a tool. Need a one-off data processing script? Build a CLI binary. The tool builder validates the output and registers it with the tool registry, making it immediately available.

**Security constraint:** New WASM tools are validated against the tool interface (`src/tools/builder/validation.rs`) and run in the same sandbox as other WASM tools — capability-based permissions, endpoint allowlisting, credential injection. A malicious tool can't escape the sandbox.

### 9.2 Docker-Based Development

Via the `create_job` tool (`src/tools/builtin/job.rs`), the model can spin up full development environments:

- **Project isolation:** Each job gets a unique directory under `~/.ironclaw/projects/`
- **Persistent workspace:** The project directory is bind-mounted and survives container teardown
- **Two modes:** IronClaw sub-agent or Claude Code CLI
- **Background execution:** `wait=false` starts the container and returns immediately, allowing concurrent work

**What this means:** Full software engineering. Create a new project, write code, build, test, iterate — all in an isolated container. The model can work on multiple projects concurrently with `wait=false`.

### 9.3 Tool Extension Management

| Tool | Purpose |
|------|---------|
| `tool_install` | Install new WASM tools from files |
| `tool_list` | List installed tools |
| `tool_remove` | Remove installed tools |
| `tool_search` | Search for available tools |
| `tool_activate` | Enable/disable tools |
| `tool_auth` | Configure tool authentication |

Source: `src/tools/builtin/extension_tools.rs`

**What this means:** The model can manage its own toolbox — installing new capabilities, removing unused ones, and configuring authentication for tool integrations.

---

## 10. Container Management

### 10.1 Docker Integration

IronClaw uses the `bollard` crate (`Cargo.toml:115`) — a pure Rust Docker API client. This provides:

- Container creation, monitoring, and lifecycle management
- Image management
- Volume and network operations

**Currently used for:** Sandbox execution of shell commands and development jobs.

**What a frontier model could do:** Beyond the current sandbox use, the Docker API client could be extended (or a new WASM tool built) to manage arbitrary containers — spin up databases, web servers, development environments, CI/CD pipelines, or any dockerised service.

**Security constraint:** The current codebase uses Docker for sandboxing with strict policies. Container creation goes through `ContainerJobManager` which enforces project directory isolation, per-job tokens, and cleanup. The model can't directly call the Docker API — it goes through the orchestrator.

**Podman note:** The `bollard` crate supports Docker-compatible APIs. Since Podman provides a Docker-compatible socket, IronClaw should work with Podman with minimal configuration changes (set `DOCKER_HOST` to the Podman socket).

### 10.2 Web Hosting

The built-in web gateway (`src/channels/web/server.rs`) already serves:
- A full dashboard UI (chat, memory, jobs, logs, extensions, routines)
- An OpenAI-compatible API at `/v1/chat/completions`
- SSE and WebSocket streaming
- Bearer token authentication

**What this means:** IronClaw already hosts a web interface. A frontier model could use the file tools and shell to create and serve HTML/CSS/JS content, or use the `create_job` tool to spin up a containerised web server for more complex sites.

---

## 11. Autonomous Behaviour & Scheduling

### 11.1 Routines Engine

Source: `src/agent/routine_engine.rs` (referenced in `src/tools/builtin/routine.rs`)

| Trigger Type | Description | Use Case |
|-------------|-------------|----------|
| `cron` | Standard cron expressions (6-field: sec min hour day month weekday) | "Every weekday at 9am" |
| `event` | Regex pattern match on incoming messages | "When someone mentions 'urgent'" |
| `webhook` | External HTTP POST triggers | CI/CD callbacks, IoT events |
| `manual` | Explicitly triggered | On-demand tasks |

**Execution modes:**
- `lightweight` — single LLM call, 4096 max tokens, loads context paths from workspace
- `full_job` — multi-turn agent loop with full tool access, max 10 iterations

**Guardrails:** Cooldown period (default 300s), max concurrent executions, dedup window.

### 11.2 Heartbeat System

Referenced throughout as a periodic background execution mechanism for monitoring and maintenance. Uses `HEARTBEAT.md` in the workspace as a checklist that the agent reviews and acts on periodically.

**What this means for a frontier model:** True autonomous operation. The model can:
- Monitor external services and alert on failures
- Perform daily data collection and reporting
- Triage incoming messages and route them appropriately
- Maintain long-running projects with scheduled check-ins
- Self-monitor its own health and performance

---

## 12. Security Architecture & Capability Boundaries

### 12.1 Defence in Depth

| Layer | Mechanism | What It Protects Against |
|-------|-----------|------------------------|
| **WASM Sandbox** | Capability-based permissions, wasmtime isolation | Malicious/buggy tools |
| **Endpoint Allowlist** | Per-tool HTTP host/path patterns | Data exfiltration, SSRF |
| **Credential Injection** | Secrets never exposed to WASM/containers; injected at proxy | Token theft |
| **Leak Detection** | Scans HTTP requests/responses for secret patterns | Exfiltration via tool output |
| **Prompt Injection Defence** | Pattern detection, content sanitisation, policy enforcement | Hostile input manipulation |
| **Docker Sandbox** | Ephemeral containers, read-only root, non-root user, capability dropping | Shell command escape |
| **Path Traversal Prevention** | Canonical path validation, symlink resolution | Filesystem escape |
| **Blocked Commands** | Hardcoded blocklist + dangerous patterns | Destructive shell commands |
| **Tool Approval** | Per-invocation user approval for sensitive tools | Unauthorised actions |
| **Identity File Protection** | System prompt files read-only from tool access | Prompt poisoning |
| **Rate Limiting** | Per-tool request limits | Abuse/runaway loops |

### 12.2 What the Security Model Prevents

- **A compromised WASM tool cannot:** read secrets, access unapproved endpoints, write outside its namespace, invoke unapproved tools, or escape the sandbox.
- **A Docker container cannot:** access the host network directly (proxied), read secrets from environment (not injected), write outside the workspace mount, or persist beyond the job lifecycle.
- **The LLM cannot:** overwrite identity/system-prompt files, execute blocked shell patterns without approval, access localhost/private IPs via HTTP, or bypass the approval system for destructive operations.

### 12.3 What the Security Model Allows (with Approval)

- Reading/writing any file on the host filesystem (when not sandboxed)
- Executing arbitrary shell commands (with blocked pattern exceptions)
- Making HTTPS requests to any public endpoint
- Sending emails, messages, calendar invites on the user's behalf
- Creating and deploying new WASM tools
- Spinning up Docker containers

---

## 13. Capabilities NOT Currently Present (but Architecturally Feasible)

These capabilities don't exist in the current codebase but could be built using the existing infrastructure (tool builder, WASM sandbox, Docker containers):

| Capability | How It Could Be Built | Difficulty |
|-----------|----------------------|------------|
| **Browser automation** | Build a WASM tool wrapping a headless browser API, or use shell tool with puppeteer in a Docker container | Medium |
| **PDF processing** | Build a WASM tool using a PDF parsing library | Low |
| **Image generation** | WASM tool calling DALL-E/Stable Diffusion APIs | Low |
| **Audio transcription** | WASM tool calling Whisper API | Low |
| **Database management** | The PostgreSQL connection is already present; SQL tools could be added | Low |
| **SSH access** | Shell tool with ssh client, or a dedicated WASM tool | Medium (security implications) |
| **IoT/smart home** | WASM tools wrapping Home Assistant, MQTT, or device APIs | Medium |
| **Financial tracking** | WASM tools for banking APIs + Sheets integration | Medium |
| **Code review** | Already feasible with file tools + LLM reasoning | Already possible |
| **Uber/transport** | Listed in `TOOLS.md` as planned | Medium |
| **Google Cloud management** | Listed in `TOOLS.md` as planned — spin up/configure/shut down instances | Medium |

---

## 14. Multi-Provider LLM Support

IronClaw uses `rig-core` (`Cargo.toml:112`) for multi-provider LLM support:

| Provider | Status | Notes |
|----------|--------|-------|
| NEAR AI | Primary | Session-based auth, default provider |
| Anthropic (Claude) | Partial | Via NEAR AI proxy |
| OpenAI | Partial | Via NEAR AI proxy |
| AWS Bedrock | Planned | |
| Google Gemini | Planned | |
| Ollama (local) | Planned | Local model support |

The `FailoverProvider` (`src/llm/failover.rs`) tries providers sequentially on retryable errors, so the system can automatically fall back to alternative models if the primary is unavailable.

**What this means:** A frontier model from any supported provider could power IronClaw. The multi-provider architecture means the user isn't locked into one vendor.

---

## 15. Summary: What a Frontier Model + IronClaw Can Do

### Direct Capabilities (Built-in)
- Read, write, edit, and navigate files on the host filesystem
- Execute arbitrary shell commands (with safety guardrails + approval)
- Make HTTPS requests to any public API
- Search and manage persistent memory across sessions
- Create and manage scheduled/reactive background tasks
- Spin up Docker development environments
- Build new software (tools, CLIs, libraries) using LLM-driven code generation
- Manage installed tools and extensions

### Integration Capabilities (WASM Tools)
- Send/read/search/draft emails (Gmail)
- Manage calendar events (Google Calendar)
- Create/edit documents, spreadsheets, and presentations (Google Docs/Sheets/Slides)
- Manage files in cloud storage (Google Drive)
- Send and receive messages via Telegram and Slack
- Authenticate via Okta

### Communication Capabilities (Channels)
- Interactive CLI/TUI with approval overlays
- Web dashboard with real-time streaming
- Telegram bot with DM pairing
- Slack integration
- HTTP webhooks for external system integration
- Proactive messaging via routines (not just request-response)

### Self-Expansion Capabilities
- Build new WASM tools to add capabilities the system doesn't currently have
- Install, configure, and manage tools at runtime
- Create containerised development environments for complex builds
- Iterate on builds with compile-test-fix loops

### Autonomous Capabilities
- Cron-scheduled background tasks
- Event-driven reactive tasks
- Webhook-triggered automation
- Heartbeat monitoring and self-repair
- Persistent memory and context across sessions

The fundamental design principle is that **the security model constrains HOW things happen (sandboxed, approved, allowlisted) but not WHAT can happen**. With user approval and the right WASM tools installed, IronClaw connected to a frontier model is essentially a general-purpose personal computing agent.
