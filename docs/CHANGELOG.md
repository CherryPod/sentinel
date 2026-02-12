# Changelog

## Phase 3 — Claude Planner + Full CaMeL Pipeline (2026-02-12)

The core CaMeL loop is complete: User requests flow through Claude (planning), Qwen (text generation), policy-enforced tools, and multi-layer security scanning.

### Phase 3a: Core Loop
- `ClaudePlanner` — async Anthropic client, JSON plan generation with variable reference validation, retry on transient errors
- `Orchestrator` — sequential step execution with `ExecutionContext` for `$variable` substitution across steps
- Data models: `PlanStep`, `Plan`, `StepResult`, `TaskResult`
- `POST /task` endpoint — full pipeline entry point
- Config: `claude_model` (default Sonnet 4.5), `claude_max_tokens`, `claude_timeout`

### Phase 3b: Tool Executor + CodeShield
- `ToolExecutor` — 7 tools (`file_write`, `file_read`, `mkdir`, `shell`, `podman_build`, `podman_run`, `podman_stop`), every operation policy-checked via `PolicyEngine`
- `CodeShield` — LlamaFirewall wrapper for static analysis of generated code, graceful degradation when not installed

### Phase 3c: HTTP Approval Flow
- `ApprovalManager` — in-memory queue with 5-minute TTL, create/check/submit/expire
- `GET /approval/{id}`, `POST /approve/{id}` endpoints
- Full flow: task → `awaiting_approval` → approve → execute → result

### Infrastructure
- `restart: always` on both containers (survives monthly reboots)
- Claude API key via Podman secrets (`~/.secrets/claude_api_key.txt` → `/run/secrets/claude_api_key`)
- Markdown code fence stripping in planner (Claude wraps JSON despite instructions)

### Tests
- 66 new tests (14 planner, 18 orchestrator, 12 tools, 10 codeshield, 12 approval)
- **259 total tests passing** (locally + in container)

---

## Phase 2 — Qwen Worker + Scan Pipeline (2026-02-09)

Air-gapped local LLM integration with full security scanning pipeline.

- `OllamaWorker` — async Qwen client with retry logic
- `ScanPipeline` — scan_input → spotlight → Qwen → scan_output
- `Spotlighting` — `^`-prefix datamarking (~50% → <3% injection success)
- `Prompt Guard 2` — 86M BERT classifier, lazy-load, chunked scanning
- `sentinel-qwen` container — air-gapped on `sentinel_internal` only, GPU via CDI
- 70 new tests including hostile Qwen output simulations
- **193 total tests passing**

---

## Phase 1 — Controller + Policy Engine (2026-02-08)

Deterministic security foundation — no LLM dependencies.

- `PolicyEngine` — YAML-driven file path and command validation
- Path traversal detection (URL encoding, null bytes, symlinks)
- `CredentialScanner` — 12 regex patterns (AWS, API keys, tokens, URIs, certs)
- `SensitivePathScanner` — block references to `/etc/shadow`, `.ssh/`, `.env`, etc.
- Provenance tracking with trust inheritance
- Structured JSON audit logging (daily rotation)
- `sentinel-controller` container on `sentinel_internal` + `sentinel_egress`
- **123 tests passing**
