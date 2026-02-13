# Changelog

## Multi-Turn Conversation Tracking (2026-02-13)

Deterministic multi-turn attack detection — closes the "Moltbook-style" memory poisoning gap identified during red teaming.

### New: ConversationAnalyzer (6 heuristic rules)
- **retry_after_block** — detects rephrased retries of previously blocked requests (SequenceMatcher similarity >0.6)
- **escalation** — capability tier tracking (observe→read→write→execute→persist→exfiltrate), flags 2+ tier jumps or reaching persist/exfiltrate
- **sensitive_topic_acceleration** — first mention of sensitive topics after N benign turns
- **instruction_override** — "from now on", "ignore instructions", "jailbreak", DAN, role reassignment patterns
- **violation_accumulation** — cumulative penalty (1.5/block) for prior security violations in session
- **context_building** — context-reference phrases ("as I mentioned") combined with sensitive content or escalation language

### New: SessionStore
- In-memory session store with 1hr TTL, max 1000 sessions, thread-safe
- Sessions track turns, cumulative risk, violation count, lock status
- Locked sessions get immediate rejection on all subsequent requests
- Ephemeral sessions for requests without `session_id` (backward compatible)

### Scoring
- Each rule scores 0.0–5.0 (capped). Single rule at max can only WARN, never BLOCK
- Thresholds: <5.0 = ALLOW, 5.0–9.9 = WARN (process but flag), 10.0+ = BLOCK (refuse + lock session)
- Risk accumulates within a session, never decreases (prevents gaming by alternating benign/malicious)
- First message always returns ALLOW (no history; single-turn scanners still protect)

### API Changes
- `POST /task` now accepts optional `session_id` field — without it, each request gets an ephemeral session
- `TaskResult` includes `conversation` field: session_id, turn_number, risk_score, action, warnings
- `GET /session/{id}` debug endpoint — view session state and turn history
- `/health` response includes `conversation_tracking` field

### WebUI
- Per-tab session ID via `crypto.randomUUID()` stored in `sessionStorage` (cleared on tab close)
- Conversation warnings displayed in chat when returned by controller
- Session reset on history clear (Shift+click)

### Config
- `SENTINEL_CONVERSATION_ENABLED=true` — kill switch to revert to fully stateless behavior
- `SENTINEL_SESSION_TTL=3600`, `SENTINEL_SESSION_MAX_COUNT=1000`
- `SENTINEL_CONVERSATION_WARN_THRESHOLD=5.0`, `SENTINEL_CONVERSATION_BLOCK_THRESHOLD=10.0`

### Tests
- 50 new tests: session store (8), retry_after_block (4), escalation (5), sensitive_topic_acceleration (4), instruction_override (6), violation_accumulation (4), context_building (4), combined scoring (5), false positive prevention (4), orchestrator integration (6)
- **365 total tests passing** (315 existing + 50 new, zero regressions)

---

## Phase 5 — Hardening + CodeShield Fix (2026-02-13)

Security hardening based on red team findings, plus fixing CodeShield to actually work.

### Hardening (4 red team gaps fixed)
- **Gap 1: CodeShield on all output** — CodeShield now scans ALL Qwen output, not just `expects_code=True` steps. Prevents surveillance scripts/malicious code in prose responses
- **Gap 2: CommandPatternScanner** — new scanner detects dangerous shell patterns (pipe-to-shell, reverse shells, base64 decode+exec, nohup, etc.) in text, not just explicit commands
- **Gap 3: Planner prompt hardening** — system prompt now contains explicit security constraints (workspace boundaries, credential prohibition, exfiltration rules, expects_code guidance)
- **Gap 4: ToolExecutor wired** — `tool_call` plan steps now execute via policy-checked ToolExecutor instead of being silently skipped

### CodeShield Fix
The `codeshield` package was installed but never worked. Two issues found and fixed:
1. **Wrong API**: Code used non-existent `llamafirewall.CodeShieldScanner`. Correct API is `codeshield.cs.CodeShield.scan_code()` (async)
2. **osemgrep bug**: Package uses `osemgrep --experimental` internally, which has a bug where `patterns` + `pattern-not` Semgrep rules return zero results. Fixed by patching `SEMGREP_COMMAND` to use regular `semgrep` at init time

> Full investigation details: `docs/archive/2026-02-13_codeshield-fix.md`

### Other
- Llama Guard 4 deliberately skipped (content moderation, not our threat model)
- `codeshield_loaded` added to `/health` endpoint
- CodeShield initialization with timing logged at startup
- Regression test suite: `controller/tests/test_hardening.py`
- **315 total tests passing** (123 Phase 1 + 70 Phase 2 + 66 Phase 3 + 56 Phase 5)

---

## Phase 4a — WebUI + Security Testing (2026-02-12)

### WebUI
Browser-based chat interface for the full CaMeL pipeline. No controller changes required.

- `sentinel-ui` container — nginx:alpine, serves static files + reverse-proxies `/api/*` to controller
- Single-page chat UI — vanilla HTML/JS/CSS, dark theme, no frameworks
- Full approval flow in browser: send task → view plan → approve/deny → see step results
- localStorage conversation history (last 100 entries, Shift+click header to clear)
- Health indicator in header — polls `/api/health` every 30s
- nginx proxy: 300s read timeout (accommodates LLM processing time)
- Port 3001:8080 on `sentinel_egress` network
- **259 tests still passing** (no controller changes)

### Security Testing (Red Team)
Ran adapted OpenClaw 19-test injection suite against the full CaMeL pipeline.

- **Result: 18/19 passed (95%)** — up from 26% on raw OpenClaw + Qwen
- Prompt Guard caught 6 attacks at input scan stage
- Claude planner refused 3 attacks at planning stage
- Output scanners blocked 3 attacks in Qwen's responses
- CaMeL architectural separation prevented 3 attacks structurally
- One failure: test 5.4 (surveillance script) — Qwen wrote full malicious script, CodeShield not invoked because Claude didn't set `expects_code: true`
- Category 3 (indirect injection via files) passed incidentally — file tools not yet operational, so injected payloads never reached Qwen. Needs re-testing when tools are wired up
- 5 security gaps identified with suggested fixes (see full report)
- Full report: `docs/archive/2026-02-12_security-test-report.md`
- Audit log: `docs/archive/2026-02-12_security-test-audit.jsonl`

---

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
