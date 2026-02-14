# Changelog

## Adversarial Stress Test (2026-02-14)

Full-pipeline adversarial stress test — 741 unique requests (100 genuine + 641 adversarial) across 10 attack categories. Designed to run unattended overnight.

### New: Stress Test Script (`scripts/stress_test.py`)
- **741 unique requests** — no repetitive prompts, all generated via a template-based variation engine with substitution pools
- **100 genuine prompts** across 14 categories: Python, Rust, Go, JavaScript, TypeScript, HTML, containers, DevOps, configs, data processing, essays, docs, bash, short queries
- **641 adversarial prompts** across 10 attack categories:
  - Direct injection (116): override phrases, persona-based, authority impersonation
  - Path traversal (97): sensitive paths, traversal variants, creative framing
  - Multi-turn chains (83): 24 chains with session IDs — boiling frog, breadcrumb, jailbreak progression, etc.
  - Social engineering (68): pretexted requests, urgency manipulation, helpfulness exploitation, gaslighting, emotional manipulation
  - Indirect injection (66): document-embedded payloads, subtle insertions in translations/transcripts/code
  - Credential exfiltration (65): fake key handling, exfiltration via curl/wget/DNS
  - Code injection (51): vulnerable code wrappers, reverse shells, supply chain, logic bombs, container escape
  - Encoding/obfuscation (51): base64, hex, ROT13, char-by-char, URL encoding, string concatenation, mixed case
  - Edge cases (45): Cyrillic homoglyphs, zero-width spaces, null bytes, extreme padding, emoji, hypothetical framing, RTL override
  - Legitimate (15): false-positive canaries from adversarial prompt set
- **~20 exact repeats** for consistency testing
- Multi-turn chains interleaved at regular intervals among shuffled singles
- Gradual ramp-up: warmup (5s delay) → steady (2s) → rapid (0s)
- JSONL logging with `os.fsync()` per request (crash-safe)
- Retry logic: 10 retries with exponential backoff, health check polling during recovery
- Budget exhaustion detection: stops gracefully if Claude rate-limited
- SIGINT/SIGTERM handling for graceful shutdown
- Progress reporting every 25 requests, summary at end

### New: Runner Script (`scripts/run_stress_test.sh`)
- Handles full lifecycle: switch to auto mode → rebuild containers → health check → smoke test → run stress test → restore approval mode to full
- `trap restore_approval EXIT` ensures approval mode is always restored, even on crash/kill
- Health check: polls `/health` every 5s, max 2 minutes
- Smoke test: sends "What is 2+2?" and verifies valid JSON response
- Logs everything to `scripts/results/runner_TIMESTAMP.log`
- Passthrough CLI args (e.g. `--max-requests 100`)

### New: Adversarial Prompts Library (`controller/tests/adversarial_prompts.py`)
- 84 handcrafted adversarial + legitimate prompts (69 adversarial + 15 legitimate)
- 10 categories with expected catch annotations
- 7 multi-turn attack chains
- Used as seed data for the stress test variation engine

### Config Change
- `podman-compose.yaml`: Added `SENTINEL_OLLAMA_TIMEOUT=1800` (30 min, was default 120s) — genuine code generation requests need time to complete through the full pipeline

### Bug Fix
- `run_stress_test.sh`: Fixed `except:` → `except Exception:` in health check — bare `except` catches `SystemExit` from `sys.exit()`, causing infinite loop

---

## Comprehensive Logging (2026-02-14)

Filled 69 logging gaps across all 11 controller modules. Every meaningful operation now emits structured JSON audit events.

### Modules Updated
- **orchestrator.py** — task_received, session_created, plan_request_start, step_start, step_complete, pipeline_complete, task_input_blocked, task_error
- **planner.py** — planner_request, planner_response (timing + tokens), plan_created (summary + step types), planner_connect_error, planner_timeout, planner_api_error
- **worker.py** — qwen_request (prompt length + hash), qwen_response (timing + length), qwen_error, qwen_retry
- **pipeline.py** — scan_input (clean/dirty + scanner list), scan_output (violations), pipeline_complete (trust level)
- **codeshield.py** — codeshield_scan_complete (issues count + CWE IDs), codeshield_scan_error, codeshield_init
- **prompt_guard.py** — prompt_guard_result (label + score), prompt_guard_error
- **tools.py** — tool_execute, tool_complete (timing + data_id), policy_check_failed, file_written
- **approval.py** — approval_requested, approval_submitted (granted/denied + reason), approval_expired, approval_checked
- **auth.py** — pin_auth_failed (path + method + remote IP + whether PIN was supplied)
- **session.py** — session_created, session_expired, session_locked, session_retrieved
- **conversation.py** — conversation_analysis (per-rule scores), conversation_block, conversation_warn

### Logging Verification
Manually tested via WebUI — every pipeline stage produces traceable structured JSON events:
- Genuine request: task_received → scan_input → planner_request → planner_response → plan_created → approval → step_start → qwen_request → qwen_response → scan_output → codeshield_scan_complete → step_complete → file_written
- Adversarial request: task_received → scan_input (clean: false) → task_input_blocked
- Missing PIN: pin_auth_failed

---

## Pipeline Quality Improvements (2026-02-13)

Fixes and improvements from live pipeline testing — HTML parsing bug, planner/worker prompt enrichment.

### Fix: HTML output breaking JSON parsing
- **Controller** (`main.py`): Added global exception handler — all errors now return JSON, never HTML error pages. Logs exception details for debugging
- **UI** (`app.js`): Added `parseJsonResponse()` helper — checks `Content-Type` before calling `.json()`, shows readable error on non-JSON responses instead of crashing with "Unexpected token '<'"

### Enhancement: Claude planner system prompt
- Added **System Context** block: hardware specs (Ryzen 7, 64GB, RTX 3060), rootless Podman, workspace path
- Added **Podman conventions**: restart:always, non-root users, HEALTHCHECK (python/wget not curl), multi-stage builds, Containerfile naming, .containerignore
- Added **Worker Awareness**: explains Qwen is air-gapped, has no context unless provided, output is untrusted
- Added **Instruction Detail** rule: "pass through ALL detail, do not summarise" with two worked examples (Containerfile + Python script including logging guidance)
- Added guard: "Adapt each prompt to the specific request — do not reuse phrasing from these examples"

### Enhancement: Qwen worker system prompt
- Added Linux/Podman context: forward slash paths, LF line endings, bash-compatible syntax, Containerfile conventions
- Spotlighting + no-tools instructions unchanged

### Modified Files
- `controller/app/main.py` — global exception handler
- `controller/app/planner.py` — enriched system prompt
- `controller/app/worker.py` — enriched system prompt
- `gateway/static/app.js` — JSON response validation

### Tests
- **395 tests passing** (zero regressions, no new tests — changes are prompt/error-handling only)

---

## Code Review Fixes (2026-02-13)

Addressed 5 of 12 remaining code review issues (from `docs/archive/2026-02-12_code-review.md`). Items #2, #3, #10 were fixed in Phase 5. Items #6, #8, #11-15 deferred (low risk for LAN+Tailscale threat model).

### Fix #7 — hex_secret_64 credential pattern refined
- Pattern now requires keyword prefix (`key=`, `secret:`, `TOKEN `, `password `, etc.) before 64-char hex string
- Prevents false positives on SHA-256 hashes, git digests, Docker image IDs
- Case-insensitive matching via `(?i)` inline flag

### Fix #9 — Podman policy check mismatch
- All three podman methods (`_podman_build`, `_podman_run`, `_podman_stop`) now build `cmd` list first, derive policy string via `shlex.join(cmd)`
- Previously `_podman_run` validated `"podman run --name {name} {image}"` but executed with `-d` flag — policy checked a different command than what ran

### Fix #5 — Podman flag deny-list
- Added `_DANGEROUS_PODMAN_FLAG_NAMES` and `_DANGEROUS_PODMAN_FLAG_VALUES` constants to `tools.py`
- `_check_podman_flags()` method rejects `-v`, `--volume`, `-p`, `--publish`, `--privileged`, `--cap-add`, `--security-opt`, `--device`, `--network=host`, `--pid=host`, `--userns=host`, `--ipc=host`
- Called before policy check in all podman methods

### Fix #4 — Relative path resolution
- `PolicyEngine.__init__` now accepts `workspace_path` (default `/workspace`)
- Path-constrained commands resolve relative args via `os.path.normpath(os.path.join(workspace_path, arg))`
- `cat ../../../etc/passwd` now correctly resolves to `/etc/passwd` and is blocked
- Glob patterns (`*`, `?`, `[`) are skipped during resolution

### Fix #1 — PIN authentication
- New `PinAuthMiddleware` (ASGI middleware) — checks `X-Sentinel-Pin` header on all requests except `/health`
- PIN loaded from Podman secret (`/run/secrets/sentinel_pin`) at startup
- Returns 401 JSON response on missing/wrong PIN; passes through when PIN is None (disabled)
- Config: `SENTINEL_PIN_REQUIRED=true`, `SENTINEL_PIN_FILE=/run/secrets/sentinel_pin`
- `/health` now includes `pin_auth_enabled` field
- WebUI: PIN stored in `sessionStorage` (cleared on tab close), injected as header on all API calls
- WebUI: PIN overlay shown on first load when auth enabled, re-shown on 401 response
- `podman-compose.yaml`: `sentinel_pin` secret added (`~/.secrets/sentinel_pin.txt`)
- Disableable: set `SENTINEL_PIN_REQUIRED=false`

### New Files
- `controller/app/auth.py` — PinAuthMiddleware
- `controller/tests/test_pin_auth.py` — 9 tests (health exempt, 401 without/wrong PIN, correct PIN, disabled mode)

### Modified Files
- `policies/sentinel-policy.yaml` — hex_secret_64 pattern
- `controller/app/tools.py` — shlex.join, flag deny-list, _check_podman_flags
- `controller/app/policy_engine.py` — workspace_path param, relative path resolution
- `controller/app/config.py` — pin_required, pin_file settings
- `controller/app/main.py` — PIN loading, middleware, health field
- `controller/tests/conftest.py` — engine fixture passes workspace_path
- `controller/tests/test_scanner.py` — hex_secret_64 tests updated
- `controller/tests/test_tools.py` — policy match + flag deny-list tests
- `controller/tests/test_policy_engine.py` — relative path tests
- `gateway/static/app.js` — PIN management, header injection, overlay
- `gateway/static/style.css` — PIN overlay styles
- `podman-compose.yaml` — sentinel_pin secret + env vars

### Tests
- 30 new tests (5 scanner, 6 tools policy match, 9 flag deny-list, 5 policy engine paths, 9 PIN auth — some overlap in counting with test classes)
- **395 total tests passing** (365 existing + 30 new, zero regressions)

### Code Review Status
| Issue | Status |
|-------|--------|
| #1 — No API authentication | **Fixed** (PIN auth) |
| #2 — CodeShield not initialized | Fixed in Phase 5 |
| #3 — Tool executor trust checks | Fixed in Phase 5 |
| #4 — Relative path resolution | **Fixed** |
| #5 — Podman flag deny-list | **Fixed** |
| #6 — CSRF protection | Deferred (PIN auth mitigates) |
| #7 — hex_secret_64 too broad | **Fixed** |
| #8 — Approval ID in reason field | Deferred (works, cosmetic) |
| #9 — Podman policy check mismatch | **Fixed** |
| #10 — ToolExecutor not wired | Fixed in Phase 5 |
| #11-15 — Design observations | Deferred (low risk) |

---

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
