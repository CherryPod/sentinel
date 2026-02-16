# Codebase Map

Developer reference for navigating the Sentinel codebase. Module responsibilities, key classes/functions, important constants, and cross-dependencies.

> This file is for Claude Code context loading and contributor onboarding. Update when modules change significantly.

---

## Source Modules (`controller/app/`)

### API & Configuration

| Module | Lines | Purpose |
|--------|-------|---------|
| `main.py` | ~200 | FastAPI app, all endpoints, CSRF middleware, request size limit, Pydantic request models with validators |
| `auth.py` | ~131 | PIN authentication ASGI middleware, per-IP lockout (5 failures / 60s), constant-time comparison |
| `config.py` | ~76 | Pydantic Settings — all config via `SENTINEL_*` env vars |
| `models.py` | ~150 | Data models: TrustLevel, DataSource, ScanResult, TaggedData, PlanStep, Plan, TaskResult, etc. |
| `audit.py` | ~52 | Structured JSON logging with daily rotation |

**Key constants:**
- `auth.py:14` — `_MAX_FAILED_ATTEMPTS = 5`, `_LOCKOUT_SECONDS = 60`
- `config.py` — all settings with defaults (approval_mode, thresholds, timeouts, etc.)

### Security Pipeline

| Module | Lines | Purpose |
|--------|-------|---------|
| `pipeline.py` | ~449 | Scan orchestration: input scan → ASCII gate → length gate → spotlighting → Qwen → output scan → echo scan |
| `scanner.py` | ~512 | Regex scanners: CredentialScanner, SensitivePathScanner, CommandPatternScanner, VulnerabilityEchoScanner, EncodingNormalizationScanner |
| `policy_engine.py` | ~288 | YAML-driven deterministic rules: file paths, commands, traversal detection, injection patterns |
| `prompt_guard.py` | ~117 | Prompt Guard 2 (86M BERT) — injection/jailbreak detection, 2000-char chunking |
| `codeshield.py` | ~136 | CodeShield/Semgrep wrapper — insecure code detection, async, fail-closed |
| `spotlighting.py` | ~33 | Per-word character prefix marking for untrusted data |
| `conversation.py` | ~493 | 8 heuristic rules for multi-turn attack detection (retry, escalation, recon, topic shift, etc.) |

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

### Execution Engine

| Module | Lines | Purpose |
|--------|-------|---------|
| `orchestrator.py` | ~350 | CaMeL execution loop: plan → approve → per-step execute → scan. Variable substitution across steps |
| `planner.py` | ~220 | Claude API client, JSON plan generation, validation, refusal detection |
| `worker.py` | ~143 | Ollama/Qwen async HTTP client, retry logic |
| `tools.py` | ~462 | Tool executor: file_write/read, mkdir, shell, podman_build/run/stop — all policy-checked |
| `approval.py` | ~192 | In-memory approval queue with 5-min TTL |

**Key constants:**
- `planner.py:12-191` — `_PLANNER_SYSTEM_PROMPT_TEMPLATE` (Claude's full instructions)
- `worker.py:12-35` — `QWEN_SYSTEM_PROMPT_TEMPLATE` (Qwen's system prompt with `{marker}` placeholder)
- `orchestrator.py` — `_FORMAT_INSTRUCTIONS`, `_CHAIN_REMINDER` (chained step safety text)
- `tools.py:14-20` — `_DANGEROUS_PODMAN_FLAG_NAMES/VALUES` (blocked flags)

**Key functions:**
- `orchestrator.handle_task()` — main entry point from `/task` endpoint
- `orchestrator.execute_approved_plan()` — runs after human approval
- `orchestrator.ExecutionContext.resolve_text_safe()` — wraps variable content with UNTRUSTED_DATA tags + markers
- `planner.ClaudePlanner.create_plan()` — calls Claude API, validates JSON response
- `tools.ToolExecutor.execute()` — dispatches to tool handler with policy check

### State Management

| Module | Lines | Purpose |
|--------|-------|---------|
| `session.py` | ~142 | In-memory session store, TTL eviction, conversation turn tracking |
| `provenance.py` | ~115 | Trust tagging, chain walking, file provenance registry, trust-safe-for-execution check |

**Key functions:**
- `provenance.create_tagged_data()` — creates entry, inherits UNTRUSTED from any parent
- `provenance.is_trust_safe_for_execution()` — called before every tool execution (the CaMeL guarantee)
- `provenance.record_file_write()` / `get_file_writer()` — file trust inheritance
- `session.SessionStore.get_or_create()` — per-source sessions with TTL

---

## Test Files (`controller/tests/`)

| File | Tests | Source Module(s) |
|------|-------|-----------------|
| `test_policy_engine.py` | ~60 | policy_engine (paths, commands, traversal, globs) |
| `test_scanner.py` | ~50 | scanner (credentials, paths, commands, echo) |
| `test_encoding_scanner.py` | ~25 | scanner (base64, hex, URL, ROT13, HTML, char-split) |
| `test_pipeline.py` | ~30 | pipeline (input/output scan, SecurityViolation, ASCII gate) |
| `test_spotlighting.py` | ~10 | spotlighting (apply/remove markers) |
| `test_prompt_guard.py` | ~15 | prompt_guard (init, chunking, classification) |
| `test_codeshield.py` | ~10 | codeshield (init, scan parsing) |
| `test_planner.py` | ~40 | planner (plan creation, validation, refusals) |
| `test_orchestrator.py` | ~50 | orchestrator (context, steps, trust gates, chain-safe) |
| `test_tools.py` | ~40 | tools (file I/O, shell, Podman, flag deny-list) |
| `test_provenance.py` | ~20 | provenance (trust inheritance, chains, file tracking) |
| `test_approval.py` | ~15 | approval (lifecycle, TTL, submit) |
| `test_conversation.py` | ~40 | conversation (all 8 rules, combined scoring, FP prevention) |
| `test_pin_auth.py` | ~20 | auth (PIN validation, lockout, timing) |
| `test_hardening.py` | ~30 | Cross-module hardening regression tests |
| `test_input_validation.py` | ~15 | main.py Pydantic validators + pipeline length gate |
| `test_hostile.py` | ~50 | Cross-module adversarial attack simulations |
| `test_worker.py` | ~10 | worker (mocked Ollama connection/timeout) |
| `conftest.py` | — | Fixtures: engine, cred_scanner, path_scanner, cmd_scanner, encoding_scanner |

**Total: 562 tests passing** (1 known failure: `test_system_prompt_includes_tool_descriptions` in test_planner.py:181)

---

## Frontend (`gateway/static/`)

| File | Lines | Purpose |
|------|-------|---------|
| `index.html` | ~38 | Chat UI structure: header + status dot, message area, input form |
| `app.js` | ~450 | Task submission, PIN management (sessionStorage), approval flow, message history (localStorage, 100 max) |
| `style.css` | ~200 | Dark theme (GitHub-inspired), responsive layout |

**Key JS functions:** `submitTask()`, `submitApproval()`, `checkStatus()`, `buildStepsHtml()`, `bindStepToggles()`

---

## Infrastructure

| File | Purpose |
|------|---------|
| `podman-compose.yaml` | 3 services, 2 networks, 2 secrets, 2 volumes |
| `policies/sentinel-policy.yaml` | ~130 lines — file access, commands, network, credential patterns, sensitive paths |
| `controller/Dockerfile` | Multi-stage: Python 3.12 (pinned) + Prompt Guard download + semgrep workaround |
| `gateway/Dockerfile` | Nginx (pinned) + self-signed TLS cert |

---

## Cross-Module Data Flow

```
User → main.py (validate, CSRF, size limit, Pydantic)
     → orchestrator.handle_task()
       → session.get_or_create()
       → conversation.analyze() [8 rules]
       → pipeline.scan_input() [Prompt Guard + 4 scanners]
       → planner.create_plan() [Claude API]
       → approval.request_plan_approval() [if full mode]
       → for each step:
           llm_task → orchestrator._execute_llm_task()
                    → pipeline.process_with_qwen()
                      → pipeline._check_prompt_ascii()
                      → spotlighting.apply_datamarking()
                      → worker.generate() → sentinel-qwen:11434
                      → provenance.create_tagged_data() [UNTRUSTED]
                      → codeshield.scan()
                      → pipeline.scan_output()
                      → scanner.VulnerabilityEchoScanner.scan()
           tool_call → provenance.is_trust_safe_for_execution()
                     → tools.execute() → policy_engine.check_*()
     → TaskResult returned
```

## Module Dependency Graph

```
main.py
  ├── auth.py (middleware)
  ├── config.py (settings)
  ├── orchestrator.py
  │     ├── planner.py → Claude API
  │     ├── pipeline.py
  │     │     ├── scanner.py (5 scanners)
  │     │     ├── prompt_guard.py → HuggingFace model
  │     │     ├── spotlighting.py
  │     │     └── worker.py → Ollama/Qwen
  │     ├── tools.py
  │     │     ├── policy_engine.py → sentinel-policy.yaml
  │     │     └── provenance.py
  │     ├── approval.py
  │     ├── session.py
  │     ├── conversation.py
  │     └── codeshield.py → semgrep
  ├── models.py (shared data types)
  └── audit.py (logging)
```
