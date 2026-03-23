# Changelog

All notable changes to Sentinel are documented here. Follows [Keep a Changelog](https://keepachangelog.com/) conventions.

---

## v0.4.0 — 2026-03-23

The security and testing release. Comprehensive 38-hour validation, AgentDojo-inspired injection benchmark, new planner/worker prompts, file patching tool, and significant pipeline hardening.

### Added
- **File patch tool** — incremental file modifications using CSS-selector-style anchors for deterministic targeting. Replaces full file rewrites for content updates. Supports `insert_after`, `insert_before`, `replace`, and `delete` operations with positional disambiguation for non-unique selectors
- **Injection benchmark** — AgentDojo-inspired test framework with 105 test cases across 6 attack vectors (file, email, calendar, Signal, Telegram, web) and 13 unique injection payloads. 100% pass rate (0 exploits). Scripts included for reproducibility
- **Planner prompt v2** — complete rewrite of the Claude planner system prompt for Sonnet 4.6 / Opus 4.6. Structured guidance for multi-step planning, cross-tool patterns, worker capabilities, and external data accuracy rules
- **Worker prompt v2** — rewrite for Qwen 3. XML response tags, fragment-aware output, explicit security boundaries
- **Keyword classifier** — routes requests to the right handler before planner dispatch, reducing unnecessary API calls and latency
- **Trust gate enforcement** — side-effect tools validate data provenance before execution. Untrusted data from worker outputs cannot reach dangerous operations without explicit scanning
- **Conversation risk accumulation** — scanner blocks and suspicious patterns accumulate risk over a session with time-based decay. Sessions lock when risk exceeds threshold
- **CI pipeline** — GitHub Actions workflow for automated test runs

### Changed
- **Planner model: Opus 4.6** — switched from Sonnet 4.6 (which replaced Sonnet 4.5) for better plan quality and episodic memory seeding. All three models evaluated — see assessment history
- **Preamble parser** — Sonnet 4.6 and Opus 4.6 emit reasoning text before JSON plans. Parser now handles this robustly (looks for `{"summary"` or `{"steps"` structure)
- **Dynamic replanning improvements** — continuation plans can now reference variables from previously executed steps. Output variable names included in replan context
- **Code fixer v2.6** — improved JS handling, code fence stripping, HTML entity unescaping
- **WebSocket idle timeout** — raised to 10 minutes to accommodate Opus planner latency on complex plans
- **Prompt Guard threshold** — raised to 0.96 to reduce false positives on legitimate requests

### Fixed
- **CSS selector anchors** — use source positions instead of string re-matching for deterministic element targeting in file_patch
- **File patch newline handling** — `insert_after` and `insert_before` ensure proper newline separation
- **Planner filename hallucination** — planner now required to discover existing files before modifying them, preventing creation of duplicate files with wrong names
- **HTML entity corruption** — Qwen RESPONSE tag content is now unescaped before processing
- **Modification verb routing** — verbs like "update", "change", "modify" correctly route to planner instead of fast path
- **Contextual reference detection** — messages referencing prior context ("the website", "that file") now route to planner with session history

### Security
- **0 exploits across 392 red team probes** — 6 threat models including compromised planner, sandbox escape, and database security
- **93.6% scanner defence rate** on 801 adversarial prompts (up from 0.12% real risk in v0.3.0 benchmark — different methodology, not directly comparable)
- **5.7% false positive rate** on genuine capability prompts
- **0 privacy boundary violations** across entire 38-hour validation run
- **Semgrep innerHTML rule** — blocks `.innerHTML = $X` with dynamic content. Generated JS uses `textContent` for DOM updates

### Testing
- **4,550 Python + 50 Rust** unit tests (up from 4,147 + 50 in v0.3.0)
- **38-hour comprehensive validation** — 1,136 adversarial/capability prompts + 60 functionality scenarios + 392 red team probes (~1,600 total)
- **Injection benchmark** — 105/105 passed, 0 exploits (AgentDojo-inspired methodology)
- **Test-to-source ratio** — 1.55:1 (64K test LOC / 41K source LOC)

---

## v0.3.0 — 2026-02-17

Major release — first fully functional deployment.

### Added
- PostgreSQL 17 migration with row-level security (SQLite fully removed)
- Contact registry with opaque IDs (planner never sees PII)
- Router with 9 fast-path templates (skip planner for simple tasks)
- Episodic learning with embedding-based hybrid retrieval (RRF search)
- Code fixer v2.5 (13 languages, 270+ tests)
- Dynamic replanning (discovery + failure-based)
- Sandboxed execution (disposable Podman containers, WASM sidecar)
- Multi-channel: Signal, Telegram, Email, Calendar, MCP server
- Routine scheduling (cron, event, interval triggers)
- WASM tool sandbox (Rust sidecar with Wasmtime, capability model, leak detection)

### Changed
- Orchestrator refactored (2,662 → 1,390 lines, split into 5 focused modules)
- 4,147 Python tests + 50 Rust tests (4,197 total)
- Zero red team breaches across 6 adversarial bands

---

## v0.2.0 — 2026-02-17

Assessment recommendations implemented, benchmark-ready.

- Script gate expanded allowlist (75% false positive reduction)
- Infrastructure hardening (TLS, CSP, CSRF, resource limits, read-only FS, pinned images)
- Persistent memory with RRF hybrid search
- Stress test v3 benchmark (1,136 prompts)

---

## v0.1.0 — 2026-02-12

Initial architecture. CaMeL-inspired dual-LLM design with 10-layer security pipeline, Podman isolation, and PIN authentication.
