# Codebase Map

Developer reference for navigating the Sentinel codebase. Update when modules change significantly.

**Inventory date:** 2026-08-31 (source-counted; supersedes the April 2026 snapshot).

---

## Package Structure

```
sentinel/              # Main Python package (105,437 lines across 343 modules)
├── analysis/          # Structural digest, content manifest, metadata extraction, logging injection
├── api/               # FastAPI app, auth, metrics, A2A, middleware
│   ├── init/          # Startup sub-modules (database, security, orchestrator, channels, shutdown)
│   └── routes/        # Extracted route handlers (12 modules)
├── audit/             # Structured JSON audit logging + typed event emitter
├── channels/          # Multi-channel (WebSocket, SSE, Signal, Telegram, Matrix, email, MCP, webhooks)
│                      # Self-registering channel pattern via registry.py
├── contacts/          # Contact registry + resolver — modularised into focused sub-modules
│                      # store.py facade → _users, _contacts, _channels, _channel_crypto, _rows
├── core/              # Config, models, approval, database, event bus, RLS, workspace
├── crypto/            # Encryption at rest — AES-256-GCM cipher, blind index, key management, migration
├── integrations/      # Google OAuth2, Gmail, Google Calendar, IMAP/SMTP, CalDAV
├── media/             # Attachment ingestion, storage, MIME validation
├── memory/            # Persistent memory (pgvector, tsvector FTS, hybrid search, episodic, reranker)
│                      # Includes anchor_maps + episodic_facts stores
├── planner/           # Claude planner + CaMeL orchestrator (79 modules, 20,683 lines)
│   ├── _context_providers/  # 6 extracted context provider classes (+ __init__; 7 modules, 835 lines)
│   └── _prompts/      # Modular system prompt sections (16 modules, 816 lines)
│       └── _sections/ # Individual prompt sections (role, tools, constraints, examples, etc.)
├── router/            # Request classification + fast-path execution (6 modules)
├── routines/          # Cron/event/interval scheduling engine + heartbeat + stats extraction
├── security/          # Phase-based scan pipeline, policy, provenance, conversation monitoring (86 modules, 23,093 lines)
│   ├── code_fixer/    # 18-module package: post-Qwen structural repair per language
│   ├── conversation/  # 20-module package: multi-turn attack detection, signal-based scoring
│   │   └── signals/   # 13 modules: 11 attack signal detectors + shared regex patterns + __init__
│   ├── scanners/      # 8-module plugin package: credential, path, command, echo, prompt-guard, semgrep + helpers
│   ├── suppression_handlers/  # 8-module FP-suppression handler package (code blocks, env templates, URIs, etc.)
│   └── rules/         # Declarative YAML rule definitions (5 files: credentials, paths, commands, echo, suppressions)
├── session/           # Session store (PostgreSQL + in-memory)
├── tools/             # Tool executor, sandbox, web search, sidecar client
│   ├── _handlers/     # Handler mixins + registry (auto-discovery via @tool_handler decorator; 16 modules)
│   ├── anchor_allocator/  # Deterministic anchor markers for file_patch targeting (11 modules)
│   └── patch_backends/    # Language-specific anchor resolution for file_patch (9 modules)
└── worker/            # Provider ABCs, Ollama client, context buffer, factory

sidecar/               # Rust WASM sidecar — core modules plus WASM tool binaries
ui/                    # Frontend (HTML/JS/CSS)
policies/              # Security policy YAML
container/             # Containerfile, sandbox Containerfile, entrypoint
rules/                 # Semgrep rules used by the code scanner
```

---

## Core Modules

### API & Config (`sentinel/api/`, `sentinel/core/`, `sentinel/audit/`)

| Module | Lines | Purpose |
|--------|-------|---------|
| `api/app.py` | 230 | FastAPI factory — creates app, registers middleware/exception handlers/routers |
| `api/lifecycle.py` | 804 | Startup/shutdown coordinator — calls `init/` sub-modules in order |
| `api/middleware.py` | 382 | Request correlation IDs, JWT auth, security headers (CSP), CSRF, request size limit |
| `api/auth.py` | 176 | PIN auth — PBKDF2-HMAC-SHA256, constant-time comparison, per-IP lockout |
| `api/auth_routes.py` | 630 | Login/logout/revocation endpoints |
| `api/sessions.py` | 91 | JWT session token creation and verification |
| `api/revocation.py` | 128 | Thread-safe in-memory JTI revocation set |
| `api/models.py` | 290 | Pydantic request models with NFC normalisation and length bounds |
| `api/metrics.py` | 144 | Dashboard metrics aggregation across stores |
| `api/a2a.py` | 672 | A2A JSON-RPC 2.0 adapter (Google A2A protocol) |
| `api/contacts.py` | 488 | CRUD endpoints for users, contacts, contact channels |
| `api/credentials.py` | 161 | CRUD endpoints for per-user service credentials |
| `api/role_guard.py` | 117 | Role-based access guard (owner > admin > user > pending) |
| `api/redirect.py` | 52 | Minimal ASGI HTTP→HTTPS redirect |
| `api/rate_limit.py` | 14 | Rate limiting stub |
| **`api/init/`** | | |
| `init/database.py` | 348 | PostgreSQL pools (migration, RLS, admin), schema, all store instances |
| `init/security.py` | 147 | PIN auth, policy engine, all scanners, ScanPipeline assembly via scanner registry |
| `init/orchestrator.py` | 801 | Ollama health + retry, tool executor, planner, orchestrator, loop controller |
| `init/channels.py` | 1,049 | Self-registering channel pattern, routine engine, heartbeat, webhook limiter, route wiring, static mount |
| `init/shutdown.py` | 310 | Ordered 11-step teardown |
| **`api/routes/`** | | |
| `routes/__init__.py` | 58 | Router aggregation and registration helpers |
| `routes/_common.py` | 28 | Shared route utilities |
| `routes/task.py` | 565 | Task submission, approval, confirmation gate, session debug |
| `routes/streaming.py` | 261 | SSE event stream, audit log SSE, heartbeat status |
| `routes/websocket.py` | 399 | WebSocket endpoint with JWT auth, bidirectional routing |
| `routes/memory.py` | 299 | Memory store/search/list/get/delete |
| `routes/routines.py` | 1,069 | Routine CRUD + manual trigger |
| `routes/loop.py` | 452 | Loop start/list/status/cancel |
| `routes/security.py` | 322 | Path/command validation and text scan/process |
| `routes/health.py` | 314 | Container health probe, client health check + metrics |
| `routes/webhooks.py` | 527 | Webhook registration, listing, deletion, inbound HMAC verification |
| `routes/a2a.py` | 344 | A2A agent card discovery and JSON-RPC task endpoint |
| **Core** | | |
| `core/config.py` | 686 | Pydantic Settings via `SENTINEL_*` env vars |
| `core/models.py` | 221 | TaggedData, StepResult, PlanStep, TaskPlan, enums |
| `core/approval.py` | 1,098 | Approval queue with configurable TTL — PostgreSQL + in-memory fallback |
| `core/confirmation.py` | 692 | Action-level confirmation gate for pending tool payloads |
| `core/pending_action_preconditions.py` | 173 | Shared submit-time precondition recheck for approval/confirmation (session lock) |
| `core/socket_auth.py` | 217 | Unix socket peer UID auth + runtime-dir validation (sidecar, signal-cli) |
| `core/bus.py` | 121 | Async pub/sub event bus with glob wildcard matching |
| `core/context.py` | 119 | Request-scoped ContextVars + `spawn_task()` |
| `core/db.py` | 255 | Periodic PostgreSQL purge helpers |
| `core/pg_schema.py` | 1,169 | Idempotent PostgreSQL schema creation (all tables, indexes, extensions) |
| `core/rls.py` | 71 | RLS-aware asyncpg pool wrapper |
| `core/credential_store.py` | 324 | Per-user AES-256-GCM encrypted service credentials |
| `core/exceptions.py` | 380 | Unified exception hierarchy rooted at SentinelError |
| `core/store_protocols.py` | 488 | `@runtime_checkable` Protocol definitions for all store interfaces |
| `core/workspace.py` | 42 | Per-user workspace path construction |
| `core/decorators.py` | 15 | `@no_audit_log` decorator |
| `audit/logger.py` | 101 | JSON-formatted TimedRotatingFileHandler |
| `audit/emitter.py` | 331 | Typed audit event emitter with structured fields |
| `audit/events.py` | 100 | Audit event type definitions and constants |
| `audit/_severity_contract.py` | 110 | Wire-contract registry for SecurityAuditEvent severity per event_type |
| **Crypto** | | |
| `crypto/cipher.py` | 93 | AES-256-GCM encrypt/decrypt primitives |
| `crypto/keys.py` | 235 | Master key loading from Podman secrets |
| `crypto/blind_index.py` | 162 | HMAC-SHA256 blind index for encrypted lookups |
| `crypto/migration.py` | 414 | Plaintext→encrypted data migration with batch processing |
| `crypto/store_mixin.py` | 44 | CryptoAuditMixin — shared encrypt/decrypt for store modules |
| `crypto/audit.py` | 72 | Crypto-specific audit event logging |
| `crypto/preflight.py` | 70 | Eager production master-key validation at startup / migration |

### Security Pipeline (`sentinel/security/`)

The scanner refactor (phases 1–10, complete 2026-04-18) and scanner hardening (H0–H6, complete 2026-04-19) split the monolithic `scanner.py` + `pipeline.py` into a phase-based pipeline with plugin scanners, declarative YAML rules, and context-aware suppression handlers.

| Module | Lines | Purpose |
|--------|-------|---------|
| **Pipeline core** | | |
| `pipeline.py` | 591 | Top-level 10-layer orchestration: input → script gate → spotlighting → Qwen → output scan. Fail-closed. Delegates to `_phase_*` modules |
| `_pipeline_factory.py` | 211 | Pipeline assembly from registered scanner plugins + rule definitions |
| `_phase_preprocessing.py` | 93 | Preprocessor — input normalisation before scan phases |
| `_phase_input.py` | 859 | Input-scan phase: validation, gates, suppression, scanner dispatch, audit |
| `_phase_output.py` | 672 | Output-scan phase: post-Qwen scanning, finalisation, audit |
| `_phase_dispatch.py` | 269 | Scanner dispatch loop — iterates registered scanners, aggregates matches |
| `_phase_shared.py` | 222 | Shared helpers used by both input and output phases |
| **Scan context & types** | | |
| `_scan_context.py` | 300 | Frozen dataclasses: ScanResult, SuppressionVerdict, scan context types (immutable) |
| `_enums.py` | 63 | Phase, Platform, Severity, EncodingType, RegionType, OutputDestination enums |
| `_scanner_names.py` | 79 | Canonical scanner order, security-vs-safety classification, legacy name mapping |
| `_scanner_registry.py` | 59 | Scanner auto-registration — scanners self-register, pipeline assembles from registry |
| `_log_shape.py` | 196 | Operator-readable command/path shape categorisation + canonical-set hashing for log extras |
| **Input gating & suppression** | | |
| `_input_gates.py` | 157 | Pre-scan input gates (length, encoding, structural) |
| `_gate_violations.py` | 81 | Gate violation types and severity mapping |
| `_encoding_normalizer.py` | 317 | Encoding detection + normalisation (base64, hex, URL, Unicode) |
| `_suppression.py` | 355 | SuppressionEngine — runs declarative YAML suppressions + handler dispatch |
| `_worker_interaction.py` | 317 | Worker invocation wrapper — contract between pipeline and Ollama/worker |
| `_audit_builders.py` | 533 | Audit event construction helpers — typed structured logging for scan phases |
| **Rule loading** | | |
| `_rule_loader.py` | 256 | YAML rule file parser and caching |
| `_rule_schema.py` | 75 | RuleDefinition, SuppressionDefinition frozen schemas |
| **Scanners (`scanners/`)** | | 8-module plugin package — each scanner self-registers |
| `scanners/credential.py` | 372 | Credential pattern scanner (API keys, tokens, private keys) |
| `scanners/sensitive_path.py` | 366 | Sensitive filesystem path detector (~/.ssh, /etc/shadow, etc.) |
| `scanners/command_pattern.py` | 202 | Dangerous shell command detector (fork bombs, pipe-to-shell, etc.) |
| `scanners/vulnerability_echo.py` | 220 | Detects Qwen echoing back scanner/policy strings verbatim |
| `scanners/prompt_guard.py` | 251 | Scanner wrapper around Meta Prompt Guard model client |
| `scanners/semgrep.py` | 410 | Semgrep CLI scanner plugin wrapping `semgrep_scanner.py` |
| `scanners/_helpers.py` | 22 | Shared scanner utilities |
| `semgrep_scanner.py` | 531 | Direct Semgrep CLI wrapper — curated rule sets, fail-closed |
| **Suppression handlers (`suppression_handlers/`)** | | Context-aware FP suppression (8 files, 1,188 lines) |
| `suppression_handlers/build_context.py` | 327 | Suppress findings inside build/CI/config blocks |
| `suppression_handlers/code_block_safe.py` | 151 | Suppress findings inside fenced code blocks when benign |
| `suppression_handlers/display_context.py` | 69 | Suppress when region is user-display-only |
| `suppression_handlers/educational_context.py` | 174 | Suppress in tutorial/educational framing |
| `suppression_handlers/env_template.py` | 102 | Suppress placeholder values in `.env.example`, etc. |
| `suppression_handlers/placeholder_values.py` | 162 | Suppress documented placeholder strings (foo, example.com, etc.) |
| `suppression_handlers/uri_parsing.py` | 146 | Suppress credentials encoded in URIs being parsed, not used |
| **Declarative rules (`rules/`)** | | Non-Python YAML rules loaded by `_rule_loader.py` |
| `rules/credentials.yaml` | 344 | Credential detection patterns |
| `rules/sensitive_paths.yaml` | 345 | Sensitive filesystem paths |
| `rules/commands.yaml` | 277 | Dangerous command patterns |
| `rules/vulnerability_echo.yaml` | 238 | Vulnerability-echo patterns |
| `rules/suppressions.yaml` | 36 | Global suppression rules |
| **Policy & constraints** | | |
| `policy_engine.py` | 871 | File path + shell command policy — allow/deny lists, URL decode, homoglyph, ANSI-C quotes |
| `constraint_validator.py` | 536 | D5: Plan-policy constraints, constitutional denylist, metachar rejection (TL4+) |
| `ssrf.py` | 642 | Python-side SSRF policy primitives (URL parse/allowlist/private-IP reject; ported from sidecar) |
| **Support utilities** | | |
| `context_classifier.py` | 397 | Shared code/shell/prose position classifier for scanners |
| `code_extractor.py` | 212 | Code block extraction from markdown for targeted Semgrep scanning |
| `homoglyph.py` | 100 | NFKD + Cyrillic→Latin normalisation |
| `spotlighting.py` | 71 | Per-word character prefix marking |
| `provenance.py` | 651 | ProvenanceStore — trust inheritance across tool calls, PostgreSQL + in-memory |
| `prompt_guard.py` | 180 | Meta Llama Prompt Guard injection detection; degrades gracefully |
| `quality_gate.py` | 238 | Python syntax + token-cap truncation warnings (advisory, never blocks) |
| **`conversation/`** | 4,345 | 20-module package: multi-turn attack detection, signal-based scoring |
| `conversation/__init__.py` | 1,088 | ConversationAnalyzer — 8 heuristic rules, session locking, signal aggregation |
| `conversation/monitor.py` | 538 | Signal processing pipeline and session state management |
| `conversation/aggregator.py` | 154 | Multi-signal score aggregation with decay |
| `conversation/config.py` | 193 | Tunable thresholds and signal weights |
| `conversation/fp_management.py` | 237 | False-positive suppression and allowlisting |
| `conversation/audit.py` | 162 | Conversation-specific audit trail |
| `conversation/types.py` | 53 | Shared type definitions for signal framework |
| **`conversation/signals/`** | 1,920 | 11 attack signal detectors + shared patterns |
| `signals/_patterns.py` | 80 | Shared regex patterns across signal detectors |
| `signals/escalation.py` | 319 | Privilege escalation and authority claim detection |
| `signals/violation_accumulation.py` | 219 | Cumulative violation scoring across turns |
| `signals/topic_shift.py` | 185 | Suspicious topic drift detection |
| `signals/code_danger.py` | 160 | Dangerous code pattern detection in conversation |
| `signals/flattery_override.py` | 154 | Social engineering via flattery/urgency |
| `signals/evaluation_framing.py` | 142 | "Pretend you're a…" reframing attempts |
| `signals/instruction_override.py` | 135 | Direct instruction override attempts |
| `signals/context_reference.py` | 128 | Suspicious context/memory references |
| `signals/sensitive_topic.py` | 121 | Sensitive topic boundary detection |
| `signals/reconnaissance.py` | 118 | System probing and capability discovery |
| `signals/retry_detection.py` | 91 | Repeated failed attempt patterns |
| **`code_fixer/`** | 5,563 | 18-module package: post-Qwen structural repair before write-to-disk |
| `_core.py` | 736 | Foundation: FixResult, `_iter_code_chars()` parser, chain runner |
| `_universal.py` | 163 | BOM removal, CRLF normalisation, trailing whitespace, prose stripping |
| `_html.py` | 437 | Tag balancing, attribute normalisation, entity encoding, accessibility |
| `_javascript.py` | 533 | Unclosed strings, brace depth, template literals, semicolons |
| `_python.py` | 1,071 | Mixed indentation, bracket completion, hallucinated import removal (AST) |
| `_css.py` | 115 | Unclosed braces, missing semicolons |
| `_rust.py` | 301 | Raw string awareness, semicolons, bracket completion |
| `_shell.py` | 317 | Shebang repair, unclosed quotes, heredoc-aware closers |
| `_json.py` | 235 | Python booleans, single quotes, trailing commas, NaN/Infinity |
| `_cross_language.py` | 425 | CSS/JS outside proper container tags, HTML wrappers in .css/.js |
| `_structural.py` | 247 | Post-fix parse validation, structural integrity flag |
| `_detectors.py` | 208 | Truncation detection and duplicate definition detection |
| `_markdown.py` | 101 | Unclosed code fences, unbalanced link/image syntax |
| `_yaml.py` | 118 | Tab/inconsistent indentation repair |
| `_dockerfile.py` | 162 | Exec-form arrays, ADD→COPY, missing USER, :latest warnings |
| `_sql.py` | 79 | Missing trailing semicolons |
| `_toml.py` | 34 | Validation and detection only |

### Execution Engine (`sentinel/planner/`, `sentinel/tools/`)

| Module | Lines | Purpose |
|--------|-------|---------|
| `planner/orchestrator.py` | 1,127 | CaMeL coordinator: Stages A–E lifecycle, mixin composition |
| `planner/_orchestrator_proto.py` | 180 | `OrchestratorServices` Protocol — shared-state contract for all mixins |
| `planner/_orchestrator_deps.py` | 33 | `OrchestratorDeps` dataclass — dependency bundle for orchestrator construction |
| `planner/_task_context.py` | 272 | `TaskContext` + `PlanExecState` — cross-stage state carriers |
| `planner/_context_provider.py` | 90 | Base class for context provider registry — providers self-register |
| `planner/intake.py` | 175 | Stage A: session binding, conversation analysis entry point |
| `planner/_intake_processing.py` | 264 | Stage A internals: multi-turn analysis, S1 input scan, contact resolution |
| `planner/_intake_types.py` | 26 | Intake data models (IntakeResult, etc.) |
| `planner/input_scan.py` | 420 | S1 input scan extraction (from intake) |
| `planner/conversation_gate.py` | 437 | Conversation-level security gating |
| `planner/builders.py` | 63 | Stage B: planner prompt construction entry point (delegates to _prompt_builder) |
| `planner/_prompt_builder.py` | 459 | Prompt assembly from modular sections |
| `planner/_learning_context.py` | 578 | Episodic context, domain summaries, canonical trajectories for prompt |
| `planner/_history_rendering.py` | 270 | Conversation history rendering for prompt |
| `planner/_error_context.py` | 291 | Error genericisation and context for replanning |
| `planner/_error_tracking.py` | 288 | Per-task error accumulation and pattern detection |
| `planner/planner.py` | 486 | Stage C: Claude API client, JSON plan generation |
| `planner/_plan_creation.py` | 248 | Plan creation helpers and preamble stripping |
| `planner/_plan_validator.py` | 507 | Plan JSON schema validation and normalisation |
| `planner/_plan_setup.py` | 185 | Pre-execution plan setup and step enrichment |
| `planner/_response_parser.py` | 296 | Claude response parsing and extraction |
| `planner/_response_select.py` | 31 | Select last non-empty llm_task content for execution result text |
| `planner/_command_shape.py` | 74 | Back-compat shim for command_shape / allowlist (delegates to security._log_shape) |
| `planner/_execution.py` | 747 | Stage E: plan/step execution loop, variable bindings |
| `planner/_execution_context.py` | 244 | Execution-scoped context and state management |
| `planner/_execution_state.py` | 228 | Execution state machine transitions |
| `planner/_step_executors.py` | 430 | Individual step type executors (llm_task, tool_call, etc.) |
| `planner/_step_enrichment.py` | 522 | Step-level context enrichment before execution |
| `planner/_output_processing.py` | 359 | Worker output processing and variable extraction |
| `planner/_post_processing.py` | 206 | Post-step cleanup and state updates |
| `planner/tool_dispatch.py` | 589 | S3 provenance → S4 constraints → S5 output scan chain |
| `planner/_tool_constraints.py` | 375 | Tool constraint evaluation helpers |
| `planner/_tool_scanning.py` | 417 | Tool output scanning pipeline |
| `planner/_replan.py` | 897 | Dynamic replanning on success (continuation) and failure (soft_failed) |
| `planner/_verification.py` | 851 | VerificationMixin — judge pipeline, assertion evaluation, judge-triggered replan |
| `planner/verification.py` | 91 | Verification entry point (delegates to _verification + _evaluation) |
| `planner/_evaluation.py` | 409 | Tier 1 deterministic + Tier 2 planner-as-judge goal verification |
| `planner/_evaluator_fns.py` | 1,180 | Individual evaluator functions for goal verification |
| `planner/_evaluators.py` | 57 | Evaluator registry and dispatch |
| `planner/_judge_payload.py` | 507 | Judge prompt construction for Tier 2 verification |
| `planner/_judge_verdict.py` | 101 | Judge verdict parsing and normalisation |
| `planner/_tier1_consensus.py` | 138 | Tier 1 multi-evaluator consensus logic |
| `planner/_classification.py` | 161 | Task classification helpers for verification routing |
| `planner/_path_normalisation.py` | 183 | Path normalisation for verification comparisons |
| `planner/_episodic.py` | 447 | EpisodicMixin — stores extracted facts from task outcomes |
| `planner/_memory_persistence.py` | 181 | Memory persistence helpers for episodic storage |
| `planner/safe_tools.py` | 181 | Planner-callable safe tool handlers — entry point |
| `planner/_safe_tool_registry.py` | 24 | Safe tool registration and dispatch |
| `planner/_safe_memory_tools.py` | 299 | Safe memory tool implementations (search, store, list) |
| `planner/_safe_session_tools.py` | 222 | Safe session tool implementations (read history, get context) |
| `planner/trust_router.py` | 123 | Deterministic SAFE/PERMITTED/DANGEROUS classification per trust level |
| `planner/loop_controller.py` | 962 | Persistent goal-pursuit wrapper — repeated orchestrator calls until goal met |
| `planner/_loop_gaps.py` | 541 | Loop gap analysis and recovery |
| `planner/_approval_gate.py` | 213 | Plan approval gate logic |
| `planner/loop_store.py` | 316 | PostgreSQL CRUD for `loop_runs` table |
| **`planner/_context_providers/`** | | 6 extracted context provider classes |
| `_episodic_records.py` | 149 | Episodic record retrieval for planner context |
| `_domain_summary.py` | 90 | Per-domain intelligence summaries |
| `_canonical.py` | 130 | Best-performing trajectory context |
| `_insights.py` | 142 | Planning insight distillation context |
| `_detailed_history.py` | 133 | Detailed conversation history context |
| `_anchor_maps.py` | 156 | Anchor map context for file_patch targeting |
| **`planner/_prompts/`** | 816 | Modular system prompt sections |
| `_prompts/__init__.py` | 35 | Prompt template registry |
| `_prompts/general.py` | 32 | General-purpose prompt template |
| `_prompts/research.py` | 39 | Research-mode prompt template |
| `_prompts/_sections/examples.py` | 183 | Few-shot example section |
| `_prompts/_sections/tool_selection.py` | 101 | Tool selection guidance section |
| `_prompts/_sections/output_schema.py` | 94 | Output JSON schema section |
| `_prompts/_sections/plan_rules.py` | 69 | Plan structure rules section |
| `_prompts/_sections/media_attachments.py` | 55 | Media attachment handling section |
| `_prompts/_sections/constraints.py` | 42 | Security constraint section |
| `_prompts/_sections/tools.py` | 41 | Tool definitions section |
| `_prompts/_sections/worker_llm.py` | 39 | Worker LLM capabilities section |
| `_prompts/_sections/security_rules.py` | 21 | Security rules section |
| `_prompts/_sections/debugging.py` | 16 | Debugging guidance section |
| `_prompts/_sections/episodic_learning.py` | 12 | Episodic learning section |
| `_prompts/_sections/role.py` | 6 | System role definition |
| **Tools** | | |
| `tools/executor.py` | 905 | Top-level tool dispatcher — assembles handler mixins |
| `tools/sandbox.py` | 825 | Disposable Podman containers via REST API (no network, dropped caps, ro rootfs) |
| `tools/sidecar.py` | 513 | SidecarClient — async Unix-socket client for Rust WASM sidecar |
| `tools/podman_proxy.py` | 871 | Security proxy for Podman socket — allowlisted operations only |
| `tools/loop_detector.py` | 126 | Per-task tool call loop detection (warn at 3, block at 6) |
| `tools/web_search.py` | 309 | Web search (Brave, SearXNG); results tagged UNTRUSTED |
| `tools/x_search.py` | 119 | X/Twitter search via xAI Grok; results tagged UNTRUSTED |
| `tools/weather.py` | 401 | Dual backend (Met Office UK, Open-Meteo worldwide) |
| `tools/crypto_price.py` | 210 | Dual backend (CoinGecko rich data, Binance real-time) |
| **`tools/_handlers/`** | | Handler mixins + registry via `@tool_handler` auto-discovery |
| `_registry.py` | 111 | Handler registry — `@tool_handler` decorator + auto-discovery loader |
| `_file_write.py` | 747 | WriteHandlerMixin — file_write, mkdir, shell, sandbox execution |
| `_file_patch.py` | 958 | PatchHandlerMixin — file_patch with anchor resolution |
| `_file_ops.py` | 885 | FileOpsHandlerMixin — file_read, file operations, hash tracking |
| `_website.py` | 833 | website_create, website_list, website_remove |
| `_email.py` | 812 | Gmail and IMAP email handlers |
| `_calendar.py` | 687 | Google Calendar and CalDAV handlers |
| `_messaging.py` | 122 | Signal and Telegram send/receive |
| `_container.py` | 376 | Podman build, run, stop |
| `_external_data.py` | 423 | Web search, X search, crypto, weather dispatch |
| `_executor_proto.py` | 54 | `ToolExecutorServices` Protocol for handler mixins |
| `_task_exec_context.py` | 87 | Per-task scoped state (file reads, hashes, loop detector) |
| `_constants.py` | 93 | Shared constants (Semgrep scanning, manifest generation gates) |
| `_file.py` | 22 | File operation helpers |
| `_types.py` | 32 | Handler type definitions |
| **`tools/anchor_allocator/`** | 1,825 | Deterministic anchor markers for file_patch targeting |
| `__init__.py` | 658 | Main allocator logic and public API |
| `_core.py` | 94 | AnchorEntry, AnchorTier models |
| `_memory.py` | 206 | Episodic memory integration for anchor maps |
| `_python.py` | 115 | AST-based Python anchor parser |
| `_javascript.py` | 120 | Regex JS/TS anchor parser |
| `_html.py` | 173 | BeautifulSoup HTML anchor parser |
| `_css.py` | 110 | Regex CSS rule/media query parser |
| `_rust.py` | 115 | Regex Rust fn/struct/impl parser |
| `_shell.py` | 78 | Regex shell function parser |
| `_config.py` | 115 | YAML/JSON/TOML anchor parsers |
| `_strip.py` | 41 | Idempotent anchor marker stripping |
| **`tools/patch_backends/`** | 3,740 | Language-specific anchor resolution for file_patch |
| `_protocol.py` | 205 | PatchBackend protocol + AnchorResult |
| `_constants.py` | 18 | Shared patch-backend constants |
| `_text.py` | 465 | Default backend — exact match, range anchors, CSS fallback |
| `_html.py` | 495 | `css:` prefix anchors via BeautifulSoup, DOM-aware replace_inner |
| `_css.py` | 332 | `sel:` prefix anchors, brace-aware splicing |
| `_javascript.py` | 559 | `fn:` and `class:` anchors via brace-depth tracking |
| `_python.py` | 785 | `fn:` and `class:` anchors via AST, supports ClassName.method |
| `_rust.py` | 872 | `fn:`, `class:`, `block:` anchors; raw string + nested comment handling |

### Memory & Context (`sentinel/memory/`, `sentinel/worker/`)

| Module | Lines | Purpose |
|--------|-------|---------|
| `memory/episodic.py` | 1,806 | Episodic store — tasks, files, errors, extracted facts; PostgreSQL + tsvector FTS |
| `memory/episodic_facts.py` | 177 | Extracted facts sub-store — CRUD for episodic fact records |
| `memory/chunks.py` | 536 | Memory chunk store — pgvector(768) + tsvector; in-memory fallback |
| `memory/search.py` | 276 | Hybrid search — FTS + vector cosine + RRF fusion |
| `memory/embeddings.py` | 183 | Async Ollama embedding client (nomic-embed-text) |
| `memory/splitter.py` | 142 | Text splitter — paragraph → sentence → word boundary (~380 words/chunk) |
| `memory/reranker.py` | 315 | FlashRank cross-encoder re-ranking + MMR diversity |
| `memory/domain_summary.py` | 407 | Per-domain aggregated intelligence (deterministic, no LLM) |
| `memory/strategy_store.py` | 338 | Strategy pattern success rates per domain |
| `memory/canonical.py` | 303 | Best-performing trajectory extraction per domain |
| `memory/insights.py` | 472 | Planning insight distillation with confidence scoring |
| `memory/anchor_maps.py` | 247 | Anchor map store — persistent anchor allocations for file_patch targeting |
| `worker/ollama.py` | 348 | OllamaWorker — HTTP client for Qwen; all output marked UNTRUSTED |
| `worker/base.py` | 115 | Abstract base classes (WorkerBase, PlannerBase, EmbeddingBase) |
| `worker/context.py` | 100 | Per-session ring buffer of prior worker output summaries |
| `worker/factory.py` | 46 | Config-driven provider factory |

### Channels & Routines

| Module | Lines | Purpose |
|--------|-------|---------|
| `channels/base.py` | 524 | Channel ABC + ChannelRouter — all transport backends implement this |
| `channels/registry.py` | 109 | Self-registering channel pattern — channels register via decorator |
| `channels/signal_channel.py` | 1,194 | Signal via signal-cli daemon + Unix socket; exponential backoff, sender allowlist |
| `channels/telegram_channel.py` | 835 | Telegram bot via long-polling |
| `channels/matrix_channel.py` | 951 | Matrix via matrix-nio E2EE client; room-based routing |
| `channels/email_channel.py` | 635 | IMAP polling channel with attachment ingestion |
| `channels/web.py` | 330 | WebSocketChannel + SSEWriter |
| `channels/mcp_server.py` | 309 | MCP server — exposes tools to MCP clients; SAFE bypass CaMeL |
| `channels/webhook.py` | 486 | Inbound webhooks with HMAC-SHA256, timestamp validation, idempotency |
| `routines/engine.py` | 1,442 | Scheduler — checks due routines, event-bus triggers, concurrent execution |
| `routines/store.py` | 742 | PostgreSQL CRUD for routines; in-memory fallback |
| `routines/stats.py` | 361 | RoutineStats — extracted statistics tracking for routine execution |
| `routines/cron.py` | 83 | Cron expression validation via croniter |
| `routines/heartbeat.py` | 201 | Periodic health checks with protected source tags |

### Router (`sentinel/router/`)

| Module | Lines | Purpose |
|--------|-------|---------|
| `router/router.py` | 697 | MessageRouter — scan_and_prepare + check_pending_actions + classify + dispatch; feature-flag gated |
| `router/keyword_classifier.py` | 649 | Deterministic regex classifier — zero GPU, microseconds |
| `router/classifier.py` | 277 | Qwen-based classifier (fallback to PLANNER on failure) |
| `router/fast_path.py` | 767 | Fast-path executor — template-matched single-tool operations; execute() split into 3 helpers |
| `router/templates.py` | 320 | Template dataclass + TemplateRegistry |

### Analysis (`sentinel/analysis/`)

| Module | Lines | Purpose |
|--------|-------|---------|
| `analysis/structural_digest.py` | 860 | Privacy-safe structural metadata from Qwen output (never raw content) |
| `analysis/content_manifest.py` | 743 | Deterministic observable properties from deployed files for goal verification |
| `analysis/metadata_extractor.py` | 214 | Trusted metadata from Python-generated artifacts |
| `analysis/logging_injector.py` | 349 | Debug entry-point logging injected into Qwen scripts |

### Integrations (`sentinel/integrations/`)

| Module | Lines | Purpose |
|--------|-------|---------|
| `integrations/imap_email.py` | 979 | IMAP/SMTP client (Proton Bridge, Fastmail, self-hosted) |
| `integrations/caldav_calendar.py` | 846 | Generic CalDAV client (Nextcloud, Radicale, Fastmail, iCloud) |
| `integrations/gmail.py` | 480 | Gmail REST API v1 client |
| `integrations/google_calendar.py` | 312 | Google Calendar REST API v3 client |
| `integrations/google_auth.py` | 159 | Google OAuth2 offline refresh token management |

### Other Packages

| Module | Lines | Purpose |
|--------|-------|---------|
| `contacts/store.py` | 71 | Facade — imports and re-exports from sub-modules |
| `contacts/_users.py` | 215 | User CRUD (create, update, list, get, delete) |
| `contacts/_contacts.py` | 251 | Contact CRUD (create, update, list, get, delete) |
| `contacts/_channels.py` | 642 | Contact channel CRUD with encrypted identifier storage |
| `contacts/_channel_crypto.py` | 60 | CryptoAuditMixin integration for channel encryption |
| `contacts/_rows.py` | 40 | Row-level data models for contact store |
| `contacts/resolver.py` | 324 | Contact resolution — opaque IDs inside, real identifiers at edges |
| `session/store.py` | 1,627 | PostgreSQL-backed conversation turn history + in-memory fallback |
| `session/_session_audit.py` | 140 | Emit `system.session_crash_reconciliation` audit events |
| `media/ingestion.py` | 318 | Channel-agnostic attachment pipeline: MIME validation, workspace save, hash |
| `media/models.py` | 145 | AttachmentMeta and MIME-type allowlist |
| `media/store.py` | 240 | PostgreSQL CRUD for media_attachments |

---

## Rust Sidecar (`sidecar/`)

WASM tool sandbox with Wasmtime. Deny-by-default capabilities, fuel metering, epoch timeouts, Aho-Corasick leak detection. **Core: 2,593 lines across 9 modules** in `sidecar/src/`. Additional code: **258-line integration test suite** (`sidecar/tests/integration.rs`) and **WASM tool binaries** under `sidecar/tools/` (file-read, file-write, shell-exec, http-fetch, common).

| File | Lines | Purpose |
|------|-------|---------|
| `src/host_functions.rs` | 657 | Host function dispatcher — `host_call(op, len)` import, capability-gated |
| `src/http_client.rs` | 524 | URL allowlist + SSRF protection — rejects private IPs, prevents DNS rebinding |
| `src/leak_detector.rs` | 361 | Aho-Corasick credential pattern scanner — O(n) multi-pattern, per-request isolation |
| `src/sandbox.rs` | 330 | Wasmtime engine — per-invocation isolation, fuel metering, memory caps, epoch timeouts |
| `src/main.rs` | 282 | Entry point — Unix domain socket listener, JSON request dispatch |
| `src/registry.rs` | 152 | Tool metadata registry — loads `.toml` definitions with WASM module paths + capabilities |
| `src/capabilities.rs` | 115 | Capability model — deny-by-default; explicit set per tool execution |
| `src/config.rs` | 95 | Resource limits via `SENTINEL_SIDECAR_*` env vars |
| `src/protocol.rs` | 77 | JSON Request/Response types for Python ↔ sidecar communication |
| `tests/integration.rs` | 258 | End-to-end integration tests (socket → dispatch → WASM) |
| `tools/common/src/lib.rs` | 145 | Shared WASM tool helpers (capability imports, JSON marshalling) |
| `tools/file-read/src/main.rs` | 50 | WASM binary — file read tool |
| `tools/file-write/src/main.rs` | 49 | WASM binary — file write tool |
| `tools/shell-exec/src/main.rs` | 50 | WASM binary — shell execution tool |
| `tools/http-fetch/src/main.rs` | 97 | WASM binary — HTTP fetch tool |

---

## Data Flow

```
User → HTTPS (uvicorn TLS)
     → SecurityHeaders → RequestSizeLimit → CSRF → JWT Auth
     → Transport: REST | WebSocket | SSE | MCP | A2A | Signal | Telegram | Matrix | Email | Webhook
       → router.MessageRouter
         → ScanPipeline.scan_input()           # S1: pre-classification scan
         → KeywordClassifier.classify()         # deterministic regex (or Qwen classifier fallback)
         → fast_path.execute() (template match) OR orchestrator path:
       → orchestrator.handle_task()
         → intake.bind_session()                # session acquisition, locked check
         → intake.analyze_conversation()        # multi-turn attack detection
         → intake.scan_input()                  # S1: input scan before planner
         → intake.resolve_contacts()            # opaque IDs for planner
         → builders.build_cross_session_context()    # tools, history, episodic, worker context
           → _context_providers/*               # 6 registered providers supply context sections
         → planner.create_plan() [Claude API]   # JSON plan with preamble stripping
         → approval.request_plan_approval()     # if full mode
         → _execution loop (for each step):
             llm_task → pipeline.process_with_qwen()
                      → _phase_preprocessing → _phase_input (gates, suppression, scanners)
                      → worker invocation via _worker_interaction
                      → _phase_output (post-Qwen scan, finalise, audit)
             tool_call → tool_dispatch.check_provenance()    # S3: before arg resolution
                       → context.resolve_args()              # argument resolution
                       → tool_dispatch.validate_constraints() # S4: after resolution [TL4+]
                       → tool_dispatch.dispatch_tool()        # S5: execute + scan output
                           → safe_tools.handler() OR executor → policy_engine
         → _verification (Tier 1 deterministic + Tier 2 planner-as-judge)
         → _replan (if needed — continuation or failure recovery)
         → _episodic.store_facts()              # extracted facts to memory
       → TaskResult
```
