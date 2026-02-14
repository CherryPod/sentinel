# Sentinel — Project Reference

> Distilled from `project-sentinel-build-plan.md`. Full plan has architecture rationale, pseudocode, test strategy, and design decisions.

---

## Architecture Summary

**CaMeL defence-in-depth:** A frontier model (Claude API) plans tasks, an air-gapped local LLM (Qwen 3 14B) does text work, and a Python Controller enforces security between them.

| Role | Component | Trust Level | Network Access |
|------|-----------|-------------|----------------|
| Privileged Planner | Claude API (Anthropic) | Trusted | Internet (via Controller) |
| Quarantined Worker | Qwen 3 14B (Ollama) | **Never trusted** | Air-gapped (sentinel_internal only) |
| Security Gateway | Python/FastAPI Controller | Deterministic | Both networks |

**Core principle:** Qwen is assumed compromised at all times. It only receives text and returns text. The Controller scans every output before acting on it.

---

## Containers

| Container | Image | Networks | Purpose |
|-----------|-------|----------|---------|
| `sentinel-controller` | Custom (Python 3.12/FastAPI) | sentinel_internal + sentinel_egress | Security gateway, orchestrator, policy engine |
| `sentinel-qwen` | `ollama/ollama` (pinned digest) | sentinel_internal ONLY | Air-gapped LLM worker (Qwen 3 14B Q4_K_M) |
| `sentinel-ui` | nginx (pinned digest) | sentinel_egress | WebUI chat interface — HTTPS on port 3001 |

### Container Config

**sentinel-qwen:**
- GPU: RTX 3060 12GB via CDI (`nvidia.com/gpu=all`)
- Volume: `sentinel-ollama-data:/root/.ollama`
- `OLLAMA_KEEP_ALIVE=5m` (release GPU after idle)
- No host ports, no internet
- Resources: 14GB RAM / 4 CPU, health checked (bash TCP to 11434)
- Image pinned to sha256 digest

**sentinel-controller:**
- Ollama: `http://sentinel-qwen:11434`, model `qwen3:14b`
- MQTT: `host.containers.internal:1883` (existing mosquitto)
- Topics: `sentinel/tasks`, `sentinel/results`, `sentinel/approval`
- Volumes: `sentinel-workspace:/workspace`, `./policies:/policies:ro`, `./logs:/logs` (host bind mount)
- Secrets: `claude_api_key`, `sentinel_pin` via Podman secrets (from `~/.secrets/`)
- PIN auth: `SENTINEL_PIN_REQUIRED=true`, PIN file at `/run/secrets/sentinel_pin`
- Resources: 4GB RAM (1GB reserved) / 4 CPU, read-only FS, health checked (python urllib to /health)
- CSRF protection: origin header validation (allowed origins configurable)
- Request size limit: 1MB (nginx + FastAPI middleware)

**sentinel-ui:**
- Image: nginx (pinned digest), static files + reverse proxy
- Port: `3001:8443` (HTTPS), `3002:8080` (HTTP redirect)
- TLS: self-signed cert generated at build time
- Proxies `/api/*` to `http://sentinel-controller:8000/` (strips `/api` prefix)
- 300s proxy read timeout (LLM calls take time)
- Network: `sentinel_egress` only (needs to reach controller)
- Resources: 128MB RAM / 1 CPU, read-only FS (tmpfs for nginx cache/PID), health checked
- Security headers: CSP, HSTS, X-Frame-Options DENY, nosniff, XSS-Protection, Referrer-Policy

---

## Networks

| Network | Type | Purpose |
|---------|------|---------|
| `sentinel_internal` | bridge, `internal: true` | **Air gap** — Qwen <-> Controller only, no external routing. Subnet `172.30.0.0/24` |
| `sentinel_egress` | bridge | Controller internet access (Claude API) + MQTT via host |

---

## Security Layers (9 total)

| # | Layer | Type | What It Catches | Phase |
|---|-------|------|-----------------|-------|
| 1 | **PIN Authentication** | ASGI middleware | Unauthenticated API access — `X-Sentinel-Pin` header, `/health` exempt | 5+ |
| 2 | **Policy Engine** | Deterministic YAML | File paths, commands, credentials, network — cannot be bypassed by prompt injection. Includes relative path resolution and podman flag deny-list | 1+5+ |
| 3 | **Spotlighting** | String manipulation | Prompt injection (~50% -> <3% success rate) — zero compute cost | 2 |
| 4 | **Prompt Guard 2** | 86M BERT classifier (CPU) | Injection detection (~67% catch rate) — 512 token window | 2 |
| 5 | **Llama Guard 4** | 12B content safety model | Harmful content (violence, hate, weapons) — GPU or CPU | 5 (skipped) |
| 6 | **CodeShield** | Semgrep static analysis (codeshield pkg) | Malicious code patterns (os.system, eval, SQL injection, traversal, shells, weak crypto) — scans ALL Qwen output | 3+5 |
| 7 | **CommandPatternScanner** | Regex patterns | Dangerous shell patterns in prose (pipe-to-shell, reverse shells, nohup, base64 decode+exec) | 5 |
| 8 | **ConversationAnalyzer** | Multi-turn heuristics | Memory poisoning, retry-after-block, capability escalation, instruction override, context building — 6 rules, additive scoring | 5+ |
| 9 | **CaMeL Provenance** | Data tagging | Untrusted data reaching dangerous destinations — architectural guarantee | 1 |

---

## Policy Engine — Key Rules

**File access:** Write/read allowed only in `/workspace/**`. Blocked: `/etc/**`, `.ssh/`, `.gnupg/`, `*.env`, `*.key`, `*.pem`, `wallet.dat`, `.bitcoin/`

**Commands allowed:** `podman build/run/stop/ps/images/logs`, `ls`, `cat`, `mkdir`, `cp`, `head`, `tail`, `wc`, `grep`, `find` (path-constrained)

**Commands blocked:** `rm -rf`, `curl`, `wget`, `ssh`, `python -c`, `bash -c`, `eval`, `exec`, pipe to shell, `chmod`, `systemctl`, and more (see policy YAML)

**Network:** Qwen outbound = none. Controller allowed: `api.anthropic.com:443`, `mosquitto:1883`, `sentinel-qwen:11434`

**Human approval required for:** port mappings (`-p`), volume mounts (`-v`), writes outside `/workspace`, unlisted commands, actions using untrusted web data

**Approval modes:** `full` (approve everything — start here) -> `smart` (auto-approve whitelisted) -> `auto`

---

## Provenance Tracking

Every data item tagged with:
- `trust_level`: "trusted" (user/Claude) or "untrusted" (Qwen/web/file)
- `source`: user, claude, qwen, web, file, tool
- `scan_results`: output from all scanners
- `derived_from`: parent data IDs (provenance chain)

**Rules:** Untrusted data cannot reach shell commands or network tools without scanning + approval. Trust level inherits — anything derived from untrusted stays untrusted.

---

## File Structure

```
~/sentinel/
├── podman-compose.yaml
├── policies/
│   └── sentinel-policy.yaml         # All security rules
├── controller/
│   ├── Dockerfile
│   ├── requirements.txt
│   └── app/
│       ├── main.py                  # FastAPI entry, all endpoints (see API Endpoints below)
│       ├── auth.py                  # PIN authentication middleware (Phase 5+)
│       ├── config.py                # Environment config (pydantic-settings)
│       ├── policy_engine.py         # YAML policy loader + path/command validators
│       ├── scanner.py               # Credential + sensitive path regex scanners
│       ├── provenance.py            # TaggedData + trust inheritance + chain walking
│       ├── audit.py                 # Structured JSON logging (daily rotation)
│       ├── models.py                # Pydantic models (TrustLevel, ScanResult, TaggedData, Plan, etc.)
│       ├── spotlighting.py          # Datamarking preprocessor (Phase 2)
│       ├── worker.py                # Ollama/Qwen async client (Phase 2)
│       ├── prompt_guard.py          # Prompt Guard 2 ML scanner (Phase 2)
│       ├── pipeline.py              # Security scan pipeline orchestrator (Phase 2)
│       ├── planner.py               # Claude API client + JSON plan generation (Phase 3)
│       ├── orchestrator.py          # CaMeL execution loop: plan → execute → scan (Phase 3)
│       ├── tools.py                 # Tool executor with policy checks (Phase 3)
│       ├── codeshield.py            # CodeShield async wrapper + semgrep patch (Phase 3+5)
│       ├── approval.py              # HTTP approval manager with TTL queue (Phase 3)
│       ├── session.py               # Session store + conversation turn tracking (Phase 5+)
│       └── conversation.py          # Multi-turn conversation analyzer — 6 heuristic rules (Phase 5+)
├── controller/tests/
│   ├── conftest.py                  # Shared fixtures (engine, scanners)
│   ├── test_policy_engine.py        # Policy rule unit tests
│   ├── test_scanner.py              # Credential + path scanner tests
│   ├── test_provenance.py           # Trust tagging + chain tests
│   ├── test_spotlighting.py         # Datamarking round-trip tests (Phase 2)
│   ├── test_worker.py               # Ollama client tests, mocked (Phase 2)
│   ├── test_prompt_guard.py         # Prompt Guard scan tests, mocked (Phase 2)
│   ├── test_pipeline.py             # Full pipeline integration tests (Phase 2)
│   ├── test_hostile.py              # Mock hostile Qwen attack simulations (Phase 2)
│   ├── test_planner.py              # Claude planner tests, mocked API (Phase 3)
│   ├── test_orchestrator.py         # Orchestrator CaMeL loop tests (Phase 3)
│   ├── test_tools.py                # Tool executor + policy check tests (Phase 3)
│   ├── test_codeshield.py           # CodeShield scanner tests (Phase 3+5)
│   ├── test_approval.py             # Approval flow + integration tests (Phase 3)
│   ├── test_hardening.py            # Phase 5 hardening regression tests
│   ├── test_conversation.py         # Multi-turn conversation tracking tests (Phase 5+)
│   └── test_pin_auth.py             # PIN authentication middleware tests (Phase 5+)
├── gateway/
│   ├── Dockerfile                   # nginx:alpine + static files
│   ├── nginx.conf                   # Static serving + /api proxy to controller
│   └── static/
│       ├── index.html               # Chat interface (single page)
│       ├── style.css                # Dark theme styling
│       └── app.js                   # Chat logic, API calls, approval flow
├── scripts/
│   ├── stress_test.py               # Adversarial stress test — 741 requests (100 genuine + 641 adversarial)
│   ├── run_stress_test.sh           # Unattended runner: auto mode, rebuild, health check, restore on exit
│   ├── .gitignore                   # Excludes results/ from git
│   └── results/                     # JSONL results + runner logs (gitignored)
├── docs/
│   ├── PROJECT_DOCS.md              # This file
│   ├── project-sentinel-build-plan.md
│   └── archive/
└── CLAUDE.md
```

---

## Key Dependencies

```
# Installed (Phase 1-3)
fastapi>=0.115.0          uvicorn>=0.34.0
httpx>=0.28.0             pyyaml>=6.0
pydantic>=2.10.0          pydantic-settings>=2.7.0
python-json-logger>=3.0.0
transformers>=4.47.0      torch>=2.5.0 (CPU-only index)
anthropic>=0.42.0         codeshield>=0.1.0 (includes semgrep)
pytest>=8.3.0             pytest-asyncio>=0.25.0

# Not yet installed (future phases)
paho-mqtt>=2.1.0
```

---

## Build Phases

| Phase | Goal | Key Deliverable |
|-------|------|-----------------|
| **1** | Controller + Policy Engine | Deterministic security controls, full test suite, zero LLM |
| **2** | Qwen Worker | Air-gapped LLM, scan pipeline, spotlighting, hostile tests |
| **3** | Claude Planner | Full CaMeL pipeline, tools, approval flow, end-to-end |
| **4** | Interfaces | Signal + WebUI integration, conversational approval |
| **5** | Hardening | Llama Guard 4, red teaming, tuning, performance benchmarks |

**Current status:** Phase 5+ — All 4 tiers complete, all 15 code review issues closed. Infrastructure hardened (TLS, CSP, CSRF, resource limits, read-only FS, pinned images, health checks). 415 tests passing

> Signal integration planned but paused. Plan archived: `docs/archive/2026-02-12_phase4a-signal-mqtt-plan.md`.
> CodeShield fix details: `docs/archive/2026-02-13_codeshield-fix.md`

---

## Trust Levels (incremental)

| Level | Qwen Can Do | Approval Mode | Progress Criteria |
|-------|-------------|---------------|-------------------|
| 0 | Text in/out only | All plans require human approval | Starting point |
| 1 | Text in/out only | Auto-approve whitelisted actions | 50+ tasks, zero incidents |
| 2 | + Read-only file access via Controller | As Level 1 | Red team passes at L1 |
| 3 | + Write to /workspace via Controller | /workspace writes auto-approved | Red team passes at L2 |
| 4 | + Sandboxed shell (bubblewrap) | Restricted shell in sandbox | Only if needed |

---

## Server Context (thebeast)

- **CPU:** Ryzen 7 5700X (8c/16t) | **RAM:** 64GB (43GB available) | **GPU:** RTX 3060 12GB
- **Storage:** 915GB NVMe, 492GB free | **Swap:** 8GB
- **Existing:** 27 other containers — do NOT touch. GPU shared via Ollama load/unload
- **MQTT:** mosquitto on port 1883 (integration point for Signal)
- **VRAM note:** Qwen 14B Q4 (~10GB) + Llama Guard 12B Q4 (~8GB) = 18GB > 12GB VRAM. Cannot coexist. Options: sequential GPU loading, CPU-only Guard, or defer Guard to Phase 5 (recommended)

---

## API Endpoints

| Method | Path | Phase | Purpose |
|--------|------|-------|---------|
| `GET` | `/health` | 1 | Status check — policy, Prompt Guard, CodeShield, planner, PIN auth. **Exempt from PIN auth** |
| `GET` | `/validate/path?path=...&operation=read` | 1 | Policy check for file path |
| `GET` | `/validate/command?command=...` | 1 | Policy check for shell command |
| `POST` | `/scan` | 2 | Run all scanners on text `{"text": "..."}` |
| `POST` | `/process` | 2 | Full Qwen pipeline: scan → spotlight → Qwen → scan |
| `POST` | `/task` | 3 | **Full CaMeL pipeline**: Claude plans → approve → Qwen executes → scanned. Accepts optional `session_id` for conversation tracking |
| `GET` | `/approval/{id}` | 3 | Check approval status (pending/approved/denied/expired). Pending responses include full step details: `prompt`, `tool`, `args`, `expects_code` |
| `POST` | `/approve/{id}` | 3 | Submit decision `{"granted": true/false, "reason": "..."}` |
| `GET` | `/session/{id}` | 5+ | Debug: view session state, turn history, risk scores |

### CaMeL Task Flow (POST /task)

```
User request → Conversation analysis (multi-turn check) → Prompt Guard scan
  → Claude plans → Approval gate
  → For each step:
      llm_task: resolve vars → Qwen generates → CodeShield (all output) → output scan
      tool_call: resolve vars → policy check → execute → tag as TRUSTED
  → TaskResult returned (includes ConversationInfo)
```

In `full` approval mode, `/task` returns `{"status": "awaiting_approval", "approval_id": "..."}`. Poll `/approval/{id}` then submit via `/approve/{id}`.

---

## Quick Commands

```bash
# Local tests (all phases, mocked deps)
PYTHONPATH=controller .venv/bin/python -m pytest controller/tests/ -v

# Container tests
podman exec sentinel-controller pytest /app/tests/ -v

# Health check (direct)
curl http://localhost:8000/health

# Health check (via WebUI proxy — HTTPS, self-signed)
curl -k https://localhost:3001/api/health

# WebUI (HTTPS — accept self-signed cert warning in browser)
# Open https://thebeast:3001 in browser

# Full CaMeL pipeline (Phase 3) — returns approval_id in full mode
# Note: all endpoints except /health require X-Sentinel-Pin header when PIN auth is enabled
curl -X POST http://localhost:8000/task -H 'Content-Type: application/json' \
  -H 'X-Sentinel-Pin: <your-pin>' \
  -d '{"request": "Write me a hello world page in HTML"}'

# Check approval status
curl -H 'X-Sentinel-Pin: <your-pin>' http://localhost:8000/approval/<approval_id>

# Approve and execute
curl -X POST http://localhost:8000/approve/<approval_id> \
  -H 'Content-Type: application/json' -H 'X-Sentinel-Pin: <your-pin>' \
  -d '{"granted": true, "reason": "Looks good"}'

# Scan text (Phase 2)
curl -X POST http://localhost:8000/scan -H 'Content-Type: application/json' \
  -H 'X-Sentinel-Pin: <your-pin>' \
  -d '{"text": "check this text for problems"}'

# Process via Qwen pipeline (Phase 2)
curl -X POST http://localhost:8000/process -H 'Content-Type: application/json' \
  -d '{"text": "Write hello world in HTML"}'

# Verify air gap
podman exec sentinel-qwen ping -c1 8.8.8.8        # should FAIL
podman exec sentinel-qwen curl https://google.com  # should FAIL

# Build controller with Prompt Guard model
podman build --secret id=hf_token,src=/home/kifterz/.secrets/hf_token.txt \
  -t sentinel_sentinel-controller controller/

# ── Stress Test ──────────────────────────────────────────────
# Run full overnight stress test (741 requests, handles auto mode + restore)
nohup ./scripts/run_stress_test.sh &

# Check stress test progress
wc -l scripts/results/stress_test_*.jsonl
tail -5 scripts/results/stress_test_*.jsonl | python3 -m json.tool
tail -20 scripts/results/nohup_output*.log

# Check if stress test is still running
ps aux | grep stress_test | grep -v grep

# View controller logs during stress test
podman logs --tail 50 sentinel-controller
```
