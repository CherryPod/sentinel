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
| `sentinel-qwen` | `ollama/ollama:latest` | sentinel_internal ONLY | Air-gapped LLM worker (Qwen 3 14B Q4_K_M) |
| `sentinel-ui` | Custom (Phase 4) | sentinel_egress | WebUI frontend on port 3001 |

### Container Config

**sentinel-qwen:**
- GPU: RTX 3060 12GB via CDI (`nvidia.com/gpu=all`)
- Volume: `sentinel-ollama-data:/root/.ollama`
- `OLLAMA_KEEP_ALIVE=5m` (release GPU after idle)
- No host ports, no internet

**sentinel-controller:**
- Ollama: `http://sentinel-qwen:11434`, model `qwen3:14b`
- MQTT: `host.containers.internal:1883` (existing mosquitto)
- Topics: `sentinel/tasks`, `sentinel/results`, `sentinel/approval`
- Volumes: `sentinel-workspace:/workspace`, `./policies:/policies:ro`, `sentinel-logs:/logs`
- Podman socket: `/run/podman/podman.sock:ro`
- Secrets: `claude_api_key` via Podman secrets (from `~/.secrets/`)

**sentinel-ui (Phase 4):**
- Port: `3001:8080` (avoids conflict with existing Open WebUI on 3000)
- Proxies to `http://sentinel-controller:8000`

---

## Networks

| Network | Type | Purpose |
|---------|------|---------|
| `sentinel_internal` | bridge, `internal: true` | **Air gap** — Qwen <-> Controller only, no external routing. Subnet `172.30.0.0/24` |
| `sentinel_egress` | bridge | Controller internet access (Claude API) + MQTT via host |

---

## Security Layers (6 total)

| # | Layer | Type | What It Catches | Phase |
|---|-------|------|-----------------|-------|
| 1 | **Policy Engine** | Deterministic YAML | File paths, commands, credentials, network — cannot be bypassed by prompt injection | 1 |
| 2 | **Spotlighting** | String manipulation | Prompt injection (~50% -> <3% success rate) — zero compute cost | 2 |
| 3 | **Prompt Guard 2** | 86M BERT classifier (CPU) | Injection detection (~67% catch rate) — 512 token window | 2 |
| 4 | **Llama Guard 4** | 12B content safety model | Harmful content (violence, hate, weapons) — GPU or CPU | 5 |
| 5 | **CodeShield** | Static analysis (LlamaFirewall) | Malicious code patterns (injection, traversal, shells, weak crypto) | 3 |
| 6 | **CaMeL Provenance** | Data tagging | Untrusted data reaching dangerous destinations — architectural guarantee | 1 |

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
│       ├── main.py                  # FastAPI entry, /health, /validate/*, /scan, /process
│       ├── config.py                # Environment config (pydantic-settings)
│       ├── policy_engine.py         # YAML policy loader + path/command validators
│       ├── scanner.py               # Credential + sensitive path regex scanners
│       ├── provenance.py            # TaggedData + trust inheritance + chain walking
│       ├── audit.py                 # Structured JSON logging (daily rotation)
│       ├── models.py                # Pydantic models (TrustLevel, ScanResult, TaggedData, etc.)
│       ├── spotlighting.py          # Datamarking preprocessor (Phase 2)
│       ├── worker.py                # Ollama/Qwen async client (Phase 2)
│       ├── prompt_guard.py          # Prompt Guard 2 ML scanner (Phase 2)
│       └── pipeline.py              # Security scan pipeline orchestrator (Phase 2)
├── controller/tests/
│   ├── conftest.py                  # Shared fixtures (engine, scanners)
│   ├── test_policy_engine.py        # Policy rule unit tests
│   ├── test_scanner.py              # Credential + path scanner tests
│   ├── test_provenance.py           # Trust tagging + chain tests
│   ├── test_spotlighting.py         # Datamarking round-trip tests (Phase 2)
│   ├── test_worker.py               # Ollama client tests, mocked (Phase 2)
│   ├── test_prompt_guard.py         # Prompt Guard scan tests, mocked (Phase 2)
│   ├── test_pipeline.py             # Full pipeline integration tests (Phase 2)
│   └── test_hostile.py              # Mock hostile Qwen attack simulations (Phase 2)
├── docs/
│   ├── PROJECT_DOCS.md              # This file
│   ├── project-sentinel-build-plan.md
│   └── archive/
└── CLAUDE.md
```

---

## Key Dependencies

```
# Installed (Phase 1 + 2)
fastapi>=0.115.0          uvicorn>=0.34.0
httpx>=0.28.0             pyyaml>=6.0
pydantic>=2.10.0          pydantic-settings>=2.7.0
python-json-logger>=3.0.0
transformers>=4.47.0      torch>=2.5.0 (CPU-only index)
pytest>=8.3.0             pytest-asyncio>=0.25.0

# Not yet installed (future phases)
anthropic>=0.42.0         paho-mqtt>=2.1.0
llamafirewall>=0.1.0
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

**Current status:** Phase 2 COMPLETE — 193 tests passing, both containers deployed and verified

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
- **Existing:** 27 containers — do NOT touch. GPU shared via Ollama load/unload
- **MQTT:** mosquitto on port 1883 (integration point for Signal)
- **VRAM note:** Qwen 14B Q4 (~10GB) + Llama Guard 12B Q4 (~8GB) = 18GB > 12GB VRAM. Cannot coexist. Options: sequential GPU loading, CPU-only Guard, or defer Guard to Phase 5 (recommended)

---

## Quick Commands

```bash
# Local tests (all phases, mocked deps)
PYTHONPATH=controller .venv/bin/python -m pytest controller/tests/ -v

# Container tests
podman exec sentinel-controller pytest /app/tests/ -v

# Health check
curl http://localhost:8000/health

# Scan text (Phase 2)
curl -X POST http://localhost:8000/scan -H 'Content-Type: application/json' \
  -d '{"text": "check this text for problems"}'

# Process via Qwen pipeline (Phase 2)
curl -X POST http://localhost:8000/process -H 'Content-Type: application/json' \
  -d '{"text": "Write hello world in HTML"}'

# Verify air gap
podman exec sentinel-qwen ping -c1 8.8.8.8        # should FAIL
podman exec sentinel-qwen curl https://google.com  # should FAIL

# Pull Qwen model
podman exec sentinel-qwen ollama pull qwen3:14b

# Check GPU
podman exec sentinel-qwen nvidia-smi

# Build controller with Prompt Guard model
podman build --secret id=hf_token,src=$HOME/.secrets/hf_token.txt \
  -t sentinel_sentinel-controller controller/
```
