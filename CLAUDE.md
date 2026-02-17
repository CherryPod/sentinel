# Project Sentinel

## Startup Context
At the start of every conversation, read `docs/design/evolution-tracker.md` and `docs/codebase-map.md` before doing anything else. After reading both, state: "Context loaded (sentinel-ready)"

## What This Is
A defence-in-depth AI assistant built on the CaMeL architecture. Claude API (Planner) plans tasks, an air-gapped Qwen 3 14B (Worker) executes them, and a Python/FastAPI Controller enforces 10 layers of security scanning between every step. The worker LLM is assumed compromised at all times. Progress tracked in `docs/design/evolution-tracker.md`.

## Tech Stack
- Python 3.12 / FastAPI (Controller)
- Podman (all containers, rootless, user kifterz)
- Ollama (Qwen 3 14B Q4_K_M, GPU-shared RTX 3060 12GB)

## Container Names (Phase 1 — not yet deployed)
- `sentinel-v2` — controller + UI + TLS (ports 3003/3004)
- `sentinel-ollama-v2` — air-gapped local LLM (sentinel_internal_v2 network ONLY)
- Compose: `podman-compose.phase1.yaml`

## Container Names (Legacy — still running)
- `sentinel-controller` — security gateway + orchestrator (port 8000)
- `sentinel-qwen` — air-gapped local LLM (sentinel_internal network ONLY)
- `sentinel-ui` — WebUI frontend (nginx, HTTPS, ports 3001/3002)

## Networks
- `sentinel_internal` / `sentinel_internal_v2` — air-gapped, internal: true, no external routing
- `sentinel_egress` / `sentinel_egress_v2` — internet access for Claude API

## Critical Safety Rules
- NEVER give sentinel-qwen internet access — the air gap is a core security layer
- NEVER trust Qwen output — always scan before acting on it
- NEVER store secrets in project files — use Podman secrets or ~/.secrets/
- NEVER modify existing containers (27 running) — this is a standalone stack
- All file operations constrained to /workspace/ inside containers
- GPU is shared — Ollama load/unload handles VRAM contention

## Testing
- Local: `.venv/bin/pytest tests/` — 1006 tests
- Container (legacy layout): `podman exec sentinel-controller pytest /app/tests/`
- Stress test: `python3 scripts/analyse_v3_results.py` (reads `benchmarks/v3-results.jsonl`)

## Documentation
| Doc | Purpose |
|-----|---------|
| `README.md` | Project overview, quick start, architecture diagram |
| `docs/architecture.md` | Containers, API endpoints, data flow, provenance |
| `docs/security-model.md` | 10 security layers, CaMeL trust model, threat model |
| `docs/deployment.md` | Build, deploy, rebuild, troubleshooting |
| `docs/roadmap.md` | Evolution plan summary, planned features |
| `docs/CHANGELOG.md` | Full version history with decision rationale |
| `docs/design/` | Active design docs (build plan, evolution plan, infrastructure) |
| `docs/assessments/` | Benchmark reports and security audits |
| `benchmarks/` | v3 stress test data + analysis scripts |

## Key Files
- `policies/sentinel-policy.yaml` — all security rules (deterministic layer)
- `sentinel/planner/orchestrator.py` — CaMeL execution loop
- `sentinel/planner/planner.py` — Claude planner system prompt
- `sentinel/security/pipeline.py` — security scan pipeline
- `sentinel/core/db.py` — SQLite database schema
- `sentinel/core/bus.py` — async event bus
- `scripts/analyse_v3_results.py` — benchmark analysis
