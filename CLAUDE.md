# Project Sentinel

## Startup Context
At the start of every conversation, read `docs/design/evolution-tracker.md` and `docs/codebase-map.md` before doing anything else. After reading both, state: "Context loaded (sentinel-ready)"

## What This Is
A defence-in-depth AI assistant built on the CaMeL architecture. Claude API (Planner) plans tasks, an air-gapped Qwen 3 14B (Worker) executes them, and a Python/FastAPI Controller enforces 10 layers of security scanning between every step. The worker LLM is assumed compromised at all times.

Phases 1-5 complete, Phase 0 (foundation restructure) complete: proper `sentinel/` Python package, 598 unit tests, v3 stress test benchmarked (1,136 prompts, 0.12% real risk rate), SQLite schema, Rust sidecar skeleton, async event bus. Preparing for open-source release on GitHub (Apache-2.0).

**Next:** Phase 1 — Infrastructure Consolidation (nginx elimination, SQLite migration, trust router). See `docs/roadmap.md` and `docs/design/evolution-plan.md`.

## Tech Stack
- Python 3.12 / FastAPI (Controller)
- Podman (all containers, rootless, user kifterz)
- Ollama (Qwen 3 14B Q4_K_M, GPU-shared RTX 3060 12GB)

## Container Names
- `sentinel-controller` — security gateway + orchestrator
- `sentinel-qwen` — air-gapped local LLM (sentinel_internal network ONLY)
- `sentinel-ui` — WebUI frontend (nginx, HTTPS)

## Networks
- `sentinel_internal` — air-gapped, internal: true, no external routing
- `sentinel_egress` — internet access for Claude API

## Critical Safety Rules
- NEVER give sentinel-qwen internet access — the air gap is a core security layer
- NEVER trust Qwen output — always scan before acting on it
- NEVER store secrets in project files — use Podman secrets or ~/.secrets/
- NEVER modify existing containers (27 running) — this is a standalone stack
- All file operations constrained to /workspace/ inside containers
- GPU is shared — Ollama load/unload handles VRAM contention

## Testing
- Local: `.venv/bin/pytest tests/` — 598 tests
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
