# Project Sentinel

## What This Is
A defence-in-depth AI assistant built on the CaMeL architecture. Claude API (Planner) plans tasks, an air-gapped Qwen 3 14B (Worker) executes them, and a Python/FastAPI Controller enforces 10 layers of security scanning between every step. The worker LLM is assumed compromised at all times.

Phases 1-5 are complete: full pipeline operational, 562 unit tests, v3 stress test benchmarked (1,136 prompts, 0.12% real risk rate), infrastructure hardened. The project is being prepared for open-source release on GitHub (Apache-2.0).

**Next:** Code restructuring (Phase 0 of evolution plan) → memory system → multi-channel access → WASM tool sandbox. See `docs/roadmap.md` and `docs/design/evolution-plan.md`.

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
- `podman exec sentinel-controller pytest /app/tests/` — 562 tests
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
- `controller/app/orchestrator.py` — CaMeL execution loop
- `controller/app/planner.py` — Claude planner system prompt
- `controller/app/pipeline.py` — security scan pipeline
- `scripts/analyse_v3_results.py` — benchmark analysis
