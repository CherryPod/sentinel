# Project Sentinel

## What This Is
CaMeL-based defence-in-depth architecture: Claude API (Planner) + air-gapped Qwen 3 14B (Worker) + Python Controller (security gateway). See `docs/architecture.md` for full architecture.

## Tech Stack
- Python 3.12 / FastAPI (Controller)
- Podman (all containers, rootless, user kifterz)
- Ollama (Qwen 3 14B Q4_K_M, GPU-shared RTX 3060 12GB)
- MQTT (existing mosquitto on host, port 1883)

## Container Names
- `sentinel-controller` — security gateway + orchestrator
- `sentinel-qwen` — air-gapped local LLM (sentinel_internal network ONLY)
- `sentinel-ui` — WebUI frontend (Phase 4)

## Networks
- `sentinel_internal` — air-gapped, internal: true, no external routing
- `sentinel_egress` — internet access for Claude API + MQTT

## Critical Safety Rules
- NEVER give sentinel-qwen internet access — the air gap is a core security layer
- NEVER trust Qwen output — always scan before acting on it
- NEVER store secrets in project files — use Podman secrets or ~/.secrets/
- NEVER modify existing containers (27 running) — this is a standalone stack
- All file operations constrained to /workspace/ inside containers
- GPU is shared — Ollama load/unload handles VRAM contention

## Build Phases
Phase 1: Controller + Policy Engine (deterministic security)
Phase 2: Qwen Worker (air-gapped LLM)
Phase 3: Claude Planner (full CaMeL pipeline)
Phase 4: Interface Integration (Signal + WebUI)
Phase 5: Hardening + Llama Guard

## Testing
- `podman exec sentinel-controller pytest /app/tests/`
- Policy engine must pass ALL security test cases before any LLM integration

## Key Files
- `policies/sentinel-policy.yaml` — all security rules (deterministic layer)
- `controller/app/orchestrator.py` — main execution loop
- `docs/design/build-plan.md` — full build plan with architecture details
