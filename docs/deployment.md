# Deployment Guide

Operations guide for building, deploying, and maintaining Sentinel.

## Prerequisites

| Requirement | Minimum | Recommended |
|-------------|---------|-------------|
| CPU | 4 cores | 8+ cores |
| RAM | 32 GB | 64 GB |
| GPU | 12 GB VRAM (NVIDIA) | RTX 3060 12GB or better |
| Storage | 20 GB free | 50 GB free |
| OS | Linux (kernel 5.x+) | Ubuntu 22.04+ |
| Podman | 4.0+ (rootless) | Latest stable |
| podman-compose | 1.0.6+ | Latest stable |
| NVIDIA Container Toolkit | Latest | With CDI configured |

**VRAM note:** Qwen 3 14B Q4_K_M uses ~10GB VRAM. If sharing the GPU with other Ollama models, `OLLAMA_KEEP_ALIVE=5m` releases VRAM after idle.

## Secret Management

Sentinel uses Podman secrets — never store secrets in project files.

```bash
# Create the secrets directory
mkdir -p ~/.secrets
chmod 700 ~/.secrets

# Anthropic API key (required for Claude planner)
echo "sk-ant-..." > ~/.secrets/claude_api_key.txt

# PIN for API authentication
echo "your-secure-pin" > ~/.secrets/sentinel_pin.txt

# HuggingFace token (required for building — downloads Prompt Guard model)
echo "hf_..." > ~/.secrets/hf_token.txt

# Lock down permissions
chmod 600 ~/.secrets/*.txt

# Register with Podman
podman secret create claude_api_key ~/.secrets/claude_api_key.txt
podman secret create sentinel_pin ~/.secrets/sentinel_pin.txt
```

## Building

### Controller (manual build required)

The controller needs a HuggingFace token at build time to download the Prompt Guard 2 model. `podman-compose build` doesn't support `--secret`, so build manually:

```bash
podman build \
  --secret id=hf_token,src=$HOME/.secrets/hf_token.txt \
  -t sentinel-controller:latest \
  -t sentinel_sentinel-controller:latest \
  -f controller/Dockerfile controller/
```

**Important:** Tag BOTH `sentinel-controller` AND `sentinel_sentinel-controller`. Podman compose adds a project prefix and will silently use an old image if the prefixed tag is stale.

### UI (compose build works)

```bash
podman compose build sentinel-ui
```

### Starting

```bash
podman compose up -d
```

## Verifying

```bash
# Health check (direct)
curl -sf http://localhost:8000/health | python3 -m json.tool

# Health check (via UI proxy — HTTPS, self-signed cert)
curl -k https://localhost:3001/api/health

# WebUI — open in browser (accept self-signed cert)
# https://your-hostname:3001

# Verify air gap
podman exec sentinel-qwen ping -c1 8.8.8.8        # should FAIL
podman exec sentinel-qwen curl https://google.com  # should FAIL

# Run tests
podman exec sentinel-controller pytest /app/tests/ -v
```

## Rebuilding After Code Changes

### Why rebuilding is tricky

1. **Image naming mismatch:** `podman build -t sentinel-controller` creates `sentinel-controller:latest`, but `podman compose up` looks for `sentinel_sentinel-controller:latest` (project prefix). Tag both names
2. **Compose won't recreate on image change:** `podman compose up -d` checks the compose config hash, not the image ID. Use `--force-recreate` or stop/rm/up
3. **Dependency chain blocks removal:** UI depends on controller depends on qwen. Stop in order: UI -> controller -> qwen
4. **Secret not passed by compose build:** Must build controller manually

### Clean rebuild procedure

```bash
# 1. Build controller (tag both names)
podman build \
  --secret id=hf_token,src=$HOME/.secrets/hf_token.txt \
  -t sentinel-controller:latest \
  -t sentinel_sentinel-controller:latest \
  -f controller/Dockerfile controller/

# 2. Stop and remove (dependency order)
podman stop sentinel-ui sentinel-controller sentinel-qwen
podman rm sentinel-ui sentinel-controller sentinel-qwen

# 3. Start fresh
podman compose up -d --force-recreate

# 4. Verify new code
podman exec sentinel-controller python -c "
from app.planner import _PLANNER_SYSTEM_PROMPT_TEMPLATE
print('Container running new code')
"

# 5. Health check
curl -sf http://localhost:8000/health | python3 -m json.tool
```

### Rebuilding the UI only

```bash
podman compose build sentinel-ui
podman stop sentinel-ui && podman rm sentinel-ui
podman compose up -d sentinel-ui
```

## Configuration Reference

Environment variables set in `podman-compose.yaml`:

| Variable | Default | Description |
|----------|---------|-------------|
| `SENTINEL_OLLAMA_URL` | `http://sentinel-qwen:11434` | Ollama API endpoint |
| `SENTINEL_OLLAMA_MODEL` | `qwen3:14b` | Worker model name |
| `SENTINEL_OLLAMA_TIMEOUT` | `1800` | Ollama request timeout (seconds) |
| `SENTINEL_PIN_REQUIRED` | `true` | Enable PIN authentication |
| `SENTINEL_PIN_FILE` | `/run/secrets/sentinel_pin` | PIN secret file path |
| `SENTINEL_ALLOWED_ORIGINS` | (see compose) | CSRF origin allowlist |
| `SENTINEL_CONVERSATION_ENABLED` | `true` | Multi-turn tracking |
| `SENTINEL_SESSION_TTL` | `3600` | Session timeout (seconds) |
| `SENTINEL_SESSION_MAX_COUNT` | `1000` | Max concurrent sessions |
| `SENTINEL_CONVERSATION_WARN_THRESHOLD` | `3.0` | Risk score warning level |
| `SENTINEL_CONVERSATION_BLOCK_THRESHOLD` | `5.0` | Risk score block level |
| `OLLAMA_KEEP_ALIVE` | `5m` | GPU VRAM release timeout |

## Running the API

```bash
# Full CaMeL pipeline — returns approval_id in full mode
curl -X POST http://localhost:8000/task \
  -H 'Content-Type: application/json' \
  -H 'X-Sentinel-Pin: <your-pin>' \
  -d '{"request": "Write a hello world page in HTML"}'

# Check approval status
curl -H 'X-Sentinel-Pin: <your-pin>' \
  http://localhost:8000/approval/<approval_id>

# Approve and execute
curl -X POST http://localhost:8000/approve/<approval_id> \
  -H 'Content-Type: application/json' \
  -H 'X-Sentinel-Pin: <your-pin>' \
  -d '{"granted": true, "reason": "Looks good"}'

# Scan text
curl -X POST http://localhost:8000/scan \
  -H 'Content-Type: application/json' \
  -H 'X-Sentinel-Pin: <your-pin>' \
  -d '{"text": "check this text for problems"}'
```

## Running Tests

```bash
# In-container (recommended)
podman exec sentinel-controller pytest /app/tests/ -v

# Local (requires Python 3.12 + venv with `pip install -e ".[dev]"`)
.venv/bin/pytest tests/ -v
```

## Stress Testing

```bash
# Run the v3 stress test (1,136 prompts, takes several hours)
nohup ./scripts/run_stress_test_v3.sh &

# Check progress
wc -l benchmarks/v3-results.jsonl

# Tail the runner log
tail -f benchmarks/v3-runner.log

# Analyse results
python3 scripts/analyse_v3_results.py
```

## Troubleshooting

### Container won't start

```bash
# Check logs
podman logs sentinel-controller
podman logs sentinel-qwen

# Verify health checks
podman inspect sentinel-controller --format '{{.State.Health.Status}}'
```

### Read-only filesystem errors

The controller runs with `read_only: true`. If a dependency tries to write (e.g., semgrep creating symlinks), the fix is to pre-create in the Dockerfile, not to disable read-only.

### GPU not available

```bash
# Check CDI is configured
podman info --format '{{.Host.CDIDevices}}'

# Check Ollama sees the GPU
podman exec sentinel-qwen ollama run qwen3:14b "test" --verbose 2>&1 | head -5
```

### Port conflicts

Sentinel uses ports 8000 (controller, internal), 3001 (HTTPS UI), and 3002 (HTTP redirect). Check for conflicts:

```bash
ss -tlnp | grep -E '8000|3001|3002'
podman ps --format '{{.Ports}}'
```
