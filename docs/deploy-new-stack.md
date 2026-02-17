# Deploy New Stack — Migration Guide

Step-by-step instructions to replace the old 3-container stack with the new 2-container stack.

**Old stack (to be retired):**
- `sentinel-controller` (port 8000) + `sentinel-qwen` + `sentinel-ui` (ports 3001/3002)
- Compose: `podman-compose.yaml` (old version, now overwritten)

**New stack:**
- `sentinel` (ports 3001/3002, HTTPS + HTTP redirect, serves UI directly)
- `sentinel-ollama` (air-gapped, GPU, reuses existing model data)
- Compose: `podman-compose.yaml`

**Time estimate:** ~15 minutes (plus ~5 minutes for image build)

---

## Prerequisites

### 1. Secrets

The new stack reads secrets from `./secrets/` (project-relative). Copy from your existing location:

```bash
cd ~/sentinel

# Create secrets dir if needed
mkdir -p secrets
chmod 700 secrets

# Copy existing secrets
cp ~/.secrets/claude_api_key.txt secrets/claude_api_key.txt
cp ~/.secrets/sentinel_pin.txt secrets/sentinel_pin.txt

# Verify HF token exists (needed for image build only)
ls ~/.secrets/hf_token.txt
```

### 2. Logs directory

```bash
mkdir -p logs
```

### 3. Verify GPU access

```bash
podman info --format '{{.Host.CDIDevices}}' | grep nvidia
```

---

## Step 1: Stop the Old Stack

```bash
cd ~/sentinel

# Stop old containers (dependency order: UI -> controller -> Ollama)
podman stop sentinel-ui sentinel-controller sentinel-qwen
podman rm sentinel-ui sentinel-controller sentinel-qwen
```

Verify they're gone:
```bash
podman ps -a --format '{{.Names}}' | grep sentinel
# Should return nothing
```

**Note:** This frees ports 3001, 3002, and 8000, and releases GPU VRAM.

---

## Step 2: Build the Sentinel Image

The controller image needs a HuggingFace token at build time to download the Prompt Guard 2 model (~350MB). `podman compose build` doesn't support `--secret`, so build manually:

```bash
podman build \
  --secret id=hf_token,src=$HOME/.secrets/hf_token.txt \
  -t sentinel:latest \
  -t sentinel_sentinel:latest \
  -f container/Containerfile .
```

**Important:** Tag BOTH `sentinel:latest` AND `sentinel_sentinel:latest`. Podman compose adds a project prefix (`sentinel_`) and will silently use a stale image if only one tag exists.

This takes ~3-5 minutes on first build (downloads PyTorch CPU, transformers, Prompt Guard model). Subsequent builds use cache.

---

## Step 3: Start the New Stack

```bash
podman compose up -d
```

This creates:
- `sentinel` container on ports 3001 (HTTPS) and 3002 (HTTP redirect)
- `sentinel-ollama` container on internal network only (air-gapped)
- `sentinel_internal` network (bridge, `internal: true` — no internet)
- `sentinel_egress` network (bridge, internet access for Claude API)
- Volumes: `sentinel-data`, `sentinel-workspace`, `sentinel-ollama-data`

---

## Step 4: Pull the Qwen Model

The new `sentinel-ollama` container uses a fresh volume. You need to pull the model:

```bash
podman exec sentinel-ollama ollama pull qwen3:14b
```

This downloads ~8GB. Takes a few minutes depending on connection speed.

**Alternative — reuse existing model data:** If you want to skip the download, you can copy the model files from the old volume before starting (but starting fresh is simpler and avoids any version mismatches).

---

## Step 5: Verify

### Health check

```bash
# Should return JSON with status info
curl -sk https://localhost:3001/api/health | python3 -m json.tool
```

### Container health

```bash
# Wait ~60s for health checks to pass
podman ps --format '{{.Names}}\t{{.Status}}'
# Should show:
#   sentinel        Up X seconds (healthy)
#   sentinel-ollama Up X seconds (healthy)
```

### Smoke test

```bash
bash scripts/smoke_test.sh
```

This checks: health endpoints, PIN auth, HTTPS redirect, UI serving, air gap, security headers.

### WebUI

Open in browser: `https://localhost:3001`

Accept the self-signed certificate warning, enter your PIN, and send a test task (e.g., "Write a hello world function in Python").

### Air gap verification

```bash
# This should FAIL (timeout/connection refused = good)
podman exec sentinel-ollama bash -c \
  'echo -e "GET / HTTP/1.0\r\nHost: google.com\r\n\r\n" > /dev/tcp/google.com/80'
```

---

## Step 6: Cleanup (Optional)

Once the new stack is verified, remove old resources:

```bash
# Remove old networks (will fail if containers still reference them — that's fine)
podman network rm sentinel_internal 2>/dev/null
podman network rm sentinel_egress 2>/dev/null

# Remove old volumes (WARNING: destroys old workspace and Ollama model cache)
# Only do this after confirming the new stack works
podman volume rm sentinel-workspace 2>/dev/null
podman volume rm sentinel-ollama-data 2>/dev/null

# Remove old images
podman rmi sentinel-controller:latest 2>/dev/null
podman rmi sentinel_sentinel-controller:latest 2>/dev/null
podman rmi sentinel-ui:latest 2>/dev/null
podman rmi sentinel_sentinel-ui:latest 2>/dev/null
```

Also remove the old phase1 compose file (no longer needed):
```bash
rm podman-compose.phase1.yaml
```

---

## Troubleshooting

### Build fails: "secret not found"

```bash
# Verify the HF token file exists
cat ~/.secrets/hf_token.txt | head -c 5
# Should show "hf_..."
```

### Container won't start: "address already in use"

```bash
# Check what's using ports 3001/3002
ss -tlnp | grep -E '3001|3002'

# If old containers are still running
podman stop sentinel-ui sentinel-controller sentinel-qwen
podman rm sentinel-ui sentinel-controller sentinel-qwen
```

### Ollama container unhealthy

```bash
podman logs sentinel-ollama
# Common: GPU not available — check CDI config
podman info --format '{{.Host.CDIDevices}}'
```

### "Permission denied" on secrets

```bash
# Secrets must be readable by the user running podman
chmod 600 secrets/*.txt
ls -la secrets/
```

### Read-only filesystem errors

The sentinel container runs with `read_only: true`. If something tries to write outside `/tmp`, `/data`, `/workspace`, or `/logs`, it will fail. This is intentional — check the logs:

```bash
podman logs sentinel
```

---

## Access Methods

After deployment:

| Method | URL |
|--------|-----|
| WebUI (HTTPS) | `https://localhost:3001` |
| HTTP redirect | `http://localhost:3002` → redirects to HTTPS |
| API health | `curl -sk https://localhost:3001/api/health` |
| API task | `curl -sk -X POST https://localhost:3001/api/task -H 'X-Sentinel-Pin: <pin>' -H 'Content-Type: application/json' -d '{"request":"..."}'` |
| WebSocket | `wss://localhost:3001/ws` |
| SSE events | `https://localhost:3001/api/events` |
| MCP | `https://localhost:3001/mcp/` |

To access from other machines on the network, add your hostname/IP to `SENTINEL_ALLOWED_ORIGINS` in `podman-compose.yaml`:
```yaml
- SENTINEL_ALLOWED_ORIGINS=https://localhost:3001,https://localhost:3002,https://your-hostname:3001
```
