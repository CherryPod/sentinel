#!/bin/bash
# TL0 Validation Runner
#
# Sends 60 genuine-only prompts to validate baseline behaviour at TL0.
# Handles approval mode switching and cleanup on exit.
# Runs in background via nohup by default (survives terminal disconnect).
#
# Prerequisites:
#   - sentinel + sentinel-ollama containers running and healthy
#   - PIN file at ~/.secrets/sentinel_pin.txt
#
# Usage:
#   ./scripts/run_tl0_validation.sh                   # 60 prompts, background
#   ./scripts/run_tl0_validation.sh --foreground       # run in current terminal
#   ./scripts/run_tl0_validation.sh --count 80         # more prompts

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
COMPOSE_FILE="$PROJECT_DIR/podman-compose.yaml"
VENV_PYTHON="$PROJECT_DIR/.venv/bin/python3"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
LOG_FILE="$PROJECT_DIR/benchmarks/tl0_validation_runner_${TIMESTAMP}.log"

# Ensure benchmarks directory exists
mkdir -p "$PROJECT_DIR/benchmarks"

# ── Auto-detach (default: run in background via nohup) ───────────

_FOREGROUND=0
_PASSTHROUGH_ARGS=()
for arg in "$@"; do
    case "$arg" in
        --foreground|--fg) _FOREGROUND=1 ;;
        *) _PASSTHROUGH_ARGS+=("$arg") ;;
    esac
done

if [ "$_FOREGROUND" -eq 0 ] && [ -z "${_VALIDATION_DETACHED:-}" ]; then
    export _VALIDATION_DETACHED=1
    nohup "$0" --foreground "${_PASSTHROUGH_ARGS[@]}" > "$LOG_FILE" 2>&1 &
    BGPID=$!
    echo "TL0 Validation launched in background (PID $BGPID)"
    echo "  Log:     $LOG_FILE"
    echo "  Follow:  tail -f $LOG_FILE"
    echo "  Stop:    kill -TERM $BGPID"
    exit 0
fi

# If running detached, nohup already redirects stdout/stderr to LOG_FILE.
# If foreground, tee to both console and file.
if [ -z "${_VALIDATION_DETACHED:-}" ]; then
    exec > >(tee -a "$LOG_FILE") 2>&1
fi

echo "============================================================"
echo "  TL0 Validation Runner"
echo "  Started: $(date)"
echo "  Log: $LOG_FILE"
echo "  Mode: $([ -n "${_VALIDATION_DETACHED:-}" ] && echo 'background (nohup)' || echo 'foreground')"
echo "============================================================"
echo

# ── Pre-flight checks ────────────────────────────────────────────

echo "[0/4] Pre-flight checks..."

if [ ! -f "$COMPOSE_FILE" ]; then
    echo "  ERROR: Compose file not found: $COMPOSE_FILE"
    exit 1
fi

if [ ! -f "$HOME/.secrets/sentinel_pin.txt" ]; then
    echo "  ERROR: PIN file not found: ~/.secrets/sentinel_pin.txt"
    exit 1
fi

if ! podman ps --format "{{.Names}}" | grep -q '^sentinel$'; then
    echo "  ERROR: sentinel container not running"
    exit 1
fi

if ! podman ps --format "{{.Names}}" | grep -q '^sentinel-ollama$'; then
    echo "  ERROR: sentinel-ollama container not running"
    exit 1
fi

CURRENT_MODE=$(grep 'SENTINEL_APPROVAL_MODE=' "$COMPOSE_FILE" | head -1 | cut -d= -f2)
echo "  Current approval mode: $CURRENT_MODE"
echo "  Containers: sentinel + sentinel-ollama running"
echo

# ── Switch to auto approval ──────────────────────────────────────

echo "[1/4] Switching to auto approval + verbose results..."

restore_settings() {
    echo
    echo "[cleanup] Restoring production settings..."
    sed -i 's/SENTINEL_APPROVAL_MODE=auto/SENTINEL_APPROVAL_MODE=full/' "$COMPOSE_FILE"
    sed -i 's/SENTINEL_VERBOSE_RESULTS=true/SENTINEL_VERBOSE_RESULTS=false/' "$COMPOSE_FILE"

    echo "[cleanup] Restarting sentinel container..."
    cd "$PROJECT_DIR"
    podman compose down 2>/dev/null || true
    sleep 3
    podman compose up -d
    echo "[cleanup] Production settings restored."
    echo "[cleanup] Finished: $(date)"
}
trap restore_settings EXIT

sed -i 's/SENTINEL_APPROVAL_MODE=full/SENTINEL_APPROVAL_MODE=auto/' "$COMPOSE_FILE"
sed -i 's/SENTINEL_VERBOSE_RESULTS=false/SENTINEL_VERBOSE_RESULTS=true/' "$COMPOSE_FILE"
echo "  Approval mode: auto"
echo "  Verbose results: enabled"
echo

# ── Restart containers ────────────────────────────────────────────

echo "[2/4] Restarting containers with validation settings..."

cd "$PROJECT_DIR"
podman compose down 2>/dev/null || true
sleep 3
podman compose up -d

echo "  Containers restarted."
echo

# ── Wait for health ──────────────────────────────────────────────

echo "[3/4] Waiting for sentinel to become healthy..."

MAX_HEALTH_WAIT=120
HEALTH_INTERVAL=5
elapsed=0

while [ $elapsed -lt $MAX_HEALTH_WAIT ]; do
    if python3 -c "
import urllib.request, ssl, json, sys
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
try:
    r = json.loads(urllib.request.urlopen('https://localhost:3001/health', context=ctx, timeout=5).read())
    if r.get('status') == 'ok':
        print('  Health check: OK')
        sys.exit(0)
    sys.exit(1)
except Exception:
    sys.exit(1)
" 2>/dev/null; then
        echo
        break
    fi

    elapsed=$((elapsed + HEALTH_INTERVAL))
    echo "  Waiting... (${elapsed}s / ${MAX_HEALTH_WAIT}s)"
    sleep $HEALTH_INTERVAL
done

if [ $elapsed -ge $MAX_HEALTH_WAIT ]; then
    echo "  ERROR: sentinel did not become healthy after ${MAX_HEALTH_WAIT}s"
    exit 1
fi

# ── Run validation ───────────────────────────────────────────────

echo "[4/4] Running TL0 validation..."
echo

# Pass through args (with --foreground/--fg already stripped)
_BENCH_ARGS=()
for arg in "$@"; do
    case "$arg" in
        --foreground|--fg) ;;
        *) _BENCH_ARGS+=("$arg") ;;
    esac
done
"$VENV_PYTHON" "$SCRIPT_DIR/tl0_validation.py" "${_BENCH_ARGS[@]}"

echo
echo "============================================================"
echo "  TL0 Validation finished at $(date)"
echo "  Results: $PROJECT_DIR/benchmarks/"
echo "  Analyse: $VENV_PYTHON $SCRIPT_DIR/analyse_tl0_validation.py benchmarks/tl0_validation_*.jsonl"
echo "============================================================"
