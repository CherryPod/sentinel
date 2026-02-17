#!/bin/bash
# Sentinel Benchmark Runner
#
# Runs the standard benchmark (1,136 prompts) against the live stack.
# Handles approval mode switching and cleanup on exit.
#
# By default, runs in the background via nohup so it survives terminal
# disconnects. Use --foreground to run in the current terminal instead.
#
# Prerequisites:
#   - sentinel + sentinel-ollama containers running and healthy
#   - PIN file at ~/.secrets/sentinel_pin.txt
#
# Usage:
#   ./scripts/run_benchmark.sh --version v0.2.0-alpha   # launches in background
#   ./scripts/run_benchmark.sh --foreground              # runs in current terminal
#   ./scripts/run_benchmark.sh --max-requests 50         # short test run
#   ./scripts/run_benchmark.sh --trust-level 4           # run at TL4 (restores original TL on exit)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
COMPOSE_FILE="$PROJECT_DIR/podman-compose.yaml"
LOG_FILE="$PROJECT_DIR/benchmarks/runner_$(date +%Y%m%d_%H%M%S).log"

# Ensure benchmarks directory exists
mkdir -p "$PROJECT_DIR/benchmarks"

# ── Auto-detach (default: run in background via nohup) ───────────
# Use --foreground / --fg to run in the current terminal instead.

_FOREGROUND=0
_BENCHMARK_TL=""
_PASSTHROUGH_ARGS=()
_SKIP_NEXT=0
for i in $(seq 1 $#); do
    arg="${!i}"
    if [ "$_SKIP_NEXT" -eq 1 ]; then
        _SKIP_NEXT=0
        continue
    fi
    case "$arg" in
        --foreground|--fg) _FOREGROUND=1 ;;
        --trust-level)
            next_i=$((i + 1))
            _BENCHMARK_TL="${!next_i}"
            _SKIP_NEXT=1
            ;;
        *) _PASSTHROUGH_ARGS+=("$arg") ;;
    esac
done

if [ "$_FOREGROUND" -eq 0 ] && [ -z "${_BENCHMARK_DETACHED:-}" ]; then
    # Re-exec with nohup so it survives terminal close
    export _BENCHMARK_DETACHED=1
    _REEXEC_ARGS=(--foreground)
    [ -n "$_BENCHMARK_TL" ] && _REEXEC_ARGS+=(--trust-level "$_BENCHMARK_TL")
    nohup "$0" "${_REEXEC_ARGS[@]}" "${_PASSTHROUGH_ARGS[@]}" > "$LOG_FILE" 2>&1 &
    BGPID=$!
    echo "Benchmark launched in background (PID $BGPID)"
    echo "  Log:    $LOG_FILE"
    echo "  Follow: tail -f $LOG_FILE"
    echo "  Stop:   kill -TERM $BGPID"
    exit 0
fi

# If running detached, log to file only (no tee — no terminal to write to)
if [ -n "${_BENCHMARK_DETACHED:-}" ]; then
    # nohup already redirected stdout/stderr to LOG_FILE, nothing to do
    :
else
    # Foreground mode: log to both console and file
    exec > >(tee -a "$LOG_FILE") 2>&1
fi

echo "============================================================"
echo "  Sentinel Benchmark Runner"
echo "  $(date)"
echo "  Log: $LOG_FILE"
echo "  Mode: $([ -n "${_BENCHMARK_DETACHED:-}" ] && echo 'background (nohup)' || echo 'foreground')"
echo "============================================================"
echo

# ── Step 0: Pre-flight checks ────────────────────────────────────

echo "[0/4] Pre-flight checks..."

if [ ! -f "$COMPOSE_FILE" ]; then
    echo "  ERROR: Compose file not found: $COMPOSE_FILE"
    exit 1
fi

if [ ! -f "$HOME/.secrets/sentinel_pin.txt" ]; then
    echo "  ERROR: PIN file not found: ~/.secrets/sentinel_pin.txt"
    exit 1
fi

# Check containers are running
if ! podman ps --format "{{.Names}}" | grep -q '^sentinel$'; then
    echo "  ERROR: sentinel container not running"
    echo "  Start with: podman compose up -d"
    exit 1
fi

if ! podman ps --format "{{.Names}}" | grep -q '^sentinel-ollama$'; then
    echo "  ERROR: sentinel-ollama container not running"
    exit 1
fi

CURRENT_MODE=$(grep 'SENTINEL_APPROVAL_MODE=' "$COMPOSE_FILE" | head -1 | cut -d= -f2)
CURRENT_TL=$(grep 'SENTINEL_TRUST_LEVEL=' "$COMPOSE_FILE" | head -1 | cut -d= -f2)
echo "  Current approval mode: $CURRENT_MODE"
echo "  Current trust level: $CURRENT_TL"
echo "  Compose file: $COMPOSE_FILE"
echo "  Containers: sentinel + sentinel-ollama running"
echo

# ── Step 1: Switch to benchmark mode ─────────────────────────────

echo "[1/4] Switching to benchmark mode (auto approval + verbose results + benchmark sessions)..."

# Always restore on exit (even on error or kill)
restore_settings() {
    echo
    echo "[cleanup] Restoring production settings..."
    sed -i 's/SENTINEL_APPROVAL_MODE=auto/SENTINEL_APPROVAL_MODE=full/' "$COMPOSE_FILE"
    sed -i 's/SENTINEL_VERBOSE_RESULTS=true/SENTINEL_VERBOSE_RESULTS=false/' "$COMPOSE_FILE"
    sed -i 's/SENTINEL_BENCHMARK_MODE=true/SENTINEL_BENCHMARK_MODE=false/' "$COMPOSE_FILE"
    # Restore trust level to pre-benchmark value
    if [ -n "$_BENCHMARK_TL" ]; then
        sed -i "s/SENTINEL_TRUST_LEVEL=${_BENCHMARK_TL}/SENTINEL_TRUST_LEVEL=${CURRENT_TL}/" "$COMPOSE_FILE"
        echo "  Trust level restored to: $CURRENT_TL"
    fi

    echo "[cleanup] Restarting sentinel container with production settings..."
    cd "$PROJECT_DIR"
    podman compose down 2>/dev/null || true
    sleep 3
    podman compose up -d
    echo "[cleanup] Done. Production settings restored, containers restarted."
}
trap restore_settings EXIT

sed -i 's/SENTINEL_APPROVAL_MODE=full/SENTINEL_APPROVAL_MODE=auto/' "$COMPOSE_FILE"
sed -i 's/SENTINEL_VERBOSE_RESULTS=false/SENTINEL_VERBOSE_RESULTS=true/' "$COMPOSE_FILE"
sed -i 's/SENTINEL_BENCHMARK_MODE=false/SENTINEL_BENCHMARK_MODE=true/' "$COMPOSE_FILE"
echo "  Approval mode set to: auto"
echo "  Verbose results: enabled"
echo "  Benchmark mode: enabled (per-prompt sessions, H-003 relaxed)"
# Set trust level if specified
if [ -n "$_BENCHMARK_TL" ]; then
    sed -i "s/SENTINEL_TRUST_LEVEL=${CURRENT_TL}/SENTINEL_TRUST_LEVEL=${_BENCHMARK_TL}/" "$COMPOSE_FILE"
    echo "  Trust level set to: $_BENCHMARK_TL (was: $CURRENT_TL)"
fi
echo

# ── Step 2: Restart containers with benchmark settings ────────────

echo "[2/4] Restarting containers with benchmark settings..."

cd "$PROJECT_DIR"
podman compose down 2>/dev/null || true
sleep 3
podman compose up -d

echo "  Containers restarted."
echo

# ── Step 3: Wait for health ───────────────────────────────────────

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
        for k in ('planner_available', 'semgrep_loaded', 'prompt_guard_loaded', 'pin_auth_enabled', 'conversation_tracking'):
            v = r.get(k)
            print(f'    {k}: {v}')
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
    echo "  Check logs: podman logs sentinel"
    exit 1
fi

# ── Step 4: Run the benchmark ─────────────────────────────────────

echo "[4/4] Starting benchmark..."
echo "  This will run for ~15 hours."
echo "  Results will be saved to: $PROJECT_DIR/benchmarks/"
echo "  To stop gracefully: kill -TERM $$"
echo

# Pass through CLI arguments to stress_test_v3.py.
# Filter out args consumed by this wrapper script.
_BENCH_ARGS=()
_SKIP_BENCH=0
for arg in "$@"; do
    if [ "$_SKIP_BENCH" -eq 1 ]; then
        _SKIP_BENCH=0
        continue
    fi
    case "$arg" in
        --foreground|--fg) ;;
        --trust-level) _SKIP_BENCH=1 ;;
        *) _BENCH_ARGS+=("$arg") ;;
    esac
done
python3 "$SCRIPT_DIR/stress_test_v3.py" "${_BENCH_ARGS[@]}"

echo
echo "============================================================"
echo "  Benchmark finished at $(date)"
echo "  Runner log: $LOG_FILE"
echo "  Results: $PROJECT_DIR/benchmarks/"
echo "============================================================"
