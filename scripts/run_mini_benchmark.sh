#!/bin/bash
# Sentinel Mini Benchmark Runner
#
# Runs the mini benchmark (~114 prompts, ~1-2 hours) against the live stack.
# A 10%-scale cross-section of the full benchmark for rapid dev iteration.
# Handles approval mode switching and cleanup on exit.
#
# By default:
#   - Interactive terminal: runs in background via nohup
#   - Non-interactive (pipe, script, && chain): runs in foreground
#   Use --foreground to force foreground, --background to force background.
#
# Prerequisites:
#   - sentinel + sentinel-ollama containers running and healthy
#   - PIN file at ~/.secrets/sentinel_pin.txt
#
# Usage:
#   ./scripts/run_mini_benchmark.sh --version v0.4.0-alpha-tl4  # background
#   ./scripts/run_mini_benchmark.sh --foreground                 # foreground
#   ./scripts/run_mini_benchmark.sh --trust-level 4              # run at TL4
#   ./scripts/run_mini_benchmark.sh --no-signal                  # suppress Signal messages
#
# Files produced:
#   benchmarks/mini_benchmark_{version}_{timestamp}.jsonl
#   benchmarks/mini_runner_{timestamp}.log
#
# Analysis:
#   .venv/bin/python3 scripts/analyse_benchmark_results.py benchmarks/mini_benchmark_*.jsonl

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
COMPOSE_FILE="$PROJECT_DIR/podman-compose.yaml"
LOG_FILE="$PROJECT_DIR/benchmarks/mini_runner_$(date +%Y%m%d_%H%M%S).log"

# Ensure benchmarks directory exists
mkdir -p "$PROJECT_DIR/benchmarks"

# ── Signal — delegated to runner_lib.sh ──────────────────────────

# ── Auto-detach (default: run in background via nohup) ───────────

_FOREGROUND=0
_BACKGROUND=0
_BENCHMARK_TL=""
SIGNAL_ENABLED=1
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
        --background|--bg) _BACKGROUND=1; _FOREGROUND=0 ;;
        --no-signal) SIGNAL_ENABLED=0 ;;
        --trust-level)
            next_i=$((i + 1))
            _BENCHMARK_TL="${!next_i}"
            _SKIP_NEXT=1
            ;;
        *) _PASSTHROUGH_ARGS+=("$arg") ;;
    esac
done

# Default to foreground when called non-interactively (from another script,
# && chain, or pipe). This prevents the Run 14 bug where mini detached
# and its EXIT trap stomped Pipeline B's containers 5 hours later.
# Use --background to explicitly force background mode when needed.
if [ "$_FOREGROUND" -eq 0 ] && [ "$_BACKGROUND" -eq 0 ] && [ -z "${_BENCHMARK_DETACHED:-}" ]; then
    if [ -t 0 ]; then
        # Interactive terminal — auto-detach as before
        export _BENCHMARK_DETACHED=1
        _REEXEC_ARGS=(--foreground)
        [ -n "$_BENCHMARK_TL" ] && _REEXEC_ARGS+=(--trust-level "$_BENCHMARK_TL")
        [ "$SIGNAL_ENABLED" -eq 0 ] && _REEXEC_ARGS+=(--no-signal)
        nohup "$0" "${_REEXEC_ARGS[@]}" "${_PASSTHROUGH_ARGS[@]}" > "$LOG_FILE" 2>&1 &
        BGPID=$!
        echo "Mini benchmark launched in background (PID $BGPID)"
        echo "  Log:    $LOG_FILE"
        echo "  Follow: tail -f $LOG_FILE"
        echo "  Stop:   kill -TERM $BGPID"
        exit 0
    else
        # Non-interactive — run in foreground to block the caller
        _FOREGROUND=1
        echo "Non-interactive context detected — running in foreground."
        echo "  Use --background to force background mode."
    fi
fi

if [ -n "${_BENCHMARK_DETACHED:-}" ]; then
    :
else
    exec > >(tee -a "$LOG_FILE") 2>&1
fi

echo "============================================================"
echo "  Sentinel MINI Benchmark Runner"
echo "  $(date)"
echo "  Log: $LOG_FILE"
echo "  Mode: $([ -n "${_BENCHMARK_DETACHED:-}" ] && echo 'background (nohup)' || echo 'foreground')"
echo "============================================================"
echo

# ── Step 0: Pre-flight checks ────────────────────────────────────

echo "[0/5] Pre-flight checks..."

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

# Source shared runner library for compose locking, Signal, health checks
source "$SCRIPT_DIR/runner_lib.sh"
runner_lib_init "$PROJECT_DIR" "$COMPOSE_FILE"
[ "$SIGNAL_ENABLED" -eq 0 ] && runner_lib_signal_enabled 0

signal_notify "Mini benchmark starting (TL${_BENCHMARK_TL:-$CURRENT_TL}, ~134 prompts, ~2h). Log: $(basename "$LOG_FILE")" "[Mini]"

# ── Step 1: Switch to benchmark mode ─────────────────────────────

echo "[1/5] Switching to benchmark mode (auto approval + verbose results + benchmark sessions)..."

restore_settings() {
    echo
    echo "[cleanup] Restoring production settings..."
    acquire_compose_lock || true
    sed -i 's/SENTINEL_APPROVAL_MODE=auto/SENTINEL_APPROVAL_MODE=full/' "$COMPOSE_FILE"
    sed -i 's/SENTINEL_VERBOSE_RESULTS=true/SENTINEL_VERBOSE_RESULTS=false/' "$COMPOSE_FILE"
    sed -i 's/SENTINEL_BENCHMARK_MODE=true/SENTINEL_BENCHMARK_MODE=false/' "$COMPOSE_FILE"
    if [ -n "$_BENCHMARK_TL" ]; then
        sed -i "s/SENTINEL_TRUST_LEVEL=${_BENCHMARK_TL}/SENTINEL_TRUST_LEVEL=${CURRENT_TL}/" "$COMPOSE_FILE"
        echo "  Trust level restored to: $CURRENT_TL"
    fi

    echo "[cleanup] Restarting sentinel container with production settings..."
    cd "$PROJECT_DIR"
    podman compose down 2>/dev/null || true
    sleep "$_RUNNER_LIB_SETTLE_DOWN"
    podman compose up -d
    release_compose_lock
    echo "[cleanup] Done. Production settings restored, containers restarted."
}
trap restore_settings EXIT

acquire_compose_lock || { echo "ERROR: Could not acquire compose lock"; exit 1; }
sed -i 's/SENTINEL_APPROVAL_MODE=full/SENTINEL_APPROVAL_MODE=auto/' "$COMPOSE_FILE"
sed -i 's/SENTINEL_VERBOSE_RESULTS=false/SENTINEL_VERBOSE_RESULTS=true/' "$COMPOSE_FILE"
sed -i 's/SENTINEL_BENCHMARK_MODE=false/SENTINEL_BENCHMARK_MODE=true/' "$COMPOSE_FILE"
echo "  Approval mode set to: auto"
echo "  Verbose results: enabled"
echo "  Benchmark mode: enabled (per-prompt sessions, H-003 relaxed)"
if [ -n "$_BENCHMARK_TL" ]; then
    sed -i "s/SENTINEL_TRUST_LEVEL=${CURRENT_TL}/SENTINEL_TRUST_LEVEL=${_BENCHMARK_TL}/" "$COMPOSE_FILE"
    echo "  Trust level set to: $_BENCHMARK_TL (was: $CURRENT_TL)"
fi
echo

# ── Step 2: Restart containers with benchmark settings ────────────

echo "[2/5] Restarting containers with benchmark settings..."

cd "$PROJECT_DIR"
podman compose down 2>/dev/null || true
sleep "$_RUNNER_LIB_SETTLE_DOWN"
podman compose up -d

echo "  Containers restarted. Settling ${_RUNNER_LIB_SETTLE_LONG}s..."
sleep "$_RUNNER_LIB_SETTLE_LONG"
echo

# ── Step 3: Wait for health ───────────────────────────────────────

echo "[3/5] Waiting for sentinel to become healthy..."

MAX_HEALTH_WAIT=300
HEALTH_INTERVAL=10
elapsed=0

while [ $elapsed -lt $MAX_HEALTH_WAIT ]; do
    if python3 -c "
import urllib.request, ssl, json, sys
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
try:
    r = json.loads(urllib.request.urlopen('https://localhost:3001/health', context=ctx, timeout=10).read())
    if r.get('status') == 'ok':
        print('  Health check: OK')
        for k in ('planner_available', 'semgrep_loaded', 'prompt_guard_loaded', 'pin_auth_enabled', 'conversation_tracking', 'approval_mode', 'benchmark_mode'):
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
    signal_notify "ABORT: Mini benchmark — container not healthy after ${MAX_HEALTH_WAIT}s." "[Mini]"
    exit 1
fi

release_compose_lock

signal_notify "Containers healthy. Running mini benchmark (~134 prompts)..." "[Mini]"

# ── Step 4: Run the mini benchmark ────────────────────────────────

echo "[4/5] Starting mini benchmark..."
echo "  This will run for ~1-2 hours (~114 prompts)."
echo "  Results will be saved to: $PROJECT_DIR/benchmarks/"
echo "  To stop gracefully: kill -TERM $$"
echo

# Filter out args consumed by this wrapper script
_BENCH_ARGS=()
_SKIP_BENCH=0
for arg in "$@"; do
    if [ "$_SKIP_BENCH" -eq 1 ]; then
        _SKIP_BENCH=0
        continue
    fi
    case "$arg" in
        --foreground|--fg|--background|--bg|--no-signal) ;;
        --trust-level) _SKIP_BENCH=1 ;;
        *) _BENCH_ARGS+=("$arg") ;;
    esac
done
# Auto-include D5 supplement at TL4
_D5_FLAG=""
if [ "$_BENCHMARK_TL" = "4" ]; then
    _D5_FLAG="--include-d5"
    echo "  D5 constraint supplement: enabled (TL4)"
fi
python3 "$SCRIPT_DIR/mini_stress_test.py" $_D5_FLAG "${_BENCH_ARGS[@]}"

# ── Step 5: Auto-analyse results ────────────────────────────────

echo
echo "[5/5] Analysing results..."

# Find the JSONL file produced by this run (most recent mini_benchmark file)
RESULTS_JSONL="$(ls -t "$PROJECT_DIR"/benchmarks/mini_benchmark_*.jsonl 2>/dev/null | head -1)"

if [ -n "$RESULTS_JSONL" ]; then
    mkdir -p "$PROJECT_DIR/docs/assessments"
    echo "  Analysing: $RESULTS_JSONL"
    "$PROJECT_DIR/.venv/bin/python3" "$SCRIPT_DIR/analyse_benchmark_results.py" "$RESULTS_JSONL" || true
    echo "  Reports: $PROJECT_DIR/docs/assessments/"
else
    echo "  WARNING: No mini benchmark JSONL found to analyse"
fi

# ── Summary ─────────────────────────────────────────────────────

# Extract summary stats from the JSONL footer for the Signal message
SUMMARY_MSG="Mini benchmark finished"
if [ -n "$RESULTS_JSONL" ]; then
    SUMMARY_MSG=$("$PROJECT_DIR/.venv/bin/python3" -c "
import json, sys
lines = [json.loads(l) for l in open(sys.argv[1]) if l.strip()]
summary = [l for l in lines if l.get('type') == 'summary']
if summary:
    s = summary[0]
    total = s.get('total', 0)
    ok = s.get('success', 0)
    blk = s.get('blocked', 0)
    ref = s.get('refused', 0)
    err = s.get('error', 0)
    fp = s.get('genuine_blocked', 0)
    fn = s.get('adversarial_passed', 0)
    elapsed = s.get('total_elapsed', 0)
    mins = int(elapsed / 60)
    print(f'Mini benchmark done ({mins}m). {total} prompts: {ok} ok, {blk} blocked, {ref} refused, {err} err. FP={fp} FN={fn}.')
else:
    print('Mini benchmark done (no summary found).')
" "$RESULTS_JSONL" 2>/dev/null || echo "Mini benchmark finished.")
fi

signal_notify "$SUMMARY_MSG" "[Mini]"

echo
echo "============================================================"
echo "  Mini benchmark finished at $(date)"
echo "  Runner log: $LOG_FILE"
echo "  Results: $RESULTS_JSONL"
echo "  Reports: $PROJECT_DIR/docs/assessments/"
echo "============================================================"
