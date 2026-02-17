#!/bin/bash
# Sentinel Functional Test Runner
#
# Runs functional test suites (Phase G) against the live stack.
# Handles approval mode switching, trust level toggling, and cleanup on exit.
#
# Unlike the security benchmark, functional tests verify that generated
# artifacts actually WORK — code compiles, tests pass, containers build.
#
# By default, runs in the background via nohup so it survives terminal
# disconnects. Use --foreground to run in the current terminal instead.
#
# Prerequisites:
#   - sentinel + sentinel-ollama containers running and healthy
#   - PIN file at ~/.secrets/sentinel_pin.txt
#
# Usage:
#   ./scripts/run_functional_tests.sh --suite build --version v0.4.0-alpha
#   ./scripts/run_functional_tests.sh --suite build --trust-level 3 --foreground
#   ./scripts/run_functional_tests.sh --suite debug --trust-level 4
#
# When called from an orchestrator (run_validation.sh), use --managed:
#   ./scripts/run_functional_tests.sh --suite build --managed --foreground
#   Skips compose modification, container restarts, and EXIT trap.
#   Caller is responsible for compose settings, container lifecycle, and health.
#
# Suites: build, debug, e2e, plans, deps, security-tax, smoke
#
# Files produced:
#   benchmarks/functional_{suite}_{version}_{timestamp}.jsonl
#   benchmarks/functional_runner_{timestamp}.log
#
# Analysis:
#   .venv/bin/python3 scripts/analyse_functional_results.py benchmarks/functional_*.jsonl

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
COMPOSE_FILE="$PROJECT_DIR/podman-compose.yaml"
LOG_FILE="$PROJECT_DIR/benchmarks/functional_runner_$(date +%Y%m%d_%H%M%S).log"

# Ensure benchmarks directory exists
mkdir -p "$PROJECT_DIR/benchmarks"

# Source shared runner library for compose locking, Signal, health checks
source "$SCRIPT_DIR/runner_lib.sh"
runner_lib_init "$PROJECT_DIR" "$COMPOSE_FILE"

# ── Parse args ────────────────────────────────────────────────────

_FOREGROUND=0
_MANAGED=0
_BENCHMARK_TL=""
_SUITE=""
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
        --managed) _MANAGED=1; _FOREGROUND=1 ;;
        --trust-level)
            next_i=$((i + 1))
            _BENCHMARK_TL="${!next_i}"
            _SKIP_NEXT=1
            ;;
        --suite)
            next_i=$((i + 1))
            _SUITE="${!next_i}"
            _SKIP_NEXT=1
            ;;
        *) _PASSTHROUGH_ARGS+=("$arg") ;;
    esac
done

if [ -z "$_SUITE" ]; then
    echo "ERROR: --suite is required"
    echo "  Available: build, debug, e2e, plans, deps, security-tax, smoke"
    exit 1
fi

# Map suite names to Python scripts
declare -A SUITE_SCRIPTS=(
    [build]="functional_test_build.py"
    [debug]="functional_test_debug.py"
    [e2e]="functional_test_e2e.py"
    [plans]="functional_test_plans.py"
    [deps]="functional_test_deps.py"
    [security-tax]="functional_test_security_tax.py"
    [smoke]="functional_test_smoke.py"
)

SUITE_SCRIPT="${SUITE_SCRIPTS[$_SUITE]:-}"
if [ -z "$SUITE_SCRIPT" ]; then
    echo "ERROR: Unknown suite '$_SUITE'"
    echo "  Available: ${!SUITE_SCRIPTS[*]}"
    exit 1
fi

if [ ! -f "$SCRIPT_DIR/$SUITE_SCRIPT" ]; then
    echo "ERROR: Suite script not found: $SCRIPT_DIR/$SUITE_SCRIPT"
    echo "  This suite has not been implemented yet."
    exit 1
fi

# ── Auto-detach (default: run in background via nohup) ────────────

if [ "$_FOREGROUND" -eq 0 ] && [ -z "${_BENCHMARK_DETACHED:-}" ]; then
    export _BENCHMARK_DETACHED=1
    _REEXEC_ARGS=(--foreground --suite "$_SUITE")
    [ -n "$_BENCHMARK_TL" ] && _REEXEC_ARGS+=(--trust-level "$_BENCHMARK_TL")
    nohup "$0" "${_REEXEC_ARGS[@]}" "${_PASSTHROUGH_ARGS[@]}" > "$LOG_FILE" 2>&1 &
    BGPID=$!
    echo "Functional test [$_SUITE] launched in background (PID $BGPID)"
    echo "  Log:    $LOG_FILE"
    echo "  Follow: tail -f $LOG_FILE"
    echo "  Stop:   kill -TERM $BGPID"
    exit 0
fi

if [ -n "${_BENCHMARK_DETACHED:-}" ]; then
    :
else
    exec > >(tee -a "$LOG_FILE") 2>&1
fi

echo "============================================================"
echo "  Sentinel Functional Test Runner"
echo "  Suite: $_SUITE ($SUITE_SCRIPT)"
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

if ! podman ps --format "{{.Names}}" | grep -q '^sentinel$'; then
    echo "  ERROR: sentinel container not running"
    echo "  Start with: podman compose up -d"
    exit 1
fi

if ! podman ps --format "{{.Names}}" | grep -q '^sentinel-ollama$'; then
    echo "  ERROR: sentinel-ollama container not running"
    exit 1
fi

echo "  Compose file: $COMPOSE_FILE"
echo "  Containers: sentinel + sentinel-ollama running"

if [ "$_MANAGED" -eq 1 ]; then
    # Caller owns compose settings, container lifecycle, and health checks.
    # We just run the test.
    echo "  Mode: managed (caller handles compose + restarts)"
    echo
else
    # Standalone mode — we manage everything ourselves.
    CURRENT_MODE=$(grep 'SENTINEL_APPROVAL_MODE=' "$COMPOSE_FILE" | head -1 | cut -d= -f2)
    CURRENT_TL=$(grep 'SENTINEL_TRUST_LEVEL=' "$COMPOSE_FILE" | head -1 | cut -d= -f2)
    CURRENT_VERBOSE=$(grep 'SENTINEL_VERBOSE_RESULTS=' "$COMPOSE_FILE" | head -1 | cut -d= -f2)
    CURRENT_BENCH=$(grep 'SENTINEL_BENCHMARK_MODE=' "$COMPOSE_FILE" | head -1 | cut -d= -f2)

    echo "  Current approval mode: $CURRENT_MODE"
    echo "  Current trust level: $CURRENT_TL"
    echo "  Current verbose results: $CURRENT_VERBOSE"
    echo "  Current benchmark mode: $CURRENT_BENCH"
    echo

    # ── Step 1: Switch to test mode ──────────────────────────────────

    echo "[1/4] Switching to functional test mode (auto approval + verbose results + benchmark sessions)..."

    restore_settings() {
        echo
        echo "[cleanup] Restoring production settings..."
        acquire_compose_lock || true
        sed -i "s/SENTINEL_APPROVAL_MODE=auto/SENTINEL_APPROVAL_MODE=${CURRENT_MODE}/" "$COMPOSE_FILE"
        sed -i "s/SENTINEL_VERBOSE_RESULTS=true/SENTINEL_VERBOSE_RESULTS=${CURRENT_VERBOSE}/" "$COMPOSE_FILE"
        sed -i "s/SENTINEL_BENCHMARK_MODE=true/SENTINEL_BENCHMARK_MODE=${CURRENT_BENCH}/" "$COMPOSE_FILE"
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
    trap 'restore_settings; release_compose_lock' EXIT

    acquire_compose_lock || { echo "ERROR: Could not acquire compose lock"; exit 1; }
    sed -i "s/SENTINEL_APPROVAL_MODE=${CURRENT_MODE}/SENTINEL_APPROVAL_MODE=auto/" "$COMPOSE_FILE"
    sed -i "s/SENTINEL_VERBOSE_RESULTS=${CURRENT_VERBOSE}/SENTINEL_VERBOSE_RESULTS=true/" "$COMPOSE_FILE"
    sed -i "s/SENTINEL_BENCHMARK_MODE=${CURRENT_BENCH}/SENTINEL_BENCHMARK_MODE=true/" "$COMPOSE_FILE"
    echo "  Approval mode set to: auto"
    echo "  Verbose results: enabled"
    echo "  Benchmark mode: enabled (per-prompt sessions)"
    if [ -n "$_BENCHMARK_TL" ]; then
        sed -i "s/SENTINEL_TRUST_LEVEL=${CURRENT_TL}/SENTINEL_TRUST_LEVEL=${_BENCHMARK_TL}/" "$COMPOSE_FILE"
        echo "  Trust level set to: $_BENCHMARK_TL (was: $CURRENT_TL)"
    fi
    echo

    # ── Step 2: Restart containers with test settings ─────────────────

    echo "[2/4] Restarting containers with test settings..."

    cd "$PROJECT_DIR"
    podman compose down 2>/dev/null || true
    sleep "$_RUNNER_LIB_SETTLE_DOWN"
    podman compose up -d

    echo "  Containers restarted. Settling ${_RUNNER_LIB_SETTLE_LONG}s..."
    sleep "$_RUNNER_LIB_SETTLE_LONG"
    echo

    # ── Step 3: Wait for health ───────────────────────────────────────

    echo "[3/4] Waiting for sentinel to become healthy..."

    if ! wait_for_health 300; then
        echo "  ERROR: sentinel did not become healthy"
        echo "  Check logs: podman logs sentinel"
        exit 1
    fi

    release_compose_lock
fi

# ── Step 4: Run the functional test suite ─────────────────────────

echo "[4/4] Starting functional test suite: $_SUITE..."
echo "  Script: $SUITE_SCRIPT"
echo "  Results: $PROJECT_DIR/benchmarks/"
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
        --foreground|--fg) ;;
        --managed) ;;
        --trust-level) _SKIP_BENCH=1 ;;
        --suite) _SKIP_BENCH=1 ;;
        *) _BENCH_ARGS+=("$arg") ;;
    esac
done

python3 "$SCRIPT_DIR/$SUITE_SCRIPT" "${_BENCH_ARGS[@]}"

# ── Auto-analyse results ────────────────────────────────────────

echo
echo "Analysing results..."

RESULTS_JSONL="$(ls -t "$PROJECT_DIR"/benchmarks/functional_${_SUITE}_*.jsonl 2>/dev/null | head -1)"

if [ -n "$RESULTS_JSONL" ]; then
    mkdir -p "$PROJECT_DIR/docs/assessments"
    echo "  Analysing: $(basename "$RESULTS_JSONL")"
    "$PROJECT_DIR/.venv/bin/python3" "$SCRIPT_DIR/analyse_functional_results.py" "$RESULTS_JSONL" || true
    REPORT="$(ls -t "$PROJECT_DIR"/docs/assessments/functional_${_SUITE}_*.md 2>/dev/null | head -1)"
    echo "  Report: ${REPORT:-not generated}"
else
    echo "  WARNING: No JSONL found for $_SUITE"
fi

echo
echo "============================================================"
echo "  Functional test [$_SUITE] finished at $(date)"
echo "  Runner log: $LOG_FILE"
echo "  Results: ${RESULTS_JSONL:-$PROJECT_DIR/benchmarks/}"
echo "  Report: ${REPORT:-not generated}"
echo "============================================================"
