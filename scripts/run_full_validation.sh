#!/bin/bash
# ─────────────────────────────────────────────────────────────────
# Sentinel Full Validation Run
#
# Chains three test suites sequentially (~36 hours total):
#   Phase 1: Full benchmark (stress_test_v3, 1,136 prompts, ~15h)
#   Phase 2: Full G-suite (G1-G5, ~8-10h)
#   Phase 3: Full red team v2 (B1-B5, ~3-4.5h)
#
# Signal notifications:
#   - Phase start/end
#   - Progress every 2 hours
#   - Final summary
#
# Usage:
#   nohup ./scripts/run_full_validation.sh > /dev/null 2>&1 &
#   ./scripts/run_full_validation.sh --foreground
#   ./scripts/run_full_validation.sh --skip-benchmark  # G-suite + red team only
#   ./scripts/run_full_validation.sh --no-signal
#   ./scripts/run_full_validation.sh --dry-run
# ─────────────────────────────────────────────────────────────────

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
COMPOSE_FILE="$PROJECT_DIR/podman-compose.yaml"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
LOG_FILE="$PROJECT_DIR/benchmarks/full_validation_${TIMESTAMP}.log"

mkdir -p "$PROJECT_DIR/benchmarks"

# ── Parse args ────────────────────────────────────────────────────

_FOREGROUND=0
_SKIP_BENCHMARK=0
_NO_SIGNAL=0
_DRY_RUN=0
_TRUST_LEVEL=4

for arg in "$@"; do
    case "$arg" in
        --foreground|--fg) _FOREGROUND=1 ;;
        --skip-benchmark) _SKIP_BENCHMARK=1 ;;
        --no-signal) _NO_SIGNAL=1 ;;
        --dry-run) _DRY_RUN=1; _FOREGROUND=1 ;;
    esac
done

# ── Auto-detach ───────────────────────────────────────────────────

if [ "$_FOREGROUND" -eq 0 ] && [ -z "${_FV_DETACHED:-}" ]; then
    export _FV_DETACHED=1
    _REEXEC_ARGS=(--foreground)
    [ "$_SKIP_BENCHMARK" -eq 1 ] && _REEXEC_ARGS+=(--skip-benchmark)
    [ "$_NO_SIGNAL" -eq 1 ] && _REEXEC_ARGS+=(--no-signal)
    nohup "$0" "${_REEXEC_ARGS[@]}" > "$LOG_FILE" 2>&1 &
    BGPID=$!
    echo "Full validation launched in background (PID $BGPID)"
    echo "  Log:    $LOG_FILE"
    echo "  Follow: tail -f $LOG_FILE"
    echo "  Stop:   kill -TERM $BGPID"
    exit 0
fi

# Foreground: tee to log + console
if [ -z "${_FV_DETACHED:-}" ]; then
    exec > >(tee -a "$LOG_FILE") 2>&1
fi

# ── Source runner_lib for Signal + compose helpers ────────────────

source "$SCRIPT_DIR/runner_lib.sh"
runner_lib_init "$PROJECT_DIR" "$COMPOSE_FILE"
[ "$_NO_SIGNAL" -eq 1 ] && runner_lib_signal_enabled 0

# ── Helper: send Signal ──────────────────────────────────────────

notify() {
    signal_notify "$1" "[FullVal]"
}

# ── Helper: progress monitor (background, every 2 hours) ────────

_PROGRESS_PID=""

start_progress_monitor() {
    local phase_name="$1"
    local start_time="$2"
    (
        while true; do
            sleep 7200  # 2 hours
            elapsed_h=$(( ($(date +%s) - start_time) / 3600 ))
            elapsed_m=$(( (($(date +%s) - start_time) % 3600) / 60 ))
            notify "Progress: ${phase_name} running for ${elapsed_h}h ${elapsed_m}m"
        done
    ) &
    _PROGRESS_PID=$!
}

stop_progress_monitor() {
    if [ -n "$_PROGRESS_PID" ]; then
        kill "$_PROGRESS_PID" 2>/dev/null || true
        wait "$_PROGRESS_PID" 2>/dev/null || true
        _PROGRESS_PID=""
    fi
}

# ── State tracking ───────────────────────────────────────────────

OVERALL_START=$(date +%s)
BENCHMARK_STATUS="skipped"
GSUITE_STATUS="not started"
REDTEAM_STATUS="not started"

# ── Cleanup on exit ──────────────────────────────────────────────

cleanup() {
    stop_progress_monitor
    local elapsed=$(( ($(date +%s) - OVERALL_START) / 3600 ))
    local msg="Full validation ENDED after ${elapsed}h."
    msg+=" Benchmark: ${BENCHMARK_STATUS}."
    msg+=" G-suite: ${GSUITE_STATUS}."
    msg+=" Red team: ${REDTEAM_STATUS}."
    msg+=" Log: full_validation_${TIMESTAMP}.log"
    echo
    echo "============================================================"
    echo "  $msg"
    echo "============================================================"
    notify "$msg"
}
trap cleanup EXIT

# ── Header ────────────────────────────────────────────────────────

echo "============================================================"
echo "  Sentinel Full Validation Run"
echo "  $(date)"
echo "  Log: $LOG_FILE"
echo "  Trust level: $_TRUST_LEVEL"
echo "  Skip benchmark: $_SKIP_BENCHMARK"
echo "  Signal: $([ "$_NO_SIGNAL" -eq 1 ] && echo 'disabled' || echo 'enabled')"
echo "============================================================"
echo

if [ "$_DRY_RUN" -eq 1 ]; then
    echo "[DRY RUN] Would execute:"
    echo "  Phase 1: ./scripts/run_benchmark.sh --foreground --trust-level $_TRUST_LEVEL"
    _NS_LABEL=""; [ "$_NO_SIGNAL" -eq 1 ] && _NS_LABEL=" --no-signal"
    echo "  Phase 2: ./scripts/run_validation.sh --skip-rebuild --trust-level $_TRUST_LEVEL${_NS_LABEL}"
    echo "  Phase 3: ./scripts/run_red_team.sh --all --v2 --trust-level $_TRUST_LEVEL${_NS_LABEL}"
    echo
    echo "  Estimated runtime: ~30-36 hours"
    exit 0
fi

# ── Phase 1: Full Benchmark (~15h) ───────────────────────────────

if [ "$_SKIP_BENCHMARK" -eq 0 ]; then
    echo
    echo "============================================================"
    echo "  PHASE 1/3: Full Benchmark (1,136 prompts, ~15h)"
    echo "  Started: $(date)"
    echo "============================================================"
    echo

    BENCHMARK_STATUS="running"
    notify "PHASE 1/3 STARTED: Full benchmark (1,136 prompts, ~15h). TL=$_TRUST_LEVEL"

    PHASE1_START=$(date +%s)
    start_progress_monitor "Phase 1 (Benchmark)" "$PHASE1_START"

    # run_benchmark.sh handles its own compose settings + restore.
    # We run it in --foreground mode since we're already in the background.
    if "$SCRIPT_DIR/run_benchmark.sh" --foreground --trust-level "$_TRUST_LEVEL"; then
        PHASE1_ELAPSED=$(( ($(date +%s) - PHASE1_START) / 60 ))
        BENCHMARK_STATUS="DONE (${PHASE1_ELAPSED}m)"
        notify "PHASE 1/3 COMPLETE: Benchmark finished in ${PHASE1_ELAPSED}m. Starting G-suite next."
    else
        PHASE1_ELAPSED=$(( ($(date +%s) - PHASE1_START) / 60 ))
        BENCHMARK_STATUS="FAILED (${PHASE1_ELAPSED}m)"
        notify "PHASE 1/3 FAILED: Benchmark exited with error after ${PHASE1_ELAPSED}m. Continuing to G-suite."
        # Don't abort — continue to G-suite and red team
    fi

    stop_progress_monitor

    # Brief settle between phases
    echo "  Settling before next phase (30s)..."
    sleep 30
else
    echo "  [Phase 1 skipped — --skip-benchmark]"
    BENCHMARK_STATUS="skipped"
fi

# ── Phase 2: Full G-Suite (~8-10h) ──────────────────────────────

echo
echo "============================================================"
echo "  PHASE 2/3: Full G-Suite (G1-G5, ~8-10h)"
echo "  Started: $(date)"
echo "============================================================"
echo

GSUITE_STATUS="running"
notify "PHASE 2/3 STARTED: Full G-suite (G1-G5, ~8-10h)"

PHASE2_START=$(date +%s)
start_progress_monitor "Phase 2 (G-suite)" "$PHASE2_START"

_SIGNAL_ARGS=()
[ "$_NO_SIGNAL" -eq 1 ] && _SIGNAL_ARGS+=(--no-signal)

if "$SCRIPT_DIR/run_validation.sh" --skip-rebuild --trust-level "$_TRUST_LEVEL" "${_SIGNAL_ARGS[@]}"; then
    PHASE2_ELAPSED=$(( ($(date +%s) - PHASE2_START) / 60 ))
    GSUITE_STATUS="DONE (${PHASE2_ELAPSED}m)"
    notify "PHASE 2/3 COMPLETE: G-suite finished in ${PHASE2_ELAPSED}m. Starting red team next."
else
    PHASE2_ELAPSED=$(( ($(date +%s) - PHASE2_START) / 60 ))
    GSUITE_STATUS="FAILED (${PHASE2_ELAPSED}m)"
    notify "PHASE 2/3 FAILED: G-suite exited with error after ${PHASE2_ELAPSED}m. Continuing to red team."
fi

stop_progress_monitor

echo "  Settling before next phase (30s)..."
sleep 30

# ── Phase 3: Full Red Team v2 (~3-4.5h) ─────────────────────────

echo
echo "============================================================"
echo "  PHASE 3/3: Full Red Team v2 (B1-B5, ~3-4.5h)"
echo "  Started: $(date)"
echo "============================================================"
echo

REDTEAM_STATUS="running"
notify "PHASE 3/3 STARTED: Full red team v2 (B1-B5, ~3-4.5h)"

PHASE3_START=$(date +%s)
start_progress_monitor "Phase 3 (Red team)" "$PHASE3_START"

if "$SCRIPT_DIR/run_red_team.sh" --all --v2 --trust-level "$_TRUST_LEVEL" "${_SIGNAL_ARGS[@]}"; then
    PHASE3_ELAPSED=$(( ($(date +%s) - PHASE3_START) / 60 ))
    REDTEAM_STATUS="DONE (${PHASE3_ELAPSED}m)"
    notify "PHASE 3/3 COMPLETE: Red team finished in ${PHASE3_ELAPSED}m."
else
    PHASE3_ELAPSED=$(( ($(date +%s) - PHASE3_START) / 60 ))
    REDTEAM_STATUS="FAILED (${PHASE3_ELAPSED}m)"
    notify "PHASE 3/3 FAILED: Red team exited with error after ${PHASE3_ELAPSED}m."
fi

stop_progress_monitor

# ── Summary ──────────────────────────────────────────────────────

OVERALL_ELAPSED_H=$(( ($(date +%s) - OVERALL_START) / 3600 ))
OVERALL_ELAPSED_M=$(( (($(date +%s) - OVERALL_START) % 3600) / 60 ))

echo
echo "============================================================"
echo "  FULL VALIDATION COMPLETE"
echo "  Total runtime: ${OVERALL_ELAPSED_H}h ${OVERALL_ELAPSED_M}m"
echo "  Benchmark: $BENCHMARK_STATUS"
echo "  G-suite:   $GSUITE_STATUS"
echo "  Red team:  $REDTEAM_STATUS"
echo "  Log: $LOG_FILE"
echo "============================================================"

# Results locations
echo
echo "  Results:"
echo "    Benchmark: benchmarks/runner_*.log (latest)"
echo "    G-suite:   benchmarks/functional_*.jsonl + docs/assessments/functional_*.md"
echo "    Red team:  benchmarks/red_team_*.jsonl + docs/assessments/red-team-*.md"
echo
echo "  Quick view:"
echo "    ./scripts/mini_gsuite_results.sh --all  (G-suite summary)"
echo "    ls -t docs/assessments/*.md | head -20  (latest reports)"
