#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────
# A/B Comparison Benchmark for Episodic Learning
#
# Runs the same set of scenarios twice:
#   Phase A: Episodic context ON (normal settings)
#   Phase B: Episodic context OFF (cross_session_token_budget=0)
#
# Scenarios are interleaved (mixed G2/G3) to simulate realistic usage
# and test whether episodic learning helps across task types.
#
# Usage:
#   ./scripts/run_ab_benchmark.sh                     # foreground
#   ./scripts/run_ab_benchmark.sh --no-signal          # no Signal msgs
#   ./scripts/run_ab_benchmark.sh --trust-level 4      # override TL
#   ./scripts/run_ab_benchmark.sh --skip-phase-a       # only phase B
#   ./scripts/run_ab_benchmark.sh --skip-phase-b       # only phase A
#   ./scripts/run_ab_benchmark.sh --dry-run            # show what would run
# ─────────────────────────────────────────────────────────────────
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# ── Source shared runner library ────────────────────────────────
source "$SCRIPT_DIR/runner_lib.sh"
runner_lib_init "$PROJECT_DIR" "$PROJECT_DIR/podman-compose.yaml"

# ── Parse arguments ─────────────────────────────────────────────
TRUST_LEVEL=""
NO_SIGNAL=0
SKIP_A=0
SKIP_B=0
DRY_RUN=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --no-signal)     NO_SIGNAL=1; shift ;;
        --trust-level)   TRUST_LEVEL="$2"; shift 2 ;;
        --skip-phase-a)  SKIP_A=1; shift ;;
        --skip-phase-b)  SKIP_B=1; shift ;;
        --dry-run)       DRY_RUN=1; shift ;;
        *)               echo "Unknown arg: $1"; exit 1 ;;
    esac
done

if [ "$NO_SIGNAL" -eq 1 ]; then
    runner_lib_signal_enabled 0
fi

# ── Lock file ───────────────────────────────────────────────────
LOCK_FILE="$PROJECT_DIR/benchmarks/.ab_benchmark.lock"
if [ -f "$LOCK_FILE" ]; then
    EXISTING_PID=$(head -1 "$LOCK_FILE" 2>/dev/null | cut -d: -f1)
    if [ -n "$EXISTING_PID" ] && kill -0 "$EXISTING_PID" 2>/dev/null; then
        echo "ERROR: A/B benchmark already running (PID $EXISTING_PID)"
        exit 1
    fi
    echo "WARNING: Stale lock file found. Removing."
    rm -f "$LOCK_FILE"
fi
echo "$$:run_ab_benchmark:$(date +%Y%m%d_%H%M%S)" > "$LOCK_FILE"

# ── Redirect to log if not interactive ──────────────────────────
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
LOG_FILE="$PROJECT_DIR/benchmarks/ab_benchmark_runner_${TIMESTAMP}.log"

if [ ! -t 0 ] && [ ! -t 1 ]; then
    exec > "$LOG_FILE" 2>&1
    echo "Non-interactive mode — logging to $LOG_FILE"
else
    exec > >(tee "$LOG_FILE") 2>&1
fi

# ── Cleanup trap ────────────────────────────────────────────────
ORIG_APPROVAL=""
ORIG_TRUST=""
ORIG_VERBOSE=""
ORIG_BENCHMARK=""
ORIG_BUDGET=""

cleanup() {
    echo
    echo "[cleanup] Restoring production settings..."
    cd "$PROJECT_DIR"

    if [ -n "$ORIG_APPROVAL" ]; then
        sed -i "s/SENTINEL_APPROVAL_MODE=auto/SENTINEL_APPROVAL_MODE=$ORIG_APPROVAL/" podman-compose.yaml
    fi
    if [ -n "$ORIG_TRUST" ] && [ -n "$TRUST_LEVEL" ]; then
        sed -i "s/SENTINEL_TRUST_LEVEL=$TRUST_LEVEL/SENTINEL_TRUST_LEVEL=$ORIG_TRUST/" podman-compose.yaml
    fi
    if [ -n "$ORIG_VERBOSE" ]; then
        sed -i "s/SENTINEL_VERBOSE_RESULTS=true/SENTINEL_VERBOSE_RESULTS=$ORIG_VERBOSE/" podman-compose.yaml
    fi
    if [ -n "$ORIG_BENCHMARK" ]; then
        sed -i "s/SENTINEL_BENCHMARK_MODE=true/SENTINEL_BENCHMARK_MODE=$ORIG_BENCHMARK/" podman-compose.yaml
    fi
    # Restore budget if changed
    if [ -n "$ORIG_BUDGET" ]; then
        if grep -q "SENTINEL_CROSS_SESSION_TOKEN_BUDGET=0" podman-compose.yaml; then
            sed -i "s/SENTINEL_CROSS_SESSION_TOKEN_BUDGET=0/SENTINEL_CROSS_SESSION_TOKEN_BUDGET=$ORIG_BUDGET/" podman-compose.yaml
        fi
    fi

    echo "  Restarting containers with production settings..."
    podman compose down 2>/dev/null || true
    sleep 5
    podman compose up -d 2>/dev/null || true

    rm -f "$LOCK_FILE"
    echo "[cleanup] Done."
}

trap cleanup EXIT

# ── Banner ──────────────────────────────────────────────────────
echo "============================================================"
echo "  A/B Comparison Benchmark — Episodic Learning"
echo "  $(date)"
echo "  Log: $LOG_FILE"
echo "  Phase A: Episodic ON (normal)       $([ "$SKIP_A" -eq 1 ] && echo "[SKIPPED]" || echo "")"
echo "  Phase B: Episodic OFF (budget=0)    $([ "$SKIP_B" -eq 1 ] && echo "[SKIPPED]" || echo "")"
echo "============================================================"
echo

if [ "$DRY_RUN" -eq 1 ]; then
    echo "[DRY RUN] Would run G2 Cat A (4 scenarios) + G3 (8 scenarios) interleaved"
    echo "          Phase A: normal settings"
    echo "          Phase B: CROSS_SESSION_TOKEN_BUDGET=0"
    rm -f "$LOCK_FILE"
    trap - EXIT
    exit 0
fi

# ── Pre-flight checks ──────────────────────────────────────────
echo "[0/6] Pre-flight checks..."

if ! podman ps --format "{{.Names}}" | grep -q '^sentinel$'; then
    echo "  ERROR: sentinel container not running"
    exit 1
fi

cd "$PROJECT_DIR"
ORIG_APPROVAL=$(grep 'SENTINEL_APPROVAL_MODE=' podman-compose.yaml | head -1 | sed 's/.*=//')
ORIG_TRUST=$(grep 'SENTINEL_TRUST_LEVEL=' podman-compose.yaml | head -1 | sed 's/.*=//')
ORIG_VERBOSE=$(grep 'SENTINEL_VERBOSE_RESULTS=' podman-compose.yaml | head -1 | sed 's/.*=//')
ORIG_BENCHMARK=$(grep 'SENTINEL_BENCHMARK_MODE=' podman-compose.yaml | head -1 | sed 's/.*=//')
ORIG_BUDGET=$(grep 'SENTINEL_CROSS_SESSION_TOKEN_BUDGET=' podman-compose.yaml | head -1 | sed 's/.*=//' || echo "2000")
[ -z "$ORIG_BUDGET" ] && ORIG_BUDGET="2000"

GIT_HEAD=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")
PYTHON="$PROJECT_DIR/.venv/bin/python3"

echo "  Current: approval=$ORIG_APPROVAL, TL=$ORIG_TRUST, budget=$ORIG_BUDGET"

# ── Apply base test settings ────────────────────────────────────
echo "[1/6] Applying base test settings..."
sed -i "s/SENTINEL_APPROVAL_MODE=$ORIG_APPROVAL/SENTINEL_APPROVAL_MODE=auto/" podman-compose.yaml
sed -i "s/SENTINEL_VERBOSE_RESULTS=$ORIG_VERBOSE/SENTINEL_VERBOSE_RESULTS=true/" podman-compose.yaml
sed -i "s/SENTINEL_BENCHMARK_MODE=$ORIG_BENCHMARK/SENTINEL_BENCHMARK_MODE=true/" podman-compose.yaml

if [ -n "$TRUST_LEVEL" ]; then
    sed -i "s/SENTINEL_TRUST_LEVEL=$ORIG_TRUST/SENTINEL_TRUST_LEVEL=$TRUST_LEVEL/" podman-compose.yaml
fi

# Results files
ON_FILE="$PROJECT_DIR/benchmarks/ab_episodic_on_${TIMESTAMP}.jsonl"
OFF_FILE="$PROJECT_DIR/benchmarks/ab_episodic_off_${TIMESTAMP}.jsonl"

# ── Phase A: Episodic ON ────────────────────────────────────────
if [ "$SKIP_A" -eq 0 ]; then
    echo "[2/6] Phase A — Episodic ON (normal budget=${ORIG_BUDGET})..."

    # Restart with normal settings (budget already at normal)
    acquire_compose_lock || exit 1
    podman compose down 2>/dev/null || true
    sleep "$_RUNNER_LIB_SETTLE_DOWN"
    podman compose up -d 2>&1
    echo "  Settling ${_RUNNER_LIB_SETTLE_LONG}s..."
    sleep "$_RUNNER_LIB_SETTLE_LONG"
    wait_for_healthy 120 || exit 1

    echo "  Running G2 Cat A (interleaved with G3)..."
    # Run G2 debug scenarios
    $PYTHON "$SCRIPT_DIR/functional_test_debug_dev.py" \
        --category a --trials 1 --output "$ON_FILE" 2>&1 | tail -5

    echo "  Running G3 E2E scenarios..."
    $PYTHON "$SCRIPT_DIR/functional_test_e2e.py" \
        --output "$ON_FILE" 2>&1 | tail -5

    echo "  Phase A complete: $ON_FILE"
else
    echo "[2/6] Phase A — SKIPPED"
fi

# ── Phase B: Episodic OFF ───────────────────────────────────────
if [ "$SKIP_B" -eq 0 ]; then
    echo "[3/6] Phase B — Episodic OFF (budget=0)..."

    # Set budget to 0 to disable episodic context
    if grep -q "SENTINEL_CROSS_SESSION_TOKEN_BUDGET=" podman-compose.yaml; then
        sed -i "s/SENTINEL_CROSS_SESSION_TOKEN_BUDGET=$ORIG_BUDGET/SENTINEL_CROSS_SESSION_TOKEN_BUDGET=0/" podman-compose.yaml
    else
        # Add the env var if it doesn't exist (insert after benchmark_mode)
        sed -i "/SENTINEL_BENCHMARK_MODE/a\\      - SENTINEL_CROSS_SESSION_TOKEN_BUDGET=0" podman-compose.yaml
    fi

    # Restart with episodic disabled
    acquire_compose_lock || exit 1
    podman compose down 2>/dev/null || true
    sleep "$_RUNNER_LIB_SETTLE_DOWN"
    podman compose up -d 2>&1
    echo "  Settling ${_RUNNER_LIB_SETTLE_LONG}s..."
    sleep "$_RUNNER_LIB_SETTLE_LONG"
    wait_for_healthy 120 || exit 1

    echo "  Running G2 Cat A (interleaved with G3)..."
    $PYTHON "$SCRIPT_DIR/functional_test_debug_dev.py" \
        --category a --trials 1 --output "$OFF_FILE" 2>&1 | tail -5

    echo "  Running G3 E2E scenarios..."
    $PYTHON "$SCRIPT_DIR/functional_test_e2e.py" \
        --output "$OFF_FILE" 2>&1 | tail -5

    echo "  Phase B complete: $OFF_FILE"

    # Restore budget
    sed -i "s/SENTINEL_CROSS_SESSION_TOKEN_BUDGET=0/SENTINEL_CROSS_SESSION_TOKEN_BUDGET=$ORIG_BUDGET/" podman-compose.yaml
else
    echo "[3/6] Phase B — SKIPPED"
fi

# ── Compare results ─────────────────────────────────────────────
echo "[4/6] Comparing results..."
if [ -f "$ON_FILE" ] && [ -f "$OFF_FILE" ]; then
    $PYTHON "$SCRIPT_DIR/ab_benchmark_compare.py" "$ON_FILE" "$OFF_FILE" --timestamp "$TIMESTAMP"
elif [ -f "$ON_FILE" ]; then
    echo "  Only Phase A results available — no comparison possible"
elif [ -f "$OFF_FILE" ]; then
    echo "  Only Phase B results available — no comparison possible"
else
    echo "  No results files found"
fi

# ── Signal notification ─────────────────────────────────────────
echo "[5/6] Sending notification..."
runner_lib_signal "A/B benchmark complete ($TIMESTAMP). Check docs/assessments/ab_benchmark_${TIMESTAMP}.md"

echo "[6/6] Done!"
echo "  Results ON:  $ON_FILE"
echo "  Results OFF: $OFF_FILE"
echo "  Report:      docs/assessments/ab_benchmark_${TIMESTAMP}.md"
