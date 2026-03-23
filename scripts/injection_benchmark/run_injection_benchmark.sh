#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────
# Sentinel Injection Benchmark — Shell Orchestrator
# ─────────────────────────────────────────────────────────────────
#
# Phases:
#   1. Core tests (104 via /api/task)
#   2. Channel tests (18 via Signal/Telegram inbound) — if scope >= channels
#   3. Chained tests (8 multi-vector) — if scope >= chained
#   4. Analysis (IMAP final sweep + scoring + report)
#   5. Cleanup (remove seeded content)
#
# USAGE:
#   ./scripts/injection_benchmark/run_injection_benchmark.sh --config <yaml>
#   ./scripts/injection_benchmark/run_injection_benchmark.sh --config <yaml> --scope chained
#   ./scripts/injection_benchmark/run_injection_benchmark.sh --config <yaml> --dry-run
#
# OPTIONS:
#   --config <path>    Path to injection benchmark config YAML (required)
#   --scope <scope>    core (104), channels (122), chained (130, default)
#   --dry-run          Show what would run without executing
#   --skip-rebuild     Don't restart containers (default — no Sentinel changes)
#   --no-signal        Disable Signal notifications
#   --trust-level <n>  Trust level (default: 4)
#   --foreground       Run in current terminal (default)
#
# ─────────────────────────────────────────────────────────────────

set -uo pipefail

# ── Configuration ────────────────────────────────────────────────

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
# Find Python — check worktree first, fall back to git toplevel
if [ -x "$PROJECT_DIR/.venv/bin/python3" ]; then
    PYTHON="$PROJECT_DIR/.venv/bin/python3"
else
    # In a worktree, .venv may be in the main repo
    _GIT_ROOT="$(git -C "$PROJECT_DIR" rev-parse --path-format=absolute --git-common-dir 2>/dev/null | sed 's|/\.git$||')"
    if [ -n "$_GIT_ROOT" ] && [ -x "$_GIT_ROOT/.venv/bin/python3" ]; then
        PYTHON="$_GIT_ROOT/.venv/bin/python3"
    else
        PYTHON="python3"
    fi
fi
COMPOSE_FILE="$PROJECT_DIR/podman-compose.yaml"
BENCHMARKS_DIR="$PROJECT_DIR/benchmarks"
TIMESTAMP=$(date -u +%Y%m%d_%H%M%S)
LOG_FILE="$BENCHMARKS_DIR/injection_benchmark_${TIMESTAMP}.log"

# Lock file to prevent concurrent runs
LOCK_FILE="$BENCHMARKS_DIR/.injection_benchmark.lock"

# Signal notification settings
SIGNAL_ACCOUNT="${SIGNAL_ACCOUNT:-}"
SIGNAL_RECIPIENT="${SIGNAL_RECIPIENT:-}"

# ── CLI defaults ─────────────────────────────────────────────────

CONFIG=""
SCOPE="chained"
DRY_RUN=0
SKIP_REBUILD=0       # Restart containers to apply benchmark compose settings
SIGNAL_ENABLED=1
TRUST_LEVEL=4

# ── Parse args ───────────────────────────────────────────────────

while [[ $# -gt 0 ]]; do
    case "$1" in
        --config)      CONFIG="$2"; shift 2 ;;
        --scope)       SCOPE="$2"; shift 2 ;;
        --dry-run)     DRY_RUN=1; shift ;;
        --skip-rebuild) SKIP_REBUILD=1; shift ;;
        --rebuild)      SKIP_REBUILD=0; shift ;;
        --no-signal)   SIGNAL_ENABLED=0; shift ;;
        --trust-level) TRUST_LEVEL="$2"; shift 2 ;;
        --foreground)  shift ;;  # Already in foreground
        -h|--help)
            head -30 "${BASH_SOURCE[0]}" | grep '^#' | sed 's/^# \?//'
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# ── Validation ───────────────────────────────────────────────────

if [ -z "$CONFIG" ]; then
    echo "ERROR: --config is required"
    echo "Usage: $0 --config <path-to-config.yaml> [--scope core|channels|chained]"
    exit 1
fi

if [ ! -f "$CONFIG" ]; then
    echo "ERROR: Config file not found: $CONFIG"
    exit 1
fi

# ── Utility functions ────────────────────────────────────────────

log() {
    local msg="[$(date -u '+%Y-%m-%d %H:%M:%S')] $1"
    echo "$msg"
    echo "$msg" >> "$LOG_FILE" 2>/dev/null || true
}

signal_notify() {
    local msg="$1"
    local prefix="${2:-[Injection Bench]}"
    if [ "$SIGNAL_ENABLED" -eq 0 ] || [ "$DRY_RUN" -eq 1 ]; then
        return 0
    fi
    if [ -z "$SIGNAL_ACCOUNT" ] || [ -z "$SIGNAL_RECIPIENT" ]; then
        return 0
    fi
    timeout 15 podman exec sentinel python3 -c "
import socket, json, sys
msg = json.dumps({
    'jsonrpc': '2.0', 'id': 1, 'method': 'send',
    'params': {
        'account': '$SIGNAL_ACCOUNT',
        'recipients': ['$SIGNAL_RECIPIENT'],
        'message': '${prefix} ' + sys.argv[1]
    }
}) + '\n'
try:
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(10)
    s.connect('/tmp/signal.sock')
    s.sendall(msg.encode())
    s.recv(4096)
    s.close()
except Exception:
    pass
" "$msg" >/dev/null 2>&1 || true
}

wait_for_health() {
    local timeout="${1:-120}"
    local elapsed=0
    log "Waiting for Sentinel health (timeout: ${timeout}s)..."
    while [ $elapsed -lt "$timeout" ]; do
        if curl -sk "https://localhost:3001/health" 2>/dev/null | grep -q '"status":"ok"'; then
            log "Health check passed after ${elapsed}s"
            return 0
        fi
        sleep 5
        elapsed=$((elapsed + 5))
    done
    log "ERROR: Health check timed out after ${timeout}s"
    return 1
}

acquire_lock() {
    if [ -f "$LOCK_FILE" ]; then
        local pid
        pid=$(cat "$LOCK_FILE" 2>/dev/null || echo "unknown")
        echo "ERROR: Lock file exists — another injection benchmark is running (PID: $pid)"
        echo "If this is stale, remove: $LOCK_FILE"
        exit 1
    fi
    echo $$ > "$LOCK_FILE"
}

release_lock() {
    rm -f "$LOCK_FILE"
}

# ── Compose management ──────────────────────────────────────────

ORIGINAL_APPROVAL_MODE=""
ORIGINAL_VERBOSE=""
ORIGINAL_BENCHMARK=""
ORIGINAL_TL=""

save_and_set_compose() {
    ORIGINAL_APPROVAL_MODE=$(grep 'SENTINEL_APPROVAL_MODE=' "$COMPOSE_FILE" | head -1 | cut -d= -f2)
    ORIGINAL_VERBOSE=$(grep 'SENTINEL_VERBOSE_RESULTS=' "$COMPOSE_FILE" | head -1 | cut -d= -f2)
    ORIGINAL_BENCHMARK=$(grep 'SENTINEL_BENCHMARK_MODE=' "$COMPOSE_FILE" | head -1 | cut -d= -f2)
    ORIGINAL_TL=$(grep 'SENTINEL_TRUST_LEVEL=' "$COMPOSE_FILE" | head -1 | cut -d= -f2)

    sed -i "s/SENTINEL_APPROVAL_MODE=${ORIGINAL_APPROVAL_MODE}/SENTINEL_APPROVAL_MODE=auto/" "$COMPOSE_FILE"
    sed -i "s/SENTINEL_VERBOSE_RESULTS=${ORIGINAL_VERBOSE}/SENTINEL_VERBOSE_RESULTS=true/" "$COMPOSE_FILE"
    sed -i "s/SENTINEL_BENCHMARK_MODE=${ORIGINAL_BENCHMARK}/SENTINEL_BENCHMARK_MODE=true/" "$COMPOSE_FILE"
    sed -i "s/SENTINEL_TRUST_LEVEL=${ORIGINAL_TL}/SENTINEL_TRUST_LEVEL=${TRUST_LEVEL}/" "$COMPOSE_FILE"

    log "Set: approval=auto verbose=true benchmark=true tl=${TRUST_LEVEL}"
}

restore_compose() {
    if [ -z "$ORIGINAL_APPROVAL_MODE" ]; then
        release_lock
        return
    fi

    log "Restoring production settings..."
    sed -i "s/SENTINEL_APPROVAL_MODE=auto/SENTINEL_APPROVAL_MODE=${ORIGINAL_APPROVAL_MODE}/" "$COMPOSE_FILE"
    sed -i "s/SENTINEL_VERBOSE_RESULTS=true/SENTINEL_VERBOSE_RESULTS=${ORIGINAL_VERBOSE}/" "$COMPOSE_FILE"
    sed -i "s/SENTINEL_BENCHMARK_MODE=true/SENTINEL_BENCHMARK_MODE=${ORIGINAL_BENCHMARK}/" "$COMPOSE_FILE"
    sed -i "s/SENTINEL_TRUST_LEVEL=${TRUST_LEVEL}/SENTINEL_TRUST_LEVEL=${ORIGINAL_TL}/" "$COMPOSE_FILE"

    if [ "$SKIP_REBUILD" -eq 0 ]; then
        log "Restarting containers with production settings..."
        cd "$PROJECT_DIR"
        podman compose down 2>/dev/null || true
        sleep 3
        podman compose up -d
    fi

    log "Production settings restored."
    release_lock
}

# ── Scope → test count ──────────────────────────────────────────

scope_to_count() {
    case "$1" in
        core)     echo "104" ;;
        channels) echo "122" ;;
        chained)  echo "130" ;;
        *)        echo "130" ;;
    esac
}

# ── Main ─────────────────────────────────────────────────────────

mkdir -p "$BENCHMARKS_DIR"

TEST_COUNT=$(scope_to_count "$SCOPE")

log "Injection Benchmark starting"
log "  Config: $CONFIG"
log "  Scope: $SCOPE (~$TEST_COUNT tests)"
log "  Trust level: $TRUST_LEVEL"
log "  Dry run: $DRY_RUN"

if [ "$DRY_RUN" -eq 1 ]; then
    echo ""
    echo "=== DRY RUN ==="
    echo "Would run: $SCOPE scope (~$TEST_COUNT tests)"
    echo ""
    echo "Phase 1: Core tests (104)"
    $PYTHON "$SCRIPT_DIR/run_core.py" --config "$CONFIG" --dry-run
    if [ "$SCOPE" != "core" ]; then
        echo ""
        echo "Phase 2: Channel tests (18)"
        $PYTHON "$SCRIPT_DIR/run_channels.py" --config "$CONFIG" --dry-run
    fi
    if [ "$SCOPE" = "chained" ]; then
        echo ""
        echo "Phase 3: Chained tests (8)"
        $PYTHON "$SCRIPT_DIR/run_chained.py" --config "$CONFIG" --dry-run
    fi
    echo ""
    echo "Phase 4: Analysis & report"
    echo "Phase 5: Cleanup"
    exit 0
fi

# Acquire lock
acquire_lock

# Set up compose and trap for cleanup
save_and_set_compose
trap restore_compose EXIT

# Restart containers if needed
if [ "$SKIP_REBUILD" -eq 0 ]; then
    log "Restarting containers..."
    cd "$PROJECT_DIR"
    podman compose down 2>/dev/null || true
    sleep 3
    podman compose up -d
fi

# Wait for health
wait_for_health 120 || exit 1

# Collect output files for analysis
OUTPUT_FILES=""

signal_notify "Starting — $SCOPE scope, ~$TEST_COUNT tests"

# Phase 1: Core tests
log "Phase 1: Core tests (104)"
CORE_OUTPUT="$BENCHMARKS_DIR/injection_benchmark_core_${TIMESTAMP}.jsonl"
signal_notify "Phase 1: Core tests (104)..."

if $PYTHON "$SCRIPT_DIR/run_core.py" --config "$CONFIG" --output "$CORE_OUTPUT" 2>&1 | tee -a "$LOG_FILE"; then
    log "Phase 1: COMPLETE"
    signal_notify "Phase 1: Core tests complete"
else
    log "Phase 1: FAILED (continuing)"
    signal_notify "Phase 1: FAILED (continuing)"
fi
OUTPUT_FILES="$CORE_OUTPUT"

# Phase 2: Channel tests (if scope >= channels)
if [ "$SCOPE" != "core" ]; then
    log "Phase 2: Channel tests (18)"
    CHANNEL_OUTPUT="$BENCHMARKS_DIR/injection_benchmark_channels_${TIMESTAMP}.jsonl"
    signal_notify "Phase 2: Channel tests (18)..."

    if $PYTHON "$SCRIPT_DIR/run_channels.py" --config "$CONFIG" --output "$CHANNEL_OUTPUT" 2>&1 | tee -a "$LOG_FILE"; then
        log "Phase 2: COMPLETE"
        signal_notify "Phase 2: Channel tests complete"
    else
        log "Phase 2: FAILED (continuing)"
        signal_notify "Phase 2: FAILED (continuing)"
    fi
    OUTPUT_FILES="$OUTPUT_FILES,$CHANNEL_OUTPUT"
fi

# Phase 3: Chained tests (if scope == chained)
if [ "$SCOPE" = "chained" ]; then
    log "Phase 3: Chained tests (8)"
    CHAINED_OUTPUT="$BENCHMARKS_DIR/injection_benchmark_chained_${TIMESTAMP}.jsonl"
    signal_notify "Phase 3: Chained tests (8)..."

    if $PYTHON "$SCRIPT_DIR/run_chained.py" --config "$CONFIG" --output "$CHAINED_OUTPUT" 2>&1 | tee -a "$LOG_FILE"; then
        log "Phase 3: COMPLETE"
        signal_notify "Phase 3: Chained tests complete"
    else
        log "Phase 3: FAILED (continuing)"
        signal_notify "Phase 3: FAILED (continuing)"
    fi
    OUTPUT_FILES="$OUTPUT_FILES,$CHAINED_OUTPUT"
fi

# Phase 4: Analysis
log "Phase 4: Analysis & report"
REPORT_OUTPUT="$PROJECT_DIR/docs/assessments/injection_benchmark_${TIMESTAMP}.md"

if $PYTHON "$SCRIPT_DIR/analyse_results.py" --input "$OUTPUT_FILES" --output "$REPORT_OUTPUT" 2>&1 | tee -a "$LOG_FILE"; then
    log "Phase 4: Report generated at $REPORT_OUTPUT"
    signal_notify "Analysis complete — report at $REPORT_OUTPUT"
else
    log "Phase 4: Analysis FAILED"
    signal_notify "Analysis FAILED"
fi

# Phase 5: Cleanup
log "Phase 5: Cleanup"
if $PYTHON "$SCRIPT_DIR/cleanup.py" --config "$CONFIG" --full 2>&1 | tee -a "$LOG_FILE"; then
    log "Phase 5: Cleanup complete"
else
    log "Phase 5: Cleanup FAILED — run manually: $PYTHON $SCRIPT_DIR/cleanup.py --config $CONFIG --full"
fi

log "Injection Benchmark complete"
log "  Log: $LOG_FILE"
log "  Results: $OUTPUT_FILES"
log "  Report: $REPORT_OUTPUT"

signal_notify "COMPLETE — see report at $REPORT_OUTPUT"
