#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────
# Sentinel Red Team — Orchestrator
# ─────────────────────────────────────────────────────────────────
#
# Wrapper script that runs the red team test suite in the designed
# sequence, handles container configuration, and produces a combined
# analysis report at the end.
#
# INDIVIDUAL SCRIPTS (can all be run standalone):
#   scripts/red_team_b3.sh       B3: External perimeter (container, network, air gap)
#   scripts/red_team_b1.py       B1: Adversarial user — adaptive AI vs full pipeline
#   scripts/red_team_b1_5.py     B1.5: Adversarial data via external channels
#   scripts/red_team_b2.py       B2: Compromised planner — rogue plan injection
#   scripts/analyse_red_team.py  Analysis: processes JSONL from any scenario
#   scripts/red_team_lib.py      Shared library for B1/B1.5 (attacker brain, JSONL, etc.)
#
# DESIGNED SEQUENCE (this script):
#   1. B3 Phase 1  — infrastructure gate (verification tests, ~5 min)
#   2. Container restart with red team settings
#   3. B1          — adversarial user vs full pipeline (~45-60 min)
#   4. B1.5        — adversarial data via channels (~15-20 min)
#   5. B2          — compromised planner (needs RED_TEAM_MODE, ~30-60 min)
#   6. B3 Phase 2  — active exploitation probes (~20-30 min)
#   7. Analysis    — combined report from all JSONL outputs
#
# B3 Phase 1 runs first as a gate — if infrastructure is broken, there's
# no point testing the application layer. B2 runs after B1/B1.5 because
# it requires SENTINEL_RED_TEAM_MODE=true (test endpoint). B3 Phase 2
# runs last because exploitation probes are the most aggressive.
#
# USAGE:
#   ./scripts/run_red_team.sh --all                 # full v1 suite in sequence
#   ./scripts/run_red_team.sh --all --v2            # full v2 suite (includes B4)
#   ./scripts/run_red_team.sh --scenario b3         # single scenario
#   ./scripts/run_red_team.sh --scenario b1 b1.5    # multiple scenarios
#   ./scripts/run_red_team.sh --skip b2             # all except B2
#   ./scripts/run_red_team.sh --analyse-only        # just run analysis on existing JSONL
#   ./scripts/run_red_team.sh --dry-run             # show what would run, don't execute
#
# OPTIONS:
#   --all              Run all scenarios in designed sequence
#   --v2               Use v2 scripts (adds B4 sandbox isolation to suite)
#   --scenario <list>  Run only specified scenarios (b3-p1, b1, b1.5, b2, b3-p2, b4)
#   --skip <list>      Run all except specified scenarios
#   --analyse-only     Skip all tests, just analyse existing JSONL in benchmarks/
#   --destructive      Pass --destructive to B3 Phase 2 (e.g. model deletion test)
#   --trust-level <n>  Trust level for testing (default: 4)
#   --dry-run          Show execution plan without running anything
#   --no-restart       Don't restart containers (assume already configured)
#   --foreground       Run in current terminal (default)
#
# PREREQUISITES:
#   - sentinel + sentinel-ollama containers running and healthy
#   - PIN file at ~/.secrets/sentinel_pin.txt
#   - Claude API key at ~/.secrets/claude_api_key.txt
#   - B2: RED_TEAM_MODE is toggled automatically (no manual setup needed)
#
# EXIT CODES:
#   0 = all scenarios completed (check reports for findings)
#   1 = pre-flight failed or scenario errored
#   2 = B3 Phase 1 gate failed (infrastructure issue)
# ─────────────────────────────────────────────────────────────────

# No set -e — we handle errors manually per scenario so that a single
# scenario failure doesn't kill all remaining scenarios in a long run.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
COMPOSE_FILE="$PROJECT_DIR/podman-compose.yaml"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
LOG_FILE="$PROJECT_DIR/benchmarks/red_team_runner_${TIMESTAMP}.log"
RESULTS_DIR="$PROJECT_DIR/benchmarks"

PYTHON="$PROJECT_DIR/.venv/bin/python3"
HTTPS_PORT="${SENTINEL_HTTPS_PORT:-3001}"
TARGET="https://localhost:${HTTPS_PORT}"
PIN_FILE="$HOME/.secrets/sentinel_pin.txt"
API_KEY_FILE="$HOME/.secrets/claude_api_key.txt"

# Signal config
SIGNAL_ENABLED=1
SIGNAL_ACCOUNT="+440000000000"
SIGNAL_RECIPIENT="00000000-0000-0000-0000-000000000000"

# ── Argument parsing ─────────────────────────────────────────────

RUN_ALL=0
DRY_RUN=0
ANALYSE_ONLY=0
DESTRUCTIVE=0
NO_RESTART=0
TRUST_LEVEL=4
USE_V2=0
SCENARIOS=()
SKIP_SCENARIOS=()

_SKIP_NEXT=0
_COLLECT_SCENARIOS=0
_COLLECT_SKIP=0

for arg in "$@"; do
    if [ "$_SKIP_NEXT" -eq 1 ]; then
        _SKIP_NEXT=0
        continue
    fi

    # Stop collecting list args when we hit a new flag
    case "$arg" in
        --*) _COLLECT_SCENARIOS=0; _COLLECT_SKIP=0 ;;
    esac

    # Collect multi-value args
    if [ "$_COLLECT_SCENARIOS" -eq 1 ]; then
        SCENARIOS+=("$arg")
        continue
    fi
    if [ "$_COLLECT_SKIP" -eq 1 ]; then
        SKIP_SCENARIOS+=("$arg")
        continue
    fi

    case "$arg" in
        --all)           RUN_ALL=1 ;;
        --scenario)      _COLLECT_SCENARIOS=1 ;;
        --skip)          _COLLECT_SKIP=1 ;;
        --analyse-only)  ANALYSE_ONLY=1 ;;
        --destructive)   DESTRUCTIVE=1 ;;
        --dry-run)       DRY_RUN=1 ;;
        --no-restart)    NO_RESTART=1 ;;
        --foreground)    : ;;             # default behaviour, accepted for compat
        --no-signal)     SIGNAL_ENABLED=0 ;;
        --v2)            USE_V2=1 ;;
        --trust-level)   _SKIP_NEXT=0  ;; # handled below
        --help|-h)
            sed -n '2,/^# ──/{ /^# ──/d; s/^# \?//p }' "$0"
            exit 0
            ;;
        *)
            # Check if it's the value for --trust-level
            if [[ "${_PREV_ARG:-}" == "--trust-level" ]]; then
                TRUST_LEVEL="$arg"
            else
                echo "ERROR: Unknown argument: $arg"
                echo "Run $0 --help for usage"
                exit 1
            fi
            ;;
    esac
    _PREV_ARG="$arg"
done

# Default to --all if no scenario selection given
if [ "$RUN_ALL" -eq 0 ] && [ "${#SCENARIOS[@]}" -eq 0 ] && [ "${#SKIP_SCENARIOS[@]}" -eq 0 ] && [ "$ANALYSE_ONLY" -eq 0 ]; then
    RUN_ALL=1
fi

# Script selection (v1 or v2)
if [ "$USE_V2" -eq 1 ]; then
    B1_SCRIPT="red_team_b1_v2.py"
    B1_5_SCRIPT="red_team_b1_5_v2.py"
    B2_SCRIPT="red_team_b2_v2.py"
    B3_SCRIPT="red_team_b3_v2.sh"
    B4_SCRIPT="red_team_b4_v2.py"
    B5_SCRIPT="red_team_b5_v2.py"
    V2_TAG="_v2"
    B3_GLOB="b3_perimeter_v2_*.jsonl"
    ALL_SCENARIOS=(b3-p1 b1 b1.5 b2 b3-p2 b4 b5)
    VERSION_LABEL="v2"
else
    B1_SCRIPT="red_team_b1.py"
    B1_5_SCRIPT="red_team_b1_5.py"
    B2_SCRIPT="red_team_b2.py"
    B3_SCRIPT="red_team_b3.sh"
    V2_TAG=""
    B3_GLOB="b3_perimeter_*.jsonl"
    ALL_SCENARIOS=(b3-p1 b1 b1.5 b2 b3-p2)
    VERSION_LABEL="v1"
fi

if [ "$RUN_ALL" -eq 1 ]; then
    SCENARIOS=("${ALL_SCENARIOS[@]}")
elif [ "${#SKIP_SCENARIOS[@]}" -gt 0 ]; then
    SCENARIOS=()
    for s in "${ALL_SCENARIOS[@]}"; do
        skip=0
        for ss in "${SKIP_SCENARIOS[@]}"; do
            # --skip b3 removes both b3-p1 and b3-p2
            if [[ "$s" == "$ss" ]] || [[ "$s" == "${ss}-p1" ]] || [[ "$s" == "${ss}-p2" ]]; then
                skip=1
                break
            fi
        done
        [ "$skip" -eq 0 ] && SCENARIOS+=("$s")
    done
fi

# ── Helpers ──────────────────────────────────────────────────────

# Collected JSONL outputs for final analysis
JSONL_FILES=()

log() {
    echo "[$(date +%H:%M:%S)] $*"
}

signal_notify() {
    local msg="$1"
    if [ "$SIGNAL_ENABLED" -eq 0 ] || [ "$DRY_RUN" -eq 1 ]; then
        return 0
    fi
    timeout 15 podman exec sentinel python3 -c "
import socket, json, sys
msg = json.dumps({
    'jsonrpc': '2.0', 'id': 1, 'method': 'send',
    'params': {
        'account': '$SIGNAL_ACCOUNT',
        'recipients': ['$SIGNAL_RECIPIENT'],
        'message': '[Sentinel Red Team] ' + sys.argv[1]
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

run_scenario() {
    local name="$1"
    shift
    log "──── $name ────"
    if [ "$DRY_RUN" -eq 1 ]; then
        log "  DRY RUN: $*"
        return 0
    fi
    "$@"
}

should_run() {
    local scenario="$1"
    for s in "${SCENARIOS[@]}"; do
        [ "$s" == "$scenario" ] && return 0
    done
    return 1
}

wait_for_health() {
    local max_wait="${1:-120}"
    local interval=5
    local elapsed=0

    log "Waiting for sentinel to become healthy..."

    while [ $elapsed -lt "$max_wait" ]; do
        if python3 -c "
import urllib.request, ssl, json, sys
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
try:
    r = json.loads(urllib.request.urlopen('${TARGET}/health', context=ctx, timeout=5).read())
    if r.get('status') == 'ok':
        print('  Health check: OK')
        sys.exit(0)
    sys.exit(1)
except Exception:
    sys.exit(1)
" 2>/dev/null; then
            return 0
        fi

        elapsed=$((elapsed + interval))
        log "  Waiting... (${elapsed}s / ${max_wait}s)"
        sleep $interval
    done

    log "  ERROR: sentinel did not become healthy after ${max_wait}s"
    return 1
}

# ── Pre-flight checks ────────────────────────────────────────────

preflight() {
    log "Pre-flight checks..."

    if [ ! -f "$COMPOSE_FILE" ]; then
        log "  ERROR: Compose file not found: $COMPOSE_FILE"
        exit 1
    fi

    if [ ! -f "$PIN_FILE" ]; then
        log "  ERROR: PIN file not found: $PIN_FILE"
        exit 1
    fi

    # B1/B1.5/B2 need Claude API key
    local needs_api_key=0
    for s in "${SCENARIOS[@]}"; do
        case "$s" in b1|b1.5|b2) needs_api_key=1 ;; esac
    done
    if [ "$needs_api_key" -eq 1 ] && [ ! -f "$API_KEY_FILE" ]; then
        log "  ERROR: Claude API key not found: $API_KEY_FILE"
        log "  Required for B1, B1.5, and B2 scenarios"
        exit 1
    fi

    # Check containers are running
    if ! podman ps --format "{{.Names}}" | grep -q '^sentinel$'; then
        log "  ERROR: sentinel container not running"
        exit 1
    fi
    if ! podman ps --format "{{.Names}}" | grep -q '^sentinel-ollama$'; then
        log "  ERROR: sentinel-ollama container not running"
        exit 1
    fi

    # Note: B2 RED_TEAM_MODE toggle is handled automatically at runtime
    if should_run b2; then
        log "  B2 requested — RED_TEAM_MODE will be toggled automatically"
    fi

    mkdir -p "$RESULTS_DIR"
    log "  All checks passed"
}

# ── Container configuration ──────────────────────────────────────

ORIGINAL_APPROVAL_MODE=""
ORIGINAL_VERBOSE=""
ORIGINAL_BENCHMARK=""
ORIGINAL_TL=""

save_and_set_compose() {
    # Capture current settings for restore (|| true prevents pipefail exit on missing vars)
    ORIGINAL_APPROVAL_MODE=$(grep 'SENTINEL_APPROVAL_MODE=' "$COMPOSE_FILE" | head -1 | cut -d= -f2 || true)
    ORIGINAL_VERBOSE=$(grep 'SENTINEL_VERBOSE_RESULTS=' "$COMPOSE_FILE" | head -1 | cut -d= -f2 || true)
    ORIGINAL_BENCHMARK=$(grep 'SENTINEL_BENCHMARK_MODE=' "$COMPOSE_FILE" | head -1 | cut -d= -f2 || true)
    ORIGINAL_TL=$(grep 'SENTINEL_TRUST_LEVEL=' "$COMPOSE_FILE" | head -1 | cut -d= -f2 || true)

    log "Configuring compose for red team testing..."
    log "  Saving current: approval=$ORIGINAL_APPROVAL_MODE verbose=$ORIGINAL_VERBOSE benchmark=$ORIGINAL_BENCHMARK tl=$ORIGINAL_TL"

    # Set red team settings
    sed -i "s/SENTINEL_APPROVAL_MODE=${ORIGINAL_APPROVAL_MODE}/SENTINEL_APPROVAL_MODE=auto/" "$COMPOSE_FILE"
    sed -i "s/SENTINEL_VERBOSE_RESULTS=${ORIGINAL_VERBOSE}/SENTINEL_VERBOSE_RESULTS=true/" "$COMPOSE_FILE"
    sed -i "s/SENTINEL_BENCHMARK_MODE=${ORIGINAL_BENCHMARK}/SENTINEL_BENCHMARK_MODE=true/" "$COMPOSE_FILE"
    sed -i "s/SENTINEL_TRUST_LEVEL=${ORIGINAL_TL}/SENTINEL_TRUST_LEVEL=${TRUST_LEVEL}/" "$COMPOSE_FILE"

    log "  Set: approval=auto verbose=true benchmark=true tl=${TRUST_LEVEL}"
}

restore_compose() {
    # Clean up RED_TEAM_MODE first if we added it (safety net for mid-B2 exits)
    if [ "$RED_TEAM_MODE_ADDED" -eq 1 ]; then
        log "Cleanup: removing RED_TEAM_MODE from compose"
        sed -i '/SENTINEL_RED_TEAM_MODE=true/d' "$COMPOSE_FILE"
        RED_TEAM_MODE_ADDED=0
    fi

    if [ -z "$ORIGINAL_APPROVAL_MODE" ]; then
        return  # Nothing to restore (--no-restart or didn't get to save)
    fi

    log "Restoring production settings..."
    sed -i "s/SENTINEL_APPROVAL_MODE=auto/SENTINEL_APPROVAL_MODE=${ORIGINAL_APPROVAL_MODE}/" "$COMPOSE_FILE"
    sed -i "s/SENTINEL_VERBOSE_RESULTS=true/SENTINEL_VERBOSE_RESULTS=${ORIGINAL_VERBOSE}/" "$COMPOSE_FILE"
    sed -i "s/SENTINEL_BENCHMARK_MODE=true/SENTINEL_BENCHMARK_MODE=${ORIGINAL_BENCHMARK}/" "$COMPOSE_FILE"
    sed -i "s/SENTINEL_TRUST_LEVEL=${TRUST_LEVEL}/SENTINEL_TRUST_LEVEL=${ORIGINAL_TL}/" "$COMPOSE_FILE"

    log "Restarting containers with production settings..."
    cd "$PROJECT_DIR"
    podman compose down 2>/dev/null || true
    sleep 3
    podman compose up -d
    log "Production settings restored."
}

restart_containers() {
    if [ "$NO_RESTART" -eq 1 ]; then
        log "Skipping container restart (--no-restart)"
        return 0
    fi

    save_and_set_compose
    trap restore_compose EXIT

    log "Restarting containers with red team settings..."
    cd "$PROJECT_DIR"
    podman compose down 2>/dev/null || true
    sleep 3
    podman compose up -d

    wait_for_health 120 || exit 1
    log "Containers ready."
}

# ── RED_TEAM_MODE management (for B2) ────────────────────────────

RED_TEAM_MODE_ADDED=0

enable_red_team_mode() {
    # Add SENTINEL_RED_TEAM_MODE=true to compose env block.
    # Idempotent — checks if already present.
    if grep -q 'SENTINEL_RED_TEAM_MODE=true' "$COMPOSE_FILE" 2>/dev/null; then
        log "RED_TEAM_MODE already enabled in compose"
        return 0
    fi

    log "Enabling RED_TEAM_MODE in compose..."
    sed -i '/SENTINEL_BENCHMARK_MODE=/a\      - SENTINEL_RED_TEAM_MODE=true' "$COMPOSE_FILE"
    RED_TEAM_MODE_ADDED=1
    log "RED_TEAM_MODE=true added to compose"
}

disable_red_team_mode() {
    # Remove SENTINEL_RED_TEAM_MODE line from compose.
    # Only removes if we added it (safety — don't remove user's config).
    if [ "$RED_TEAM_MODE_ADDED" -eq 0 ]; then
        return 0
    fi

    log "Removing RED_TEAM_MODE from compose..."
    sed -i '/SENTINEL_RED_TEAM_MODE=true/d' "$COMPOSE_FILE"
    RED_TEAM_MODE_ADDED=0
    log "RED_TEAM_MODE removed from compose"
}

restart_with_red_team_mode() {
    enable_red_team_mode
    log "Restarting containers with RED_TEAM_MODE..."
    cd "$PROJECT_DIR"
    podman compose down 2>/dev/null || true
    sleep 3
    podman compose up -d
    wait_for_health 120 || return 1
    log "Containers ready (RED_TEAM_MODE enabled)."
}

restart_without_red_team_mode() {
    disable_red_team_mode
    log "Restarting containers without RED_TEAM_MODE..."
    cd "$PROJECT_DIR"
    podman compose down 2>/dev/null || true
    sleep 3
    podman compose up -d
    wait_for_health 120 || return 1
    log "Containers ready (RED_TEAM_MODE removed)."
}

cleanup_workspace() {
    log "Cleaning workspace volume..."
    podman exec sentinel sh -c 'find /workspace -mindepth 1 -delete 2>/dev/null; echo done' || true
    log "  Workspace cleaned."
}

# ── Scenario runners ─────────────────────────────────────────────

run_red_team_b3_phase1() {
    run_scenario "B3 Phase 1: Infrastructure Verification ($VERSION_LABEL)" \
        bash "$SCRIPT_DIR/$B3_SCRIPT" --phase 1
    # B3 writes its own JSONL — find the latest one
    local latest
    latest=$(ls -t "$RESULTS_DIR"/$B3_GLOB 2>/dev/null | head -1 || true)
    if [ -n "$latest" ]; then
        JSONL_FILES+=("$latest")
    fi
}

run_red_team_b1() {
    local output="$RESULTS_DIR/red_team_b1${V2_TAG}_${TIMESTAMP}.jsonl"
    run_scenario "B1: Adversarial User ($VERSION_LABEL)" \
        "$PYTHON" "$SCRIPT_DIR/$B1_SCRIPT" \
            --target "$TARGET" \
            --pin-file "$PIN_FILE" \
            --api-key-file "$API_KEY_FILE" \
            --output "$output"
    JSONL_FILES+=("$output")
}

run_red_team_b1_5() {
    local output="$RESULTS_DIR/red_team_b1_5${V2_TAG}_${TIMESTAMP}.jsonl"
    run_scenario "B1.5: Adversarial Data ($VERSION_LABEL)" \
        "$PYTHON" "$SCRIPT_DIR/$B1_5_SCRIPT" \
            --target "$TARGET" \
            --pin-file "$PIN_FILE" \
            --api-key-file "$API_KEY_FILE" \
            --output "$output"
    JSONL_FILES+=("$output")
}

run_red_team_b2() {
    local output="$RESULTS_DIR/red_team_b2${V2_TAG}_${TIMESTAMP}.jsonl"
    run_scenario "B2: Compromised Planner ($VERSION_LABEL)" \
        "$PYTHON" "$SCRIPT_DIR/$B2_SCRIPT" \
            --target "$TARGET" \
            --pin-file "$PIN_FILE" \
            --api-key-file "$API_KEY_FILE" \
            --output "$output" \
            --no-verify
    JSONL_FILES+=("$output")
}

run_red_team_b3_phase2() {
    local destructive_flag=""
    [ "$DESTRUCTIVE" -eq 1 ] && destructive_flag="--destructive"
    run_scenario "B3 Phase 2: Active Exploitation ($VERSION_LABEL)" \
        bash "$SCRIPT_DIR/$B3_SCRIPT" --phase 2 $destructive_flag
    local latest
    latest=$(ls -t "$RESULTS_DIR"/$B3_GLOB 2>/dev/null | head -1 || true)
    if [ -n "$latest" ]; then
        # Only add if not already in the list (Phase 1 may have added it)
        local already=0
        for f in "${JSONL_FILES[@]}"; do
            [ "$f" == "$latest" ] && already=1
        done
        [ "$already" -eq 0 ] && JSONL_FILES+=("$latest")
    fi
}

run_red_team_b4() {
    local output="$RESULTS_DIR/red_team_b4_v2_${TIMESTAMP}.jsonl"
    run_scenario "B4: Sandbox Isolation (v2)" \
        "$PYTHON" "$SCRIPT_DIR/$B4_SCRIPT" \
            --output "$output"
    JSONL_FILES+=("$output")
}

run_red_team_b5() {
    local output="$RESULTS_DIR/red_team_b5_v2_${TIMESTAMP}.jsonl"
    run_scenario "B5: Database Security (v2)" \
        "$PYTHON" "$SCRIPT_DIR/$B5_SCRIPT" \
            --output "$output"
    JSONL_FILES+=("$output")
}

run_analysis() {
    log "──── Analysis ────"

    if [ "${#JSONL_FILES[@]}" -eq 0 ]; then
        # Find all red team JSONL from this run or recent files
        while IFS= read -r f; do
            JSONL_FILES+=("$f")
        done < <(ls -t "$RESULTS_DIR"/red_team_*.jsonl "$RESULTS_DIR"/b3_perimeter*.jsonl 2>/dev/null | head -10)
    fi

    if [ "${#JSONL_FILES[@]}" -eq 0 ]; then
        log "  No JSONL files found to analyse"
        return 0
    fi

    log "  Analysing ${#JSONL_FILES[@]} result file(s):"
    for f in "${JSONL_FILES[@]}"; do
        log "    $(basename "$f")"
        if [ "$DRY_RUN" -eq 0 ]; then
            "$PYTHON" "$SCRIPT_DIR/analyse_red_team.py" "$f" || true
        fi
    done
}

# ── Main ─────────────────────────────────────────────────────────

echo "============================================================"
echo "  Sentinel Red Team Suite ($VERSION_LABEL)"
echo "  $(date)"
echo "  Log: $LOG_FILE"
echo "  Scenarios: ${SCENARIOS[*]}"
echo "============================================================"
echo

# Force Python to flush stdout/stderr immediately (prevents lost output on crash)
export PYTHONUNBUFFERED=1

# Tee all output to log
exec > >(tee -a "$LOG_FILE") 2>&1

if [ "$ANALYSE_ONLY" -eq 1 ]; then
    run_analysis
    echo
    log "Analysis complete. Reports in docs/assessments/"
    exit 0
fi

# Pre-flight
preflight

OVERALL_START=$(date +%s)
signal_notify "Started ($VERSION_LABEL). Scenarios: ${SCENARIOS[*]}" "[Red Team]"

# B3 Phase 1 — infrastructure gate (runs before container restart)
if should_run b3-p1; then
    signal_notify "B3 Phase 1 ($VERSION_LABEL): infrastructure gate..." "[Red Team]"
    b3_rc=0
    run_red_team_b3_phase1 || b3_rc=$?
    if [ "$b3_rc" -ne 0 ] && [ "$DRY_RUN" -eq 0 ]; then
        log "B3 Phase 1 FAILED (exit $b3_rc) — infrastructure issues detected."
        log "Fix infrastructure before running application-layer tests."
        signal_notify "ABORT: B3 Phase 1 failed (infrastructure). Check log." "[Red Team]"
        exit 2
    fi
    signal_notify "B3 Phase 1: PASS" "[Red Team]"
    echo
fi

# Container restart for B1/B1.5/B2 (sets auto approval, benchmark mode, TL)
NEEDS_RESTART=0
for s in "${SCENARIOS[@]}"; do
    case "$s" in b1|b1.5|b2) NEEDS_RESTART=1 ;; esac
done
if [ "$NEEDS_RESTART" -eq 1 ]; then
    restart_containers
    echo
fi

# Track per-scenario results for summary
_RT_FAILURES=0

# B1 — adversarial user
if should_run b1; then
    cleanup_workspace
    signal_notify "B1 ($VERSION_LABEL): adversarial user (~45-60 min)..." "[Red Team]"
    if run_red_team_b1; then
        signal_notify "B1: complete" "[Red Team]"
    else
        echo "  WARNING: B1 exited with error — continuing to next scenario"
        signal_notify "B1: FAILED (continuing)" "[Red Team]"
        _RT_FAILURES=$((_RT_FAILURES + 1))
    fi
    echo
fi

# B1.5 — adversarial data via channels
if should_run b1.5; then
    cleanup_workspace
    signal_notify "B1.5 ($VERSION_LABEL): adversarial data (~15-20 min)..." "[Red Team]"
    if run_red_team_b1_5; then
        signal_notify "B1.5: complete" "[Red Team]"
    else
        echo "  WARNING: B1.5 exited with error — continuing to next scenario"
        signal_notify "B1.5: FAILED (continuing)" "[Red Team]"
        _RT_FAILURES=$((_RT_FAILURES + 1))
    fi
    echo
fi

# B2 — compromised planner (needs RED_TEAM_MODE toggle + restart)
if should_run b2; then
    cleanup_workspace
    signal_notify "B2 ($VERSION_LABEL): compromised planner — toggling RED_TEAM_MODE..." "[Red Team]"
    restart_with_red_team_mode
    if run_red_team_b2; then
        signal_notify "B2: complete" "[Red Team]"
    else
        echo "  WARNING: B2 exited with error — continuing to next scenario"
        signal_notify "B2: FAILED (continuing)" "[Red Team]"
        _RT_FAILURES=$((_RT_FAILURES + 1))
    fi
    restart_without_red_team_mode
    echo
fi

# B3 Phase 2 — active exploitation
if should_run b3-p2; then
    cleanup_workspace
    signal_notify "B3 Phase 2 ($VERSION_LABEL): active exploitation probes..." "[Red Team]"
    if run_red_team_b3_phase2; then
        signal_notify "B3 Phase 2: complete" "[Red Team]"
    else
        echo "  WARNING: B3 Phase 2 exited with error — continuing"
        signal_notify "B3 Phase 2: FAILED (continuing)" "[Red Team]"
        _RT_FAILURES=$((_RT_FAILURES + 1))
    fi
    echo
fi

# B4 — sandbox isolation (v2 only, runs after perimeter tests)
if should_run b4; then
    signal_notify "B4 ($VERSION_LABEL): sandbox isolation (17 categories)..." "[Red Team]"
    if run_red_team_b4; then
        signal_notify "B4: complete" "[Red Team]"
    else
        echo "  WARNING: B4 exited with error — continuing"
        signal_notify "B4: FAILED (continuing)" "[Red Team]"
        _RT_FAILURES=$((_RT_FAILURES + 1))
    fi
    echo
fi

# B5 — database security (v2 only, direct DB tests via podman exec)
if should_run b5; then
    signal_notify "B5 ($VERSION_LABEL): database security (12 categories)..." "[Red Team]"
    if run_red_team_b5; then
        signal_notify "B5: complete" "[Red Team]"
    else
        echo "  WARNING: B5 exited with error — continuing"
        signal_notify "B5: FAILED (continuing)" "[Red Team]"
        _RT_FAILURES=$((_RT_FAILURES + 1))
    fi
    echo
fi

# Analysis
run_analysis

overall_elapsed=$(( $(date +%s) - OVERALL_START ))
hours=$((overall_elapsed / 3600))
mins=$(( (overall_elapsed % 3600) / 60 ))

echo
echo "============================================================"
echo "  Red Team Suite Complete"
echo "  $(date)"
echo "  Total: ${hours}h ${mins}m"
echo "  Runner log: $LOG_FILE"
echo "  JSONL results: $RESULTS_DIR/red_team_*_${TIMESTAMP}.jsonl"
echo "  Reports: docs/assessments/"
echo "============================================================"

signal_notify "Complete ($VERSION_LABEL, ${hours}h ${mins}m). Scenarios: ${SCENARIOS[*]}. Check reports." "[Red Team]"
