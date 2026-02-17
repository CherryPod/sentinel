#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────
# Sentinel Validation Runner
# ─────────────────────────────────────────────────────────────────
#
# Rebuilds the container and runs the G-suite functional test
# suites (G1-G5) at a given trust level. This validates that the
# application builds cleanly and passes functional acceptance
# tests before promotion.
#
# Compose settings (approval mode, benchmark mode, trust level)
# are set ONCE before the suite loop and restored ONCE on exit.
# Individual suite runs use --managed to skip their own compose
# management. This avoids unnecessary container restarts between
# suites.
#
# For security testing, run the red team suite separately:
#   ./scripts/run_red_team.sh --all
#
# SEQUENCE:
#   1. Save compose settings, switch to test mode
#   2. Container rebuild (incorporates source changes) — optional
#   3. Container restart + health check (one restart for all suites)
#   4. G1-G5 functional suites (build, debug, e2e, plans, deps)
#   5. Summary
#   6. EXIT trap: restore compose settings + restart
#
# USAGE:
#   ./scripts/run_validation.sh                  # full run
#   ./scripts/run_validation.sh --skip-rebuild   # skip container rebuild
#   ./scripts/run_validation.sh --no-signal      # skip Signal notifications
#   ./scripts/run_validation.sh --trust-level 3  # run at TL3 instead of TL4
#   ./scripts/run_validation.sh --dry-run        # show plan, don't execute
#
# RUN UNATTENDED:
#   nohup ./scripts/run_validation.sh > /dev/null 2>&1 &
#   # All output goes to benchmarks/validation_*.log via tee
#   # Signal messages arrive on your phone as it progresses
#
# CHAIN WITH RED TEAM:
#   ./scripts/run_validation.sh && ./scripts/run_red_team.sh --all
#
# PREREQUISITES:
#   - sentinel + sentinel-ollama containers running
#   - PIN file at ~/.secrets/sentinel_pin.txt
#   - Claude API key at ~/.secrets/claude_api_key.txt
#   - HF token at ~/.secrets/hf_token.txt (for container rebuild)
#   - Rust sidecar binary at sidecar/target/release/sentinel-sidecar
#
# OUTPUT:
#   benchmarks/validation_<timestamp>.log        — this script's log
#   benchmarks/functional_*_<timestamp>.jsonl    — per-suite results
#
# EXIT CODES:
#   0 = all suites passed
#   1 = one or more suites failed or build error
# ─────────────────────────────────────────────────────────────────

set -uo pipefail
# Note: no set -e — we handle errors manually so one suite failing
# doesn't abort the entire run.

PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
SCRIPT_DIR="$PROJECT_DIR/scripts"
COMPOSE_FILE="$PROJECT_DIR/podman-compose.yaml"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
LOG_FILE="$PROJECT_DIR/benchmarks/validation_${TIMESTAMP}.log"

TRUST_LEVEL=4
HEALTH_TIMEOUT=300  # 5 min — generous for cold start with model loading
RESTART_SETTLE=10   # seconds after compose up before health checks

# Signal config — delegated to runner_lib.sh
SIGNAL_ENABLED=1

# Flags
SKIP_REBUILD=0
DRY_RUN=0

_PREV_ARG=""
for arg in "$@"; do
    if [[ "$_PREV_ARG" == "--trust-level" ]]; then
        TRUST_LEVEL="$arg"
        _PREV_ARG=""
        continue
    fi
    case "$arg" in
        --no-signal)     SIGNAL_ENABLED=0 ;;
        --skip-rebuild)  SKIP_REBUILD=1 ;;
        --trust-level)   _PREV_ARG="$arg" ;;
        --dry-run)       DRY_RUN=1 ;;
        --help|-h)
            sed -n '2,/^# ──/{ /^# ──/d; s/^# \?//p }' "$0"
            exit 0
            ;;
        *)
            echo "ERROR: Unknown argument: $arg"
            echo "Run $0 --help for usage"
            exit 1
            ;;
    esac
    _PREV_ARG="$arg"
done

# ── Helpers ──────────────────────────────────────────────────────

mkdir -p "$PROJECT_DIR/benchmarks"

# Source shared runner library for compose locking, Signal, health checks
source "$SCRIPT_DIR/runner_lib.sh"
runner_lib_init "$PROJECT_DIR" "$COMPOSE_FILE"
[ "$SIGNAL_ENABLED" -eq 0 ] && runner_lib_signal_enabled 0
[ "$DRY_RUN" -eq 1 ] && runner_lib_signal_enabled 0

# Tee all output to log file
exec > >(tee -a "$LOG_FILE") 2>&1

log() {
    echo "[$(date +%H:%M:%S)] $*"
}

# ── Compose lifecycle ────────────────────────────────────────────
# Save current settings, switch to test mode, restore on exit.
# Uses the same save-actual-values pattern as run_red_team.sh.

ORIGINAL_APPROVAL_MODE=""
ORIGINAL_VERBOSE=""
ORIGINAL_BENCHMARK=""
ORIGINAL_TL=""

save_and_set_compose() {
    acquire_compose_lock || return 1
    # Read current values from compose (|| true prevents pipefail on missing)
    ORIGINAL_APPROVAL_MODE=$(grep 'SENTINEL_APPROVAL_MODE=' "$COMPOSE_FILE" | head -1 | cut -d= -f2 || true)
    ORIGINAL_VERBOSE=$(grep 'SENTINEL_VERBOSE_RESULTS=' "$COMPOSE_FILE" | head -1 | cut -d= -f2 || true)
    ORIGINAL_BENCHMARK=$(grep 'SENTINEL_BENCHMARK_MODE=' "$COMPOSE_FILE" | head -1 | cut -d= -f2 || true)
    ORIGINAL_TL=$(grep 'SENTINEL_TRUST_LEVEL=' "$COMPOSE_FILE" | head -1 | cut -d= -f2 || true)

    log "Saving compose settings: approval=$ORIGINAL_APPROVAL_MODE verbose=$ORIGINAL_VERBOSE benchmark=$ORIGINAL_BENCHMARK tl=$ORIGINAL_TL"

    # Apply test mode settings
    sed -i "s/SENTINEL_APPROVAL_MODE=${ORIGINAL_APPROVAL_MODE}/SENTINEL_APPROVAL_MODE=auto/" "$COMPOSE_FILE"
    sed -i "s/SENTINEL_VERBOSE_RESULTS=${ORIGINAL_VERBOSE}/SENTINEL_VERBOSE_RESULTS=true/" "$COMPOSE_FILE"
    sed -i "s/SENTINEL_BENCHMARK_MODE=${ORIGINAL_BENCHMARK}/SENTINEL_BENCHMARK_MODE=true/" "$COMPOSE_FILE"
    sed -i "s/SENTINEL_TRUST_LEVEL=${ORIGINAL_TL}/SENTINEL_TRUST_LEVEL=${TRUST_LEVEL}/" "$COMPOSE_FILE"

    log "Set: approval=auto verbose=true benchmark=true tl=${TRUST_LEVEL}"
}

restore_compose() {
    if [ -z "$ORIGINAL_APPROVAL_MODE" ]; then
        return  # Nothing saved — didn't get to save_and_set_compose
    fi

    acquire_compose_lock || true
    log "Restoring compose settings..."
    sed -i "s/SENTINEL_APPROVAL_MODE=auto/SENTINEL_APPROVAL_MODE=${ORIGINAL_APPROVAL_MODE}/" "$COMPOSE_FILE"
    sed -i "s/SENTINEL_VERBOSE_RESULTS=true/SENTINEL_VERBOSE_RESULTS=${ORIGINAL_VERBOSE}/" "$COMPOSE_FILE"
    sed -i "s/SENTINEL_BENCHMARK_MODE=true/SENTINEL_BENCHMARK_MODE=${ORIGINAL_BENCHMARK}/" "$COMPOSE_FILE"
    sed -i "s/SENTINEL_TRUST_LEVEL=${TRUST_LEVEL}/SENTINEL_TRUST_LEVEL=${ORIGINAL_TL}/" "$COMPOSE_FILE"

    log "Restored: approval=$ORIGINAL_APPROVAL_MODE verbose=$ORIGINAL_VERBOSE benchmark=$ORIGINAL_BENCHMARK tl=$ORIGINAL_TL"

    log "Restarting containers with restored settings..."
    cd "$PROJECT_DIR"
    podman compose down 2>/dev/null || true
    sleep "$_RUNNER_LIB_SETTLE_DOWN"
    podman compose up -d
    release_compose_lock
    log "Production settings restored, containers restarted."
}

# ── Dry run ──────────────────────────────────────────────────────

if [ "$DRY_RUN" -eq 1 ]; then
    echo "============================================================"
    echo "  Sentinel Validation Runner — DRY RUN"
    echo "============================================================"
    echo
    echo "  Timestamp:     $TIMESTAMP"
    echo "  Trust level:   TL${TRUST_LEVEL}"
    echo "  Log:           $LOG_FILE"
    echo "  Signal:        $([ "$SIGNAL_ENABLED" -eq 1 ] && echo "ON" || echo "OFF")"
    echo "  Health timeout: ${HEALTH_TIMEOUT}s"
    echo
    echo "  Sequence:"
    echo "    1. Save compose settings, switch to test mode"
    [ "$SKIP_REBUILD" -eq 0 ] && echo "    2. Container rebuild + tag" || echo "    2. (skip rebuild)"
    echo "    3. Container restart + health check (once for all suites)"
    echo "    4. G-suite at TL${TRUST_LEVEL}: build, debug, e2e, plans, deps (--managed, no restarts)"
    echo "    5. Summary + restore compose + restart"
    echo
    echo "  No actions taken."
    exit 0
fi

# ── Start ────────────────────────────────────────────────────────

echo "============================================================"
echo "  Sentinel Validation Runner"
echo "  $(date)"
echo "  Trust level: TL${TRUST_LEVEL}"
echo "  Log: $LOG_FILE"
echo "  Signal: $([ "$SIGNAL_ENABLED" -eq 1 ] && echo "ON" || echo "OFF")"
echo "============================================================"
echo

export PYTHONUNBUFFERED=1

OVERALL_START=$(date +%s)
GSUITE_PASS=0
GSUITE_FAIL=0
GSUITE_SUITES=(build debug e2e plans deps)

signal_notify "Validation started at TL${TRUST_LEVEL}. Rebuild=$([ "$SKIP_REBUILD" -eq 0 ] && echo yes || echo skip). Suites: ${GSUITE_SUITES[*]}. ETA ~8-10h." "[Validation]"

# ── Step 1: Set compose to test mode ─────────────────────────────

log "═══ STEP 1: Compose settings ═══"
save_and_set_compose
trap 'restore_compose; release_compose_lock' EXIT
echo

# ── Step 2: Container rebuild (optional) ─────────────────────────

if [ "$SKIP_REBUILD" -eq 0 ]; then
    log "═══ STEP 2: Container rebuild ═══"
    signal_notify "Step 2: Rebuilding container..." "[Validation]"

    rebuild_start=$(date +%s)

    # Check sidecar binary exists
    if [ ! -f "$PROJECT_DIR/sidecar/target/release/sentinel-sidecar" ]; then
        log "Sidecar binary missing — building..."
        if ! cargo build --manifest-path "$PROJECT_DIR/sidecar/Cargo.toml" --release 2>&1; then
            log "ERROR: Sidecar build failed"
            signal_notify "ABORT: Sidecar Rust build failed. Check log." "[Validation]"
            exit 1
        fi
    fi

    # Build container
    cd "$PROJECT_DIR"
    if podman build \
        --secret id=hf_token,src="$HOME/.secrets/hf_token.txt" \
        -t sentinel \
        -f container/Containerfile \
        . 2>&1; then

        # Tag for compose
        podman tag sentinel sentinel_sentinel
        rebuild_elapsed=$(( $(date +%s) - rebuild_start ))
        log "Container built + tagged in ${rebuild_elapsed}s"
        signal_notify "Container rebuilt (${rebuild_elapsed}s). Restarting..." "[Validation]"
    else
        log "ERROR: Container build failed"
        signal_notify "ABORT: Container build failed. Check log." "[Validation]"
        exit 1
    fi
    echo
else
    log "═══ STEP 2: Container rebuild (SKIPPED) ═══"
    echo
fi

# ── Step 3: Restart + health check (once for all suites) ─────────
# Picks up test mode compose settings AND new image (if rebuilt).

log "═══ STEP 3: Container restart ═══"
log "Restarting containers (test mode)..."
cd "$PROJECT_DIR"
podman compose down 2>/dev/null || true
sleep "$_RUNNER_LIB_SETTLE_DOWN"
podman compose up -d 2>&1
sleep "$_RUNNER_LIB_SETTLE_LONG"
if ! wait_for_health 300; then
    signal_notify "ABORT: Container not healthy after restart (300s timeout). Check log." "[Validation]"
    exit 1
fi
release_compose_lock
signal_notify "Containers healthy. Starting G-suite at TL${TRUST_LEVEL}..." "[Validation]"
echo

# ── Step 4: G-suite (all suites, no restarts between them) ───────

log "═══ STEP 4: G-suite (G1-G5) at TL${TRUST_LEVEL} ═══"
gsuite_start=$(date +%s)

for suite in "${GSUITE_SUITES[@]}"; do
    # ── Pre-suite gate: verify container health + config ──
    if ! verify_or_recover "auto" "true"; then
        log "FATAL: Cannot recover benchmark config. Aborting to save API cost."
        signal_notify "FATAL: Aborting validation — config corruption unrecoverable. ${GSUITE_PASS}P/${GSUITE_FAIL}F completed before abort." "[Validation]"
        # Mark remaining suites as failed
        remaining=$(( ${#GSUITE_SUITES[@]} - GSUITE_PASS - GSUITE_FAIL ))
        GSUITE_FAIL=$((GSUITE_FAIL + remaining))
        break
    fi

    log "── Starting G-suite: $suite ──"
    gsuite_elapsed_so_far=$(( $(date +%s) - gsuite_start ))
    signal_notify "Starting $suite (${GSUITE_PASS}P/${GSUITE_FAIL}F, $(format_elapsed $gsuite_elapsed_so_far) elapsed)" "[Validation]"

    suite_start=$(date +%s)
    suite_rc=0
    "$SCRIPT_DIR/run_functional_tests.sh" \
        --suite "$suite" --trust-level "$TRUST_LEVEL" --managed --foreground 2>&1 || suite_rc=$?

    suite_elapsed=$(( $(date +%s) - suite_start ))

    if [ "$suite_rc" -eq 0 ]; then
        GSUITE_PASS=$((GSUITE_PASS + 1))
        log "  $suite: DONE ($(format_elapsed $suite_elapsed))"
    else
        GSUITE_FAIL=$((GSUITE_FAIL + 1))
        log "  $suite: FAILED exit=$suite_rc ($(format_elapsed $suite_elapsed))"
    fi
    echo
done

gsuite_elapsed=$(( $(date +%s) - gsuite_start ))

# ── Auto-analyse results ─────────────────────────────────────────

log "═══ Analysing G-suite results ═══"

PYTHON="$PROJECT_DIR/.venv/bin/python3"
mkdir -p "$PROJECT_DIR/docs/assessments"

ANALYSED=0
while IFS= read -r f; do
    log "  Analysing $(basename "$f")"
    "$PYTHON" "$SCRIPT_DIR/analyse_functional_results.py" "$f" || true
    ANALYSED=$((ANALYSED + 1))
done < <(find "$PROJECT_DIR/benchmarks" -maxdepth 1 -name "functional_*.jsonl" -newer "$LOG_FILE" 2>/dev/null | sort)

if [ "$ANALYSED" -gt 0 ]; then
    log "  Generated $ANALYSED reports in docs/assessments/"
    signal_notify "G-suite analysis done ($ANALYSED reports)." "[Validation]"
else
    log "  No new JSONL found to analyse"
fi

# ── Summary ──────────────────────────────────────────────────────

overall_elapsed=$(( $(date +%s) - OVERALL_START ))

echo
echo "============================================================"
echo "  VALIDATION COMPLETE"
echo "  $(date)"
echo "  Total: $(format_elapsed $overall_elapsed)"
echo "============================================================"
echo
echo "  G-suite:   ${GSUITE_PASS}/${#GSUITE_SUITES[@]} passed"
echo "  Results:   benchmarks/functional_*.jsonl"
echo "  Reports:   docs/assessments/"
echo "  Log:       $LOG_FILE"
echo "============================================================"

final_msg="Validation complete ($(format_elapsed $overall_elapsed)). G-suite: ${GSUITE_PASS}/${#GSUITE_SUITES[@]} passed."
signal_notify "$final_msg" "[Validation]"

# Exit with non-zero if anything failed (EXIT trap restores compose)
if [ "$GSUITE_FAIL" -gt 0 ]; then
    exit 1
fi
exit 0
