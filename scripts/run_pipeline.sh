#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────
# Sentinel Pipeline Runner
# ─────────────────────────────────────────────────────────────────
#
# Chains the validation runner (rebuild + G-suite) and the red team
# runner (B1, B1.5, B2, B3) into a single unattended pipeline.
# Signal messages arrive at each phase transition.
#
# SEQUENCE:
#   1. Validation — container rebuild + G1-G5 functional suites
#   2. Red team   — B3-P1 gate → B1 → B1.5 → B2 → B3-P2 → B4 → B5
#   3. Analysis   — G-suite + red team report generation, consolidated summary
#   4. Summary
#
# G-suite failures do NOT abort the red team — the two suites are
# independent, and Qwen variance means some G-suite failures are
# expected. Both results are reported in the final summary.
#
# USAGE:
#   ./scripts/run_pipeline.sh                  # full pipeline
#   ./scripts/run_pipeline.sh --skip-rebuild   # skip container rebuild
#   ./scripts/run_pipeline.sh --skip-redteam   # validation only
#   ./scripts/run_pipeline.sh --skip-gsuite    # red team only (no rebuild)
#   ./scripts/run_pipeline.sh --skip-analysis  # skip report generation
#   ./scripts/run_pipeline.sh --no-signal      # suppress Signal messages
#   ./scripts/run_pipeline.sh --trust-level 3  # run at TL3
#   ./scripts/run_pipeline.sh --dry-run        # show plan, don't execute
#
# RUN UNATTENDED:
#   nohup ./scripts/run_pipeline.sh > /dev/null 2>&1 &
#   # All output goes to benchmarks/pipeline_*.log
#   # Signal messages arrive on your phone as it progresses
#
# PREREQUISITES:
#   - sentinel + sentinel-ollama containers running
#   - PIN file at ~/.secrets/sentinel_pin.txt
#   - Claude API key at ~/.secrets/claude_api_key.txt
#   - HF token at ~/.secrets/hf_token.txt (for container rebuild)
#   - Rust sidecar binary at sidecar/target/release/sentinel-sidecar
#
# EXIT CODES:
#   0 = pipeline completed (check individual results for pass/fail)
#   1 = hard failure (build error, infrastructure broken)
# ─────────────────────────────────────────────────────────────────

set -uo pipefail

PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
SCRIPT_DIR="$PROJECT_DIR/scripts"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
LOG_FILE="$PROJECT_DIR/benchmarks/pipeline_${TIMESTAMP}.log"

# Signal config — delegated to runner_lib.sh
SIGNAL_ENABLED=1

# Flags
TRUST_LEVEL=4
SKIP_REBUILD=0
SKIP_GSUITE=0
SKIP_REDTEAM=0
SKIP_ANALYSIS=0
DRY_RUN=0
NO_SIGNAL_FLAG=""

_PREV_ARG=""
for arg in "$@"; do
    if [[ "$_PREV_ARG" == "--trust-level" ]]; then
        TRUST_LEVEL="$arg"
        _PREV_ARG=""
        continue
    fi
    case "$arg" in
        --no-signal)      SIGNAL_ENABLED=0; NO_SIGNAL_FLAG="--no-signal" ;;
        --skip-rebuild)   SKIP_REBUILD=1 ;;
        --skip-gsuite)    SKIP_GSUITE=1 ;;
        --skip-redteam)   SKIP_REDTEAM=1 ;;
        --skip-analysis)  SKIP_ANALYSIS=1 ;;
        --trust-level)    _PREV_ARG="$arg" ;;
        --dry-run)        DRY_RUN=1 ;;
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

# Create a timestamp marker file for -newer comparisons.
# The log file's mtime is continuously updated by tee, making
# -newer $LOG_FILE unreliable. This marker is touched once and
# never written to again.
MARKER_FILE="$PROJECT_DIR/benchmarks/.pipeline_start_${TIMESTAMP}"
touch "$MARKER_FILE"

# Tee all output to log file
exec > >(tee -a "$LOG_FILE") 2>&1

log() {
    echo "[$(date +%H:%M:%S)] $*"
}

# Source shared runner library for Signal, health checks, format helpers
source "$SCRIPT_DIR/runner_lib.sh"
runner_lib_init "$PROJECT_DIR" "$PROJECT_DIR/podman-compose.yaml"
[ "$SIGNAL_ENABLED" -eq 0 ] && runner_lib_signal_enabled 0
[ "$DRY_RUN" -eq 1 ] && runner_lib_signal_enabled 0

# ── Dry run ──────────────────────────────────────────────────────

if [ "$DRY_RUN" -eq 1 ]; then
    echo "============================================================"
    echo "  Sentinel Pipeline Runner — DRY RUN"
    echo "============================================================"
    echo
    echo "  Timestamp:     $TIMESTAMP"
    echo "  Trust level:   TL${TRUST_LEVEL}"
    echo "  Log:           $LOG_FILE"
    echo "  Signal:        $([ "$SIGNAL_ENABLED" -eq 1 ] && echo "ON" || echo "OFF")"
    echo
    echo "  Sequence:"
    if [ "$SKIP_GSUITE" -eq 0 ]; then
        [ "$SKIP_REBUILD" -eq 0 ] && echo "    1. Validation: rebuild + G1-G5" || echo "    1. Validation: G1-G5 (skip rebuild)"
    else
        echo "    1. Validation: SKIPPED"
    fi
    if [ "$SKIP_REDTEAM" -eq 0 ]; then
        echo "    2. Red team: B3-P1 → B1 → B1.5 → B2 → B3-P2 → B4"
    else
        echo "    2. Red team: SKIPPED"
    fi
    if [ "$SKIP_ANALYSIS" -eq 0 ]; then
        echo "    3. Analysis: G-suite + red team reports → consolidated summary"
    else
        echo "    3. Analysis: SKIPPED"
    fi
    echo "    4. Summary"
    echo
    echo "  No actions taken."
    exit 0
fi

# ── Start ────────────────────────────────────────────────────────

OVERALL_START=$(date +%s)

echo "============================================================"
echo "  Sentinel Pipeline Runner"
echo "  $(date)"
echo "  Trust level: TL${TRUST_LEVEL}"
echo "  Log: $LOG_FILE"
echo "  Signal: $([ "$SIGNAL_ENABLED" -eq 1 ] && echo "ON" || echo "OFF")"
echo "  Validation: $([ "$SKIP_GSUITE" -eq 0 ] && echo "YES" || echo "SKIP")"
echo "  Red team: $([ "$SKIP_REDTEAM" -eq 0 ] && echo "YES" || echo "SKIP")"
echo "  Analysis: $([ "$SKIP_ANALYSIS" -eq 0 ] && echo "YES" || echo "SKIP")"
echo "============================================================"
echo

parts=""
[ "$SKIP_GSUITE" -eq 0 ] && parts="validation"
[ "$SKIP_REDTEAM" -eq 0 ] && parts="${parts:+$parts + }red team"
signal_notify "Pipeline started at TL${TRUST_LEVEL}: ${parts}." "[Pipeline]"

VALIDATION_RESULT=""
REDTEAM_RESULT=""

# ── Phase 1: Validation (rebuild + G-suite) ──────────────────────

if [ "$SKIP_GSUITE" -eq 0 ]; then
    log "═══════════════════════════════════════════════════════════"
    log "  PHASE 1: VALIDATION (rebuild + G-suite)"
    log "═══════════════════════════════════════════════════════════"
    echo

    validation_start=$(date +%s)
    validation_rc=0

    # Build the validation args
    validation_args=(--trust-level "$TRUST_LEVEL")
    [ "$SKIP_REBUILD" -eq 1 ] && validation_args+=(--skip-rebuild)
    [ -n "$NO_SIGNAL_FLAG" ] && validation_args+=("$NO_SIGNAL_FLAG")

    "$SCRIPT_DIR/run_validation.sh" "${validation_args[@]}" || validation_rc=$?

    validation_elapsed=$(( $(date +%s) - validation_start ))
    val_hours=$((validation_elapsed / 3600))
    val_mins=$(( (validation_elapsed % 3600) / 60 ))

    if [ "$validation_rc" -eq 0 ]; then
        VALIDATION_RESULT="PASS (${val_hours}h ${val_mins}m)"
        log "Validation phase: PASS (${val_hours}h ${val_mins}m)"
    else
        VALIDATION_RESULT="ISSUES (exit $validation_rc, ${val_hours}h ${val_mins}m)"
        log "Validation phase: completed with issues (exit $validation_rc, ${val_hours}h ${val_mins}m)"
    fi

    signal_notify "Validation done: $VALIDATION_RESULT. $([ "$SKIP_REDTEAM" -eq 0 ] && echo "Starting red team in 30s..." || echo "Pipeline complete.")" "[Pipeline]"
    echo
else
    VALIDATION_RESULT="SKIPPED"
    log "═══ PHASE 1: VALIDATION (SKIPPED) ═══"
    echo
fi

# ── Phase transition: settle gap ─────────────────────────────────

if [ "$SKIP_GSUITE" -eq 0 ] && [ "$SKIP_REDTEAM" -eq 0 ]; then
    log "── Phase transition: validation → red team ──"
    log "  Waiting 30s for containers to settle after G-suite cleanup..."
    sleep 30

    # Verify containers are healthy before starting red team.
    # The validation EXIT trap restarts containers with production settings,
    # but this may race with the red team startup. Belt-and-suspenders.
    log "  Verifying container health..."
    health_ok=0
    for attempt in 1 2 3; do
        if python3 -c "
import urllib.request, ssl, json, sys
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
try:
    r = json.loads(urllib.request.urlopen('https://localhost:3001/health', context=ctx, timeout=10).read())
    sys.exit(0 if r.get('status') == 'ok' else 1)
except Exception: sys.exit(1)
" 2>/dev/null; then
            health_ok=1
            log "  Health check: OK"
            break
        fi
        log "  Health check failed (attempt $attempt/3), waiting 15s..."
        sleep 15
    done

    if [ "$health_ok" -eq 0 ]; then
        log "  WARNING: Container not healthy. Red team will restart anyway."
        signal_notify "WARNING: containers unhealthy between phases. Red team will restart." "[Pipeline]"
    fi
    echo
fi

# ── Phase 2: Red Team ────────────────────────────────────────────

if [ "$SKIP_REDTEAM" -eq 0 ]; then
    log "═══════════════════════════════════════════════════════════"
    log "  PHASE 2: RED TEAM"
    log "═══════════════════════════════════════════════════════════"
    echo

    redteam_start=$(date +%s)
    redteam_rc=0

    # Build the red team args — always --all, pass through flags
    # Red team does its own restart with red team settings (auto approval,
    # benchmark mode, appropriate TL). It also handles B2 RED_TEAM_MODE toggle.
    redteam_args=(--all --v2 --trust-level "$TRUST_LEVEL")
    [ -n "$NO_SIGNAL_FLAG" ] && redteam_args+=("$NO_SIGNAL_FLAG")

    "$SCRIPT_DIR/run_red_team.sh" "${redteam_args[@]}" || redteam_rc=$?

    redteam_elapsed=$(( $(date +%s) - redteam_start ))
    rt_hours=$((redteam_elapsed / 3600))
    rt_mins=$(( (redteam_elapsed % 3600) / 60 ))

    if [ "$redteam_rc" -eq 0 ]; then
        REDTEAM_RESULT="COMPLETE (${rt_hours}h ${rt_mins}m)"
        log "Red team phase: complete (${rt_hours}h ${rt_mins}m)"
    elif [ "$redteam_rc" -eq 2 ]; then
        REDTEAM_RESULT="B3 GATE FAIL (${rt_hours}h ${rt_mins}m)"
        log "Red team phase: B3 gate failed (${rt_hours}h ${rt_mins}m)"
    else
        REDTEAM_RESULT="ERROR exit=$redteam_rc (${rt_hours}h ${rt_mins}m)"
        log "Red team phase: error exit=$redteam_rc (${rt_hours}h ${rt_mins}m)"
    fi
    echo
else
    REDTEAM_RESULT="SKIPPED"
    log "═══ PHASE 2: RED TEAM (SKIPPED) ═══"
    echo
fi

# ── Phase 3: Analysis ────────────────────────────────────────────

ANALYSIS_RESULT="SKIPPED"

if [ "$SKIP_ANALYSIS" -eq 0 ]; then
    PYTHON="$PROJECT_DIR/.venv/bin/python3"

    log "═══════════════════════════════════════════════════════════"
    log "  PHASE 3: ANALYSIS"
    log "═══════════════════════════════════════════════════════════"
    echo

    signal_notify "Phase 3: Generating analysis reports..." "[Pipeline]"
    mkdir -p "$PROJECT_DIR/docs/assessments"

    # Collect G-suite JSONL files created during this pipeline run.
    # Uses -newer $LOG_FILE — the log was created at pipeline start,
    # so any functional JSONL newer than it was produced by this run.
    GSUITE_JSONL=()
    while IFS= read -r f; do
        GSUITE_JSONL+=("$f")
    done < <(find "$PROJECT_DIR/benchmarks" -maxdepth 1 -name "functional_*.jsonl" -newer "$MARKER_FILE" 2>/dev/null | sort)

    if [ "${#GSUITE_JSONL[@]}" -gt 0 ]; then
        log "Analysing ${#GSUITE_JSONL[@]} G-suite results..."
        for f in "${GSUITE_JSONL[@]}"; do
            log "  $(basename "$f")"
            "$PYTHON" "$SCRIPT_DIR/analyse_functional_results.py" "$f" || true
        done
        signal_notify "G-suite analysis done (${#GSUITE_JSONL[@]} reports)." "[Pipeline]"
    else
        log "No G-suite JSONL found for this run"
    fi

    # Red team analysis — only if red team ran AND its runner didn't already analyse.
    # run_red_team.sh calls analyse_red_team.py internally, so check for existing reports.
    REDTEAM_JSONL=()
    while IFS= read -r f; do
        REDTEAM_JSONL+=("$f")
    done < <(find "$PROJECT_DIR/benchmarks" -maxdepth 1 \( -name "red_team_*.jsonl" -o -name "b3_perimeter_*.jsonl" \) -newer "$MARKER_FILE" 2>/dev/null | sort)

    rt_analysed=0
    if [ "${#REDTEAM_JSONL[@]}" -gt 0 ]; then
        for f in "${REDTEAM_JSONL[@]}"; do
            report="$PROJECT_DIR/docs/assessments/$(basename "${f%.jsonl}").md"
            if [ ! -f "$report" ]; then
                log "  Analysing $(basename "$f") (not yet analysed)"
                "$PYTHON" "$SCRIPT_DIR/analyse_red_team.py" "$f" || true
                rt_analysed=$((rt_analysed + 1))
            fi
        done
        if [ "$rt_analysed" -gt 0 ]; then
            signal_notify "Red team analysis done (${rt_analysed} new reports)." "[Pipeline]"
        else
            log "  All red team results already analysed by runner"
        fi
    fi

    # Consolidated pipeline summary — single scorecard with all results
    SUMMARY_FILE="$PROJECT_DIR/docs/assessments/pipeline_${TIMESTAMP}.md"
    ALL_JSONL=("${GSUITE_JSONL[@]}" "${REDTEAM_JSONL[@]}")

    if [ "${#ALL_JSONL[@]}" -gt 0 ]; then
        log "Generating consolidated pipeline report..."
        "$PYTHON" "$SCRIPT_DIR/analyse_pipeline_results.py" \
            --output "$SUMMARY_FILE" \
            --timestamp "$TIMESTAMP" \
            "${ALL_JSONL[@]}" || true
    else
        log "WARNING: No JSONL files found for consolidated report"
        echo "# Pipeline Run — $(date '+%Y-%m-%d %H:%M')" > "$SUMMARY_FILE"
        echo "" >> "$SUMMARY_FILE"
        echo "No results found. Check -newer marker file." >> "$SUMMARY_FILE"
    fi

    ANALYSIS_RESULT="DONE"
    log "Analysis complete. Summary: $SUMMARY_FILE"
    log "Reports: docs/assessments/"
    signal_notify "Analysis complete. Reports in docs/assessments/" "[Pipeline]"
    echo
else
    log "═══ PHASE 3: ANALYSIS (SKIPPED) ═══"
    echo
fi

# ── Summary ──────────────────────────────────────────────────────

overall_elapsed=$(( $(date +%s) - OVERALL_START ))

echo "============================================================"
echo "  PIPELINE COMPLETE"
echo "  $(date)"
echo "  Total: $(format_elapsed $overall_elapsed)"
echo "============================================================"
echo
echo "  Validation: $VALIDATION_RESULT"
echo "  Red team:   $REDTEAM_RESULT"
echo "  Analysis:   $ANALYSIS_RESULT"
echo
echo "  Results:  benchmarks/functional_*.jsonl, benchmarks/red_team_*.jsonl"
echo "  Reports:  docs/assessments/"
echo "  Log:      $LOG_FILE"
echo "============================================================"

# Clean up marker file
rm -f "$MARKER_FILE"

signal_notify "Pipeline complete ($(format_elapsed $overall_elapsed)). Validation: $VALIDATION_RESULT. Red team: $REDTEAM_RESULT. Analysis: $ANALYSIS_RESULT." "[Pipeline]"
