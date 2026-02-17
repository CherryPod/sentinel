#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────
# Sentinel Episodic Learning Evaluation Runner
# ─────────────────────────────────────────────────────────────────
#
# Evaluates whether the episodic learning pipeline improves planner
# performance by running G2 (debug) repeatedly to accumulate
# episodic records, then running a full G-suite with a warm DB.
#
# Between each G2 run, domain summaries are refreshed so the
# hierarchical context injection (Phase 2) has aggregated data.
#
# Sets SENTINEL_LOG_LEVEL=DEBUG for the duration so the retrieval
# pipeline is fully instrumented (logs persist to /logs/).
#
# SEQUENCE:
#   1. Save compose settings, switch to test mode + DEBUG logging
#   2. Container rebuild (optional)
#   3. Seed domain summaries from existing episodic records
#   4. Run G2 × N iterations (default 3), refresh summaries between
#   5. Run full G-suite (G1-G5) with warm DB
#   6. Summary + restore settings
#
# USAGE:
#   ./scripts/run_episodic_eval.sh                  # 3×G2 + G-suite
#   ./scripts/run_episodic_eval.sh --g2-runs 5      # 5×G2 + G-suite
#   ./scripts/run_episodic_eval.sh --skip-rebuild    # skip container rebuild
#   ./scripts/run_episodic_eval.sh --skip-gsuite     # G2 runs only, no G-suite
#   ./scripts/run_episodic_eval.sh --no-signal       # no Signal notifications
#   ./scripts/run_episodic_eval.sh --dry-run         # show plan, don't execute
#
# RUN UNATTENDED:
#   nohup ./scripts/run_episodic_eval.sh > /dev/null 2>&1 &
#
# OUTPUT:
#   benchmarks/episodic_eval_<timestamp>.log         — this script's log
#   benchmarks/functional_debug_dev_*.jsonl           — per-G2 results
#   benchmarks/functional_*_<timestamp>.jsonl         — G-suite results
#   logs/audit-<date>.jsonl                           — DEBUG retrieval logs
# ─────────────────────────────────────────────────────────────────

set -uo pipefail

PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
SCRIPT_DIR="$PROJECT_DIR/scripts"
COMPOSE_FILE="$PROJECT_DIR/podman-compose.yaml"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
LOG_FILE="$PROJECT_DIR/benchmarks/episodic_eval_${TIMESTAMP}.log"
LOCK_FILE="$PROJECT_DIR/benchmarks/.episodic_eval.lock"
PYTHON="$PROJECT_DIR/.venv/bin/python3"

TRUST_LEVEL=4
G2_RUNS=3
SIGNAL_ENABLED=1
SKIP_REBUILD=0
SKIP_GSUITE=0
DRY_RUN=0

# ── Argument parsing ─────────────────────────────────────────────

_PREV_ARG=""
for arg in "$@"; do
    if [[ "$_PREV_ARG" == "--trust-level" ]]; then
        TRUST_LEVEL="$arg"; _PREV_ARG=""; continue
    fi
    if [[ "$_PREV_ARG" == "--g2-runs" ]]; then
        G2_RUNS="$arg"; _PREV_ARG=""; continue
    fi
    case "$arg" in
        --no-signal)     SIGNAL_ENABLED=0 ;;
        --skip-rebuild)  SKIP_REBUILD=1 ;;
        --skip-gsuite)   SKIP_GSUITE=1 ;;
        --trust-level)   _PREV_ARG="$arg" ;;
        --g2-runs)       _PREV_ARG="$arg" ;;
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

# ── Lock file ────────────────────────────────────────────────────

if [ -f "$LOCK_FILE" ]; then
    existing_pid=$(cat "$LOCK_FILE" 2>/dev/null || true)
    if [ -n "$existing_pid" ] && kill -0 "$existing_pid" 2>/dev/null; then
        echo "ERROR: Episodic eval already running (PID $existing_pid)"
        echo "  Lock: $LOCK_FILE"
        exit 1
    fi
    echo "WARNING: Stale lock file found (PID $existing_pid not running). Removing."
    rm -f "$LOCK_FILE"
fi
echo $$ > "$LOCK_FILE"
trap 'rm -f "$LOCK_FILE"' EXIT

# ── Helpers ──────────────────────────────────────────────────────

mkdir -p "$PROJECT_DIR/benchmarks"

source "$SCRIPT_DIR/runner_lib.sh"
runner_lib_init "$PROJECT_DIR" "$COMPOSE_FILE"
[ "$SIGNAL_ENABLED" -eq 0 ] && runner_lib_signal_enabled 0
[ "$DRY_RUN" -eq 1 ] && runner_lib_signal_enabled 0

exec > >(tee -a "$LOG_FILE") 2>&1

log() {
    echo "[$(date +%H:%M:%S)] $*"
}

# ── Compose lifecycle ────────────────────────────────────────────

ORIGINAL_APPROVAL_MODE=""
ORIGINAL_VERBOSE=""
ORIGINAL_BENCHMARK=""
ORIGINAL_TL=""
ORIGINAL_LOG_LEVEL=""

save_and_set_compose() {
    acquire_compose_lock || return 1
    ORIGINAL_APPROVAL_MODE=$(grep 'SENTINEL_APPROVAL_MODE=' "$COMPOSE_FILE" | head -1 | cut -d= -f2 || true)
    ORIGINAL_VERBOSE=$(grep 'SENTINEL_VERBOSE_RESULTS=' "$COMPOSE_FILE" | head -1 | cut -d= -f2 || true)
    ORIGINAL_BENCHMARK=$(grep 'SENTINEL_BENCHMARK_MODE=' "$COMPOSE_FILE" | head -1 | cut -d= -f2 || true)
    ORIGINAL_TL=$(grep 'SENTINEL_TRUST_LEVEL=' "$COMPOSE_FILE" | head -1 | cut -d= -f2 || true)
    ORIGINAL_LOG_LEVEL=$(grep 'SENTINEL_LOG_LEVEL=' "$COMPOSE_FILE" | head -1 | cut -d= -f2 || true)

    log "Saving compose settings: approval=$ORIGINAL_APPROVAL_MODE verbose=$ORIGINAL_VERBOSE benchmark=$ORIGINAL_BENCHMARK tl=$ORIGINAL_TL log_level=$ORIGINAL_LOG_LEVEL"

    sed -i "s/SENTINEL_APPROVAL_MODE=${ORIGINAL_APPROVAL_MODE}/SENTINEL_APPROVAL_MODE=auto/" "$COMPOSE_FILE"
    sed -i "s/SENTINEL_VERBOSE_RESULTS=${ORIGINAL_VERBOSE}/SENTINEL_VERBOSE_RESULTS=true/" "$COMPOSE_FILE"
    sed -i "s/SENTINEL_BENCHMARK_MODE=${ORIGINAL_BENCHMARK}/SENTINEL_BENCHMARK_MODE=true/" "$COMPOSE_FILE"
    sed -i "s/SENTINEL_TRUST_LEVEL=${ORIGINAL_TL}/SENTINEL_TRUST_LEVEL=${TRUST_LEVEL}/" "$COMPOSE_FILE"
    sed -i "s/SENTINEL_LOG_LEVEL=${ORIGINAL_LOG_LEVEL}/SENTINEL_LOG_LEVEL=DEBUG/" "$COMPOSE_FILE"

    log "Set: approval=auto verbose=true benchmark=true tl=${TRUST_LEVEL} log_level=DEBUG"
}

restore_compose() {
    if [ -z "$ORIGINAL_APPROVAL_MODE" ]; then
        return
    fi

    acquire_compose_lock || true
    log "Restoring compose settings..."
    sed -i "s/SENTINEL_APPROVAL_MODE=auto/SENTINEL_APPROVAL_MODE=${ORIGINAL_APPROVAL_MODE}/" "$COMPOSE_FILE"
    sed -i "s/SENTINEL_VERBOSE_RESULTS=true/SENTINEL_VERBOSE_RESULTS=${ORIGINAL_VERBOSE}/" "$COMPOSE_FILE"
    sed -i "s/SENTINEL_BENCHMARK_MODE=true/SENTINEL_BENCHMARK_MODE=${ORIGINAL_BENCHMARK}/" "$COMPOSE_FILE"
    sed -i "s/SENTINEL_TRUST_LEVEL=${TRUST_LEVEL}/SENTINEL_TRUST_LEVEL=${ORIGINAL_TL}/" "$COMPOSE_FILE"
    sed -i "s/SENTINEL_LOG_LEVEL=DEBUG/SENTINEL_LOG_LEVEL=${ORIGINAL_LOG_LEVEL}/" "$COMPOSE_FILE"

    log "Restored: approval=$ORIGINAL_APPROVAL_MODE verbose=$ORIGINAL_VERBOSE benchmark=$ORIGINAL_BENCHMARK tl=$ORIGINAL_TL log_level=$ORIGINAL_LOG_LEVEL"

    log "Restarting containers with restored settings..."
    cd "$PROJECT_DIR"
    podman compose down 2>/dev/null || true
    sleep "$_RUNNER_LIB_SETTLE_DOWN"
    podman compose up -d
    release_compose_lock
    log "Production settings restored, containers restarted."
}

# ── Domain summary seeding ───────────────────────────────────────

seed_domain_summaries() {
    # Generate domain summaries from existing episodic records.
    # Prints full summary text for visibility.
    local label="${1:-seed}"
    log "Generating domain summaries ($label)..."

    local output
    output=$(timeout 60 podman exec sentinel python3 -c "
import asyncio, sys
sys.path.insert(0, '/app')

async def seed():
    import asyncpg
    from sentinel.core.context import current_user_id
    from sentinel.memory.episodic import EpisodicStore
    from sentinel.memory.domain_summary import DomainSummaryStore, generate_domain_summary

    current_user_id.set(1)
    pool = await asyncpg.create_pool(
        'postgresql://sentinel_owner:sentinel_owner_pass@/sentinel?host=/tmp',
        min_size=1, max_size=1,
    )

    # Get domains with record counts
    async with pool.acquire() as conn:
        await conn.execute(\"SET LOCAL app.current_user_id = '1'\")
        rows = await conn.fetch(
            \"SELECT task_domain, count(*) as n FROM episodic_records \"
            \"WHERE task_domain IS NOT NULL GROUP BY task_domain ORDER BY n DESC\"
        )

    if not rows:
        print('NO_RECORDS')
        await pool.close()
        return

    episodic_store = EpisodicStore(pool=pool)
    summary_store = DomainSummaryStore(pool=pool)

    for row in rows:
        domain = row['task_domain']
        count = row['n']
        try:
            summary = await generate_domain_summary(domain, episodic_store, user_id=1)
            await summary_store.upsert(summary)
            print(f'DOMAIN:{domain}|COUNT:{count}|TEXT:{summary.summary_text}')
        except Exception as e:
            print(f'ERROR:{domain}|{e}')

    await pool.close()

asyncio.run(seed())
" 2>&1) || true

    if [ -z "$output" ] || echo "$output" | grep -q "NO_RECORDS"; then
        log "  No episodic records found — nothing to seed"
        signal_notify "Summary seed ($label): no episodic records in DB" "[Episodic]"
        return 1
    fi

    # Parse and display results
    local summary_msg=""
    while IFS= read -r line; do
        if [[ "$line" == DOMAIN:* ]]; then
            local domain count text
            domain=$(echo "$line" | sed 's/DOMAIN:\([^|]*\).*/\1/')
            count=$(echo "$line" | sed 's/.*COUNT:\([^|]*\).*/\1/')
            text=$(echo "$line" | sed 's/.*TEXT://')
            log "  $domain ($count records): $text"
            summary_msg="${summary_msg}${domain}(${count}): ${text}\n"
        elif [[ "$line" == ERROR:* ]]; then
            log "  ERROR: $line"
        fi
    done <<< "$output"

    signal_notify "Summary $label done. $(echo "$output" | grep -c '^DOMAIN:') domains refreshed. Check runner log for details." "[Episodic]"
}

# ── Episodic DB record count ─────────────────────────────────────

get_episodic_counts() {
    # Returns "total|debug_count" or "0|0" on failure
    timeout 15 podman exec sentinel python3 -c "
import asyncio, asyncpg
async def count():
    conn = await asyncpg.connect('postgresql://sentinel_owner:sentinel_owner_pass@/sentinel?host=/tmp')
    await conn.execute(\"SET LOCAL app.current_user_id = '1'\")
    total = await conn.fetchval('SELECT count(*) FROM episodic_records')
    debug = await conn.fetchval(\"SELECT count(*) FROM episodic_records WHERE task_domain = 'code_debugging'\")
    print(f'{total}|{debug}')
    await conn.close()
asyncio.run(count())
" 2>/dev/null || echo "0|0"
}

# ── G2 score extraction ─────────────────────────────────────────

get_g2_score() {
    # Extract converged/total from a G2 debug JSONL file
    local jsonl="$1"
    "$PYTHON" -c "
import json, sys
lines = [json.loads(l) for l in open(sys.argv[1]) if json.loads(l).get('prompt_id')]
total = len(lines)
converged = sum(1 for l in lines if l.get('convergence'))
print(f'{converged}/{total}')
" "$jsonl" 2>/dev/null || echo "?/?"
}

# ── Dry run ──────────────────────────────────────────────────────

if [ "$DRY_RUN" -eq 1 ]; then
    echo "============================================================"
    echo "  Episodic Learning Evaluation — DRY RUN"
    echo "============================================================"
    echo
    echo "  Timestamp:     $TIMESTAMP"
    echo "  Trust level:   TL${TRUST_LEVEL}"
    echo "  G2 runs:       $G2_RUNS"
    echo "  G-suite:       $([ "$SKIP_GSUITE" -eq 0 ] && echo "yes" || echo "skip")"
    echo "  Log:           $LOG_FILE"
    echo "  Signal:        $([ "$SIGNAL_ENABLED" -eq 1 ] && echo "ON" || echo "OFF")"
    echo
    echo "  Sequence:"
    echo "    1. Save compose, set test mode + DEBUG logging"
    [ "$SKIP_REBUILD" -eq 0 ] && echo "    2. Container rebuild + tag" || echo "    2. (skip rebuild)"
    echo "    3. Seed domain summaries from existing records"
    echo "    4. G2 × $G2_RUNS (refresh summaries between each)"
    [ "$SKIP_GSUITE" -eq 0 ] && echo "    5. Full G-suite (G1-G5) with warm DB" || echo "    5. (skip G-suite)"
    echo "    6. Summary + restore compose + restart"
    echo
    echo "  Estimated runtime:"
    echo "    G2 × $G2_RUNS: ~$((G2_RUNS * 150))m"
    [ "$SKIP_GSUITE" -eq 0 ] && echo "    G-suite:  ~300m"
    echo "    Total:    ~$(( G2_RUNS * 150 + (1 - SKIP_GSUITE) * 300 ))m"
    echo
    echo "  No actions taken."
    exit 0
fi

# ── Start ────────────────────────────────────────────────────────

echo "============================================================"
echo "  Episodic Learning Evaluation"
echo "  $(date)"
echo "  G2 runs: $G2_RUNS + $([ "$SKIP_GSUITE" -eq 0 ] && echo "full G-suite" || echo "no G-suite")"
echo "  Trust level: TL${TRUST_LEVEL}"
echo "  Log level: DEBUG (retrieval pipeline instrumented)"
echo "  Log: $LOG_FILE"
echo "============================================================"
echo

export PYTHONUNBUFFERED=1

OVERALL_START=$(date +%s)
G2_SCORES=()

signal_notify "Episodic eval starting. ${G2_RUNS}×G2 + $([ "$SKIP_GSUITE" -eq 0 ] && echo "G-suite" || echo "no G-suite"). TL${TRUST_LEVEL}. DEBUG logging enabled." "[Episodic]"

# ── Step 1: Set compose to test mode + DEBUG ─────────────────────

log "═══ STEP 1: Compose settings ═══"
save_and_set_compose
# Update trap to include both restore and lock cleanup
trap 'restore_compose; release_compose_lock; rm -f "$LOCK_FILE"' EXIT
echo

# ── Step 2: Container rebuild (optional) ─────────────────────────

if [ "$SKIP_REBUILD" -eq 0 ]; then
    log "═══ STEP 2: Container rebuild ═══"
    signal_notify "Rebuilding container..." "[Episodic]"

    rebuild_start=$(date +%s)

    if [ ! -f "$PROJECT_DIR/sidecar/target/release/sentinel-sidecar" ]; then
        log "Sidecar binary missing — building..."
        if ! cargo build --manifest-path "$PROJECT_DIR/sidecar/Cargo.toml" --release 2>&1; then
            log "ERROR: Sidecar build failed"
            signal_notify "ABORT: Sidecar build failed." "[Episodic]"
            exit 1
        fi
    fi

    cd "$PROJECT_DIR"
    if podman build \
        --secret id=hf_token,src="$HOME/.secrets/hf_token.txt" \
        -t sentinel \
        -f container/Containerfile \
        . 2>&1; then
        podman tag sentinel sentinel_sentinel
        rebuild_elapsed=$(( $(date +%s) - rebuild_start ))
        log "Container built + tagged in ${rebuild_elapsed}s"
        signal_notify "Container rebuilt (${rebuild_elapsed}s)." "[Episodic]"
    else
        log "ERROR: Container build failed"
        signal_notify "ABORT: Container build failed." "[Episodic]"
        exit 1
    fi
    echo
else
    log "═══ STEP 2: Container rebuild (SKIPPED) ═══"
    echo
fi

# ── Step 3: Restart + health check ───────────────────────────────

log "═══ STEP 3: Container restart (DEBUG logging) ═══"
cd "$PROJECT_DIR"
podman compose down 2>/dev/null || true
sleep "$_RUNNER_LIB_SETTLE_DOWN"
podman compose up -d 2>&1
sleep "$_RUNNER_LIB_SETTLE_LONG"
if ! wait_for_health 300; then
    signal_notify "ABORT: Container not healthy after restart." "[Episodic]"
    exit 1
fi
release_compose_lock
signal_notify "Containers healthy (DEBUG logging active)." "[Episodic]"
echo

# ── Step 4: Initial domain summary seed ──────────────────────────

log "═══ STEP 4: Initial domain summary seed ═══"
counts=$(get_episodic_counts)
total_records=$(echo "$counts" | cut -d'|' -f1)
debug_records=$(echo "$counts" | cut -d'|' -f2)
log "Episodic DB: $total_records total, $debug_records debug records"
signal_notify "DB state: $total_records total, $debug_records debug records. Seeding summaries..." "[Episodic]"

seed_domain_summaries "initial"
echo

# ── Step 5: G2 × N iterations ───────────────────────────────────

log "═══ STEP 5: G2 × $G2_RUNS iterations ═══"

for i in $(seq 1 "$G2_RUNS"); do
    log "── G2 Run $i/$G2_RUNS ──"

    # Pre-run: record count
    counts=$(get_episodic_counts)
    total_records=$(echo "$counts" | cut -d'|' -f1)
    debug_records=$(echo "$counts" | cut -d'|' -f2)
    log "  DB before: $total_records total, $debug_records debug"

    # Pre-suite gate
    if ! verify_or_recover "auto" "true"; then
        log "FATAL: Config corruption. Aborting."
        signal_notify "FATAL: Config corruption before G2 run $i. Aborting." "[Episodic]"
        break
    fi

    signal_notify "G2 run $i/$G2_RUNS starting ($debug_records debug records in DB)" "[Episodic]"

    g2_start=$(date +%s)
    g2_rc=0
    "$SCRIPT_DIR/run_functional_tests.sh" \
        --suite debug --trust-level "$TRUST_LEVEL" --managed --foreground 2>&1 || g2_rc=$?

    g2_elapsed=$(( $(date +%s) - g2_start ))

    # Find the JSONL that was just created
    g2_jsonl=$(ls -t "$PROJECT_DIR"/benchmarks/functional_debug_dev_*.jsonl 2>/dev/null | head -1)
    g2_score="?/?"
    if [ -n "$g2_jsonl" ]; then
        g2_score=$(get_g2_score "$g2_jsonl")
    fi
    G2_SCORES+=("$g2_score")

    # Post-run: updated record count
    counts=$(get_episodic_counts)
    total_records=$(echo "$counts" | cut -d'|' -f1)
    debug_records=$(echo "$counts" | cut -d'|' -f2)

    log "  G2 Run $i: $g2_score ($(format_elapsed $g2_elapsed)). DB: $total_records total, $debug_records debug"
    signal_notify "G2 run $i/$G2_RUNS: $g2_score ($(format_elapsed $g2_elapsed)). DB: $total_records total, $debug_records debug." "[Episodic]"

    # Refresh domain summaries between runs (not after the last one — G-suite will do it)
    if [ "$i" -lt "$G2_RUNS" ] || [ "$SKIP_GSUITE" -eq 0 ]; then
        log "  Refreshing domain summaries..."
        seed_domain_summaries "post-G2-run-$i"
    fi

    echo
done

# ── Step 6: Full G-suite (optional) ─────────────────────────────

if [ "$SKIP_GSUITE" -eq 0 ]; then
    log "═══ STEP 6: Full G-suite with warm DB ═══"

    # Final summary refresh before G-suite
    log "  Final domain summary refresh..."
    seed_domain_summaries "pre-gsuite"

    counts=$(get_episodic_counts)
    total_records=$(echo "$counts" | cut -d'|' -f1)
    debug_records=$(echo "$counts" | cut -d'|' -f2)

    signal_notify "Starting full G-suite ($total_records total, $debug_records debug records). ETA ~5h." "[Episodic]"

    GSUITE_SUITES=(build debug e2e plans deps)
    GSUITE_PASS=0
    GSUITE_FAIL=0
    gsuite_start=$(date +%s)

    for suite in "${GSUITE_SUITES[@]}"; do
        if ! verify_or_recover "auto" "true"; then
            log "FATAL: Config corruption during G-suite. Aborting."
            signal_notify "FATAL: Config corruption during G-suite ($suite). ${GSUITE_PASS}P/${GSUITE_FAIL}F before abort." "[Episodic]"
            remaining=$(( ${#GSUITE_SUITES[@]} - GSUITE_PASS - GSUITE_FAIL ))
            GSUITE_FAIL=$((GSUITE_FAIL + remaining))
            break
        fi

        log "── G-suite: $suite ──"
        gsuite_elapsed_so_far=$(( $(date +%s) - gsuite_start ))
        signal_notify "G-suite: starting $suite (${GSUITE_PASS}P/${GSUITE_FAIL}F, $(format_elapsed $gsuite_elapsed_so_far) elapsed)" "[Episodic]"

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

        # Refresh summaries after each suite — accumulate cross-domain data
        seed_domain_summaries "post-gsuite-$suite"
        echo
    done

    gsuite_elapsed=$(( $(date +%s) - gsuite_start ))

    # Auto-analyse results
    log "═══ Analysing results ═══"
    mkdir -p "$PROJECT_DIR/docs/assessments"
    ANALYSED=0
    while IFS= read -r f; do
        log "  Analysing $(basename "$f")"
        "$PYTHON" "$SCRIPT_DIR/analyse_functional_results.py" "$f" || true
        ANALYSED=$((ANALYSED + 1))
    done < <(find "$PROJECT_DIR/benchmarks" -maxdepth 1 -name "functional_*.jsonl" -newer "$LOG_FILE" 2>/dev/null | sort)

    signal_notify "G-suite complete ($(format_elapsed $gsuite_elapsed)). ${GSUITE_PASS}/${#GSUITE_SUITES[@]} passed. $ANALYSED reports generated." "[Episodic]"
fi

# ── Summary ──────────────────────────────────────────────────────

overall_elapsed=$(( $(date +%s) - OVERALL_START ))

# Final DB state
counts=$(get_episodic_counts)
total_records=$(echo "$counts" | cut -d'|' -f1)
debug_records=$(echo "$counts" | cut -d'|' -f2)

echo
echo "============================================================"
echo "  EPISODIC EVALUATION COMPLETE"
echo "  $(date)"
echo "  Total: $(format_elapsed $overall_elapsed)"
echo "============================================================"
echo
echo "  G2 accumulation curve:"
for i in "${!G2_SCORES[@]}"; do
    echo "    Run $((i+1)): ${G2_SCORES[$i]}"
done
echo
if [ "$SKIP_GSUITE" -eq 0 ]; then
    echo "  G-suite: ${GSUITE_PASS}/${#GSUITE_SUITES[@]} passed ($(format_elapsed $gsuite_elapsed))"
fi
echo "  Final DB: $total_records total, $debug_records debug records"
echo
echo "  Logs:"
echo "    Runner:     $LOG_FILE"
echo "    Retrieval:  $PROJECT_DIR/logs/audit-$(date +%Y-%m-%d).jsonl"
echo "    Results:    benchmarks/functional_*.jsonl"
echo "    Reports:    docs/assessments/"
echo "============================================================"

# Build final Signal summary
g2_summary="G2 curve:"
for i in "${!G2_SCORES[@]}"; do
    g2_summary="$g2_summary Run$((i+1))=${G2_SCORES[$i]}"
done
gsuite_summary=""
if [ "$SKIP_GSUITE" -eq 0 ]; then
    gsuite_summary=" G-suite: ${GSUITE_PASS}/${#GSUITE_SUITES[@]}."
fi
signal_notify "Episodic eval complete ($(format_elapsed $overall_elapsed)). $g2_summary.$gsuite_summary DB: $total_records total, $debug_records debug. Retrieval logs in audit-$(date +%Y-%m-%d).jsonl" "[Episodic]"

exit 0
