#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────
# Mini G-Suite: fast feedback benchmark for iterative development
#
# Runs a targeted subset of G2 (debug) + full G3 (e2e) in ~30-40 min.
# Designed for quick regression checks between code changes, NOT for
# release validation. Use run_pipeline.sh for full validation.
#
# What it runs:
#   G2: Category A only, 1 trial each (4 scenarios, ~15-20 min)
#   G3: All 8 scenarios (already fast at ~16 min)
#
# What it skips (runtime budget):
#   Cat B (b1-b3): 15-33 min per scenario, too slow for fast feedback
#   Cat C (c2, c3): 17-28 min per scenario, too slow for fast feedback
#   Cat C c1 omitted with rest of Cat C (consistently passes anyway)
#   Run full G2 at benchmark gates for complete coverage.
#
# Usage:
#   ./scripts/run_mini_gsuite.sh                        # foreground
#   ./scripts/run_mini_gsuite.sh --no-signal             # no Signal msgs
#   ./scripts/run_mini_gsuite.sh --trust-level 3         # override TL
#   nohup ./scripts/run_mini_gsuite.sh > /dev/null 2>&1 &
#
# Results:
#   ./scripts/mini_gsuite_results.sh                     # show latest
#   docs/assessments/mini_gsuite_<timestamp>.md           # summary report
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

while [[ $# -gt 0 ]]; do
    case "$1" in
        --no-signal)     NO_SIGNAL=1; shift ;;
        --trust-level)   TRUST_LEVEL="$2"; shift 2 ;;
        *)               echo "Unknown arg: $1"; exit 1 ;;
    esac
done

if [ "$NO_SIGNAL" -eq 1 ]; then
    runner_lib_signal_enabled 0
fi

# ── Lock file — prevent duplicate runs ──────────────────────────
LOCK_FILE="$PROJECT_DIR/benchmarks/.mini_gsuite.lock"
if [ -f "$LOCK_FILE" ]; then
    EXISTING_PID=$(head -1 "$LOCK_FILE" 2>/dev/null | cut -d: -f1)
    if [ -n "$EXISTING_PID" ] && kill -0 "$EXISTING_PID" 2>/dev/null; then
        echo "ERROR: Mini G-suite already running (PID $EXISTING_PID)"
        echo "  Lock: $LOCK_FILE"
        echo "  Kill it first: kill $EXISTING_PID"
        exit 1
    fi
    echo "WARNING: Stale lock file found (PID $EXISTING_PID not running). Removing."
    rm -f "$LOCK_FILE"
fi
echo "$$:run_mini_gsuite:$(date +%Y%m%d_%H%M%S)" > "$LOCK_FILE"

# ── Redirect to log if not interactive ──────────────────────────
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
LOG_FILE="$PROJECT_DIR/benchmarks/mini_gsuite_runner_${TIMESTAMP}.log"

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

cleanup() {
    echo
    echo "[cleanup] Restoring production settings..."

    cd "$PROJECT_DIR"

    # Restore compose settings
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
echo "  Mini G-Suite — Fast Feedback Benchmark"
echo "  $(date)"
echo "  Log: $LOG_FILE"
echo "  G2: Cat A only, 1 trial (4 scenarios)"
echo "  G3: Full suite (8 scenarios)"
echo "  Expected runtime: ~30-40 min"
echo "============================================================"
echo

# ── Pre-flight: capture current settings ────────────────────────
echo "[0/7] Pre-flight checks..."

if ! podman ps --format "{{.Names}}" | grep -q '^sentinel$'; then
    echo "  ERROR: sentinel container not running"
    exit 1
fi
if ! podman ps --format "{{.Names}}" | grep -q '^sentinel-ollama$'; then
    echo "  ERROR: sentinel-ollama container not running"
    exit 1
fi

cd "$PROJECT_DIR"
ORIG_APPROVAL=$(grep 'SENTINEL_APPROVAL_MODE=' podman-compose.yaml | head -1 | sed 's/.*=//')
ORIG_TRUST=$(grep 'SENTINEL_TRUST_LEVEL=' podman-compose.yaml | head -1 | sed 's/.*=//')
ORIG_VERBOSE=$(grep 'SENTINEL_VERBOSE_RESULTS=' podman-compose.yaml | head -1 | sed 's/.*=//')
ORIG_BENCHMARK=$(grep 'SENTINEL_BENCHMARK_MODE=' podman-compose.yaml | head -1 | sed 's/.*=//')

echo "  Current: approval=$ORIG_APPROVAL, TL=$ORIG_TRUST, verbose=$ORIG_VERBOSE, benchmark=$ORIG_BENCHMARK"

# Capture git HEAD for the results report
GIT_HEAD=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")
GIT_BRANCH=$(git branch --show-current 2>/dev/null || echo "unknown")

# ── Apply test settings ─────────────────────────────────────────
echo "[1/7] Applying test settings..."

sed -i "s/SENTINEL_APPROVAL_MODE=$ORIG_APPROVAL/SENTINEL_APPROVAL_MODE=auto/" podman-compose.yaml
sed -i "s/SENTINEL_VERBOSE_RESULTS=$ORIG_VERBOSE/SENTINEL_VERBOSE_RESULTS=true/" podman-compose.yaml
sed -i "s/SENTINEL_BENCHMARK_MODE=$ORIG_BENCHMARK/SENTINEL_BENCHMARK_MODE=true/" podman-compose.yaml

if [ -n "$TRUST_LEVEL" ]; then
    sed -i "s/SENTINEL_TRUST_LEVEL=$ORIG_TRUST/SENTINEL_TRUST_LEVEL=$TRUST_LEVEL/" podman-compose.yaml
    echo "  Trust level: $ORIG_TRUST → $TRUST_LEVEL"
fi

echo "  Approval: $ORIG_APPROVAL → auto"
echo "  Verbose results: enabled"
echo "  Benchmark mode: enabled"

# ── Restart containers ──────────────────────────────────────────
echo "[2/7] Restarting containers with test settings..."

acquire_compose_lock || exit 1

podman compose down 2>/dev/null || true
sleep "$_RUNNER_LIB_SETTLE_DOWN"
podman compose up -d 2>&1
echo "  Containers restarted. Settling ${_RUNNER_LIB_SETTLE_LONG}s..."
sleep "$_RUNNER_LIB_SETTLE_LONG"

echo "[3/7] Waiting for sentinel to become healthy..."
if ! wait_for_health 300; then
    echo "  ERROR: sentinel did not become healthy"
    release_compose_lock
    exit 1
fi

release_compose_lock

# ── Signal: starting ────────────────────────────────────────────
EFFECTIVE_TL="${TRUST_LEVEL:-$ORIG_TRUST}"
signal_notify "Starting mini G-suite (G2 Cat A x1 + full G3) at TL${EFFECTIVE_TL} [${GIT_HEAD}]" "[Mini G-Suite]"

START_TIME=$(date +%s)

# ── G2: Category A, 1 trial ────────────────────────────────────
echo
echo "[4/7] Running G2 (debug) — Category A, 1 trial..."
echo

G2_START=$(date +%s)

python3 "$SCRIPT_DIR/functional_test_debug.py" \
    --category A \
    --trials 1 \
    --base-url https://localhost:3001

G2_END=$(date +%s)
G2_ELAPSED=$((G2_END - G2_START))

# Find G2 results and score
G2_FILE=$(ls -t "$PROJECT_DIR"/benchmarks/functional_debug_dev_*.jsonl 2>/dev/null | head -1)
G2_SCORE="?/?"
if [ -n "$G2_FILE" ]; then
    G2_SCORE=$("$PROJECT_DIR/.venv/bin/python3" -c "
import json, sys
lines = [json.loads(l) for l in open(sys.argv[1]) if json.loads(l).get('type','') == 'result']
passed = sum(1 for l in lines if l.get('verification_passed', False))
print(f'{passed}/{len(lines)}')
" "$G2_FILE" 2>/dev/null || echo "?/?")
fi

echo
echo "  G2 done: $G2_SCORE ($(format_elapsed $G2_ELAPSED))"
signal_notify "G2 Cat A done: $G2_SCORE ($(format_elapsed $G2_ELAPSED)). Starting G3..." "[Mini G-Suite]"

# Analyse G2
G2_REPORT=""
if [ -n "$G2_FILE" ]; then
    echo "  Analysing G2 results..."
    "$PROJECT_DIR/.venv/bin/python3" "$SCRIPT_DIR/analyse_functional_results.py" "$G2_FILE" 2>/dev/null || true
    G2_REPORT=$(ls -t "$PROJECT_DIR"/docs/assessments/functional_debug_dev_*.md 2>/dev/null | head -1)
fi

# ── G3: Full suite ──────────────────────────────────────────────
echo
echo "[5/7] Running G3 (e2e) — full suite..."
echo

# Verify config hasn't been corrupted between suites
if ! verify_benchmark_config "auto" "true"; then
    echo "  WARNING: Config mismatch before G3 — attempting recovery"
    restart_containers_locked "inter-suite recovery" || {
        echo "  FATAL: Could not recover config"
        signal_notify "FATAL: Config corruption before G3. Aborting." "[Mini G-Suite]"
        exit 1
    }
fi

G3_START=$(date +%s)

python3 "$SCRIPT_DIR/functional_test_e2e.py" \
    --url https://localhost:3001

G3_END=$(date +%s)
G3_ELAPSED=$((G3_END - G3_START))

# Find G3 results and score
G3_FILE=$(ls -t "$PROJECT_DIR"/benchmarks/functional_e2e_*.jsonl 2>/dev/null | head -1)
G3_SCORE="?/?"
if [ -n "$G3_FILE" ]; then
    G3_SCORE=$("$PROJECT_DIR/.venv/bin/python3" -c "
import json, sys
lines = [json.loads(l) for l in open(sys.argv[1]) if json.loads(l).get('type','') == 'result']
passed = sum(1 for l in lines if l.get('verification_passed', False))
print(f'{passed}/{len(lines)}')
" "$G3_FILE" 2>/dev/null || echo "?/?")
fi

echo
echo "  G3 done: $G3_SCORE ($(format_elapsed $G3_ELAPSED))"

# Analyse G3
G3_REPORT=""
if [ -n "$G3_FILE" ]; then
    echo "  Analysing G3 results..."
    "$PROJECT_DIR/.venv/bin/python3" "$SCRIPT_DIR/analyse_functional_results.py" "$G3_FILE" 2>/dev/null || true
    G3_REPORT=$(ls -t "$PROJECT_DIR"/docs/assessments/functional_e2e_*.md 2>/dev/null | head -1)
fi

# ── Generate summary report ────────────────────────────────────
echo
echo "[6/7] Generating summary report..."

END_TIME=$(date +%s)
TOTAL_ELAPSED=$((END_TIME - START_TIME))

REPORT_FILE="$PROJECT_DIR/docs/assessments/mini_gsuite_${TIMESTAMP}.md"
mkdir -p "$PROJECT_DIR/docs/assessments"

# Build the report via Python for clean data extraction
"$PROJECT_DIR/.venv/bin/python3" - "$G2_FILE" "$G3_FILE" "$REPORT_FILE" \
    "$TIMESTAMP" "$GIT_HEAD" "$GIT_BRANCH" "$EFFECTIVE_TL" \
    "$G2_SCORE" "$G3_SCORE" \
    "$G2_ELAPSED" "$G3_ELAPSED" "$TOTAL_ELAPSED" \
    "${G2_REPORT:-none}" "${G3_REPORT:-none}" "$LOG_FILE" << 'PYTHON_EOF'
import json, sys, os

g2_file, g3_file, report_file = sys.argv[1], sys.argv[2], sys.argv[3]
timestamp, git_head, git_branch, trust_level = sys.argv[4:8]
g2_score, g3_score = sys.argv[8], sys.argv[9]
g2_elapsed, g3_elapsed, total_elapsed = int(sys.argv[10]), int(sys.argv[11]), int(sys.argv[12])
g2_report, g3_report, log_file = sys.argv[13], sys.argv[14], sys.argv[15]

def fmt_time(s):
    h, m = s // 3600, (s % 3600) // 60
    return f"{h}h {m}m" if h > 0 else f"{m}m {s % 60}s"

def load_results(path):
    if not path or path == "none" or not os.path.exists(path):
        return []
    return [json.loads(l) for l in open(path) if json.loads(l).get("type", "") != "header"]

# ── G2 per-scenario table ──────────────────────────────────────
g2_lines = load_results(g2_file)
g2_rows = []
for r in g2_lines:
    pid = r.get("prompt_id", "?")
    passed = r.get("verification_passed", False)
    turns = r.get("turns_total", "?")
    elapsed = r.get("elapsed_s", 0)
    cycles = r.get("fix_cycle_count", "?")
    status = "PASS" if passed else "FAIL"

    fail_info = ""
    if not passed:
        tds = r.get("turn_details", [])
        blocked = sum(1 for t in tds if t.get("api_status") == "blocked")
        errors = sum(1 for t in tds if t.get("api_status") == "error")
        failed = sum(1 for t in tds if t.get("api_status") == "failed")
        verif_fails = sum(1 for t in tds if t.get("verification_passed") is False and t.get("api_status") == "success")
        parts = []
        if blocked:    parts.append(f"{blocked} blocked")
        if errors:     parts.append(f"{errors} infra-error")
        if failed:     parts.append(f"{failed} bad-output")
        if verif_fails: parts.append(f"{verif_fails} verif-fail")
        fail_info = ", ".join(parts) if parts else "unknown"

    g2_rows.append(f"| {pid} | {status} | {turns} | {cycles} | {elapsed:.0f}s | {fail_info} |")

# ── G3 per-scenario table ──────────────────────────────────────
g3_lines = load_results(g3_file)
g3_rows = []
for r in g3_lines:
    sid = r.get("scenario_id", "?")
    tl = r.get("trust_level_required", "?")
    passed = r.get("verification_passed", False)
    api_status = r.get("response_status", "?")
    elapsed = r.get("elapsed_s", 0)
    steps = r.get("plan_steps", 0) or len(r.get("step_outcomes", []))
    status = "PASS" if passed else "FAIL"

    note = ""
    if not passed:
        if api_status == "error":     note = "API/infra error"
        elif api_status == "blocked": note = "scanner-blocked"
        elif api_status == "failed":  note = "execution failed"
        elif api_status == "success": note = "verification failed"
        else:                         note = f"status={api_status}"

    g3_rows.append(f"| {sid} | TL{tl} | {status} | {steps} | {elapsed:.0f}s | {note} |")

# ── Write report ───────────────────────────────────────────────
with open(report_file, "w") as f:
    f.write(f"""# Mini G-Suite Results — {timestamp}

| | |
|---|---|
| **Commit** | `{git_head}` ({git_branch}) |
| **Trust Level** | {trust_level} |
| **Runtime** | {fmt_time(total_elapsed)} |

## Scores

| Suite | Score | Time |
|-------|-------|------|
| **G2 Cat A** (1 trial, 4 scenarios) | **{g2_score}** | {fmt_time(g2_elapsed)} |
| **G3 E2E** (8 scenarios) | **{g3_score}** | {fmt_time(g3_elapsed)} |

## G2 — Debugging (Category A)

Syntax errors where stderr contains the answer. Target: converge in ≤3 fix cycles.

| Scenario | Result | Turns | Fix Cycles | Time | Failure Detail |
|----------|--------|-------|------------|------|----------------|
{chr(10).join(g2_rows)}

## G3 — End-to-End Workflows

| Scenario | TL | Result | Steps | Time | Notes |
|----------|-----|--------|-------|------|-------|
{chr(10).join(g3_rows)}

## Coverage Note

This is a fast-feedback subset (~30-40 min). Cat B and Cat C are excluded
for runtime reasons (15-33 min per scenario). Run full G2 at benchmark
gates for complete coverage.

## Raw Data

| File | Path |
|------|------|
| G2 JSONL | `{os.path.basename(g2_file) if g2_file else "none"}` |
| G3 JSONL | `{os.path.basename(g3_file) if g3_file else "none"}` |
| G2 detail | `{os.path.basename(g2_report) if g2_report != "none" else "none"}` |
| G3 detail | `{os.path.basename(g3_report) if g3_report != "none" else "none"}` |
| Runner log | `{os.path.basename(log_file)}` |
""")

print(f"  Report written: {report_file}")
PYTHON_EOF

# ── Console summary ────────────────────────────────────────────
echo
echo "[7/7] Mini G-Suite complete"
echo "============================================================"
echo "  G2 (Cat A, 1 trial): $G2_SCORE  ($(format_elapsed $G2_ELAPSED))"
echo "  G3 (full):           $G3_SCORE  ($(format_elapsed $G3_ELAPSED))"
echo "  Total:               $(format_elapsed $TOTAL_ELAPSED)"
echo
echo "  Report:     $REPORT_FILE"
echo "  Runner log: $LOG_FILE"
echo
echo "  Quick view: ./scripts/mini_gsuite_results.sh"
echo "============================================================"

signal_notify "DONE [${GIT_HEAD}].
G2 Cat A: $G2_SCORE ($(format_elapsed $G2_ELAPSED))
G3 full:  $G3_SCORE ($(format_elapsed $G3_ELAPSED))
Total:    $(format_elapsed $TOTAL_ELAPSED)
Report:   docs/assessments/mini_gsuite_${TIMESTAMP}.md" "[Mini G-Suite]"
