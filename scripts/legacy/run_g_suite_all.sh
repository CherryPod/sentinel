#!/bin/bash
# Run G1-G5 functional suites sequentially at TL4.
# G6 (security-tax) excluded — requires dual-config (BASELINE_MODE toggle).
# Each suite handles its own container restart + cleanup.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SUITES=(build debug e2e plans deps)
LOG="$HOME/sentinel/benchmarks/g_suite_all_$(date +%Y%m%d_%H%M%S).log"

echo "=== G1-G5 Full Suite Run (TL4) ===" | tee "$LOG"
echo "Started: $(date)" | tee -a "$LOG"
echo "Suites: ${SUITES[*]}" | tee -a "$LOG"
echo "Log: $LOG" | tee -a "$LOG"
echo | tee -a "$LOG"

PASS=0
FAIL=0

for suite in "${SUITES[@]}"; do
    echo "--- Starting $suite at $(date) ---" | tee -a "$LOG"
    if "$SCRIPT_DIR/run_functional_tests.sh" --suite "$suite" --trust-level 4 --foreground >> "$LOG" 2>&1; then
        echo "  $suite: DONE" | tee -a "$LOG"
        PASS=$((PASS + 1))
    else
        echo "  $suite: FAILED (exit $?)" | tee -a "$LOG"
        FAIL=$((FAIL + 1))
    fi
    echo | tee -a "$LOG"
done

echo "=== G1-G5 COMPLETE ===" | tee -a "$LOG"
echo "Finished: $(date)" | tee -a "$LOG"
echo "Passed: $PASS / ${#SUITES[@]}" | tee -a "$LOG"
echo "Failed: $FAIL / ${#SUITES[@]}" | tee -a "$LOG"
