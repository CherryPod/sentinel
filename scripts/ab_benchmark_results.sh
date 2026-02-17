#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────
# Quick A/B Benchmark Results Viewer
#
# Usage:
#   ./scripts/ab_benchmark_results.sh         # show latest report
#   ./scripts/ab_benchmark_results.sh --all    # show all reports
#   ./scripts/ab_benchmark_results.sh --diff   # compare last two runs
# ─────────────────────────────────────────────────────────────────
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
ASSESSMENTS="$PROJECT_DIR/docs/assessments"

case "${1:-latest}" in
    --all)
        echo "=== All A/B Benchmark Reports ==="
        ls -lt "$ASSESSMENTS"/ab_benchmark_*.md 2>/dev/null || echo "  No reports found"
        ;;
    --diff)
        FILES=($(ls -t "$ASSESSMENTS"/ab_benchmark_*.md 2>/dev/null))
        if [ ${#FILES[@]} -lt 2 ]; then
            echo "Need at least 2 reports for diff"
            exit 1
        fi
        echo "=== Comparing ==="
        echo "  New: ${FILES[0]}"
        echo "  Old: ${FILES[1]}"
        echo
        diff --color=auto "${FILES[1]}" "${FILES[0]}" || true
        ;;
    *)
        LATEST=$(ls -t "$ASSESSMENTS"/ab_benchmark_*.md 2>/dev/null | head -1)
        if [ -z "$LATEST" ]; then
            echo "No A/B benchmark reports found"
            echo "Run: ./scripts/run_ab_benchmark.sh"
            exit 1
        fi
        echo "=== Latest A/B Benchmark Report ==="
        echo "  File: $LATEST"
        echo
        cat "$LATEST"
        ;;
esac
