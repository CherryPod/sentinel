#!/usr/bin/env bash
# Show the latest mini G-suite results.
# Usage: ./scripts/mini_gsuite_results.sh          # latest
#        ./scripts/mini_gsuite_results.sh --all     # list all runs
#        ./scripts/mini_gsuite_results.sh --diff     # compare last 2 runs
set -uo pipefail

PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
ASSESSMENTS="$PROJECT_DIR/docs/assessments"
PYTHON="$PROJECT_DIR/.venv/bin/python3"

case "${1:-}" in
    --all)
        echo "Mini G-Suite runs:"
        echo
        "$PYTHON" - << 'EOF'
import glob, re, os

files = sorted(glob.glob(os.path.expanduser(
    "~/sentinel/docs/assessments/mini_gsuite_*.md"
)), reverse=True)

if not files:
    print("  No runs found.")
    raise SystemExit(0)

for f in files:
    name = os.path.basename(f)
    # Extract scores from the file
    g2 = g3 = commit = runtime = "?"
    for line in open(f):
        if "**G2 Cat A**" in line:
            m = re.search(r"\*\*(\d+/\d+)\*\*", line)
            if m: g2 = m.group(1)
        elif "**G3 E2E**" in line:
            m = re.search(r"\*\*(\d+/\d+)\*\*", line)
            if m: g3 = m.group(1)
        elif "**Commit**" in line:
            m = re.search(r"`([a-f0-9]+)`", line)
            if m: commit = m.group(1)
        elif "**Runtime**" in line:
            m = re.search(r"\| (.+?) \|$", line.strip())
            if m: runtime = m.group(1).strip()
    # Extract timestamp from filename
    ts = name.replace("mini_gsuite_", "").replace(".md", "")
    date_str = f"{ts[:4]}-{ts[4:6]}-{ts[6:8]} {ts[9:11]}:{ts[11:13]}"
    print(f"  {date_str}  G2={g2}  G3={g3}  [{commit}]  {runtime}  {name}")
EOF
        ;;

    --diff)
        FILES=($(ls -t "$ASSESSMENTS"/mini_gsuite_*.md 2>/dev/null | head -2))
        if [ ${#FILES[@]} -lt 2 ]; then
            echo "Need at least 2 runs to diff. Found ${#FILES[@]}."
            exit 1
        fi
        echo "Comparing:"
        echo "  NEW: $(basename "${FILES[0]}")"
        echo "  OLD: $(basename "${FILES[1]}")"
        echo
        "$PYTHON" - "${FILES[0]}" "${FILES[1]}" << 'DIFFEOF'
import json, sys, os, re

def extract_scores(path):
    g2 = g3 = commit = "?"
    scenarios = {}
    section = None
    for line in open(path):
        if "**G2 Cat A**" in line:
            m = re.search(r"\*\*(\d+/\d+)\*\*", line)
            if m: g2 = m.group(1)
        elif "**G3 E2E**" in line:
            m = re.search(r"\*\*(\d+/\d+)\*\*", line)
            if m: g3 = m.group(1)
        elif "**Commit**" in line:
            m = re.search(r"`([a-f0-9]+)`", line)
            if m: commit = m.group(1)
        elif "## G2" in line: section = "g2"
        elif "## G3" in line: section = "g3"
        elif "## Coverage" in line or "## Raw" in line: section = None
        elif line.startswith("| ") and section and "Scenario" not in line and "---" not in line:
            cols = [c.strip() for c in line.split("|")[1:-1]]
            if len(cols) >= 2:
                scenarios[cols[0]] = cols[1]  # scenario -> PASS/FAIL
    return {"g2": g2, "g3": g3, "commit": commit, "scenarios": scenarios}

new = extract_scores(sys.argv[1])
old = extract_scores(sys.argv[2])

print(f"  Scores:  G2 {old['g2']} -> {new['g2']}   G3 {old['g3']} -> {new['g3']}")
print(f"  Commits: {old['commit']} -> {new['commit']}")
print()

# Show changes
all_scenarios = sorted(set(list(new["scenarios"].keys()) + list(old["scenarios"].keys())))
changes = []
for s in all_scenarios:
    o = old["scenarios"].get(s, "?")
    n = new["scenarios"].get(s, "?")
    if o != n:
        arrow = "improved" if n == "PASS" and o != "PASS" else "regressed" if n != "PASS" and o == "PASS" else "changed"
        changes.append((s, o, n, arrow))

if changes:
    print("  Changes:")
    for s, o, n, arrow in changes:
        marker = "+" if arrow == "improved" else "-" if arrow == "regressed" else "~"
        print(f"    {marker} {s}: {o} -> {n}")
else:
    print("  No changes between runs.")
DIFFEOF
        ;;

    ""|--latest)
        LATEST=$(ls -t "$ASSESSMENTS"/mini_gsuite_*.md 2>/dev/null | head -1)
        if [ -z "$LATEST" ]; then
            echo "No mini G-suite results found."
            echo "Run: ./scripts/run_mini_gsuite.sh"
            exit 1
        fi
        cat "$LATEST"
        ;;

    *)
        echo "Usage: $0 [--all | --diff | --latest]"
        exit 1
        ;;
esac
