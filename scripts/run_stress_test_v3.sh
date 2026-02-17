#!/bin/bash
# Sentinel Stress Test Runner v3 (v2 + 160 capability benchmarks)
#
# Handles the full lifecycle:
#   1. Switch approval mode to auto
#   2. Rebuild containers with latest code
#   3. Wait for health check
#   4. Run the stress test
#   5. Restore approval mode to full
#
# Designed to run unattended overnight. The approval mode is always
# restored on exit (via trap), even if the script crashes or is killed.
#
# Usage:
#   ./scripts/run_stress_test.sh
#   ./scripts/run_stress_test.sh --max-requests 100   # shorter run

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
COMPOSE_FILE="$PROJECT_DIR/podman-compose.yaml"
LOG_FILE="$SCRIPT_DIR/results/runner_$(date +%Y%m%d_%H%M%S).log"

# Ensure results directory exists
mkdir -p "$SCRIPT_DIR/results"

# Log to both console and file
exec > >(tee -a "$LOG_FILE") 2>&1

echo "============================================================"
echo "  Sentinel Stress Test Runner"
echo "  $(date)"
echo "  Log: $LOG_FILE"
echo "============================================================"
echo

# ── Step 0: Pre-flight checks ────────────────────────────────────

echo "[0/5] Pre-flight checks..."

if [ ! -f "$COMPOSE_FILE" ]; then
    echo "  ERROR: Compose file not found: $COMPOSE_FILE"
    exit 1
fi

if [ ! -f "$HOME/.secrets/sentinel_pin.txt" ]; then
    echo "  ERROR: PIN file not found: ~/.secrets/sentinel_pin.txt"
    exit 1
fi

# Check current approval mode
CURRENT_MODE=$(grep 'SENTINEL_APPROVAL_MODE=' "$COMPOSE_FILE" | head -1 | cut -d= -f2)
echo "  Current approval mode: $CURRENT_MODE"
echo "  Compose file: $COMPOSE_FILE"
echo

# ── Step 1: Switch to auto mode ──────────────────────────────────

echo "[1/5] Switching to stress test mode (auto approval + verbose results)..."

# Always restore on exit (even on error or kill)
restore_settings() {
    echo
    echo "[cleanup] Restoring production settings..."
    sed -i 's/SENTINEL_APPROVAL_MODE=auto/SENTINEL_APPROVAL_MODE=full/' "$COMPOSE_FILE"
    sed -i 's/SENTINEL_VERBOSE_RESULTS=true/SENTINEL_VERBOSE_RESULTS=false/' "$COMPOSE_FILE"
    echo "[cleanup] Done. Approval mode + verbose results restored."
}
trap restore_settings EXIT

sed -i 's/SENTINEL_APPROVAL_MODE=full/SENTINEL_APPROVAL_MODE=auto/' "$COMPOSE_FILE"
sed -i 's/SENTINEL_VERBOSE_RESULTS=false/SENTINEL_VERBOSE_RESULTS=true/' "$COMPOSE_FILE"
echo "  Approval mode set to: auto"
echo "  Verbose results: enabled"
echo

# ── Step 2: Rebuild and restart containers ────────────────────────

echo "[2/5] Rebuilding containers..."

cd "$PROJECT_DIR"

echo "  Stopping existing containers..."
podman compose down 2>/dev/null || true
sleep 3

echo "  Building controller and UI..."
podman compose build sentinel-controller sentinel-ui

echo "  Starting all containers..."
podman compose up -d

echo "  Containers started."
echo

# ── Step 3: Wait for health ───────────────────────────────────────

echo "[3/5] Waiting for controller to become healthy..."

MAX_HEALTH_WAIT=120  # 2 minutes
HEALTH_INTERVAL=5
elapsed=0

while [ $elapsed -lt $MAX_HEALTH_WAIT ]; do
    if curl -sf http://localhost:8000/health 2>/dev/null | python3 -c "
import sys, json
try:
    r = json.load(sys.stdin)
    if r.get('status') == 'ok':
        print('  Health check: OK')
        print('    Planner: ' + ('available' if r.get('planner_available') else 'NOT available'))
        print('    CodeShield: ' + ('loaded' if r.get('codeshield_loaded') else 'NOT loaded'))
        print('    Prompt Guard: ' + ('loaded' if r.get('prompt_guard_loaded') else 'NOT loaded'))
        print('    PIN auth: ' + ('enabled' if r.get('pin_auth_enabled') else 'disabled'))
        print('    Conversation tracking: ' + ('enabled' if r.get('conversation_tracking') else 'disabled'))
        sys.exit(0)
    else:
        sys.exit(1)
except Exception:
    sys.exit(1)
" 2>/dev/null; then
        echo
        break
    fi

    elapsed=$((elapsed + HEALTH_INTERVAL))
    echo "  Waiting... (${elapsed}s / ${MAX_HEALTH_WAIT}s)"
    sleep $HEALTH_INTERVAL
done

if [ $elapsed -ge $MAX_HEALTH_WAIT ]; then
    echo "  ERROR: Controller did not become healthy after ${MAX_HEALTH_WAIT}s"
    echo "  Check logs: podman logs sentinel-controller"
    exit 1
fi

# ── Step 4: Quick HTML fix verification ───────────────────────────

echo "[4/5] Quick smoke test (verifying JSON responses)..."

PIN=$(cat "$HOME/.secrets/sentinel_pin.txt")

# Send a simple request and verify we get JSON back
SMOKE_RESULT=$(curl -sf -X POST http://localhost:8000/task \
    -H "Content-Type: application/json" \
    -H "X-Sentinel-Pin: $PIN" \
    -d '{"request": "What is 2+2?", "source": "smoke_test"}' \
    --max-time 120 2>/dev/null || echo '{"error": "curl failed"}')

if echo "$SMOKE_RESULT" | python3 -c "
import sys, json
try:
    r = json.load(sys.stdin)
    status = r.get('status', 'unknown')
    print(f'  Smoke test response: status={status}')
    if status in ('success', 'blocked', 'error', 'awaiting_approval'):
        sys.exit(0)
    else:
        print(f'  Unexpected status: {status}')
        sys.exit(1)
except Exception as e:
    print(f'  ERROR: Not valid JSON: {e}')
    sys.exit(1)
" 2>/dev/null; then
    echo "  Smoke test passed (valid JSON response)"
else
    echo "  WARNING: Smoke test failed. Continuing anyway..."
fi
echo

# ── Step 5: Run the stress test ───────────────────────────────────

echo "[5/5] Starting stress test..."
echo "  This will run for several hours."
echo "  Results will be saved to: $SCRIPT_DIR/results/"
echo "  To stop gracefully: kill -TERM \$\$ or Ctrl+C"
echo

# Pass through any CLI arguments (like --max-requests)
python3 "$SCRIPT_DIR/stress_test_v3.py" "$@"

echo
echo "============================================================"
echo "  Stress test finished at $(date)"
echo "  Runner log: $LOG_FILE"
echo "  Results: $SCRIPT_DIR/results/"
echo "============================================================"
