#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────
# Shared helper library for Sentinel runner scripts.
# Source this file — do not execute directly.
#
# Provides:
#   - Compose file locking (flock-based mutual exclusion)
#   - Signal notification via daemon socket
#   - Health check with config verification
#   - Container restart with settle time
#
# Usage:
#   source "$(dirname "$0")/runner_lib.sh"
#   runner_lib_init "$PROJECT_DIR" "$COMPOSE_FILE"
# ─────────────────────────────────────────────────────────────────

# Guard against direct execution
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    echo "ERROR: runner_lib.sh must be sourced, not executed directly."
    exit 1
fi

# ── Initialisation ────────────────────────────────────────────────
# Call once after sourcing. Sets up paths used by all helpers.

_RUNNER_LIB_PROJECT_DIR=""
_RUNNER_LIB_COMPOSE_FILE=""
_RUNNER_LIB_COMPOSE_LOCK_FD=""
_RUNNER_LIB_SETTLE_SHORT=15   # seconds between suites
_RUNNER_LIB_SETTLE_LONG=30    # seconds after compose up, before health check
_RUNNER_LIB_SETTLE_DOWN=15    # seconds after compose down, before compose up

runner_lib_init() {
    _RUNNER_LIB_PROJECT_DIR="$1"
    _RUNNER_LIB_COMPOSE_FILE="$2"
    mkdir -p "$_RUNNER_LIB_PROJECT_DIR/benchmarks"
}

# ── Compose file locking ─────────────────────────────────────────
# Uses flock for mutual exclusion. Only ONE script can modify the
# compose file at a time. Lock is acquired before any sed/restart
# and released after containers are healthy.

COMPOSE_LOCK_FILE=""

acquire_compose_lock() {
    # Acquire exclusive flock on the compose lock file.
    # Blocks up to 120s, then fails. This is generous — compose
    # operations (sed + restart + health) take ~60s normally.
    COMPOSE_LOCK_FILE="${_RUNNER_LIB_PROJECT_DIR}/benchmarks/.compose.lock"
    exec 9>"$COMPOSE_LOCK_FILE"
    if ! flock --timeout 120 9; then
        echo "ERROR: Could not acquire compose lock after 120s."
        echo "  Another runner script is modifying compose settings."
        echo "  Lock file: $COMPOSE_LOCK_FILE"
        echo "  Check: fuser $COMPOSE_LOCK_FILE"
        return 1
    fi
    # Write our PID + script name for debugging stale locks
    echo "$$:$(basename "$0"):$(date +%Y%m%d_%H%M%S)" >&9
}

release_compose_lock() {
    # Release the flock. Safe to call even if lock wasn't acquired.
    if [ -n "${COMPOSE_LOCK_FILE:-}" ]; then
        flock --unlock 9 2>/dev/null || true
        exec 9>&- 2>/dev/null || true
        COMPOSE_LOCK_FILE=""
    fi
}

# ── Signal notification ───────────────────────────────────────────
# Sends a message via the signal-cli daemon socket inside the
# sentinel container. Best-effort — failures don't abort the run.

_RUNNER_LIB_SIGNAL_ENABLED=1
_RUNNER_LIB_SIGNAL_ACCOUNT="+440000000000"
_RUNNER_LIB_SIGNAL_RECIPIENT="00000000-0000-0000-0000-000000000000"

runner_lib_signal_enabled() {
    _RUNNER_LIB_SIGNAL_ENABLED="$1"
}

signal_notify() {
    local msg="$1"
    local prefix="${2:-[Sentinel]}"
    if [ "$_RUNNER_LIB_SIGNAL_ENABLED" -eq 0 ]; then
        return 0
    fi
    # Best-effort — if container is down, this silently fails
    timeout 15 podman exec sentinel python3 -c "
import socket, json, sys
msg = json.dumps({
    'jsonrpc': '2.0', 'id': 1, 'method': 'send',
    'params': {
        'account': '$_RUNNER_LIB_SIGNAL_ACCOUNT',
        'recipients': ['$_RUNNER_LIB_SIGNAL_RECIPIENT'],
        'message': '$prefix ' + sys.argv[1]
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

# ── Health check ──────────────────────────────────────────────────

wait_for_health() {
    # Wait for sentinel container to report healthy.
    # Args: $1 = max wait seconds (default 300)
    local max_wait="${1:-300}"
    local interval=10
    local elapsed=0

    echo "[runner_lib] Waiting for sentinel health (timeout ${max_wait}s)..."
    sleep "$_RUNNER_LIB_SETTLE_LONG"

    while [ $elapsed -lt "$max_wait" ]; do
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
            echo "[runner_lib] Health check: OK (after ${elapsed}s)"
            return 0
        fi
        elapsed=$((elapsed + interval))
        echo "[runner_lib]   Not ready yet... (${elapsed}s / ${max_wait}s)"
        sleep "$interval"
    done

    echo "[runner_lib] ERROR: Container not healthy after ${max_wait}s"
    return 1
}

# ── Config verification ───────────────────────────────────────────
# Queries /health to verify the container is running with the
# expected benchmark settings. Returns 0 if OK, 1 if mismatch.

verify_benchmark_config() {
    # Verify the container has the expected approval_mode and benchmark_mode.
    # Args: $1 = expected approval_mode (default "auto")
    #       $2 = expected benchmark_mode (default "true")
    local expected_approval="${1:-auto}"
    local expected_benchmark="${2:-true}"

    python3 -c "
import urllib.request, ssl, json, sys
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
try:
    r = json.loads(urllib.request.urlopen('https://localhost:3001/health', context=ctx, timeout=10).read())
    actual_approval = r.get('approval_mode', 'unknown')
    actual_benchmark = str(r.get('benchmark_mode', 'unknown')).lower()
    expected_approval = sys.argv[1]
    expected_benchmark = sys.argv[2]
    ok = True
    if actual_approval != expected_approval:
        print(f'CONFIG MISMATCH: approval_mode={actual_approval} (expected {expected_approval})')
        ok = False
    if actual_benchmark != expected_benchmark:
        print(f'CONFIG MISMATCH: benchmark_mode={actual_benchmark} (expected {expected_benchmark})')
        ok = False
    if ok:
        print(f'Config OK: approval_mode={actual_approval}, benchmark_mode={actual_benchmark}')
    sys.exit(0 if ok else 1)
except Exception as e:
    print(f'Config check failed: {e}')
    sys.exit(1)
" "$expected_approval" "$expected_benchmark" 2>/dev/null
}

# ── Container restart (with locking + settle) ─────────────────────

restart_containers_locked() {
    # Restart containers with compose lock held. Includes generous
    # settle times for long unattended runs.
    # Args: $1 = context message for logging
    local context="${1:-}"
    echo "[runner_lib] Restarting containers${context:+ ($context)}..."

    acquire_compose_lock || return 1

    cd "$_RUNNER_LIB_PROJECT_DIR"
    podman compose down 2>/dev/null || true
    sleep "$_RUNNER_LIB_SETTLE_DOWN"
    podman compose up -d 2>&1
    sleep "$_RUNNER_LIB_SETTLE_LONG"

    local health_rc=0
    wait_for_health 300 || health_rc=$?

    release_compose_lock

    return $health_rc
}

# ── Pre-suite gate ────────────────────────────────────────────────
# Verifies container health + config before each suite. If config
# is corrupted, attempts one recovery (re-apply compose + restart).
# If recovery fails, returns non-zero so the caller can abort.

verify_or_recover() {
    # Verify benchmark config. On mismatch, attempt one recovery.
    # Args: $1 = expected approval_mode (default "auto")
    #       $2 = expected benchmark_mode (default "true")
    local expected_approval="${1:-auto}"
    local expected_benchmark="${2:-true}"

    echo "[runner_lib] Pre-suite config check..."

    # Check 1: Is the container even running?
    if ! podman ps --format "{{.Names}}" | grep -q '^sentinel$'; then
        echo "[runner_lib] WARNING: sentinel container not running!"
        echo "[runner_lib] Attempting recovery..."
        restart_containers_locked "config recovery" || return 1
    fi

    # Check 2: Is config correct?
    if verify_benchmark_config "$expected_approval" "$expected_benchmark"; then
        return 0
    fi

    # Config mismatch — attempt recovery
    echo "[runner_lib] CONFIG CORRUPTION DETECTED — another process may have restarted containers"
    echo "[runner_lib] Attempting recovery: re-apply compose settings + restart..."
    signal_notify "WARNING: Config corruption detected mid-run. Attempting recovery..."

    # Re-apply the compose settings by restarting with current compose file
    # (the compose file should still have test settings from the caller's setup)
    restart_containers_locked "config recovery" || {
        echo "[runner_lib] FATAL: Container restart failed during recovery"
        signal_notify "FATAL: Container restart failed during config recovery. Aborting run."
        return 1
    }

    # Verify again after recovery
    if verify_benchmark_config "$expected_approval" "$expected_benchmark"; then
        echo "[runner_lib] Recovery successful — config verified"
        signal_notify "Recovery successful. Resuming run."
        return 0
    fi

    echo "[runner_lib] FATAL: Config still wrong after recovery. Aborting to save API cost."
    signal_notify "FATAL: Config still wrong after recovery. Aborting run — check compose file for external interference."
    return 1
}

# ── Formatting helpers ────────────────────────────────────────────

format_elapsed() {
    # Format seconds as "Xh Ym" or "Ym Zs"
    local secs="$1"
    local hours=$((secs / 3600))
    local mins=$(( (secs % 3600) / 60 ))
    if [ "$hours" -gt 0 ]; then
        echo "${hours}h ${mins}m"
    else
        echo "${mins}m $((secs % 60))s"
    fi
}
