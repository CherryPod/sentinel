#!/bin/bash
# Sentinel health watchdog — self-heal + Signal notifications
#
# Called by sentinel-watchdog.timer every 15 minutes.
# Checks container health, attempts restart on failure,
# notifies via Signal (through sentinel container) on:
#   - First healthy check after reboot (state file cleared by /tmp)
#   - Recovery after failed attempts
#   - Persistent failures (after 2 silent attempts, then hourly)
#
# State file: /tmp/sentinel-watchdog.state (cleared on reboot)

set -euo pipefail

STATE_FILE="/tmp/sentinel-watchdog.state"
COMPOSE_FILE="$HOME/sentinel/podman-compose.yaml"

# Signal config — sends via sentinel's own signal-cli daemon
SIGNAL_ACCOUNT="+440000000000"
SIGNAL_RECIPIENT="00000000-0000-0000-0000-000000000000"

# Thresholds
MAX_SILENT_ATTEMPTS=2
BACKOFF_SECONDS=3600  # 1 hour

# --- State management ---

read_state() {
    if [[ -f "$STATE_FILE" ]]; then
        source "$STATE_FILE"
    else
        ATTEMPTS=0
        LAST_ALERT_EPOCH=0
        LAST_HEALTHY=""
    fi
}

write_state() {
    cat > "$STATE_FILE" <<EOF
ATTEMPTS=$ATTEMPTS
LAST_ALERT_EPOCH=$LAST_ALERT_EPOCH
LAST_HEALTHY="$LAST_HEALTHY"
EOF
}

reset_state() {
    ATTEMPTS=0
    LAST_ALERT_EPOCH=0
    LAST_HEALTHY=$(date -u '+%Y-%m-%d %H:%M UTC')
    write_state
}

# --- Signal notification ---
# Sends via signal-cli daemon socket inside the sentinel container.
# Best-effort — if container is mid-startup, this silently fails.

signal_notify() {
    local msg="$1"
    timeout 15 podman exec sentinel python3 -c "
import socket, json, sys
msg = json.dumps({
    'jsonrpc': '2.0', 'id': 1, 'method': 'send',
    'params': {
        'account': '$SIGNAL_ACCOUNT',
        'recipients': ['$SIGNAL_RECIPIENT'],
        'message': '[Watchdog] ' + sys.argv[1]
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

# --- Health checks ---

check_health() {
    local sentinel_status sentinel_health ollama_status
    local healthy=true

    # Check sentinel-ollama is running
    ollama_status=$(podman inspect --format '{{.State.Status}}' sentinel-ollama 2>/dev/null || echo "missing")
    if [[ "$ollama_status" != "running" ]]; then
        healthy=false
    fi

    # Check sentinel is running AND healthy (has internal healthcheck)
    sentinel_status=$(podman inspect --format '{{.State.Status}}' sentinel 2>/dev/null || echo "missing")
    sentinel_health=$(podman inspect --format '{{.State.Health.Status}}' sentinel 2>/dev/null || echo "unknown")

    if [[ "$sentinel_status" != "running" ]]; then
        healthy=false
    elif [[ "$sentinel_health" == "unhealthy" ]]; then
        healthy=false
    fi
    # "starting" is OK — container is in start_period, give it time

    if $healthy; then
        echo "healthy"
    else
        echo "unhealthy|sentinel=$sentinel_status($sentinel_health)|ollama=$ollama_status"
    fi
}

# --- Recovery ---

restart_stack() {
    echo "[watchdog] Restarting sentinel stack..."
    podman-compose -f "$COMPOSE_FILE" down 2>/dev/null || true
    podman-compose -f "$COMPOSE_FILE" up -d 2>/dev/null
}

# --- Main ---

main() {
    read_state

    local result
    result=$(check_health)

    if [[ "$result" == "healthy" ]]; then
        # First healthy check after reboot (state file was cleared)
        if [[ -z "$LAST_HEALTHY" ]]; then
            echo "[watchdog] First healthy check after boot"
            reset_state
            # Wait a moment for signal-cli to be ready, then notify
            sleep 5
            signal_notify "Reboot complete — all systems healthy"
            exit 0
        fi

        # Recovery after previous failures
        if [[ "$ATTEMPTS" -gt 0 ]]; then
            echo "[watchdog] Recovered after $ATTEMPTS attempts"
            local prev_attempts=$ATTEMPTS
            reset_state
            signal_notify "Recovered after $prev_attempts restart attempt(s) — system healthy"
            exit 0
        fi

        # Routine healthy check — silent
        reset_state
        exit 0
    fi

    # Unhealthy — extract detail for logging
    local detail="${result#unhealthy|}"
    echo "[watchdog] Unhealthy: $detail (attempt $((ATTEMPTS + 1)))"

    ATTEMPTS=$((ATTEMPTS + 1))
    local now
    now=$(date +%s)

    if [[ "$ATTEMPTS" -le "$MAX_SILENT_ATTEMPTS" ]]; then
        # Silent restart — don't alert yet
        restart_stack
        write_state
        exit 0
    fi

    # Past silent attempts — alert with backoff
    local since_last_alert=$((now - LAST_ALERT_EPOCH))

    if [[ "$ATTEMPTS" -eq $((MAX_SILENT_ATTEMPTS + 1)) ]] || [[ "$since_last_alert" -ge "$BACKOFF_SECONDS" ]]; then
        # Restart, then try to alert (container may or may not be ready)
        restart_stack
        LAST_ALERT_EPOCH=$now
        write_state
        sleep 30  # give containers time to start before sending
        signal_notify "Failed $ATTEMPTS health checks — $detail. Auto-restarted, may need attention"
        exit 0
    fi

    # In backoff period — restart but don't alert
    restart_stack
    write_state
}

main "$@"
