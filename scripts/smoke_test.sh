#!/usr/bin/env bash
# Smoke test for Sentinel after podman compose up.
#
# Verifies core functionality without requiring API keys or GPU.
# Run from project root after starting the stack:
#   podman compose up -d
#   bash scripts/smoke_test.sh
#
# Exit codes: 0 = all checks pass, 1 = one or more failed

set -euo pipefail

HTTPS_PORT="${SENTINEL_HTTPS_PORT:-3001}"
HTTP_PORT="${SENTINEL_HTTP_PORT:-3002}"
BASE="https://localhost:${HTTPS_PORT}"
CURL="curl -sk --max-time 10"

PASS=0
FAIL=0

check() {
    local desc="$1"
    shift
    if "$@" >/dev/null 2>&1; then
        echo "  [PASS] $desc"
        PASS=$((PASS + 1))
    else
        echo "  [FAIL] $desc"
        FAIL=$((FAIL + 1))
    fi
}

echo "Sentinel Smoke Test"
echo "==================="
echo "Target: localhost:${HTTPS_PORT} (HTTPS), localhost:${HTTP_PORT} (HTTP)"
echo

# 1. Health endpoints
echo "1. Health endpoints"
check "GET /health returns 200" $CURL -o /dev/null -w '%{http_code}' "$BASE/health" | grep -q 200
check "GET /api/health returns 200" $CURL -o /dev/null -w '%{http_code}' "$BASE/api/health" | grep -q 200

# 2. PIN auth enforced
echo "2. PIN authentication"
check "POST /api/task without PIN returns 401" \
    bash -c "$CURL -o /dev/null -w '%{http_code}' -X POST '$BASE/api/task' -H 'Content-Type: application/json' -d '{\"request\":\"test\"}' | grep -q 401"

# 3. HTTP→HTTPS redirect
echo "3. HTTP to HTTPS redirect"
check "HTTP request returns 301" \
    bash -c "curl -s --max-time 10 -o /dev/null -w '%{http_code}' http://localhost:${HTTP_PORT}/ | grep -q 301"

# 4. Static UI
echo "4. Static UI"
check "GET / serves HTML containing 'Sentinel'" \
    bash -c "$CURL '$BASE/' | grep -qi sentinel"

# 5. Air gap (Ollama container can't reach internet)
echo "5. Air gap verification"
OLLAMA_CONTAINER="sentinel-ollama"
if podman ps --format '{{.Names}}' | grep -q "$OLLAMA_CONTAINER"; then
    check "Ollama container cannot reach internet" \
        bash -c "! podman exec $OLLAMA_CONTAINER bash -c 'echo -e \"GET / HTTP/1.0\r\nHost: google.com\r\n\r\n\" > /dev/tcp/google.com/80' 2>/dev/null"
else
    echo "  [SKIP] Ollama container not running ($OLLAMA_CONTAINER)"
fi

# 6. Security headers
echo "6. Security headers"
HEADERS=$($CURL -I "$BASE/health" 2>/dev/null)
check "X-Content-Type-Options present" echo "$HEADERS" | grep -qi "x-content-type-options"
check "X-Frame-Options present" echo "$HEADERS" | grep -qi "x-frame-options"
check "Content-Security-Policy present" echo "$HEADERS" | grep -qi "content-security-policy"

echo
echo "==================="
echo "Results: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ] && echo "All checks passed." || echo "Some checks failed!"
exit "$FAIL"
