#!/usr/bin/env bash
# Create hourly stress-test routines for all integrations.
# These run more frequently than smoke tests (every hour vs every 2 hours)
# and include sandbox exercises to stress the full integration surface.
#
# Usage: ./scripts/setup_stress_routines.sh [--base-url URL] [--pin PIN]
#
# Defaults: https://localhost:3001/api  (reads PIN from ~/.secrets/sentinel_pin.txt)

set -euo pipefail

BASE_URL="https://localhost:3001/api"
PIN=$(cat ~/.secrets/sentinel_pin.txt 2>/dev/null || echo "")

if [[ -z "$PIN" ]]; then
    echo "ERROR: No PIN found. Pass --pin or put in ~/.secrets/sentinel_pin.txt" >&2
    exit 1
fi

# Parse optional flags
while [[ $# -gt 0 ]]; do
    case "$1" in
        --base-url) BASE_URL="$2"; shift 2 ;;
        --pin)      PIN="$2"; shift 2 ;;
        *)          shift ;;
    esac
done

CURL="curl -sk -H Content-Type:application/json -H X-Sentinel-Pin:${PIN}"

echo "=== Creating stress-test routines (hourly) ==="
echo "Target: ${BASE_URL}/routine"
echo

# 1. [STRESS] Web Search — hourly :05
echo "1/7  [STRESS] Web Search"
$CURL -X POST "${BASE_URL}/routine" -d '{
  "name": "[STRESS] Web Search",
  "description": "Hourly Brave search stress test — exercises web_search tool under sustained load",
  "trigger_type": "cron",
  "trigger_config": {"cron": "5 * * * *"},
  "action_config": {
    "prompt": "Do a web search for \"Brighton weather today\" and summarise the result in one sentence.",
    "approval_mode": "auto"
  },
  "enabled": true,
  "cooldown_s": 1800
}' | python3 -m json.tool --no-ensure-ascii 2>/dev/null && echo || echo "FAILED"

# 2. [STRESS] Email Round-Trip — hourly :10
echo "2/7  [STRESS] Email Round-Trip"
$CURL -X POST "${BASE_URL}/routine" -d '{
  "name": "[STRESS] Email Round-Trip",
  "description": "Hourly SMTP send + IMAP read-back stress test",
  "trigger_type": "cron",
  "trigger_config": {"cron": "10 * * * *"},
  "action_config": {
    "prompt": "Send an email to your-email@example.com with subject \"Stress Test\" and body \"Hourly stress test at this time.\" Then check the inbox for the most recent email and confirm it arrived. Report success or failure.",
    "approval_mode": "auto"
  },
  "enabled": true,
  "cooldown_s": 1800
}' | python3 -m json.tool --no-ensure-ascii 2>/dev/null && echo || echo "FAILED"

# 3. [STRESS] Signal Send — hourly :15
echo "3/7  [STRESS] Signal Send"
$CURL -X POST "${BASE_URL}/routine" -d '{
  "name": "[STRESS] Signal Send",
  "description": "Hourly signal_send tool stress test",
  "trigger_type": "cron",
  "trigger_config": {"cron": "15 * * * *"},
  "action_config": {
    "prompt": "Send a Signal message saying: \"Hourly stress test — Signal OK.\"",
    "approval_mode": "auto"
  },
  "enabled": true,
  "cooldown_s": 1800
}' | python3 -m json.tool --no-ensure-ascii 2>/dev/null && echo || echo "FAILED"

# 4. [STRESS] Telegram Send — hourly :20
echo "4/7  [STRESS] Telegram Send"
$CURL -X POST "${BASE_URL}/routine" -d '{
  "name": "[STRESS] Telegram Send",
  "description": "Hourly telegram_send tool stress test",
  "trigger_type": "cron",
  "trigger_config": {"cron": "20 * * * *"},
  "action_config": {
    "prompt": "Send a Telegram message saying: \"Hourly stress test — Telegram OK.\"",
    "approval_mode": "auto"
  },
  "enabled": true,
  "cooldown_s": 1800
}' | python3 -m json.tool --no-ensure-ascii 2>/dev/null && echo || echo "FAILED"

# 5. [STRESS] Calendar Round-Trip — hourly :25
echo "5/7  [STRESS] Calendar Round-Trip"
$CURL -X POST "${BASE_URL}/routine" -d '{
  "name": "[STRESS] Calendar Round-Trip",
  "description": "Hourly CalDAV create + list stress test",
  "trigger_type": "cron",
  "trigger_config": {"cron": "25 * * * *"},
  "action_config": {
    "prompt": "Create a calendar event titled \"Stress Test\" for 30 minutes from now, then list calendar events for the next 2 hours and confirm the event appears. Report success or failure.",
    "approval_mode": "auto"
  },
  "enabled": true,
  "cooldown_s": 1800
}' | python3 -m json.tool --no-ensure-ascii 2>/dev/null && echo || echo "FAILED"

# 6. [STRESS] Sandbox Exercise — hourly :35
echo "6/7  [STRESS] Sandbox Exercise"
$CURL -X POST "${BASE_URL}/routine" -d '{
  "name": "[STRESS] Sandbox Exercise",
  "description": "Hourly sandbox file_write + shell_exec stress test",
  "trigger_type": "cron",
  "trigger_config": {"cron": "35 * * * *"},
  "action_config": {
    "prompt": "Write a Python script to /workspace/stress_test.py that prints '\''Hello from sandbox'\'', the current user ID using os.getuid(), and the current time. Then execute it with shell_exec and report the output.",
    "approval_mode": "auto"
  },
  "enabled": true,
  "cooldown_s": 1800
}' | python3 -m json.tool --no-ensure-ascii 2>/dev/null && echo || echo "FAILED"

# 7. [STRESS] Full Integration — hourly :00
echo "7/7  [STRESS] Full Integration"
$CURL -X POST "${BASE_URL}/routine" -d '{
  "name": "[STRESS] Full Integration",
  "description": "Hourly combined stress test — all integrations in one plan",
  "trigger_type": "cron",
  "trigger_config": {"cron": "0 * * * *"},
  "action_config": {
    "prompt": "Run a full integration check: (1) web search for '\''Brighton weather'\'', (2) list today'\''s calendar events, (3) signal message '\''Hourly integration test complete'\'', (4) telegram message '\''Hourly integration test complete'\'', (5) email results to your-email@example.com. Report success/failure for each.",
    "approval_mode": "auto"
  },
  "enabled": true,
  "cooldown_s": 1800
}' | python3 -m json.tool --no-ensure-ascii 2>/dev/null && echo || echo "FAILED"

echo
echo "=== Done. 7 stress-test routines created. ==="
echo "Check with: curl -sk -H X-Sentinel-Pin:${PIN} ${BASE_URL}/routine | python3 -m json.tool"
echo "Note: All routines use cooldown_s=1800 (30 min) to prevent overlap."
