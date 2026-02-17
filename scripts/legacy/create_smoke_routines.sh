#!/usr/bin/env bash
# Create smoke test routines for all integrations.
# Run after deploying the signal_send/telegram_send tools.
#
# Usage: ./scripts/create_smoke_routines.sh [--base-url URL] [--pin PIN]
#
# Defaults: https://localhost:3002/api  (reads PIN from ~/.secrets/sentinel_pin.txt)

set -euo pipefail

BASE_URL="${1:-https://localhost:3002/api}"
PIN=$(cat ~/.secrets/sentinel_pin.txt 2>/dev/null || echo "")

if [[ -z "$PIN" ]]; then
    echo "ERROR: No PIN found. Pass as second arg or put in ~/.secrets/sentinel_pin.txt" >&2
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

echo "=== Creating smoke test routines ==="
echo "Target: ${BASE_URL}/routine"
echo

# 1. Smoke: Web Search — odd hours :05
echo "1/6  Smoke: Web Search"
$CURL -X POST "${BASE_URL}/routine" -d '{
  "name": "Smoke: Web Search",
  "description": "Brave search smoke test — rotates London weather, Bitcoin price, Brighton tides",
  "trigger_type": "cron",
  "trigger_config": {"cron": "5 1-23/2 * * *"},
  "action_config": {
    "prompt": "Do a web search for the current weather in London. Return the temperature and conditions in one sentence.",
    "approval_mode": "auto"
  },
  "enabled": true,
  "cooldown_s": 3600
}' | python3 -m json.tool --no-ensure-ascii 2>/dev/null && echo || echo "FAILED"

# 2. Smoke: Email — odd hours :15
echo "2/6  Smoke: Email"
$CURL -X POST "${BASE_URL}/routine" -d '{
  "name": "Smoke: Email",
  "description": "Send a test email to your-email@example.com",
  "trigger_type": "cron",
  "trigger_config": {"cron": "15 1-23/2 * * *"},
  "action_config": {
    "prompt": "Send an email to your-email@example.com with subject \"Sentinel Smoke Test\" and body \"Automated smoke test — integration check at this time. No action required.\"",
    "approval_mode": "auto"
  },
  "enabled": true,
  "cooldown_s": 3600
}' | python3 -m json.tool --no-ensure-ascii 2>/dev/null && echo || echo "FAILED"

# 3. Smoke: Signal — odd hours :25
echo "3/6  Smoke: Signal"
$CURL -X POST "${BASE_URL}/routine" -d '{
  "name": "Smoke: Signal",
  "description": "Send a Signal check-in message via signal_send tool",
  "trigger_type": "cron",
  "trigger_config": {"cron": "25 1-23/2 * * *"},
  "action_config": {
    "prompt": "Send a Signal message saying: \"Sentinel smoke test — Signal integration OK.\"",
    "approval_mode": "auto"
  },
  "enabled": true,
  "cooldown_s": 3600
}' | python3 -m json.tool --no-ensure-ascii 2>/dev/null && echo || echo "FAILED"

# 4. Smoke: Telegram — odd hours :35
echo "4/6  Smoke: Telegram"
$CURL -X POST "${BASE_URL}/routine" -d '{
  "name": "Smoke: Telegram",
  "description": "Send a Telegram check-in message via telegram_send tool",
  "trigger_type": "cron",
  "trigger_config": {"cron": "35 1-23/2 * * *"},
  "action_config": {
    "prompt": "Send a Telegram message saying: \"Sentinel smoke test — Telegram integration OK.\"",
    "approval_mode": "auto"
  },
  "enabled": true,
  "cooldown_s": 3600
}' | python3 -m json.tool --no-ensure-ascii 2>/dev/null && echo || echo "FAILED"

# 5. Smoke: Calendar — odd hours :45
echo "5/6  Smoke: Calendar"
$CURL -X POST "${BASE_URL}/routine" -d '{
  "name": "Smoke: Calendar",
  "description": "List calendar events in the next 48h, note any upcoming",
  "trigger_type": "cron",
  "trigger_config": {"cron": "45 1-23/2 * * *"},
  "action_config": {
    "prompt": "List my calendar events for the next 48 hours. If there are upcoming events, summarise them briefly. If none, just say \"No events in the next 48 hours.\"",
    "approval_mode": "auto"
  },
  "enabled": true,
  "cooldown_s": 3600
}' | python3 -m json.tool --no-ensure-ascii 2>/dev/null && echo || echo "FAILED"

# 6. Smoke: Combined — even hours :00
echo "6/6  Smoke: Combined"
$CURL -X POST "${BASE_URL}/routine" -d '{
  "name": "Smoke: Combined",
  "description": "Combined smoke test — web search, calendar, signal, telegram, email in one plan",
  "trigger_type": "cron",
  "trigger_config": {"cron": "0 */2 * * *"},
  "action_config": {
    "prompt": "Run a combined integration check: 1) Do a web search for \"current UTC time\" and note the result. 2) List my calendar events for the next 48 hours. 3) Send a Signal message saying \"Combined smoke test OK — all integrations checked.\" 4) Send a Telegram message saying \"Combined smoke test OK — all integrations checked.\" 5) Send an email to your-email@example.com with subject \"Sentinel Combined Smoke\" and body with the web search result and calendar summary.",
    "approval_mode": "auto"
  },
  "enabled": true,
  "cooldown_s": 3600
}' | python3 -m json.tool --no-ensure-ascii 2>/dev/null && echo || echo "FAILED"

echo
echo "=== Done. Check with: curl -sk -H X-Sentinel-Pin:${PIN} ${BASE_URL}/routine | python3 -m json.tool ==="
