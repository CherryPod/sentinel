"""Telegram injection vector — seed via Bot API, verify allowlist."""
import json
import os
import urllib.request
import urllib.error


def _get_bot_token() -> str:
    """Read Telegram bot token from secrets file."""
    path = os.path.expanduser("~/.secrets/injection_bench_telegram_bot_token.txt")
    try:
        return open(path).read().strip()
    except FileNotFoundError:
        raise FileNotFoundError(
            f"Telegram bot token not found at {path} — "
            f"create it or skip Telegram tests"
        )


def send_telegram_message(config, chat_id: str, message: str) -> bool:
    """Send a Telegram message via Bot API.

    Args:
        config: Benchmark config.
        chat_id: The chat ID to send to.
        message: The message text.

    Returns:
        True if the Bot API returned ok.
    """
    token = _get_bot_token()
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    data = json.dumps({"chat_id": chat_id, "text": message}).encode("utf-8")

    req = urllib.request.Request(
        url, data=data,
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            result = json.loads(resp.read().decode("utf-8"))
            return result.get("ok", False)
    except (urllib.error.URLError, urllib.error.HTTPError):
        return False


def send_telegram_message_unknown(config, message: str) -> bool:
    """Send a Telegram message from a non-allowlisted chat.

    Tests whether Sentinel's Telegram allowlist drops unknown senders.
    """
    return send_telegram_message(
        config, config.contacts.unknown_telegram_chat_id, message,
    )


def verify_telegram_allowlist_configured(config) -> bool:
    """Check if the Telegram unknown chat ID is configured.

    Returns False if empty — unknown-sender tests should be skipped.
    """
    return bool(config.contacts.unknown_telegram_chat_id)
