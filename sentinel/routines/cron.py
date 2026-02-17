"""Cron expression validation and next-run calculation.

Wraps croniter with validation helpers used by the routine store and engine.
"""

from datetime import datetime, timezone

from croniter import croniter


def validate_cron(expression: str) -> bool:
    """Check whether *expression* is a valid 5-field cron string."""
    return croniter.is_valid(expression)


def next_run(expression: str, base: datetime | None = None) -> datetime:
    """Return the next UTC datetime matching *expression* after *base*.

    Args:
        expression: A valid 5-field cron expression (e.g. "0 9 * * MON").
        base: Start time (defaults to now UTC).

    Returns:
        Next matching UTC datetime.

    Raises:
        ValueError: If *expression* is not a valid cron string.
    """
    if not validate_cron(expression):
        raise ValueError(f"Invalid cron expression: {expression!r}")
    if base is None:
        base = datetime.now(timezone.utc)
    it = croniter(expression, base)
    return it.get_next(datetime).replace(tzinfo=timezone.utc)


def validate_trigger_config(trigger_type: str, trigger_config: dict) -> None:
    """Validate that *trigger_config* matches *trigger_type*.

    Raises:
        ValueError: On any validation failure.
    """
    if trigger_type == "cron":
        cron_expr = trigger_config.get("cron")
        if not cron_expr or not isinstance(cron_expr, str):
            raise ValueError("Cron trigger requires 'cron' key with a string expression")
        if not validate_cron(cron_expr):
            raise ValueError(f"Invalid cron expression: {cron_expr!r}")

    elif trigger_type == "event":
        event_topic = trigger_config.get("event")
        if not event_topic or not isinstance(event_topic, str):
            raise ValueError("Event trigger requires 'event' key with a topic pattern")

    elif trigger_type == "interval":
        seconds = trigger_config.get("seconds")
        if not isinstance(seconds, int) or seconds < 1:
            raise ValueError("Interval trigger requires 'seconds' key with a positive integer")

    else:
        raise ValueError(f"Unknown trigger_type: {trigger_type!r} (must be cron, event, or interval)")
