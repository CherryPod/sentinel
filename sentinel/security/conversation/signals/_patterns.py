"""Shared signal patterns — reusable helpers for multiple signal extractors.

Extracted from sensitive_topic.py (S2) to avoid cross-signal coupling.
Used by: sensitive_topic.py (S2), context_reference.py (S4), evaluation_framing.py (S10).
"""

from __future__ import annotations

import re

# ── Sensitive topic patterns ──────────────────────────────────


def _sensitive_re(
    term: str, *, prefix: bool = False, literal: bool = False
) -> re.Pattern[str]:
    """Build a regex for a sensitive topic term."""
    escaped = re.escape(term)
    if literal:
        return re.compile(escaped, re.IGNORECASE)
    if prefix:
        return re.compile(rf"\b{escaped}", re.IGNORECASE)
    return re.compile(rf"\b{escaped}\b", re.IGNORECASE)


SENSITIVE_TOPIC_CATEGORIES: dict[str, list[re.Pattern[str]]] = {
    "credential": [
        _sensitive_re("password"),
        _sensitive_re("secret"),
        _sensitive_re("credential"),
        _sensitive_re("api key"),
        _sensitive_re("token"),
        _sensitive_re("private key"),
    ],
    "system_file": [
        _sensitive_re("shadow"),
        _sensitive_re("passwd"),
        _sensitive_re("/etc/shadow", literal=True),
        _sensitive_re(".ssh", literal=True),
        _sensitive_re("authorized_keys"),
        _sensitive_re("/root/", literal=True),
        _sensitive_re("/home/", literal=True),
        _sensitive_re("/var/log/", literal=True),
        _sensitive_re("bash_history"),
        _sensitive_re(".bashrc", literal=True),
        _sensitive_re("sudoers"),
        _sensitive_re("auth.log"),
    ],
    "privilege": [
        _sensitive_re("root access"),
        _sensitive_re("sudo"),
        _sensitive_re("privilege"),
        _sensitive_re("escalat", prefix=True),
        _sensitive_re("system access"),
    ],
    "attack_tool": [
        _sensitive_re("reverse shell"),
        _sensitive_re("backdoor"),
        _sensitive_re("exploit"),
        _sensitive_re("payload"),
        _sensitive_re("malware"),
    ],
    "control_tampering": [
        _sensitive_re("disable security"),
        _sensitive_re("disable firewall"),
        _sensitive_re("disable logging"),
        _sensitive_re("delete logs"),
        _sensitive_re("clear history"),
        _sensitive_re("cover tracks"),
    ],
}


def get_sensitive_categories(text: str) -> set[str]:
    """Return which sensitive topic categories are present in text."""
    categories: set[str] = set()
    for cat, patterns in SENSITIVE_TOPIC_CATEGORIES.items():
        if any(p.search(text) for p in patterns):
            categories.add(cat)
    return categories
