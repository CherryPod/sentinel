import logging  # auto:logger
import re
import secrets

logger = logging.getLogger(__name__)  # auto:logger


# Symbols unlikely to appear naturally in user data.
# Excludes < > & " ' (XML-sensitive), $ (variable syntax), ^ (old static marker).
# Excludes {}[]()\/_ (common in code). 12 symbols → 12^4 ≈ 20K combinations.
# Marker changes per-request and Qwen is air-gapped, so brute-force guessing
# of the 4-char marker is impractical.
_MARKER_POOL = "~!@#%*+=|;:"


def generate_marker(length: int = 4) -> str:
    """Generate a random spotlighting marker for this request."""
    return "".join(secrets.choice(_MARKER_POOL) for _ in range(length))


def apply_datamarking(text: str, marker: str = "^") -> str:
    """Prefix every word with the marker character.

    Words are defined as contiguous non-whitespace sequences.
    Whitespace (spaces, newlines, tabs) is preserved as-is.
    """
    logger.debug(
        "apply_datamarking called",
        extra={
            "event": "spotlighting.apply_datamarking",
            "text_len": len(text) if hasattr(text, "__len__") else 0,
            "marker": marker,
        },
    )  # auto:entry
    if not text:
        logger.debug(
            "apply_datamarking: not_text",
            extra={
                "event": "spotlighting.apply_datamarking.match",
                "reason": "not_text",
            },
        )  # auto:neg
        return text
    logger.debug(
        "apply_datamarking: not_text_passed",
        extra={
            "event": "spotlighting.apply_datamarking.passed",
            "reason": "not_text_passed",
        },
    )  # auto:neg

    # Split on whitespace boundaries, keeping the separators
    tokens = re.split(r"(\s+)", text)
    result = []
    for token in tokens:
        if token and not token.isspace():
            result.append(f"{marker}{token}")
        else:
            result.append(token)
    return "".join(result)


def remove_datamarking(text: str, marker: str = "^") -> str:
    """Strip the marker prefix from every word."""
    if not text or not marker:
        return text

    # Remove marker that appears at the start of a word
    # (after whitespace or at the start of the string)
    escaped = re.escape(marker)
    return re.sub(rf"(?<=\s){escaped}|^{escaped}", "", text)
