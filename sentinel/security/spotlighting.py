import re


def apply_datamarking(text: str, marker: str = "^") -> str:
    """Prefix every word with the marker character.

    Words are defined as contiguous non-whitespace sequences.
    Whitespace (spaces, newlines, tabs) is preserved as-is.
    """
    if not text:
        return text

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
