"""Unicode homoglyph normalisation for security scanning.

Converts visually confusable characters (Cyrillic→Latin, accented→base)
to their Latin equivalents before pattern matching. This prevents bypass
attacks like /еtc/ѕhadow (Cyrillic е and ѕ) evading a check for /etc/shadow.

Only normalises characters that are visual confusables — non-confusable
Unicode (arrows, math, CJK, etc.) passes through unchanged. The script
gate blocks non-Latin scripts from reaching Qwen; this module catches
them in text that's already been generated or in path arguments.
"""

import logging
import unicodedata

logger = logging.getLogger(__name__)

# Cyrillic → Latin visual confusable map.
# Only includes characters that look identical or near-identical to Latin
# letters in common monospace/sans-serif fonts. This is a security tool,
# not a linguistic transliterator — we map by VISUAL similarity, not
# phonetic similarity.
_CYRILLIC_TO_LATIN: dict[str, str] = {
    # Lower-case
    "\u0430": "a",  # а
    "\u0435": "e",  # е
    "\u043e": "o",  # о
    "\u0440": "p",  # р
    "\u0441": "c",  # с
    "\u0443": "y",  # у
    "\u0445": "x",  # х
    "\u0455": "s",  # ѕ
    "\u0456": "i",  # і
    "\u0458": "j",  # ј
    "\u04bb": "h",  # һ
    "\u0501": "d",  # ԁ
    # Upper-case
    "\u0405": "S",  # Ѕ — C78, paired with ѕ U+0455
    "\u0406": "I",  # І — C78, paired with і U+0456
    "\u0408": "J",  # Ј — C78, paired with ј U+0458
    "\u0410": "A",  # А
    "\u0412": "B",  # В
    "\u0415": "E",  # Е
    "\u041a": "K",  # К
    "\u041c": "M",  # М
    "\u041d": "H",  # Н
    "\u041e": "O",  # О
    "\u0420": "P",  # Р
    "\u0421": "C",  # С
    "\u0422": "T",  # Т
    "\u0423": "Y",  # У
    "\u0425": "X",  # Х
    "\u04ba": "H",  # Һ — C78, paired with һ U+04BB
    "\u0500": "D",  # Ԁ — C78, paired with ԁ U+0501
}

# Build a translation table for str.translate() — fast single-pass replacement
_CONFUSABLE_TABLE = str.maketrans(_CYRILLIC_TO_LATIN)


def normalise_homoglyphs(text: str) -> str:
    """Normalise Unicode homoglyphs to Latin equivalents.

    Four-step process:
    1. NFKD decomposition — splits precomposed characters (é → e + accent)
    2. Strip combining marks — removes accents/diacritics (category Mn)
    3. Strip invisible format chars — removes zero-width and soft-hyphen
       characters (category Cf) that break regex matching without being
       visible: U+200B (ZWSP), U+200C (ZWNJ), U+200D (ZWJ), U+FEFF (BOM),
       U+00AD (soft hyphen), U+2060 (word joiner), U+180E (MVS)
    4. Cyrillic→Latin — replaces visual confusables via translation table

    Non-confusable Unicode (arrows, math symbols, CJK, etc.) passes
    through unchanged.
    """
    logger.debug(
        "Homoglyph normalisation started",
        extra={"event": "homoglyph.normalise", "text_len": len(text)},
    )
    if not text:
        return text

    # Step 1: NFKD decomposition — é (U+00E9) → e (U+0065) + ◌́ (U+0301)
    decomposed = unicodedata.normalize("NFKD", text)

    # Step 2+3: Strip combining marks (Mn) and invisible format chars (Cf)
    stripped = "".join(
        ch for ch in decomposed if unicodedata.category(ch) not in ("Mn", "Cf")
    )

    # Step 4: Cyrillic → Latin visual confusables
    result = stripped.translate(_CONFUSABLE_TABLE)
    logger.debug(
        "Homoglyph normalisation complete",
        extra={
            "event": "homoglyph.normalise_complete",
            "changed": result != text,
        },
    )
    return result
