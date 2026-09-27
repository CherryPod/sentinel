"""Standalone encoding normalizer for the security scanner pipeline.

Decodes common encodings (base64, hex, URL, ROT13, HTML entities, char
splitting, Unicode escapes) and returns frozen ``DecodedVariant`` objects.
No scanner references — this is purely a text decoder.

The pipeline runs all scanners on both raw text AND decoded variants,
replacing the old ``EncodingNormalizationScanner`` coupling.
"""

from __future__ import annotations

import base64
import codecs
import html
import logging
import re
import urllib.parse
from collections.abc import Callable

from sentinel.security._enums import EncodingType
from sentinel.security._scan_context import DecodedVariant

logger = logging.getLogger(__name__)

# ── Regex patterns for encoding detection ────────────────────────────

# Base64 candidates: 16+ chars from the base64 alphabet, optional padding
_BASE64_RE = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")

# Hex candidates: 16+ hex chars, even length
_HEX_RE = re.compile(r"[0-9a-fA-F]{16,}")

# URL encoding: at least one %XX sequence
_URL_ENCODED_RE = re.compile(r"%[0-9a-fA-F]{2}")

# HTML entities: numeric (&#123;) or named (&amp;)
_HTML_ENTITY_RE = re.compile(r"&#\d+;|&#x[0-9a-fA-F]+;|&[a-z]+;", re.IGNORECASE)

# Char splitting: 4+ single characters separated by spaces or tabs (#46).
# Catches both "c a t /etc" (space-separated) and "c\ta\tt" (tab-separated)
# and mixed variants used to evade space-only regex matchers.
_CHAR_SPLIT_RE = re.compile(r"(?:^|\s)((?:\S[ \t]){3,}\S)(?:\s|$)")

# Unicode escape patterns: \uXXXX, \xXX, \NNN (octal)
_UNICODE_ESCAPE_RE = re.compile(
    r"(?:\\u[0-9a-fA-F]{4}|\\x[0-9a-fA-F]{2}|\\[0-3]?[0-7]{1,2})"
)

# Minimum printable characters for a decoded result to be considered valid
_MIN_PRINTABLE = 4

# Maximum number of decode layers to attempt before stopping iteration
MAX_DECODE_DEPTH = 3

# Keywords that indicate ROT13 decoded text is worth scanning.
# Without this filter, ROT13 produces a variant for every alphabetic text.
_ROT13_KEYWORDS = re.compile(
    r"(?:eval|exec|system|import|subprocess|socket|connect|password|secret|"
    r"shadow|passwd|ssh|token|key|curl|wget|bash|/bin/|/etc/|\.env)",
    re.IGNORECASE,
)


class EncodingNormalizer:
    """Decodes common encodings and produces ``DecodedVariant`` objects.

    Pure text decoder — no scanner references, no scanning logic.
    Decoded variants flow into ``ScanContext.decoded_variants`` and the
    pipeline runs all scanners on them.
    """

    def decode(self, text: str) -> tuple[DecodedVariant, ...]:
        """Try all decoders and return decoded variants across up to MAX_DECODE_DEPTH layers.

        Iterates decode to a bounded fixed point: each layer's decoded texts
        are fed back as inputs for the next layer, surfacing nested encodings
        such as base64(base64(payload)). Stops when no new variants are found
        or MAX_DECODE_DEPTH layers have been processed.

        Decoded texts are deduplicated — the same plaintext is never scanned
        twice regardless of which decode path produced it.

        Returns a tuple of ``DecodedVariant`` (frozen) for each unique decoded
        output found at any layer.
        """
        if not text:
            return ()

        logger.debug(
            "encoding_normalizer.decode called",
            extra={
                "event": "security.encoding_normalizer.decode",
                "text_len": len(text),
            },
        )

        # frontier: (input_text, parent_chain, parent_root_span)
        # parent_root_span is None for depth-0 — decoder spans are already
        # root-relative. For depth>0 it holds the root-relative span of the
        # parent variant so the original_span contract is preserved throughout.
        frontier: list[tuple[str, tuple[EncodingType, ...], tuple[int, int] | None]] = [
            (text, (), None)
        ]
        seen_texts: set[str] = {text}
        all_variants: list[DecodedVariant] = []

        for _depth in range(MAX_DECODE_DEPTH):
            if not frontier:
                break
            next_frontier: list[
                tuple[str, tuple[EncodingType, ...], tuple[int, int] | None]
            ] = []

            for input_text, parent_chain, parent_root_span in frontier:
                for span, decoded_text, enc_type in self._decode_one_layer(
                    input_text, len(parent_chain)
                ):
                    if decoded_text in seen_texts:
                        continue
                    seen_texts.add(decoded_text)
                    new_chain = parent_chain + (enc_type,)
                    # original_span must always index raw_text per the DecodedVariant
                    # contract. At depth 0 the decoder span is already root-relative;
                    # for nested layers the parent's root span is the best available
                    # root-relative anchor (the encoding region in raw_text that
                    # contains this decoded content).
                    root_span = span if parent_root_span is None else parent_root_span
                    all_variants.append(
                        DecodedVariant(
                            # encoding records the outermost encoding type
                            encoding=new_chain[0],
                            original_span=root_span,
                            decoded_text=decoded_text,
                            decode_chain=new_chain,
                        )
                    )
                    next_frontier.append((decoded_text, new_chain, root_span))

            frontier = next_frontier

        if not all_variants:
            logger.debug(
                "encoding_normalizer.decode: no variants found",
                extra={
                    "event": "security.encoding_normalizer.no_variants",
                    "text_len": len(text) if text else 0,
                },
            )

        return tuple(all_variants)

    def _decode_one_layer(
        self,
        text: str,
        chain_depth: int,
    ) -> list[tuple[tuple[int, int], str, EncodingType]]:
        """Run all decoders against ``text`` and return raw decode results.

        Returns a flat list of ``(span, decoded_text, encoding_type)`` triples.
        Does not construct ``DecodedVariant`` objects — chain assembly and
        deduplication happen in ``decode()``.
        """
        logger.debug(
            "encoding_normalizer._decode_one_layer called",
            extra={
                "event": "security.encoding_normalizer.decode_one_layer",
                "text_len": len(text),
                "chain_depth": chain_depth,
            },
        )
        results: list[tuple[tuple[int, int], str, EncodingType]] = []

        for span, decoded_text in self._try_base64(text):
            results.append((span, decoded_text, EncodingType.BASE64))

        for span, decoded_text in self._try_hex(text):
            results.append((span, decoded_text, EncodingType.HEX))

        _SingleDecoder = tuple[
            Callable[[str], tuple[tuple[int, int], str] | None], EncodingType
        ]
        single_decoders: list[_SingleDecoder] = [
            (self._try_url_decode, EncodingType.URL),
            (self._try_rot13, EncodingType.ROT13),
            (self._try_html_entities, EncodingType.HTML),
            (self._try_char_splitting, EncodingType.CHAR_SPLIT),
            (self._try_unicode_escapes, EncodingType.UNICODE),
        ]
        for try_fn, enc_type in single_decoders:
            result = try_fn(text)
            if result is not None:
                span, decoded_text = result
                results.append((span, decoded_text, enc_type))

        return results

    # ── Decode methods ───────────────────────────────────────────────

    @staticmethod
    def _is_valid_decoded(text: str) -> bool:
        """Check if decoded text is valid UTF-8 with enough printable chars."""
        printable_count = sum(1 for c in text if c.isprintable())
        return printable_count >= _MIN_PRINTABLE

    def _try_base64(self, text: str) -> list[tuple[tuple[int, int], str]]:
        """Extract and decode base64 candidate substrings."""
        results: list[tuple[tuple[int, int], str]] = []
        for match in _BASE64_RE.finditer(text):
            candidate = match.group()
            try:
                decoded_bytes = base64.b64decode(candidate, validate=True)
                decoded_str = decoded_bytes.decode("utf-8")
                if self._is_valid_decoded(decoded_str):
                    results.append(((match.start(), match.end()), decoded_str))
            except (ValueError, UnicodeDecodeError):
                continue
        return results

    def _try_hex(self, text: str) -> list[tuple[tuple[int, int], str]]:
        """Extract and decode hex candidate substrings (even-length only)."""
        results: list[tuple[tuple[int, int], str]] = []
        for match in _HEX_RE.finditer(text):
            candidate = match.group()
            if len(candidate) % 2 != 0:
                continue
            try:
                decoded_bytes = bytes.fromhex(candidate)
                decoded_str = decoded_bytes.decode("utf-8")
                if self._is_valid_decoded(decoded_str):
                    results.append(((match.start(), match.end()), decoded_str))
            except (ValueError, UnicodeDecodeError):
                continue
        return results

    def _try_url_decode(self, text: str) -> tuple[tuple[int, int], str] | None:
        """URL-decode if text contains percent-encoded sequences."""
        if not _URL_ENCODED_RE.search(text):
            return None
        decoded = urllib.parse.unquote(text)
        if decoded == text:
            return None
        # URL decoding applies to the whole text
        return (0, len(text)), decoded

    def _try_rot13(self, text: str) -> tuple[tuple[int, int], str] | None:
        """ROT13 the full text, but only return if decoded contains relevant keywords."""
        decoded = codecs.decode(text, "rot_13")
        if decoded == text:
            return None
        if _ROT13_KEYWORDS.search(decoded):
            return (0, len(text)), decoded
        return None

    def _try_html_entities(self, text: str) -> tuple[tuple[int, int], str] | None:
        """Unescape HTML entities if present."""
        if not _HTML_ENTITY_RE.search(text):
            return None
        decoded = html.unescape(text)
        if decoded == text:
            return None
        # HTML entity decoding applies to the whole text
        return (0, len(text)), decoded

    def _try_char_splitting(self, text: str) -> tuple[tuple[int, int], str] | None:
        """Collapse single-char-space/tab patterns (e.g. 'c a t' -> 'cat').

        Handles both space-separated ('c a t') and tab-separated ('c\\ta\\tt')
        variants (#46) so that tab-based evasion is caught alongside the
        original space-based technique.
        """

        def _collapse(match: re.Match) -> str:
            segment = match.group(1)
            chars = re.split(r"[ \t]", segment)
            if all(len(c) == 1 for c in chars):
                return " " + "".join(chars) + " "
            return match.group(0)

        decoded = _CHAR_SPLIT_RE.sub(_collapse, text).strip()
        if decoded == text:
            return None
        # Char splitting applies to the whole text
        return (0, len(text)), decoded

    def _try_unicode_escapes(self, text: str) -> tuple[tuple[int, int], str] | None:
        """Decode \\uXXXX, \\xXX, and octal \\NNN escape sequences.

        Uses per-match regex substitution to avoid codec pitfalls with mixed
        octal/unicode content. Returns decoded text only if it passes the
        printable-character validity check; returns None if no escapes found.
        """
        if not _UNICODE_ESCAPE_RE.search(text):
            return None
        try:

            def _replace(m: re.Match) -> str:
                s = m.group(0)
                if s.startswith("\\u") or s.startswith("\\x"):
                    return chr(int(s[2:], 16))
                # octal \NNN
                return chr(int(s[1:], 8))

            decoded = _UNICODE_ESCAPE_RE.sub(_replace, text)
            if decoded == text:
                return None
            if self._is_valid_decoded(decoded):
                return (0, len(text)), decoded
        except (ValueError, OverflowError):
            logger.debug(
                "encoding_normalizer: unicode escape decode failed",
                extra={
                    "event": "security.encoding_normalizer.unicode_escape_error",
                },
                exc_info=True,
            )
        return None
