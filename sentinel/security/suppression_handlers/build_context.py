"""Suppression handler: build context.

Suppresses command-pattern matches (specifically ``dangerous_rm``)
that appear inside Dockerfile, Containerfile, or Makefile contexts
where ``rm -rf`` targeting cache/temp dirs or shell variables is
standard build cleanup.

Extracted from ``CommandPatternScanner._is_dockerfile_content``
(scanner.py:1682-1701), ``_is_build_file_content`` (scanner.py:1703-1714),
and ``_is_safe_rm_in_build_context`` (scanner.py:1715-1811).
"""

from __future__ import annotations

import logging
import re

from sentinel.security._enums import RegionType
from sentinel.security._scan_context import (
    ScanContext,
    ScanMatch,
    decoded_variant_encoding_matches,
)
from sentinel.security.homoglyph import normalise_homoglyphs

logger = logging.getLogger(__name__)

# Dockerfile/Containerfile language tags
_DOCKERFILE_TAGS = frozenset({"dockerfile", "containerfile", "docker"})

# rm targets that are safe cache/temp cleanup in Dockerfiles
_DOCKERFILE_SAFE_RM_TARGETS = re.compile(
    r"/var/cache/|/var/lib/apt/|/var/lib/dpkg/|/tmp/|/var/tmp/"
    r"|/root/\.cache/|/var/log/"
)

# Dockerfile instruction keywords for content-based detection
_DOCKERFILE_INSTRUCTION_RE = re.compile(
    r"^\s*(?:FROM|RUN|COPY|ADD|ENTRYPOINT|CMD|EXPOSE|ENV|ARG|"
    r"WORKDIR|USER|VOLUME|LABEL|HEALTHCHECK|ONBUILD|STOPSIGNAL|SHELL)\s",
    re.MULTILINE | re.IGNORECASE,
)

# Build-file language tags
_BUILD_FILE_TAGS = frozenset({"makefile", "make", "cmake"})

# Build-file instruction keywords for content-based detection
_BUILD_FILE_INSTRUCTION_RE = re.compile(
    r"^\s*(?:\.PHONY|\.SUFFIXES|\.DEFAULT|\.PRECIOUS|\.SECONDARY"
    r"|define\s|endef|ifeq\s|ifneq\s|ifdef\s|ifndef\s|endif"
    r"|include\s|-include\s|sinclude\s|override\s|export\s|unexport\s"
    r"|vpath\s)\s*",
    re.MULTILINE | re.IGNORECASE,
)

# Makefile target rule pattern: word: (optional deps) — but not URLs (://)
_MAKEFILE_TARGET_RE = re.compile(
    r"^[a-zA-Z_][a-zA-Z0-9_./-]*\s*:(?!//)",
    re.MULTILINE,
)

# Variable-targeted rm (shell variables like $(VAR) or $VAR)
_BUILD_FILE_SAFE_RM_TARGET = re.compile(r"rm\s+(-[a-zA-Z]*[rf][a-zA-Z]*\s+)+\$")

# <RESPONSE>/<think> tags that Qwen wraps around output — strip before
# content-based detection
_RESPONSE_TAG_RE = re.compile(r"</?(?:RESPONSE|think)>", re.IGNORECASE)


class BuildContextHandler:
    """Suppress dangerous_rm matches in Dockerfile/Makefile contexts."""

    handler_id: str = "build_context"

    def evaluate(
        self,
        match: ScanMatch,
        context: ScanContext,
        params: dict | None = None,
    ) -> bool:
        """Return True if the match should be suppressed.

        Only applies to ``dangerous_rm`` patterns. Checks for
        Dockerfile/Makefile context via language tags or content heuristics.
        """
        logger.debug(
            "Evaluating build context",
            extra={
                "event": "security.suppression.build_context.evaluate",
                "rule_id": match.rule_id,
                "offset": match.offset,
            },
        )

        # Only dangerous_rm is eligible for build context exemption
        if not match.rule_id.endswith("dangerous_rm"):
            logger.debug(
                "Build context: not dangerous_rm pattern",
                extra={
                    "event": "security.suppression.build_context.not_eligible",
                    "reason": "not_dangerous_rm",
                },
            )
            return False
        logger.debug(
            "Build context: dangerous_rm check passed, evaluating context",
            extra={
                "event": "security.suppression.build_context.eligible",
                "reason": "is_dangerous_rm",
            },
        )  # auto:neg

        # Determine enclosing block context
        block_lang, in_code_block = self._get_block_lang(match, context)
        content = self._get_surrounding_content(match, context)

        return self._check_safe_rm(
            match.matched_text, block_lang, content, in_code_block
        )

    def _check_safe_rm(
        self, match_text: str, block_lang: str, content: str, in_code_block: bool
    ) -> bool:
        """Check if a dangerous_rm match is safe in a build context.

        Checks Dockerfile targets, build-file targets, and
        variable-targeted rm in code blocks.
        """
        # Dockerfile exemption: rm targeting cache/temp dirs
        if _DOCKERFILE_SAFE_RM_TARGETS.search(match_text):
            if block_lang in _DOCKERFILE_TAGS:
                logger.debug(
                    "Build context: Dockerfile safe target with matching tag",
                    extra={
                        "event": "security.suppression.build_context.suppressed",
                        "reason": "dockerfile_safe_target_tag",
                    },
                )
                return True
            # Content-based detection — Qwen non-deterministically tags
            # Containerfile output as "bash"
            if _is_dockerfile_content(content):
                logger.debug(
                    "Build context: Dockerfile safe target via content heuristic",
                    extra={
                        "event": "security.suppression.build_context.suppressed",
                        "reason": "dockerfile_safe_target_content",
                    },
                )
                return True

        # Build-file exemption: rm targeting variables in Makefile context
        if _BUILD_FILE_SAFE_RM_TARGET.search(match_text):
            if block_lang in _BUILD_FILE_TAGS:
                logger.debug(
                    "Build context: build file safe target with matching tag",
                    extra={
                        "event": "security.suppression.build_context.suppressed",
                        "reason": "build_file_target_tag",
                    },
                )
                return True
            if _is_build_file_content(content):
                logger.debug(
                    "Build context: build file safe target via content heuristic",
                    extra={
                        "event": "security.suppression.build_context.suppressed",
                        "reason": "build_file_target_content",
                    },
                )
                return True
            # Variable-targeted rm in ANY code block is safe — the scanner
            # can't evaluate shell variables, and `rm -rf $DIR` is standard
            # cleanup in bash/shell scripts, CI/CD runners, etc.
            if in_code_block:
                logger.debug(
                    "Build context: variable-targeted rm in code block",
                    extra={
                        "event": "security.suppression.build_context.suppressed",
                        "reason": "variable_targeted_rm",
                    },
                )
                return True

        logger.debug(
            "Build context: no exemption matched",
            extra={
                "event": "security.suppression.build_context.no_exemption",
                "reason": "no_exemption",
            },
        )
        return False

    # Region types that count as "inside a code block" for the
    # variable-rm heuristic.  classify_regions() produces CODE_BLOCK
    # for non-shell fences, SHELL for shell-tagged fences, and
    # INDENTED_CODE for indented blocks.
    _CODE_REGION_TYPES = frozenset(
        {
            RegionType.CODE_BLOCK,
            RegionType.SHELL,
            RegionType.INDENTED_CODE,
        }
    )

    @staticmethod
    def _get_block_lang(match: ScanMatch, context: ScanContext) -> tuple[str, bool]:
        """Get the language tag and code-block status of the enclosing region.

        Returns ``(language_tag, in_code_block)`` where *in_code_block*
        is True when the match falls inside any code-region type
        (CODE_BLOCK, SHELL, or INDENTED_CODE).
        """

        def _extract(region_type: RegionType, lang_tag: str | None) -> tuple[str, bool]:
            in_code = region_type in BuildContextHandler._CODE_REGION_TYPES
            if region_type == RegionType.CODE_BLOCK:
                return (lang_tag or "").lower(), in_code
            if region_type == RegionType.SHELL:
                return "sh", in_code
            return "", in_code

        # Check match's own region first
        if match.region is not None:
            return _extract(match.region.region_type, match.region.language_tag)

        # For encoded matches, match.offset is in decoded-variant coordinate
        # space — do NOT compare it directly against context.regions (which
        # are in normalised_text space).  Find the variant whose decoded text
        # contains the matched content at match.offset, then use
        # variant.original_span[0] as a proxy for the blob's position in
        # normalised_text.  The encoded blob (base64/hex/URL chars) is ASCII
        # and unchanged by homoglyph normalisation, so the original_span
        # position is accurate unless there are stripped format chars before
        # the blob in the main text (negligible in practice).
        if match.rule_id.startswith("encoded:"):
            end = match.offset + match.length
            for variant in context.decoded_variants:
                if not decoded_variant_encoding_matches(variant, match.rule_id):
                    continue
                normalised_variant = normalise_homoglyphs(variant.decoded_text)
                if end <= len(normalised_variant) and normalised_variant[match.offset:end] == match.matched_text:
                    blob_start = variant.original_span[0]
                    for region in context.regions:
                        if region.start <= blob_start < region.end:
                            return _extract(region.region_type, region.language_tag)
                    return "", False
            if context.decoded_variants:
                logger.warning(
                    "Encoded match: no decoded variant found for block_lang lookup — no region",
                    extra={
                        "event": "security.suppression.build_context.encoded_no_variant",
                        "rule_id": match.rule_id,
                        "offset": match.offset,
                    },
                )
            return "", False

        # Non-encoded fallback: region boundaries are in normalised_text space
        for region in context.regions:
            if region.start <= match.offset < region.end:
                return _extract(region.region_type, region.language_tag)
        return "", False

    @staticmethod
    def _get_surrounding_content(match: ScanMatch, context: ScanContext) -> str:
        """Get the surrounding content for content-based heuristics.

        Uses the enclosing region's content if available, otherwise
        falls back to the full normalised text.  Region offsets are in
        normalised_text coordinate space, so the slice must come from
        that string, not raw_text.

        For encoded matches (rule_id prefixed ``encoded:<enc>:``) the offset
        is in the decoded-variant text, not normalised_text.  Return the full
        decoded-variant text so that content heuristics see the real content.
        """
        if match.rule_id.startswith("encoded:"):
            # Encoded matches: offset indexes the normalised decoded-variant
            # text, not the main normalised_text.  Use the variant's full text
            # so Dockerfile/Makefile heuristics see the actual decoded content.
            end = match.offset + match.length
            for variant in context.decoded_variants:
                if not decoded_variant_encoding_matches(variant, match.rule_id):
                    continue
                normalised = normalise_homoglyphs(variant.decoded_text)
                if end <= len(normalised) and normalised[match.offset:end] == match.matched_text:
                    return normalised
            if context.decoded_variants:
                logger.warning(
                    "Encoded match: no decoded variant found for offset — falling back to main text",
                    extra={
                        "event": "security.suppression.build_context.encoded_fallback",
                        "rule_id": match.rule_id,
                        "offset": match.offset,
                    },
                )
            # No variant found (e.g. synthetic context) — fall through to main text.

        # normalised_text and region offsets share the same coordinate space.
        # Fall back to raw_text for synthetic contexts without normalised_text.
        source = context.normalised_text if context.normalised_text is not None else context.raw_text

        if match.region is not None:
            return source[match.region.start : match.region.end]

        for region in context.regions:
            if region.start <= match.offset < region.end:
                return source[region.start : region.end]

        return source


def _is_dockerfile_content(text: str) -> bool:
    """Heuristic: does *text* look like Dockerfile/Containerfile content?

    Returns True if the text contains a ``FROM`` instruction AND at least
    one other Dockerfile instruction.
    """
    cleaned = _RESPONSE_TAG_RE.sub("", text)
    instructions = _DOCKERFILE_INSTRUCTION_RE.findall(cleaned)
    if len(instructions) < 2:
        return False
    return any(instr.strip().upper().startswith("FROM") for instr in instructions)


def _is_build_file_content(text: str) -> bool:
    """Heuristic: does *text* look like a Makefile or build script?

    Returns True if the text contains a Makefile directive or at least
    two target rules.
    """
    if _BUILD_FILE_INSTRUCTION_RE.search(text):
        return True
    return len(_MAKEFILE_TARGET_RE.findall(text)) >= 2
