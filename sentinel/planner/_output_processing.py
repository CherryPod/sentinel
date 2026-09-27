"""Worker output processing pipeline for plan execution.

Handles artifact stripping, security scanning, format validation,
and code fence unwrapping. All functions are module-level (no
mixin/self references).

Extracted from _execution.py during planner modularisation Phase 4.
"""

import html as html_module
import json
import logging
import re

from sentinel.core.models import OutputDestination, StepResult
from sentinel.security import semgrep_scanner
from sentinel.security.code_extractor import (
    CodeBlock,
    close_unclosed_fences,
    extract_code_blocks,
    strip_emoji_from_code_blocks,
)
from sentinel.security.quality_gate import check_code_quality

logger = logging.getLogger(__name__)


def _strip_worker_artifacts(
    content: str, step_id: str, output_format: str | None
) -> str:
    """Strip worker-injected artifacts from raw output before scanning.

    Sequential cleanup: emoji strip (D-005 defence) → think tag removal
    (Qwen3 architecture leakage) → RESPONSE tag extraction (tagged output
    format) → HTML entity unescape (Qwen XML encoding).

    Returns cleaned content string.  Pure function — no side effects.
    """
    logger.debug(
        "Stripping worker artifacts",
        extra={
            "event": "execution.strip_worker_artifacts_enter",
            "step_id": step_id,
            "content_length": len(content),
        },
    )

    # D-005: Strip emoji BEFORE scanning — prevents emoji injection bypass
    # where emoji causes Semgrep parse failure, then stripping produces
    # clean malicious code that was never successfully scanned.
    pre_emoji = content
    content = strip_emoji_from_code_blocks(content)
    if content != pre_emoji:
        logger.debug(
            "Emoji stripped from code blocks",
            extra={
                "event": "execution.emoji_strip",
                "step_id": step_id,
                "chars_removed": len(pre_emoji) - len(content),
            },
        )
    else:
        logger.debug(
            "Emoji check clean — none found",
            extra={"event": "execution.emoji_strip_clean", "step_id": step_id},
        )

    # Qwen3 thinking mode produces <think>...</think> blocks even in
    # non-thinking prompts (architecture leakage). <RESPONSE> tags are
    # from the tagged output format instruction. Strip both defensively
    # before code block extraction — the B-006 fallback puts the entire
    # text into a single CodeBlock, so surviving tags would re-appear
    # when the EXECUTION destination unwraps the block.
    stripped = content.strip()
    pre_think = stripped
    stripped = re.sub(r"<think>.*?</think>\s*", "", stripped, flags=re.DOTALL).strip()
    if stripped != pre_think:
        logger.debug(
            "Think block stripped from worker output",
            extra={
                "event": "execution.think_block_strip",
                "step_id": step_id,
                "chars_removed": len(pre_think) - len(stripped),
            },
        )
    else:
        logger.debug(
            "Think block check clean — none found",
            extra={"event": "execution.think_block_strip_clean", "step_id": step_id},
        )

    if "<RESPONSE>" in stripped and "</RESPONSE>" in stripped:
        start = stripped.index("<RESPONSE>") + len("<RESPONSE>")
        end = stripped.rindex("</RESPONSE>")
        extracted = stripped[start:end].strip()
        logger.debug(
            "RESPONSE tag extraction",
            extra={
                "event": "execution.response_tag_extract",
                "step_id": step_id,
                "pre_extract_length": len(stripped),
                "post_extract_length": len(extracted),
                "pre_extract_preview": stripped[:500],
                "post_extract_preview": extracted[:500],
                "has_entities_before": ("&lt;" in stripped),
                "has_entities_after": ("&lt;" in extracted),
            },
        )
        # Qwen sometimes entity-encodes HTML content inside
        # RESPONSE tags (treating them as XML). Unescape to
        # restore raw HTML. Safe: html.unescape on non-encoded
        # content is a no-op.
        if "&lt;" in extracted or "&gt;" in extracted or "&amp;" in extracted:
            extracted = html_module.unescape(extracted)
            logger.info(
                "Unescaped HTML entities from RESPONSE tag content",
                extra={
                    "event": "execution.response_entity_unescape",
                    "step_id": step_id,
                },
            )
        content = extracted
        if output_format != "tagged":
            logger.info(
                "Defensive strip — removed unsolicited RESPONSE tags "
                "from worker output",
                extra={
                    "event": "execution.defensive_response_tag_strip",
                    "step_id": step_id,
                    "output_format": output_format,
                },
            )
    elif "<RESPONSE>" in stripped:
        start = stripped.index("<RESPONSE>") + len("<RESPONSE>")
        content = stripped[start:].strip()
        logger.info(
            "Stripped truncated RESPONSE tag (no closing tag — likely output cap hit)",
            extra={
                "event": "execution.truncated_response_tag_strip",
                "step_id": step_id,
            },
        )
    else:
        content = stripped
        logger.debug(
            "No RESPONSE tags found — content used as-is",
            extra={
                "event": "execution.no_response_tags",
                "step_id": step_id,
                "content_len": len(stripped),
                "has_entities": ("&lt;" in stripped),
            },
        )

    logger.debug(
        "Worker artifacts stripped",
        extra={
            "event": "execution.strip_worker_artifacts_exit",
            "step_id": step_id,
            "content_length": len(content),
        },
    )
    return content


async def _run_security_scans(
    content: str, step_id: str, worker_usage: dict | None
) -> tuple[list[CodeBlock], list[str]] | StepResult:
    """Close fences, extract code blocks, run quality gate and Semgrep.

    Returns (code_blocks, quality_warnings) on success, or a blocking
    StepResult if Semgrep flags insecure code.
    """
    logger.debug(
        "Running security scans on worker output",
        extra={
            "event": "execution.security_scans_enter",
            "step_id": step_id,
            "content_length": len(content),
        },
    )

    # R9: Close unclosed code fences.
    pre_fence = content
    content = close_unclosed_fences(content)
    if content != pre_fence:
        logger.debug(
            "Closed unclosed code fences",
            extra={"event": "execution.fence_close", "step_id": step_id},
        )
    else:
        logger.debug(
            "Fence check clean — all fences properly closed",
            extra={"event": "execution.fence_close_clean", "step_id": step_id},
        )

    # Extract code blocks once
    code_blocks = extract_code_blocks(content)
    logger.debug(
        "Code blocks extracted",
        extra={
            "event": "execution.code_blocks_extracted",
            "step_id": step_id,
            "block_count": len(code_blocks),
            "block_languages": [b.language for b in code_blocks],
            "block_sizes": [len(b.code) for b in code_blocks],
            "blocks_have_entities": [("&lt;" in b.code) for b in code_blocks],
        },
    )

    # R7: Post-generation quality gate — warns, never blocks.
    # Runs BEFORE Semgrep so warnings are available even on blocked
    # steps (e.g. truncation signal on Semgrep-blocked output helps
    # F1 enriched planner history diagnose the failure mode).
    quality_warnings = check_code_quality(code_blocks, worker_usage)
    if quality_warnings:
        logger.warning(
            "Quality gate warnings",
            extra={
                "event": "execution.quality_gate_warnings",
                "step_id": step_id,
                "warnings": quality_warnings,
            },
        )
    else:
        logger.debug(
            "Quality gate clean — no warnings",
            extra={"event": "execution.quality_gate_clean", "step_id": step_id},
        )

    # Semgrep scan on ALL Qwen output (not just expects_code steps).
    if not semgrep_scanner.is_loaded():
        logger.debug(
            "Semgrep not loaded — scan skipped",
            extra={"event": "execution.semgrep_skipped_not_loaded", "step_id": step_id},
        )
    else:
        sg_result = await semgrep_scanner.scan_blocks(
            [(b.code, b.language) for b in code_blocks]
        )
        if sg_result.found:
            logger.warning(
                "Semgrep blocked generated code",
                extra={
                    "event": "execution.semgrep_blocked",
                    "step_id": step_id,
                    "matches": len(sg_result.matches),
                },
            )
            return StepResult(
                step_id=step_id,
                status="blocked",
                error=f"Semgrep: insecure code detected ({len(sg_result.matches)} issues)",
                quality_warnings=quality_warnings,
            )
        logger.debug(
            "Semgrep scan clean — no issues in generated code",
            extra={
                "event": "execution.semgrep_clean",
                "step_id": step_id,
                "blocks_scanned": len(code_blocks),
            },
        )

    logger.debug(
        "Security scans passed",
        extra={
            "event": "execution.security_scans_exit",
            "step_id": step_id,
            "block_count": len(code_blocks),
            "warning_count": len(quality_warnings) if quality_warnings else 0,
        },
    )
    return code_blocks, quality_warnings or []


def _validate_and_unwrap(
    content: str,
    step_id: str,
    output_format: str | None,
    destination: OutputDestination,
    code_blocks: list[CodeBlock],
) -> str | StepResult:
    """Validate output format and unwrap execution-destined code fences.

    Returns the (possibly unwrapped) content string on success, or a
    StepResult with status="error" if format validation fails.
    """
    logger.debug(
        "Validating and unwrapping worker output",
        extra={
            "event": "execution.validate_unwrap_enter",
            "step_id": step_id,
            "output_format": output_format,
            "destination": destination.value,
            "block_count": len(code_blocks),
        },
    )

    # Validate output format if specified (P8)
    if output_format == "json":
        try:
            json.loads(content)
        except (json.JSONDecodeError, ValueError):
            logger.warning(
                "Output format violation: not valid JSON",
                extra={
                    "event": "execution.json_format_violation",
                    "step_id": step_id,
                },
                exc_info=True,
            )
            return StepResult(
                step_id=step_id,
                status="error",
                error="Output format violation: response is not valid JSON",
            )

    # When the output feeds a downstream tool_call (EXECUTION destination),
    # unwrap markdown code fences. Qwen frequently wraps code in
    # ```python...``` even for execution-destined output. A single code
    # block means the entire response IS the code — safe to unwrap.
    # Multiple blocks or DISPLAY-destined output are left as-is.
    if (
        destination == OutputDestination.EXECUTION
        and len(code_blocks) == 1
        and code_blocks[0].code.strip()
    ):
        content = code_blocks[0].code
        logger.debug(
            "Unwrapped single code block for execution-destined output",
            extra={
                "event": "execution.execution_fence_unwrap",
                "step_id": step_id,
                "language": code_blocks[0].language,
                "content_len": len(content),
            },
        )
    else:
        logger.debug(
            "No fence unwrap (multi-block or display destination)",
            extra={
                "event": "execution.no_fence_unwrap",
                "step_id": step_id,
                "destination": str(destination),
                "block_count": len(code_blocks),
                "content_len": len(content),
            },
        )

    logger.debug(
        "Validate and unwrap complete",
        extra={
            "event": "execution.validate_unwrap_exit",
            "step_id": step_id,
            "content_length": len(content),
        },
    )
    return content
