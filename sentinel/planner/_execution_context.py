"""Variable binding context for plan execution.

Tracks named variables ($var_name references) during step execution,
resolving them in prompts and arguments with both trusted and
untrusted (datamarked) substitution modes.

Extracted from _execution.py during planner modularisation Phase 4.
"""

import logging
import re

from sentinel.core.models import TaggedData
from sentinel.security.spotlighting import apply_datamarking

from .builders import CHAIN_REMINDER

logger = logging.getLogger(__name__)

# Variable reference pattern: matches $lowercase_with_underscores_and_digits.
# Shared across resolve_text, resolve_text_safe, and get_referenced_data_ids
# to ensure consistent behaviour. Broad \w+ would match $HOME/$PATH which
# causes false-positive provenance blocks.
_VAR_RE = r"\$[a-z_][a-z0-9_]*"


class ExecutionContext:
    """Tracks variable bindings during plan execution."""

    def __init__(self) -> None:
        self._vars: dict[str, TaggedData] = {}

    def set(self, var_name: str, data: TaggedData) -> None:
        self._vars[var_name] = data
        logger.debug(
            "Variable stored in execution context",
            extra={
                "event": "execution.var_store",
                "var_name": var_name,
                "data_id": data.id,
                "content_length": len(data.content) if data.content else 0,
            },
        )

    def get(self, var_name: str) -> TaggedData | None:
        result = self._vars.get(var_name)
        if result is not None:
            logger.debug(
                "ExecutionContext.get hit",
                extra={"event": "execution.context.get", "var_name": var_name},
            )
        return result

    def resolve_text(self, text: str) -> str:
        """Replace $var_name references with their content."""
        if not text:
            return text

        def replacer(match: re.Match) -> str:
            var_name = match.group(0)
            data = self._vars.get(var_name)
            if data is not None:
                logger.debug(
                    "Variable resolved",
                    extra={
                        "event": "execution.var_resolve",
                        "var_name": var_name,
                        "data_id": data.id,
                        "content_length": len(data.content) if data.content else 0,
                    },
                )
                return data.content
            return var_name  # leave unresolved refs as-is

        resolved = re.sub(_VAR_RE, replacer, text)

        # D-001: Warn on unresolved variable references (likely planner typos)
        unresolved = [
            m.group(0)
            for m in re.finditer(_VAR_RE, resolved)
            if m.group(0) not in self._vars and self._vars  # only warn if vars exist
        ]
        if unresolved:
            logger.warning(
                "Unresolved variable references: %s",
                unresolved,
                extra={"event": "execution.unresolved_vars", "vars": unresolved},
            )

        return resolved

    def resolve_args(self, args: dict) -> dict:
        """Replace $var_name references in dict values (recurses into nested dicts and lists)."""
        resolved = {}
        for key, value in args.items():
            if isinstance(value, str):
                resolved[key] = self.resolve_text(value)
            elif isinstance(value, dict):
                logger.debug(
                    "resolve_args: clean",
                    extra={"event": "execution.resolve_args.branch.clean"},
                )
                resolved[key] = self.resolve_args(value)
            elif isinstance(value, list):
                logger.debug(
                    "resolve_args: clean",
                    extra={"event": "execution.resolve_args.branch.clean"},
                )
                resolved[key] = [
                    self.resolve_text(item)
                    if isinstance(item, str)
                    else self.resolve_args(item)
                    if isinstance(item, dict)
                    else item
                    for item in value
                ]
            else:
                logger.debug(
                    "resolve_args: clean",
                    extra={"event": "execution.resolve_args.branch.clean"},
                )
                resolved[key] = value
        return resolved

    def get_referenced_data_ids(self, text: str) -> list[str]:
        """Return data IDs from all $var_name references found in text."""
        logger.debug(
            "get_referenced_data_ids called",
            extra={
                "event": "execution.get_referenced_data_ids",
                "text_len": len(text) if text else 0,
            },
        )
        if not text:
            return []
        data_ids = []
        for match in re.finditer(_VAR_RE, text):
            var_name = match.group(0)
            data = self._vars.get(var_name)
            if data is not None:
                data_ids.append(data.id)
        return data_ids

    def get_referenced_data_ids_from_args(self, args: dict) -> list[str]:
        """Return data IDs from all $var_name references in dict values (recurses into nested dicts and lists)."""
        data_ids = []
        for value in args.values():
            if isinstance(value, str):
                data_ids.extend(self.get_referenced_data_ids(value))
            elif isinstance(value, dict):
                logger.debug(
                    "get_referenced_data_ids_from_args: clean",
                    extra={
                        "event": "execution.get_referenced_data_ids_from_args.branch.clean"
                    },
                )
                data_ids.extend(self.get_referenced_data_ids_from_args(value))
            elif isinstance(value, list):
                logger.debug(
                    "get_referenced_data_ids_from_args: clean",
                    extra={
                        "event": "execution.get_referenced_data_ids_from_args.branch.clean"
                    },
                )
                for item in value:
                    if isinstance(item, str):
                        data_ids.extend(self.get_referenced_data_ids(item))
                    elif isinstance(item, dict):
                        # Mirror resolve_args (:104-116) which recurses into
                        # list-of-dict. Without this branch, a $var reference
                        # inside a dict inside a list (e.g. website.media =
                        # [{"source": "$var", "dest": "x"}]) resolves at exec
                        # time but is invisible to S3 — provenance gate sees
                        # no referenced IDs and skips the trust check.
                        data_ids.extend(self.get_referenced_data_ids_from_args(item))
        return data_ids

    def resolve_text_safe(self, text: str, marker: str) -> str:
        """Replace $var_name references with tagged, datamarked content.

        Unlike resolve_text(), this wraps substituted content in
        <UNTRUSTED_DATA> tags with spotlighting markers, treating
        prior step output as untrusted data (which it is).
        """
        logger.debug(
            "resolve_text_safe called",
            extra={
                "event": "execution.resolve_text_safe",
                "text_len": len(text) if hasattr(text, "__len__") else 0,
                "marker": marker,
            },
        )  # auto:entry
        if not text:
            logger.debug(
                "resolve_text_safe: not_text",
                extra={
                    "event": "execution.resolve_text_safe.match",
                    "reason": "not_text",
                },
            )  # auto:neg
            return text

        has_substitution = False

        def replacer(match: re.Match) -> str:
            nonlocal has_substitution
            var_name = match.group(0)
            data = self._vars.get(var_name)
            if data is not None:
                has_substitution = True
                if marker:
                    logger.debug(
                        "resolve_text_safe: marker",
                        extra={
                            "event": "execution.resolve_text_safe.match",
                            "reason": "marker",
                        },
                    )  # auto:neg
                    marked = apply_datamarking(data.content, marker=marker)
                else:
                    logger.debug(
                        "resolve_text_safe: marker",
                        extra={
                            "event": "execution.resolve_text_safe.clean",
                            "reason": "marker",
                        },
                    )  # auto:neg
                    marked = data.content
                return f"\n<UNTRUSTED_DATA>\n{marked}\n</UNTRUSTED_DATA>\n"
            return var_name  # leave unresolved refs as-is

        resolved = re.sub(_VAR_RE, replacer, text)

        if has_substitution:
            logger.debug(
                "resolve_text_safe: has_substitution",
                extra={
                    "event": "execution.resolve_text_safe.match",
                    "reason": "has_substitution",
                },
            )  # auto:neg
            resolved += f"\n\n{CHAIN_REMINDER}"

        return resolved
