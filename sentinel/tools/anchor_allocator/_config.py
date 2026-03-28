"""YAML, JSON, and TOML anchor parsers using stdlib."""

from __future__ import annotations

import json
import logging

from sentinel.tools.anchor_allocator._core import AnchorEntry, AnchorTier

logger = logging.getLogger(__name__)


def parse_yaml_anchors(content: str) -> list[AnchorEntry]:
    """Parse YAML and return anchor candidates (top-level keys only).

    Returns an empty list on parse failure (fail-safe).
    """
    if not content.strip():
        return []

    try:
        import yaml
        data = yaml.safe_load(content)
    except Exception as exc:
        logger.warning("yaml_anchor_parse_failed", exc_info=exc)
        return []

    if not isinstance(data, dict):
        return []

    return [
        AnchorEntry(
            name=f"key-{key}",
            line=0,
            tier=AnchorTier.SECTION,
            description=f"YAML key: {key}",
            has_end=False,
        )
        for key in data
    ]


def parse_json_anchors(content: str) -> list[AnchorEntry]:
    """Parse JSON and return anchor candidates (top-level keys only).

    JSON has no comment syntax — anchors describe structure for the
    episodic memory map but markers cannot be inserted into the file.
    Returns an empty list on parse failure (fail-safe).
    """
    if not content.strip():
        return []

    try:
        data = json.loads(content)
    except Exception as exc:
        logger.warning("json_anchor_parse_failed", exc_info=exc)
        return []

    if not isinstance(data, dict):
        return []

    return [
        AnchorEntry(
            name=f"key-{key}",
            line=0,
            tier=AnchorTier.SECTION,
            description=f"JSON key: {key}",
            has_end=False,
        )
        for key in data
    ]


def parse_toml_anchors(content: str) -> list[AnchorEntry]:
    """Parse TOML and return anchor candidates (sections and arrays).

    Returns an empty list on parse failure (fail-safe).
    """
    if not content.strip():
        return []

    try:
        import tomllib
        data = tomllib.loads(content)
    except Exception as exc:
        logger.warning("toml_anchor_parse_failed", exc_info=exc)
        return []

    if not isinstance(data, dict):
        return []

    return [
        AnchorEntry(
            name=f"section-{key}",
            line=0,
            tier=AnchorTier.SECTION,
            description=f"TOML section: [{key}]",
            has_end=False,
        )
        for key in data
    ]
