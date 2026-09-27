"""Enums for the security scanner pipeline.

Shared value types used across scanners, rules, suppression, and pipeline
orchestration.  All inherit ``(str, Enum)`` for clean YAML/JSON serialization.
"""

from __future__ import annotations

from enum import Enum


class Severity(str, Enum):
    """Severity level assigned to a scan match."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class Platform(str, Enum):
    """Target platform for a detection rule."""

    LINUX = "linux"
    WINDOWS = "windows"
    MACOS = "macos"
    ALL = "all"


class Phase(str, Enum):
    """Pipeline phase in which a scanner participates."""

    INPUT = "input"
    OUTPUT = "output"


class OutputDestination(str, Enum):
    """Where scanned output will be sent after scanning."""

    DISPLAY = "display"
    EXECUTION = "execution"


class RegionType(str, Enum):
    """Content region type produced by ContextClassifier."""

    CODE_BLOCK = "code_block"
    SHELL = "shell"
    PROSE = "prose"
    CONFIG = "config"
    INDENTED_CODE = "indented_code"


class EncodingType(str, Enum):
    """Encoding layer type produced by EncodingNormalizer."""

    BASE64 = "base64"
    HEX = "hex"
    URL = "url"
    ROT13 = "rot13"
    HTML = "html"
    UNICODE = "unicode"
    CHAR_SPLIT = "char_split"
