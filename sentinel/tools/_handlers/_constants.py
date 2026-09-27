"""Shared constants for file and website handler mixins.

These gate Semgrep scanning and defence-in-depth code stripping.
Centralised here to prevent silent divergence between handlers.
"""

import os

# Extensions that trigger content manifest and structural digest generation.
# Used by file_write, file_patch, and website_create to decide which outputs
# get integrity tracking.  Previously duplicated as _MANIFEST_EXTENSIONS
# (_file.py, executor.py) and _DIGEST_EXTENSIONS (_website.py).
_MANIFEST_EXTENSIONS = frozenset({"html", "htm", "js", "mjs", "py", "css"})

# Code file extensions for defence-in-depth stripping of <RESPONSE> tags
# and markdown fences before writing to disk.
# Extensionless filenames that the code fixer should process.
# Previously duplicated in _file.py and _website.py.
_EXTENSIONLESS_FIXER_NAMES = frozenset(
    {
        "Dockerfile",
        "Containerfile",
        "Makefile",
        "GNUmakefile",
        "makefile",
    }
)

_CODE_EXTENSIONS = frozenset(
    {
        ".py",
        ".rs",
        ".js",
        ".ts",
        ".jsx",
        ".tsx",
        ".c",
        ".cpp",
        ".h",
        ".hpp",
        ".java",
        ".go",
        ".rb",
        ".sh",
        ".bash",
        ".zsh",
        ".pl",
        ".lua",
        ".zig",
        ".swift",
        ".kt",
        ".scala",
        ".r",
        ".cs",
        ".toml",
        ".yaml",
        ".yml",
        ".json",
        ".xml",
        ".html",
        ".css",
        ".sql",
        ".dockerfile",
        ".containerfile",
        ".cfg",
        ".ini",
        ".conf",
        ".php",
        ".svg",
    }
)

# Map file extensions to Semgrep language hints for pre-write scanning (D4)
_EXT_TO_LANG: dict[str, str] = {
    ".py": "python",
    ".js": "javascript",
    ".ts": "typescript",
    ".java": "java",
    ".c": "c",
    ".cpp": "cpp",
    ".cs": "csharp",
    ".php": "php",
    ".rb": "ruby",
    ".go": "go",
    ".rs": "rust",
    ".sh": "bash",
}


def _detect_language_from_path(path: str) -> str | None:
    """Extract language hint from file extension for Semgrep scanning."""
    _, ext = os.path.splitext(path)
    return _EXT_TO_LANG.get(ext.lower())
