"""Metadata extraction utilities for F1 structured outcome capture.

Extracts trusted metadata from Python-generated artifacts (code blocks,
file contents, process output). All output is safe to share with the
planner — no Qwen conversational text crosses the privacy boundary.
"""

from __future__ import annotations

import ast
import difflib
import logging

from sentinel.core.config import OLLAMA_NUM_PREDICT

logger = logging.getLogger(__name__)

_STDERR_MAX_LINES = 10
_STDERR_MAX_CHARS = 1500


class _SymbolVisitor(ast.NodeVisitor):
    """Collects top-level function/class names and imports."""

    def __init__(self):
        self.defined_symbols: list[str] = []
        self.imports: list[str] = []

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self.defined_symbols.append(node.name)
        # Do not call generic_visit — prevents collecting nested defs

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self.defined_symbols.append(node.name)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self.defined_symbols.append(node.name)
        # Do not call generic_visit — prevents collecting nested defs

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            self.imports.append(alias.name)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        module = node.module or ""
        for alias in node.names:
            self.imports.append(f"{module}.{alias.name}" if module else alias.name)


def extract_code_symbols(code: str, language: str) -> dict:
    """Extract function/class names and imports from code.

    Python only in F1 (uses stdlib ast). Other languages deferred to F2
    (tree-sitter). Returns empty lists on parse failure — never raises.
    """
    empty = {"defined_symbols": [], "imports": []}
    if not code or language != "python":
        return empty
    try:
        tree = ast.parse(code)
    except (SyntaxError, RecursionError, MemoryError, ValueError):
        logger.warning(
            "extract_code_symbols: parse failed",
            exc_info=True,
            extra={
                "event": "metadata_extractor.extract_code_symbols_error",
                "error_category": "parse_error",
            },
        )
        return empty
    visitor = _SymbolVisitor()
    visitor.visit(tree)
    logger.debug(
        "extract_code_symbols: %d symbols, %d imports",
        len(visitor.defined_symbols),
        len(visitor.imports),
        extra={
            "event": "metadata_extractor.extract_code_symbols_complete",
            "symbol_count": len(visitor.defined_symbols),
            "import_count": len(visitor.imports),
        },
    )
    return {
        "defined_symbols": visitor.defined_symbols,
        "imports": visitor.imports,
    }


def extract_diff_stats(before: str | None, after: str) -> str:
    """Compute +N/-M line change counts between before and after content.

    Uses difflib.unified_diff to count added/removed lines.
    Returns a compact string like '+5/-2 lines'.
    """
    logger.debug(
        "extract_diff_stats called",
        extra={
            "event": "metadata_extractor.extract_diff_stats",
            "before_len": len(before) if hasattr(before, "__len__") else 0,
            "after_len": len(after) if hasattr(after, "__len__") else 0,
        },
    )  # auto:entry
    before_lines = (before or "").splitlines(keepends=True)
    after_lines = after.splitlines(keepends=True)
    added = 0
    removed = 0
    for line in difflib.unified_diff(before_lines, after_lines):
        if line.startswith("+") and not line.startswith("+++"):
            added += 1
        elif line.startswith("-") and not line.startswith("---"):
            removed += 1
    return f"+{added}/-{removed} lines"


def extract_complexity(code: str, language: str) -> dict:
    """Extract cyclomatic complexity metrics using lizard.

    Returns the highest complexity function name and its score.
    Supports Python, JavaScript, C/C++, Java, Rust, Go, and more.
    """
    import lizard as _lizard

    empty = {"complexity_max": None, "complexity_function": None}
    if not code:
        return empty

    ext_map = {
        "python": "f.py",
        "javascript": "f.js",
        "typescript": "f.ts",
        "java": "f.java",
        "c": "f.c",
        "cpp": "f.cpp",
        "rust": "f.rs",
        "go": "f.go",
        "ruby": "f.rb",
        "shell": "f.sh",
        "bash": "f.sh",
    }
    filename = ext_map.get(language, f"f.{language}")

    try:
        analysis = _lizard.analyze_file.analyze_source_code(filename, code)
    except Exception:  # broad catch — third-party library, can't predict failure modes
        logger.warning(
            "extract_complexity: lizard analysis failed",
            exc_info=True,
            extra={
                "event": "metadata_extractor.extract_complexity_error",
                "error_category": "analysis_error",
            },
        )
        return empty

    if not analysis.function_list:
        return empty

    most_complex = max(analysis.function_list, key=lambda f: f.cyclomatic_complexity)
    return {
        "complexity_max": most_complex.cyclomatic_complexity,
        "complexity_function": most_complex.name,
    }


def extract_stderr_preview(
    stderr: str | None,
    max_lines: int = _STDERR_MAX_LINES,
    max_chars: int = _STDERR_MAX_CHARS,
) -> str:
    """Extract a truncated preview of stderr output.

    Returns at most max_lines lines and max_chars characters.
    This is OS-generated output (from subprocess), not Qwen text.
    """
    logger.debug(
        "extract_stderr_preview called",
        extra={
            "event": "metadata_extractor.extract_stderr_preview",
            "stderr_len": len(stderr) if hasattr(stderr, "__len__") else 0,
            "max_lines": max_lines,
            "max_chars": max_chars,
        },
    )  # auto:entry
    if not stderr:
        return ""
    lines = stderr.splitlines()[:max_lines]
    preview = "\n".join(lines)
    if len(preview) > max_chars:
        preview = preview[:max_chars]
    return preview


def compute_token_usage_ratio(
    worker_usage: dict | None, max_tokens: int = OLLAMA_NUM_PREDICT
) -> float | None:
    """Compute the ratio of tokens generated vs max allowed.

    High ratios (>0.95) indicate the worker likely hit the token cap
    and output may be truncated. Returns None if usage data unavailable.
    """
    logger.debug(
        "compute_token_usage_ratio called",
        extra={
            "event": "metadata_extractor.compute_token_usage_ratio",
            "has_usage": worker_usage is not None,
            "max_tokens": max_tokens,
        },
    )
    if not worker_usage or max_tokens <= 0:
        return None
    eval_count = worker_usage.get("eval_count")
    if eval_count is None:
        return None
    return round(eval_count / max_tokens, 3)
