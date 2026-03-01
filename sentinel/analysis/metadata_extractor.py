"""Metadata extraction utilities for F1 structured outcome capture.

Extracts trusted metadata from Python-generated artifacts (code blocks,
file contents, process output). All output is safe to share with the
planner — no Qwen conversational text crosses the privacy boundary.
"""

from __future__ import annotations

import ast
import difflib


class _SymbolVisitor(ast.NodeVisitor):
    """Collects top-level function/class names and imports."""

    def __init__(self):
        self.defined_symbols: list[str] = []
        self.imports: list[str] = []

    def visit_FunctionDef(self, node: ast.FunctionDef):
        self.defined_symbols.append(node.name)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef):
        self.defined_symbols.append(node.name)

    def visit_ClassDef(self, node: ast.ClassDef):
        self.defined_symbols.append(node.name)

    def visit_Import(self, node: ast.Import):
        for alias in node.names:
            self.imports.append(alias.name)

    def visit_ImportFrom(self, node: ast.ImportFrom):
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
    except SyntaxError:
        return empty
    visitor = _SymbolVisitor()
    visitor.visit(tree)
    return {
        "defined_symbols": visitor.defined_symbols,
        "imports": visitor.imports,
    }


def extract_diff_stats(before: str | None, after: str) -> str:
    """Compute +N/-M line change counts between before and after content.

    Uses difflib.unified_diff to count added/removed lines.
    Returns a compact string like '+5/-2 lines'.
    """
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
        "python": "f.py", "javascript": "f.js", "typescript": "f.ts",
        "java": "f.java", "c": "f.c", "cpp": "f.cpp", "rust": "f.rs",
        "go": "f.go", "ruby": "f.rb", "shell": "f.sh", "bash": "f.sh",
    }
    filename = ext_map.get(language, f"f.{language}")

    try:
        analysis = _lizard.analyze_file.analyze_source_code(filename, code)
    except Exception:
        return empty

    if not analysis.function_list:
        return empty

    most_complex = max(analysis.function_list, key=lambda f: f.cyclomatic_complexity)
    return {
        "complexity_max": most_complex.cyclomatic_complexity,
        "complexity_function": most_complex.name,
    }


def extract_stderr_preview(
    stderr: str | None, max_lines: int = 3, max_chars: int = 500
) -> str:
    """Extract a truncated preview of stderr output.

    Returns at most max_lines lines and max_chars characters.
    This is OS-generated output (from subprocess), not Qwen text.
    """
    if not stderr:
        return ""
    lines = stderr.splitlines()[:max_lines]
    preview = "\n".join(lines)
    if len(preview) > max_chars:
        preview = preview[:max_chars]
    return preview


def compute_token_usage_ratio(
    worker_usage: dict | None, max_tokens: int = 8192
) -> float | None:
    """Compute the ratio of tokens generated vs max allowed.

    High ratios (>0.95) indicate the worker likely hit the token cap
    and output may be truncated. Returns None if usage data unavailable.
    """
    if not worker_usage or max_tokens <= 0:
        return None
    eval_count = worker_usage.get("eval_count")
    if eval_count is None:
        return None
    return round(eval_count / max_tokens, 3)
