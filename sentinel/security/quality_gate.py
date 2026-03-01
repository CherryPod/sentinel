"""Post-generation quality gate for Qwen-produced code blocks.

Detects two failure modes that are NOT security violations but degrade
output quality and should be surfaced to the caller as warnings:

  1. Python syntax errors — truncated or malformed code that ast.parse
     cannot accept, indicating Qwen produced broken output.

  2. Token-cap truncation — when eval_count approaches num_predict (8192),
     the response was likely cut off mid-generation.  The dominant failure
     mode in the TL2 benchmark (5% Python syntax error rate, almost all
     from truncation).

This module never blocks — it only returns warning strings.  Blocking is
the security pipeline's job.  Quality warnings are advisory: they inform
the planner's enriched history format (Phase F1) and are logged for
monitoring but do not change step status.

Only stdlib is used here (ast, textwrap) — no external dependencies.
"""

import ast
import textwrap

from sentinel.security.code_extractor import CodeBlock

# Mirror of OllamaWorker._DEFAULT_OPTIONS["num_predict"].  Kept here as a
# local constant to avoid importing from sentinel.worker (circular risk).
# If the Ollama cap changes, update both locations.
_NUM_PREDICT = 8192

# Flag truncation when eval_count / num_predict >= this threshold.
# At 95%+ utilisation the model is almost certainly against the cap.
# From F1 research: token_usage_ratio >= 0.95 correlates with truncated output.
_TOKEN_CAP_THRESHOLD = 0.95

# ---------------------------------------------------------------------------
# Negative markers — if any appear in the first 30 lines, it is NOT Python.
# Ported from scripts/analyse_benchmark_results.py._looks_like_python() (Q2 fix).
# Rust and C/C++ share structural patterns with Python (let, import, self)
# but have strong distinguishing signals — check negatives first.
# ---------------------------------------------------------------------------
_NOT_PYTHON_MARKERS: list[str] = [
    "fn ",        # Rust function declaration
    "let ",       # Rust/JS variable binding
    "mut ",       # Rust mutable binding
    "impl ",      # Rust impl block
    "pub fn",     # Rust public function
    "println!(",  # Rust macro
    "-> {",       # Rust return type + block
    "(&self)",    # Rust self reference
    "#include",   # C/C++ include directive
    "int main(",  # C/C++ main function
    "std::",      # C++ standard library
    "cout <<",    # C++ output stream
    "printf(",    # C printf
    "void ",      # C/C++ void return
    "#ifndef",    # C/C++ header guard
    "#define",    # C/C++ macro
]

# ---------------------------------------------------------------------------
# Positive markers — presence of 2+ suggests Python; 1+ with colon lines
# also qualifies.  These are structural Python idioms that rarely appear
# in other languages.
# ---------------------------------------------------------------------------
_PYTHON_MARKERS: list[str] = [
    "def ", "class ", "import ", "from ",
    "if __name__", "async def ", "await ",
    "self.", "print(", "try:", "except ",
    "with open(", "raise ", "elif ", "lambda ", "yield ",
]


def check_code_quality(
    code_blocks: list[CodeBlock],
    worker_usage: dict | None = None,
) -> list[str]:
    """Run post-generation quality checks on extracted code blocks.

    Checks performed:
      - Python syntax validation for blocks tagged as Python or heuristically
        identified as Python (handles untagged blocks from Qwen).
      - Token-cap truncation detection via worker_usage eval_count.

    Returns:
        List of warning strings.  Empty list means no quality issues found.
        Strings are human-readable and suitable for logging and planner context.
    """
    warnings: list[str] = []

    # Token-cap truncation check — run once per response, not per block.
    truncation_warning = _check_truncation(worker_usage)
    if truncation_warning:
        warnings.append(truncation_warning)

    # Syntax check — run on each block that is or looks like Python.
    for i, block in enumerate(code_blocks):
        is_python = block.language == "python"
        if not is_python and block.language is None:
            is_python = _is_likely_python(block.code)

        if not is_python:
            continue

        valid, error_msg = _check_python_syntax(block.code)
        if not valid:
            # Include first 40 chars of the block for context in logs.
            snippet = block.code[:40].replace("\n", "\\n")
            warnings.append(
                f"Python syntax error ({error_msg}) in block {i + 1}: {snippet!r}..."
            )

    return warnings


def _check_truncation(worker_usage: dict | None) -> str | None:
    """Return a truncation warning string, or None if not truncated.

    Uses eval_count from Ollama's token stats.  When eval_count /
    _NUM_PREDICT >= _TOKEN_CAP_THRESHOLD the response very likely
    hit the token cap mid-generation.
    """
    if worker_usage is None:
        return None

    eval_count = worker_usage.get("eval_count")
    if not isinstance(eval_count, int) or eval_count <= 0:
        return None

    ratio = eval_count / _NUM_PREDICT
    if ratio >= _TOKEN_CAP_THRESHOLD:
        return (
            f"Token cap likely hit: {eval_count}/{_NUM_PREDICT} tokens used "
            f"({ratio:.1%}) — response may be truncated"
        )
    return None


def _check_python_syntax(code: str) -> tuple[bool, str]:
    """Try to parse Python code.  Returns (valid, error_message).

    Ported from scripts/analyse_benchmark_results.py.check_python_syntax() (Q3 fix).
    Tries dedented first (handles method bodies and class snippets with
    consistent leading indentation), then raw (handles mixed-indent code
    that textwrap.dedent would mangle).

    Passes if EITHER parse succeeds — avoids false positives on valid-but-
    oddly-indented code from Qwen's code decomposition output.
    """
    try:
        ast.parse(textwrap.dedent(code))
        return True, ""
    except SyntaxError:
        pass
    try:
        ast.parse(code)
        return True, ""
    except SyntaxError as exc:
        return False, f"Line {exc.lineno}: {exc.msg}"


def _is_likely_python(code: str) -> bool:
    """Heuristic: does an untagged code block look like Python?

    Ported from scripts/analyse_benchmark_results.py._looks_like_python() (Q2 fix).
    The code_extractor._detect_language() only checks import/from/def/class,
    missing blocks that are all function calls, assignments, or exception
    handling.  This check is broader.

    Uses the first 30 lines as a sample — enough to catch language-specific
    patterns without processing large blocks unnecessarily.
    """
    lines = code.strip().splitlines()
    if not lines:
        return False
    sample = "\n".join(lines[:30])

    # Negative markers — any one of these rules out Python
    if any(marker in sample for marker in _NOT_PYTHON_MARKERS):
        return False

    # Positive markers — 2+ is a strong signal
    hits = sum(1 for marker in _PYTHON_MARKERS if marker in sample)
    if hits >= 2:
        return True

    # Single marker + colon-terminated lines (def foo():, for x in y:, if x:)
    colon_lines = sum(1 for line in lines[:30] if line.rstrip().endswith(":"))
    return hits >= 1 and colon_lines >= 2
