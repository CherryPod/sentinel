"""Structural digest extraction for Qwen output files.

Extracts privacy-safe structural metadata from files — element names,
function names, references, counts — never raw content. This metadata
feeds into the judge payload so the planner-as-judge can evaluate
whether Qwen's output matches the user's goal.
"""

from __future__ import annotations

import ast
import logging
import re
import sys

from sentinel.core.decorators import no_audit_log

logger = logging.getLogger(__name__)

# Reuse the same regex from anchor_allocator/_html.py
_JS_FUNC_RE = re.compile(
    r"(?:async\s+)?function\s+(\w+)\s*\(",
    re.MULTILINE,
)

_STRUCTURAL_TAGS = frozenset(
    {
        "nav",
        "header",
        "footer",
        "main",
        "section",
        "article",
        "aside",
        "form",
        "table",
    }
)

# ── JS regex patterns ───────────────────────────────────────────────
# const/let/var name = (...) => or async (...) =>
# Known imprecision: the 200-char lookahead for => can produce false positives
# when => appears on the same line from an unrelated context (e.g., a ternary
# or comment). This is acceptable for structural digest purposes — false
# positives create noise in the digest but not safety issues. Do not attempt
# to "fix" individual false positive reports without a proper JS parser.
_JS_ARROW_RE = re.compile(
    r"(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s+)?\(?",
    re.MULTILINE,
)
_JS_CLASS_RE = re.compile(
    r"class\s+(\w+)\s*(?:extends\s+\w+\s*)?\{",
    re.MULTILINE,
)
_JS_GETBYID_RE = re.compile(
    r"getElementById\s*\(\s*['\"]([^'\"]+)['\"]\s*\)",
)
_JS_QUERYSELECTOR_RE = re.compile(
    r"querySelector(?:All)?\s*\(\s*['\"]#([^'\"]+)['\"]\s*\)",
)
_JS_TIMER_RE = re.compile(
    r"(setInterval|setTimeout)\s*\([^,]+,\s*(\d+)\s*\)",
)
_JS_LISTENER_RE = re.compile(
    r"addEventListener\s*\(\s*['\"](\w+)['\"]\s*,",
)
_JS_FETCH_RE = re.compile(
    r"(?:fetch\s*\(|new\s+XMLHttpRequest|\$\.ajax)",
)

# ── CSS regex patterns ──────────────────────────────────────────────
_CSS_SELECTOR_RE = re.compile(
    r"(?:^|\})\s*([.#]?[\w][\w\-]*(?:\s+[.#]?[\w][\w\-]*)*)\s*\{",
    re.MULTILINE,
)
_CSS_PROPERTY_RE = re.compile(r"[\w\-]+\s*:\s*[^;{}]+;")
_CSS_MEDIA_RE = re.compile(r"@media\s")

# ── Stdlib module names for cross-reference checks ──────────────────
_STDLIB_MODULES = (
    frozenset(sys.stdlib_module_names)
    if hasattr(sys, "stdlib_module_names")
    else frozenset(
        {
            "json",
            "os",
            "sys",
            "re",
            "math",
            "datetime",
            "pathlib",
            "io",
            "collections",
            "itertools",
            "functools",
            "typing",
            "logging",
            "subprocess",
            "asyncio",
            "hashlib",
            "base64",
            "time",
            "random",
            "csv",
            "xml",
            "html",
            "http",
            "urllib",
            "shutil",
            "glob",
            "textwrap",
            "abc",
            "dataclasses",
            "enum",
            "copy",
            "pprint",
            "unittest",
            "argparse",
            "configparser",
            "socket",
            "struct",
            "threading",
            "multiprocessing",
            "contextlib",
            "traceback",
            "tempfile",
            "pickle",
            "sqlite3",
            "uuid",
            "secrets",
            "statistics",
            "heapq",
            "bisect",
            "operator",
            "string",
            "decimal",
            "fractions",
            "ast",
            "inspect",
            "dis",
            "code",
            "codeop",
        }
    )
)

# Common third-party packages pre-installed in the sandbox
_KNOWN_PACKAGES = frozenset(
    {
        "requests",
        "aiohttp",
        "beautifulsoup4",
        "bs4",
        "numpy",
        "pandas",
        "flask",
        "fastapi",
        "pydantic",
        "httpx",
        "pytest",
        "yaml",
        "toml",
        "dotenv",
        "jinja2",
        "markdown",
        "pillow",
        "PIL",
    }
)


# ── Public API ──────────────────────────────────────────────────────


@no_audit_log
def extract_structural_digest(
    filename: str,
    content: str,
    language: str,
) -> dict:
    """Extract structural metadata from file content.

    Returns a dict of privacy-safe metadata — names, counts, references,
    never raw content. Safe to include in judge payloads that cross the
    privacy boundary.

    Dispatches to language-specific extractors. Returns empty digest for
    unsupported languages (never raises).
    """
    if not content:
        logger.debug(
            "structural_digest: empty content for %s",
            filename,
            extra={"event": "structural_digest.empty", "file_name": filename},
        )
        return _empty_digest(language or _guess_language(filename))
    logger.debug(
        "extract_structural_digest: not_content_passed",
        extra={
            "event": "structural_digest.empty.passed",
            "reason": "not_content_passed",
        },
    )  # auto:neg

    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    lang = language or _guess_language(filename)
    if lang in ("html", "htm") or ext in ("html", "htm"):
        digest = _extract_html(content)
        logger.debug(
            "structural_digest: HTML %s — %d IDs, %d scripts, %d panels",
            filename,
            len(digest["element_ids"]),
            len(digest["script_refs"]),
            digest["panel_count"],
            extra={
                "event": "structural_digest.html",
                "file_name": filename,
                "id_count": len(digest["element_ids"]),
                "script_count": len(digest["script_refs"]),
                "panel_count": digest["panel_count"],
            },
        )
        return digest
    if lang in ("javascript", "js", "mjs") or ext in ("js", "mjs"):
        digest = _extract_js(content)
        logger.debug(
            "structural_digest: JS %s — %d functions, %d DOM refs, fetch=%s",
            filename,
            len(digest["functions_defined"]),
            len(digest["dom_references"]),
            digest["fetch_calls"],
            extra={
                "event": "structural_digest.js",
                "file_name": filename,
                "function_count": len(digest["functions_defined"]),
                "dom_ref_count": len(digest["dom_references"]),
                "fetch_calls": digest["fetch_calls"],
            },
        )
        return digest
    if lang in ("python", "py") or ext == "py":
        digest = _extract_python(content)
        logger.debug(
            "structural_digest: Python %s — %d functions, %d classes, syntax_valid=%s",
            filename,
            len(digest["functions_defined"]),
            len(digest["classes_defined"]),
            digest["syntax_valid"],
            extra={
                "event": "structural_digest.python",
                "file_name": filename,
                "function_count": len(digest["functions_defined"]),
                "class_count": len(digest["classes_defined"]),
                "syntax_valid": digest["syntax_valid"],
            },
        )
        return digest
    if lang == "css" or ext == "css":
        digest = _extract_css(content)
        logger.debug(
            "structural_digest: CSS %s — %d selectors, %d properties, %d media queries",
            filename,
            len(digest["selectors"]),
            digest["property_count"],
            digest["media_queries"],
            extra={
                "event": "structural_digest.css",
                "file_name": filename,
                "selector_count": len(digest["selectors"]),
                "property_count": digest["property_count"],
                "media_queries": digest["media_queries"],
            },
        )
        return digest
    logger.debug(
        "structural_digest: unsupported language %s — returning empty",
        lang or "unknown",
        extra={
            "event": "structural_digest.unsupported_language",
            "lang": lang or "unknown",
        },
    )
    return _empty_digest(lang)


def cross_reference_check(
    digests: dict[str, dict],
    written_files: set[str] | None = None,
) -> list[dict]:
    """Compare structural metadata across files in the same site.

    Returns a list of warning dicts with keys: type, file, detail, severity.
    """
    warnings: list[dict] = []
    if not digests:
        logger.debug(
            "cross_reference_check: no digests to check",
            extra={"event": "structural_digest.cross_ref_empty"},
        )
        return warnings

    logger.debug(
        "cross_reference_check: %d digests, %d written files",
        len(digests),
        len(written_files) if written_files else len(digests),
        extra={
            "event": "structural_digest.cross_ref_start",
            "digest_count": len(digests),
        },
    )

    if written_files is None:
        written_files = set(digests.keys())

    # Collect all HTML element IDs across all HTML files
    all_html_ids: set[str] = set()
    for _fname, digest in digests.items():
        if "element_ids" in digest:
            all_html_ids.update(digest["element_ids"])

    # Check JS DOM references against HTML IDs
    for fname, digest in digests.items():
        dom_refs = digest.get("dom_references", [])
        for ref in dom_refs:
            if ref not in all_html_ids:
                warnings.append(
                    {
                        "type": "missing_element",
                        "file": fname,
                        "detail": f"JS references element '{ref}' but no HTML file defines id='{ref}'",
                        "severity": "HIGH",
                    }
                )

    # Check HTML script refs against written files
    for fname, digest in digests.items():
        script_refs = digest.get("script_refs", [])
        for ref in script_refs:
            ref_basename = ref.rsplit("/", 1)[-1]
            if ref_basename not in written_files and ref not in written_files:
                warnings.append(
                    {
                        "type": "missing_script",
                        "file": fname,
                        "detail": f"HTML references script '{ref}' but file was not written",
                        "severity": "HIGH",
                    }
                )

    # Check Python imports against written files and known packages
    for fname, digest in digests.items():
        imports = digest.get("imports", [])
        for imp in imports:
            top_level = imp.split(".")[0]
            if top_level in _STDLIB_MODULES:
                continue
            if top_level in _KNOWN_PACKAGES:
                continue
            possible_files = {f"{top_level}.py", top_level}
            if not possible_files & written_files:
                warnings.append(
                    {
                        "type": "missing_module",
                        "file": fname,
                        "detail": f"Python imports '{top_level}' but module was not written and is not stdlib/known",
                        "severity": "MEDIUM",
                    }
                )

    if warnings:
        logger.info(
            "cross_reference_check: %d warnings found",
            len(warnings),
            extra={
                "event": "structural_digest.cross_ref_warnings",
                "warning_count": len(warnings),
                "types": [w["type"] for w in warnings],
            },
        )
    else:
        logger.debug(
            "cross_reference_check: all references valid",
            extra={"event": "structural_digest.cross_ref_clean"},
        )

    return warnings


def structural_survival_check(
    before_content: str,
    after_content: str,
    language: str,
) -> dict:
    """Compare structural elements before and after a patch.

    Returns a dict with:
    - elements_removed: list of structural identifiers that were present
      before but missing after
    - elements_added: list of new structural identifiers
    - survival_ok: True if no removals detected

    The principle is language-agnostic: whatever the language's "structural
    identity" is (HTML element IDs, Python function/class names, JS function
    names, CSS selectors), verify they survive the patch.
    """
    if not before_content:
        logger.debug(
            "structural_survival_check: not_before_content",
            extra={
                "event": "structural_digest.structural_survival_check.match",
                "reason": "not_before_content",
            },
        )  # auto:neg
        return {"elements_removed": [], "elements_added": [], "survival_ok": True}

    before_ids = _extract_structural_ids(before_content, language)
    after_ids = _extract_structural_ids(after_content, language)

    removed = sorted(before_ids - after_ids)
    added = sorted(after_ids - before_ids)

    if removed:
        logger.warning(
            "structural_survival: %d elements removed (%s), %d added",
            len(removed),
            ", ".join(removed[:5]),
            len(added),
            extra={
                "event": "structural_digest.survival_fail",
                "language": language,
                "removed_count": len(removed),
                "added_count": len(added),
                "before_count": len(before_ids),
                "after_count": len(after_ids),
            },
        )
    else:
        logger.debug(
            "structural_survival: all %d elements survived, %d new",
            len(before_ids),
            len(added),
            extra={
                "event": "structural_digest.survival_ok",
                "language": language,
                "survived_count": len(before_ids),
                "added_count": len(added),
            },
        )

    return {
        "elements_removed": removed,
        "elements_added": added,
        "survival_ok": len(removed) == 0,
    }


# ── Internal helpers ────────────────────────────────────────────────


def _guess_language(filename: str) -> str:
    """Guess language from filename extension."""
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    return {
        "html": "html",
        "htm": "html",
        "js": "javascript",
        "mjs": "javascript",
        "py": "python",
        "css": "css",
    }.get(ext, "")


def _empty_digest(language: str) -> dict:
    """Return an empty digest with the right keys for the language."""
    if language in ("html", "htm"):
        logger.debug(
            "structural_digest: empty digest for html",
            extra={"event": "structural_digest.empty_digest", "resolved_lang": "html"},
        )
        return {
            "element_ids": [],
            "script_refs": [],
            "link_refs": [],
            "css_classes": [],
            "structural_tags": [],
            "inline_script_functions": [],
            "panel_count": 0,
            "class_counts": {},
        }
    logger.debug(
        "_empty_digest: language_in_passed",
        extra={
            "event": "structural_digest.empty_digest.passed",
            "reason": "language_in_passed",
        },
    )  # auto:neg
    if language in ("javascript", "js", "mjs"):
        logger.debug(
            "structural_digest: empty digest for javascript",
            extra={
                "event": "structural_digest.empty_digest",
                "resolved_lang": "javascript",
            },
        )
        return {
            "syntax_valid": None,
            "functions_defined": [],
            "dom_references": [],
            "timer_calls": [],
            "event_listeners": [],
            "fetch_calls": False,
            "code_fixer_errors": [],
        }
    logger.debug(
        "_empty_digest: language_in_passed",
        extra={
            "event": "structural_digest.empty_digest.passed",
            "reason": "language_in_passed",
        },
    )  # auto:neg
    if language in ("python", "py"):
        logger.debug(
            "structural_digest: empty digest for python",
            extra={
                "event": "structural_digest.empty_digest",
                "resolved_lang": "python",
            },
        )
        return {
            "syntax_valid": None,
            "functions_defined": [],
            "classes_defined": [],
            "imports": [],
        }
    logger.debug(
        "_empty_digest: language_in_passed",
        extra={
            "event": "structural_digest.empty_digest.passed",
            "reason": "language_in_passed",
        },
    )  # auto:neg
    if language == "css":
        logger.debug(
            "structural_digest: empty digest for css",
            extra={"event": "structural_digest.empty_digest", "resolved_lang": "css"},
        )
        return {
            "selectors": [],
            "property_count": 0,
            "media_queries": 0,
        }
    logger.debug(
        "structural_digest: empty digest for unknown lang=%s",
        language or "unknown",
        extra={
            "event": "structural_digest.empty_digest",
            "resolved_lang": language or "unknown",
        },
    )
    return {}


def _extract_html(content: str) -> dict:
    """Extract structural metadata from HTML content."""
    # Lazy import: bs4 is in [project.optional-dependencies] worker, so
    # consumers on the planner/lifecycle import chain must not eagerly load it.
    # See cleanup-pass C17 / Q17-FL1.
    try:
        from bs4 import BeautifulSoup
    except ImportError:
        logger.warning(
            "structural_digest: bs4 not installed, skipping HTML digest extraction",
            extra={"event": "structural_digest.bs4_unavailable"},
            exc_info=True,  # auto:exc
        )
        return _empty_digest("html")
    try:
        soup = BeautifulSoup(content, "html.parser")
    except Exception:  # catch-all: untrusted content parsing (BeautifulSoup)
        logger.warning(
            "structural_digest: HTML parse failed, returning empty",
            exc_info=True,
            extra={"event": "structural_digest.html_parse_error"},
        )
        return _empty_digest("html")

    element_ids = []
    for tag in soup.find_all(True, id=True):
        tag_id = tag.get("id", "")
        if tag_id and tag.name not in ("html", "head", "body"):
            element_ids.append(tag_id)

    script_refs = []
    for script in soup.find_all("script", src=True):
        src = script.get("src", "")
        if src:
            script_refs.append(src)

    link_refs = []
    for link in soup.find_all("link", href=True):
        href = link.get("href", "")
        if href:
            link_refs.append(href)

    structural_tags = []
    for tag_name in _STRUCTURAL_TAGS:
        if soup.find(tag_name):
            structural_tags.append(tag_name)

    class_counts: dict[str, int] = {}
    for tag in soup.find_all(True, class_=True):
        for cls in tag.get("class", []):
            class_counts[cls] = class_counts.get(cls, 0) + 1

    inline_funcs = []
    for script in soup.find_all("script"):
        if script.string and not script.get("src"):
            for match in _JS_FUNC_RE.finditer(script.string):
                inline_funcs.append(match.group(1))

    return {
        "element_ids": element_ids,
        "script_refs": script_refs,
        "link_refs": link_refs,
        "css_classes": sorted(class_counts.keys()),
        "structural_tags": sorted(structural_tags),
        "inline_script_functions": inline_funcs,
        "panel_count": class_counts.get("panel", 0),
        "class_counts": class_counts,
    }


def _extract_js(content: str) -> dict:
    """Extract structural metadata from JavaScript content."""
    logger.debug(
        "_extract_js called",
        extra={
            "event": "structural_digest._extract_js",
            "content_len": len(content),
        },
    )
    functions = []
    for match in _JS_FUNC_RE.finditer(content):
        functions.append(match.group(1))
    for match in _JS_ARROW_RE.finditer(content):
        name = match.group(1)
        pos = match.end()
        lookahead = content[pos : pos + 200]
        if "=>" in lookahead.split("\n")[0] or "=>" in lookahead.split(";")[0]:
            functions.append(name)
    for match in _JS_CLASS_RE.finditer(content):
        functions.append(match.group(1))

    dom_refs = []
    for match in _JS_GETBYID_RE.finditer(content):
        dom_refs.append(match.group(1))
    for match in _JS_QUERYSELECTOR_RE.finditer(content):
        dom_refs.append(match.group(1))

    timer_calls = []
    for match in _JS_TIMER_RE.finditer(content):
        timer_calls.append(f"{match.group(1)}({match.group(2)})")

    event_listeners = []
    for match in _JS_LISTENER_RE.finditer(content):
        event_listeners.append(match.group(1))

    fetch_calls = bool(_JS_FETCH_RE.search(content))

    return {
        "syntax_valid": None,  # Set later by code fixer errors or command_returns
        "functions_defined": functions,
        "dom_references": dom_refs,
        "timer_calls": timer_calls,
        "event_listeners": event_listeners,
        "fetch_calls": fetch_calls,
        "code_fixer_errors": [],  # Populated by caller from FixResult
    }


def _extract_python(content: str) -> dict:
    """Extract structural metadata from Python content using stdlib ast."""
    logger.debug(
        "_extract_python called",
        extra={
            "event": "structural_digest._extract_python",
            "content_len": len(content),
        },
    )
    try:
        tree = ast.parse(content)
    except (SyntaxError, MemoryError, RecursionError, ValueError):
        # SyntaxError: invalid code. MemoryError/RecursionError: pathological
        # nesting (Qwen can produce deeply nested structures). ValueError:
        # null bytes or encoding issues. All → syntax_valid=False, empty lists.
        logger.warning(
            "_extract_python: SyntaxError | MemoryError | RecursionError | ValueError",
            exc_info=True,
            extra={
                "event": "structural_digest._extract_python_error",
                "error_category": "parse_error",
            },
        )
        return {
            "syntax_valid": False,
            "functions_defined": [],
            "classes_defined": [],
            "imports": [],
        }

    functions = []
    classes = []
    imports = []

    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            functions.append(node.name)
        elif isinstance(node, ast.ClassDef):
            classes.append(node.name)
        elif isinstance(node, ast.Import):
            for alias in node.names:
                imports.append(alias.name)
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            for alias in node.names:
                imports.append(f"{module}.{alias.name}" if module else alias.name)

    return {
        "syntax_valid": True,
        "functions_defined": functions,
        "classes_defined": classes,
        "imports": imports,
    }


def _extract_css(content: str) -> dict:
    """Extract structural metadata from CSS content."""
    logger.debug(
        "_extract_css called",
        extra={
            "event": "structural_digest._extract_css",
            "content_len": len(content),
        },
    )
    selectors = []
    for match in _CSS_SELECTOR_RE.finditer(content):
        sel = match.group(1).strip()
        if sel and not sel.startswith("@"):
            selectors.append(sel)

    property_count = len(_CSS_PROPERTY_RE.findall(content))
    media_queries = len(_CSS_MEDIA_RE.findall(content))

    return {
        "selectors": selectors,
        "property_count": property_count,
        "media_queries": media_queries,
    }


def _extract_structural_ids(content: str, language: str) -> set[str]:
    """Extract the set of structural identifiers for a given language."""
    logger.debug(
        "_extract_structural_ids called",
        extra={
            "event": "structural_digest._extract_structural_ids",
            "content_len": len(content),
            "language": language,
        },
    )
    if language in ("html", "htm"):
        digest = _extract_html(content)
        ids = set(digest.get("element_ids", []))
        logger.debug(
            "structural_ids: html — %d IDs",
            len(ids),
            extra={
                "event": "structural_digest.extract_ids",
                "lang": "html",
                "id_count": len(ids),
            },
        )
        return ids
    logger.debug(
        "_extract_structural_ids: language_in_passed",
        extra={
            "event": "structural_digest.extract_ids.passed",
            "reason": "language_in_passed",
        },
    )  # auto:neg

    if language in ("javascript", "js", "mjs"):
        digest = _extract_js(content)
        ids = set(digest.get("functions_defined", []))
        logger.debug(
            "structural_ids: js — %d functions",
            len(ids),
            extra={
                "event": "structural_digest.extract_ids",
                "lang": "javascript",
                "id_count": len(ids),
            },
        )
        return ids
    logger.debug(
        "_extract_structural_ids: language_in_passed",
        extra={
            "event": "structural_digest.extract_ids.passed",
            "reason": "language_in_passed",
        },
    )  # auto:neg

    if language in ("python", "py"):
        digest = _extract_python(content)
        funcs = set(digest.get("functions_defined", []))
        classes = set(digest.get("classes_defined", []))
        ids = funcs | classes
        logger.debug(
            "structural_ids: python — %d IDs (%d funcs, %d classes)",
            len(ids),
            len(funcs),
            len(classes),
            extra={
                "event": "structural_digest.extract_ids",
                "lang": "python",
                "id_count": len(ids),
            },
        )
        return ids
    logger.debug(
        "_extract_structural_ids: language_in_passed",
        extra={
            "event": "structural_digest.extract_ids.passed",
            "reason": "language_in_passed",
        },
    )  # auto:neg

    if language == "css":
        digest = _extract_css(content)
        ids = set(digest.get("selectors", []))
        logger.debug(
            "structural_ids: css — %d selectors",
            len(ids),
            extra={
                "event": "structural_digest.extract_ids",
                "lang": "css",
                "id_count": len(ids),
            },
        )
        return ids

    logger.debug(
        "structural_ids: unsupported language %s",
        language or "unknown",
        extra={
            "event": "structural_digest.extract_ids_unsupported",
            "lang": language or "unknown",
        },
    )
    return set()
