#!/usr/bin/env python3
"""G2: Debugging & Error Recovery Functional Test Suite.

Multi-turn test runner that sends prompts designed to produce errors,
then measures the system's ability to diagnose and fix them using
F1 metadata alone (without breaking the privacy boundary).

Key difference from G1: maintains conversation context across turns via
the same `source` parameter, so the planner sees F1 enriched history
from all previous turns when deciding how to fix errors.

Categories:
  A — Syntax error debugging (4 prompts, errors deterministic/high-probability)
  B — Build failure debugging (3 prompts, multi-file integration errors)
  C — Iterative refinement (3 prompts, pre-seeded buggy files, user-driven)

Usage:
    python3 scripts/functional_test_debug.py [OPTIONS]

    --version VERSION    Version tag for JSONL header (default: dev)
    --trials N           Trials for Category A prompts (B/C always 1) (default: 3)
    --category A|B|C     Run only one category (default: all)
    --base-url URL       Sentinel API URL (default: https://localhost:3001)
    --output PATH        JSONL output path (default: auto-generated in benchmarks/)
    --max-turns N        Max turns per scenario before declaring spiral (default: 8)
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import re
import shlex
import signal
import ssl
import subprocess
import sys
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_BASE_URL = "https://localhost:3001"
MAX_RETRIES = 2
RETRY_BACKOFF_BASE = 15  # seconds — 15, 30
API_TIMEOUT = 1800  # 30 min per API call (multi-turn debug: Qwen generation is slow)
VERIFY_TIMEOUT = 120  # 2 min per verification command
CLEANUP_TIMEOUT = 30
HEALTH_TIMEOUT = 120  # 2 min health wait
MAX_TURNS_DEFAULT = 8
PREVIEW_LEN = 150

_SSL_CTX = ssl.create_default_context()
_SSL_CTX.check_hostname = False
_SSL_CTX.verify_mode = ssl.CERT_NONE

PIN_PATH = Path.home() / ".secrets" / "sentinel_pin.txt"

# ---------------------------------------------------------------------------
# Category C seed files — pre-seeded buggy code placed in /workspace/
# ---------------------------------------------------------------------------

SEED_FILES: dict[str, dict[str, str]] = {
    "debug_c1_wrong_output": {
        "/workspace/sort_employees.py": '''\
"""Sort employees by salary (descending), breaking ties by name (alphabetical)."""


def sort_employees(employees):
    # Bug 1: sorts ascending instead of descending
    # Bug 2: doesn't break ties by name
    return sorted(employees, key=lambda e: e["salary"])


def main():
    employees = [
        {"name": "Charlie", "salary": 75000, "department": "Engineering"},
        {"name": "Alice", "salary": 92000, "department": "Marketing"},
        {"name": "Eve", "salary": 75000, "department": "Engineering"},
        {"name": "Bob", "salary": 92000, "department": "Sales"},
        {"name": "Diana", "salary": 88000, "department": "Engineering"},
    ]

    result = sort_employees(employees)
    for emp in result:
        print(f"{emp['name']:10s} ${emp['salary']:>8,}  {emp['department']}")


if __name__ == "__main__":
    main()
''',
    },
    "debug_c2_test_driven": {
        "/workspace/text_utils.py": '''\
"""Text utility functions."""


def word_count(text):
    """Count words in text. Empty string returns 0."""
    # Bug: doesn't handle multiple spaces or leading/trailing whitespace
    return len(text.split(" "))


def truncate(text, max_length, suffix="..."):
    """Truncate text to max_length including suffix."""
    # Bug: doesn't account for suffix length in the total
    if len(text) > max_length:
        return text[:max_length] + suffix
    return text


def title_case(text):
    """Title case: capitalise words except small words (a, an, the, of, in, on,
    at, to, for) — but always capitalise the first word."""
    # Bug: doesn't capitalise the first word if it's a small word
    words = text.split()
    small_words = {"a", "an", "the", "of", "in", "on", "at", "to", "for"}
    return " ".join(
        w if w.lower() in small_words else w.capitalize()
        for w in words
    )


def extract_emails(text):
    """Extract all email addresses from text."""
    import re
    # Bug: overly simple regex — misses dots/hyphens in local part
    return re.findall(r'[a-zA-Z]+@[a-zA-Z]+\\.[a-zA-Z]+', text)
''',
    },
    "debug_c3_progressive_features": {
        "/workspace/inventory.py": '''\
"""Simple inventory management system."""


class Inventory:
    def __init__(self):
        self.items = {}

    def add_item(self, name, quantity, price):
        """Add item or increase quantity if exists."""
        if name in self.items:
            self.items[name]["quantity"] += quantity
        else:
            self.items[name] = {"quantity": quantity, "price": price}

    def get_total_value(self):
        """Calculate total inventory value."""
        return sum(
            item["quantity"] * item["price"] for item in self.items.values()
        )

    def __str__(self):
        lines = ["Inventory:"]
        for name, info in self.items.items():
            lines.append(f"  {name}: {info['quantity']} @ ${info['price']:.2f}")
        lines.append(f"Total value: ${self.get_total_value():.2f}")
        return "\\n".join(lines)
''',
    },
}

# ---------------------------------------------------------------------------
# Debug prompts — 10 total (4A + 3B + 3C)
# ---------------------------------------------------------------------------

DEBUG_PROMPTS: list[dict] = [
    # -----------------------------------------------------------------------
    # Category A: Syntax Error Debugging
    # Errors are deterministic or high-probability. stderr contains the answer.
    # Should resolve in ≤3 turns.
    # -----------------------------------------------------------------------
    {
        "prompt_id": "debug_a1_missing_import",
        "category": "A",
        "initial_prompt": (
            "Write a Python script that uses the `requests` library to fetch "
            "https://example.com and print the HTTP status code. Save it to "
            "`/workspace/fetch.py` and then run it with "
            "`python3 /workspace/fetch.py`."
        ),
        "verification_command": "cd /workspace && python3 fetch.py",
        "expected_outcome": (
            "Script runs successfully after switching to urllib.request "
            "or handling the missing module"
        ),
        "max_turns": 5,
        "debug_followup": (
            "The previous task failed. Please diagnose the error and fix "
            "the script so it runs successfully."
        ),
        "error_indicators": [
            "requests", "ModuleNotFoundError", "no module", "urllib",
            "import error", "not installed",
        ],
        "stderr_indicators": [
            "ModuleNotFoundError", "requests", "No module named",
        ],
    },
    {
        "prompt_id": "debug_a2_complex_syntax",
        "category": "A",
        "initial_prompt": (
            "Write a single Python file at `/workspace/advanced.py` that "
            "demonstrates ALL of these advanced features in working code:\n"
            "1. A decorator factory that takes arguments and caches results\n"
            "2. A context manager class with `__enter__` and `__exit__`\n"
            "3. Nested list comprehensions with conditional filtering\n"
            "4. A dataclass with `__post_init__` validation\n"
            "5. A generator function that yields from a recursive structure\n"
            "Include a `main()` function that exercises every feature and "
            "prints results. Then run `python3 /workspace/advanced.py`."
        ),
        "verification_command": "cd /workspace && python3 advanced.py",
        "expected_outcome": (
            "Script runs successfully, demonstrating all features without "
            "syntax errors"
        ),
        "max_turns": 5,
        "debug_followup": (
            "The previous task failed. Please diagnose the error and fix "
            "the script so it runs successfully."
        ),
        "error_indicators": [
            "SyntaxError", "IndentationError", "NameError",
            "syntax", "indent", "undefined",
        ],
        "stderr_indicators": [
            "SyntaxError", "line", "IndentationError", "NameError",
        ],
    },
    {
        "prompt_id": "debug_a3_wrong_path",
        "category": "A",
        "initial_prompt": (
            "Create a Python module at `/workspace/src/utils/helpers.py` with "
            "a function `format_date(date_string)` that parses ISO 8601 date "
            "strings (like '2024-01-15') and returns formatted strings like "
            "'January 15, 2024'. Also create the necessary `__init__.py` files "
            "for the package structure. Then test it by running:\n"
            "`python3 -c \"from helpers import format_date; "
            "print(format_date('2024-01-15'))\"`"
        ),
        "verification_command": (
            "cd /workspace && python3 -c \""
            "import sys; sys.path.insert(0, 'src/utils'); "
            "from helpers import format_date; "
            "result = format_date('2024-01-15'); "
            "assert 'January' in result or 'Jan' in result, f'Unexpected: {result}'; "
            "print(result)\""
        ),
        "expected_outcome": (
            "Planner corrects the import path using session files context "
            "showing the actual file location"
        ),
        "max_turns": 5,
        "debug_followup": (
            "The previous task failed. Please diagnose the error and fix "
            "the import so the function can be used successfully."
        ),
        "error_indicators": [
            "ModuleNotFoundError", "FileNotFoundError", "path",
            "import", "src/utils", "sys.path", "PYTHONPATH",
        ],
        "stderr_indicators": [
            "ModuleNotFoundError", "No module named", "FileNotFoundError",
        ],
    },
    {
        "prompt_id": "debug_a4_type_error",
        "category": "A",
        "initial_prompt": (
            "Write a Python script at `/workspace/stats.py` that reads "
            "`/workspace/measurements.txt` (one value per line) and computes "
            "the mean and standard deviation. First create the measurements "
            "file with these values, one per line:\n"
            "23.5\n18.2\nN/A\n31.0\n27.8\nERROR\n19.4\n"
            "Then run `python3 /workspace/stats.py`."
        ),
        "verification_command": (
            "cd /workspace && python3 stats.py"
        ),
        "expected_outcome": (
            "Script handles non-numeric values gracefully (skip or report) "
            "and computes stats on valid numbers"
        ),
        "max_turns": 5,
        "debug_followup": (
            "The previous task failed. Please diagnose the error and fix "
            "the script so it handles all input values correctly."
        ),
        "error_indicators": [
            "ValueError", "float", "convert", "N/A", "ERROR",
            "invalid literal", "non-numeric", "skip", "filter",
        ],
        "stderr_indicators": [
            "ValueError", "could not convert", "invalid literal",
        ],
    },
    # -----------------------------------------------------------------------
    # Category B: Build Failure Debugging
    # Harder errors: multi-file integration, environment, tool chains.
    # stderr may not contain the full answer; needs reasoning.
    # Should resolve in ≤5 turns.
    # -----------------------------------------------------------------------
    {
        "prompt_id": "debug_b1_multi_module",
        "category": "B",
        "initial_prompt": (
            "Create a Python data processing pipeline at `/workspace/pipeline/`:\n"
            "- `models.py`: Define `DataPoint` (name: str, value: float, "
            "category: str) and `Dataset` (points: list of DataPoint) dataclasses\n"
            "- `loader.py`: A `load_csv(filepath)` function that reads CSV "
            "into a Dataset\n"
            "- `transform.py`: `normalize(dataset)` scales values 0-1, "
            "`filter_by_category(dataset, cat)` filters, "
            "`aggregate(dataset)` returns per-category averages\n"
            "- `reporter.py`: `generate_report(dataset, aggregated)` returns "
            "a formatted text summary\n"
            "- `main.py`: Wire everything — load, normalize, aggregate, report\n\n"
            "Create `/workspace/sample.csv` with this content:\n"
            "name,value,category\n"
            "Alpha,85.2,A\nBeta,92.1,B\nGamma,78.5,A\n"
            "Delta,88.9,B\nEpsilon,95.3,A\nZeta,71.4,B\n"
            "Eta,83.7,A\nTheta,90.0,B\nIota,76.2,A\nKappa,87.6,B\n\n"
            "Run `python3 /workspace/pipeline/main.py /workspace/sample.csv`."
        ),
        "verification_command": (
            "cd /workspace && python3 pipeline/main.py sample.csv"
        ),
        "expected_outcome": (
            "Pipeline runs end-to-end: loads CSV, normalizes, aggregates, "
            "prints report"
        ),
        "max_turns": 6,
        "debug_followup": (
            "The previous task failed. Please diagnose the error and fix "
            "the pipeline so it runs end-to-end."
        ),
        "error_indicators": [
            "ImportError", "ModuleNotFoundError", "AttributeError",
            "TypeError", "relative import", "__init__",
            "csv", "dataclass", "argument",
        ],
        "stderr_indicators": [
            "ImportError", "ModuleNotFoundError", "AttributeError",
            "TypeError", "Traceback",
        ],
    },
    {
        "prompt_id": "debug_b2_test_runner",
        "category": "B",
        "initial_prompt": (
            "Create a Python math library at `/workspace/mathlib/`:\n"
            "- `mathlib/__init__.py`: Package init with `__version__ = '0.1.0'`\n"
            "- `mathlib/core.py`: Functions `fibonacci(n)`, `is_prime(n)`, "
            "`gcd(a, b)`, `lcm(a, b)`\n"
            "- `mathlib/stats.py`: Functions `mean(values)`, `median(values)`, "
            "`mode(values)`, `stddev(values)` — stdlib only, no numpy\n"
            "- `tests/test_core.py`: Unit tests using `unittest` for all "
            "core functions (at least 3 tests each)\n"
            "- `tests/test_stats.py`: Unit tests using `unittest` for all "
            "stats functions (at least 3 tests each)\n"
            "- `run_tests.sh`: Shell script that runs all tests via "
            "`python3 -m unittest discover -s tests -v`\n\n"
            "Run `bash /workspace/mathlib/run_tests.sh`."
        ),
        "verification_command": (
            "cd /workspace/mathlib && "
            "python3 -m unittest discover -s tests -v 2>&1 | "
            "tail -1 | grep -q 'OK'"
        ),
        "expected_outcome": (
            "All unit tests pass — correct implementations and proper "
            "package imports from test files"
        ),
        "max_turns": 6,
        "debug_followup": (
            "The previous task failed. Please diagnose the test failures "
            "and fix the code so all tests pass."
        ),
        "error_indicators": [
            "FAILED", "ERROR", "ImportError", "AssertionError",
            "ModuleNotFoundError", "unittest", "test",
        ],
        "stderr_indicators": [
            "FAILED", "ERROR", "Traceback", "AssertionError",
        ],
    },
    {
        "prompt_id": "debug_b3_config_app",
        "category": "B",
        "initial_prompt": (
            "Create a Python task manager at `/workspace/taskmanager/`:\n"
            "- `config.py`: Load settings from "
            "`/workspace/taskmanager/config.json` "
            "(db_path, max_tasks, log_level)\n"
            "- `database.py`: SQLite-backed storage with `create_task(title)`, "
            "`list_tasks()`, `complete_task(task_id)`, `delete_task(task_id)`\n"
            "- `cli.py`: argparse CLI with subcommands: add, list, complete, "
            "delete\n"
            "- `main.py`: Entry point — init config, init database, dispatch CLI\n"
            "- `config.json`: Default config with "
            "`db_path=/workspace/tasks.db`\n\n"
            "Run `python3 /workspace/taskmanager/main.py add 'Buy groceries' "
            "&& python3 /workspace/taskmanager/main.py list`."
        ),
        "verification_command": (
            "cd /workspace && "
            "python3 taskmanager/main.py add 'Test task' && "
            "python3 taskmanager/main.py list | grep -q 'Test task'"
        ),
        "expected_outcome": (
            "Task manager creates and lists tasks successfully with "
            "SQLite persistence"
        ),
        "max_turns": 6,
        "debug_followup": (
            "The previous task failed. Please diagnose the error and fix "
            "the application so it can add and list tasks."
        ),
        "error_indicators": [
            "FileNotFoundError", "json", "config", "sqlite",
            "argparse", "ImportError", "KeyError",
        ],
        "stderr_indicators": [
            "FileNotFoundError", "KeyError", "json.decoder",
            "sqlite3", "Traceback",
        ],
        "known_limitation": "Sandbox has network_disabled + read_only_rootfs — pip install cannot work",
    },
    # -----------------------------------------------------------------------
    # Category C: Multi-Turn Iterative Refinement
    # Pre-seeded buggy files. User-directed follow-ups.
    # Tests context retention and progressive improvement.
    # -----------------------------------------------------------------------
    {
        "prompt_id": "debug_c1_wrong_output",
        "category": "C",
        "initial_prompt": (
            "The script at `/workspace/sort_employees.py` should sort "
            "employees by salary in descending order (highest first). "
            "Run it with `python3 /workspace/sort_employees.py` and check: "
            "the output should show Alice and Bob (at $92,000) before Diana "
            "(at $88,000), and Diana before Charlie and Eve (at $75,000). "
            "Fix the sorting if it's wrong."
        ),
        "verification_command": (
            "cd /workspace && python3 -c \"\n"
            "exec(open('sort_employees.py').read())\n"
            "result = sort_employees([\n"
            "    {'name': 'Charlie', 'salary': 75000, 'department': 'Eng'},\n"
            "    {'name': 'Alice', 'salary': 92000, 'department': 'Mkt'},\n"
            "    {'name': 'Eve', 'salary': 75000, 'department': 'Eng'},\n"
            "    {'name': 'Bob', 'salary': 92000, 'department': 'Sales'},\n"
            "    {'name': 'Diana', 'salary': 88000, 'department': 'Eng'},\n"
            "])\n"
            "names = [e['name'] for e in result]\n"
            "# Check descending salary order\n"
            "salaries = [e['salary'] for e in result]\n"
            "assert salaries == sorted(salaries, reverse=True), "
            "f'Not descending: {salaries}'\n"
            "# Check alphabetical tiebreak\n"
            "assert names.index('Alice') < names.index('Bob'), "
            "'Alice should come before Bob'\n"
            "assert names.index('Charlie') < names.index('Eve'), "
            "'Charlie should come before Eve'\n"
            "print('All checks passed:', names)\n"
            "\""
        ),
        "expected_outcome": (
            "Employees sorted descending by salary with alphabetical "
            "tiebreaking"
        ),
        "max_turns": 4,
        "followup_prompts": [
            (
                "The salary sorting is better now, but employees with the same "
                "salary should be sorted alphabetically by name. Alice should "
                "appear before Bob (both at $92,000), and Charlie before Eve "
                "(both at $75,000). Please fix the tiebreaking."
            ),
            (
                "Please verify the sorting works correctly by running the "
                "script and checking the output order."
            ),
        ],
        "error_indicators": [
            "sort", "descending", "reverse", "key", "lambda",
            "tiebreak", "alphabetical",
        ],
        "stderr_indicators": [],
    },
    {
        "prompt_id": "debug_c2_test_driven",
        "category": "C",
        "initial_prompt": (
            "Write comprehensive tests for `/workspace/text_utils.py` at "
            "`/workspace/test_text_utils.py` using Python's `unittest` module. "
            "Test edge cases: empty strings, multiple consecutive spaces, "
            "leading/trailing whitespace, punctuation-only strings, and "
            "Unicode text. Run the tests with:\n"
            "`cd /workspace && python3 -m unittest test_text_utils -v`"
        ),
        "verification_command": (
            "cd /workspace && python3 -m unittest test_text_utils -v 2>&1 | "
            "tail -1 | grep -q 'OK'"
        ),
        "expected_outcome": (
            "All tests pass after fixing bugs in text_utils.py"
        ),
        "max_turns": 5,
        "followup_prompts": [
            (
                "Some tests failed because the functions in `text_utils.py` "
                "have bugs. Please fix the functions so all tests pass. "
                "Do NOT modify the tests — only fix the implementation."
            ),
            (
                "There are still some failing tests. Please continue fixing "
                "`text_utils.py` and run the tests again."
            ),
            (
                "Please run the tests one more time to verify everything "
                "passes."
            ),
        ],
        "error_indicators": [
            "FAILED", "AssertionError", "word_count", "truncate",
            "title_case", "extract_emails", "bug", "fix",
        ],
        "stderr_indicators": [
            "FAILED", "AssertionError", "Traceback",
        ],
    },
    {
        "prompt_id": "debug_c3_progressive_features",
        "category": "C",
        "initial_prompt": (
            "There's an Inventory class at `/workspace/inventory.py`. Add "
            "these features:\n"
            "1. `remove_item(name, quantity)` — reduce quantity; raise "
            "ValueError if insufficient stock or item not found\n"
            "2. `search(query)` — return items whose names contain the query "
            "(case-insensitive)\n"
            "3. `save_to_json(filepath)` and `load_from_json(filepath)` for "
            "persistence\n\n"
            "Write a test script at `/workspace/test_inventory.py` that "
            "exercises all existing and new methods (use `assert` statements, "
            "not unittest). Run it with `python3 /workspace/test_inventory.py`."
        ),
        "verification_command": (
            "cd /workspace && python3 test_inventory.py"
        ),
        "expected_outcome": (
            "Inventory class has all requested features and tests pass"
        ),
        "max_turns": 6,
        "followup_prompts": [
            (
                "Now add a `restock_report()` method that returns a list of "
                "item names with quantity below a configurable threshold "
                "(default 5). Also add `apply_discount(name, percent)` that "
                "reduces an item's price by the given percentage. Update the "
                "test script to cover these new methods and run it."
            ),
            (
                "Add modification history tracking: the Inventory should "
                "record each operation (add, remove, discount) with a "
                "timestamp. Add `get_history(item_name=None)` that returns "
                "history, optionally filtered by item name. Update the tests "
                "and run them."
            ),
            (
                "Please run the full test script one more time to verify "
                "everything works together."
            ),
        ],
        "error_indicators": [
            "Inventory", "remove_item", "search", "save", "load",
            "json", "ValueError", "test",
        ],
        "stderr_indicators": [
            "AssertionError", "AttributeError", "NameError", "Traceback",
        ],
    },
]


# ---------------------------------------------------------------------------
# Privacy boundary violation patterns — if the planner's plan_summary
# contains these, the planner is requesting information it shouldn't have
# ---------------------------------------------------------------------------

_PRIVACY_VIOLATION_PATTERNS = [
    r"(?i)show me (?:the|what) (?:worker|qwen|model) (?:produced|output|generated)",
    r"(?i)(?:can you |please )?(?:share|provide) the (?:raw|actual|full) (?:output|response|code)",
    r"(?i)what did (?:the worker|qwen|the model) (?:return|produce|generate|write)",
    r"(?i)i need to see the (?:actual|raw|worker|generated) (?:output|response|code)",
    r"(?i)paste (?:the|what) (?:was generated|the output)",
]
_PRIVACY_VIOLATION_RES = [re.compile(p) for p in _PRIVACY_VIOLATION_PATTERNS]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _read_pin() -> str:
    """Read Sentinel PIN from secrets file."""
    try:
        return PIN_PATH.read_text().strip()
    except FileNotFoundError:
        print(f"ERROR: PIN file not found at {PIN_PATH}", file=sys.stderr)
        sys.exit(1)


def check_health(base_url: str, timeout: int = 10) -> bool:
    """Check if Sentinel controller is healthy."""
    try:
        req = urllib.request.Request(f"{base_url}/health")
        with urllib.request.urlopen(req, timeout=timeout, context=_SSL_CTX) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            return data.get("status") == "ok"
    except Exception:
        return False


def exec_in_container(command: str, timeout: int = VERIFY_TIMEOUT) -> tuple[int, str, str]:
    """Run a command inside the sentinel container via podman exec."""
    try:
        result = subprocess.run(
            ["podman", "exec", "sentinel", "bash", "-c", command],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return 124, "", f"Command timed out after {timeout}s"
    except Exception as exc:
        return 1, "", str(exc)


def exec_in_sandbox(command: str, timeout: int = VERIFY_TIMEOUT) -> tuple[int, str, str]:
    """Run a command in a disposable sandbox container matching Sentinel's sandbox.

    Uses the same image, volume, uid (nobody/65534), and security settings as
    Sentinel's PodmanSandbox.run() so that verification runs in an identical
    environment to the code execution.  This avoids cross-container uid
    namespace issues where files created by the sandbox can't be overwritten
    by the sentinel container's root user (rootless Podman maps them to
    different host uids).
    """
    try:
        result = subprocess.run(
            [
                "podman", "run", "--rm",
                "-v", "sentinel_sentinel-workspace:/workspace:rw",
                "--read-only",
                "--tmpfs", "/tmp:size=100M",
                "-w", "/workspace",
                "--cap-drop", "ALL",
                "--cap-add", "CAP_SETUID",
                "--cap-add", "CAP_SETGID",
                "--security-opt", "no-new-privileges",
                "--network", "none",
                "sentinel-sandbox:latest",
                "sh", "-c",
                # Match sandbox.py: chmod workspace, drop to nobody, run command
                f"chmod 1777 /workspace 2>/dev/null; "
                f"exec setpriv --reuid=65534 --regid=65534 --clear-groups "
                f"sh -c {shlex.quote(command)}",
            ],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return 124, "", f"Command timed out after {timeout}s"
    except Exception as exc:
        return 1, "", str(exc)


def cleanup_workspace() -> None:
    """Remove all files in /workspace/ inside the container."""
    exec_in_container(
        "find /workspace -mindepth 1 -delete 2>/dev/null; echo done",
        timeout=CLEANUP_TIMEOUT,
    )


def seed_files(files: dict[str, str]) -> None:
    """Write pre-seeded files into /workspace/ inside the container."""
    for path, content in files.items():
        # Ensure parent directory exists
        parent = str(Path(path).parent)
        exec_in_container(f"mkdir -p {parent}", timeout=10)
        # Write via base64 to avoid heredoc delimiter collisions
        b64 = base64.b64encode(content.encode("utf-8")).decode("ascii")
        exec_in_container(
            f"echo '{b64}' | base64 -d > {path}",
            timeout=10,
        )


def post_task(
    base_url: str, pin: str, request_text: str, source: str
) -> tuple[dict | None, int]:
    """POST a task to the Sentinel API. Returns (response_dict, http_status)."""
    url = f"{base_url}/api/task"
    body = json.dumps({"request": request_text, "source": source}).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=body,
        headers={
            "Content-Type": "application/json",
            "X-Sentinel-Pin": pin,
            "Origin": base_url,
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=API_TIMEOUT, context=_SSL_CTX) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            return data, resp.status
    except urllib.error.HTTPError as exc:
        try:
            err_body = json.loads(exc.read().decode("utf-8"))
        except Exception:
            err_body = {"error": str(exc)}
        return err_body, exc.code
    except Exception as exc:
        return {"error": str(exc)}, 0


# ---------------------------------------------------------------------------
# Main test class
# ---------------------------------------------------------------------------

class DebugCapabilityTest:
    """Multi-turn debugging test runner for G2 functional tests."""

    def __init__(
        self,
        base_url: str,
        pin: str,
        version: str,
        trials: int,
        categories: list[str] | None,
        max_turns: int,
        output_path: Path,
    ):
        self.base_url = base_url
        self.pin = pin
        self.version = version
        self.trials = trials
        self.categories = categories  # None = all
        self.max_turns = max_turns
        self.output_path = output_path
        self.stop_requested = False

        # Stats for summary
        self._results: list[dict] = []

    # -- Signal handling ----------------------------------------------------

    def _setup_signals(self) -> None:
        def handler(signum, _frame):
            name = signal.Signals(signum).name
            print(f"\n  Signal {name} received. Finishing current scenario...")
            self.stop_requested = True
        signal.signal(signal.SIGINT, handler)
        signal.signal(signal.SIGTERM, handler)

    # -- Health check -------------------------------------------------------

    def _wait_for_health(self, max_wait: int = HEALTH_TIMEOUT) -> bool:
        start = time.monotonic()
        while time.monotonic() - start < max_wait:
            if check_health(self.base_url):
                return True
            time.sleep(5)
        return False

    # -- Queue building -----------------------------------------------------

    def _build_queue(self) -> list[dict]:
        """Build execution queue from prompt definitions with trial expansion."""
        prompts = DEBUG_PROMPTS
        if self.categories:
            prompts = [p for p in prompts if p["category"] in self.categories]

        queue = []
        for prompt_def in prompts:
            cat = prompt_def["category"]
            # Category A gets N trials, B/C get 1 trial
            num_trials = self.trials if cat == "A" else 1
            for trial in range(1, num_trials + 1):
                entry = dict(prompt_def)
                entry["trial"] = trial
                entry["total_trials"] = num_trials
                # Use per-prompt max_turns or global default
                if entry.get("max_turns") is None:
                    entry["max_turns"] = self.max_turns
                queue.append(entry)
        return queue

    # -- JSONL output -------------------------------------------------------

    def _open_output(self) -> None:
        self.output_path.parent.mkdir(parents=True, exist_ok=True)
        self._outfile = open(self.output_path, "a")

    def _write_line(self, obj: dict) -> None:
        self._outfile.write(json.dumps(obj, default=str) + "\n")
        self._outfile.flush()
        os.fsync(self._outfile.fileno())

    def _write_header(self, queue: list[dict]) -> None:
        unique_ids = {item["prompt_id"] for item in queue}
        cats_in_queue = sorted({item["category"] for item in queue})
        trials_per_cat = {}
        for item in queue:
            cat = item["category"]
            trials_per_cat[cat] = item["total_trials"]

        self._write_line({
            "type": "header",
            "started_at": datetime.now(timezone.utc).isoformat(),
            "version": self.version,
            "base_url": self.base_url,
            "test_suite": "debugging",
            "total_prompts": len(queue),
            "unique_prompts": len(unique_ids),
            "categories": cats_in_queue,
            "trials_per_category": trials_per_cat,
            "max_turns": self.max_turns,
        })

    def _write_summary(self) -> None:
        results = self._results
        by_cat: dict[str, dict] = {}
        total_converged = 0
        total_cycles = []

        for r in results:
            cat = r.get("category", "?")
            if cat not in by_cat:
                by_cat[cat] = {
                    "total": 0, "converged": 0, "not_converged": 0,
                    "api_errors": 0, "fix_cycles": [],
                }
            by_cat[cat]["total"] += 1
            if r.get("convergence"):
                by_cat[cat]["converged"] += 1
                total_converged += 1
            elif r.get("error"):
                by_cat[cat]["api_errors"] += 1
            else:
                by_cat[cat]["not_converged"] += 1
            if r.get("fix_cycle_count"):
                by_cat[cat]["fix_cycles"].append(r["fix_cycle_count"])
                total_cycles.append(r["fix_cycle_count"])

        total_api_errors = sum(
            1 for cat_stats in by_cat.values()
            for _ in range(cat_stats["api_errors"])
        )
        self._write_line({
            "type": "summary",
            "total": len(results),
            "converged": total_converged,
            "not_converged": len(results) - total_converged - total_api_errors,
            "api_errors": total_api_errors,
            "mean_fix_cycles": (
                round(sum(total_cycles) / len(total_cycles), 1)
                if total_cycles else None
            ),
            "total_elapsed": round(
                sum(r.get("elapsed_s", 0) for r in results), 1
            ),
            "by_category": {
                cat: {
                    **{k: v for k, v in stats.items() if k != "fix_cycles"},
                    "mean_fix_cycles": (
                        round(sum(stats["fix_cycles"]) / len(stats["fix_cycles"]), 1)
                        if stats["fix_cycles"] else None
                    ),
                }
                for cat, stats in by_cat.items()
            },
        })

    # -- Single API turn ----------------------------------------------------

    def _execute_turn(
        self, prompt_text: str, source: str, turn_num: int
    ) -> dict:
        """Execute a single API turn with retry logic."""
        turn_result: dict = {
            "turn": turn_num,
            "prompt": prompt_text,
            "prompt_preview": prompt_text[:PREVIEW_LEN],
            "http_status": 0,
            "response_status": None,
            "plan_summary": None,
            "plan_steps": 0,
            "step_outcomes": [],
            "steps": [],
            "planner_usage": {},
            "elapsed_s": 0,
        }

        for attempt in range(MAX_RETRIES):
            start = time.monotonic()
            resp, http_status = post_task(
                self.base_url, self.pin, prompt_text, source
            )
            elapsed = time.monotonic() - start

            if http_status > 0:
                # Got a response (success or HTTP error)
                turn_result["http_status"] = http_status
                turn_result["elapsed_s"] = round(elapsed, 1)

                if resp:
                    turn_result["response_status"] = resp.get("status")
                    turn_result["plan_summary"] = resp.get("plan_summary")
                    turn_result["reason"] = resp.get("reason")
                    turn_result["error"] = resp.get("error")

                    steps = resp.get("step_results") or []
                    turn_result["plan_steps"] = len(steps)
                    turn_result["steps"] = [
                        {
                            "step_id": s.get("step_id", ""),
                            "status": s.get("status"),
                            "error": s.get("error"),
                            "quality_warnings": s.get("quality_warnings", []),
                            "worker_usage": s.get("worker_usage"),
                        }
                        for s in steps
                    ]
                    turn_result["step_outcomes"] = resp.get("step_outcomes") or []
                    turn_result["planner_usage"] = resp.get("planner_usage") or {}
                break
            else:
                # Connection error — retry with backoff
                if attempt < MAX_RETRIES - 1:
                    wait = RETRY_BACKOFF_BASE * (2 ** attempt)
                    print(f"    Connection error (attempt {attempt + 1}). "
                          f"Retrying in {wait}s...")
                    time.sleep(wait)
                    if not self._wait_for_health(max_wait=60):
                        print("    Health check failed. Aborting retries.")
                        turn_result["error"] = "Health check failed after retry"
                        break
                else:
                    turn_result["error"] = resp.get("error", "Connection failed")

        return turn_result

    # -- Verification -------------------------------------------------------

    def _verify(self, item: dict) -> dict:
        """Run verification command in a disposable sandbox container.

        Uses exec_in_sandbox so verification runs with the same uid (nobody)
        and environment as Sentinel's sandbox — avoids cross-container uid
        mapping issues with rootless Podman on the shared workspace volume.
        """
        v_cmd = item["verification_command"]
        exit_code, stdout, stderr = exec_in_sandbox(v_cmd, timeout=VERIFY_TIMEOUT)

        passed = exit_code == 0
        return {
            "verification_exit_code": exit_code,
            "verification_passed": passed,
            "verification_output": stdout[:2000] if stdout else "",
            "verification_error": stderr[:500] if stderr and not passed else "",
        }

    # -- Heuristic checks ---------------------------------------------------

    def _check_diagnosis(self, turns: list[dict], item: dict) -> bool | None:
        """Check if the planner correctly identified the root cause.

        Returns True if plan_summary of a fix turn references the actual error,
        False if it doesn't, None if no diagnosis was needed (first turn succeeded).
        """
        if len(turns) <= 1:
            # First turn only — either succeeded or no fix attempt yet
            if turns and turns[0].get("verification_passed"):
                return None  # No diagnosis needed
            return None  # Can't assess from a single turn

        indicators = item.get("error_indicators", [])
        if not indicators:
            return None  # No indicators defined

        # Check plan_summary of fix turns (turn 2+) for error indicators
        for turn in turns[1:]:
            summary = (turn.get("plan_summary") or "").lower()
            for indicator in indicators:
                if indicator.lower() in summary:
                    return True
        return False

    def _check_stderr_usage(self, turns: list[dict], item: dict) -> bool | None:
        """Check if the planner used stderr info in its diagnosis.

        Returns True if plan_summary references stderr content, False if not,
        None if no debugging occurred.
        """
        if len(turns) <= 1:
            return None

        indicators = item.get("stderr_indicators", [])
        if not indicators:
            return None

        for turn in turns[1:]:
            summary = (turn.get("plan_summary") or "").lower()
            for indicator in indicators:
                if indicator.lower() in summary:
                    return True
        return False

    def _check_privacy_boundary(self, turns: list[dict]) -> bool:
        """Check that the planner never requested raw Qwen output.

        Returns True if privacy boundary held, False if violated.
        """
        for turn in turns:
            summary = turn.get("plan_summary") or ""
            for pattern in _PRIVACY_VIOLATION_RES:
                if pattern.search(summary):
                    return False
        return True

    # -- Main scenario runner -----------------------------------------------

    def _run_debug_scenario(self, index: int, item: dict) -> dict:
        """Run a complete multi-turn debugging scenario."""
        prompt_id = item["prompt_id"]
        category = item["category"]
        trial = item["trial"]
        max_t = item["max_turns"]

        print(f"\n  [{index + 1}] {prompt_id} (Cat {category}, "
              f"trial {trial}/{item['total_trials']})")

        start = time.monotonic()
        source = f"debug_{prompt_id}_t{trial}_{int(time.time())}"

        # Clean workspace
        print("    Cleaning workspace...")
        cleanup_workspace()

        # Seed files for Category C
        seed = SEED_FILES.get(prompt_id)
        if seed:
            print(f"    Seeding {len(seed)} file(s)...")
            seed_files(seed)

        turns: list[dict] = []
        current_prompt = item["initial_prompt"]
        verification_passed = False
        fix_cycle_count = 0

        for turn_num in range(1, max_t + 1):
            label = "Initial" if turn_num == 1 else f"Fix #{fix_cycle_count}"
            print(f"    Turn {turn_num}/{max_t} ({label}): "
                  f"sending {len(current_prompt)} chars...")

            # Send prompt to API
            turn_result = self._execute_turn(current_prompt, source, turn_num)

            # Run verification regardless of API status (might have partial work)
            status = turn_result.get("response_status")
            if status in ("success", "blocked"):
                print(f"    Turn {turn_num}: API {status}. Verifying...")
                v_result = self._verify(item)
                turn_result.update(v_result)

                if v_result["verification_passed"]:
                    print(f"    Turn {turn_num}: VERIFICATION PASSED")
                    verification_passed = True
                    turns.append(turn_result)
                    break
                else:
                    v_err = v_result.get("verification_error", "")[:100]
                    print(f"    Turn {turn_num}: verification failed "
                          f"(exit {v_result['verification_exit_code']})"
                          f"{': ' + v_err if v_err else ''}")
            elif status == "error" or turn_result.get("error"):
                err = (turn_result.get("error") or "unknown")[:100]
                print(f"    Turn {turn_num}: API error: {err}")
                turn_result["verification_passed"] = None
                turn_result["verification_exit_code"] = None
            else:
                print(f"    Turn {turn_num}: status={status}")
                turn_result["verification_passed"] = None
                turn_result["verification_exit_code"] = None

            turns.append(turn_result)
            fix_cycle_count += 1  # Count each non-passing turn as a fix cycle

            # Determine next prompt
            if turn_num >= max_t:
                break  # Budget exhausted

            if category in ("A", "B"):
                current_prompt = item["debug_followup"]
            elif category == "C":
                followups = item.get("followup_prompts", [])
                # turn_num 1 used initial_prompt, so followup index = turn_num - 1
                followup_idx = turn_num - 1
                if followup_idx < len(followups):
                    current_prompt = followups[followup_idx]
                else:
                    # Exhausted predefined follow-ups — generic fix request
                    current_prompt = (
                        "The previous changes didn't fully work. Please check "
                        "the test output and fix any remaining issues."
                    )

        elapsed = time.monotonic() - start

        # Compute heuristic metrics
        diagnosis_accurate = self._check_diagnosis(turns, item)
        stderr_used = self._check_stderr_usage(turns, item)
        privacy_held = self._check_privacy_boundary(turns)

        if verification_passed:
            print(f"    CONVERGED in {fix_cycle_count} turn(s) "
                  f"({elapsed:.1f}s)")
        else:
            print(f"    DID NOT CONVERGE after {fix_cycle_count} turn(s) "
                  f"({elapsed:.1f}s)")

        # Aggregate token usage across turns
        total_planner_tokens = 0
        total_worker_tokens = 0
        for t in turns:
            pu = t.get("planner_usage") or {}
            total_planner_tokens += (
                pu.get("input_tokens", 0) + pu.get("output_tokens", 0)
            )
            for s in t.get("steps", []):
                wu = s.get("worker_usage") or {}
                total_worker_tokens += wu.get("eval_count", 0)

        return {
            "type": "result",
            "index": index,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "test_suite": "debugging",
            "prompt_id": prompt_id,
            "category": category,
            "initial_prompt": item["initial_prompt"],
            "initial_prompt_preview": item["initial_prompt"][:PREVIEW_LEN],
            "trial": trial,
            "total_trials": item["total_trials"],
            "elapsed_s": round(elapsed, 1),
            "turns_total": len(turns),
            "fix_cycle_count": fix_cycle_count,
            "convergence": verification_passed,
            "diagnosis_accurate": diagnosis_accurate,
            "stderr_used_in_diagnosis": stderr_used,
            "privacy_boundary_held": privacy_held,
            "verification_command": item["verification_command"],
            "verification_exit_code": (
                turns[-1].get("verification_exit_code") if turns else None
            ),
            "verification_passed": verification_passed,
            "verification_output": (
                turns[-1].get("verification_output") if turns else None
            ),
            "verification_error": (
                turns[-1].get("verification_error")
                if turns and not verification_passed else None
            ),
            "total_planner_tokens": total_planner_tokens,
            "total_worker_tokens": total_worker_tokens,
            "known_limitation": item.get("known_limitation"),
            "turn_details": turns,
        }

    # -- Main run -----------------------------------------------------------

    def run(self) -> None:
        """Run the full G2 debugging test suite."""
        self._setup_signals()
        self._open_output()

        queue = self._build_queue()
        print(f"\nG2: Debugging & Error Recovery Test Suite")
        print(f"  Version:    {self.version}")
        print(f"  Base URL:   {self.base_url}")
        print(f"  Output:     {self.output_path}")
        print(f"  Prompts:    {len(queue)} ({len(set(i['prompt_id'] for i in queue))} unique)")
        print(f"  Max turns:  {self.max_turns}")
        cats = sorted(set(i["category"] for i in queue))
        for cat in cats:
            n = sum(1 for i in queue if i["category"] == cat)
            print(f"  Category {cat}: {n} executions")

        # Health check before starting
        print("\n  Checking controller health...")
        if not self._wait_for_health():
            print("ERROR: Controller not healthy after 120s. Aborting.",
                  file=sys.stderr)
            sys.exit(1)
        print("  Controller healthy. Starting test suite.\n")

        self._write_header(queue)

        for i, item in enumerate(queue):
            if self.stop_requested:
                print(f"\n  Stop requested. Finishing after {i} scenarios.")
                break

            result = self._run_debug_scenario(i, item)
            self._results.append(result)
            self._write_line(result)

        self._write_summary()
        self._outfile.close()

        # Print final summary
        total = len(self._results)
        converged = sum(1 for r in self._results if r.get("convergence"))
        cycles = [r["fix_cycle_count"] for r in self._results
                  if r.get("fix_cycle_count")]
        mean_cycles = (
            round(sum(cycles) / len(cycles), 1) if cycles else 0
        )

        print(f"\n{'=' * 60}")
        print(f"  G2 COMPLETE: {converged}/{total} converged, "
              f"mean {mean_cycles} cycles")
        print(f"  Results: {self.output_path}")
        print(f"{'=' * 60}\n")


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="G2: Debugging & Error Recovery Functional Test Suite"
    )
    parser.add_argument(
        "--version", default="dev",
        help="Version tag for JSONL header (default: dev)",
    )
    parser.add_argument(
        "--trials", type=int, default=3,
        help="Trials for Category A prompts; B/C always 1 (default: 3)",
    )
    parser.add_argument(
        "--category", choices=["A", "B", "C"], action="append",
        help="Run only specified category (repeatable; default: all)",
    )
    parser.add_argument(
        "--base-url", default=DEFAULT_BASE_URL,
        help=f"Sentinel API URL (default: {DEFAULT_BASE_URL})",
    )
    parser.add_argument(
        "--output",
        help="JSONL output path (default: auto-generated in benchmarks/)",
    )
    parser.add_argument(
        "--max-turns", type=int, default=MAX_TURNS_DEFAULT,
        help=f"Max turns per scenario (default: {MAX_TURNS_DEFAULT})",
    )
    args = parser.parse_args()

    pin = _read_pin()

    if args.output:
        output_path = Path(args.output)
    else:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = Path(f"benchmarks/functional_debug_{args.version}_{ts}.jsonl")

    runner = DebugCapabilityTest(
        base_url=args.base_url,
        pin=pin,
        version=args.version,
        trials=args.trials,
        categories=args.category,
        max_turns=args.max_turns,
        output_path=output_path,
    )
    runner.run()


if __name__ == "__main__":
    main()
