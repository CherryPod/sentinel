#!/usr/bin/env python3
"""Sentinel Functional Test: Environment & Dependency Management (G5)

Can Sentinel handle tasks requiring external dependencies? Tests Solution C
only (fallback strategy detection) — the planner's ability to detect
ModuleNotFoundError from stderr and adapt (use stdlib alternatives, report
to user, or generate inline). Solutions A and B require infrastructure
changes — see docs/design/dependency-management.md.

6 prompts graduated from stdlib baseline through missing packages to
debugging + dependency combos. Multi-turn support: when install fails,
tracks whether the planner sends a follow-up with an adapted strategy.

Secondary output: list of packages the system attempts to use, feeding
into the Solution A design decision (which packages to pre-install).

Spec: docs/assessments/test_proposals.md §5
Tracker: docs/design/capability-deployment-tracker.md → G5

Files produced:
  benchmarks/functional_deps_{version}_{timestamp}.jsonl

Prerequisites:
    - sentinel + sentinel-ollama containers running on port 3001 (HTTPS)
    - SENTINEL_APPROVAL_MODE=auto (run_functional_tests.sh handles this)
    - SENTINEL_VERBOSE_RESULTS=true
    - SENTINEL_BENCHMARK_MODE=true
    - PIN in ~/.secrets/sentinel_pin.txt
    - TL4 (shell execution needed for install attempts and verification)

Usage:
    python3 scripts/functional_test_deps.py
    python3 scripts/functional_test_deps.py --version v0.4.0-alpha
    python3 scripts/functional_test_deps.py --max-turns 6
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
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

# ── Configuration ─────────────────────────────────────────────────

FILE_PREFIX = "functional_deps"
REQUEST_TIMEOUT = 1800      # 30 min per API call (Qwen generation is slow)
HEALTH_TIMEOUT = 10
HEALTH_WAIT_MAX = 120
RETRY_DELAY_BASE = 15
MAX_RETRIES = 2
VERIFICATION_TIMEOUT = 120  # 2 min for verification commands
CLEANUP_TIMEOUT = 30
MAX_TURNS_DEFAULT = 6       # enough for: initial + install fail + adapt
PREVIEW_LEN = 150
CONTAINER_NAME = "sentinel"

# SSL context for self-signed certs
_SSL_CTX = ssl.create_default_context()
_SSL_CTX.check_hostname = False
_SSL_CTX.verify_mode = ssl.CERT_NONE

_SCRIPT_DIR = Path(__file__).resolve().parent
_PROJECT_DIR = _SCRIPT_DIR.parent

# Patterns that indicate the planner requested raw Qwen output (privacy breach)
_PRIVACY_VIOLATION_RES = [
    re.compile(r"show\s+(?:me\s+)?(?:the\s+)?(?:raw|full|actual)\s+(?:output|response)", re.I),
    re.compile(r"what\s+did\s+(?:qwen|the\s+worker)\s+(?:say|produce|output|generate)", re.I),
    re.compile(r"paste\s+the\s+(?:worker|qwen)\s+(?:output|response)", re.I),
]

# Patterns that indicate a pip/install attempt in plan_summary or step content
_INSTALL_PATTERNS = [
    re.compile(r"pip\s+install", re.I),
    re.compile(r"pip3\s+install", re.I),
    re.compile(r"python\s+-m\s+pip", re.I),
    re.compile(r"apt.get\s+install", re.I),
    re.compile(r"apt\s+install", re.I),
    re.compile(r"conda\s+install", re.I),
    re.compile(r"poetry\s+add", re.I),
]

# Patterns that indicate a fallback/adaptation strategy
_FALLBACK_PATTERNS = {
    "stdlib_alternative": [
        re.compile(r"(?:use|switch|fall\s*back|replace|alternative).*(?:stdlib|standard\s+lib|built.?in|urllib|csv|json|os\b|sys\b|http\.)", re.I),
        re.compile(r"(?:urllib|csv\s+module|http\.client|http\.server|json\s+module)", re.I),
        re.compile(r"without\s+(?:external|third.?party)\s+(?:dep|lib|package)", re.I),
    ],
    "user_report": [
        re.compile(r"(?:cannot|can.t|unable|not\s+able)\s+(?:to\s+)?install", re.I),
        re.compile(r"(?:need|require|missing)\s+(?:to\s+)?install", re.I),
        re.compile(r"(?:package|dependency|module)\s+(?:is\s+)?(?:not\s+)?(?:available|installed|found)", re.I),
        re.compile(r"inform\s+(?:the\s+)?user", re.I),
    ],
    "inline_generation": [
        re.compile(r"(?:implement|write|create|generate)\s+(?:the\s+)?(?:functionality|logic|code)\s+(?:inline|directly|manually|from\s+scratch)", re.I),
        re.compile(r"(?:inline|manual)\s+(?:implementation|version)", re.I),
    ],
}

# Package name extraction from plan summaries and step content
_PACKAGE_NAME_RE = re.compile(
    r"(?:pip3?\s+install|import|from)\s+([a-zA-Z][a-zA-Z0-9_.-]*)"
)

# Common stdlib modules to filter out of package tracking
_STDLIB_MODULES = frozenset({
    "os", "sys", "json", "csv", "re", "math", "random", "time", "datetime",
    "pathlib", "collections", "itertools", "functools", "typing", "abc",
    "io", "string", "textwrap", "unicodedata", "struct", "codecs",
    "pprint", "reprlib", "enum", "numbers", "decimal", "fractions",
    "statistics", "array", "bisect", "heapq", "copy", "operator",
    "contextlib", "atexit", "traceback", "warnings", "dataclasses",
    "tempfile", "glob", "fnmatch", "shutil", "pickle", "shelve",
    "marshal", "sqlite3", "zlib", "gzip", "bz2", "lzma", "zipfile",
    "tarfile", "hashlib", "hmac", "secrets", "base64", "binascii",
    "subprocess", "sched", "queue", "threading", "multiprocessing",
    "concurrent", "asyncio", "socket", "ssl", "select", "selectors",
    "signal", "mmap", "email", "mailbox", "mimetypes", "html",
    "xml", "webbrowser", "urllib", "http", "ftplib", "poplib",
    "imaplib", "smtplib", "uuid", "socketserver", "xmlrpc",
    "ipaddress", "logging", "getpass", "curses", "platform",
    "ctypes", "unittest", "doctest", "pdb", "profile", "timeit",
    "venv", "distutils", "importlib", "pkgutil", "modulefinder",
    "ast", "dis", "inspect", "site", "configparser", "argparse",
    "gettext", "locale",
})


# ── Prompt definitions ────────────────────────────────────────────

DEPS_PROMPTS: list[dict] = [
    {
        "prompt_id": "deps_1_stdlib_baseline",
        "prompt": (
            "Write a Python script at `/workspace/process_files.py` that:\n"
            "1. Uses `json` to read a config from `/workspace/config.json`\n"
            "2. Uses `os` and `pathlib` to list all `.txt` files in `/workspace/data/`\n"
            "3. Uses `csv` to write a summary CSV at `/workspace/summary.csv` "
            "with columns: filename, size_bytes, modified_time\n"
            "First create the test data: a `/workspace/config.json` with "
            '{"data_dir": "/workspace/data"} and a `/workspace/data/` directory '
            "with 3 small `.txt` files containing sample text.\n"
            "Then run `python3 /workspace/process_files.py` to verify it works."
        ),
        "dependency_type": "stdlib",
        "verification_command": (
            "python3 /workspace/process_files.py && "
            "test -f /workspace/summary.csv && "
            "python3 -c \""
            "import csv; "
            "rows = list(csv.reader(open('/workspace/summary.csv'))); "
            "assert len(rows) >= 4, f'Expected header + 3 rows, got {len(rows)}'; "
            "assert 'filename' in rows[0][0].lower() or 'file' in rows[0][0].lower(), "
            "f'Missing filename header: {rows[0]}'; "
            "print(f'Summary CSV valid: {len(rows)-1} data rows')\""
        ),
        "expected_outcome": "Script processes files using only stdlib modules",
        "adaptation_followup": None,  # shouldn't need adaptation
        "max_turns": 3,
    },
    {
        "prompt_id": "deps_2_preinstalled_requests",
        "prompt": (
            "Write a Python script at `/workspace/fetch_url.py` that uses the "
            "`requests` library to fetch https://example.com, print the HTTP "
            "status code and the first 200 characters of the response body. "
            "Save it and run it with `python3 /workspace/fetch_url.py`."
        ),
        "dependency_type": "pre-installed",
        "verification_command": (
            "python3 /workspace/fetch_url.py 2>&1 || "
            "python3 -c \""
            "# If requests failed, check if an adapted version exists\n"
            "import subprocess, sys; "
            "r = subprocess.run(['python3', '/workspace/fetch_url.py'], "
            "capture_output=True, text=True, timeout=30); "
            "out = r.stdout + r.stderr; "
            "if r.returncode == 0: "
            "    print('Script ran successfully'); sys.exit(0); "
            "elif 'ModuleNotFoundError' in out or 'No module named' in out: "
            "    print('MISSING_DEP: requests not pre-installed'); sys.exit(1); "
            "else: "
            "    print(f'Script failed: {out[:200]}'); sys.exit(1)\""
        ),
        "expected_outcome": (
            "Succeeds if requests is pre-installed, fails gracefully if not"
        ),
        "adaptation_followup": (
            "The previous task failed because a required package is not available. "
            "Please adapt the script to work without the missing package — use "
            "Python's standard library instead."
        ),
        "max_turns": 4,
    },
    {
        "prompt_id": "deps_3_missing_pandas",
        "prompt": (
            "Write a Python script at `/workspace/analyse_data.py` that:\n"
            "1. Reads a CSV file `/workspace/sales.csv` with columns: "
            "date, product, quantity, price\n"
            "2. Calculates total revenue per product\n"
            "3. Finds the top-selling product by quantity\n"
            "4. Prints a summary report\n"
            "Use the `pandas` library for data analysis.\n"
            "First create `/workspace/sales.csv` with at least 10 rows of "
            "sample data across 3-4 products.\n"
            "Then run `python3 /workspace/analyse_data.py`."
        ),
        "dependency_type": "missing",
        "verification_command": (
            "python3 /workspace/analyse_data.py 2>&1; "
            "EXIT=$?; "
            "if [ $EXIT -eq 0 ]; then "
            "    echo 'Script succeeded'; "
            "elif python3 -c 'import pandas' 2>/dev/null; then "
            "    echo 'UNEXPECTED_FAIL: pandas available but script failed'; exit 1; "
            "else "
            "    echo 'EXPECTED_FAIL: pandas not available'; exit 1; "
            "fi"
        ),
        "expected_outcome": (
            "If pandas pre-installed: succeeds. If not: should detect "
            "ModuleNotFoundError and suggest stdlib csv alternative"
        ),
        "adaptation_followup": (
            "The pandas library is not available in this environment and cannot "
            "be installed. Please rewrite the script using only Python's standard "
            "library (the `csv` module) to achieve the same analysis."
        ),
        "max_turns": 5,
    },
    {
        "prompt_id": "deps_4_install_attempt",
        "prompt": (
            "Install the `flask` package and create a minimal web server at "
            "`/workspace/server.py` with a single endpoint GET /health that "
            "returns JSON {'status': 'ok'}. Then verify the import works by "
            "running `python3 -c \"import flask; print(flask.__version__)\"`."
        ),
        "dependency_type": "missing",
        "verification_command": (
            "python3 -c 'import flask; print(flask.__version__)' 2>&1; "
            "EXIT=$?; "
            "if [ $EXIT -eq 0 ]; then "
            "    echo 'Flask import succeeded'; "
            "else "
            "    # Check if the script was adapted to work without flask\n"
            "    if [ -f /workspace/server.py ]; then "
            "        python3 -c \""
            "import ast; "
            "code = open('/workspace/server.py').read(); "
            "tree = ast.parse(code); "
            "imports = [n.names[0].name for n in ast.walk(tree) "
            "           if isinstance(n, ast.Import)]; "
            "from_imports = [n.module for n in ast.walk(tree) "
            "               if isinstance(n, ast.ImportFrom) and n.module]; "
            "all_imports = imports + from_imports; "
            "if 'http.server' in all_imports or 'http' in all_imports: "
            "    print('ADAPTED: uses http.server instead of flask'); "
            "elif 'flask' in all_imports: "
            "    print('UNADAPTED: still imports flask'); "
            "else: "
            "    print(f'ADAPTED: uses {all_imports}'); "
            "\" 2>&1; "
            "    else "
            "        echo 'NO_FILE: server.py not created'; exit 1; "
            "    fi; "
            "fi"
        ),
        "expected_outcome": (
            "Tests whether system can handle pip install — sandbox blocks "
            "network, should detect failure and adapt"
        ),
        "adaptation_followup": (
            "The package installation failed because this environment does not "
            "have network access. Please create the web server using only "
            "Python's standard library (http.server module) instead."
        ),
        "max_turns": 5,
    },
    {
        "prompt_id": "deps_5_venv_creation",
        "prompt": (
            "Create a Python project with proper dependency management at "
            "`/workspace/myproject/`:\n"
            "1. Create a `requirements.txt` listing `requests>=2.28.0` and "
            "`pyyaml>=6.0`\n"
            "2. Create a virtual environment at `/workspace/myproject/.venv/`\n"
            "3. Try to install the requirements into the venv\n"
            "4. Create `main.py` that imports from both packages and prints "
            "a status message\n"
            "5. Run `main.py` using the venv's Python interpreter"
        ),
        "dependency_type": "missing",
        "verification_command": (
            "test -f /workspace/myproject/requirements.txt && "
            "test -f /workspace/myproject/main.py && "
            "echo 'Project files exist'; "
            "# Check if venv was created (may fail due to sandbox)\n"
            "if [ -d /workspace/myproject/.venv ]; then "
            "    echo 'Venv directory created'; "
            "else "
            "    echo 'NO_VENV: venv not created (expected in sandbox)'; "
            "fi; "
            "# Try running main.py\n"
            "python3 /workspace/myproject/main.py 2>&1 || "
            "echo 'MAIN_FAILED: main.py execution failed'"
        ),
        "expected_outcome": (
            "Should create project files and venv in /workspace/. Install "
            "will likely fail (sandbox). Should detect and report."
        ),
        "adaptation_followup": (
            "The virtual environment creation or package installation failed "
            "due to environment constraints. Please adapt `main.py` to work "
            "with only Python's standard library — use `urllib.request` instead "
            "of `requests` and the built-in `json` module where you would have "
            "used `pyyaml`."
        ),
        "max_turns": 5,
    },
    {
        "prompt_id": "deps_6_debug_importerror",
        "prompt": (
            "The script at `/workspace/app.py` fails with an ImportError for "
            "the `pydantic` package. Please diagnose the issue and fix it so "
            "the script runs successfully."
        ),
        "dependency_type": "missing",
        "seed_files": {
            "/workspace/app.py": (
                "#!/usr/bin/env python3\n"
                '"""Simple data validation app using pydantic."""\n'
                "\n"
                "from pydantic import BaseModel, validator\n"
                "from typing import Optional\n"
                "import json\n"
                "\n"
                "\n"
                "class UserProfile(BaseModel):\n"
                '    name: str\n'
                '    email: str\n'
                '    age: Optional[int] = None\n'
                "\n"
                '    @validator("email")\n'
                "    def validate_email(cls, v):\n"
                '        if "@" not in v:\n'
                '            raise ValueError("Invalid email")\n'
                "        return v\n"
                "\n"
                '    @validator("age")\n'
                "    def validate_age(cls, v):\n"
                "        if v is not None and (v < 0 or v > 150):\n"
                '            raise ValueError("Age must be between 0 and 150")\n'
                "        return v\n"
                "\n"
                "\n"
                "def main():\n"
                "    test_data = [\n"
                '        {"name": "Alice", "email": "alice@example.com", "age": 30},\n'
                '        {"name": "Bob", "email": "bob@example.com"},\n'
                '        {"name": "Charlie", "email": "charlie@example.com", "age": 25},\n'
                "    ]\n"
                "\n"
                "    for data in test_data:\n"
                "        user = UserProfile(**data)\n"
                '        print(f"Valid: {user.name} ({user.email})")\n'
                "\n"
                '    print("All profiles validated successfully")\n'
                "\n"
                "\n"
                'if __name__ == "__main__":\n'
                "    main()\n"
            ),
        },
        "verification_command": (
            "python3 /workspace/app.py 2>&1; "
            "EXIT=$?; "
            "if [ $EXIT -eq 0 ]; then "
            "    echo 'Script ran successfully'; "
            "else "
            "    echo 'Script still failing'; exit 1; "
            "fi"
        ),
        "expected_outcome": (
            "Should diagnose missing pydantic dep, attempt install, and on "
            "failure adapt to use dataclasses + manual validation"
        ),
        "adaptation_followup": (
            "The pydantic package cannot be installed in this environment. "
            "Please rewrite the script to use Python's built-in `dataclasses` "
            "module with manual validation to achieve the same functionality."
        ),
        "max_turns": 6,
    },
]


# ── Utility functions ─────────────────────────────────────────────

def post_json(url, data, headers, timeout=REQUEST_TIMEOUT):
    """POST JSON data and return (response_dict, http_status)."""
    body = json.dumps(data).encode("utf-8")
    req = urllib.request.Request(url, data=body, headers=headers)
    req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=_SSL_CTX) as resp:
            return json.loads(resp.read().decode("utf-8")), resp.status
    except urllib.error.HTTPError as e:
        try:
            return json.loads(e.read().decode("utf-8")), e.code
        except (json.JSONDecodeError, UnicodeDecodeError):
            return {"error": f"HTTP {e.code}: {e.reason}"}, e.code
    except (ConnectionError, OSError, TimeoutError) as e:
        return {"error": str(e)}, 0


def check_health(base_url, timeout=HEALTH_TIMEOUT):
    """Check if the controller is healthy."""
    try:
        req = urllib.request.Request(f"{base_url}/health")
        with urllib.request.urlopen(req, timeout=timeout, context=_SSL_CTX) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            return data.get("status") == "ok"
    except Exception:
        return False


def exec_in_container(command, timeout=VERIFICATION_TIMEOUT):
    """Run a command inside the sentinel container via podman exec.

    Returns (exit_code, stdout, stderr).
    """
    try:
        result = subprocess.run(
            ["podman", "exec", CONTAINER_NAME, "bash", "-c", command],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return -1, "", f"Command timed out after {timeout}s"
    except FileNotFoundError:
        return -1, "", "podman not found"
    except Exception as e:
        return -1, "", str(e)


def exec_in_sandbox(command: str, timeout: int = VERIFICATION_TIMEOUT) -> tuple[int, str, str]:
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


def cleanup_workspace():
    """Remove all files from /workspace/ inside the container."""
    exit_code, stdout, stderr = exec_in_container(
        "find /workspace -mindepth 1 -delete 2>/dev/null; echo done",
        timeout=CLEANUP_TIMEOUT,
    )
    if exit_code != 0 and "done" not in stdout:
        print(f"  WARNING: Workspace cleanup may have failed: {stderr}")


def seed_files(files: dict[str, str]):
    """Write seed files into the container via podman exec.

    Uses base64 encoding to avoid shell escaping issues with complex content.
    """
    for path, content in files.items():
        # Ensure parent directory exists
        parent = str(Path(path).parent)
        exec_in_container(f"mkdir -p {parent}")

        # base64 encode and decode inside container
        b64 = base64.b64encode(content.encode("utf-8")).decode("ascii")
        exit_code, _, stderr = exec_in_container(
            f"echo '{b64}' | base64 -d > {path}"
        )
        if exit_code != 0:
            print(f"    WARNING: Failed to seed {path}: {stderr}")
        else:
            print(f"    Seeded: {path} ({len(content)} bytes)")


# ── Test runner ───────────────────────────────────────────────────

class DependencyManagementTest:
    """G5: Environment & Dependency Management Test Suite."""

    def __init__(
        self,
        base_url: str,
        pin: str,
        results_dir: str,
        version: str | None = None,
        max_turns: int = MAX_TURNS_DEFAULT,
    ):
        self.base_url = base_url
        self.pin = pin
        self.results_dir = Path(results_dir)
        self.version = version
        self.max_turns_override = max_turns
        self.stop_requested = False
        self.results_fh = None

        # Track all packages the system attempts to use
        self.packages_seen: dict[str, list[str]] = {}  # package -> [prompt_ids]

        self.stats = {
            "total": 0,
            "success": 0,
            "adapted": 0,
            "not_adapted": 0,
            "api_errors": 0,
            "blocked": 0,
            "by_dep_type": {},
        }

    # -- API interaction ------------------------------------------------

    def _execute_turn(self, prompt_text: str, source: str, turn_num: int) -> dict:
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

        data = {"request": prompt_text, "source": source}
        headers = {
            "X-Sentinel-Pin": self.pin,
            "Origin": self.base_url,
        }

        for attempt in range(MAX_RETRIES):
            start = time.monotonic()
            resp, http_status = post_json(
                f"{self.base_url}/api/task",
                data,
                headers,
                timeout=REQUEST_TIMEOUT,
            )
            elapsed = time.monotonic() - start

            if http_status > 0:
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
                            "content": s.get("content"),
                            "worker_response": s.get("worker_response"),
                            "quality_warnings": s.get("quality_warnings", []),
                            "worker_usage": s.get("worker_usage"),
                        }
                        for s in steps
                    ]
                    turn_result["step_outcomes"] = resp.get("step_outcomes") or []
                    turn_result["planner_usage"] = resp.get("planner_usage") or {}
                break
            else:
                if attempt < MAX_RETRIES - 1:
                    wait = RETRY_DELAY_BASE * (2 ** attempt)
                    print(f"      Connection error (attempt {attempt + 1}). "
                          f"Retrying in {wait}s...")
                    time.sleep(wait)
                    if not self._wait_for_health(max_wait=60):
                        turn_result["error"] = "Health check failed after retry"
                        break
                else:
                    turn_result["error"] = resp.get("error", "Connection failed") if resp else "Connection failed"

        return turn_result

    # -- Verification ---------------------------------------------------

    def _verify(self, item: dict) -> dict:
        """Run the verification command in a disposable sandbox container."""
        v_cmd = item["verification_command"]
        exit_code, stdout, stderr = exec_in_sandbox(v_cmd)

        output = stdout.strip()
        if stderr.strip():
            output += "\n--- stderr ---\n" + stderr.strip()

        passed = exit_code == 0

        return {
            "verification_command": v_cmd,
            "verification_exit_code": exit_code,
            "verification_passed": passed,
            "verification_output": output[:2000],
            "verification_error": stderr.strip()[:500] if not passed else None,
        }

    # -- Heuristic analysis ---------------------------------------------

    def _detect_install_attempted(self, turns: list[dict]) -> bool:
        """Check if any turn attempted to install a package."""
        for turn in turns:
            summary = turn.get("plan_summary") or ""
            for pat in _INSTALL_PATTERNS:
                if pat.search(summary):
                    return True
            # Also check step content / worker responses
            for step in turn.get("steps", []):
                for field in ("content", "worker_response"):
                    text = step.get(field) or ""
                    for pat in _INSTALL_PATTERNS:
                        if pat.search(text):
                            return True
        return False

    def _detect_fallback_strategy(self, turns: list[dict]) -> str:
        """Detect which fallback strategy was used.

        Returns one of: stdlib_alternative, user_report, inline_generation, none
        """
        for strategy, patterns in _FALLBACK_PATTERNS.items():
            for turn in turns:
                summary = turn.get("plan_summary") or ""
                for pat in patterns:
                    if pat.search(summary):
                        return strategy
                # Check step content
                for step in turn.get("steps", []):
                    for field in ("content", "worker_response"):
                        text = step.get(field) or ""
                        for pat in patterns:
                            if pat.search(text):
                                return strategy
        return "none"

    def _detect_adaptation_success(
        self, turns: list[dict], verification_passed: bool
    ) -> bool | None:
        """Check if adaptation was successful.

        Returns True if adapted and verification passed, False if adapted
        but still failing, None if no adaptation was needed.
        """
        # If the first turn's verification passed, no adaptation needed
        if len(turns) >= 1:
            first_v = turns[0].get("verification_passed")
            if first_v is True:
                return None  # no adaptation needed

        # If there were follow-up turns, check if adaptation worked
        if len(turns) > 1:
            return verification_passed

        return None

    def _extract_packages(self, turns: list[dict], prompt_id: str):
        """Extract package names from turns and track them."""
        for turn in turns:
            summary = turn.get("plan_summary") or ""
            for match in _PACKAGE_NAME_RE.finditer(summary):
                pkg = match.group(1).lower()
                # Filter out stdlib modules
                if pkg not in _STDLIB_MODULES:
                    self.packages_seen.setdefault(pkg, [])
                    if prompt_id not in self.packages_seen[pkg]:
                        self.packages_seen[pkg].append(prompt_id)

            for step in turn.get("steps", []):
                for field in ("content", "worker_response"):
                    text = step.get(field) or ""
                    for match in _PACKAGE_NAME_RE.finditer(text):
                        pkg = match.group(1).lower()
                        if pkg not in _STDLIB_MODULES:
                            self.packages_seen.setdefault(pkg, [])
                            if prompt_id not in self.packages_seen[pkg]:
                                self.packages_seen[pkg].append(prompt_id)

    def _check_missing_dep_detection(self, turns: list[dict]) -> bool:
        """Check if the system detected a missing dependency.

        Returns True if any turn's plan_summary or step outcomes reference
        ModuleNotFoundError, ImportError, or missing module.
        """
        patterns = [
            "modulenotfounderror", "importerror", "no module named",
            "module not found", "not installed", "missing module",
            "missing dependency", "missing package",
        ]
        for turn in turns:
            summary = (turn.get("plan_summary") or "").lower()
            for p in patterns:
                if p in summary:
                    return True
            # Check step outcomes for stderr with module errors
            for so in turn.get("step_outcomes", []):
                stderr = (so.get("stderr_preview") or "").lower()
                for p in patterns:
                    if p in stderr:
                        return True
        return False

    def _check_silent_failure(
        self, turns: list[dict], verification_passed: bool,
        dependency_type: str
    ) -> bool:
        """Check for silent failure: broken output without detecting the issue.

        Returns True if the system produced code that fails but didn't
        acknowledge the dependency problem.
        """
        if verification_passed:
            return False  # Not a failure
        if dependency_type == "stdlib":
            return False  # Stdlib shouldn't have dep issues

        # If the code fails AND the system didn't detect the missing dep
        detected = self._check_missing_dep_detection(turns)
        if not detected and len(turns) == 1:
            # Only one turn (no follow-up) and no detection — silent failure
            return True
        return False

    def _check_privacy_boundary(self, turns: list[dict]) -> bool:
        """Check that the planner never requested raw Qwen output."""
        for turn in turns:
            summary = turn.get("plan_summary") or ""
            for pattern in _PRIVACY_VIOLATION_RES:
                if pattern.search(summary):
                    return False
        return True

    # -- Main scenario runner -------------------------------------------

    def _run_scenario(self, index: int, item: dict) -> dict:
        """Run a complete dependency test scenario with multi-turn support."""
        prompt_id = item["prompt_id"]
        dep_type = item["dependency_type"]
        max_t = min(item.get("max_turns", MAX_TURNS_DEFAULT), self.max_turns_override)

        print(f"\n  [{index + 1}/{len(DEPS_PROMPTS)}] {prompt_id} "
              f"(type={dep_type})")

        start = time.monotonic()
        source = f"deps_{prompt_id}_{int(time.time())}"

        # Clean workspace
        print("    Cleaning workspace...")
        cleanup_workspace()

        # Seed files if needed
        seed = item.get("seed_files")
        if seed:
            print(f"    Seeding {len(seed)} file(s)...")
            seed_files(seed)

        turns: list[dict] = []
        current_prompt = item["prompt"]
        verification_passed = False

        for turn_num in range(1, max_t + 1):
            if self.stop_requested:
                break

            label = "Initial" if turn_num == 1 else f"Follow-up #{turn_num - 1}"
            print(f"    Turn {turn_num}/{max_t} ({label}): "
                  f"sending {len(current_prompt)} chars...")

            # Send prompt to API
            turn_result = self._execute_turn(current_prompt, source, turn_num)

            # Run verification
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
                    print(f"    Turn {turn_num}: verification failed"
                          f"{': ' + v_err if v_err else ''}")
            elif status == "error" or turn_result.get("error"):
                err = (turn_result.get("error") or "unknown")[:100]
                print(f"    Turn {turn_num}: API error: {err}")
                turn_result["verification_passed"] = None
            else:
                print(f"    Turn {turn_num}: status={status}")
                turn_result["verification_passed"] = None

            turns.append(turn_result)

            # Determine next prompt
            if turn_num >= max_t:
                break

            adaptation = item.get("adaptation_followup")
            if adaptation and turn_num == 1:
                # First follow-up: use the specific adaptation prompt
                current_prompt = adaptation
            elif adaptation and turn_num > 1:
                # Further follow-ups: generic fix request
                current_prompt = (
                    "The adapted version still isn't working. Please check "
                    "the error and fix any remaining issues."
                )
            else:
                # No adaptation defined — generic fix
                current_prompt = (
                    "The previous task failed. Please diagnose the error "
                    "and fix the script so it runs successfully."
                )

        elapsed = time.monotonic() - start

        # Compute heuristic metrics
        install_attempted = self._detect_install_attempted(turns)
        fallback_strategy = self._detect_fallback_strategy(turns)
        adaptation_successful = self._detect_adaptation_success(
            turns, verification_passed
        )
        missing_dep_detected = self._check_missing_dep_detection(turns)
        silent_failure = self._check_silent_failure(
            turns, verification_passed, dep_type
        )
        privacy_held = self._check_privacy_boundary(turns)

        # Track packages
        self._extract_packages(turns, prompt_id)

        # Aggregate tokens
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

        status_label = "PASS" if verification_passed else "FAIL"
        if fallback_strategy != "none":
            status_label += f" (adapted: {fallback_strategy})"
        print(f"    → {status_label} ({len(turns)} turns, {elapsed:.1f}s)")

        return {
            "type": "result",
            "index": index,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "test_suite": "deps",
            "prompt_id": prompt_id,
            "prompt": item["prompt"],
            "prompt_preview": item["prompt"][:PREVIEW_LEN],
            "dependency_type": dep_type,
            "elapsed_s": round(elapsed, 1),
            "turns_total": len(turns),
            "verification_passed": verification_passed,
            "verification_command": item["verification_command"],
            "verification_exit_code": (
                turns[-1].get("verification_exit_code") if turns else None
            ),
            "verification_output": (
                turns[-1].get("verification_output") if turns else None
            ),
            "verification_error": (
                turns[-1].get("verification_error")
                if turns and not verification_passed else None
            ),
            # G5-specific fields
            "install_attempted": install_attempted,
            "fallback_strategy": fallback_strategy,
            "adaptation_successful": adaptation_successful,
            "missing_dep_detected": missing_dep_detected,
            "silent_failure": silent_failure,
            "privacy_boundary_held": privacy_held,
            # Token usage
            "total_planner_tokens": total_planner_tokens,
            "total_worker_tokens": total_worker_tokens,
            # Turn details for debugging
            "turn_details": turns,
        }

    # -- Health check ---------------------------------------------------

    def _wait_for_health(self, max_wait=HEALTH_WAIT_MAX):
        """Wait for the controller to become healthy."""
        start = time.monotonic()
        while time.monotonic() - start < max_wait:
            if check_health(self.base_url):
                return True
            time.sleep(5)
        return False

    # -- Signal handling ------------------------------------------------

    def _setup_signals(self):
        """Handle SIGINT/SIGTERM for graceful shutdown."""
        def handler(signum, frame):
            sig_name = signal.Signals(signum).name
            print(f"\n  Signal {sig_name} received. Finishing current prompt...")
            self.stop_requested = True
        signal.signal(signal.SIGINT, handler)
        signal.signal(signal.SIGTERM, handler)

    # -- Results I/O ----------------------------------------------------

    def _write_result(self, result):
        """Write a result line to the JSONL file."""
        if self.results_fh:
            self.results_fh.write(json.dumps(result, default=str) + "\n")
            self.results_fh.flush()
            os.fsync(self.results_fh.fileno())

    def _update_stats(self, result):
        """Update running statistics."""
        self.stats["total"] += 1
        dep_type = result.get("dependency_type", "unknown")

        if dep_type not in self.stats["by_dep_type"]:
            self.stats["by_dep_type"][dep_type] = {
                "total": 0, "passed": 0, "adapted": 0,
                "failed": 0, "errors": 0, "blocked": 0,
            }
        d = self.stats["by_dep_type"][dep_type]
        d["total"] += 1

        status = result.get("response_status") if result.get("turn_details") else "error"
        v_passed = result.get("verification_passed")

        if result.get("turn_details") and result["turn_details"][-1].get("response_status") == "error":
            self.stats["api_errors"] += 1
            d["errors"] += 1
        elif v_passed is True:
            self.stats["success"] += 1
            d["passed"] += 1
            if result.get("adaptation_successful") is True:
                self.stats["adapted"] += 1
                d["adapted"] += 1
        elif v_passed is False:
            self.stats["not_adapted"] += 1
            d["failed"] += 1
        elif result.get("turn_details") and result["turn_details"][-1].get("response_status") == "blocked":
            self.stats["blocked"] += 1
            d["blocked"] += 1
        else:
            self.stats["api_errors"] += 1
            d["errors"] += 1

    # -- Main entry point -----------------------------------------------

    def run(self):
        """Run the full G5 dependency management test suite."""
        self._setup_signals()

        total_prompts = len(DEPS_PROMPTS)
        print("Environment & Dependency Management Test Suite (G5)")
        print(f"  Prompts: {total_prompts}")
        print(f"  Max turns per prompt: {self.max_turns_override}")
        print()

        # Wait for health
        print(f"Checking controller health at {self.base_url}...")
        if not self._wait_for_health():
            print("ERROR: Controller is not healthy. Aborting.")
            return

        # Verify podman exec works
        print("Verifying container access...")
        exit_code, stdout, stderr = exec_in_container("echo ok")
        if exit_code != 0 or "ok" not in stdout:
            print(f"ERROR: Cannot exec into container '{CONTAINER_NAME}'")
            print(f"  exit_code={exit_code}, stderr={stderr}")
            return
        print("  Container exec: OK")
        print()

        # Open results file
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        version = self.version or ts
        results_file = self.results_dir / f"{FILE_PREFIX}_{version}_{ts}.jsonl"
        self.results_fh = open(results_file, "w", buffering=1)
        print(f"Results file: {results_file}")

        # Write header
        header = {
            "type": "header",
            "started_at": datetime.now(timezone.utc).isoformat(),
            "version": version,
            "base_url": self.base_url,
            "test_suite": "deps",
            "total_prompts": total_prompts,
            "max_turns": self.max_turns_override,
        }
        self._write_result(header)

        print(f"\n{'='*60}")
        print(f"  DEPENDENCY MANAGEMENT TEST STARTING — {total_prompts} scenarios")
        print(f"{'='*60}\n")

        start_time = time.monotonic()

        for i, item in enumerate(DEPS_PROMPTS):
            if self.stop_requested:
                print(f"\n  Stop requested. Finishing after {i} scenarios.")
                break

            result = self._run_scenario(i, item)
            self._write_result(result)
            self._update_stats(result)

        # Write package usage summary
        pkg_summary = {
            "type": "package_usage",
            "packages": {
                pkg: {"count": len(prompts), "prompts": prompts}
                for pkg, prompts in sorted(
                    self.packages_seen.items(),
                    key=lambda x: -len(x[1])
                )
            },
            "total_unique_packages": len(self.packages_seen),
        }
        self._write_result(pkg_summary)

        # Write summary
        total_elapsed = time.monotonic() - start_time
        self.stats["total_elapsed"] = round(total_elapsed, 1)
        summary = {"type": "summary", **self.stats}
        self._write_result(summary)

        if self.results_fh:
            self.results_fh.close()

        self._print_summary(total_elapsed)

    def _print_summary(self, total_elapsed):
        """Print a human-readable summary."""
        s = self.stats
        total = s["total"]

        print(f"\n{'='*60}")
        print("  DEPENDENCY MANAGEMENT TEST COMPLETE")
        print(f"{'='*60}")
        print(f"  Duration:      {total_elapsed/60:.1f} minutes")
        print(f"  Scenarios:     {total}/{len(DEPS_PROMPTS)}")
        print()
        print("  Results:")
        print(f"    Passed:      {s['success']}")
        print(f"    Adapted:     {s['adapted']}")
        print(f"    Failed:      {s['not_adapted']}")
        print(f"    API errors:  {s['api_errors']}")
        if total > 0:
            pass_rate = 100 * s["success"] / total
            print(f"    Pass rate:   {pass_rate:.1f}%")
        print()

        print("  By dependency type:")
        print(f"    {'Type':15s}  {'Total':>5s}  {'Pass':>5s}  {'Adapt':>5s}  "
              f"{'Fail':>5s}  {'Err':>5s}")
        print(f"    {'-'*15}  {'-'*5}  {'-'*5}  {'-'*5}  {'-'*5}  {'-'*5}")
        for dt in sorted(s["by_dep_type"].keys()):
            d = s["by_dep_type"][dt]
            print(
                f"    {dt:15s}  {d['total']:5d}  {d['passed']:5d}  "
                f"{d['adapted']:5d}  {d['failed']:5d}  {d['errors']:5d}"
            )
        print()

        if self.packages_seen:
            print("  Packages attempted (feeds Solution A design):")
            for pkg, prompts in sorted(
                self.packages_seen.items(), key=lambda x: -len(x[1])
            ):
                print(f"    {pkg}: used by {len(prompts)} prompt(s)")
        print(f"{'='*60}")


# ── Main ──────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Sentinel Environment & Dependency Management Test Suite (G5)"
    )
    parser.add_argument(
        "--url", default="https://localhost:3001",
        help="Sentinel base URL (default: https://localhost:3001)",
    )
    parser.add_argument(
        "--results-dir",
        default=str(_PROJECT_DIR / "benchmarks"),
        help="Directory for results files (default: benchmarks/)",
    )
    parser.add_argument(
        "--version", default=None,
        help="Build version for results filename",
    )
    parser.add_argument(
        "--max-turns", type=int, default=MAX_TURNS_DEFAULT,
        help=f"Max turns per scenario (default: {MAX_TURNS_DEFAULT})",
    )
    args = parser.parse_args()

    # Read PIN
    pin_path = Path.home() / ".secrets" / "sentinel_pin.txt"
    if not pin_path.exists():
        print(f"ERROR: PIN file not found: {pin_path}")
        sys.exit(1)
    pin = pin_path.read_text().strip()

    # Ensure results directory exists
    results_dir = Path(args.results_dir)
    results_dir.mkdir(parents=True, exist_ok=True)

    # Run
    test = DependencyManagementTest(
        base_url=args.url,
        pin=pin,
        results_dir=str(results_dir),
        version=args.version,
        max_turns=args.max_turns,
    )
    test.run()


if __name__ == "__main__":
    main()
