#!/usr/bin/env python3
"""Sentinel Functional Test: Autonomous End-to-End Workflow (G3)

Can Sentinel handle complete real-world tasks from request to finished result?
8 graduated scenarios from simple file reads to container lifecycle to
self-scheduling routines. Includes a TL4 gate check: a trivial shell
execution test that must pass before scenarios 4-8 run.

Spec: docs/assessments/test_proposals.md §3
Tracker: docs/design/capability-deployment-tracker.md → G3

Files produced:
  benchmarks/functional_e2e_{version}_{timestamp}.jsonl

Prerequisites:
    - sentinel + sentinel-ollama containers running on port 3001 (HTTPS)
    - SENTINEL_APPROVAL_MODE=auto (run_functional_tests.sh handles this)
    - SENTINEL_VERBOSE_RESULTS=true
    - SENTINEL_BENCHMARK_MODE=true
    - PIN in ~/.secrets/sentinel_pin.txt
    - TL2 minimum (scenario 1), TL3 (scenarios 2-3), TL4 (scenarios 4-8)

Usage:
    python3 scripts/functional_test_e2e.py
    python3 scripts/functional_test_e2e.py --version v0.4.0-alpha
    python3 scripts/functional_test_e2e.py --scenario 1 --scenario 2  # subset
"""

import argparse
import json
import os
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

FILE_PREFIX = "functional_e2e"
REQUEST_TIMEOUT = 1800      # 30 min per turn (multi-step plans: Qwen generation is slow)
HEALTH_TIMEOUT = 10
HEALTH_WAIT_MAX = 120
RETRY_DELAY_BASE = 15
MAX_RETRIES = 2
VERIFICATION_TIMEOUT = 120  # 2 min for verification commands
CLEANUP_TIMEOUT = 30        # 30s for workspace cleanup
CONTAINER_NAME = "sentinel"
MAX_TURNS_PER_SCENARIO = 8  # hard cap to prevent spirals

# SSL context for self-signed certs
_SSL_CTX = ssl.create_default_context()
_SSL_CTX.check_hostname = False
_SSL_CTX.verify_mode = ssl.CERT_NONE

_SCRIPT_DIR = Path(__file__).resolve().parent
_PROJECT_DIR = _SCRIPT_DIR.parent


# ── Pre-seeded file content ──────────────────────────────────────

# Scenario 1: simple README for file_read test
_PRESEED_README = """\
# Test Project

This is a sample project README for testing Sentinel's file reading capability.

## Features
- Feature A: does something useful
- Feature B: does something else
- Feature C: the best feature

## Installation
Run `pip install -r requirements.txt`

## License
MIT
"""

# Scenario 6: Python file with a deliberate TypeError
_PRESEED_BUGGY_PY = """\
def process_items(items):
    \"\"\"Process a list of items and return their string representations.\"\"\"
    results = []
    for item in items:
        # Bug: trying to concatenate string with integer
        results.append("Item: " + item)
    return results


def main():
    # This will crash: passing integers instead of strings
    data = [1, 2, 3, 4, 5]
    output = process_items(data)
    for line in output:
        print(line)


if __name__ == "__main__":
    main()
"""

# Scenario 7: minimal Flask app with Containerfile
_PRESEED_APP_MAIN = """\
from flask import Flask, jsonify

app = Flask(__name__)

@app.route("/health")
def health():
    return jsonify({"status": "ok", "service": "test-app"})

@app.route("/")
def index():
    return jsonify({"message": "Hello from test app"})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
"""

_PRESEED_APP_REQUIREMENTS = "flask>=3.0.0\n"

_PRESEED_APP_CONTAINERFILE = """\
FROM python:3.12-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .

EXPOSE 5000
CMD ["python", "main.py"]
"""


# ── Scenario definitions ─────────────────────────────────────────
# Each scenario has:
#   scenario_id, prompt (initial message), turns_expected,
#   trust_level_required, verification_command, expected_outcome,
#   preseed (files to place before running), follow_up_prompts (optional),
#   follow_up_condition (optional function to decide if follow-up needed)

E2E_SCENARIOS = [
    # ── Scenario 1: Simple file read (TL2) ────────────────────────
    {
        "scenario_id": "s1_file_read",
        "prompt": "What's in `/workspace/README.md`? Summarise the key sections.",
        "turns_expected": 1,
        "trust_level_required": 2,
        "preseed": {"README.md": _PRESEED_README},
        "verification_command": None,  # success = non-empty response mentioning features
        "verify_response": True,       # verify response content, not file system
        "response_must_contain": ["feature", "install"],
        "expected_outcome": "Response summarises README content",
    },

    # ── Scenario 2: Single file creation (TL3) ───────────────────
    {
        "scenario_id": "s2_file_create",
        "prompt": (
            "Create a Python hello-world script at `/workspace/hello.py` "
            "that prints 'Hello from Sentinel!' when run."
        ),
        "turns_expected": 1,
        "trust_level_required": 3,
        "preseed": {},
        "verification_command": (
            "test -f /workspace/hello.py && "
            "python3 /workspace/hello.py 2>&1 | grep -qi 'hello' && "
            "echo 'PASS'"
        ),
        "expected_outcome": "File exists and prints hello message",
    },

    # ── Scenario 3: Web search and summarise (TL2) ────────────────
    {
        "scenario_id": "s3_web_search",
        "prompt": (
            "Search the web for 'Python FastAPI tutorial' and summarise "
            "the top 3 results. Include the URL and a one-sentence summary "
            "for each."
        ),
        "turns_expected": 1,
        "trust_level_required": 2,
        "preseed": {},
        "verification_command": None,
        "verify_response": True,
        "response_must_contain": ["fastapi"],
        "expected_outcome": "Response contains FastAPI search results",
    },

    # ── Scenario 4: Write + execute script (TL4) ─────────────────
    {
        "scenario_id": "s4_write_and_run",
        "prompt": (
            "Write a Python script at `/workspace/count.py` that counts "
            "the number of lines in a given file. Then run it on "
            "`/workspace/README.md` and tell me the line count."
        ),
        "turns_expected": 1,
        "trust_level_required": 4,
        "preseed": {"README.md": _PRESEED_README},
        "verification_command": (
            "test -f /workspace/count.py && "
            "python3 /workspace/count.py /workspace/README.md 2>&1"
        ),
        "expected_outcome": "Script exists, runs, and reports line count",
    },

    # ── Scenario 5: Multi-file project + tests (TL4) ─────────────
    {
        "scenario_id": "s5_package_and_test",
        "prompt": (
            "Create a Python package at `/workspace/mylib/` with:\n"
            "1. `__init__.py`\n"
            "2. `utils.py` with two functions: `reverse_string(s)` and "
            "`count_vowels(s)`\n"
            "3. `tests/test_utils.py` with pytest tests for both functions\n"
            "Then run the tests and tell me the results."
        ),
        "turns_expected": 2,
        "trust_level_required": 4,
        "preseed": {},
        "verification_command": (
            "cd /workspace && python3 -m pytest mylib/tests/test_utils.py -v 2>&1"
        ),
        "expected_outcome": "Package created, tests pass",
    },

    # ── Scenario 6: Debug a buggy file (TL4) ─────────────────────
    {
        "scenario_id": "s6_debug_buggy",
        "prompt": (
            "There's a bug in `/workspace/buggy.py` — it crashes with a "
            "TypeError when you run it. Find the bug and fix it so it runs "
            "successfully."
        ),
        "turns_expected": 2,
        "trust_level_required": 4,
        "preseed": {"buggy.py": _PRESEED_BUGGY_PY},
        "verification_command": (
            "python3 /workspace/buggy.py 2>&1 && echo 'PASS'"
        ),
        "expected_outcome": "Fixed buggy.py runs without TypeError",
        # If the first turn doesn't fix it, prompt again
        "follow_up_prompts": [
            (
                "The script at `/workspace/buggy.py` still crashes. "
                "Please read the file, diagnose the TypeError, and fix it."
            ),
        ],
    },

    # ── Scenario 7: Container build (TL4) ────────────────────────
    {
        "scenario_id": "s7_container_build",
        "prompt": (
            "There's a Flask app in `/workspace/app/` along with a Containerfile. "
            "Examine what's there, verify the Containerfile looks correct, and "
            "list any issues you find. Then create a simple test script at "
            "`/workspace/test_app.py` that imports the Flask app and "
            "verifies the /health endpoint exists."
        ),
        "turns_expected": 2,
        "trust_level_required": 4,
        "preseed": {
            "app/main.py": _PRESEED_APP_MAIN,
            "app/requirements.txt": _PRESEED_APP_REQUIREMENTS,
            "app/Containerfile": _PRESEED_APP_CONTAINERFILE,
        },
        "verification_command": (
            "test -f /workspace/test_app.py && "
            "cd /workspace/app && python3 -c \""
            "from main import app; "
            "client = app.test_client(); "
            "resp = client.get('/health'); "
            "assert resp.status_code == 200; "
            "print('Health endpoint OK')\" 2>&1"
        ),
        "expected_outcome": "Test script created, health endpoint verified",
        "known_limitation": "Sandbox cannot run podman/docker build — no socket, no network, no privileges",
    },

    # ── Scenario 8: Routine scheduling (TL4) ─────────────────────
    {
        "scenario_id": "s8_routine_setup",
        "prompt": (
            "Create a health-check script at `/workspace/health_check.py` "
            "that checks if a file `/workspace/status.txt` exists and "
            "reports its content. The script should create the file with "
            "'healthy' if it doesn't exist, or read and print it if it does. "
            "Then run it to verify it works."
        ),
        "turns_expected": 2,
        "trust_level_required": 4,
        "preseed": {},
        "verification_command": (
            "python3 /workspace/health_check.py 2>&1 && "
            "test -f /workspace/status.txt && "
            "echo 'PASS'"
        ),
        "expected_outcome": "Health check script created, runs, creates/reads status file",
        "follow_up_prompts": [
            (
                "Good. Now run the health check script again — it should "
                "read the existing status.txt this time and report its content."
            ),
        ],
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


def check_health(base_url, timeout=HEALTH_TIMEOUT):
    """Check if the controller is healthy. Returns True/False."""
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


def run_on_host(command, timeout=VERIFICATION_TIMEOUT):
    """Run a command on the host (not inside a container).

    Returns (exit_code, stdout, stderr).
    """
    try:
        result = subprocess.run(
            ["bash", "-c", command],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return -1, "", f"Command timed out after {timeout}s"
    except Exception as e:
        return -1, "", str(e)


def cleanup_workspace():
    """Remove all files from /workspace/ inside the container."""
    exit_code, stdout, stderr = exec_in_container(
        "find /workspace -mindepth 1 -delete 2>/dev/null; echo done",
        timeout=CLEANUP_TIMEOUT,
    )
    if exit_code != 0 and "done" not in stdout:
        print(f"  WARNING: Workspace cleanup may have failed: {stderr}")


def preseed_files(file_dict):
    """Write pre-seeded files into /workspace/ inside the container.

    file_dict maps relative paths (e.g. "buggy.py" or "app/main.py")
    to file content strings.
    """
    for rel_path, content in file_dict.items():
        abs_path = f"/workspace/{rel_path}"
        # Ensure parent directory exists
        parent = str(Path(abs_path).parent)
        if parent != "/workspace":
            exec_in_container(f"mkdir -p {parent}")
        # Write file via heredoc (safe for most content)
        # Use base64 to avoid shell escaping issues
        import base64
        b64 = base64.b64encode(content.encode("utf-8")).decode("ascii")
        exit_code, stdout, stderr = exec_in_container(
            f"echo '{b64}' | base64 -d > {abs_path}"
        )
        if exit_code != 0:
            print(f"    WARNING: Failed to preseed {rel_path}: {stderr}")
        else:
            # Verify file was written
            exit_code, stdout, _ = exec_in_container(f"wc -c < {abs_path}")
            if exit_code == 0:
                size = stdout.strip()
                print(f"    Pre-seeded: {rel_path} ({size} bytes)")


# ── TL4 gate check ───────────────────────────────────────────────

TL4_GATE_RETRIES = 3
TL4_GATE_RETRY_DELAY = 15  # seconds between retries


def run_tl4_gate(base_url, pin):
    """Run a trivial shell execution test to verify TL4 is working.

    Retries up to TL4_GATE_RETRIES times with backoff to handle transient
    failures (Qwen not loaded, VRAM contention, approval mode race).
    Returns True if TL4 is operational, False only after all retries fail.
    """
    data = {
        "request": "Run 'echo hello' and return the output.",
        "source": "functional_e2e_tl4_gate",
    }
    headers = {
        "X-Sentinel-Pin": pin,
        "Origin": base_url,
    }

    for attempt in range(TL4_GATE_RETRIES):
        attempt_label = f"(attempt {attempt + 1}/{TL4_GATE_RETRIES})"
        print(f"  Running TL4 gate check: 'echo hello' {attempt_label}...")

        try:
            response, http_status = post_json(
                f"{base_url}/api/task", data, headers, timeout=120
            )
        except Exception as e:
            print(f"    TL4 gate attempt failed: {e}")
            if attempt < TL4_GATE_RETRIES - 1:
                print(f"    Retrying in {TL4_GATE_RETRY_DELAY}s...")
                time.sleep(TL4_GATE_RETRY_DELAY)
            continue

        if response is None:
            print("    TL4 gate attempt failed: no response")
            if attempt < TL4_GATE_RETRIES - 1:
                print(f"    Retrying in {TL4_GATE_RETRY_DELAY}s...")
                time.sleep(TL4_GATE_RETRY_DELAY)
            continue

        status = response.get("status", "unknown")
        if status == "success":
            # Check if the response mentions "hello"
            steps = response.get("step_results", [])
            for step in steps:
                content = step.get("content", "") or step.get("worker_response", "")
                if content and "hello" in content.lower():
                    print("    TL4 gate PASSED: shell execution working")
                    return True
            # Even if "hello" isn't in the steps, success status means TL4 works
            print("    TL4 gate PASSED: status=success")
            return True
        else:
            reason = response.get("reason", response.get("error", "unknown"))
            print(f"    TL4 gate attempt failed: status={status}, reason={reason}")
            if attempt < TL4_GATE_RETRIES - 1:
                print(f"    Retrying in {TL4_GATE_RETRY_DELAY}s...")
                time.sleep(TL4_GATE_RETRY_DELAY)

    print("    TL4 gate FAILED: all retries exhausted")
    return False


# ── Test runner ───────────────────────────────────────────────────

class E2EWorkflowTest:
    def __init__(self, base_url, pin, results_dir, version=None,
                 scenarios=None, trials=1):
        self.base_url = base_url
        self.pin = pin
        self.results_dir = Path(results_dir)
        self.version = version
        self.scenario_filter = scenarios  # None = all scenarios
        self.trials = trials
        self.stop_requested = False
        self.results_fh = None
        self.tl4_available = None  # set after gate check

        self.stats = {
            "total": 0,
            "success": 0,
            "failed": 0,
            "skipped": 0,
            "api_errors": 0,
            "blocked": 0,
            "tl4_gate_skipped": 0,
            "graduation_skipped": 0,
            "total_elapsed": 0.0,
            "total_turns": 0,
        }

    def run(self):
        """Run the E2E workflow test suite."""
        self._setup_signals()

        # Filter scenarios if specified
        scenarios = E2E_SCENARIOS
        if self.scenario_filter:
            scenarios = [
                s for s in scenarios
                if s["scenario_id"] in self.scenario_filter
                or any(
                    s["scenario_id"].startswith(f"s{n}_")
                    for n in self.scenario_filter
                    if isinstance(n, int) or (isinstance(n, str) and n.isdigit())
                )
            ]

        if not scenarios:
            print("ERROR: No scenarios selected (check --scenario filter)")
            return

        # Build queue with trials
        queue = []
        for scenario in scenarios:
            for trial in range(self.trials):
                queue.append({
                    **scenario,
                    "trial": trial + 1,
                    "total_trials": self.trials,
                })

        total_items = len(queue)
        print(f"E2E Workflow Test Suite (G3)")
        print(f"  Scenarios: {len(scenarios)} unique, {total_items} total (× trials)")
        print(f"  Trust levels needed: TL2 (s1,s3), TL3 (s2), TL4 (s4-s8)")
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
        print(f"  Container exec: OK")
        print()

        # Open results file
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.run_ts = ts  # used in source keys to isolate test sessions
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
            "test_suite": "e2e_workflow",
            "total_scenarios": len(scenarios),
            "total_items": total_items,
            "trials": self.trials,
            "scenario_ids": [s["scenario_id"] for s in scenarios],
        }
        self._write_result(header)

        print(f"\n{'='*60}")
        print(f"  E2E WORKFLOW TEST STARTING — {total_items} executions")
        print(f"{'='*60}\n")

        start_time = time.monotonic()

        # Track scenarios 1-3 results for graduation check
        early_results = {}  # scenario_id → passed (True/False/None)

        for i, item in enumerate(queue):
            if self.stop_requested:
                print(f"\n  Stop requested. Finishing after {i} executions.")
                break

            sid = item["scenario_id"]
            trial = item["trial"]
            total_trials = item["total_trials"]
            trial_label = f" (trial {trial}/{total_trials})" if total_trials > 1 else ""
            tl_req = item["trust_level_required"]

            print(f"  [{i+1}/{total_items}] {sid} (TL{tl_req}){trial_label}")

            # TL4 gate check: run once before the first TL4 scenario
            if tl_req >= 4 and self.tl4_available is None:
                self.tl4_available = run_tl4_gate(self.base_url, self.pin)
                if not self.tl4_available:
                    print("    TL4 gate failed — skipping all TL4 scenarios")

            # Skip TL4 scenarios if gate failed
            if tl_req >= 4 and not self.tl4_available:
                result = self._make_skip_result(
                    i, item, "TL4 gate check failed"
                )
                self._write_result(result)
                self._update_stats(result, is_tl4_skip=True)
                print(f"    → SKIP (TL4 not available)")
                continue

            # Graduation check: if scenarios 1-3 all failed, skip 4-8
            scenario_num = int(sid.split("_")[0][1:])
            if scenario_num >= 4 and trial == 1:
                s1_s3_results = [
                    early_results.get(f"s{n}")
                    for n in [1, 2, 3]
                    if f"s{n}" in {
                        k.split("_")[0] for k in early_results
                    }
                ]
                # If we have results for 1-3 and ALL failed
                if (
                    len(s1_s3_results) >= 3
                    and all(r is False for r in s1_s3_results)
                ):
                    result = self._make_skip_result(
                        i, item,
                        "Graduation check: scenarios 1-3 all failed"
                    )
                    self._write_result(result)
                    self._update_stats(result, is_graduation_skip=True)
                    print(f"    → SKIP (graduation: s1-s3 all failed)")
                    continue

            # Clean workspace and preseed files
            print(f"    Cleaning workspace...")
            cleanup_workspace()

            preseed = item.get("preseed", {})
            if preseed:
                preseed_files(preseed)

            # Execute the scenario (potentially multi-turn)
            result = self._execute_scenario(i, item)

            # Write result
            self._write_result(result)
            self._update_stats(result)

            # Track early scenario results for graduation
            passed = result.get("verification_passed")
            if passed is None:
                # For response-verified scenarios, check response_verified
                passed = result.get("response_verified")
            # Use the first scenario number prefix for tracking
            s_prefix = sid.split("_")[0]
            early_results[s_prefix] = passed

            # Print result
            v = result.get("verification_passed")
            rv = result.get("response_verified")
            if v is not None:
                v_str = "PASS" if v else "FAIL"
            elif rv is not None:
                v_str = "PASS" if rv else "FAIL"
            else:
                v_str = "SKIP"

            turns = result.get("turns_actual", 1)
            elapsed = result.get("elapsed_s", 0)
            steps = result.get("plan_steps", "?")
            tools = result.get("tools_used", [])
            tool_str = ", ".join(tools[:4]) if tools else "none"
            print(f"    → {v_str} ({turns} turn(s), {steps} steps, "
                  f"{elapsed}s, tools: {tool_str})")
            if v is False and result.get("verification_error"):
                err = result["verification_error"][:120]
                print(f"    → Error: {err}")

        # Write summary
        total_elapsed = time.monotonic() - start_time
        self.stats["total_elapsed"] = round(total_elapsed, 1)
        summary = {"type": "summary", **self.stats}
        self._write_result(summary)

        if self.results_fh:
            self.results_fh.close()

        self._print_summary(total_elapsed, total_items)

    def _execute_scenario(self, index, item):
        """Execute a scenario, potentially spanning multiple turns.

        Returns a result dict with all E2E-specific fields.
        """
        sid = item["scenario_id"]
        prompt = item["prompt"]
        source = f"functional_e2e_{index}_{self.run_ts}"

        result = {
            "type": "result",
            "index": index,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "test_suite": "e2e_workflow",
            "scenario_id": sid,
            "prompt": prompt,
            "prompt_preview": prompt[:150],
            "prompt_len": len(prompt),
            "trust_level_required": item["trust_level_required"],
            "turns_expected": item["turns_expected"],
            "trial": item["trial"],
        }

        # Turn 1: send initial prompt
        t0 = time.monotonic()
        turn_results = []
        all_tools = set()
        total_plan_steps = 0
        all_step_outcomes = []
        planner_usage_total = {}
        variable_threading_ok = True

        response, http_status = self._send_turn(
            prompt, source, headers={
                "X-Sentinel-Pin": self.pin,
                "Origin": self.base_url,
            }
        )

        turn_1 = self._parse_turn_response(response, http_status)
        turn_results.append(turn_1)
        all_tools.update(turn_1.get("tools", []))
        total_plan_steps += turn_1.get("step_count", 0)
        if turn_1.get("step_outcomes"):
            all_step_outcomes.extend(turn_1["step_outcomes"])
        if turn_1.get("planner_usage"):
            planner_usage_total = turn_1["planner_usage"]

        # Check if we need follow-up turns
        current_turn = 1
        need_follow_up = False

        # Run verification after first turn to decide
        if item.get("verification_command") and turn_1["status"] == "success":
            v_result = self._verify(item)
            if not v_result["verification_passed"]:
                need_follow_up = True
        elif item.get("verify_response") and turn_1["status"] == "success":
            # Check response content
            rv = self._verify_response(turn_1, item)
            if not rv:
                need_follow_up = True

        # Send follow-up turns if needed and available
        follow_ups = item.get("follow_up_prompts", [])
        follow_up_idx = 0

        while (
            need_follow_up
            and follow_up_idx < len(follow_ups)
            and current_turn < MAX_TURNS_PER_SCENARIO
            and not self.stop_requested
        ):
            current_turn += 1
            fu_prompt = follow_ups[follow_up_idx]
            follow_up_idx += 1

            print(f"    Turn {current_turn}: follow-up...")

            fu_response, fu_http = self._send_turn(
                fu_prompt, source, headers={
                    "X-Sentinel-Pin": self.pin,
                    "Origin": self.base_url,
                }
            )
            fu_turn = self._parse_turn_response(fu_response, fu_http)
            turn_results.append(fu_turn)
            all_tools.update(fu_turn.get("tools", []))
            total_plan_steps += fu_turn.get("step_count", 0)
            if fu_turn.get("step_outcomes"):
                all_step_outcomes.extend(fu_turn["step_outcomes"])

            # Re-verify after follow-up
            if item.get("verification_command") and fu_turn["status"] == "success":
                v_result = self._verify(item)
                if v_result["verification_passed"]:
                    need_follow_up = False
            elif fu_turn["status"] != "success":
                # Can't recover from error/blocked
                need_follow_up = False

        elapsed = time.monotonic() - t0

        # Build final result
        result["elapsed_s"] = round(elapsed, 2)
        result["http_status"] = turn_results[0].get("http_status", 0)
        result["turns_actual"] = current_turn
        result["tools_used"] = sorted(all_tools)
        result["plan_steps"] = total_plan_steps
        result["turn_results"] = turn_results

        if all_step_outcomes:
            result["step_outcomes"] = all_step_outcomes
        if planner_usage_total:
            result["planner_usage"] = planner_usage_total

        # Determine overall status from last meaningful turn
        last_turn = turn_results[-1]
        result["response_status"] = last_turn["status"]

        # Check for variable threading success (all steps completed)
        for tr in turn_results:
            for so in tr.get("step_outcomes", []):
                if so.get("status") == "error" and "variable" in str(so.get("error", "")).lower():
                    variable_threading_ok = False
        result["variable_threading_success"] = variable_threading_ok

        # Final verification
        if item.get("verification_command"):
            if result["response_status"] == "success":
                v_result = self._verify(item)
                result.update(v_result)
            else:
                result["verification_passed"] = None
                result["verification_command"] = item["verification_command"]
                result["verification_exit_code"] = None
                result["verification_output"] = None
                result["verification_error"] = (
                    f"Skipped: status={result['response_status']}"
                )
        elif item.get("verify_response"):
            # Verify response content rather than filesystem
            rv = self._verify_response(last_turn, item)
            result["response_verified"] = rv
            result["verification_passed"] = rv

        result["expected_outcome"] = item["expected_outcome"]
        result["known_limitation"] = item.get("known_limitation")

        return result

    def _send_turn(self, prompt, source, headers):
        """Send a single turn to the API. Returns (response_dict, http_status)."""
        data = {
            "request": prompt,
            "source": source,
        }

        for attempt in range(MAX_RETRIES):
            try:
                return post_json(
                    f"{self.base_url}/api/task",
                    data,
                    headers,
                    timeout=REQUEST_TIMEOUT,
                )
            except (ConnectionError, OSError, TimeoutError) as e:
                if attempt < MAX_RETRIES - 1:
                    wait = RETRY_DELAY_BASE * (2 ** attempt)
                    print(f"    Connection error (attempt {attempt+1}): {e}")
                    print(f"    Retrying in {wait}s...")
                    time.sleep(wait)
                    if not self._wait_for_health():
                        break
                else:
                    return None, 0

        return None, 0

    def _parse_turn_response(self, response, http_status):
        """Parse an API response into a turn result dict."""
        turn = {"http_status": http_status}

        if response is None:
            turn["status"] = "error"
            turn["error"] = "No response received"
            turn["step_count"] = 0
            return turn

        turn["status"] = response.get("status", "unknown")
        turn["plan_summary"] = response.get("plan_summary")
        turn["reason"] = response.get("reason")
        turn["error"] = response.get("error") or response.get("reason")

        # Extract response text (for response verification)
        turn["response_text"] = response.get("response", "")

        steps = response.get("step_results", [])
        turn["step_results"] = steps or []
        turn["step_count"] = len(steps) if steps else 0

        # Extract tools used from step IDs
        tools = set()
        if steps:
            for s in steps:
                step_id = s.get("step_id", "")
                # step_id format is like "tool_call:file_write" or "llm_task"
                if ":" in step_id:
                    tools.add(step_id.split(":", 1)[1])
                else:
                    tools.add(step_id)
        turn["tools"] = sorted(tools)

        step_outcomes = response.get("step_outcomes")
        if step_outcomes:
            turn["step_outcomes"] = step_outcomes

        planner_usage = response.get("planner_usage")
        if planner_usage:
            turn["planner_usage"] = planner_usage

        # Check for scanner blocks
        scanner_blocks = []
        for so in (step_outcomes or []):
            sr = so.get("scanner_result")
            if sr and sr != "clean":
                scanner_blocks.append(sr)
        if scanner_blocks:
            turn["scanner_blocks"] = scanner_blocks

        return turn

    def _verify(self, item):
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

    def _verify_response(self, turn, item):
        """Verify the response content contains expected keywords.

        Used for scenarios that check response quality, not filesystem state.
        """
        must_contain = item.get("response_must_contain", [])
        if not must_contain:
            # No specific content required, just check success
            return turn.get("status") == "success"

        response_text = (turn.get("response_text", "") or "").lower()
        plan_summary = (turn.get("plan_summary", "") or "").lower()
        combined = response_text + " " + plan_summary

        # Check step_results for display content (e.g. LLM summary steps)
        for sr in turn.get("step_results", []):
            content = (sr.get("content", "") or "").lower()
            combined += " " + content

        return all(kw.lower() in combined for kw in must_contain)

    def _make_skip_result(self, index, item, reason):
        """Create a skip result entry."""
        return {
            "type": "result",
            "index": index,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "test_suite": "e2e_workflow",
            "scenario_id": item["scenario_id"],
            "prompt": item["prompt"],
            "prompt_preview": item["prompt"][:150],
            "prompt_len": len(item["prompt"]),
            "trust_level_required": item["trust_level_required"],
            "turns_expected": item["turns_expected"],
            "trial": item["trial"],
            "elapsed_s": 0,
            "http_status": 0,
            "response_status": "skipped",
            "skip_reason": reason,
            "turns_actual": 0,
            "tools_used": [],
            "plan_steps": 0,
            "verification_passed": None,
            "variable_threading_success": None,
            "known_limitation": item.get("known_limitation"),
        }

    def _write_result(self, result):
        """Write a result line to the JSONL file with immediate flush."""
        if self.results_fh:
            self.results_fh.write(json.dumps(result, default=str) + "\n")
            self.results_fh.flush()
            os.fsync(self.results_fh.fileno())

    def _update_stats(self, result, is_tl4_skip=False, is_graduation_skip=False):
        """Update running statistics."""
        self.stats["total"] += 1

        if is_tl4_skip:
            self.stats["tl4_gate_skipped"] += 1
            self.stats["skipped"] += 1
            return
        if is_graduation_skip:
            self.stats["graduation_skipped"] += 1
            self.stats["skipped"] += 1
            return

        status = result.get("response_status", "unknown")
        v_passed = result.get("verification_passed")

        if status == "error":
            self.stats["api_errors"] += 1
        elif status == "blocked":
            self.stats["blocked"] += 1
        elif status == "skipped":
            self.stats["skipped"] += 1
        elif v_passed is True:
            self.stats["success"] += 1
        elif v_passed is False:
            self.stats["failed"] += 1
        else:
            # No verification (e.g. response-only check)
            rv = result.get("response_verified")
            if rv is True:
                self.stats["success"] += 1
            elif rv is False:
                self.stats["failed"] += 1
            else:
                self.stats["skipped"] += 1

        self.stats["total_turns"] += result.get("turns_actual", 0)

    def _wait_for_health(self, max_wait=HEALTH_WAIT_MAX):
        """Wait for the controller to become healthy."""
        start = time.monotonic()
        while time.monotonic() - start < max_wait:
            if check_health(self.base_url):
                return True
            time.sleep(5)
        return False

    def _setup_signals(self):
        """Handle SIGINT/SIGTERM for graceful shutdown."""
        def handler(signum, frame):
            sig_name = signal.Signals(signum).name
            print(f"\n  Signal {sig_name} received. Finishing current scenario...")
            self.stop_requested = True
        signal.signal(signal.SIGINT, handler)
        signal.signal(signal.SIGTERM, handler)

    def _print_summary(self, total_elapsed, queue_size):
        """Print a human-readable summary."""
        s = self.stats
        total = s["total"]
        print(f"\n{'='*60}")
        print(f"  E2E WORKFLOW TEST COMPLETE")
        print(f"{'='*60}")
        print(f"  Duration:          {total_elapsed/60:.1f} minutes")
        print(f"  Scenarios:         {total}/{queue_size}")
        if total_elapsed > 0:
            print(f"  Rate:              {total/total_elapsed*60:.1f} scenarios/min")
        print(f"  Total turns:       {s['total_turns']}")
        print()
        print(f"  Results:")
        print(f"    Passed:          {s['success']}")
        print(f"    Failed:          {s['failed']}")
        print(f"    Skipped:         {s['skipped']}")
        if s["tl4_gate_skipped"] > 0:
            print(f"      TL4 gate:      {s['tl4_gate_skipped']}")
        if s["graduation_skipped"] > 0:
            print(f"      Graduation:    {s['graduation_skipped']}")
        print(f"    API errors:      {s['api_errors']}")
        print(f"    Blocked:         {s['blocked']}")
        if total > 0:
            runnable = total - s["skipped"]
            if runnable > 0:
                pass_rate = 100 * s["success"] / runnable
                print(f"    Pass rate:       {pass_rate:.1f}% "
                      f"(of {runnable} runnable)")
        print()

        # Per-scenario summary
        print(f"  Per-scenario breakdown:")
        print(f"    {'Scenario':25s}  {'TL':>3s}  {'Status':>8s}  "
              f"{'Turns':>5s}  {'Elapsed':>8s}")
        print(f"    {'-'*25}  {'-'*3}  {'-'*8}  {'-'*5}  {'-'*8}")
        # Read back from JSONL (we've already written everything)
        # Instead, just note it's in the file
        print(f"    (See JSONL for per-scenario details)")
        print(f"{'='*60}")


# ── Main ──────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Sentinel E2E Workflow Test Suite (G3)"
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
        "--scenario", action="append", default=None,
        help=(
            "Run only specific scenarios (can be repeated). "
            "Use scenario IDs like 's1_file_read' or just numbers like '1'"
        ),
    )
    parser.add_argument(
        "--trials", type=int, default=1,
        help="Number of trials per scenario (default: 1)",
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

    # Parse scenario filter
    scenario_filter = None
    if args.scenario:
        scenario_filter = []
        for s in args.scenario:
            # Accept both "s1_file_read" and "1"
            if s.isdigit():
                scenario_filter.append(s)
            else:
                scenario_filter.append(s)

    # Run
    test = E2EWorkflowTest(
        base_url=args.url,
        pin=pin,
        results_dir=str(results_dir),
        version=args.version,
        scenarios=scenario_filter,
        trials=args.trials,
    )
    test.run()


if __name__ == "__main__":
    main()
