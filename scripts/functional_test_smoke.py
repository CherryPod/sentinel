#!/usr/bin/env python3
"""Sentinel Functional Test: Daily Smoke Test (G7)

Lightweight daily health check — 5 cherry-picked prompts, one from each
G-phase suite (G1-G5), covering every verification mode:
  - smoke_build  (G1 t1_validate_ip)  — single-turn, container exec
  - smoke_debug  (G2 debug_a1)        — multi-turn (up to 5), follow-up
  - smoke_e2e    (G3 s1_file_read)    — single-turn, response text check
  - smoke_plans  (G4 s1_explain_tcp)  — single-turn, plan quality gate
  - smoke_deps   (G5 deps_1_stdlib)   — single-turn, container exec

Excludes G6 (Security Tax) by design — security-tax is a slow comparison
test, not a smoke signal.

Spec: docs/assessments/test_proposals.md §7
Tracker: docs/design/capability-deployment-tracker.md → G7

Files produced:
  benchmarks/functional_smoke_{version}_{timestamp}.jsonl

Prerequisites:
    - sentinel + sentinel-ollama containers running on port 3001 (HTTPS)
    - SENTINEL_APPROVAL_MODE=auto (run_functional_tests.sh handles this)
    - SENTINEL_VERBOSE_RESULTS=true
    - SENTINEL_BENCHMARK_MODE=true
    - PIN in ~/.secrets/sentinel_pin.txt
    - TL4 recommended (smoke_deps needs shell exec)

Usage:
    python3 scripts/functional_test_smoke.py
    python3 scripts/functional_test_smoke.py --version v0.4.1-alpha
    python3 scripts/functional_test_smoke.py --prompt smoke_build  # single prompt
"""

import argparse
import base64
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

FILE_PREFIX = "functional_smoke"
REQUEST_TIMEOUT = 1800      # 30 min per prompt (multi-step plans: Qwen generation is slow)
HEALTH_TIMEOUT = 10
HEALTH_WAIT_MAX = 120
RETRY_DELAY_BASE = 15
MAX_RETRIES = 2
VERIFICATION_TIMEOUT = 120  # 2 min for verification commands
CLEANUP_TIMEOUT = 30        # 30s for workspace cleanup
CONTAINER_NAME = "sentinel"

# SSL context for self-signed certs
_SSL_CTX = ssl.create_default_context()
_SSL_CTX.check_hostname = False
_SSL_CTX.verify_mode = ssl.CERT_NONE

_SCRIPT_DIR = Path(__file__).resolve().parent
_PROJECT_DIR = _SCRIPT_DIR.parent


# ── Pre-seeded file content (smoke_e2e) ──────────────────────────

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


# ── Smoke prompt definitions ─────────────────────────────────────
# One prompt cherry-picked from each G1-G5 suite.
# Each prompt declares its verification_type so the runner knows which
# path to take: "exec" (container exec), "response" (text match),
# "plan" (step-count gate), or "multi_turn" (follow-up loop).

SMOKE_PROMPTS = [
    # ── smoke_build (from G1 t1_validate_ip) ─────────────────────
    # Single-turn, verification via container exec.
    {
        "prompt_id": "smoke_build",
        "source_suite": "G1",
        "source_prompt_id": "t1_validate_ip",
        "prompt": (
            "Write a Python function called `validate_ip` that validates IPv4 "
            "addresses. It should return True for valid addresses and False for "
            "invalid ones. Save it to `/workspace/validate_ip.py`"
        ),
        "verification_type": "exec",
        "verification_command": (
            "cd /workspace && python3 -c \""
            "from validate_ip import validate_ip; "
            "assert validate_ip('192.168.1.1'), '192.168.1.1 should be valid'; "
            "assert validate_ip('10.0.0.0'), '10.0.0.0 should be valid'; "
            "assert not validate_ip('999.1.1.1'), '999.1.1.1 should be invalid'; "
            "assert not validate_ip('abc'), 'abc should be invalid'; "
            "print('All assertions passed')\""
        ),
        "expected_outcome": "Exit code 0, all assertions pass",
    },

    # ── smoke_debug (from G2 debug_a1_missing_import) ────────────
    # Multi-turn (up to 5 turns). Initial prompt triggers a likely
    # ModuleNotFoundError (requests not in container), follow-up asks
    # the planner to diagnose and fix.
    {
        "prompt_id": "smoke_debug",
        "source_suite": "G2",
        "source_prompt_id": "debug_a1_missing_import",
        "prompt": (
            "Write a Python script that uses the `requests` library to fetch "
            "https://example.com and print the HTTP status code. Save it to "
            "`/workspace/fetch.py` and then run it with "
            "`python3 /workspace/fetch.py`."
        ),
        "verification_type": "multi_turn",
        "verification_command": "cd /workspace && python3 fetch.py",
        "max_turns": 5,
        "debug_followup": (
            "The previous task failed. Please diagnose the error and fix "
            "the script so it runs successfully."
        ),
        "error_indicators": [
            "requests", "ModuleNotFoundError", "no module", "urllib",
            "import error", "not installed",
        ],
        "expected_outcome": (
            "Script runs successfully after switching to urllib.request "
            "or handling the missing module"
        ),
    },

    # ── smoke_e2e (from G3 s1_file_read) ─────────────────────────
    # Single-turn, response text verification (must contain "feature"
    # and "install"). Needs README preseed.
    {
        "prompt_id": "smoke_e2e",
        "source_suite": "G3",
        "source_prompt_id": "s1_file_read",
        "prompt": "What's in `/workspace/README.md`? Summarise the key sections.",
        "verification_type": "response",
        "response_must_contain": ["feature", "install"],
        "preseed": {"README.md": _PRESEED_README},
        "expected_outcome": "Response summarises README content",
    },

    # ── smoke_plans (from G4 s1_explain_tcp) ─────────────────────
    # Single-turn, response text verification (must contain "syn" and
    # "ack"), plan quality gate (expected_steps_max=1).
    {
        "prompt_id": "smoke_plans",
        "source_suite": "G4",
        "source_prompt_id": "s1_explain_tcp",
        "prompt": "Explain how TCP's three-way handshake works.",
        "verification_type": "plan",
        "response_must_contain": ["syn", "ack"],
        "expected_steps_max": 1,
        "expected_outcome": "Response explains TCP handshake, plan is 1 step",
    },

    # ── smoke_deps (from G5 deps_1_stdlib_baseline) ──────────────
    # Single-turn, verification via container exec.
    {
        "prompt_id": "smoke_deps",
        "source_suite": "G5",
        "source_prompt_id": "deps_1_stdlib_baseline",
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
        "verification_type": "exec",
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

    file_dict maps relative paths (e.g. "README.md" or "app/main.py")
    to file content strings. Uses base64 encoding to avoid shell escaping.
    """
    for rel_path, content in file_dict.items():
        abs_path = f"/workspace/{rel_path}"
        # Ensure parent directory exists
        parent = str(Path(abs_path).parent)
        if parent != "/workspace":
            exec_in_container(f"mkdir -p {parent}")
        # Write file via base64 to avoid shell escaping issues
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


# ── Test runner ───────────────────────────────────────────────────

class DailySmokeTest:
    """Runs the 5 smoke prompts and writes JSONL results.

    Handles four verification modes:
      - exec:       run a command in the container, check exit code
      - response:   check API response text for required keywords
      - plan:       check response keywords AND step count
      - multi_turn: run follow-up turns if first turn fails verification
    """

    def __init__(self, base_url, pin, results_dir, version=None,
                 prompt_filter=None):
        self.base_url = base_url
        self.pin = pin
        self.results_dir = Path(results_dir)
        self.version = version
        self.prompt_filter = prompt_filter  # None = all prompts
        self.stop_requested = False
        self.results_fh = None

        self.stats = {
            "total": 0,
            "smoke_passed": 0,
            "smoke_failed": 0,
            "smoke_skipped": 0,
            "api_errors": 0,
            "blocked": 0,
            "total_elapsed": 0.0,
            "total_turns": 0,
            "by_suite": {},
        }

    def run(self):
        """Run the daily smoke test suite."""
        self._setup_signals()

        # Filter prompts if --prompt specified
        prompts = SMOKE_PROMPTS
        if self.prompt_filter:
            prompts = [
                p for p in prompts
                if p["prompt_id"] in self.prompt_filter
            ]

        if not prompts:
            print("ERROR: No prompts selected (check --prompt filter)")
            return

        print("Daily Smoke Test Suite (G7)")
        print(f"  Prompts: {len(prompts)}")
        for p in prompts:
            print(f"    {p['prompt_id']} ({p['source_suite']})")
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
            "test_suite": "daily_smoke",
            "total_prompts": len(prompts),
            "prompt_ids": [p["prompt_id"] for p in prompts],
        }
        self._write_result(header)

        print(f"\n{'='*60}")
        print(f"  DAILY SMOKE TEST STARTING — {len(prompts)} prompts")
        print(f"{'='*60}\n")

        start_time = time.monotonic()

        for i, item in enumerate(prompts):
            if self.stop_requested:
                print(f"\n  Stop requested. Finishing after {i} prompts.")
                break

            pid = item["prompt_id"]
            vtype = item["verification_type"]
            src = item["source_suite"]

            print(f"  [{i+1}/{len(prompts)}] {pid} ({src}, {vtype})")

            # Clean workspace before each prompt
            print(f"    Cleaning workspace...")
            cleanup_workspace()

            # Preseed files if needed
            preseed = item.get("preseed", {})
            if preseed:
                preseed_files(preseed)

            # Execute the prompt via the appropriate handler
            if vtype == "multi_turn":
                result = self._run_multi_turn(i, item)
            else:
                result = self._run_single_turn(i, item)

            # Write result
            self._write_result(result)
            self._update_stats(result)

            # Print result
            passed = result.get("smoke_passed")
            v_str = "PASS" if passed is True else ("FAIL" if passed is False else "SKIP")
            elapsed = result.get("elapsed_s", 0)
            turns = result.get("turns_actual", 1)
            steps = result.get("plan_steps", "?")
            print(f"    -> {v_str} ({turns} turn(s), {steps} steps, {elapsed}s)")
            if passed is False and result.get("verification_error"):
                err = result["verification_error"][:120]
                print(f"    -> Error: {err}")

        # Write summary
        total_elapsed = time.monotonic() - start_time
        self.stats["total_elapsed"] = round(total_elapsed, 1)
        summary = {"type": "summary", **self.stats}
        self._write_result(summary)

        if self.results_fh:
            self.results_fh.close()

        self._print_summary(total_elapsed, len(prompts))

    # ── Single-turn handler ──────────────────────────────────────

    def _run_single_turn(self, index, item):
        """Handle exec, response, and plan verification types."""
        pid = item["prompt_id"]
        prompt = item["prompt"]
        vtype = item["verification_type"]

        t0 = time.monotonic()

        # Send task to API
        response, http_status = self._send_task(
            prompt, f"functional_smoke_{index}_{self.run_ts}"
        )
        elapsed = time.monotonic() - t0

        # Build base result
        result = self._make_base_result(index, item, response, http_status, elapsed)
        result["turns_actual"] = 1

        status = result["response_status"]

        # ── Exec verification ────────────────────────────────────
        if vtype == "exec":
            if status == "success":
                v = self._verify_exec(item)
                result.update(v)
                result["smoke_passed"] = v["verification_passed"]
            else:
                result["smoke_passed"] = None
                result["verification_command"] = item.get("verification_command")
                result["verification_error"] = (
                    f"Skipped: API returned {status}"
                )

        # ── Response text verification ───────────────────────────
        elif vtype == "response":
            if status == "success":
                rv = self._verify_response(response, item)
                result["response_verified"] = rv
                result["smoke_passed"] = rv
            else:
                result["response_verified"] = None
                result["smoke_passed"] = None
                result["verification_error"] = (
                    f"Skipped: API returned {status}"
                )

        # ── Plan quality gate + response check ───────────────────
        elif vtype == "plan":
            if status == "success":
                # Check response text
                rv = self._verify_response(response, item)
                result["response_verified"] = rv

                # Check step count
                max_steps = item.get("expected_steps_max")
                step_count = result.get("plan_steps", 0)
                in_range = step_count <= max_steps if max_steps is not None else True
                result["plan_step_count_ok"] = in_range
                result["expected_steps_max"] = max_steps

                # Both must pass
                result["smoke_passed"] = rv and in_range
            else:
                result["response_verified"] = None
                result["plan_step_count_ok"] = None
                result["smoke_passed"] = None
                result["verification_error"] = (
                    f"Skipped: API returned {status}"
                )

        return result

    # ── Multi-turn handler ───────────────────────────────────────

    def _run_multi_turn(self, index, item):
        """Handle multi-turn debug verification (follow-up loop).

        Sends the initial prompt, verifies via exec, and if it fails,
        sends follow-up prompts to the same session source until either
        verification passes or max_turns is reached.
        """
        pid = item["prompt_id"]
        prompt = item["prompt"]
        max_turns = item.get("max_turns", 5)
        followup = item.get("debug_followup", "")
        source = f"functional_smoke_{index}_{self.run_ts}"

        t0 = time.monotonic()
        turn_results = []
        current_turn = 0
        passed = False

        # ── Turn 1: initial prompt ───────────────────────────────
        current_turn += 1
        response, http_status = self._send_task(prompt, source)
        turn_1 = self._parse_turn_response(response, http_status, current_turn)
        turn_results.append(turn_1)

        # Verify after turn 1
        if turn_1["status"] == "success":
            v = self._verify_exec(item)
            turn_1["verification_passed"] = v["verification_passed"]
            turn_1["verification_output"] = v.get("verification_output", "")
            turn_1["verification_error"] = v.get("verification_error")
            passed = v["verification_passed"]

        # ── Follow-up turns ──────────────────────────────────────
        while (
            not passed
            and current_turn < max_turns
            and followup
            and not self.stop_requested
        ):
            current_turn += 1
            print(f"    Turn {current_turn}: follow-up...")

            fu_response, fu_http = self._send_task(followup, source)
            fu_turn = self._parse_turn_response(fu_response, fu_http, current_turn)
            turn_results.append(fu_turn)

            # Verify after follow-up
            if fu_turn["status"] == "success":
                v = self._verify_exec(item)
                fu_turn["verification_passed"] = v["verification_passed"]
                fu_turn["verification_output"] = v.get("verification_output", "")
                fu_turn["verification_error"] = v.get("verification_error")
                passed = v["verification_passed"]
            else:
                # Can't recover from error/blocked status
                break

        elapsed = time.monotonic() - t0

        # Build result
        result = {
            "type": "result",
            "index": index,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "test_suite": "daily_smoke",
            "prompt_id": pid,
            "source_suite": item["source_suite"],
            "source_prompt_id": item["source_prompt_id"],
            "prompt": prompt,
            "prompt_preview": prompt[:150],
            "prompt_len": len(prompt),
            "verification_type": item["verification_type"],
            "elapsed_s": round(elapsed, 2),
            "http_status": turn_results[0].get("http_status", 0),
            "turns_actual": current_turn,
            "turn_results": turn_results,
            "smoke_passed": passed,
            "expected_outcome": item["expected_outcome"],
        }

        # Aggregate step count from all turns
        total_steps = sum(tr.get("step_count", 0) for tr in turn_results)
        result["plan_steps"] = total_steps

        # Set response_status from first turn (for stats)
        result["response_status"] = turn_results[0]["status"]

        # If verification never ran, mark it
        if not any(tr.get("verification_passed") is not None for tr in turn_results):
            result["smoke_passed"] = None
            result["verification_error"] = (
                f"Verification never ran: all turns returned {turn_results[-1]['status']}"
            )

        return result

    # ── Shared helpers ───────────────────────────────────────────

    def _send_task(self, prompt, source):
        """Send a task to the API with retry logic.

        Returns (response_dict_or_None, http_status).
        """
        data = {
            "request": prompt,
            "source": source,
        }
        headers = {
            "X-Sentinel-Pin": self.pin,
            "Origin": self.base_url,
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

    def _make_base_result(self, index, item, response, http_status, elapsed):
        """Build the common result fields from an API response."""
        pid = item["prompt_id"]
        prompt = item["prompt"]

        result = {
            "type": "result",
            "index": index,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "test_suite": "daily_smoke",
            "prompt_id": pid,
            "source_suite": item["source_suite"],
            "source_prompt_id": item["source_prompt_id"],
            "prompt": prompt,
            "prompt_preview": prompt[:150],
            "prompt_len": len(prompt),
            "verification_type": item["verification_type"],
            "elapsed_s": round(elapsed, 2),
            "http_status": http_status,
            "expected_outcome": item["expected_outcome"],
        }

        if response is None:
            result["response_status"] = "error"
            result["error"] = "No response received"
            result["plan_steps"] = 0
        else:
            result["response_status"] = response.get("status", "unknown")
            result["plan_summary"] = response.get("plan_summary")
            result["reason"] = response.get("reason")
            result["error"] = response.get("error") or response.get("reason")

            steps = response.get("step_results", [])
            result["plan_steps"] = len(steps) if steps else 0

            # Preserve verbose step data
            if steps:
                verbose_steps = []
                for s in steps:
                    vstep = {
                        "step_id": s.get("step_id"),
                        "status": s.get("status"),
                        "error": s.get("error"),
                    }
                    if s.get("worker_response") is not None:
                        vstep["worker_response"] = s["worker_response"]
                    if s.get("content"):
                        vstep["content"] = s["content"]
                    if s.get("quality_warnings"):
                        vstep["quality_warnings"] = s["quality_warnings"]
                    verbose_steps.append(vstep)
                result["steps"] = verbose_steps

            step_outcomes = response.get("step_outcomes")
            if step_outcomes:
                result["step_outcomes"] = step_outcomes

            planner_usage = response.get("planner_usage")
            if planner_usage:
                result["planner_usage"] = planner_usage

            # Check for scanner blocks in steps
            scanner_blocks = []
            for so in (step_outcomes or []):
                sr = so.get("scanner_result")
                if sr and sr != "clean":
                    scanner_blocks.append(sr)
            if scanner_blocks:
                result["scanner_blocks"] = scanner_blocks

        return result

    def _parse_turn_response(self, response, http_status, turn_number):
        """Parse an API response into a per-turn result dict."""
        turn = {"turn": turn_number, "http_status": http_status}

        if response is None:
            turn["status"] = "error"
            turn["error"] = "No response received"
            turn["step_count"] = 0
            return turn

        turn["status"] = response.get("status", "unknown")
        turn["plan_summary"] = response.get("plan_summary")
        turn["error"] = response.get("error") or response.get("reason")

        steps = response.get("step_results", [])
        turn["step_count"] = len(steps) if steps else 0

        step_outcomes = response.get("step_outcomes")
        if step_outcomes:
            turn["step_outcomes"] = step_outcomes

        return turn

    def _verify_exec(self, item):
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

    def _verify_response(self, response, item):
        """Verify API response text contains expected keywords.

        Checks response text, plan_summary, and step content for the
        required keywords (case-insensitive).
        """
        must_contain = item.get("response_must_contain", [])
        if not must_contain:
            # No specific content required — success status is enough
            return response is not None and response.get("status") == "success"

        # Gather all text from the response
        parts = []
        if response:
            parts.append(response.get("response", "") or "")
            parts.append(response.get("plan_summary", "") or "")

            # Check step results for content
            for step in response.get("step_results", []):
                parts.append(step.get("worker_response", "") or "")
                parts.append(step.get("content", "") or "")

        combined = " ".join(parts).lower()
        return all(kw.lower() in combined for kw in must_contain)

    def _write_result(self, result):
        """Write a result line to the JSONL file with immediate flush."""
        if self.results_fh:
            self.results_fh.write(json.dumps(result, default=str) + "\n")
            self.results_fh.flush()
            os.fsync(self.results_fh.fileno())

    def _update_stats(self, result):
        """Update running statistics."""
        self.stats["total"] += 1
        self.stats["total_turns"] += result.get("turns_actual", 1)

        suite = result.get("source_suite", "unknown")
        if suite not in self.stats["by_suite"]:
            self.stats["by_suite"][suite] = {"total": 0, "passed": 0, "failed": 0}
        bs = self.stats["by_suite"][suite]
        bs["total"] += 1

        status = result.get("response_status", "unknown")
        passed = result.get("smoke_passed")

        if status == "error":
            self.stats["api_errors"] += 1
        elif status == "blocked":
            self.stats["blocked"] += 1
        elif passed is True:
            self.stats["smoke_passed"] += 1
            bs["passed"] += 1
        elif passed is False:
            self.stats["smoke_failed"] += 1
            bs["failed"] += 1
        else:
            self.stats["smoke_skipped"] += 1

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
            print(f"\n  Signal {sig_name} received. Finishing current prompt...")
            self.stop_requested = True
        signal.signal(signal.SIGINT, handler)
        signal.signal(signal.SIGTERM, handler)

    def _print_summary(self, total_elapsed, queue_size):
        """Print a human-readable summary."""
        s = self.stats
        total = s["total"]
        print(f"\n{'='*60}")
        print(f"  DAILY SMOKE TEST COMPLETE")
        print(f"{'='*60}")
        print(f"  Duration:      {total_elapsed/60:.1f} minutes")
        print(f"  Prompts:       {total}/{queue_size}")
        if total_elapsed > 0:
            print(f"  Rate:          {total/total_elapsed*60:.1f} prompts/min")
        print(f"  Total turns:   {s['total_turns']}")
        print()
        print(f"  Results:")
        print(f"    Passed:      {s['smoke_passed']}")
        print(f"    Failed:      {s['smoke_failed']}")
        print(f"    Skipped:     {s['smoke_skipped']}")
        print(f"    API errors:  {s['api_errors']}")
        print(f"    Blocked:     {s['blocked']}")
        if total > 0:
            runnable = total - s["smoke_skipped"]
            if runnable > 0:
                pass_rate = 100 * s["smoke_passed"] / runnable
                print(f"    Pass rate:   {pass_rate:.1f}% (of {runnable} runnable)")
        print()
        if s["by_suite"]:
            print(f"  By source suite:")
            for suite in sorted(s["by_suite"].keys()):
                bs = s["by_suite"][suite]
                status = "PASS" if bs["passed"] == bs["total"] else "FAIL"
                print(f"    {suite}: {status} ({bs['passed']}/{bs['total']})")
        print(f"{'='*60}")


# ── Main ──────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Sentinel Daily Smoke Test Suite (G7)"
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
        "--prompt", action="append", default=None,
        help=(
            "Run only specific prompts (can be repeated). "
            "Use prompt IDs like 'smoke_build', 'smoke_debug', etc."
        ),
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
    test = DailySmokeTest(
        base_url=args.url,
        pin=pin,
        results_dir=str(results_dir),
        version=args.version,
        prompt_filter=args.prompt,
    )
    test.run()


if __name__ == "__main__":
    main()
