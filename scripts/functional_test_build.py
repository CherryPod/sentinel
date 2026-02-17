#!/usr/bin/env python3
"""Sentinel Functional Test: Build Capability (G1)

Can Sentinel create artifacts that actually work? 13 prompts across 3 tiers:
  - Tier 1: Single file creation (5 prompts) — compile/parse/run verification
  - Tier 2: Multi-file project (5 prompts) — cross-file coordination
  - Tier 3: Container build & run (3 prompts) — full container lifecycle

SWE-bench-style execution-based verification — generated code is compiled/run,
not just graded. This is the most important gap: existing benchmarks grade
output text but never execute it.

Spec: docs/assessments/test_proposals.md §1
Tracker: docs/design/capability-deployment-tracker.md → G1

Files produced:
  benchmarks/functional_build_{version}_{timestamp}.jsonl

Prerequisites:
    - sentinel + sentinel-ollama containers running on port 3001 (HTTPS)
    - SENTINEL_APPROVAL_MODE=auto (run_functional_tests.sh handles this)
    - SENTINEL_VERBOSE_RESULTS=true
    - SENTINEL_BENCHMARK_MODE=true
    - PIN in ~/.secrets/sentinel_pin.txt
    - TL3 minimum (Tier 1-2), TL4 for Tier 3

Usage:
    python3 scripts/functional_test_build.py
    python3 scripts/functional_test_build.py --version v0.4.0-alpha --trials 3
    python3 scripts/functional_test_build.py --tier 1           # Tier 1 only
    python3 scripts/functional_test_build.py --tier 1 --tier 2  # Tier 1+2 only
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

FILE_PREFIX = "functional_build"
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


# ── Prompt definitions ────────────────────────────────────────────
# Each prompt has: prompt_id, prompt, tier, verification_command,
# expected_outcome (human-readable), cleanup (optional extra cleanup)

BUILD_PROMPTS = [
    # ── Tier 1: Single File Creation (5 prompts) ──────────────────
    {
        "prompt_id": "t1_validate_ip",
        "prompt": (
            "Write a Python function called `validate_ip` that validates IPv4 "
            "addresses. It should return True for valid addresses and False for "
            "invalid ones. Save it to `/workspace/validate_ip.py`"
        ),
        "tier": 1,
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
    {
        "prompt_id": "t1_json_config",
        "prompt": (
            "Create a JSON config file at `/workspace/config.json` with the "
            "following fields: database host, port (integer), username, and a "
            "list of allowed origins (at least 2 entries)"
        ),
        "tier": 1,
        "verification_command": (
            "python3 -c \""
            "import json; "
            "d = json.load(open('/workspace/config.json')); "
            "has_host = any(k for k in d if 'host' in k.lower()); "
            "assert has_host, f'Missing host-related key in {list(d.keys())}'; "
            "has_port = any(k for k in d if 'port' in k.lower()); "
            "assert has_port, f'Missing port-related key in {list(d.keys())}'; "
            "origins = None; "
            "[origins := v for k, v in d.items() if 'origin' in k.lower() and isinstance(v, list)]; "
            "assert origins and len(origins) >= 2, "
            "'Need at least 2 allowed origins'; "
            "print('Valid JSON config')\""
        ),
        "expected_outcome": "Valid JSON with required keys",
    },
    {
        "prompt_id": "t1_bash_setup",
        "prompt": (
            "Write a bash script at `/workspace/setup.sh` that creates a "
            "directory structure with three directories: src/, tests/, and docs/. "
            "All directories should be created under /workspace/"
        ),
        "tier": 1,
        "verification_command": (
            "bash /workspace/setup.sh && "
            "test -d /workspace/src && "
            "test -d /workspace/tests && "
            "test -d /workspace/docs && "
            "echo 'All directories created'"
        ),
        "expected_outcome": "Directories src/, tests/, docs/ exist",
    },
    {
        "prompt_id": "t1_gitignore",
        "prompt": (
            "Create a `.gitignore` file at `/workspace/.gitignore` for a Python "
            "project. Include entries for: venv/, __pycache__/, .env, *.pyc, "
            "*.egg-info/, dist/, and build/"
        ),
        "tier": 1,
        "verification_command": (
            "grep -q '__pycache__' /workspace/.gitignore && "
            "grep -q '.env' /workspace/.gitignore && "
            "grep -q 'venv' /workspace/.gitignore && "
            "grep -qF '*.pyc' /workspace/.gitignore && "
            "echo 'All required patterns present'"
        ),
        "expected_outcome": "Required gitignore patterns present",
    },
    {
        "prompt_id": "t1_rust_binary_search",
        "prompt": (
            "Write a Rust function in `/workspace/src/lib.rs` that implements "
            "binary search on a sorted slice of i32. The function should be "
            "called `binary_search_sorted` and return `Option<usize>` with the "
            "index of the target element. Create the `/workspace/src/` directory "
            "if needed"
        ),
        "tier": 1,
        "verification_command": (
            "rustc --edition 2021 /workspace/src/lib.rs --crate-type lib "
            "-o /tmp/test_lib.rlib 2>&1 && echo 'Compilation successful'"
        ),
        "expected_outcome": "Compiles without errors",
    },

    # ── Tier 2: Multi-File Project (5 prompts) ────────────────────
    {
        "prompt_id": "t2_python_package",
        "prompt": (
            "Create a Python package at `/workspace/mylib/` with:\n"
            "1. `__init__.py` that imports from utils\n"
            "2. `utils.py` with 3 helper functions: `slugify(text)` that "
            "converts text to URL slugs, `truncate(text, length)` that "
            "truncates with ellipsis, and `is_palindrome(text)` that checks "
            "for palindromes\n"
            "3. `tests/test_utils.py` with pytest tests for each function "
            "(at least 2 tests per function)"
        ),
        "tier": 2,
        "verification_command": (
            "cd /workspace && python3 -m pytest mylib/tests/test_utils.py -v 2>&1"
        ),
        "expected_outcome": "All pytest tests pass",
    },
    {
        "prompt_id": "t2_static_website",
        "prompt": (
            "Build a static HTML website at `/workspace/site/` with:\n"
            "1. `index.html` — a page with a heading, a paragraph, and a "
            "counter button\n"
            "2. `style.css` — basic styling (background colour, centred content, "
            "button styling)\n"
            "3. `app.js` — JavaScript that increments a counter display when "
            "the button is clicked\n"
            "The HTML must link to both the CSS and JS files using relative paths"
        ),
        "tier": 2,
        "verification_command": (
            "test -f /workspace/site/index.html && "
            "test -f /workspace/site/style.css && "
            "test -f /workspace/site/app.js && "
            "grep -q 'link.*style.css' /workspace/site/index.html && "
            "grep -q 'script.*app.js' /workspace/site/index.html && "
            "echo 'All files present with correct references'"
        ),
        "expected_outcome": "All files exist with correct cross-references",
    },
    {
        "prompt_id": "t2_fastapi_app",
        "prompt": (
            "Create a FastAPI application at `/workspace/api/` with:\n"
            "1. `main.py` — a FastAPI app with 3 endpoints: "
            "GET /health (returns {'status': 'ok'}), "
            "GET /items (returns a list), "
            "POST /items (creates an item with name and price fields)\n"
            "2. `models.py` — Pydantic models for Item (name: str, price: float)\n"
            "3. `requirements.txt` — listing fastapi and uvicorn"
        ),
        "tier": 2,
        "verification_command": (
            "cd /workspace/api && python3 -c \""
            "from main import app; "
            "from models import Item; "
            "assert hasattr(app, 'routes'), 'No routes found'; "
            "item = Item(name='test', price=9.99); "
            "assert item.name == 'test'; "
            "print('Import chain valid, models work')\""
        ),
        "expected_outcome": "Import chain valid, Pydantic models work",
    },
    {
        "prompt_id": "t2_makefile_c_project",
        "prompt": (
            "Write a Makefile-driven C project at `/workspace/calc/` with:\n"
            "1. `main.c` — a program that calls add() and multiply() then "
            "prints results\n"
            "2. `math_ops.c` — implements add(int, int) and multiply(int, int)\n"
            "3. `math_ops.h` — header file with function declarations\n"
            "4. `Makefile` — builds the project with gcc, target name `calc`"
        ),
        "tier": 2,
        "verification_command": (
            "cd /workspace/calc && make 2>&1 && "
            "test -f calc && echo 'Build successful'"
        ),
        "expected_outcome": "make builds successfully, binary exists",
    },
    {
        "prompt_id": "t2_compose_stack",
        "prompt": (
            "Create a podman-compose.yaml at `/workspace/stack/podman-compose.yaml` "
            "that defines:\n"
            "1. A Python web app service using python:3.12-slim image\n"
            "2. A Redis service using redis:7-alpine image\n"
            "3. An internal network connecting both services\n"
            "The web app should have a dependency on Redis"
        ),
        "tier": 2,
        "verification_command": (
            "python3 -c \""
            "import yaml; "
            "d = yaml.safe_load(open('/workspace/stack/podman-compose.yaml')); "
            "assert 'services' in d, 'Missing services key'; "
            "svcs = d['services']; "
            "assert len(svcs) >= 2, f'Expected >=2 services, got {len(svcs)}'; "
            "print(f'Valid compose: {len(svcs)} services')\""
        ),
        "expected_outcome": "Valid compose YAML with >= 2 services",
    },

    # ── Tier 3: Container Build & Run (3 prompts) ─────────────────
    # NOTE: Tier 3 verification checks file existence and content correctness
    # but does NOT run `podman build` — podman is not available inside the
    # sentinel container, and host-side builds would require copying files out.
    # Full container lifecycle testing (build + run) is deferred to when TL4
    # is active and a host-side verification path is implemented.
    {
        "prompt_id": "t3_simple_container",
        "prompt": (
            "Create a Containerfile at `/workspace/hello/Containerfile` for a "
            "Python 3.12-slim image that runs a simple HTTP server on port 8080. "
            "Also create `/workspace/hello/requirements.txt` with flask listed. "
            "The Containerfile should: use a non-root user, copy requirements.txt "
            "and install dependencies, then copy the app code"
        ),
        "tier": 3,
        "verification_command": (
            "test -f /workspace/hello/Containerfile && "
            "test -f /workspace/hello/requirements.txt && "
            "grep -qi 'FROM.*python' /workspace/hello/Containerfile && "
            "grep -qi 'flask' /workspace/hello/requirements.txt && "
            "echo 'Containerfile and requirements present and valid'"
        ),
        "expected_outcome": "Containerfile and requirements.txt exist with correct content",
        "cleanup": "podman rmi test-hello 2>/dev/null || true",
    },
    {
        "prompt_id": "t3_flask_webapp",
        "prompt": (
            "Write a complete Flask app at `/workspace/webapp/` with:\n"
            "1. `Containerfile` — Python 3.12-slim base, install requirements, "
            "copy app, expose port 5000, run with flask run --host 0.0.0.0\n"
            "2. `app.py` — Flask app with a /health endpoint that returns "
            "JSON {'status': 'ok', 'service': 'webapp'}\n"
            "3. `requirements.txt` — listing flask\n"
            "4. `.containerignore` — ignoring __pycache__, .git, *.pyc"
        ),
        "tier": 3,
        "verification_command": (
            "test -f /workspace/webapp/Containerfile && "
            "test -f /workspace/webapp/app.py && "
            "test -f /workspace/webapp/requirements.txt && "
            "test -f /workspace/webapp/.containerignore && "
            "grep -q 'health' /workspace/webapp/app.py && "
            "echo 'All webapp files present'"
        ),
        "expected_outcome": "All files present with health endpoint",
        "cleanup": (
            "podman stop test-webapp-run 2>/dev/null || true; "
            "podman rm test-webapp-run 2>/dev/null || true; "
            "podman rmi test-webapp 2>/dev/null || true"
        ),
    },
    {
        "prompt_id": "t3_multistage_rust",
        "prompt": (
            "Create a multi-stage Containerfile at `/workspace/rustapp/Containerfile` "
            "that:\n"
            "1. Stage 1 (builder): uses rust:1.75 image, creates a new binary "
            "project with cargo init, builds in release mode\n"
            "2. Stage 2 (runtime): uses debian:bookworm-slim, copies the "
            "compiled binary from the builder stage, runs it\n"
            "Also create a simple `/workspace/rustapp/src/main.rs` that prints "
            "'Hello from Rust container'"
        ),
        "tier": 3,
        "verification_command": (
            "test -f /workspace/rustapp/Containerfile && "
            "test -f /workspace/rustapp/src/main.rs && "
            "grep -q 'FROM.*rust' /workspace/rustapp/Containerfile && "
            "grep -qi 'FROM.*debian\\|FROM.*slim\\|FROM.*distroless' /workspace/rustapp/Containerfile && "
            "echo 'Multi-stage Containerfile present'"
        ),
        "expected_outcome": "Multi-stage Containerfile with builder + runtime stages",
        "cleanup": "podman rmi test-rustapp 2>/dev/null || true",
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

    Used for Tier 3 cleanup where podman commands must run on the host.
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


# ── Test runner ───────────────────────────────────────────────────

class BuildCapabilityTest:
    def __init__(self, base_url, pin, results_dir, version=None,
                 tiers=None, trials=1):
        self.base_url = base_url
        self.pin = pin
        self.results_dir = Path(results_dir)
        self.version = version
        self.tiers = tiers  # None = all tiers
        self.trials = trials
        self.stop_requested = False
        self.results_fh = None

        self.stats = {
            "total": 0,
            "verification_passed": 0,
            "verification_failed": 0,
            "verification_skipped": 0,
            "api_errors": 0,
            "blocked": 0,
            "total_elapsed": 0.0,
            "by_tier": {},
        }

    def run(self):
        """Run the build capability test suite."""
        self._setup_signals()

        # Filter prompts by tier if specified
        prompts = BUILD_PROMPTS
        if self.tiers:
            prompts = [p for p in prompts if p["tier"] in self.tiers]

        if not prompts:
            print("ERROR: No prompts selected (check --tier filter)")
            return

        # Build queue with trials
        queue = []
        for prompt_def in prompts:
            tier = prompt_def["tier"]
            # Tier 1 gets configurable trials, Tier 2-3 get 1 trial
            # (unless --trials overrides for all)
            num_trials = self.trials if tier == 1 else min(self.trials, 1)
            if self.trials > 1:
                # If user explicitly set trials > 1, apply to all
                num_trials = self.trials
            for trial in range(num_trials):
                queue.append({
                    **prompt_def,
                    "trial": trial + 1,
                    "total_trials": num_trials,
                })

        total_prompts = len(queue)
        tier_summary = {}
        for q in queue:
            tier_summary.setdefault(q["tier"], 0)
            tier_summary[q["tier"]] += 1

        print(f"Build Capability Test Suite (G1)")
        print(f"  Prompts: {total_prompts} ({len(prompts)} unique × trials)")
        for t in sorted(tier_summary):
            print(f"    Tier {t}: {tier_summary[t]} executions")
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
            "test_suite": "build_capability",
            "total_prompts": total_prompts,
            "unique_prompts": len(prompts),
            "tiers": sorted(tier_summary.keys()),
            "trials_per_tier": {
                str(t): tier_summary[t] // sum(
                    1 for p in prompts if p["tier"] == t
                )
                for t in tier_summary
            },
        }
        self._write_result(header)

        print(f"\n{'='*60}")
        print(f"  BUILD CAPABILITY TEST STARTING — {total_prompts} executions")
        print(f"{'='*60}\n")

        start_time = time.monotonic()

        for i, item in enumerate(queue):
            if self.stop_requested:
                print(f"\n  Stop requested. Finishing after {i} executions.")
                break

            pid = item["prompt_id"]
            tier = item["tier"]
            trial = item["trial"]
            total_trials = item["total_trials"]
            trial_label = f" (trial {trial}/{total_trials})" if total_trials > 1 else ""

            print(f"  [{i+1}/{total_prompts}] {pid} (Tier {tier}){trial_label}")

            # Clean workspace before each prompt
            print(f"    Cleaning workspace...")
            cleanup_workspace()

            # Send task to API
            result = self._execute_prompt(i, item)

            # Run verification
            if result["response_status"] == "success":
                v_result = self._verify(item)
                result.update(v_result)
            else:
                result["verification_passed"] = None
                result["verification_command"] = item["verification_command"]
                result["verification_exit_code"] = None
                result["verification_output"] = None
                result["verification_error"] = (
                    f"Skipped: API returned {result['response_status']}"
                )

            # Write result
            self._write_result(result)
            self._update_stats(result)

            # Per-prompt cleanup (e.g. container images for Tier 3)
            # Tier 3 cleanup runs podman commands which must execute on the
            # host, not inside the container (podman isn't available there)
            extra_cleanup = item.get("cleanup")
            if extra_cleanup:
                run_on_host(extra_cleanup, timeout=CLEANUP_TIMEOUT)

            # Print result
            v = result.get("verification_passed")
            v_str = "PASS" if v is True else ("FAIL" if v is False else "SKIP")
            elapsed = result.get("elapsed_s", 0)
            steps = result.get("plan_steps", "?")
            print(f"    → {v_str} ({steps} steps, {elapsed}s)")
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

        self._print_summary(total_elapsed, total_prompts)

    def _execute_prompt(self, index, item):
        """Send a prompt to the API and return the result dict."""
        prompt = item["prompt"]
        pid = item["prompt_id"]

        data = {
            "request": prompt,
            "source": f"functional_build_{index}_{self.run_ts}",
        }
        headers = {
            "X-Sentinel-Pin": self.pin,
            "Origin": self.base_url,
        }

        t0 = time.monotonic()
        response = None
        http_status = 0
        error_msg = None

        for attempt in range(MAX_RETRIES):
            try:
                response, http_status = post_json(
                    f"{self.base_url}/api/task",
                    data,
                    headers,
                    timeout=REQUEST_TIMEOUT,
                )
                break
            except (ConnectionError, OSError, TimeoutError) as e:
                error_msg = str(e)
                if attempt < MAX_RETRIES - 1:
                    wait = RETRY_DELAY_BASE * (2 ** attempt)
                    print(f"    Connection error (attempt {attempt+1}): {e}")
                    print(f"    Retrying in {wait}s...")
                    time.sleep(wait)
                    if not self._wait_for_health():
                        break

        elapsed = time.monotonic() - t0

        result = {
            "type": "result",
            "index": index,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "test_suite": "build_capability",
            "prompt_id": pid,
            "prompt": prompt,
            "prompt_preview": prompt[:150],
            "prompt_len": len(prompt),
            "tier": item["tier"],
            "trial": item["trial"],
            "elapsed_s": round(elapsed, 2),
            "http_status": http_status,
        }

        if response is None:
            result["response_status"] = "error"
            result["error"] = error_msg or "No response received"
            result["plan_steps"] = 0
        else:
            result["response_status"] = response.get("status", "unknown")
            result["plan_summary"] = response.get("plan_summary")
            result["reason"] = response.get("reason")
            result["error"] = response.get("error") or response.get("reason")

            steps = response.get("step_results", [])
            result["plan_steps"] = len(steps) if steps else 0
            result["step_count"] = result["plan_steps"]

            # Extract step types
            if steps:
                step_types = []
                verbose_steps = []
                for s in steps:
                    stype = s.get("step_id", "unknown")
                    step_types.append(stype)
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
                    if s.get("worker_usage"):
                        vstep["worker_usage"] = s["worker_usage"]
                    verbose_steps.append(vstep)
                result["plan_step_types"] = step_types
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

    def _verify(self, item):
        """Run the verification command in a disposable sandbox container."""
        v_cmd = item["verification_command"]
        exit_code, stdout, stderr = exec_in_sandbox(v_cmd)

        # Combine stdout and stderr for output
        output = stdout.strip()
        if stderr.strip():
            output += "\n--- stderr ---\n" + stderr.strip()

        passed = exit_code == 0

        return {
            "verification_command": v_cmd,
            "verification_exit_code": exit_code,
            "verification_passed": passed,
            "verification_output": output[:2000],  # truncate long output
            "verification_error": stderr.strip()[:500] if not passed else None,
        }

    def _write_result(self, result):
        """Write a result line to the JSONL file with immediate flush."""
        if self.results_fh:
            self.results_fh.write(json.dumps(result, default=str) + "\n")
            self.results_fh.flush()
            os.fsync(self.results_fh.fileno())

    def _update_stats(self, result):
        """Update running statistics."""
        self.stats["total"] += 1
        tier = result.get("tier", 0)
        tier_key = f"tier_{tier}"

        if tier_key not in self.stats["by_tier"]:
            self.stats["by_tier"][tier_key] = {
                "total": 0, "passed": 0, "failed": 0,
                "skipped": 0, "errors": 0, "blocked": 0,
            }
        t = self.stats["by_tier"][tier_key]
        t["total"] += 1

        status = result.get("response_status", "unknown")
        v_passed = result.get("verification_passed")

        if status == "error":
            self.stats["api_errors"] += 1
            t["errors"] += 1
        elif status == "blocked":
            self.stats["blocked"] += 1
            t["blocked"] += 1
        elif v_passed is True:
            self.stats["verification_passed"] += 1
            t["passed"] += 1
        elif v_passed is False:
            self.stats["verification_failed"] += 1
            t["failed"] += 1
        else:
            self.stats["verification_skipped"] += 1
            t["skipped"] += 1

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
        print(f"  BUILD CAPABILITY TEST COMPLETE")
        print(f"{'='*60}")
        print(f"  Duration:      {total_elapsed/60:.1f} minutes")
        print(f"  Executions:    {total}/{queue_size}")
        if total_elapsed > 0:
            print(f"  Rate:          {total/total_elapsed*60:.1f} prompts/min")
        print()
        print(f"  Results:")
        print(f"    Passed:      {s['verification_passed']}")
        print(f"    Failed:      {s['verification_failed']}")
        print(f"    Skipped:     {s['verification_skipped']}")
        print(f"    API errors:  {s['api_errors']}")
        print(f"    Blocked:     {s['blocked']}")
        if total > 0:
            pass_rate = 100 * s["verification_passed"] / total
            print(f"    Pass rate:   {pass_rate:.1f}%")
        print()

        print(f"  By tier:")
        print(f"    {'Tier':8s}  {'Total':>5s}  {'Pass':>5s}  {'Fail':>5s}  "
              f"{'Skip':>5s}  {'Err':>5s}  {'Blk':>5s}  {'Rate':>6s}")
        print(f"    {'-'*8}  {'-'*5}  {'-'*5}  {'-'*5}  "
              f"{'-'*5}  {'-'*5}  {'-'*5}  {'-'*6}")
        for tier_key in sorted(s["by_tier"].keys()):
            t = s["by_tier"][tier_key]
            rate = f"{100*t['passed']/t['total']:.0f}%" if t["total"] > 0 else "N/A"
            print(
                f"    {tier_key:8s}  {t['total']:5d}  {t['passed']:5d}  "
                f"{t['failed']:5d}  {t['skipped']:5d}  {t['errors']:5d}  "
                f"{t['blocked']:5d}  {rate:>6s}"
            )
        print(f"{'='*60}")


# ── Main ──────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Sentinel Build Capability Test Suite (G1)"
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
        "--tier", type=int, action="append", default=None,
        help="Run only specific tiers (can be repeated: --tier 1 --tier 2)",
    )
    parser.add_argument(
        "--trials", type=int, default=1,
        help="Number of trials per prompt (default: 1, spec recommends 3 for Tier 1)",
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
    test = BuildCapabilityTest(
        base_url=args.url,
        pin=pin,
        results_dir=str(results_dir),
        version=args.version,
        tiers=args.tier,
        trials=args.trials,
    )
    test.run()


if __name__ == "__main__":
    main()
