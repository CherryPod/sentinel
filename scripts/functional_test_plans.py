#!/usr/bin/env python3
"""Sentinel Functional Test: Plan Quality & Decomposition (G4)

Does the planner produce good plans — well-decomposed, appropriately
constrained, token-efficient, and structured for the worker's capabilities?

15 prompts across 3 categories:
  - Simple (5) — should NOT decompose (1 step, prose or trivial code)
  - Medium (5) — should decompose into 2-4 steps
  - Complex (5) — must decompose into 4-8 steps with module boundaries

This test inspects PLANS, not outputs. It submits prompts via the API but
only analyses the plan structure (step count, types, constraints, variable
naming, output size risk). Execution still happens (the API runs the full
pipeline), but verification is structural — no execution-based checks.

Spec: docs/assessments/test_proposals.md §4
Tracker: docs/design/capability-deployment-tracker.md → G4

Files produced:
  benchmarks/functional_plans_{version}_{timestamp}.jsonl

Prerequisites:
    - sentinel + sentinel-ollama containers running on port 3001 (HTTPS)
    - SENTINEL_APPROVAL_MODE=auto (run_functional_tests.sh handles this)
    - SENTINEL_VERBOSE_RESULTS=true
    - SENTINEL_BENCHMARK_MODE=true
    - PIN in ~/.secrets/sentinel_pin.txt
    - TL2 minimum; TL4 recommended (to test constraint generation quality)

Usage:
    python3 scripts/functional_test_plans.py
    python3 scripts/functional_test_plans.py --version v0.4.0-alpha
    python3 scripts/functional_test_plans.py --category simple
    python3 scripts/functional_test_plans.py --category medium --category complex
"""

import argparse
import json
import os
import re
import signal
import ssl
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

# ── Configuration ─────────────────────────────────────────────────

FILE_PREFIX = "functional_plans"
REQUEST_TIMEOUT = 1800      # 30 min per prompt (complex plans: 8 Qwen steps × ~200s each)
HEALTH_TIMEOUT = 10
HEALTH_WAIT_MAX = 120
RETRY_DELAY_BASE = 15
MAX_RETRIES = 2

# SSL context for self-signed certs
_SSL_CTX = ssl.create_default_context()
_SSL_CTX.check_hostname = False
_SSL_CTX.verify_mode = ssl.CERT_NONE

_SCRIPT_DIR = Path(__file__).resolve().parent
_PROJECT_DIR = _SCRIPT_DIR.parent

# Variable naming patterns
_VAR_PATTERN = re.compile(r"\$([a-zA-Z_][a-zA-Z0-9_]*)")
_GENERIC_VAR_PATTERN = re.compile(
    r"^step\d+_(?:output|result|response|data|code)$"
)


# ── Prompt definitions ────────────────────────────────────────────
# Each prompt defines expected plan shape for scoring.

PLAN_PROMPTS = [
    # ── Simple (5) — should NOT decompose ────────────────────────
    # Good plans: 1 step, llm_task, no tool calls
    {
        "prompt_id": "s1_explain_tcp",
        "prompt": "Explain how TCP's three-way handshake works.",
        "category": "simple",
        "expected_steps_min": 1,
        "expected_steps_max": 1,
    },
    {
        "prompt_id": "s2_haiku",
        "prompt": "Write a haiku about a rainy morning in autumn.",
        "category": "simple",
        "expected_steps_min": 1,
        "expected_steps_max": 1,
    },
    {
        "prompt_id": "s3_regex_explain",
        "prompt": (
            "Explain what this regex does: "
            r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$"
        ),
        "category": "simple",
        "expected_steps_min": 1,
        "expected_steps_max": 1,
    },
    {
        "prompt_id": "s4_git_rebase",
        "prompt": (
            "What is the difference between git rebase and git merge? "
            "When should you use each?"
        ),
        "category": "simple",
        "expected_steps_min": 1,
        "expected_steps_max": 1,
    },
    {
        "prompt_id": "s5_short_function",
        "prompt": (
            "Write a Python function that checks whether a string is a "
            "valid email address using a basic regex check. Save it to "
            "/workspace/validate_email.py"
        ),
        "category": "simple",
        "expected_steps_min": 1,
        "expected_steps_max": 2,
    },

    # ── Medium (5) — should decompose 2-4 steps ─────────────────
    {
        "prompt_id": "m1_rest_api",
        "prompt": (
            "Create a REST API with 3 endpoints using FastAPI:\n"
            "- GET /users — returns a list of users\n"
            "- POST /users — creates a new user with name and email\n"
            "- GET /users/{id} — returns a single user\n"
            "Save the code to /workspace/api/main.py with a Pydantic "
            "model in /workspace/api/models.py"
        ),
        "category": "medium",
        "expected_steps_min": 2,
        "expected_steps_max": 6,
    },
    {
        "prompt_id": "m2_cli_tool",
        "prompt": (
            "Build a command-line tool at /workspace/wordcount.py that:\n"
            "- Accepts a file path as an argument\n"
            "- Counts lines, words, and characters\n"
            "- Supports a --json flag to output results as JSON\n"
            "- Has proper error handling for missing files\n"
            "Use argparse for argument parsing."
        ),
        "category": "medium",
        "expected_steps_min": 1,
        "expected_steps_max": 3,
    },
    {
        "prompt_id": "m3_data_processor",
        "prompt": (
            "Create a CSV data processing pipeline at /workspace/pipeline/:\n"
            "- /workspace/pipeline/reader.py — reads CSV files\n"
            "- /workspace/pipeline/transformer.py — filters rows and adds "
            "computed columns\n"
            "- /workspace/pipeline/writer.py — writes output to a new CSV"
        ),
        "category": "medium",
        "expected_steps_min": 2,
        "expected_steps_max": 6,
    },
    {
        "prompt_id": "m4_test_suite",
        "prompt": (
            "Write a Python module at /workspace/calculator.py with functions "
            "for add, subtract, multiply, divide (with ZeroDivisionError "
            "handling). Then write a pytest test file at "
            "/workspace/test_calculator.py with at least 3 tests per function."
        ),
        "category": "medium",
        "expected_steps_min": 2,
        "expected_steps_max": 6,
    },
    {
        "prompt_id": "m5_config_system",
        "prompt": (
            "Create a configuration management system at /workspace/config/:\n"
            "- /workspace/config/schema.py — Pydantic model for app config "
            "(database, redis, logging settings)\n"
            "- /workspace/config/loader.py — loads from YAML file with env "
            "var override support\n"
            "- /workspace/config/defaults.yaml — default configuration values"
        ),
        "category": "medium",
        "expected_steps_min": 2,
        "expected_steps_max": 6,
    },

    # ── Complex (5) — must decompose 4-8 steps ──────────────────
    {
        "prompt_id": "c1_microservice",
        "prompt": (
            "Build a task management microservice at /workspace/taskservice/ "
            "with:\n"
            "1. /workspace/taskservice/models.py — SQLAlchemy models for "
            "Task (id, title, description, status, created_at, updated_at) "
            "and Tag (many-to-many)\n"
            "2. /workspace/taskservice/database.py — async SQLite connection "
            "with session factory\n"
            "3. /workspace/taskservice/crud.py — CRUD operations for tasks\n"
            "4. /workspace/taskservice/main.py — FastAPI app with 5 endpoints "
            "(list, create, get, update, delete tasks)\n"
            "5. /workspace/taskservice/tests/test_crud.py — pytest tests for "
            "the CRUD layer\n"
            "6. /workspace/taskservice/Containerfile — Python 3.12-slim, "
            "install deps, copy code, run with uvicorn"
        ),
        "category": "complex",
        "expected_steps_min": 4,
        "expected_steps_max": 8,
    },
    {
        "prompt_id": "c2_rust_http",
        "prompt": (
            "Create a Rust HTTP server at /workspace/httpserver/ with:\n"
            "1. /workspace/httpserver/Cargo.toml — dependencies for a simple "
            "HTTP server (no frameworks, use std::net::TcpListener)\n"
            "2. /workspace/httpserver/src/main.rs — TCP listener, request "
            "parser, route matching\n"
            "3. /workspace/httpserver/src/router.rs — route handler dispatch "
            "for GET /health, GET /echo, POST /json\n"
            "4. /workspace/httpserver/src/response.rs — HTTP response "
            "builder (status line, headers, body)\n"
            "5. /workspace/httpserver/src/request.rs — HTTP request parser "
            "(method, path, headers, body)\n"
            "6. /workspace/httpserver/tests/integration.rs — integration tests"
        ),
        "category": "complex",
        "expected_steps_min": 4,
        "expected_steps_max": 8,
    },
    {
        "prompt_id": "c3_full_stack",
        "prompt": (
            "Create a URL shortener service at /workspace/shortener/ with:\n"
            "1. Backend: FastAPI with endpoints POST /shorten (takes URL, "
            "returns short code), GET /{code} (redirects)\n"
            "2. Storage: SQLite with async access, table for URLs\n"
            "3. Frontend: a single index.html with a form to submit URLs "
            "and display the shortened result\n"
            "4. Tests: pytest tests for the API endpoints\n"
            "5. Containerfile: Python 3.12-slim, multi-stage if useful\n"
            "6. README.md: how to build and run"
        ),
        "category": "complex",
        "expected_steps_min": 4,
        "expected_steps_max": 8,
    },
    {
        "prompt_id": "c4_monitoring",
        "prompt": (
            "Build a system monitoring dashboard at /workspace/monitor/ with:\n"
            "1. /workspace/monitor/collector.py — collects CPU, memory, disk "
            "metrics using psutil (or os/subprocess stdlib if psutil "
            "unavailable)\n"
            "2. /workspace/monitor/storage.py — stores metrics in SQLite with "
            "timestamp, metric_name, metric_value columns\n"
            "3. /workspace/monitor/api.py — FastAPI endpoints: GET /metrics "
            "(latest), GET /metrics/history?hours=N, GET /health\n"
            "4. /workspace/monitor/dashboard.html — HTML page with charts "
            "(using inline JavaScript, no CDN dependencies)\n"
            "5. /workspace/monitor/scheduler.py — background task that "
            "collects metrics every 60 seconds\n"
            "6. /workspace/monitor/tests/test_collector.py — unit tests for "
            "the collector module"
        ),
        "category": "complex",
        "expected_steps_min": 4,
        "expected_steps_max": 8,
    },
    {
        "prompt_id": "c5_plugin_system",
        "prompt": (
            "Design and implement a plugin system at /workspace/plugins/ with:\n"
            "1. /workspace/plugins/core/registry.py — PluginRegistry class "
            "that discovers and loads plugins from a directory\n"
            "2. /workspace/plugins/core/base.py — PluginBase ABC with "
            "name, version, init(), execute(), cleanup() methods\n"
            "3. /workspace/plugins/core/manager.py — PluginManager that "
            "handles lifecycle (load, init, execute, cleanup) with error "
            "isolation per plugin\n"
            "4. /workspace/plugins/builtin/hello.py — example plugin\n"
            "5. /workspace/plugins/builtin/counter.py — stateful counter plugin\n"
            "6. /workspace/plugins/tests/test_registry.py — tests for "
            "discovery and loading\n"
            "7. /workspace/plugins/tests/test_lifecycle.py — tests for "
            "init/execute/cleanup lifecycle"
        ),
        "category": "complex",
        "expected_steps_min": 4,
        "expected_steps_max": 8,
    },
]


# ── Plan analysis functions ───────────────────────────────────────

def extract_variable_names(result):
    """Extract $variable_name patterns from plan_summary and step prompts.

    Returns a list of variable names found (without the $ prefix).
    """
    sources = []
    ps = result.get("plan_summary") or ""
    sources.append(ps)

    # Verbose step data — planner_prompt contains the step's prompt text
    # which references prior step output variables
    for step in result.get("steps", []):
        pp = step.get("planner_prompt") or ""
        sources.append(pp)
        wr = step.get("worker_response") or ""
        sources.append(wr)

    text = "\n".join(sources)
    return list(set(_VAR_PATTERN.findall(text)))


def score_variable_naming(var_names):
    """Score variable naming quality (0.0 to 1.0).

    Descriptive names like $data_models, $api_routes score 1.0.
    Generic names like $step1_output, $step2_result score 0.0.
    Mixed gets a proportional score.
    """
    if not var_names:
        return 1.0  # No variables = single step, naming is N/A (fine)

    descriptive = 0
    for name in var_names:
        if not _GENERIC_VAR_PATTERN.match(name):
            descriptive += 1

    return round(descriptive / len(var_names), 2)


def analyse_step_count(step_count, category, expected_min, expected_max):
    """Analyse whether step count is appropriate for the category.

    Returns a dict with scoring results.
    """
    in_range = expected_min <= step_count <= expected_max
    over_decomposed = step_count > expected_max
    under_decomposed = step_count < expected_min

    return {
        "step_count": step_count,
        "expected_range": f"{expected_min}-{expected_max}",
        "in_range": in_range,
        "over_decomposed": over_decomposed,
        "under_decomposed": under_decomposed,
    }


def analyse_constraints(step_outcomes):
    """Analyse constraint coverage and quality from step outcomes.

    Returns constraint analysis dict.
    """
    tool_call_steps = [
        so for so in step_outcomes
        if so.get("step_type") == "tool_call"
    ]

    if not tool_call_steps:
        return {
            "tool_call_count": 0,
            "constrained_count": 0,
            "constraint_coverage": None,
            "constraint_results": [],
        }

    constrained = 0
    results = []
    for so in tool_call_steps:
        cr = so.get("constraint_result", "skipped")
        results.append(cr)
        if cr in ("validated", "denylist_block", "violation"):
            constrained += 1

    coverage = round(constrained / len(tool_call_steps), 2) if tool_call_steps else 0.0

    return {
        "tool_call_count": len(tool_call_steps),
        "constrained_count": constrained,
        "constraint_coverage": coverage,
        "constraint_results": results,
    }


def analyse_output_size_risk(step_outcomes):
    """Check if any step produced excessively large output (token cap risk).

    output_size > 8000 chars (~200 lines) signals token cap risk.
    output_size > 12000 chars (~300 lines) is almost certainly truncated.
    """
    risky_steps = []
    for i, so in enumerate(step_outcomes):
        if so.get("step_type") != "llm_task":
            continue
        output_size = so.get("output_size", 0)
        # ~40 chars per line average for code
        estimated_lines = output_size / 40 if output_size else 0
        token_ratio = so.get("token_usage_ratio")
        truncated = token_ratio is not None and token_ratio >= 0.95

        if output_size > 8000 or truncated:
            risky_steps.append({
                "step_index": i,
                "output_size": output_size,
                "estimated_lines": round(estimated_lines),
                "token_usage_ratio": token_ratio,
                "truncated": truncated,
            })

    return {
        "risky_step_count": len(risky_steps),
        "risky_steps": risky_steps,
        "has_token_cap_risk": len(risky_steps) > 0,
    }


def analyse_step_types(step_outcomes):
    """Categorise step types."""
    types = [so.get("step_type", "unknown") for so in step_outcomes]
    return {
        "step_types": types,
        "llm_task_count": types.count("llm_task"),
        "tool_call_count": types.count("tool_call"),
    }


def analyse_context_threading(step_outcomes, var_names):
    """Check if multi-step plans properly thread context via variables.

    A plan with >1 llm_task step should use variables to pass context.
    """
    llm_steps = [so for so in step_outcomes if so.get("step_type") == "llm_task"]

    if len(llm_steps) <= 1:
        return {
            "needs_threading": False,
            "has_variables": len(var_names) > 0,
            "threading_score": 1.0,  # N/A for single-step
        }

    # Multi-step plans need variables for context threading
    has_vars = len(var_names) > 0
    return {
        "needs_threading": True,
        "has_variables": has_vars,
        "threading_score": 1.0 if has_vars else 0.0,
    }


def compute_plan_score(analysis):
    """Compute an overall plan quality score (0.0 to 1.0).

    Weighted average of individual criteria.
    """
    scores = []
    weights = []

    # Step count appropriateness (weight: 3)
    scores.append(1.0 if analysis["step_analysis"]["in_range"] else 0.0)
    weights.append(3)

    # Variable naming quality (weight: 1)
    scores.append(analysis["variable_naming_score"])
    weights.append(1)

    # Constraint coverage (weight: 2) — only at TL4
    cc = analysis["constraint_analysis"]["constraint_coverage"]
    if cc is not None:
        scores.append(cc)
        weights.append(2)

    # Output size risk (weight: 2) — 1.0 if no risky steps
    osr = analysis["output_size_risk"]
    risk_penalty = min(osr["risky_step_count"] * 0.5, 1.0)
    scores.append(1.0 - risk_penalty)
    weights.append(2)

    # Context threading (weight: 1)
    scores.append(analysis["context_threading"]["threading_score"])
    weights.append(1)

    if not weights:
        return 0.0

    weighted_sum = sum(s * w for s, w in zip(scores, weights))
    return round(weighted_sum / sum(weights), 2)


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


# ── Test runner ───────────────────────────────────────────────────

class PlanQualityTest:
    def __init__(self, base_url, pin, results_dir, version=None,
                 categories=None, trials=1):
        self.base_url = base_url
        self.pin = pin
        self.results_dir = Path(results_dir)
        self.version = version
        self.categories = categories  # None = all categories
        self.trials = trials
        self.stop_requested = False
        self.results_fh = None

        self.stats = {
            "total": 0,
            "success": 0,
            "blocked": 0,
            "error": 0,
            "refused": 0,
            "in_range": 0,
            "over_decomposed": 0,
            "under_decomposed": 0,
            "total_elapsed": 0.0,
            "plan_scores": [],
            "by_category": {},
        }

    def run(self):
        """Run the plan quality test suite."""
        self._setup_signals()

        # Filter prompts by category if specified
        prompts = PLAN_PROMPTS
        if self.categories:
            prompts = [p for p in prompts if p["category"] in self.categories]

        if not prompts:
            print("ERROR: No prompts selected (check --category filter)")
            return

        # Build queue with trials
        queue = []
        for prompt_def in prompts:
            for trial in range(self.trials):
                queue.append({
                    **prompt_def,
                    "trial": trial + 1,
                    "total_trials": self.trials,
                })

        total_prompts = len(queue)
        cat_summary = {}
        for q in queue:
            cat_summary.setdefault(q["category"], 0)
            cat_summary[q["category"]] += 1

        print("Plan Quality & Decomposition Test Suite (G4)")
        print(f"  Prompts: {total_prompts} ({len(prompts)} unique × {self.trials} trial(s))")
        for c in ("simple", "medium", "complex"):
            if c in cat_summary:
                print(f"    {c}: {cat_summary[c]} executions")
        print()

        # Wait for health
        print(f"Checking controller health at {self.base_url}...")
        if not self._wait_for_health():
            print("ERROR: Controller is not healthy. Aborting.")
            return

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
            "test_suite": "plan_quality",
            "total_prompts": total_prompts,
            "unique_prompts": len(prompts),
            "categories": sorted(cat_summary.keys()),
            "trials": self.trials,
        }
        self._write_result(header)

        print(f"\n{'='*60}")
        print(f"  PLAN QUALITY TEST STARTING — {total_prompts} executions")
        print(f"{'='*60}\n")

        start_time = time.monotonic()

        for i, item in enumerate(queue):
            if self.stop_requested:
                print(f"\n  Stop requested. Finishing after {i} executions.")
                break

            pid = item["prompt_id"]
            category = item["category"]
            trial = item["trial"]
            total_trials = item["total_trials"]
            trial_label = f" (trial {trial}/{total_trials})" if total_trials > 1 else ""

            print(f"  [{i+1}/{total_prompts}] {pid} ({category}){trial_label}")

            # Send task to API
            result = self._execute_prompt(i, item)

            # Analyse the plan structure
            analysis = self._analyse_plan(result, item)
            result.update(analysis)

            # Write result
            self._write_result(result)
            self._update_stats(result)

            # Print result summary
            sc = result.get("plan_score", "?")
            steps = result.get("step_count", "?")
            exp = result.get("expected_range", "?")
            in_range = result.get("in_range")
            range_str = "OK" if in_range else "OUT"
            elapsed = result.get("elapsed_s", 0)
            print(f"    → {steps} steps (expected {exp}) [{range_str}] score={sc} ({elapsed}s)")

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
            "source": f"functional_plans_{index}_{self.run_ts}",
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
            "test_suite": "plan_quality",
            "prompt_id": pid,
            "prompt": prompt,
            "prompt_preview": prompt[:150],
            "prompt_len": len(prompt),
            "category": item["category"],
            "trial": item["trial"],
            "elapsed_s": round(elapsed, 2),
            "http_status": http_status,
            "expected_steps_min": item["expected_steps_min"],
            "expected_steps_max": item["expected_steps_max"],
        }

        if response is None:
            result["response_status"] = "error"
            result["error"] = error_msg or "No response received"
            result["step_count"] = 0
        else:
            result["response_status"] = response.get("status", "unknown")
            result["plan_summary"] = response.get("plan_summary")
            result["reason"] = response.get("reason")
            result["error"] = response.get("error") or response.get("reason")

            steps = response.get("step_results", [])
            result["step_count"] = len(steps) if steps else 0

            # Preserve verbose step data for analysis
            if steps:
                verbose_steps = []
                for s in steps:
                    vstep = {
                        "step_id": s.get("step_id"),
                        "status": s.get("status"),
                        "error": s.get("error"),
                        "planner_prompt": s.get("planner_prompt"),
                        "worker_response": s.get("worker_response"),
                        "worker_usage": s.get("worker_usage"),
                        "quality_warnings": s.get("quality_warnings"),
                    }
                    verbose_steps.append(vstep)
                result["steps"] = verbose_steps

            step_outcomes = response.get("step_outcomes", [])
            if step_outcomes:
                result["step_outcomes"] = step_outcomes

            planner_usage = response.get("planner_usage")
            if planner_usage:
                result["planner_usage"] = planner_usage

        return result

    def _analyse_plan(self, result, item):
        """Analyse plan quality and return scoring fields."""
        step_count = result.get("step_count", 0)
        step_outcomes = result.get("step_outcomes", [])
        category = item["category"]

        # Handle non-success responses
        if result.get("response_status") not in ("success",):
            return {
                "step_analysis": {
                    "step_count": step_count,
                    "expected_range": f"{item['expected_steps_min']}-{item['expected_steps_max']}",
                    "in_range": False,
                    "over_decomposed": False,
                    "under_decomposed": False,
                },
                "step_type_analysis": {"step_types": [], "llm_task_count": 0, "tool_call_count": 0},
                "variable_names": [],
                "variable_naming_score": 0.0,
                "constraint_analysis": {
                    "tool_call_count": 0, "constrained_count": 0,
                    "constraint_coverage": None, "constraint_results": [],
                },
                "output_size_risk": {"risky_step_count": 0, "risky_steps": [], "has_token_cap_risk": False},
                "context_threading": {"needs_threading": False, "has_variables": False, "threading_score": 0.0},
                "plan_score": 0.0,
                "in_range": False,
                "over_decomposed": False,
                "under_decomposed": False,
                "expected_range": f"{item['expected_steps_min']}-{item['expected_steps_max']}",
            }

        # Run analyses
        step_analysis = analyse_step_count(
            step_count, category,
            item["expected_steps_min"], item["expected_steps_max"],
        )
        step_type_analysis = analyse_step_types(step_outcomes)
        var_names = extract_variable_names(result)
        var_score = score_variable_naming(var_names)
        constraint_analysis = analyse_constraints(step_outcomes)
        output_size_risk = analyse_output_size_risk(step_outcomes)
        context_threading = analyse_context_threading(step_outcomes, var_names)

        analysis = {
            "step_analysis": step_analysis,
            "step_type_analysis": step_type_analysis,
            "variable_names": var_names,
            "variable_naming_score": var_score,
            "constraint_analysis": constraint_analysis,
            "output_size_risk": output_size_risk,
            "context_threading": context_threading,
        }

        # Compute overall plan score
        plan_score = compute_plan_score(analysis)
        analysis["plan_score"] = plan_score

        # Top-level convenience fields for easy JSONL querying
        analysis["in_range"] = step_analysis["in_range"]
        analysis["over_decomposed"] = step_analysis["over_decomposed"]
        analysis["under_decomposed"] = step_analysis["under_decomposed"]
        analysis["expected_range"] = step_analysis["expected_range"]
        analysis["constraint_coverage"] = constraint_analysis["constraint_coverage"]
        analysis["has_token_cap_risk"] = output_size_risk["has_token_cap_risk"]

        return analysis

    def _write_result(self, result):
        """Write a result line to the JSONL file with immediate flush."""
        if self.results_fh:
            self.results_fh.write(json.dumps(result, default=str) + "\n")
            self.results_fh.flush()
            os.fsync(self.results_fh.fileno())

    def _update_stats(self, result):
        """Update running statistics."""
        self.stats["total"] += 1
        category = result.get("category", "unknown")

        if category not in self.stats["by_category"]:
            self.stats["by_category"][category] = {
                "total": 0, "success": 0, "in_range": 0,
                "over": 0, "under": 0, "scores": [],
            }
        c = self.stats["by_category"][category]
        c["total"] += 1

        status = result.get("response_status", "unknown")
        if status == "success":
            self.stats["success"] += 1
            c["success"] += 1
        elif status == "blocked":
            self.stats["blocked"] += 1
        elif status == "refused":
            self.stats["refused"] += 1
        else:
            self.stats["error"] += 1

        if result.get("in_range"):
            self.stats["in_range"] += 1
            c["in_range"] += 1
        if result.get("over_decomposed"):
            self.stats["over_decomposed"] += 1
            c["over"] += 1
        if result.get("under_decomposed"):
            self.stats["under_decomposed"] += 1
            c["under"] += 1

        plan_score = result.get("plan_score")
        if plan_score is not None:
            self.stats["plan_scores"].append(plan_score)
            c["scores"].append(plan_score)

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
        successful = s["success"]

        print(f"\n{'='*60}")
        print(f"  PLAN QUALITY TEST COMPLETE")
        print(f"{'='*60}")
        print(f"  Duration:         {total_elapsed/60:.1f} minutes")
        print(f"  Executions:       {total}/{queue_size}")
        if total_elapsed > 0:
            print(f"  Rate:             {total/total_elapsed*60:.1f} prompts/min")
        print()
        print(f"  API Results:")
        print(f"    Success:        {s['success']}")
        print(f"    Blocked:        {s['blocked']}")
        print(f"    Refused:        {s['refused']}")
        print(f"    Error:          {s['error']}")
        print()
        print(f"  Decomposition:")
        print(f"    In range:       {s['in_range']}/{successful} "
              f"({100*s['in_range']/successful:.0f}%)" if successful > 0 else
              f"    In range:       N/A")
        print(f"    Over-decomposed: {s['over_decomposed']}")
        print(f"    Under-decomposed: {s['under_decomposed']}")
        print()

        if s["plan_scores"]:
            import statistics
            avg_score = statistics.mean(s["plan_scores"])
            print(f"  Plan Quality:")
            print(f"    Avg score:      {avg_score:.2f}")
            print(f"    Min score:      {min(s['plan_scores']):.2f}")
            print(f"    Max score:      {max(s['plan_scores']):.2f}")
            print()

        print(f"  By category:")
        print(f"    {'Category':10s}  {'Total':>5s}  {'OK':>5s}  {'Over':>5s}  "
              f"{'Under':>5s}  {'Avg Score':>9s}  {'Range %':>7s}")
        print(f"    {'-'*10}  {'-'*5}  {'-'*5}  {'-'*5}  "
              f"{'-'*5}  {'-'*9}  {'-'*7}")
        for cat in ("simple", "medium", "complex"):
            if cat not in s["by_category"]:
                continue
            c = s["by_category"][cat]
            avg = f"{statistics.mean(c['scores']):.2f}" if c["scores"] else "N/A"
            rate = f"{100*c['in_range']/c['total']:.0f}%" if c["total"] > 0 else "N/A"
            print(
                f"    {cat:10s}  {c['total']:5d}  {c['in_range']:5d}  "
                f"{c['over']:5d}  {c['under']:5d}  {avg:>9s}  {rate:>7s}"
            )
        print(f"{'='*60}")


# ── Main ──────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Sentinel Plan Quality & Decomposition Test Suite (G4)"
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
        "--category", action="append", default=None,
        help="Run only specific categories (can be repeated: --category simple --category medium)",
    )
    parser.add_argument(
        "--trials", type=int, default=1,
        help="Number of trials per prompt (default: 1)",
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
    test = PlanQualityTest(
        base_url=args.url,
        pin=pin,
        results_dir=str(results_dir),
        version=args.version,
        categories=args.category,
        trials=args.trials,
    )
    test.run()


if __name__ == "__main__":
    main()
