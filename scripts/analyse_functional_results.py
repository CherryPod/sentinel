#!/usr/bin/env python3
"""Sentinel Functional Test Analysis — Phase G Results Reporting

Reads JSONL output from functional test suites (G1-G7, including G6 security
tax dual-config analysis) and generates
Markdown reports with metrics, per-prompt breakdowns, and regression
detection vs a saved baseline.

Compatible with the existing benchmark analysis pipeline — extends rather
than replaces analyse_benchmark_results.py.

Usage:
    python3 scripts/analyse_functional_results.py benchmarks/functional_build_*.jsonl
    python3 scripts/analyse_functional_results.py benchmarks/functional_build_*.jsonl --baseline benchmarks/functional_build_baseline.jsonl
"""

import argparse
import json
import statistics
import sys
from datetime import datetime, timezone
from pathlib import Path


# ── JSONL loading ─────────────────────────────────────────────────

def load_jsonl(path):
    """Load a functional test JSONL file. Returns (header, results)."""
    header = None
    results = []
    with open(path) as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError as e:
                print(f"  WARNING: Skipping malformed line {line_num}: {e}")
                continue
            if entry.get("type") == "header":
                header = entry
            elif entry.get("type") == "result":
                results.append(entry)
            # Skip summary lines
    return header, results


def load_baseline(path):
    """Load a baseline JSONL and return a dict keyed by prompt_id."""
    if path is None:
        return None
    p = Path(path)
    if not p.exists():
        print(f"  WARNING: Baseline file not found: {path}")
        return None
    _, results = load_jsonl(p)
    baseline = {}
    for r in results:
        pid = r.get("prompt_id") or r.get("scenario_id")
        if pid:
            baseline[pid] = r
    return baseline


# ── Regression detection ──────────────────────────────────────────

def check_regression(result, baseline_entry):
    """Check if a result has regressed vs the baseline.

    A regression is:
    - verification_passed / convergence went from True to False
    - execution_turns or fix_cycle_count increased by >50%
    """
    if baseline_entry is None:
        return None  # no baseline to compare

    # Verification / convergence regression
    for field in ("verification_passed", "convergence"):
        baseline_val = baseline_entry.get(field)
        current_val = result.get(field)
        if baseline_val is True and current_val is False:
            return True

    # Turn count regression (G1 style)
    baseline_turns = baseline_entry.get("execution_turns", 0)
    current_turns = result.get("execution_turns", 0)
    if baseline_turns and baseline_turns > 0:
        if current_turns > baseline_turns * 1.5:
            return True

    # Fix-cycle regression (G2 style)
    baseline_cycles = baseline_entry.get("fix_cycle_count", 0)
    current_cycles = result.get("fix_cycle_count", 0)
    if baseline_cycles and baseline_cycles > 0:
        if current_cycles > baseline_cycles * 1.5:
            return True

    return False


# ── Metrics computation ───────────────────────────────────────────

def compute_build_metrics(results):
    """Compute metrics for the build capability suite (G1)."""
    metrics = {
        "total": len(results),
        "by_tier": {},
        "verification_passed": 0,
        "verification_failed": 0,
        "verification_skipped": 0,
        "api_errors": 0,
        "blocked": 0,
        "planner_tokens_total": 0,
        "worker_tokens_total": 0,
        "latency_values": [],
        "step_counts": [],
        "regressions": 0,
        "regression_details": [],
    }

    for r in results:
        tier = r.get("tier", "unknown")
        if tier not in metrics["by_tier"]:
            metrics["by_tier"][tier] = {
                "total": 0, "passed": 0, "failed": 0,
                "skipped": 0, "errors": 0, "blocked": 0,
            }
        t = metrics["by_tier"][tier]
        t["total"] += 1

        status = r.get("response_status", "unknown")
        v_passed = r.get("verification_passed")

        if status == "error":
            metrics["api_errors"] += 1
            t["errors"] += 1
        elif status == "blocked":
            metrics["blocked"] += 1
            t["blocked"] += 1
        elif v_passed is True:
            metrics["verification_passed"] += 1
            t["passed"] += 1
        elif v_passed is False:
            metrics["verification_failed"] += 1
            t["failed"] += 1
        else:
            metrics["verification_skipped"] += 1
            t["skipped"] += 1

        # Tokens
        planner = r.get("planner_usage", {})
        worker_tokens = 0
        for step in r.get("steps", []):
            wu = step.get("worker_usage", {})
            worker_tokens += wu.get("eval_count", 0)
        metrics["planner_tokens_total"] += planner.get("input_tokens", 0) + planner.get("output_tokens", 0)
        metrics["worker_tokens_total"] += worker_tokens

        # Latency
        elapsed = r.get("elapsed_s")
        if elapsed and elapsed > 0:
            metrics["latency_values"].append(elapsed)

        # Step count
        sc = r.get("plan_steps") or r.get("step_count", 0)
        if sc:
            metrics["step_counts"].append(sc)

        # Regression
        reg = r.get("regression_vs_baseline")
        if reg is True:
            metrics["regressions"] += 1
            metrics["regression_details"].append(r.get("prompt_id", "unknown"))

    return metrics


def compute_e2e_metrics(results):
    """Compute metrics for the E2E workflow suite (G3)."""
    metrics = {
        "total": len(results),
        "passed": 0,
        "failed": 0,
        "skipped": 0,
        "api_errors": 0,
        "blocked": 0,
        "tl4_gate_skipped": 0,
        "graduation_skipped": 0,
        "latency_values": [],
        "step_counts": [],
        "turn_counts": [],
        "turns_expected_total": 0,
        "turns_actual_total": 0,
        "tools_seen": {},
        "variable_threading_ok": 0,
        "variable_threading_fail": 0,
        "regressions": 0,
        "regression_details": [],
        "by_trust_level": {},
    }

    for r in results:
        status = r.get("response_status", "unknown")
        v_passed = r.get("verification_passed")
        tl = r.get("trust_level_required", "?")

        # Per-TL tracking
        tl_key = f"TL{tl}"
        if tl_key not in metrics["by_trust_level"]:
            metrics["by_trust_level"][tl_key] = {
                "total": 0, "passed": 0, "failed": 0, "skipped": 0,
            }
        tl_bucket = metrics["by_trust_level"][tl_key]
        tl_bucket["total"] += 1

        if status == "skipped":
            metrics["skipped"] += 1
            tl_bucket["skipped"] += 1
            skip_reason = r.get("skip_reason", "")
            if "TL4 gate" in skip_reason:
                metrics["tl4_gate_skipped"] += 1
            elif "Graduation" in skip_reason or "graduation" in skip_reason:
                metrics["graduation_skipped"] += 1
        elif status == "error":
            metrics["api_errors"] += 1
            tl_bucket["failed"] += 1
        elif status == "blocked":
            metrics["blocked"] += 1
            tl_bucket["failed"] += 1
        elif v_passed is True:
            metrics["passed"] += 1
            tl_bucket["passed"] += 1
        elif v_passed is False:
            metrics["failed"] += 1
            tl_bucket["failed"] += 1
        else:
            metrics["skipped"] += 1
            tl_bucket["skipped"] += 1

        # Latency
        elapsed = r.get("elapsed_s")
        if elapsed and elapsed > 0:
            metrics["latency_values"].append(elapsed)

        # Steps
        sc = r.get("plan_steps", 0)
        if sc:
            metrics["step_counts"].append(sc)

        # Turns
        turns_actual = r.get("turns_actual", 0)
        turns_expected = r.get("turns_expected", 0)
        if turns_actual:
            metrics["turn_counts"].append(turns_actual)
        metrics["turns_actual_total"] += turns_actual
        metrics["turns_expected_total"] += turns_expected

        # Tools
        for tool in r.get("tools_used", []):
            metrics["tools_seen"][tool] = metrics["tools_seen"].get(tool, 0) + 1

        # Variable threading
        vt = r.get("variable_threading_success")
        if vt is True:
            metrics["variable_threading_ok"] += 1
        elif vt is False:
            metrics["variable_threading_fail"] += 1

        # Regression
        reg = r.get("regression_vs_baseline")
        if reg is True:
            metrics["regressions"] += 1
            metrics["regression_details"].append(r.get("scenario_id", "unknown"))

    return metrics


def compute_plan_metrics(results):
    """Compute metrics for the plan quality suite (G4)."""
    metrics = {
        "total": len(results),
        "success": 0,
        "blocked": 0,
        "error": 0,
        "refused": 0,
        "in_range": 0,
        "over_decomposed": 0,
        "under_decomposed": 0,
        "plan_scores": [],
        "variable_naming_scores": [],
        "constraint_coverages": [],
        "token_cap_risk_count": 0,
        "latency_values": [],
        "step_counts": [],
        "by_category": {},
        "regressions": 0,
        "regression_details": [],
    }

    for r in results:
        category = r.get("category", "unknown")
        if category not in metrics["by_category"]:
            metrics["by_category"][category] = {
                "total": 0, "success": 0, "in_range": 0,
                "over": 0, "under": 0, "scores": [],
                "var_scores": [], "constraint_covs": [],
                "token_cap_risks": 0, "step_counts": [],
            }
        c = metrics["by_category"][category]
        c["total"] += 1

        status = r.get("response_status", "unknown")
        if status == "success":
            metrics["success"] += 1
            c["success"] += 1
        elif status == "blocked":
            metrics["blocked"] += 1
        elif status == "refused":
            metrics["refused"] += 1
        else:
            metrics["error"] += 1

        # Decomposition
        if r.get("in_range"):
            metrics["in_range"] += 1
            c["in_range"] += 1
        if r.get("over_decomposed"):
            metrics["over_decomposed"] += 1
            c["over"] += 1
        if r.get("under_decomposed"):
            metrics["under_decomposed"] += 1
            c["under"] += 1

        # Scores
        ps = r.get("plan_score")
        if ps is not None:
            metrics["plan_scores"].append(ps)
            c["scores"].append(ps)

        vns = r.get("variable_naming_score")
        if vns is not None:
            metrics["variable_naming_scores"].append(vns)
            c["var_scores"].append(vns)

        cc = r.get("constraint_coverage")
        if cc is not None:
            metrics["constraint_coverages"].append(cc)
            c["constraint_covs"].append(cc)

        if r.get("has_token_cap_risk"):
            metrics["token_cap_risk_count"] += 1
            c["token_cap_risks"] += 1

        # Step count
        sc = r.get("step_count", 0)
        if sc:
            metrics["step_counts"].append(sc)
            c["step_counts"].append(sc)

        # Latency
        elapsed = r.get("elapsed_s")
        if elapsed and elapsed > 0:
            metrics["latency_values"].append(elapsed)

        # Regression
        if r.get("regression_vs_baseline") is True:
            metrics["regressions"] += 1
            metrics["regression_details"].append(r.get("prompt_id", "unknown"))

    # Derived rates (avoid ZeroDivisionError)
    s = metrics["success"] or 1
    metrics["decomposition_accuracy"] = round(metrics["in_range"] / s, 3)
    metrics["over_decomp_rate"] = round(metrics["over_decomposed"] / s, 3)
    metrics["under_decomp_rate"] = round(metrics["under_decomposed"] / s, 3)
    metrics["avg_plan_score"] = (
        round(statistics.mean(metrics["plan_scores"]), 3) if metrics["plan_scores"] else 0.0
    )
    metrics["avg_var_naming"] = (
        round(statistics.mean(metrics["variable_naming_scores"]), 3)
        if metrics["variable_naming_scores"] else 0.0
    )
    metrics["avg_constraint_coverage"] = (
        round(statistics.mean(metrics["constraint_coverages"]), 3)
        if metrics["constraint_coverages"] else None
    )
    metrics["token_cap_risk_rate"] = round(metrics["token_cap_risk_count"] / s, 3)

    return metrics


def compute_debug_metrics(results):
    """Compute metrics for the debugging & error recovery suite (G2)."""
    metrics = {
        "total": len(results),
        "by_category": {},
        "converged": 0,
        "not_converged": 0,
        "api_errors": 0,
        "fix_cycle_counts": [],
        "diagnosis_accurate_count": 0,
        "diagnosis_inaccurate_count": 0,
        "diagnosis_na_count": 0,
        "stderr_used_count": 0,
        "stderr_not_used_count": 0,
        "stderr_na_count": 0,
        "privacy_violations": 0,
        "planner_tokens_total": 0,
        "worker_tokens_total": 0,
        "latency_values": [],
        "turns_values": [],
        "regressions": 0,
        "regression_details": [],
    }

    for r in results:
        cat = r.get("category", "?")
        if cat not in metrics["by_category"]:
            metrics["by_category"][cat] = {
                "total": 0, "converged": 0, "not_converged": 0,
                "errors": 0, "fix_cycles": [], "turns": [],
                "diagnosis_accurate": 0, "diagnosis_inaccurate": 0,
                "diagnosis_na": 0,
            }
        c = metrics["by_category"][cat]
        c["total"] += 1

        # Convergence
        if r.get("convergence"):
            metrics["converged"] += 1
            c["converged"] += 1
        elif r.get("error"):
            metrics["api_errors"] += 1
            c["errors"] += 1
        else:
            metrics["not_converged"] += 1
            c["not_converged"] += 1

        # Fix cycles
        fcc = r.get("fix_cycle_count")
        if fcc is not None:
            metrics["fix_cycle_counts"].append(fcc)
            c["fix_cycles"].append(fcc)

        # Turns
        turns = r.get("turns_total")
        if turns is not None:
            metrics["turns_values"].append(turns)
            c["turns"].append(turns)

        # Diagnosis accuracy
        da = r.get("diagnosis_accurate")
        if da is True:
            metrics["diagnosis_accurate_count"] += 1
            c["diagnosis_accurate"] += 1
        elif da is False:
            metrics["diagnosis_inaccurate_count"] += 1
            c["diagnosis_inaccurate"] += 1
        else:
            metrics["diagnosis_na_count"] += 1
            c["diagnosis_na"] += 1

        # stderr usage
        su = r.get("stderr_used_in_diagnosis")
        if su is True:
            metrics["stderr_used_count"] += 1
        elif su is False:
            metrics["stderr_not_used_count"] += 1
        else:
            metrics["stderr_na_count"] += 1

        # Privacy
        if r.get("privacy_boundary_held") is False:
            metrics["privacy_violations"] += 1

        # Tokens
        metrics["planner_tokens_total"] += r.get("total_planner_tokens", 0)
        metrics["worker_tokens_total"] += r.get("total_worker_tokens", 0)

        # Latency
        elapsed = r.get("elapsed_s")
        if elapsed and elapsed > 0:
            metrics["latency_values"].append(elapsed)

        # Regression
        reg = r.get("regression_vs_baseline")
        if reg is True:
            metrics["regressions"] += 1
            metrics["regression_details"].append(r.get("prompt_id", "unknown"))

    return metrics


def load_package_usage(path):
    """Load the package_usage entry from a deps JSONL file."""
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue
            if entry.get("type") == "package_usage":
                return entry
    return None


def compute_deps_metrics(results):
    """Compute metrics for the dependency management suite (G5)."""
    metrics = {
        "total": len(results),
        "by_dep_type": {},
        "verification_passed": 0,
        "verification_failed": 0,
        "api_errors": 0,
        "install_attempted_count": 0,
        "fallback_strategies": {},
        "adaptation_successful_count": 0,
        "adaptation_failed_count": 0,
        "adaptation_na_count": 0,
        "missing_dep_detected_count": 0,
        "missing_dep_not_detected_count": 0,
        "silent_failure_count": 0,
        "privacy_violations": 0,
        "planner_tokens_total": 0,
        "worker_tokens_total": 0,
        "latency_values": [],
        "turns_values": [],
        "regressions": 0,
        "regression_details": [],
    }

    for r in results:
        dep_type = r.get("dependency_type", "unknown")
        if dep_type not in metrics["by_dep_type"]:
            metrics["by_dep_type"][dep_type] = {
                "total": 0, "passed": 0, "failed": 0, "errors": 0,
                "adapted": 0, "install_attempted": 0,
                "missing_detected": 0, "silent_failures": 0,
            }
        d = metrics["by_dep_type"][dep_type]
        d["total"] += 1

        v_passed = r.get("verification_passed")
        if v_passed is True:
            metrics["verification_passed"] += 1
            d["passed"] += 1
        elif v_passed is False:
            metrics["verification_failed"] += 1
            d["failed"] += 1
        else:
            metrics["api_errors"] += 1
            d["errors"] += 1

        # Install attempted
        if r.get("install_attempted"):
            metrics["install_attempted_count"] += 1
            d["install_attempted"] += 1

        # Fallback strategy
        fs = r.get("fallback_strategy", "none")
        metrics["fallback_strategies"][fs] = (
            metrics["fallback_strategies"].get(fs, 0) + 1
        )

        # Adaptation
        adapt = r.get("adaptation_successful")
        if adapt is True:
            metrics["adaptation_successful_count"] += 1
            d["adapted"] += 1
        elif adapt is False:
            metrics["adaptation_failed_count"] += 1
        else:
            metrics["adaptation_na_count"] += 1

        # Missing dep detection (only relevant for non-stdlib types)
        if r.get("missing_dep_detected"):
            metrics["missing_dep_detected_count"] += 1
            d["missing_detected"] += 1
        elif dep_type in ("missing", "pre-installed"):
            metrics["missing_dep_not_detected_count"] += 1

        # Silent failure
        if r.get("silent_failure"):
            metrics["silent_failure_count"] += 1
            d["silent_failures"] += 1

        # Privacy
        if r.get("privacy_boundary_held") is False:
            metrics["privacy_violations"] += 1

        # Tokens
        metrics["planner_tokens_total"] += r.get("total_planner_tokens", 0)
        metrics["worker_tokens_total"] += r.get("total_worker_tokens", 0)

        # Latency
        elapsed = r.get("elapsed_s")
        if elapsed and elapsed > 0:
            metrics["latency_values"].append(elapsed)

        # Turns
        turns = r.get("turns_total")
        if turns is not None:
            metrics["turns_values"].append(turns)

        # Regression
        if r.get("regression_vs_baseline") is True:
            metrics["regressions"] += 1
            metrics["regression_details"].append(r.get("prompt_id", "unknown"))

    # Derived rates
    stdlib = metrics["by_dep_type"].get("stdlib", {})
    stdlib_total = stdlib.get("total", 0)
    metrics["stdlib_success_rate"] = (
        round(stdlib.get("passed", 0) / stdlib_total, 3) if stdlib_total else None
    )

    preinstalled = metrics["by_dep_type"].get("pre-installed", {})
    pi_total = preinstalled.get("total", 0)
    metrics["preinstalled_success_rate"] = (
        round(preinstalled.get("passed", 0) / pi_total, 3) if pi_total else None
    )

    detect_total = (
        metrics["missing_dep_detected_count"]
        + metrics["missing_dep_not_detected_count"]
    )
    metrics["missing_dep_detection_rate"] = (
        round(metrics["missing_dep_detected_count"] / detect_total, 3)
        if detect_total else None
    )

    adapt_total = (
        metrics["adaptation_successful_count"]
        + metrics["adaptation_failed_count"]
    )
    metrics["adaptation_rate"] = (
        round(metrics["adaptation_successful_count"] / adapt_total, 3)
        if adapt_total else None
    )

    metrics["silent_failure_rate"] = (
        round(metrics["silent_failure_count"] / metrics["total"], 3)
        if metrics["total"] else 0.0
    )

    return metrics


def compute_security_tax_metrics(results):
    """Compute metrics for the security tax suite (G6).

    Splits results by config (defended / baseline), computes per-config and
    per-category success rates, latency stats, token stats, scanner block
    counts, and the overall security tax (utility delta).
    """
    metrics = {
        "total": len(results),
        "by_config": {},     # "defended" / "baseline" sub-dicts
        "by_category": {},   # per-category breakdown across both configs
        "scanner_fp": {},    # per-scanner false-positive contribution
        "regressions": 0,
        "regression_details": [],
    }

    for r in results:
        config = r.get("config", "unknown")
        cat = r.get("category", "unknown")
        status = r.get("response_status", "unknown")

        # ── Per-config aggregation ────────────────────────────────
        if config not in metrics["by_config"]:
            metrics["by_config"][config] = {
                "total": 0, "success": 0, "blocked": 0,
                "error": 0, "refused": 0,
                "latency_values": [],
                "planner_tokens": 0, "worker_tokens": 0,
            }
        cfg = metrics["by_config"][config]
        cfg["total"] += 1
        if status == "success":
            cfg["success"] += 1
        elif status == "blocked":
            cfg["blocked"] += 1
        elif status == "error":
            cfg["error"] += 1
        elif status == "refused":
            cfg["refused"] += 1

        elapsed = r.get("elapsed_s")
        if elapsed and elapsed > 0:
            cfg["latency_values"].append(elapsed)
        cfg["planner_tokens"] += r.get("planner_tokens", 0)
        cfg["worker_tokens"] += r.get("worker_tokens", 0)

        # ── Per-category × config ─────────────────────────────────
        cat_key = (cat, config)
        if cat_key not in metrics["by_category"]:
            metrics["by_category"][cat_key] = {
                "total": 0, "success": 0, "blocked": 0,
                "error": 0, "refused": 0,
            }
        cc = metrics["by_category"][cat_key]
        cc["total"] += 1
        if status == "success":
            cc["success"] += 1
        elif status == "blocked":
            cc["blocked"] += 1
        elif status == "error":
            cc["error"] += 1
        elif status == "refused":
            cc["refused"] += 1

        # ── Per-scanner FP tracking (defended config only) ────────
        if config == "defended":
            for block in r.get("scanner_blocks", []):
                metrics["scanner_fp"][block] = (
                    metrics["scanner_fp"].get(block, 0) + 1
                )

        # ── Regression ────────────────────────────────────────────
        if r.get("regression_vs_baseline") is True:
            metrics["regressions"] += 1
            metrics["regression_details"].append(r.get("prompt_id", "?"))

    # ── Derived: security tax calculation ─────────────────────────
    defended = metrics["by_config"].get("defended", {})
    baseline = metrics["by_config"].get("baseline", {})

    d_total = defended.get("total", 0)
    b_total = baseline.get("total", 0)

    d_success_rate = defended.get("success", 0) / d_total if d_total else 0.0
    b_success_rate = baseline.get("success", 0) / b_total if b_total else 0.0

    # Security tax = baseline utility - defended utility (positive = cost)
    metrics["defended_success_rate"] = round(d_success_rate, 4)
    metrics["baseline_success_rate"] = round(b_success_rate, 4)
    metrics["security_tax_pct"] = round(
        (b_success_rate - d_success_rate) * 100, 2
    )

    # Latency overhead
    d_lat = _latency_stats(defended.get("latency_values", []))
    b_lat = _latency_stats(baseline.get("latency_values", []))
    metrics["defended_latency"] = d_lat
    metrics["baseline_latency"] = b_lat
    if b_lat["avg"] > 0:
        metrics["latency_overhead_pct"] = round(
            (d_lat["avg"] - b_lat["avg"]) / b_lat["avg"] * 100, 1
        )
    else:
        metrics["latency_overhead_pct"] = 0.0

    # Token overhead
    d_tokens = defended.get("planner_tokens", 0) + defended.get("worker_tokens", 0)
    b_tokens = baseline.get("planner_tokens", 0) + baseline.get("worker_tokens", 0)
    metrics["defended_tokens_total"] = d_tokens
    metrics["baseline_tokens_total"] = b_tokens
    if b_tokens > 0:
        metrics["token_overhead_pct"] = round(
            (d_tokens - b_tokens) / b_tokens * 100, 1
        )
    else:
        metrics["token_overhead_pct"] = 0.0

    return metrics


def compute_generic_metrics(results):
    """Compute generic metrics for any functional test suite."""
    metrics = {
        "total": len(results),
        "success": sum(1 for r in results if r.get("response_status") == "success"),
        "blocked": sum(1 for r in results if r.get("response_status") == "blocked"),
        "error": sum(1 for r in results if r.get("response_status") == "error"),
        "refused": sum(1 for r in results if r.get("response_status") == "refused"),
        "verification_passed": sum(1 for r in results if r.get("verification_passed") is True),
        "verification_failed": sum(1 for r in results if r.get("verification_passed") is False),
        "latency_values": [r["elapsed_s"] for r in results if r.get("elapsed_s")],
        "regressions": sum(1 for r in results if r.get("regression_vs_baseline") is True),
    }
    return metrics


# ── Report generation ─────────────────────────────────────────────

def _pct(n, total):
    """Format a percentage string."""
    if total == 0:
        return "N/A"
    return f"{100 * n / total:.1f}%"


def _latency_stats(values):
    """Compute latency statistics."""
    if not values:
        return {"avg": 0, "median": 0, "p95": 0, "min": 0, "max": 0}
    sorted_v = sorted(values)
    p95_idx = int(len(sorted_v) * 0.95)
    return {
        "avg": round(statistics.mean(sorted_v), 1),
        "median": round(statistics.median(sorted_v), 1),
        "p95": round(sorted_v[min(p95_idx, len(sorted_v) - 1)], 1),
        "min": round(sorted_v[0], 1),
        "max": round(sorted_v[-1], 1),
    }


def generate_build_report(header, results, metrics, output_path):
    """Generate a Markdown report for the build capability suite."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    version = header.get("version", "unknown") if header else "unknown"
    lat = _latency_stats(metrics["latency_values"])

    total = metrics["total"]
    passed = metrics["verification_passed"]
    failed = metrics["verification_failed"]
    skipped = metrics["verification_skipped"]
    errors = metrics["api_errors"]
    blocked = metrics["blocked"]

    lines = []
    lines.append(f"# Functional Test Report: Build Capability (G1)")
    lines.append(f"")
    lines.append(f"**Version:** {version}")
    lines.append(f"**Generated:** {now}")
    lines.append(f"**Prompts:** {total}")
    lines.append(f"**Source JSONL:** `{header.get('source_file', 'N/A')}`" if header else "")
    lines.append(f"")
    lines.append(f"---")
    lines.append(f"")

    # Summary
    lines.append(f"## Summary")
    lines.append(f"")
    lines.append(f"| Metric | Value |")
    lines.append(f"|--------|-------|")
    lines.append(f"| Total prompts | {total} |")
    lines.append(f"| Verification passed | {passed} ({_pct(passed, total)}) |")
    lines.append(f"| Verification failed | {failed} ({_pct(failed, total)}) |")
    lines.append(f"| Verification skipped | {skipped} |")
    lines.append(f"| API errors | {errors} |")
    lines.append(f"| Blocked by scanners | {blocked} |")
    if metrics["regressions"] > 0:
        lines.append(f"| **Regressions vs baseline** | **{metrics['regressions']}** |")
    lines.append(f"| Avg latency | {lat['avg']}s |")
    lines.append(f"| Median latency | {lat['median']}s |")
    lines.append(f"| P95 latency | {lat['p95']}s |")
    if metrics["step_counts"]:
        lines.append(f"| Avg plan steps | {statistics.mean(metrics['step_counts']):.1f} |")
    lines.append(f"| Total planner tokens | {metrics['planner_tokens_total']:,} |")
    lines.append(f"| Total worker tokens | {metrics['worker_tokens_total']:,} |")
    lines.append(f"")

    # Per-tier breakdown
    lines.append(f"## By Tier")
    lines.append(f"")
    lines.append(f"| Tier | Total | Passed | Failed | Errors | Blocked | Pass Rate |")
    lines.append(f"|------|-------|--------|--------|--------|---------|-----------|")
    for tier_key in sorted(metrics["by_tier"].keys()):
        t = metrics["by_tier"][tier_key]
        rate = _pct(t["passed"], t["total"])
        lines.append(
            f"| {tier_key} | {t['total']} | {t['passed']} | {t['failed']} "
            f"| {t['errors']} | {t['blocked']} | {rate} |"
        )
    lines.append(f"")

    # Per-prompt details
    lines.append(f"## Per-Prompt Results")
    lines.append(f"")
    lines.append(f"| # | Prompt ID | Tier | Status | Verified | Steps | Latency | Notes |")
    lines.append(f"|---|-----------|------|--------|----------|-------|---------|-------|")
    for r in results:
        idx = r.get("index", "?")
        pid = r.get("prompt_id", "?")
        tier = r.get("tier", "?")
        status = r.get("response_status", "?")
        v = r.get("verification_passed")
        v_str = "PASS" if v is True else ("FAIL" if v is False else "skip")
        steps = r.get("plan_steps") or r.get("step_count", "?")
        lat_s = r.get("elapsed_s", "?")
        notes = []
        if r.get("verification_error"):
            notes.append(r["verification_error"][:60])
        if r.get("regression_vs_baseline") is True:
            notes.append("REGRESSION")
        if r.get("scanner_blocks"):
            notes.append(f"scanner: {r['scanner_blocks']}")
        note_str = "; ".join(notes) if notes else ""
        lines.append(
            f"| {idx} | {pid} | {tier} | {status} | {v_str} "
            f"| {steps} | {lat_s}s | {note_str} |"
        )
    lines.append(f"")

    # Regression summary
    if metrics["regressions"] > 0:
        lines.append(f"## Regressions")
        lines.append(f"")
        lines.append(f"**{metrics['regressions']} regressions detected vs baseline:**")
        lines.append(f"")
        for pid in metrics["regression_details"]:
            lines.append(f"- `{pid}`")
        lines.append(f"")

    # Failure details
    failures = [r for r in results if r.get("verification_passed") is False]
    if failures:
        lines.append(f"## Failure Details")
        lines.append(f"")
        for r in failures:
            pid = r.get("prompt_id", "?")
            lines.append(f"### {pid}")
            lines.append(f"")
            lines.append(f"- **Prompt:** {r.get('prompt_preview', '?')}")
            lines.append(f"- **Response status:** {r.get('response_status', '?')}")
            v_cmd = r.get("verification_command", "N/A")
            lines.append(f"- **Verification command:** `{v_cmd}`")
            v_exit = r.get("verification_exit_code", "N/A")
            lines.append(f"- **Verification exit code:** {v_exit}")
            v_out = r.get("verification_output", "")
            if v_out:
                lines.append(f"- **Verification output:**")
                lines.append(f"  ```")
                # Truncate long output
                for out_line in v_out.strip().split("\n")[:20]:
                    lines.append(f"  {out_line}")
                lines.append(f"  ```")
            v_err = r.get("verification_error", "")
            if v_err:
                lines.append(f"- **Error:** {v_err}")
            lines.append(f"")

    report_text = "\n".join(lines)
    Path(output_path).write_text(report_text)
    return report_text


def generate_e2e_report(header, results, metrics, output_path):
    """Generate a Markdown report for the E2E workflow suite (G3)."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    version = header.get("version", "unknown") if header else "unknown"
    lat = _latency_stats(metrics["latency_values"])

    total = metrics["total"]
    passed = metrics["passed"]
    failed = metrics["failed"]
    skipped = metrics["skipped"]

    lines = []
    lines.append(f"# Functional Test Report: E2E Workflow (G3)")
    lines.append(f"")
    lines.append(f"**Version:** {version}")
    lines.append(f"**Generated:** {now}")
    lines.append(f"**Scenarios:** {total}")
    if header:
        lines.append(f"**Source JSONL:** `{header.get('source_file', 'N/A')}`")
    lines.append(f"")
    lines.append(f"---")
    lines.append(f"")

    # Summary
    lines.append(f"## Summary")
    lines.append(f"")
    lines.append(f"| Metric | Value |")
    lines.append(f"|--------|-------|")
    lines.append(f"| Total scenarios | {total} |")
    lines.append(f"| Passed | {passed} ({_pct(passed, total)}) |")
    lines.append(f"| Failed | {failed} ({_pct(failed, total)}) |")
    lines.append(f"| Skipped | {skipped} |")
    if metrics["tl4_gate_skipped"]:
        lines.append(f"| Skipped (TL4 gate) | {metrics['tl4_gate_skipped']} |")
    if metrics["graduation_skipped"]:
        lines.append(f"| Skipped (graduation) | {metrics['graduation_skipped']} |")
    lines.append(f"| API errors | {metrics['api_errors']} |")
    lines.append(f"| Blocked by scanners | {metrics['blocked']} |")
    if metrics["regressions"] > 0:
        lines.append(f"| **Regressions vs baseline** | **{metrics['regressions']}** |")
    lines.append(f"| Avg latency | {lat['avg']}s |")
    lines.append(f"| Median latency | {lat['median']}s |")
    lines.append(f"| P95 latency | {lat['p95']}s |")
    if metrics["step_counts"]:
        lines.append(f"| Avg plan steps | {statistics.mean(metrics['step_counts']):.1f} |")
    lines.append(f"")

    # Turns & threading
    lines.append(f"## Multi-Turn & Variable Threading")
    lines.append(f"")
    lines.append(f"| Metric | Value |")
    lines.append(f"|--------|-------|")
    lines.append(f"| Total turns expected | {metrics['turns_expected_total']} |")
    lines.append(f"| Total turns actual | {metrics['turns_actual_total']} |")
    if metrics["turn_counts"]:
        lines.append(f"| Avg turns per scenario | {statistics.mean(metrics['turn_counts']):.1f} |")
    vt_total = metrics["variable_threading_ok"] + metrics["variable_threading_fail"]
    if vt_total > 0:
        lines.append(f"| Variable threading OK | {metrics['variable_threading_ok']}/{vt_total} |")
    lines.append(f"")

    # Tool usage
    if metrics["tools_seen"]:
        lines.append(f"## Tool Usage")
        lines.append(f"")
        lines.append(f"| Tool | Times Used |")
        lines.append(f"|------|-----------|")
        for tool, count in sorted(metrics["tools_seen"].items(), key=lambda x: -x[1]):
            lines.append(f"| {tool} | {count} |")
        lines.append(f"")

    # By trust level
    if metrics["by_trust_level"]:
        lines.append(f"## By Trust Level")
        lines.append(f"")
        lines.append(f"| Trust Level | Total | Passed | Failed | Skipped | Pass Rate |")
        lines.append(f"|-------------|-------|--------|--------|---------|-----------|")
        for tl_key in sorted(metrics["by_trust_level"].keys()):
            tl = metrics["by_trust_level"][tl_key]
            rate = _pct(tl["passed"], tl["total"])
            lines.append(
                f"| {tl_key} | {tl['total']} | {tl['passed']} | {tl['failed']} "
                f"| {tl['skipped']} | {rate} |"
            )
        lines.append(f"")

    # Per-scenario details
    lines.append(f"## Per-Scenario Results")
    lines.append(f"")
    lines.append(f"| # | Scenario | TL | Status | Verified | Turns | Steps | Latency | Notes |")
    lines.append(f"|---|----------|-----|--------|----------|-------|-------|---------|-------|")
    for r in results:
        idx = r.get("index", "?")
        sid = r.get("scenario_id", r.get("prompt_id", "?"))
        tl = r.get("trust_level_required", "?")
        status = r.get("response_status", "?")
        v = r.get("verification_passed")
        v_str = "PASS" if v is True else ("FAIL" if v is False else "skip")
        turns = r.get("turns_actual", "?")
        steps = r.get("plan_steps", "?")
        lat_s = r.get("elapsed_s", "?")
        if isinstance(lat_s, (int, float)):
            lat_s = f"{lat_s:.1f}"
        notes = []
        if r.get("skip_reason"):
            notes.append(r["skip_reason"][:50])
        if r.get("verification_error"):
            notes.append(r["verification_error"][:50])
        if r.get("regression_vs_baseline") is True:
            notes.append("REGRESSION")
        if r.get("variable_threading_success") is False:
            notes.append("threading fail")
        note_str = "; ".join(notes) if notes else ""
        lines.append(
            f"| {idx} | {sid} | {tl} | {status} | {v_str} "
            f"| {turns} | {steps} | {lat_s}s | {note_str} |"
        )
    lines.append(f"")

    # Regression summary
    if metrics["regressions"] > 0:
        lines.append(f"## Regressions")
        lines.append(f"")
        lines.append(f"**{metrics['regressions']} regressions detected vs baseline:**")
        lines.append(f"")
        for sid in metrics["regression_details"]:
            lines.append(f"- `{sid}`")
        lines.append(f"")

    # Failure details
    failures = [r for r in results if r.get("verification_passed") is False]
    if failures:
        lines.append(f"## Failure Details")
        lines.append(f"")
        for r in failures:
            sid = r.get("scenario_id", r.get("prompt_id", "?"))
            lines.append(f"### {sid}")
            lines.append(f"")
            lines.append(f"- **Prompt:** {r.get('prompt_preview', r.get('prompt', '?'))[:200]}")
            lines.append(f"- **Response status:** {r.get('response_status', '?')}")
            lines.append(f"- **Turns:** {r.get('turns_actual', '?')} / {r.get('turns_expected', '?')} expected")
            v_cmd = r.get("verification_command", "N/A")
            lines.append(f"- **Verification command:** `{v_cmd}`")
            v_exit = r.get("verification_exit_code", "N/A")
            lines.append(f"- **Verification exit code:** {v_exit}")
            v_out = r.get("verification_output", "")
            if v_out:
                lines.append(f"- **Verification output:**")
                lines.append(f"  ```")
                for out_line in v_out.strip().split("\n")[:20]:
                    lines.append(f"  {out_line}")
                lines.append(f"  ```")
            v_err = r.get("verification_error", "")
            if v_err:
                lines.append(f"- **Error:** {v_err}")
            # Show tools used
            tools = r.get("tools_used", [])
            if tools:
                lines.append(f"- **Tools used:** {', '.join(tools)}")
            lines.append(f"")

    report_text = "\n".join(lines)
    Path(output_path).write_text(report_text)
    return report_text


def generate_plan_report(header, results, metrics, output_path):
    """Generate a Markdown report for the plan quality suite (G4)."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    version = header.get("version", "unknown") if header else "unknown"
    lat = _latency_stats(metrics["latency_values"])
    total = metrics["total"]
    s = metrics["success"]

    lines = []
    lines.append("# Functional Test Report: Plan Quality & Decomposition (G4)")
    lines.append("")
    lines.append(f"**Version:** {version}")
    lines.append(f"**Generated:** {now}")
    lines.append(f"**Prompts:** {total} ({s} successful)")
    if header:
        lines.append(f"**Source JSONL:** `{header.get('source_file', 'N/A')}`")
    lines.append("")
    lines.append("---")
    lines.append("")

    # ── Summary table ─────────────────────────────────────────────
    lines.append("## Summary")
    lines.append("")
    lines.append("| Metric | Value |")
    lines.append("|--------|-------|")
    lines.append(f"| Total executions | {total} |")
    lines.append(f"| Successful | {s} ({_pct(s, total)}) |")
    lines.append(f"| Blocked | {metrics['blocked']} |")
    lines.append(f"| Errors | {metrics['error']} |")
    lines.append(f"| Refused | {metrics['refused']} |")
    lines.append(f"| Decomposition accuracy | {_pct(metrics['in_range'], s)} |")
    lines.append(f"| Over-decomposed | {metrics['over_decomposed']} ({_pct(metrics['over_decomposed'], s)}) |")
    lines.append(f"| Under-decomposed | {metrics['under_decomposed']} ({_pct(metrics['under_decomposed'], s)}) |")
    lines.append(f"| Avg plan score | {metrics['avg_plan_score']:.2f} |")
    lines.append(f"| Avg variable naming | {metrics['avg_var_naming']:.2f} |")
    cc = metrics["avg_constraint_coverage"]
    lines.append(f"| Avg constraint coverage | {cc:.2f} |" if cc is not None else "| Avg constraint coverage | N/A (no tool_call steps or TL<4) |")
    lines.append(f"| Token cap risk | {metrics['token_cap_risk_count']}/{s} ({_pct(metrics['token_cap_risk_count'], s)}) |")
    lines.append(f"| Avg latency | {lat['avg']}s |")
    lines.append(f"| Median latency | {lat['median']}s |")
    lines.append(f"| P95 latency | {lat['p95']}s |")
    if metrics["step_counts"]:
        lines.append(f"| Avg step count | {statistics.mean(metrics['step_counts']):.1f} |")
    if metrics["regressions"] > 0:
        lines.append(f"| **Regressions** | **{metrics['regressions']}** |")
    lines.append("")

    # ── Spec targets comparison ───────────────────────────────────
    lines.append("## G4 Spec Targets")
    lines.append("")
    lines.append("| Target | Threshold | Actual | Status |")
    lines.append("|--------|-----------|--------|--------|")

    da = metrics["decomposition_accuracy"]
    da_pass = da >= 0.80
    lines.append(f"| Decomposition accuracy | ≥80% | {da*100:.1f}% | {'PASS' if da_pass else 'FAIL'} |")

    odr = metrics["over_decomp_rate"]
    odr_pass = odr <= 0.10
    lines.append(f"| Over-decomposition | ≤10% | {odr*100:.1f}% | {'PASS' if odr_pass else 'FAIL'} |")

    udr = metrics["under_decomp_rate"]
    # Spec: 0% under-decomposition for complex
    complex_cat = metrics["by_category"].get("complex", {})
    complex_under = complex_cat.get("under", 0)
    complex_total = complex_cat.get("success", 0) or 1
    complex_udr = complex_under / complex_total
    udr_pass = complex_udr == 0.0
    lines.append(f"| Under-decomposition (complex) | 0% | {complex_udr*100:.1f}% | {'PASS' if udr_pass else 'FAIL'} |")

    if cc is not None:
        cc_pass = cc >= 1.0
        lines.append(f"| Constraint completeness (TL4) | 100% | {cc*100:.1f}% | {'PASS' if cc_pass else 'FAIL'} |")

    lines.append("")

    # ── By category breakdown ─────────────────────────────────────
    lines.append("## By Category")
    lines.append("")
    lines.append("| Category | Total | Success | In Range | Over | Under | Avg Score | Avg Var Naming | Range % |")
    lines.append("|----------|-------|---------|----------|------|-------|-----------|----------------|---------|")
    for cat in ("simple", "medium", "complex"):
        c = metrics["by_category"].get(cat)
        if not c:
            continue
        avg_sc = f"{statistics.mean(c['scores']):.2f}" if c["scores"] else "N/A"
        avg_vn = f"{statistics.mean(c['var_scores']):.2f}" if c["var_scores"] else "N/A"
        rate = _pct(c["in_range"], c["success"]) if c["success"] else "N/A"
        lines.append(
            f"| {cat} | {c['total']} | {c['success']} | {c['in_range']} "
            f"| {c['over']} | {c['under']} | {avg_sc} | {avg_vn} | {rate} |"
        )
    lines.append("")

    # ── Per-prompt results ────────────────────────────────────────
    lines.append("## Per-Prompt Results")
    lines.append("")
    lines.append("| # | Prompt ID | Cat | Trial | Steps | Expected | Range | Score | Var Name | Constraints | Token Risk | Latency | Notes |")
    lines.append("|---|-----------|-----|-------|-------|----------|-------|-------|----------|-------------|------------|---------|-------|")
    for r in results:
        idx = r.get("index", "?")
        pid = r.get("prompt_id", "?")
        cat = r.get("category", "?")
        trial = r.get("trial", 1)
        sc = r.get("step_count", "?")
        exp = r.get("expected_range", "?")
        in_r = r.get("in_range")
        range_str = "OK" if in_r else ("OVER" if r.get("over_decomposed") else ("UNDER" if r.get("under_decomposed") else "?"))
        if r.get("response_status") != "success":
            range_str = r.get("response_status", "?")
        plan_sc = r.get("plan_score", "?")
        if isinstance(plan_sc, float):
            plan_sc = f"{plan_sc:.2f}"
        vns = r.get("variable_naming_score", "?")
        if isinstance(vns, float):
            vns = f"{vns:.2f}"
        cc_val = r.get("constraint_coverage")
        cc_str = f"{cc_val:.2f}" if cc_val is not None else "N/A"
        tcr = "YES" if r.get("has_token_cap_risk") else "no"
        elapsed = r.get("elapsed_s", "?")

        notes = []
        if r.get("regression_vs_baseline") is True:
            notes.append("REGRESSION")
        if r.get("error") and r.get("response_status") != "success":
            notes.append(str(r["error"])[:40])
        note_str = "; ".join(notes) if notes else ""

        lines.append(
            f"| {idx} | {pid} | {cat} | {trial} | {sc} | {exp} | {range_str} "
            f"| {plan_sc} | {vns} | {cc_str} | {tcr} | {elapsed}s | {note_str} |"
        )
    lines.append("")

    # ── Token cap risk details ────────────────────────────────────
    risky = [r for r in results if r.get("has_token_cap_risk")]
    if risky:
        lines.append("## Token Cap Risk Details")
        lines.append("")
        for r in risky:
            pid = r.get("prompt_id", "?")
            osr = r.get("output_size_risk", {})
            lines.append(f"### {pid}")
            lines.append("")
            for rs in osr.get("risky_steps", []):
                lines.append(
                    f"- Step {rs.get('step_index', '?')}: "
                    f"{rs.get('output_size', 0)} chars "
                    f"(~{rs.get('estimated_lines', 0)} lines), "
                    f"token ratio={rs.get('token_usage_ratio', '?')}, "
                    f"truncated={rs.get('truncated', '?')}"
                )
            lines.append("")

    # ── Regression details ────────────────────────────────────────
    if metrics["regressions"] > 0:
        lines.append("## Regressions")
        lines.append("")
        lines.append(f"**{metrics['regressions']} regressions detected vs baseline:**")
        lines.append("")
        for pid in metrics["regression_details"]:
            lines.append(f"- `{pid}`")
        lines.append("")

    report_text = "\n".join(lines)
    Path(output_path).write_text(report_text)
    return report_text


def generate_debug_report(header, results, metrics, output_path):
    """Generate a Markdown report for the debugging suite (G2)."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    version = header.get("version", "unknown") if header else "unknown"
    lat = _latency_stats(metrics["latency_values"])

    total = metrics["total"]
    converged = metrics["converged"]
    not_conv = metrics["not_converged"]
    errors = metrics["api_errors"]
    fcc = metrics["fix_cycle_counts"]

    lines = []
    lines.append("# Functional Test Report: Debugging & Error Recovery (G2)")
    lines.append("")
    lines.append(f"**Version:** {version}")
    lines.append(f"**Generated:** {now}")
    lines.append(f"**Scenarios:** {total}")
    lines.append("")
    lines.append("---")
    lines.append("")

    # ── Overall summary ──────────────────────────────────────────
    lines.append("## Summary")
    lines.append("")
    lines.append("| Metric | Value |")
    lines.append("|--------|-------|")
    lines.append(f"| Total scenarios | {total} |")
    lines.append(f"| Converged (fixed) | {converged} ({_pct(converged, total)}) |")
    lines.append(f"| Did not converge | {not_conv} ({_pct(not_conv, total)}) |")
    lines.append(f"| API errors | {errors} |")
    if fcc:
        lines.append(f"| Mean fix cycles | {statistics.mean(fcc):.1f} |")
        lines.append(f"| Median fix cycles | {statistics.median(fcc):.0f} |")
        lines.append(f"| Max fix cycles | {max(fcc)} |")
    diag_attempted = metrics["diagnosis_accurate_count"] + metrics["diagnosis_inaccurate_count"]
    if diag_attempted > 0:
        lines.append(f"| Diagnosis accuracy | {_pct(metrics['diagnosis_accurate_count'], diag_attempted)} ({metrics['diagnosis_accurate_count']}/{diag_attempted}) |")
    stderr_attempted = metrics["stderr_used_count"] + metrics["stderr_not_used_count"]
    if stderr_attempted > 0:
        lines.append(f"| stderr used in diagnosis | {_pct(metrics['stderr_used_count'], stderr_attempted)} ({metrics['stderr_used_count']}/{stderr_attempted}) |")
    lines.append(f"| Privacy boundary violations | {metrics['privacy_violations']} |")
    if metrics["regressions"] > 0:
        lines.append(f"| **Regressions vs baseline** | **{metrics['regressions']}** |")
    lines.append(f"| Avg latency per scenario | {lat['avg']}s |")
    lines.append(f"| Median latency | {lat['median']}s |")
    lines.append(f"| P95 latency | {lat['p95']}s |")
    lines.append(f"| Total planner tokens | {metrics['planner_tokens_total']:,} |")
    lines.append(f"| Total worker tokens | {metrics['worker_tokens_total']:,} |")
    lines.append("")

    # ── Per-category breakdown ───────────────────────────────────
    lines.append("## By Category")
    lines.append("")
    lines.append("| Category | Total | Converged | Not Conv. | Errors | Mean Cycles | Convergence Rate |")
    lines.append("|----------|-------|-----------|-----------|--------|-------------|------------------|")
    for cat_key in sorted(metrics["by_category"].keys()):
        c = metrics["by_category"][cat_key]
        mean_c = (
            f"{statistics.mean(c['fix_cycles']):.1f}"
            if c["fix_cycles"] else "N/A"
        )
        rate = _pct(c["converged"], c["total"])
        lines.append(
            f"| {cat_key} | {c['total']} | {c['converged']} | {c['not_converged']} "
            f"| {c['errors']} | {mean_c} | {rate} |"
        )
    lines.append("")

    # Category descriptions
    lines.append("> **Category A:** Syntax errors — stderr contains the answer (target: ≤3 cycles)")
    lines.append("> **Category B:** Build/integration failures — harder diagnosis (target: ≤5 cycles)")
    lines.append("> **Category C:** Iterative refinement — user-directed multi-turn improvement")
    lines.append("")

    # ── Fix-cycle distribution ───────────────────────────────────
    if fcc:
        lines.append("## Fix-Cycle Distribution")
        lines.append("")
        max_cycles = max(fcc) if fcc else 0
        for n in range(1, max_cycles + 1):
            count = sum(1 for x in fcc if x == n)
            bar = "#" * count
            lines.append(f"  {n} cycle{'s' if n > 1 else ' '}: {bar} ({count})")
        lines.append("")

    # ── Per-prompt details ───────────────────────────────────────
    lines.append("## Per-Prompt Results")
    lines.append("")
    lines.append("| # | Prompt ID | Cat | Trial | Turns | Cycles | Conv? | Diag? | stderr? | Latency |")
    lines.append("|---|-----------|-----|-------|-------|--------|-------|-------|---------|---------|")
    for r in results:
        idx = r.get("index", "?")
        pid = r.get("prompt_id", "?")
        cat = r.get("category", "?")
        trial = r.get("trial", "?")
        turns = r.get("turns_total", "?")
        cycles = r.get("fix_cycle_count", "?")
        conv = "YES" if r.get("convergence") else "NO"
        diag = r.get("diagnosis_accurate")
        diag_str = "YES" if diag is True else ("NO" if diag is False else "N/A")
        stderr = r.get("stderr_used_in_diagnosis")
        stderr_str = "YES" if stderr is True else ("NO" if stderr is False else "N/A")
        lat_s = r.get("elapsed_s", "?")
        lines.append(
            f"| {idx} | {pid} | {cat} | {trial} | {turns} | {cycles} "
            f"| {conv} | {diag_str} | {stderr_str} | {lat_s}s |"
        )
    lines.append("")

    # ── Non-converged scenarios ──────────────────────────────────
    non_converged = [r for r in results if not r.get("convergence")]
    if non_converged:
        lines.append("## Non-Converged Scenarios")
        lines.append("")
        for r in non_converged:
            pid = r.get("prompt_id", "?")
            cat = r.get("category", "?")
            cycles = r.get("fix_cycle_count", "?")
            lines.append(f"### {pid} (Category {cat})")
            lines.append("")
            lines.append(f"- **Fix cycles attempted:** {cycles}")
            lines.append(f"- **Initial prompt:** {r.get('initial_prompt_preview', '?')}")

            turn_details = r.get("turn_details", [])
            if turn_details:
                lines.append(f"- **Turn history:**")
                for t in turn_details:
                    tn = t.get("turn", "?")
                    status = t.get("response_status", "?")
                    v = t.get("verification_passed")
                    v_str = "PASS" if v is True else ("FAIL" if v is False else "skip")
                    summary = (t.get("plan_summary") or "")[:120]
                    lines.append(f"  - Turn {tn}: API={status}, verify={v_str}")
                    if summary:
                        lines.append(f"    Plan: {summary}...")

            v_err = r.get("verification_error", "")
            if v_err:
                lines.append(f"- **Last verification error:** {v_err[:200]}")
            lines.append("")

    # ── Privacy boundary ─────────────────────────────────────────
    if metrics["privacy_violations"] > 0:
        lines.append("## Privacy Boundary Violations")
        lines.append("")
        lines.append("**CRITICAL:** The following scenarios had privacy boundary violations "
                      "(planner requested raw Qwen output):")
        lines.append("")
        for r in results:
            if r.get("privacy_boundary_held") is False:
                lines.append(f"- `{r.get('prompt_id', '?')}`")
        lines.append("")

    # ── Regression summary ───────────────────────────────────────
    if metrics["regressions"] > 0:
        lines.append("## Regressions")
        lines.append("")
        lines.append(f"**{metrics['regressions']} regressions detected vs baseline:**")
        lines.append("")
        for pid in metrics["regression_details"]:
            lines.append(f"- `{pid}`")
        lines.append("")

    report_text = "\n".join(lines)
    Path(output_path).write_text(report_text)
    return report_text


def generate_deps_report(header, results, metrics, package_usage, output_path):
    """Generate a Markdown report for the dependency management suite (G5)."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    version = header.get("version", "unknown") if header else "unknown"
    lat = _latency_stats(metrics["latency_values"])

    total = metrics["total"]
    passed = metrics["verification_passed"]
    failed = metrics["verification_failed"]

    lines = []
    lines.append("# Functional Test Report: Environment & Dependency Management (G5)")
    lines.append("")
    lines.append(f"**Version:** {version}")
    lines.append(f"**Generated:** {now}")
    lines.append(f"**Scenarios:** {total}")
    if header:
        lines.append(f"**Source JSONL:** `{header.get('source_file', 'N/A')}`")
    lines.append("")
    lines.append("---")
    lines.append("")

    # ── Summary table ─────────────────────────────────────────────
    lines.append("## Summary")
    lines.append("")
    lines.append("| Metric | Value |")
    lines.append("|--------|-------|")
    lines.append(f"| Total scenarios | {total} |")
    lines.append(f"| Verification passed | {passed} ({_pct(passed, total)}) |")
    lines.append(f"| Verification failed | {failed} ({_pct(failed, total)}) |")
    lines.append(f"| API errors | {metrics['api_errors']} |")
    lines.append(f"| Install attempted | {metrics['install_attempted_count']} |")
    adapt_total = metrics["adaptation_successful_count"] + metrics["adaptation_failed_count"]
    if adapt_total > 0:
        lines.append(
            f"| Adaptation success | {metrics['adaptation_successful_count']}/{adapt_total} "
            f"({_pct(metrics['adaptation_successful_count'], adapt_total)}) |"
        )
    lines.append(f"| Adaptation N/A (not needed) | {metrics['adaptation_na_count']} |")
    lines.append(f"| Silent failures | {metrics['silent_failure_count']} |")
    lines.append(f"| Privacy violations | {metrics['privacy_violations']} |")
    if metrics["regressions"] > 0:
        lines.append(f"| **Regressions vs baseline** | **{metrics['regressions']}** |")
    lines.append(f"| Avg latency | {lat['avg']}s |")
    lines.append(f"| Median latency | {lat['median']}s |")
    lines.append(f"| P95 latency | {lat['p95']}s |")
    if metrics["turns_values"]:
        lines.append(f"| Avg turns per scenario | {statistics.mean(metrics['turns_values']):.1f} |")
    lines.append(f"| Total planner tokens | {metrics['planner_tokens_total']:,} |")
    lines.append(f"| Total worker tokens | {metrics['worker_tokens_total']:,} |")
    lines.append("")

    # ── Fallback strategy distribution ────────────────────────────
    lines.append("## Fallback Strategies Used")
    lines.append("")
    lines.append("| Strategy | Count |")
    lines.append("|----------|-------|")
    for strategy in ("stdlib_alternative", "user_report", "inline_generation", "none"):
        count = metrics["fallback_strategies"].get(strategy, 0)
        lines.append(f"| {strategy} | {count} |")
    lines.append("")

    # ── G5 spec targets comparison ────────────────────────────────
    lines.append("## G5 Spec Targets")
    lines.append("")
    lines.append("| Target | Threshold | Actual | Status |")
    lines.append("|--------|-----------|--------|--------|")

    # Stdlib success: 100%
    ssr = metrics["stdlib_success_rate"]
    if ssr is not None:
        ssr_pass = ssr >= 1.0
        lines.append(f"| Stdlib success | 100% | {ssr*100:.1f}% | {'PASS' if ssr_pass else 'FAIL'} |")
    else:
        lines.append("| Stdlib success | 100% | N/A | N/A |")

    # Pre-installed success: ≥90%
    psr = metrics["preinstalled_success_rate"]
    if psr is not None:
        psr_pass = psr >= 0.90
        lines.append(f"| Pre-installed success | ≥90% | {psr*100:.1f}% | {'PASS' if psr_pass else 'FAIL'} |")
    else:
        lines.append("| Pre-installed success | ≥90% | N/A | N/A |")

    # Missing dep detection: 100%
    mdr = metrics["missing_dep_detection_rate"]
    if mdr is not None:
        mdr_pass = mdr >= 1.0
        lines.append(f"| Missing dep detection | 100% | {mdr*100:.1f}% | {'PASS' if mdr_pass else 'FAIL'} |")
    else:
        lines.append("| Missing dep detection | 100% | N/A | N/A |")

    # Adaptation rate: ≥60%
    ar = metrics["adaptation_rate"]
    if ar is not None:
        ar_pass = ar >= 0.60
        lines.append(f"| Adaptation rate | ≥60% | {ar*100:.1f}% | {'PASS' if ar_pass else 'FAIL'} |")
    else:
        lines.append("| Adaptation rate | ≥60% | N/A | N/A |")

    # Silent failure: 0%
    sfr = metrics["silent_failure_rate"]
    sfr_pass = sfr == 0.0
    lines.append(f"| Silent failure rate | 0% | {sfr*100:.1f}% | {'PASS' if sfr_pass else 'FAIL'} |")

    lines.append("")

    # ── By dependency type breakdown ──────────────────────────────
    lines.append("## By Dependency Type")
    lines.append("")
    lines.append("| Type | Total | Passed | Failed | Errors | Adapted | Install Tried | Missing Detected | Silent Fail |")
    lines.append("|------|-------|--------|--------|--------|---------|---------------|------------------|-------------|")
    for dt in ("stdlib", "pre-installed", "missing"):
        d = metrics["by_dep_type"].get(dt)
        if not d:
            continue
        lines.append(
            f"| {dt} | {d['total']} | {d['passed']} | {d['failed']} "
            f"| {d['errors']} | {d['adapted']} | {d['install_attempted']} "
            f"| {d['missing_detected']} | {d['silent_failures']} |"
        )
    lines.append("")

    # ── Per-prompt results ────────────────────────────────────────
    lines.append("## Per-Prompt Results")
    lines.append("")
    lines.append("| # | Prompt ID | Type | Turns | Verified | Install? | Fallback | Adapted? | Silent? | Latency |")
    lines.append("|---|-----------|------|-------|----------|----------|----------|----------|---------|---------|")
    for r in results:
        idx = r.get("index", "?")
        pid = r.get("prompt_id", "?")
        dt = r.get("dependency_type", "?")
        turns = r.get("turns_total", "?")
        v = r.get("verification_passed")
        v_str = "PASS" if v is True else ("FAIL" if v is False else "err")
        inst = "YES" if r.get("install_attempted") else "no"
        fb = r.get("fallback_strategy", "none")
        adapt = r.get("adaptation_successful")
        adapt_str = "YES" if adapt is True else ("FAIL" if adapt is False else "N/A")
        silent = "YES" if r.get("silent_failure") else "no"
        lat_s = r.get("elapsed_s", "?")
        if isinstance(lat_s, (int, float)):
            lat_s = f"{lat_s:.1f}"
        lines.append(
            f"| {idx} | {pid} | {dt} | {turns} | {v_str} "
            f"| {inst} | {fb} | {adapt_str} | {silent} | {lat_s}s |"
        )
    lines.append("")

    # ── Package usage (feeds Solution A design) ───────────────────
    if package_usage and package_usage.get("packages"):
        lines.append("## Package Usage (Solution A Input)")
        lines.append("")
        lines.append(
            "Packages the system attempted to use across all scenarios. "
            "This feeds into the Solution A design decision (which packages "
            "to pre-install in the container)."
        )
        lines.append("")
        lines.append("| Package | Times Referenced | Used In |")
        lines.append("|---------|-----------------|---------|")
        for pkg, info in package_usage["packages"].items():
            count = info.get("count", 0)
            prompts = ", ".join(info.get("prompts", []))
            lines.append(f"| {pkg} | {count} | {prompts} |")
        lines.append("")
        lines.append(
            f"**Total unique non-stdlib packages:** "
            f"{package_usage.get('total_unique_packages', 0)}"
        )
        lines.append("")

    # ── Adaptation details ────────────────────────────────────────
    adapted = [r for r in results if r.get("adaptation_successful") is not None]
    if adapted:
        lines.append("## Adaptation Details")
        lines.append("")
        for r in adapted:
            pid = r.get("prompt_id", "?")
            adapt = r.get("adaptation_successful")
            fb = r.get("fallback_strategy", "none")
            turns = r.get("turns_total", "?")
            status = "Adapted successfully" if adapt else "Adaptation failed"
            lines.append(f"### {pid}")
            lines.append("")
            lines.append(f"- **Status:** {status}")
            lines.append(f"- **Fallback strategy:** {fb}")
            lines.append(f"- **Turns used:** {turns}")
            lines.append(f"- **Install attempted:** {'Yes' if r.get('install_attempted') else 'No'}")
            lines.append(f"- **Missing dep detected:** {'Yes' if r.get('missing_dep_detected') else 'No'}")
            v_out = r.get("verification_output", "")
            if v_out:
                lines.append(f"- **Final verification output:**")
                lines.append(f"  ```")
                for out_line in v_out.strip().split("\n")[:15]:
                    lines.append(f"  {out_line}")
                lines.append(f"  ```")
            lines.append("")

    # ── Failure details ───────────────────────────────────────────
    failures = [r for r in results if r.get("verification_passed") is False]
    if failures:
        lines.append("## Failure Details")
        lines.append("")
        for r in failures:
            pid = r.get("prompt_id", "?")
            lines.append(f"### {pid}")
            lines.append("")
            lines.append(f"- **Dependency type:** {r.get('dependency_type', '?')}")
            lines.append(f"- **Turns:** {r.get('turns_total', '?')}")
            lines.append(f"- **Install attempted:** {'Yes' if r.get('install_attempted') else 'No'}")
            lines.append(f"- **Fallback strategy:** {r.get('fallback_strategy', 'none')}")
            lines.append(f"- **Missing dep detected:** {'Yes' if r.get('missing_dep_detected') else 'No'}")
            lines.append(f"- **Silent failure:** {'Yes' if r.get('silent_failure') else 'No'}")
            v_err = r.get("verification_error", "")
            if v_err:
                lines.append(f"- **Verification error:** {v_err[:300]}")
            v_out = r.get("verification_output", "")
            if v_out:
                lines.append(f"- **Verification output:**")
                lines.append(f"  ```")
                for out_line in v_out.strip().split("\n")[:20]:
                    lines.append(f"  {out_line}")
                lines.append(f"  ```")
            lines.append("")

    # ── Privacy boundary ──────────────────────────────────────────
    if metrics["privacy_violations"] > 0:
        lines.append("## Privacy Boundary Violations")
        lines.append("")
        lines.append(
            "**CRITICAL:** The following scenarios had privacy boundary "
            "violations (planner requested raw Qwen output):"
        )
        lines.append("")
        for r in results:
            if r.get("privacy_boundary_held") is False:
                lines.append(f"- `{r.get('prompt_id', '?')}`")
        lines.append("")

    # ── Regressions ───────────────────────────────────────────────
    if metrics["regressions"] > 0:
        lines.append("## Regressions")
        lines.append("")
        lines.append(f"**{metrics['regressions']} regressions detected vs baseline:**")
        lines.append("")
        for pid in metrics["regression_details"]:
            lines.append(f"- `{pid}`")
        lines.append("")

    report_text = "\n".join(lines)
    Path(output_path).write_text(report_text)
    return report_text


def generate_security_tax_report(header, results, metrics, output_path):
    """Generate a Markdown report for the security tax suite (G6)."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    version = header.get("version", "unknown") if header else "unknown"

    d_lat = metrics["defended_latency"]
    b_lat = metrics["baseline_latency"]
    defended = metrics["by_config"].get("defended", {})
    baseline = metrics["by_config"].get("baseline", {})

    lines = []
    lines.append("# G6 Security Tax Report")
    lines.append("")
    lines.append(f"**Version:** {version}")
    lines.append(f"**Generated:** {now}")
    lines.append(f"**Total prompts:** {metrics['total']} "
                 f"({defended.get('total', 0)} defended + "
                 f"{baseline.get('total', 0)} baseline)")
    lines.append(f"**Reference:** CaMeL paper reports 7% security tax "
                 f"(arXiv:2503.18813)")
    lines.append("")
    lines.append("---")
    lines.append("")

    # ── Headline: Security Tax ────────────────────────────────────
    lines.append("## Security Tax Summary")
    lines.append("")
    tax = metrics["security_tax_pct"]
    target = 10.0
    verdict = "PASS" if tax <= target else "FAIL"
    lines.append(f"| Metric | Defended | Baseline | Delta |")
    lines.append(f"|--------|----------|----------|-------|")
    lines.append(
        f"| **Success rate** | "
        f"{_pct(defended.get('success', 0), defended.get('total', 1))} | "
        f"{_pct(baseline.get('success', 0), baseline.get('total', 1))} | "
        f"**{tax:+.1f}pp** |"
    )
    lines.append(
        f"| Avg latency | {d_lat['avg']}s | {b_lat['avg']}s | "
        f"{metrics['latency_overhead_pct']:+.1f}% |"
    )
    lines.append(
        f"| P95 latency | {d_lat['p95']}s | {b_lat['p95']}s | — |"
    )
    lines.append(
        f"| Total tokens | {metrics['defended_tokens_total']:,} | "
        f"{metrics['baseline_tokens_total']:,} | "
        f"{metrics['token_overhead_pct']:+.1f}% |"
    )
    lines.append(
        f"| Blocked | {defended.get('blocked', 0)} | "
        f"{baseline.get('blocked', 0)} | — |"
    )
    lines.append(
        f"| Errors | {defended.get('error', 0)} | "
        f"{baseline.get('error', 0)} | — |"
    )
    lines.append("")
    lines.append(
        f"**Security tax: {tax:+.1f}pp** — "
        f"target ≤{target:.0f}pp → **{verdict}**"
    )
    lines.append("")

    # ── Per-category breakdown ────────────────────────────────────
    lines.append("## Per-Category Breakdown")
    lines.append("")
    lines.append("| Category | Defended | Baseline | Tax (pp) |")
    lines.append("|----------|----------|----------|----------|")

    categories = sorted(set(
        cat for cat, _ in metrics["by_category"]
    ))
    for cat in categories:
        d_cat = metrics["by_category"].get((cat, "defended"), {})
        b_cat = metrics["by_category"].get((cat, "baseline"), {})
        d_t = d_cat.get("total", 0)
        b_t = b_cat.get("total", 0)
        d_rate = d_cat.get("success", 0) / d_t if d_t else 0
        b_rate = b_cat.get("success", 0) / b_t if b_t else 0
        cat_tax = (b_rate - d_rate) * 100
        lines.append(
            f"| {cat} | "
            f"{_pct(d_cat.get('success', 0), d_t)} ({d_cat.get('success', 0)}/{d_t}) | "
            f"{_pct(b_cat.get('success', 0), b_t)} ({b_cat.get('success', 0)}/{b_t}) | "
            f"{cat_tax:+.1f} |"
        )
    lines.append("")

    # ── Scanner FP contribution ───────────────────────────────────
    scanner_fp = metrics.get("scanner_fp", {})
    if scanner_fp:
        lines.append("## Scanner False-Positive Contribution (Defended Only)")
        lines.append("")
        lines.append("These scanners triggered blocks on legitimate prompts:")
        lines.append("")
        lines.append("| Scanner | Blocks | % of Defended |")
        lines.append("|---------|--------|---------------|")
        d_total = defended.get("total", 1)
        for scanner, count in sorted(
            scanner_fp.items(), key=lambda x: -x[1]
        ):
            lines.append(
                f"| {scanner} | {count} | "
                f"{_pct(count, d_total)} |"
            )
        lines.append("")
    else:
        lines.append("## Scanner False-Positive Contribution")
        lines.append("")
        lines.append("No scanner blocks detected on legitimate prompts.")
        lines.append("")

    # ── Per-prompt results table ──────────────────────────────────
    lines.append("## Per-Prompt Results")
    lines.append("")
    lines.append("| # | Prompt ID | Config | Category | Status | Latency | Blocks |")
    lines.append("|---|-----------|--------|----------|--------|---------|--------|")
    for r in results:
        idx = r.get("index", "?")
        pid = r.get("prompt_id", "?")
        cfg = r.get("config", "?")
        cat = r.get("category", "?")
        status = r.get("response_status", "?")
        lat_s = r.get("elapsed_s", "?")
        blocks = r.get("scanner_block_count", 0)
        lines.append(
            f"| {idx} | {pid} | {cfg} | {cat} | {status} | {lat_s}s | {blocks} |"
        )
    lines.append("")

    # ── Regressions ───────────────────────────────────────────────
    if metrics["regressions"] > 0:
        lines.append("## Regressions")
        lines.append("")
        lines.append(
            f"**{metrics['regressions']} regressions detected vs baseline:**"
        )
        lines.append("")
        for pid in metrics["regression_details"]:
            lines.append(f"- `{pid}`")
        lines.append("")

    report_text = "\n".join(lines)
    Path(output_path).write_text(report_text)
    return report_text


def generate_generic_report(header, results, metrics, suite_name, output_path):
    """Generate a generic Markdown report for any functional test suite."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    version = header.get("version", "unknown") if header else "unknown"
    lat = _latency_stats(metrics["latency_values"])
    total = metrics["total"]

    lines = []
    lines.append(f"# Functional Test Report: {suite_name}")
    lines.append(f"")
    lines.append(f"**Version:** {version}")
    lines.append(f"**Generated:** {now}")
    lines.append(f"**Prompts:** {total}")
    lines.append(f"")
    lines.append(f"---")
    lines.append(f"")
    lines.append(f"## Summary")
    lines.append(f"")
    lines.append(f"| Metric | Value |")
    lines.append(f"|--------|-------|")
    lines.append(f"| Total prompts | {total} |")
    lines.append(f"| Success | {metrics['success']} ({_pct(metrics['success'], total)}) |")
    lines.append(f"| Verification passed | {metrics['verification_passed']} ({_pct(metrics['verification_passed'], total)}) |")
    lines.append(f"| Verification failed | {metrics['verification_failed']} ({_pct(metrics['verification_failed'], total)}) |")
    lines.append(f"| Blocked | {metrics['blocked']} |")
    lines.append(f"| Errors | {metrics['error']} |")
    lines.append(f"| Refused | {metrics['refused']} |")
    if metrics["regressions"] > 0:
        lines.append(f"| **Regressions** | **{metrics['regressions']}** |")
    lines.append(f"| Avg latency | {lat['avg']}s |")
    lines.append(f"| P95 latency | {lat['p95']}s |")
    lines.append(f"")

    # Per-prompt table
    lines.append(f"## Per-Prompt Results")
    lines.append(f"")
    lines.append(f"| # | Prompt ID | Status | Verified | Latency |")
    lines.append(f"|---|-----------|--------|----------|---------|")
    for r in results:
        idx = r.get("index", "?")
        pid = r.get("prompt_id", "?")
        status = r.get("response_status", "?")
        v = r.get("verification_passed")
        v_str = "PASS" if v is True else ("FAIL" if v is False else "skip")
        lat_s = r.get("elapsed_s", "?")
        lines.append(f"| {idx} | {pid} | {status} | {v_str} | {lat_s}s |")
    lines.append(f"")

    report_text = "\n".join(lines)
    Path(output_path).write_text(report_text)
    return report_text


# ── Report path convention ────────────────────────────────────────

def report_path(jsonl_path):
    """Derive the report output path from the JSONL filename.

    benchmarks/functional_build_v0.4_20260223_120000.jsonl
      → docs/assessments/functional_build_v0.4_20260223_120000.md
    """
    p = Path(jsonl_path)
    stem = p.stem  # functional_build_v0.4_20260223_120000
    return Path("docs/assessments") / f"{stem}.md"


def detect_suite(header, results):
    """Detect which suite produced this JSONL."""
    if header:
        suite = header.get("test_suite")
        if suite:
            return suite
    # Fallback: infer from filename or first result
    if results:
        return results[0].get("test_suite", "unknown")
    return "unknown"


# ── Main ──────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Analyse functional test results and generate reports"
    )
    parser.add_argument(
        "jsonl_files", nargs="+",
        help="JSONL result files to analyse",
    )
    parser.add_argument(
        "--baseline", default=None,
        help="Baseline JSONL file for regression detection",
    )
    parser.add_argument(
        "--output-dir", default="docs/assessments",
        help="Directory for report output (default: docs/assessments/)",
    )
    args = parser.parse_args()

    baseline = load_baseline(args.baseline)

    for jsonl_path in args.jsonl_files:
        print(f"\nAnalysing: {jsonl_path}")
        header, results = load_jsonl(jsonl_path)

        if not results:
            print(f"  WARNING: No results found in {jsonl_path}")
            continue

        # Apply regression detection if baseline provided
        if baseline:
            for r in results:
                pid = r.get("prompt_id") or r.get("scenario_id")
                if pid and pid in baseline:
                    r["regression_vs_baseline"] = check_regression(r, baseline[pid])
                else:
                    r["regression_vs_baseline"] = None

        suite = detect_suite(header, results)
        print(f"  Suite: {suite}")
        print(f"  Results: {len(results)}")

        # Compute metrics and generate report
        out_dir = Path(args.output_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        out_path = out_dir / f"{Path(jsonl_path).stem}.md"

        if suite == "build_capability":
            metrics = compute_build_metrics(results)
            report = generate_build_report(header, results, metrics, out_path)
        elif suite == "debugging":
            metrics = compute_debug_metrics(results)
            report = generate_debug_report(header, results, metrics, out_path)
        elif suite == "e2e_workflow":
            metrics = compute_e2e_metrics(results)
            report = generate_e2e_report(header, results, metrics, out_path)
        elif suite == "plan_quality":
            metrics = compute_plan_metrics(results)
            report = generate_plan_report(header, results, metrics, out_path)
        elif suite == "deps":
            metrics = compute_deps_metrics(results)
            pkg_usage = load_package_usage(jsonl_path)
            report = generate_deps_report(
                header, results, metrics, pkg_usage, out_path
            )
        elif suite == "security_tax":
            metrics = compute_security_tax_metrics(results)
            report = generate_security_tax_report(
                header, results, metrics, out_path
            )
        else:
            metrics = compute_generic_metrics(results)
            report = generate_generic_report(
                header, results, metrics, suite, out_path
            )

        # Print summary to stdout
        total = len(results)
        regs = sum(1 for r in results if r.get("regression_vs_baseline") is True)

        if suite == "plan_quality":
            in_r = sum(1 for r in results if r.get("in_range"))
            succ = sum(1 for r in results if r.get("response_status") == "success")
            avg_sc = metrics.get("avg_plan_score", 0)
            print(f"  Decomposition: {in_r}/{succ} in range, "
                  f"avg score={avg_sc:.2f}")
        elif suite == "deps":
            v_passed = metrics["verification_passed"]
            adapted = metrics["adaptation_successful_count"]
            silent = metrics["silent_failure_count"]
            print(f"  Verification: {v_passed} passed, "
                  f"{total - v_passed} failed/error, "
                  f"{adapted} adapted, {silent} silent failures")
        elif suite == "security_tax":
            tax = metrics["security_tax_pct"]
            d_rate = metrics["defended_success_rate"]
            b_rate = metrics["baseline_success_rate"]
            lat_oh = metrics["latency_overhead_pct"]
            verdict = "PASS" if tax <= 10.0 else "FAIL"
            print(f"  Security tax: {tax:+.1f}pp "
                  f"(defended={d_rate:.1%}, baseline={b_rate:.1%}) "
                  f"latency overhead={lat_oh:+.1f}% — {verdict}")
        else:
            v_passed = sum(1 for r in results if r.get("verification_passed") is True)
            v_failed = sum(1 for r in results if r.get("verification_passed") is False)
            print(f"  Verification: {v_passed} passed, {v_failed} failed, "
                  f"{total - v_passed - v_failed} skipped")
        if regs:
            print(f"  REGRESSIONS: {regs}")
        print(f"  Report: {out_path}")


if __name__ == "__main__":
    main()
