#!/usr/bin/env python3
"""Compare A/B benchmark results: episodic ON vs OFF.

Reads two JSONL result files and produces a side-by-side comparison
report saved to docs/assessments/.

Usage:
    python3 scripts/ab_benchmark_compare.py <on_file> <off_file> [--timestamp TS]
"""

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path


def load_results(path: str) -> list[dict]:
    """Load JSONL results file."""
    results = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                results.append(json.loads(line))
    return results


def classify_suite(result: dict) -> str:
    """Classify a result as G2 or G3 based on scenario name."""
    scenario = result.get("scenario_id", result.get("scenario", ""))
    if "debug" in scenario.lower() or scenario.startswith("a") or scenario.startswith("b") or scenario.startswith("c"):
        return "G2"
    return "G3"


def is_pass(result: dict) -> bool:
    """Check if a result is a pass."""
    verdict = result.get("verdict", result.get("result", ""))
    return verdict in ("pass", "success", "completed")


def format_pct(n: int, total: int) -> str:
    """Format as X/Y (Z%)."""
    if total == 0:
        return "0/0 (0%)"
    pct = round(100 * n / total)
    return f"{n}/{total} ({pct}%)"


def compare(on_results: list[dict], off_results: list[dict]) -> dict:
    """Compare ON vs OFF results."""
    # Group by suite
    on_g2 = [r for r in on_results if classify_suite(r) == "G2"]
    on_g3 = [r for r in on_results if classify_suite(r) == "G3"]
    off_g2 = [r for r in off_results if classify_suite(r) == "G2"]
    off_g3 = [r for r in off_results if classify_suite(r) == "G3"]

    on_g2_pass = sum(1 for r in on_g2 if is_pass(r))
    on_g3_pass = sum(1 for r in on_g3 if is_pass(r))
    off_g2_pass = sum(1 for r in off_g2 if is_pass(r))
    off_g3_pass = sum(1 for r in off_g3 if is_pass(r))

    on_total_pass = on_g2_pass + on_g3_pass
    off_total_pass = off_g2_pass + off_g3_pass
    on_total = len(on_results)
    off_total = len(off_results)

    # Per-scenario breakdown — match by scenario_id
    on_by_scenario = {
        r.get("scenario_id", r.get("scenario", f"unknown_{i}")): r
        for i, r in enumerate(on_results)
    }
    off_by_scenario = {
        r.get("scenario_id", r.get("scenario", f"unknown_{i}")): r
        for i, r in enumerate(off_results)
    }
    all_scenarios = sorted(set(on_by_scenario.keys()) | set(off_by_scenario.keys()))

    scenarios = []
    episodic_helped = 0
    episodic_hurt = 0
    for s in all_scenarios:
        on_r = on_by_scenario.get(s)
        off_r = off_by_scenario.get(s)
        on_p = is_pass(on_r) if on_r else None
        off_p = is_pass(off_r) if off_r else None

        note = ""
        if on_p is True and off_p is False:
            note = "← episodic helped"
            episodic_helped += 1
        elif on_p is False and off_p is True:
            note = "← episodic hurt"
            episodic_hurt += 1

        scenarios.append({
            "scenario": s,
            "on": "PASS" if on_p else ("FAIL" if on_p is False else "N/A"),
            "off": "PASS" if off_p else ("FAIL" if off_p is False else "N/A"),
            "note": note,
        })

    return {
        "on_g2": format_pct(on_g2_pass, len(on_g2)),
        "off_g2": format_pct(off_g2_pass, len(off_g2)),
        "on_g3": format_pct(on_g3_pass, len(on_g3)),
        "off_g3": format_pct(off_g3_pass, len(off_g3)),
        "on_total": format_pct(on_total_pass, on_total),
        "off_total": format_pct(off_total_pass, off_total),
        "delta_g2": on_g2_pass - off_g2_pass,
        "delta_g3": on_g3_pass - off_g3_pass,
        "delta_total": on_total_pass - off_total_pass,
        "scenarios": scenarios,
        "episodic_helped": episodic_helped,
        "episodic_hurt": episodic_hurt,
    }


def render_report(comp: dict, timestamp: str, on_file: str, off_file: str) -> str:
    """Render comparison as markdown report."""
    lines = [
        f"# A/B Episodic Learning Comparison — {timestamp}",
        "",
        f"**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M')}",
        f"**Episodic ON:** `{Path(on_file).name}`",
        f"**Episodic OFF:** `{Path(off_file).name}`",
        "",
        "## Summary",
        "",
        "| Suite | Episodic ON | Episodic OFF | Delta |",
        "|-------|-------------|--------------|-------|",
        f"| G2 (debug) | {comp['on_g2']} | {comp['off_g2']} | {comp['delta_g2']:+d} |",
        f"| G3 (e2e) | {comp['on_g3']} | {comp['off_g3']} | {comp['delta_g3']:+d} |",
        f"| **Overall** | **{comp['on_total']}** | **{comp['off_total']}** | **{comp['delta_total']:+d}** |",
        "",
        "## Per-Scenario Breakdown",
        "",
        "| Scenario | ON | OFF | Note |",
        "|----------|----|----|------|",
    ]

    for s in comp["scenarios"]:
        lines.append(f"| {s['scenario']} | {s['on']} | {s['off']} | {s['note']} |")

    lines.extend([
        "",
        "## Conclusion",
        "",
        f"Episodic learning helped in **{comp['episodic_helped']}** scenario(s) "
        f"and hurt in **{comp['episodic_hurt']}** scenario(s).",
    ])

    if comp["delta_total"] > 0:
        lines.append(f"Net improvement: **+{comp['delta_total']}** scenarios with episodic context.")
    elif comp["delta_total"] < 0:
        lines.append(f"Net regression: **{comp['delta_total']}** scenarios with episodic context.")
    else:
        lines.append("No measurable difference between episodic ON and OFF.")

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="Compare A/B benchmark results")
    parser.add_argument("on_file", help="JSONL with episodic ON results")
    parser.add_argument("off_file", help="JSONL with episodic OFF results")
    parser.add_argument("--timestamp", default=datetime.now().strftime("%Y%m%d_%H%M%S"))
    args = parser.parse_args()

    on_results = load_results(args.on_file)
    off_results = load_results(args.off_file)

    print(f"Loaded {len(on_results)} ON results, {len(off_results)} OFF results")

    comp = compare(on_results, off_results)
    report = render_report(comp, args.timestamp, args.on_file, args.off_file)

    # Print to stdout
    print(report)

    # Save to docs/assessments
    report_path = f"docs/assessments/ab_benchmark_{args.timestamp}.md"
    Path(report_path).parent.mkdir(parents=True, exist_ok=True)
    Path(report_path).write_text(report)
    print(f"\nReport saved to {report_path}")


if __name__ == "__main__":
    main()
