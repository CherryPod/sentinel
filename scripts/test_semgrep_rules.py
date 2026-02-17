#!/usr/bin/env python3
"""
Semgrep Rule Validation — Replay benchmark data through new scanner.

Reads ALL benchmark JSONL files, extracts code blocks from entries where
CodeShield was expected to catch, runs each through SemgrepScanner, and
reports catch rate vs the CodeShield baseline.

Usage:
  .venv/bin/python3 scripts/test_semgrep_rules.py
  .venv/bin/python3 scripts/test_semgrep_rules.py --verbose     # show per-entry details
  .venv/bin/python3 scripts/test_semgrep_rules.py --misses-only  # only show what Semgrep missed
"""

import argparse
import asyncio
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

# Add project root to path so we can import sentinel modules
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from sentinel.security.semgrep_scanner import initialize, scan_blocks, _find_semgrep

BENCHMARKS_DIR = PROJECT_ROOT / "benchmarks"
RULES_DIR = PROJECT_ROOT / "rules" / "semgrep"


# ---------------------------------------------------------------------------
# Data loading
# ---------------------------------------------------------------------------

def find_jsonl_files() -> list[Path]:
    """Find all benchmark JSONL files."""
    return sorted(BENCHMARKS_DIR.glob("*.jsonl"))


def load_jsonl(path: Path) -> list[dict]:
    """Load result entries from a JSONL file."""
    results = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            entry = json.loads(line)
            if entry.get("type") == "result":
                results.append(entry)
    return results


def extract_code_blocks(text: str) -> list[tuple[str, str]]:
    """Extract fenced code blocks. Returns list of (language, code)."""
    blocks = []
    pattern = re.compile(r"```(\w*)\n(.*?)```", re.DOTALL)
    for m in pattern.finditer(text):
        lang = m.group(1).lower() or "unknown"
        code = m.group(2).strip()
        if code:  # skip empty blocks
            blocks.append((lang, code))
    return blocks


def get_worker_response(r: dict) -> str:
    """Get the combined worker response from all steps."""
    parts = []
    for step in r.get("steps", []):
        wr = step.get("worker_response", "")
        if wr:
            parts.append(wr)
    return "\n".join(parts)


# ---------------------------------------------------------------------------
# Entry collection — deduplicate across all runs
# ---------------------------------------------------------------------------

def collect_codeshield_entries(jsonl_files: list[Path]) -> list[dict]:
    """Collect all entries where CodeShield was expected, deduplicated by prompt.

    When the same prompt appears in multiple benchmark runs, we keep the one
    with the longest worker_response (most code to scan).
    """
    # Key: prompt_preview → best entry
    by_prompt: dict[str, dict] = {}

    for path in jsonl_files:
        results = load_jsonl(path)
        source = path.name
        for r in results:
            ec = r.get("expected_catch", "")
            if "CodeShield" not in ec:
                continue

            prompt_key = r.get("prompt_preview", "")[:200]
            worker_resp = get_worker_response(r)
            r["_worker_response"] = worker_resp
            r["_source"] = source
            r["_code_blocks"] = extract_code_blocks(worker_resp)

            # Keep the entry with the most code content
            existing = by_prompt.get(prompt_key)
            if existing is None or len(worker_resp) > len(existing["_worker_response"]):
                by_prompt[prompt_key] = r

    return list(by_prompt.values())


# ---------------------------------------------------------------------------
# Scanning
# ---------------------------------------------------------------------------

async def scan_entry(entry: dict) -> dict:
    """Run SemgrepScanner on an entry's code blocks. Returns result dict."""
    blocks = entry["_code_blocks"]
    index = entry.get("index", "?")
    category = entry.get("category", "?")
    status = entry.get("response_status", "?")
    reason = entry.get("reason", "")

    result = {
        "index": index,
        "category": category,
        "original_status": status,
        "original_reason": reason,
        "source": entry.get("_source", "?"),
        "num_code_blocks": len(blocks),
        "semgrep_caught": False,
        "semgrep_matches": [],
        "codeshield_caught": "CodeShield" in reason,
        "other_scanner_caught": status == "blocked" and "CodeShield" not in reason,
        "no_code_blocks": len(blocks) == 0,
    }

    if not blocks:
        return result

    # Map language tags to what semgrep expects
    lang_map = {
        "py": "python", "python3": "python", "python2": "python",
        "js": "javascript", "jsx": "javascript", "ts": "typescript",
        "tsx": "typescript", "sh": "bash", "zsh": "bash",
        "cs": "csharp", "c++": "cpp", "rb": "ruby",
    }

    scan_input = []
    for lang, code in blocks:
        normalized_lang = lang_map.get(lang, lang)
        scan_input.append((code, normalized_lang))

    scan_result = await scan_blocks(scan_input)
    if scan_result.found:
        result["semgrep_caught"] = True
        result["semgrep_matches"] = [
            {"pattern": m.pattern_name, "matched_text": m.matched_text[:100]}
            for m in scan_result.matches
        ]

    return result


async def scan_all(entries: list[dict]) -> list[dict]:
    """Scan all entries sequentially (semgrep is CPU-heavy, no point parallelizing)."""
    results = []
    total = len(entries)
    for i, entry in enumerate(entries, 1):
        result = await scan_entry(entry)
        results.append(result)
        # Progress indicator
        if i % 10 == 0 or i == total:
            caught = sum(1 for r in results if r["semgrep_caught"])
            print(f"  [{i}/{total}] scanned — {caught} caught so far", flush=True)
    return results


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def print_report(entries: list[dict], results: list[dict], verbose: bool = False, misses_only: bool = False):
    """Print the catch rate comparison report."""
    total = len(results)
    semgrep_caught = [r for r in results if r["semgrep_caught"]]
    codeshield_caught = [r for r in results if r["codeshield_caught"]]
    other_caught = [r for r in results if r["other_scanner_caught"]]
    no_code = [r for r in results if r["no_code_blocks"]]

    # Entries with code blocks (the ones semgrep can actually scan)
    has_code = [r for r in results if not r["no_code_blocks"]]
    semgrep_caught_with_code = [r for r in semgrep_caught if not r["no_code_blocks"]]

    print()
    print("=" * 70)
    print("SEMGREP RULE VALIDATION — BENCHMARK REPLAY")
    print("=" * 70)

    # Sources
    sources = Counter(r["source"] for r in results)
    print(f"\nSources ({len(sources)} JSONL files, {total} unique CodeShield entries):")
    for src, count in sources.most_common():
        print(f"  {src}: {count} entries")

    # Overall stats
    print(f"\n{'─' * 50}")
    print(f"OVERALL ({total} entries where CodeShield was expected)")
    print(f"{'─' * 50}")
    print(f"  Entries with code blocks:    {len(has_code)}")
    print(f"  Entries without code blocks: {len(no_code)} (refusals/prose — nothing to scan)")
    print()
    print(f"  CodeShield caught:           {len(codeshield_caught)}/{total} ({len(codeshield_caught)/total*100:.1f}%)")
    print(f"  Semgrep caught:              {len(semgrep_caught)}/{total} ({len(semgrep_caught)/total*100:.1f}%)")
    print(f"  Other scanners caught:       {len(other_caught)}/{total} ({len(other_caught)/total*100:.1f}%)")

    if has_code:
        print(f"\n  Semgrep on code-only subset: {len(semgrep_caught_with_code)}/{len(has_code)} ({len(semgrep_caught_with_code)/len(has_code)*100:.1f}%)")

    # By category
    print(f"\n{'─' * 50}")
    print("BY CATEGORY")
    print(f"{'─' * 50}")

    cat_results: dict[str, list[dict]] = defaultdict(list)
    for r in results:
        cat_results[r["category"]].append(r)

    print(f"\n  {'Category':<30} {'Total':>5} {'Code':>5} {'SG':>5} {'CS':>5} {'SG%':>6} {'CS%':>6}")
    print(f"  {'─'*30} {'─'*5} {'─'*5} {'─'*5} {'─'*5} {'─'*6} {'─'*6}")
    for cat in sorted(cat_results.keys(), key=lambda c: -len(cat_results[c])):
        items = cat_results[cat]
        cat_total = len(items)
        cat_code = sum(1 for r in items if not r["no_code_blocks"])
        cat_sg = sum(1 for r in items if r["semgrep_caught"])
        cat_cs = sum(1 for r in items if r["codeshield_caught"])
        sg_pct = (cat_sg / cat_total * 100) if cat_total else 0
        cs_pct = (cat_cs / cat_total * 100) if cat_total else 0
        print(f"  {cat:<30} {cat_total:>5} {cat_code:>5} {cat_sg:>5} {cat_cs:>5} {sg_pct:>5.1f}% {cs_pct:>5.1f}%")

    # By language
    print(f"\n{'─' * 50}")
    print("BY CODE LANGUAGE")
    print(f"{'─' * 50}")

    lang_stats: dict[str, dict[str, int]] = defaultdict(lambda: {"blocks": 0, "caught": 0})
    for entry, result in zip(entries, results):
        for lang, _ in entry["_code_blocks"]:
            lang_stats[lang]["blocks"] += 1
        if result["semgrep_caught"]:
            for lang, _ in entry["_code_blocks"]:
                lang_stats[lang]["caught"] += 1

    print(f"\n  {'Language':<20} {'Blocks':>6} {'Caught':>6}")
    print(f"  {'─'*20} {'─'*6} {'─'*6}")
    for lang in sorted(lang_stats.keys(), key=lambda l: -lang_stats[l]["blocks"]):
        d = lang_stats[lang]
        print(f"  {lang:<20} {d['blocks']:>6} {d['caught']:>6}")

    # Semgrep matches breakdown
    print(f"\n{'─' * 50}")
    print("SEMGREP RULE HITS")
    print(f"{'─' * 50}")

    rule_hits = Counter()
    for r in semgrep_caught:
        for m in r["semgrep_matches"]:
            rule_hits[m["pattern"]] += 1

    if rule_hits:
        for rule, count in rule_hits.most_common():
            print(f"  {rule}: {count}")
    else:
        print("  (none)")

    # Detailed entries
    if verbose or misses_only:
        if misses_only:
            show_entries = [(e, r) for e, r in zip(entries, results)
                           if not r["semgrep_caught"] and not r["no_code_blocks"]]
            print(f"\n{'─' * 50}")
            print(f"MISSES — {len(show_entries)} entries with code that Semgrep didn't catch")
            print(f"{'─' * 50}")
        else:
            show_entries = list(zip(entries, results))
            print(f"\n{'─' * 50}")
            print(f"ALL ENTRIES — {len(show_entries)} entries")
            print(f"{'─' * 50}")

        for entry, result in show_entries:
            sg = "CAUGHT" if result["semgrep_caught"] else "MISSED"
            cs = "CS:caught" if result["codeshield_caught"] else "CS:missed"
            code_info = f"{result['num_code_blocks']} blocks" if result["num_code_blocks"] else "no code"
            print(f"\n  [{result['index']}] {result['category']} | {sg} | {cs} | {code_info} | {result['source']}")
            if result["semgrep_matches"]:
                for m in result["semgrep_matches"]:
                    print(f"    → {m['pattern']}: {m['matched_text']}")
            # Show code preview for misses
            if not result["semgrep_caught"] and entry["_code_blocks"]:
                for lang, code in entry["_code_blocks"][:2]:
                    preview = code[:200].replace("\n", "\n      ")
                    print(f"    [{lang}] {preview}{'...' if len(code) > 200 else ''}")

    # Summary
    print(f"\n{'=' * 70}")
    sg_rate = len(semgrep_caught) / total * 100 if total else 0
    cs_rate = len(codeshield_caught) / total * 100 if total else 0
    delta = sg_rate - cs_rate
    print(f"RESULT: Semgrep {sg_rate:.1f}% vs CodeShield {cs_rate:.1f}% ({'+' if delta >= 0 else ''}{delta:.1f}pp)")
    if has_code:
        sg_code_rate = len(semgrep_caught_with_code) / len(has_code) * 100
        print(f"        Semgrep on scannable entries: {sg_code_rate:.1f}% ({len(semgrep_caught_with_code)}/{len(has_code)})")
    target = 60.0
    if sg_rate >= target:
        print(f"        TARGET MET: ≥{target:.0f}% catch rate")
    else:
        gap = target - sg_rate
        needed = int(gap / 100 * total) + 1
        print(f"        GAP: {gap:.1f}pp below {target:.0f}% target — need ~{needed} more catches")
    print("=" * 70)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

async def async_main(args):
    # Initialize scanner
    print(f"Semgrep binary: {_find_semgrep()}")
    print(f"Rules directory: {RULES_DIR}")
    ok = initialize(rules_dir=RULES_DIR, timeout=30)
    if not ok:
        print("ERROR: Failed to initialize SemgrepScanner")
        sys.exit(1)
    print("SemgrepScanner initialized")

    # Find and load benchmark files
    jsonl_files = find_jsonl_files()
    print(f"\nFound {len(jsonl_files)} benchmark files:")
    for f in jsonl_files:
        print(f"  {f.name}")

    # Collect CodeShield entries across all files
    print("\nCollecting CodeShield entries (deduplicating by prompt)...")
    entries = collect_codeshield_entries(jsonl_files)
    print(f"  {len(entries)} unique entries with CodeShield as expected scanner")

    code_entries = sum(1 for e in entries if e["_code_blocks"])
    print(f"  {code_entries} have code blocks to scan")

    # Scan
    print("\nScanning with SemgrepScanner...")
    results = await scan_all(entries)

    # Report
    print_report(entries, results, verbose=args.verbose, misses_only=args.misses_only)


def main():
    parser = argparse.ArgumentParser(description="Validate Semgrep rules against benchmark data")
    parser.add_argument("--verbose", action="store_true", help="Show per-entry details")
    parser.add_argument("--misses-only", action="store_true", help="Only show entries Semgrep missed")
    args = parser.parse_args()
    asyncio.run(async_main(args))


if __name__ == "__main__":
    main()
