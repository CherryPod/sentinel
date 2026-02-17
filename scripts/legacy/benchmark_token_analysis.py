#!/usr/bin/env python3
"""Benchmark token and cost analysis for Sentinel JSONL benchmark files.

Reads a benchmark JSONL file and extracts token/character metrics for:
- User prompts (original input)
- Claude planner prompts (Claude's expanded instructions to Qwen)
- Qwen worker responses (LLM output)

Token estimation uses the rule of thumb: 1 token ~ 4 characters for English text.

Usage:
    .venv/bin/python3 scripts/benchmark_token_analysis.py benchmarks/<file>.jsonl
"""

import json
import sys
import statistics
from pathlib import Path


# Token estimation: 1 token ~ 4 characters for English text
CHARS_PER_TOKEN = 4


def estimate_tokens(text: str) -> int:
    """Estimate token count from character count (1 token ~ 4 chars)."""
    if not text:
        return 0
    return max(1, len(text) // CHARS_PER_TOKEN)


def count_words(text: str) -> int:
    """Count words in text."""
    if not text:
        return 0
    return len(text.split())


def analyse_jsonl(filepath: str) -> None:
    """Read a benchmark JSONL file and print token/character metrics."""
    path = Path(filepath)
    if not path.exists():
        print(f"Error: file not found: {filepath}")
        sys.exit(1)

    # Accumulators
    header = None
    total_entries = 0
    entries_with_steps = 0
    entries_blocked_at_input = 0
    entries_with_worker_response = 0

    # User prompt metrics (from prompt_preview — note: may be truncated)
    # We use prompt_len field for accurate character counts
    user_prompt_lens = []       # prompt_len from JSONL (accurate)
    user_prompt_chars = []      # actual character count from prompt_preview

    # Planner prompt metrics (Claude's expanded prompt to Qwen)
    planner_prompt_chars = []
    planner_prompt_tokens = []

    # Resolved prompt metrics (after variable substitution)
    resolved_prompt_chars = []
    resolved_prompt_tokens = []

    # Worker response metrics (Qwen output)
    worker_response_chars = []
    worker_response_tokens = []
    worker_response_words = []

    # Content field metrics (post-processed output returned to user)
    content_chars = []
    content_tokens = []

    # Per-entry aggregated metrics
    entry_total_worker_chars = []
    entry_total_planner_chars = []

    # Status breakdown
    status_counts = {}

    # Category breakdown
    category_worker_chars = {}
    category_worker_tokens = {}
    category_counts = {}

    # Timing
    elapsed_times = []

    with open(path, "r") as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue

            try:
                entry = json.loads(line)
            except json.JSONDecodeError as e:
                print(f"Warning: skipping malformed JSON on line {line_num}: {e}")
                continue

            # Skip header
            if entry.get("type") == "header":
                header = entry
                continue

            if entry.get("type") != "result":
                continue

            total_entries += 1

            # Track status
            status = entry.get("response_status", "unknown")
            status_counts[status] = status_counts.get(status, 0) + 1

            # Track category
            category = entry.get("category", "unknown")
            category_counts[category] = category_counts.get(category, 0) + 1

            # User prompt metrics
            prompt_len = entry.get("prompt_len", 0)
            user_prompt_lens.append(prompt_len)

            prompt_preview = entry.get("prompt_preview", "")
            user_prompt_chars.append(len(prompt_preview))

            # Timing
            elapsed = entry.get("elapsed_s", 0)
            if elapsed > 0:
                elapsed_times.append(elapsed)

            # Steps analysis
            steps = entry.get("steps", [])
            if not steps:
                entries_blocked_at_input += 1
                continue

            entries_with_steps += 1

            entry_worker_total = 0
            entry_planner_total = 0

            for step in steps:
                # Planner prompt (Claude's expanded instructions)
                pp = step.get("planner_prompt", "")
                if pp:
                    pp_chars = len(pp)
                    pp_tokens = estimate_tokens(pp)
                    planner_prompt_chars.append(pp_chars)
                    planner_prompt_tokens.append(pp_tokens)
                    entry_planner_total += pp_chars

                # Resolved prompt (after variable substitution — sent to Qwen)
                rp = step.get("resolved_prompt", "")
                if rp:
                    rp_chars = len(rp)
                    rp_tokens = estimate_tokens(rp)
                    resolved_prompt_chars.append(rp_chars)
                    resolved_prompt_tokens.append(rp_tokens)

                # Worker response (Qwen's raw output)
                wr = step.get("worker_response", "")
                if wr:
                    entries_with_worker_response += 1
                    wr_chars = len(wr)
                    wr_tokens = estimate_tokens(wr)
                    wr_words = count_words(wr)
                    worker_response_chars.append(wr_chars)
                    worker_response_tokens.append(wr_tokens)
                    worker_response_words.append(wr_words)
                    entry_worker_total += wr_chars

                    # Per-category tracking
                    if category not in category_worker_chars:
                        category_worker_chars[category] = []
                        category_worker_tokens[category] = []
                    category_worker_chars[category].append(wr_chars)
                    category_worker_tokens[category].append(wr_tokens)

                # Content field (post-processed output)
                ct = step.get("content", "")
                if ct:
                    ct_chars = len(ct)
                    ct_tokens = estimate_tokens(ct)
                    content_chars.append(ct_chars)
                    content_tokens.append(ct_tokens)

            if entry_worker_total > 0:
                entry_total_worker_chars.append(entry_worker_total)
            if entry_planner_total > 0:
                entry_total_planner_chars.append(entry_planner_total)

    # --- Print results ---
    print("=" * 72)
    print("SENTINEL BENCHMARK TOKEN & COST ANALYSIS")
    print("=" * 72)
    print(f"File: {path.name}")
    if header:
        print(f"Started: {header.get('started_at', 'N/A')}")
        print(f"Queue size: {header.get('actual_queue_size', 'N/A')}")
    print()

    # Overview
    print("-" * 72)
    print("OVERVIEW")
    print("-" * 72)
    print(f"Total result entries:           {total_entries}")
    print(f"Entries with steps (processed): {entries_with_steps}")
    print(f"Entries blocked at input scan:  {entries_blocked_at_input}")
    print(f"Steps with worker responses:    {entries_with_worker_response}")
    print()

    # Status breakdown
    print("Response status breakdown:")
    for status, count in sorted(status_counts.items(), key=lambda x: -x[1]):
        pct = (count / total_entries * 100) if total_entries > 0 else 0
        print(f"  {status:20s} {count:5d}  ({pct:5.1f}%)")
    print()

    # User prompt metrics
    print("-" * 72)
    print("USER PROMPTS (input to system)")
    print("-" * 72)
    print(f"  Count:                {len(user_prompt_lens)}")
    if user_prompt_lens:
        total_prompt_chars = sum(user_prompt_lens)
        total_prompt_tokens = total_prompt_chars // CHARS_PER_TOKEN
        print(f"  Total characters:     {total_prompt_chars:,}")
        print(f"  Total tokens (est):   {total_prompt_tokens:,}")
        print(f"  Avg chars/prompt:     {statistics.mean(user_prompt_lens):,.1f}")
        print(f"  Avg tokens/prompt:    {statistics.mean(user_prompt_lens) / CHARS_PER_TOKEN:,.1f}")
        print(f"  Median chars/prompt:  {statistics.median(user_prompt_lens):,.1f}")
        print(f"  Min chars:            {min(user_prompt_lens):,}")
        print(f"  Max chars:            {max(user_prompt_lens):,}")
        print(f"  Std dev (chars):      {statistics.stdev(user_prompt_lens):,.1f}" if len(user_prompt_lens) > 1 else "")
    print()

    # Claude planner prompt metrics
    print("-" * 72)
    print("CLAUDE PLANNER PROMPTS (Claude's expanded instructions to Qwen)")
    print("-" * 72)
    print(f"  Count:                {len(planner_prompt_chars)}")
    if planner_prompt_chars:
        total_pp_chars = sum(planner_prompt_chars)
        total_pp_tokens = sum(planner_prompt_tokens)
        print(f"  Total characters:     {total_pp_chars:,}")
        print(f"  Total tokens (est):   {total_pp_tokens:,}")
        print(f"  Avg chars/prompt:     {statistics.mean(planner_prompt_chars):,.1f}")
        print(f"  Avg tokens/prompt:    {statistics.mean(planner_prompt_tokens):,.1f}")
        print(f"  Median chars:         {statistics.median(planner_prompt_chars):,.1f}")
        print(f"  Min chars:            {min(planner_prompt_chars):,}")
        print(f"  Max chars:            {max(planner_prompt_chars):,}")
        print(f"  Expansion ratio:      {total_pp_chars / sum(user_prompt_lens):,.2f}x" if sum(user_prompt_lens) > 0 else "")
        print(f"    (Claude expands user prompts by this factor on average)")
    print()

    # Resolved prompt metrics (what actually goes to Qwen)
    print("-" * 72)
    print("RESOLVED PROMPTS (actual input sent to Qwen worker)")
    print("-" * 72)
    print(f"  Count:                {len(resolved_prompt_chars)}")
    if resolved_prompt_chars:
        total_rp_chars = sum(resolved_prompt_chars)
        total_rp_tokens = sum(resolved_prompt_tokens)
        print(f"  Total characters:     {total_rp_chars:,}")
        print(f"  Total tokens (est):   {total_rp_tokens:,}")
        print(f"  Avg chars/prompt:     {statistics.mean(resolved_prompt_chars):,.1f}")
        print(f"  Avg tokens/prompt:    {statistics.mean(resolved_prompt_tokens):,.1f}")
        print(f"  Median chars:         {statistics.median(resolved_prompt_chars):,.1f}")
        print(f"  Min chars:            {min(resolved_prompt_chars):,}")
        print(f"  Max chars:            {max(resolved_prompt_chars):,}")
    print()

    # Worker response metrics
    print("-" * 72)
    print("QWEN WORKER RESPONSES (LLM output)")
    print("-" * 72)
    print(f"  Count:                {len(worker_response_chars)}")
    if worker_response_chars:
        total_wr_chars = sum(worker_response_chars)
        total_wr_tokens = sum(worker_response_tokens)
        total_wr_words = sum(worker_response_words)
        print(f"  Total characters:     {total_wr_chars:,}")
        print(f"  Total tokens (est):   {total_wr_tokens:,}")
        print(f"  Total words:          {total_wr_words:,}")
        print(f"  Avg chars/response:   {statistics.mean(worker_response_chars):,.1f}")
        print(f"  Avg tokens/response:  {statistics.mean(worker_response_tokens):,.1f}")
        print(f"  Avg words/response:   {statistics.mean(worker_response_words):,.1f}")
        print(f"  Median chars:         {statistics.median(worker_response_chars):,.1f}")
        print(f"  Median tokens:        {statistics.median(worker_response_tokens):,.1f}")
        print(f"  Min chars:            {min(worker_response_chars):,}")
        print(f"  Max chars:            {max(worker_response_chars):,}")
        print(f"  Min tokens:           {min(worker_response_tokens):,}")
        print(f"  Max tokens:           {max(worker_response_tokens):,}")
        if len(worker_response_chars) > 1:
            print(f"  Std dev (chars):      {statistics.stdev(worker_response_chars):,.1f}")
            print(f"  Std dev (tokens):     {statistics.stdev(worker_response_tokens):,.1f}")
        # Percentiles
        sorted_chars = sorted(worker_response_chars)
        p25_idx = len(sorted_chars) // 4
        p75_idx = 3 * len(sorted_chars) // 4
        p90_idx = int(0.9 * len(sorted_chars))
        p95_idx = int(0.95 * len(sorted_chars))
        p99_idx = int(0.99 * len(sorted_chars))
        print(f"  P25 chars:            {sorted_chars[p25_idx]:,}")
        print(f"  P75 chars:            {sorted_chars[p75_idx]:,}")
        print(f"  P90 chars:            {sorted_chars[p90_idx]:,}")
        print(f"  P95 chars:            {sorted_chars[p95_idx]:,}")
        print(f"  P99 chars:            {sorted_chars[p99_idx]:,}")
        # Token estimation crosscheck with word-based method
        tokens_by_words = int(total_wr_words / 0.75)
        print()
        print(f"  Token estimation crosscheck:")
        print(f"    By chars (1 tok ~ 4 chars):   {total_wr_tokens:,}")
        print(f"    By words (1 tok ~ 0.75 words): {tokens_by_words:,}")
        print(f"    Difference:                    {abs(total_wr_tokens - tokens_by_words):,} ({abs(total_wr_tokens - tokens_by_words) / max(total_wr_tokens, 1) * 100:.1f}%)")
    print()

    # Content field metrics (what gets returned to user after processing)
    print("-" * 72)
    print("CONTENT FIELD (post-processed output returned to user)")
    print("-" * 72)
    print(f"  Count:                {len(content_chars)}")
    if content_chars:
        total_ct_chars = sum(content_chars)
        total_ct_tokens = sum(content_tokens)
        print(f"  Total characters:     {total_ct_chars:,}")
        print(f"  Total tokens (est):   {total_ct_tokens:,}")
        print(f"  Avg chars/entry:      {statistics.mean(content_chars):,.1f}")
        print(f"  Avg tokens/entry:     {statistics.mean(content_tokens):,.1f}")
        if worker_response_chars:
            # Content vs worker_response ratio
            print(f"  Content/Worker ratio: {total_ct_chars / sum(worker_response_chars):.3f}")
            print(f"    (content is typically the same or slightly different from worker_response)")
    print()

    # Combined totals
    print("-" * 72)
    print("COMBINED TOTALS")
    print("-" * 72)
    total_all_input_chars = sum(user_prompt_lens) + sum(planner_prompt_chars) + sum(resolved_prompt_chars)
    total_all_output_chars = sum(worker_response_chars)
    total_all_chars = total_all_input_chars + total_all_output_chars

    print(f"  All input characters:")
    print(f"    User prompts:       {sum(user_prompt_lens):,}")
    print(f"    Planner prompts:    {sum(planner_prompt_chars):,}")
    print(f"    Resolved prompts:   {sum(resolved_prompt_chars):,}")
    print(f"    Total input:        {total_all_input_chars:,}")
    print(f"    Total input tokens: {total_all_input_chars // CHARS_PER_TOKEN:,}")
    print()
    print(f"  All output characters:")
    print(f"    Worker responses:   {total_all_output_chars:,}")
    print(f"    Total output tokens:{total_all_output_chars // CHARS_PER_TOKEN:,}")
    print()
    print(f"  Grand total:")
    print(f"    All characters:     {total_all_chars:,}")
    print(f"    All tokens (est):   {total_all_chars // CHARS_PER_TOKEN:,}")
    print()

    # Qwen-specific summary (what matters for Ollama cost/throughput)
    print("-" * 72)
    print("QWEN (OLLAMA) THROUGHPUT SUMMARY")
    print("-" * 72)
    if resolved_prompt_chars and worker_response_chars:
        qwen_input_chars = sum(resolved_prompt_chars)
        qwen_output_chars = sum(worker_response_chars)
        qwen_input_tokens = qwen_input_chars // CHARS_PER_TOKEN
        qwen_output_tokens = qwen_output_chars // CHARS_PER_TOKEN
        print(f"  Qwen input (resolved prompts):")
        print(f"    Total chars:        {qwen_input_chars:,}")
        print(f"    Total tokens:       {qwen_input_tokens:,}")
        print(f"  Qwen output (worker responses):")
        print(f"    Total chars:        {qwen_output_chars:,}")
        print(f"    Total tokens:       {qwen_output_tokens:,}")
        print(f"  Qwen total throughput:")
        print(f"    Total chars:        {qwen_input_chars + qwen_output_chars:,}")
        print(f"    Total tokens:       {qwen_input_tokens + qwen_output_tokens:,}")
        if elapsed_times:
            # Only count entries that had worker responses
            total_elapsed = sum(elapsed_times)
            print(f"  Timing:")
            print(f"    Total wall time:    {total_elapsed:,.1f}s ({total_elapsed / 3600:,.2f}h)")
            print(f"    Avg time/entry:     {statistics.mean(elapsed_times):,.1f}s")
            print(f"    Median time/entry:  {statistics.median(elapsed_times):,.1f}s")
            if entries_with_worker_response > 0:
                # Throughput = output tokens / time for entries that generated output
                # Approximate: sum(worker times) is not separately tracked, use total elapsed
                print(f"    Output tok/s (est): {qwen_output_tokens / total_elapsed:,.1f}")
    print()

    # Category breakdown (top 10 by total output tokens)
    print("-" * 72)
    print("CATEGORY BREAKDOWN (top 15 by total Qwen output tokens)")
    print("-" * 72)
    if category_worker_tokens:
        cat_totals = {
            cat: sum(tokens)
            for cat, tokens in category_worker_tokens.items()
        }
        sorted_cats = sorted(cat_totals.items(), key=lambda x: -x[1])[:15]
        print(f"  {'Category':<30s} {'Count':>6s} {'Tot Tokens':>12s} {'Avg Tokens':>12s} {'Tot Chars':>12s}")
        print(f"  {'-'*30} {'-'*6} {'-'*12} {'-'*12} {'-'*12}")
        for cat, tot_tokens in sorted_cats:
            count = len(category_worker_tokens[cat])
            avg_tokens = tot_tokens / count if count > 0 else 0
            tot_chars = sum(category_worker_chars[cat])
            print(f"  {cat:<30s} {count:>6d} {tot_tokens:>12,d} {avg_tokens:>12,.0f} {tot_chars:>12,d}")
    print()

    # Distribution histogram of worker response lengths
    print("-" * 72)
    print("WORKER RESPONSE LENGTH DISTRIBUTION")
    print("-" * 72)
    if worker_response_chars:
        # Buckets: 0-500, 500-1K, 1K-2K, 2K-5K, 5K-10K, 10K-20K, 20K+
        buckets = [
            (0, 500, "0-500 chars"),
            (500, 1000, "500-1K chars"),
            (1000, 2000, "1K-2K chars"),
            (2000, 5000, "2K-5K chars"),
            (5000, 10000, "5K-10K chars"),
            (10000, 20000, "10K-20K chars"),
            (20000, float("inf"), "20K+ chars"),
        ]
        for low, high, label in buckets:
            count = sum(1 for c in worker_response_chars if low <= c < high)
            pct = count / len(worker_response_chars) * 100
            bar = "#" * int(pct / 2)
            print(f"  {label:<15s} {count:>5d} ({pct:5.1f}%) {bar}")
    print()

    print("=" * 72)
    print("NOTE: Token estimates use 1 token ~ 4 characters (English text rule")
    print("of thumb). Actual tokenizer counts may vary by ~10-20%. For Qwen 3,")
    print("which uses a large vocabulary, actual token counts may be lower than")
    print("character-based estimates.")
    print("=" * 72)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <benchmark.jsonl>")
        sys.exit(1)
    analyse_jsonl(sys.argv[1])
