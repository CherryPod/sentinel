#!/usr/bin/env python3
"""Extract examples across the response-length spectrum for cost comparison table."""

import json
import sys

CHARS_PER_TOKEN = 4
SENTINEL_COST_PER_PROMPT = 0.00551  # Claude planner API
SENTINEL_ELEC_PER_PROMPT = 0.00176  # marginal electricity
CLAUDE_INPUT_PER_MTOK = 3.00
CLAUDE_OUTPUT_PER_MTOK = 15.00
CLAUDE_SYSTEM_PROMPT_TOKENS = 500  # typical direct-to-Claude system prompt


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "benchmarks/benchmark_v0.2.1-alpha_20260219_003410.jsonl"

    entries = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            entry = json.loads(line)
            if entry.get("type") != "result":
                continue
            steps = entry.get("steps", [])
            if not steps:
                continue
            for step in steps:
                wr = step.get("worker_response", "")
                if wr:
                    prompt_preview = entry.get("prompt_preview", "")
                    category = entry.get("category", "unknown")
                    wr_tokens = max(1, len(wr) // CHARS_PER_TOKEN)
                    prompt_tokens = max(1, entry.get("prompt_len", len(prompt_preview)) // CHARS_PER_TOKEN)
                    entries.append({
                        "prompt": prompt_preview,
                        "category": category,
                        "prompt_tokens": prompt_tokens,
                        "response_tokens": wr_tokens,
                        "response_words": len(wr.split()),
                        "response_chars": len(wr),
                    })

    entries.sort(key=lambda x: x["response_tokens"])
    print(f"Total entries with responses: {len(entries)}")
    print()

    # Pick 10 examples across the spectrum
    percentiles = [1, 5, 10, 20, 35, 50, 65, 80, 92, 99]

    print(f"{'Pct':>4s} | {'Resp Tok':>9s} | {'Words':>6s} | {'Sentinel':>9s} | {'Claude':>9s} | {'Ratio':>6s} | {'Category':>25s} | Prompt (truncated)")
    print("-" * 160)

    for pct in percentiles:
        idx = min(int(pct / 100 * len(entries)), len(entries) - 1)
        e = entries[idx]

        # Sentinel cost (fixed per prompt)
        sentinel_cost = SENTINEL_COST_PER_PROMPT + SENTINEL_ELEC_PER_PROMPT

        # Direct Claude cost
        input_tokens = e["prompt_tokens"] + CLAUDE_SYSTEM_PROMPT_TOKENS
        output_tokens = e["response_tokens"]
        claude_input_cost = input_tokens / 1_000_000 * CLAUDE_INPUT_PER_MTOK
        claude_output_cost = output_tokens / 1_000_000 * CLAUDE_OUTPUT_PER_MTOK
        claude_cost = claude_input_cost + claude_output_cost

        ratio = claude_cost / sentinel_cost if sentinel_cost > 0 else 0

        prompt_clean = e["prompt"].replace("\n", " ").strip()[:120]

        print(f"P{pct:>3d} | {e['response_tokens']:>9,d} | {e['response_words']:>6,d} | ${sentinel_cost:>8.4f} | ${claude_cost:>8.4f} | {ratio:>5.1f}x | {e['category']:>25s} | {prompt_clean}")

    print()
    print("=" * 80)
    print("CROSSOVER ANALYSIS")
    print("=" * 80)

    # Find the crossover point where Sentinel becomes cheaper
    sentinel_fixed = SENTINEL_COST_PER_PROMPT + SENTINEL_ELEC_PER_PROMPT
    # Claude cost = (prompt_tokens + 500) * 3/1M + output_tokens * 15/1M
    # Sentinel cost = sentinel_fixed (constant)
    # Crossover: sentinel_fixed = (prompt_tokens + 500) * 3/1M + output_tokens * 15/1M
    # Solving for output_tokens (assuming avg 132 prompt tokens):
    avg_prompt_tokens = 132
    claude_input_baseline = (avg_prompt_tokens + CLAUDE_SYSTEM_PROMPT_TOKENS) / 1_000_000 * CLAUDE_INPUT_PER_MTOK
    remaining = sentinel_fixed - claude_input_baseline
    if remaining > 0:
        crossover_tokens = remaining / (CLAUDE_OUTPUT_PER_MTOK / 1_000_000)
        print(f"Sentinel cost per prompt: ${sentinel_fixed:.5f}")
        print(f"Claude input baseline (avg prompt + system): ${claude_input_baseline:.5f}")
        print(f"Remaining budget for output tokens: ${remaining:.5f}")
        print(f"Crossover output token count: {crossover_tokens:,.0f} tokens")
        print(f"Crossover in characters: ~{crossover_tokens * 4:,.0f} chars")
        print(f"Crossover in words: ~{crossover_tokens * 0.75:,.0f} words")
        print()
        print(f"Responses shorter than ~{crossover_tokens:,.0f} tokens ({crossover_tokens * 0.75:,.0f} words) are CHEAPER via direct Claude API")
        print(f"Responses longer than ~{crossover_tokens:,.0f} tokens are CHEAPER via Sentinel pipeline")
    else:
        print("Sentinel is always cheaper than Claude (input baseline exceeds sentinel cost)")

    print()
    # What % of benchmark responses are above/below crossover
    above = sum(1 for e in entries if e["response_tokens"] >= crossover_tokens)
    below = len(entries) - above
    print(f"Benchmark responses above crossover: {above}/{len(entries)} ({above/len(entries)*100:.1f}%)")
    print(f"Benchmark responses below crossover: {below}/{len(entries)} ({below/len(entries)*100:.1f}%)")

    # Per-bucket analysis
    print()
    print("COST BY RESPONSE LENGTH BUCKET")
    print("-" * 90)
    buckets = [
        (0, 100, "< 100 tokens"),
        (100, 300, "100-300 tokens"),
        (300, 500, "300-500 tokens"),
        (500, 1000, "500-1K tokens"),
        (1000, 2000, "1K-2K tokens"),
        (2000, 5000, "2K-5K tokens"),
        (5000, 10000, "5K-10K tokens"),
        (10000, 999999, "10K+ tokens"),
    ]

    print(f"{'Bucket':>15s} | {'Count':>6s} | {'Avg Sentinel':>12s} | {'Avg Claude':>12s} | {'Avg Ratio':>10s} | {'Sentinel Cheaper?':>18s}")
    print("-" * 90)

    for low, high, label in buckets:
        bucket_entries = [e for e in entries if low <= e["response_tokens"] < high]
        if not bucket_entries:
            continue

        total_sentinel = 0
        total_claude = 0
        for e in bucket_entries:
            s_cost = sentinel_fixed
            c_input = (e["prompt_tokens"] + CLAUDE_SYSTEM_PROMPT_TOKENS) / 1_000_000 * CLAUDE_INPUT_PER_MTOK
            c_output = e["response_tokens"] / 1_000_000 * CLAUDE_OUTPUT_PER_MTOK
            total_sentinel += s_cost
            total_claude += c_input + c_output

        avg_s = total_sentinel / len(bucket_entries)
        avg_c = total_claude / len(bucket_entries)
        ratio = avg_c / avg_s
        cheaper = "YES" if avg_c > avg_s else "no"

        print(f"{label:>15s} | {len(bucket_entries):>6d} | ${avg_s:>11.5f} | ${avg_c:>11.5f} | {ratio:>9.2f}x | {cheaper:>18s}")


if __name__ == "__main__":
    main()
