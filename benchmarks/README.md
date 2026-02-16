# Benchmarks

This directory contains the v3 stress test benchmark data — 1,136 prompts tested against Sentinel's full CaMeL pipeline.

## Files

| File | Description | Size |
|------|-------------|------|
| `v3-results.jsonl` | Full results — one JSON object per prompt, includes Qwen responses | 6.9 MB |
| `v3-runner.log` | Test runner execution log | |

## Key Metrics (v3)

| Metric | Result |
|--------|--------|
| Total prompts | 1,136 (~314 genuine + ~788 adversarial + 34 benchmark) |
| Adversarial categories | 21+ (injection, traversal, social engineering, multi-turn, encoding, etc.) |
| Raw escape rate | 25.8% (209/811 adversarial) |
| Real risk rate | **0.12%** (1/811 adversarial after manual triage) |
| Genuine pass rate | 79.7% |
| False positive rate | 18.8% (60/320 genuine) |

The raw escape rate is misleading — 70% of "escapes" were actually refused by Claude or Qwen, 22% produced benign output, and 5% were educational content with appropriate warnings.

## Running the Analysis

```bash
# Generate full security + quality reports
python3 scripts/analyse_v3_results.py

# Inspect a specific result (by index)
python3 scripts/analyse_v3_results.py --show 42

# Raw JSON dump of a specific result
python3 scripts/analyse_v3_results.py --show 42 --raw

# Generate only the security report
python3 scripts/analyse_v3_results.py --security-only

# Generate only the quality report
python3 scripts/analyse_v3_results.py --quality-only

# Dry run (print to stdout instead of writing files)
python3 scripts/analyse_v3_results.py --dry-run
```

The analysis script reads from `benchmarks/v3-results.jsonl` by default.

## Assessment Reports

- [Security Analysis](../docs/assessments/v3-security-analysis.md) — escape triage, category breakdown, false positive analysis
- [Quality Analysis](../docs/assessments/v3-quality-analysis.md) — code generation quality across 4 difficulty tiers
- [Capability Assessment](../docs/assessments/v3-capability-assessment.md) — overall system capability evaluation
- [Expert Report](../docs/assessments/v3-expert-report.md) — independent security assessment
- [CaMeL Pipeline Assessment](../docs/assessments/camel-pipeline-assessment.md) — v2 architecture evaluation (historical)

## Data Format

Each line in `v3-results.jsonl` is a JSON object with:

```json
{
  "index": 0,
  "category": "genuine_code",
  "prompt": "Write a Python function...",
  "is_adversarial": false,
  "response_status": "success",
  "response": { "status": "completed", "result": "...", ... },
  "qwen_response": "Full Qwen output text...",
  "timestamp": "2026-02-15T16:31:14.123456",
  "duration_seconds": 45.2
}
```
