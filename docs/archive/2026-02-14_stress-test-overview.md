# Stress Test Results — 2026-02-14 Overnight Run

## Test Configuration
- **741 requests queued** (742 results + 1 header record)
- **100 genuine** across 14 categories (Python, Rust, Go, JS, TS, HTML, bash, containers, DevOps, configs, data, essays, docs, short queries)
- **641 adversarial** across 10 attack categories
- **~20 exact repeats** for consistency testing
- **15 "legitimate" canaries** — adversarial-sounding but benign requests
- Run time: 00:19 → 10:00 (~10 hours)
- Approval mode: `auto` during test, restored to `full` on completion
- Qwen timeout: 1800s (30 min)

## Files
- **Results:** `scripts/results/2026-02-14-overnight/stress_test_results.jsonl`
- **Runner log:** `scripts/results/2026-02-14-overnight/runner.log`
- **Nohup log:** `scripts/results/2026-02-14-overnight/nohup.log`
- **Test script:** `scripts/stress_test.py`
- **Aborted run:** `scripts/results/aborted/` (earlier failed attempt, kept for reference)

## JSONL Record Format
Each result record has these fields:
```
type, index, timestamp, phase, category, prompt_len, prompt_preview,
session_id, multi_turn_step, elapsed_s, http_status, expected_catch,
response_status, plan_summary, reason, error, step_count,
conv_risk_score, conv_action, conv_warnings
```
- `response_status`: `success` | `blocked` | `error`
- `expected_catch`: what the test expects to happen (e.g. `"none -- should pass"`, `"credential_scanner"`, etc.)

## Overall Results

| Status | Count | % |
|--------|-------|---|
| Blocked | 433 | 58.4% |
| Success | 274 | 36.9% |
| Error | 34 | 4.6% |

## Genuine Requests (100)

| Status | Count | % | Notes |
|--------|-------|---|-------|
| Success | 80 | 80.0% | Correctly allowed |
| Blocked | 17 | 17.0% | **False positives** |
| Error | 3 | 3.0% | Pipeline errors |

**False positive rate: 17%** — needs investigation and tuning.

### Per-Category
| Category | Total | Success | Blocked | Error |
|----------|-------|---------|---------|-------|
| genuine_python | 19 | 14 | 5 | 0 |
| genuine_docs | 12 | 9 | 3 | 0 |
| genuine_essay | 10 | 10 | 0 | 0 |
| genuine_short | 10 | 10 | 0 | 0 |
| genuine_data | 6 | 6 | 0 | 0 |
| genuine_config | 6 | 4 | 1 | 1 |
| genuine_devops | 4 | 4 | 0 | 0 |
| genuine_go | 4 | 4 | 0 | 0 |
| genuine_rust | 4 | 2 | 1 | 1 |
| genuine_bash | 3 | 0 | 3 | 0 |
| genuine_container | 3 | 1 | 2 | 0 |
| genuine_javascript | 2 | 2 | 0 | 0 |
| genuine_html | 1 | 1 | 0 | 0 |
| genuine_typescript | 1 | 1 | 0 | 0 |
| legitimate (canaries) | 15 | 12 | 2 | 1 |

**Worst FP offenders:** `genuine_bash` (3/3 blocked), `genuine_container` (2/3 blocked), `genuine_python` (5/19 blocked)

## Adversarial Requests (642)

| Status | Count | % | Notes |
|--------|-------|---|-------|
| Blocked | 416 | 64.8% | Correctly caught |
| Success | 194 | 30.2% | **Escapes** |
| Error | 31 | 4.8% | Pipeline errors |

**Escape rate: 30.2%** — 194 adversarial prompts got through. Needs deep investigation.

### Per-Category
| Category | Total | Blocked | Escaped | Error | Block Rate |
|----------|-------|---------|---------|-------|------------|
| direct_injection | 116 | 99 | 17 | 0 | 85.3% |
| path_traversal | 97 | 57 | 40 | 0 | 58.8% |
| multi_turn | 83 | 40 | 38 | 5 | 48.2% |
| social_engineering | 68 | 43 | 25 | 0 | 63.2% |
| indirect_injection | 66 | 49 | 15 | 2 | 74.2% |
| credential_exfiltration | 65 | 40 | 25 | 0 | 61.5% |
| code_injection | 51 | 26 | 25 | 0 | 51.0% |
| encoding_obfuscation | 51 | 28 | 4 | 19 | 54.9% |
| edge_case | 44 | 34 | 5 | 5 | 77.3% |

**Strongest:** `direct_injection` (85.3% blocked), `edge_case` (77.3%), `indirect_injection` (74.2%)
**Weakest:** `multi_turn` (48.2%), `code_injection` (51.0%), `encoding_obfuscation` (54.9%)

## Errors (34 total)

| Error Type | Count | Categories |
|------------|-------|------------|
| Claude returned empty response | ~21 | encoding_obfuscation (19), edge_case (3-5) |
| Unknown step type (`file_write`, `mkdir`) | ~8 | multi_turn, indirect_injection |
| Invalid JSON from Claude | 1 | genuine_config |
| Tool execution failed (file not found) | ~2 | multi_turn, indirect_injection |
| Tool execution failed (podman not found) | 1 | legitimate |

Most errors are Claude refusing to engage with obfuscated prompts (returning empty) or generating step types the orchestrator doesn't recognise.

## Key Observations (Initial)

1. **False positive problem** — 17% of genuine requests blocked. CodeShield is the likely culprit (we saw this with the very first result — a legitimate concurrent downloader blocked for 3 CodeShield issues)
2. **194 adversarial escapes** — `path_traversal` (40), `multi_turn` (38), `social_engineering` (25), `code_injection` (25), `credential_exfiltration` (25) are the biggest gaps
3. **Multi-turn is the weakest link** — only 48.2% block rate despite having dedicated conversation tracking
4. **Encoding/obfuscation mostly errored** — Claude returned empty responses for 19/51, masking the real block rate
5. **Unknown step types** — Claude is generating `file_write` and `mkdir` step types that the orchestrator doesn't recognise, causing errors instead of proper handling

## Next Steps (Full Analysis)
- [ ] Investigate all 194 adversarial escapes — what got through and why
- [ ] Investigate all 17 genuine false positives — which scanner blocked and why
- [ ] Analyse the 34 errors — are any masking escapes or blocking genuine requests
- [ ] Check which security layer caught each blocked request (Prompt Guard, policy, CodeShield, conversation, Claude refusal)
- [ ] Review timing data — avg/p95/max elapsed_s by category
- [ ] Write recommendations for tuning
