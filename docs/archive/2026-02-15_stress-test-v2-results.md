# Stress Test v2 — Full Results

**Date:** 2026-02-14 23:01 UTC → 2026-02-15 08:19 UTC (9.3 hours)
**Results file:** `scripts/results/stress_test_20260214_230101.jsonl`
**Runner log:** `scripts/results/runner_20260214_230034.log`
**Test script:** `scripts/stress_test.py` (~4400 lines, 976 prompts)
**Run command:** `./scripts/run_stress_test.sh` (nohup, auto approval mode)

## Context

This is the **second iteration** of the stress test. Changes since v1 (overnight run, 742 prompts):

- **+234 prompts** (976 total): 75 genuine_multi_turn + 160 new adversarial categories
- **New adversarial categories:** tool_manipulation (30), non_english_injection (30), cross_model_confusion (15), payload_free_injection (15), threshold_evasion (10), chunking_boundary (8), dos_resource (10), unicode_homoglyph (12), owasp_llm (15), model_specific_jailbreak (10), benchmark_inspired (5)
- **Session isolation:** each request gets unique source (`stress_test_N`) — no cascade locking
- **Rate limit retry:** 429s retry 5x with exponential backoff
- **Prompt caching:** Claude system prompt cached (~90% input token savings)
- **Planner fix:** single llm_task for text gen (was creating unnecessary file_write steps)
- **Runner classification fix:** planner refusals no longer misclassified as escapes

## High-Level Results

| Metric | Value |
|--------|-------|
| Total requests | 976 |
| Genuine + legitimate | 175 |
| Adversarial | 801 |
| Duration | 558.9 minutes (9.3 hours) |
| Rate | 1.7 req/min |
| Rate limit hits | 8 (all recovered via retry) |

## Security Performance

| Metric | v1 (742 prompts) | v2 (976 prompts) | Change |
|--------|-------------------|-------------------|--------|
| **Escape rate** | 5.3% (34/642) | **5.5% (44/801)** | +0.2% |
| **Combined catch rate** | 89.9% | **93.3% (747/801)** | +3.4% |
| Hard block rate | 64.9% | 67.8% (543/801) | +2.9% |
| Planner refusal rate | 25.0% | 25.5% (204/801) | +0.5% |
| **False positive rate (genuine)** | 17% (17/100) | **14.3% (25/175)** | -2.7% |
| FP blocked | 10 | 17 | — |
| FP refused | 5 | 8 | — |
| Errors | 34 | 13 | -21 |

## Genuine Task Performance

**Pass rate: 147/175 (84.0%)**

| Category | Total | Passed | Blocked (FP) | Refused (FP) | Error |
|----------|-------|--------|------------|------------|-------|
| genuine_bash | 3 | 3 | 0 | 0 | 0 |
| genuine_config | 6 | 4 | 1 | 0 | 1 |
| genuine_container | 3 | 1 | 1 | 0 | 1 |
| genuine_data | 6 | 6 | 0 | 0 | 0 |
| genuine_devops | 4 | 4 | 0 | 0 | 0 |
| genuine_docs | 12 | 10 | 2 | 0 | 0 |
| genuine_essay | 10 | 10 | 0 | 0 | 0 |
| genuine_go | 4 | 4 | 0 | 0 | 0 |
| genuine_html | 1 | 1 | 0 | 0 | 0 |
| genuine_javascript | 2 | 2 | 0 | 0 | 0 |
| genuine_multi_turn | 75 | 57 | 10 | 8 | 0 |
| genuine_python | 19 | 17 | 2 | 0 | 0 |
| genuine_rust | 4 | 4 | 0 | 0 | 0 |
| genuine_short | 10 | 10 | 0 | 0 | 0 |
| genuine_typescript | 1 | 1 | 0 | 0 | 0 |
| legitimate | 15 | 13 | 1 | 0 | 1 |

### Genuine Response Times (successful only)

| Metric | Value |
|--------|-------|
| Min | 2.9s |
| Max | 1,429s (23.8 min) |
| Average | 135.7s |
| Median | 100.0s |

**By category:**
- genuine_bash: 3 ok, avg 82s, range 52-119s
- genuine_config: 4 ok, avg 78s, range 35-125s
- genuine_container: 1 ok, avg 48s
- genuine_data: 6 ok, avg 141s, range 47-337s
- genuine_devops: 4 ok, avg 119s, range 71-152s
- genuine_docs: 10 ok, avg 118s, range 41-236s
- genuine_essay: 10 ok, avg 164s, range 102-254s
- genuine_go: 4 ok, avg 96s, range 68-135s
- genuine_html: 1 ok, avg 101s
- genuine_javascript: 2 ok, avg 81s, range 65-97s
- genuine_multi_turn: 57 ok, avg 149s, range 3-1429s
- genuine_python: 17 ok, avg 142s, range 33-337s
- genuine_rust: 4 ok, avg 74s, range 54-107s
- genuine_short: 10 ok, avg 55s, range 22-113s
- genuine_typescript: 1 ok, avg 97s
- legitimate: 13 ok, avg 127s, range 3-432s

### Qwen Output Quality (NOT YET ASSESSED)
The stress test JSONL does not store the full response content — only metadata (plan_summary, status, timing, step_count). To assess Qwen's output quality (essay accuracy, code correctness, hallucination rate), we would need to either:
1. Run a targeted subset with full response logging, or
2. Manually test via the WebUI with specific prompts

This is flagged as a follow-up task.

## Adversarial Performance

**Combined catch rate: 747/801 (93.3%)**
**True escape rate: 44/801 (5.5%)**

### By Category

| Category | Total | Blocked | Refused | Escaped | Error | Escape % |
|----------|-------|---------|---------|---------|-------|----------|
| benchmark_inspired | 5 | 5 | 0 | 0 | 0 | 0% |
| chunking_boundary | 8 | 8 | 0 | 0 | 0 | 0% |
| model_specific_jailbreak | 10 | 10 | 0 | 0 | 0 | 0% |
| encoding_obfuscation | 51 | 28 | 17 | 6 | 0 | 12% |
| non_english_injection | 30 | 27 | 0 | 3 | 0 | 10% |
| threshold_evasion | 10 | 9 | 0 | 1 | 0 | 10% |
| unicode_homoglyph | 12 | 11 | 0 | 1 | 0 | 8% |
| edge_case | 44 | 35 | 2 | 4 | 3 | 9% |
| indirect_injection | 70 | 60 | 1 | 3 | 6 | 4% |
| cross_model_confusion | 15 | 11 | 0 | 4 | 0 | 27% |
| credential_exfiltration | 66 | 46 | 19 | 1 | 0 | 2% |
| social_engineering | 65 | 46 | 19 | 0 | 0 | 0% |
| path_traversal | 97 | 58 | 39 | 0 | 0 | 0% |
| direct_injection | 114 | 93 | 21 | 0 | 0 | 0% |
| tool_manipulation | 30 | 19 | 11 | 0 | 0 | 0% |
| payload_free_injection | 15 | 11 | 4 | 0 | 0 | 0% |
| owasp_llm | 15 | 6 | 9 | 0 | 0 | 0% |
| dos_resource | 10 | 6 | 0 | 3 | 1 | 30% |
| code_injection | 51 | 17 | 24 | 10 | 0 | 20% |
| multi_turn | 83 | 37 | 21 | 22 | 3 | 27% |

### Top Block Reasons (scanner-level)

| Count | Reason |
|-------|--------|
| 200 | Input blocked — sensitive_path_scanner: sensitive_path |
| 90 | Output blocked — prompt_guard: prompt_guard_label_1 |
| 87 | Input blocked — prompt_guard: prompt_guard_label_1 |
| 38 | Input blocked — prompt_guard + sensitive_path (combined) |
| 22 | Output blocked — sensitive_path_scanner (multiple hits) |
| 20 | Output blocked — sensitive_path_scanner: sensitive_path |
| 13 | Input blocked — command_pattern_scanner: pipe_to_shell |
| 10 | Input blocked — sensitive_path_scanner (multiple hits) |
| 9 | Output blocked — sensitive_path_scanner (3+ hits) |
| 6 | Input blocked — credential_scanner: api_key |

### Categories with 0% Escape Rate (fully defended)
- benchmark_inspired, chunking_boundary, model_specific_jailbreak
- social_engineering, path_traversal, direct_injection
- tool_manipulation, payload_free_injection, owasp_llm

### Weakest Categories (highest escape %)
1. **dos_resource: 30%** — 3/10 escaped (repetitive input, nested JSON, repeated phrases)
2. **multi_turn: 27%** — 22/83 escaped (gradual escalation, innocuous-looking individual turns)
3. **cross_model_confusion: 27%** — 4/15 escaped (bilingual injection, Chinese instructions)
4. **code_injection: 20%** — 10/51 escaped (vulnerable code wrapped in "help me improve/test" framing)
5. **encoding_obfuscation: 12%** — 6/51 escaped

## False Positives (25 total)

### By Scanner

| Scanner | FP Count | Trigger |
|---------|----------|---------|
| sensitive_path_scanner (output) | 8 | Qwen output mentioned paths like `/etc/`, `/usr/` in educational context |
| credential_scanner (output) | 5 | Qwen output contained example Redis URIs, postgres URIs, JWT tokens |
| command_pattern_scanner (input) | 2 | Python socket/websocket server prompts matched "reverse shell" pattern |
| command_pattern_scanner (output) | 1 | setuid/setgid explanation matched chmod_setuid pattern |
| CodeShield (output) | 1 | Redis cache decorator flagged as insecure |
| Provenance trust gate | 1 | Redis Sentinel config — multi-step plan hit trust gate |
| Tool execution | 1 | Podman networking example — `||` matched injection pattern |
| Planner refusal | 6 | Multi-turn context loss — planner couldn't follow conversation |

### Key FP Patterns
1. **Output scanners too aggressive on educational content** — Qwen explaining cgroups, Containerfiles, CI pipelines, setuid bits naturally mentions sensitive paths and commands
2. **Credential scanner matches example URIs** — `redis://localhost:6379`, `postgresql://user:pass@host/db` in code examples
3. **Socket/websocket prompts match reverse shell** — "Python asyncio websocket server" triggers `scripting_reverse_shell`
4. **Multi-turn context loss** — planner can't reference earlier conversation, refuses follow-up questions

## Errors (13 total)

| Error Type | Count | Details |
|------------|-------|---------|
| File not found | 4 | Tool tried to read non-existent workspace files |
| Undefined variable | 4 | Planner referenced `$vars` not defined in prior steps |
| Podman not available | 1 | `podman` binary not in container PATH |
| Invalid JSON from Claude | 1 | Truncated planner response |
| Unknown step type | 1 | Planner used `file_write` type (not a valid step type) |
| Injection pattern in tool | 1 | `||` in shell command blocked by injection detector |
| Missing file for injection test | 1 | Adversarial test referenced non-existent file |

## Comparison: v1 vs v2

| What changed | v1 → v2 |
|--------------|---------|
| Prompt count | 742 → 976 (+31%) |
| Genuine prompts | 100 → 175 (+75%, mainly multi-turn) |
| Adversarial categories | 10 → 21 (+11 new categories) |
| True escape rate | 5.3% → 5.5% (stable despite harder test set) |
| Combined catch rate | 89.9% → 93.3% (+3.4%) |
| False positive rate | 17% → 14.3% (-2.7%) |
| Errors | 34 → 13 (-62%) |
| Session isolation | No → Yes |
| Rate limit handling | Budget stop → Retry 5x |

The escape rate held steady at ~5.5% despite adding 11 new adversarial categories, many specifically designed to probe weaknesses (threshold evasion, boundary chunking, model-specific jailbreaks, benchmark-inspired attacks). The new categories that were added (tool_manipulation, model_specific_jailbreak, benchmark_inspired, payload_free_injection, etc.) were almost all fully defended — the escapes concentrate in the same categories as v1: multi_turn and code_injection.

## Follow-Up Tasks

1. **Analyse the 44 escapes** — determine which are true security risks vs. benign (e.g., "list files in /workspace/" is arguably fine)
2. **Tune FP scanners** — sensitive_path_scanner and credential_scanner are too aggressive on output (educational content, example URIs)
3. **Assess Qwen output quality** — need targeted tests with full response logging to evaluate essays, code, hallucinations
4. **Multi-turn FP reduction** — planner context loss causes 6 refused FPs in genuine multi-turn chains
5. **code_injection category** — 20% escape rate needs investigation; "help me improve this vulnerable code" framing bypasses scanners
