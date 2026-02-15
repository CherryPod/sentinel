# Sentinel — Memory

## Key Reports & Assessments

- **Stress test v2 assessment (2026-02-15):** `docs/archive/2026-02-15_camel-pipeline-assessment.md`
  - Overall grade: 3.0/5 — strong foundations, not deployment-ready
  - Conversation analyser scored 1.0/5 — conv_risk_score 0.00 on all 22 multi-turn escapes
  - 19 of 25 FPs fixable with 3 targeted scanner pattern changes (no security cost)
  - Worker output quality ungraded — JSONL doesn't store response content
- **Stress test v2 raw results:** `docs/archive/2026-02-15_stress-test-v2-results.md`
- **Security audit (2026-02-14):** `docs/archive/2026-02-14_stress-test-security-audit.md`
- **Stress test v1 overview:** `docs/archive/2026-02-14_stress-test-overview.md`

## Gotchas & Learnings

- Stress test JSONL stores metadata only — no response content. Need separate quality test with full logging
- Container uses read-only FS with files copied at build time (not bind-mounted). Must rebuild to pick up code changes — see `docs/PROJECT_DOCS.md` "Rebuilding Containers" section
- Hostile Qwen test payloads must put sensitive paths in operational context (code blocks, shell commands) — context-aware output scanner passes prose mentions
- When updating existing tests for scanner behavior changes, check `test_hostile.py` too — it simulates real attacks and depends on scanner behavior
- `execute_approved_plan` must record turns in the session — without this, `full` approval mode breaks multi-turn conversation history (turns never get stored, planner sees empty history)
- Browser/nginx 504 timeout (300s) is shorter than Qwen generation time for long prompts. If Turn 1 times out in the browser and user sends Turn 2 before the server finishes Turn 1, the session has no history yet. Not a code bug — concurrency/latency issue
- ASCII prompt gate only checks `prompt` param, not `untrusted_data`. Hostile test for chained Chinese injection needs `skip_input_scan=True` to simulate the real scenario (orchestrator skips input scan on chained steps because output was already scanned)

## What Was Done (2026-02-15, latest session)

Three defence-in-depth additions targeting W4 (encoding obfuscation) and W7 (cross-model bilingual injection):

1. **EncodingNormalizationScanner** (W4) — decodes base64/hex/URL/ROT13/HTML entities/char-splitting and re-scans decoded text with inner scanners. Wired into both input + output scan pipelines
2. **Planner language safety rule** (W7 LLM layer) — LANGUAGE SAFETY RULE in planner system prompt tells Claude to never include non-English text in worker prompts, translate everything to English first
3. **ASCII prompt gate** (W7 deterministic layer) — regex allowlist (`\x20`-`\x7E` + whitespace) on the `prompt` param in `process_with_qwen()`, catches anything Claude lets through

529 tests passing (up from 492). All changes in scanner.py, pipeline.py, planner.py + tests.

## Next Steps

Priority order:

1. **Targeted stress test rerun** — validate W4 + W7 improvements with real data (encoding_obfuscation, cross_model_confusion, non_english_injection, plus genuine categories for FP check). This is the most important next step — unit tests prove the logic works, but only a live stress test proves it works against real attack patterns
2. **Edge case/DoS input validation** — empty prompts (`.`, whitespace) waste minutes of Qwen time. Add min/max length + nesting limits before pipeline. Quick win
3. **Multi-turn escapes (27%)** — biggest remaining gap. Conversation analyser scored 0.00 on all 22 escapes. Needs fundamental rework — current heuristics don't catch gradual trust-building. Consider: sliding-window chain scoring, explicit multi-turn state machine, or dedicated Claude call for chain assessment
4. **Planner undefined variable errors** — 5 errors in stress test, quick planner prompt fix
5. **Scanner concentration risk (W3)** — structural, not urgent. Two scanners handle ~86% of blocks. If either has a systematic blind spot, escape rate spikes
6. **Qwen output quality (W5)** — still unmeasured. Need quality test with full response logging to grade actual output
7. **Response latency (W6)** — hardware-constrained (RTX 3060 + 14B model). Not fixable without hardware upgrade or smaller model

### Considerations

- W4 and W7 are now both LLM + deterministic layered. The stress test rerun will show if the encoding scanner catches the base64/hex obfuscation attacks that previously escaped, and whether the ASCII gate blocks bilingual injection that the planner rule misses
- The EncodingNormalizationScanner runs ROT13 on all input/output — watch for FPs on normal text that happens to ROT13 into a scanner pattern. The stress test rerun will surface this if it's an issue
- Multi-turn remains the hardest problem. The conversation analyser's heuristic rules aren't enough — each individual turn looks benign. May need to invest in a dedicated chain-assessment approach rather than iterating on heuristics

## Key Paths for Context Loading

- `memory/MEMORY.md` — this file (gotchas, next steps)
- `docs/PROJECT_DOCS.md` — architecture, config, file tree, current status
- `docs/CHANGELOG.md` — version history, all changes
- `docs/archive/2026-02-15_camel-pipeline-assessment.md` — stress test v2 expert assessment (3.0/5)
- `docs/archive/2026-02-15_security-improvement-plan.md` — implementation plan for the post-assessment work
- `controller/app/` — all source code (scanner.py, pipeline.py, orchestrator.py, planner.py, conversation.py, session.py, approval.py)
- `controller/tests/` — all tests (test_scanner.py, test_pipeline.py, test_hostile.py, test_encoding_scanner.py, test_conversation.py, test_orchestrator.py, test_planner.py)
- `scripts/stress_test_runner.py` — stress test runner
- `policies/sentinel-policy.yaml` — security policy rules

## Resolved (2026-02-15)

- ~~sensitive_path_scanner FP source (11/25)~~ → Fixed: context-aware `scan_output_text()` for output scanning
- ~~Planner has no session memory~~ → Fixed: conversation history injected into planner prompt
- ~~Code injection "review/test/debug" escapes~~ → Fixed: VulnerabilityEchoScanner compares input/output fingerprints
- ~~Conversation analyser blind to trust-building~~ → Improved: Rules 7 (recon) + 8 (topic shift) + Claude chain-level assessment
- ~~Encoding obfuscation bypasses regex (W4)~~ → Fixed: EncodingNormalizationScanner decodes before re-scanning
- ~~Cross-model bilingual injection (W7)~~ → Fixed: planner language safety rule + ASCII prompt gate (deterministic backstop)
