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

## Next Steps (post 2026-02-15 improvements)

Priority order:
1. **Targeted stress test rerun** — validate improvements with real data (multi_turn, code_injection, genuine_multi_turn, FP-prone categories)
2. **Cross-model confusion (W7)** — 27% escape on bilingual injection. Cheapest remaining win: planner prompt rule to translate non-English text
3. **Edge case/DoS input validation** — empty prompts (`.`, whitespace) waste minutes. Add min/max length + nesting limits
4. **Encoding obfuscation** — 12% escape. Base64/ROT13/URL encoding bypass regex. Needs pre-scan decode step
5. **Planner undefined variable errors** — 5 errors, quick planner prompt fix
6. **Scanner concentration risk (W3)** — structural, not urgent. Two scanners handle ~86% of blocks
7. **Qwen output quality (W5)** — still unmeasured. Need quality test with full response logging
8. **Response latency (W6)** — hardware-constrained (RTX 3060 + 14B model)

## Key Paths for Context Loading

- `memory/MEMORY.md` — this file (gotchas, next steps)
- `docs/PROJECT_DOCS.md` — architecture, config, file tree, current status
- `docs/CHANGELOG.md` — version history, all changes
- `docs/archive/2026-02-15_camel-pipeline-assessment.md` — stress test v2 expert assessment (3.0/5)
- `docs/archive/2026-02-15_security-improvement-plan.md` — implementation plan for the work just completed
- `controller/app/` — all source code (scanner.py, pipeline.py, orchestrator.py, planner.py, conversation.py, session.py, approval.py)
- `controller/tests/` — all tests (test_scanner.py, test_pipeline.py, test_hostile.py, test_conversation.py, test_orchestrator.py, test_planner.py)
- `scripts/stress_test_runner.py` — stress test runner
- `policies/sentinel-policy.yaml` — security policy rules

## Resolved (2026-02-15)

- ~~sensitive_path_scanner FP source (11/25)~~ → Fixed: context-aware `scan_output_text()` for output scanning
- ~~Planner has no session memory~~ → Fixed: conversation history injected into planner prompt
- ~~Code injection "review/test/debug" escapes~~ → Fixed: VulnerabilityEchoScanner compares input/output fingerprints
- ~~Conversation analyser blind to trust-building~~ → Improved: Rules 7 (recon) + 8 (topic shift) + Claude chain-level assessment
