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
- Conversation analyser heuristic rules don't fire on trust-building turns (step 0/1 of chains). Keyword-based detection is blind to innocuous-looking individual turns
- sensitive_path_scanner is both the top blocker (47.1%) AND the top FP source (11/25). Context-aware output scanning needed
- Planner has no session memory — each /task call is stateless. Causes 8 FPs on genuine multi-turn follow-ups ("missing context")
- All 10 code_injection escapes use same pattern: submit vulnerable code + "review/test/debug this". Input-output vulnerability comparison needed
