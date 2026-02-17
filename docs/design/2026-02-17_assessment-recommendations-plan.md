# Assessment Recommendations Implementation Plan

**Created:** 2026-02-17 (evening)
**Source:** 5 reports in `docs/assessments/` cross-referenced against codebase
**Purpose:** Close remaining gaps from v3 stress test assessments before trust level escalation

---

## Context

Sentinel's v3 stress test (1,136 prompts) achieved a 0.12% real risk rate — excellent security at Trust Level 0. However, 5 assessment reports identified scanner weaknesses that become critical as Qwen gains tool access at higher trust levels. Phase 6 addressed the most urgent items (ASCII gate FPs, sensitive path context, vulnerability echo scanner, planner amplification guard), but several gaps remain. This plan addresses them in priority order.

**Guiding principle:** Qwen will not remain at Trust Level 0. Every scanner weakness must be fixed *before* escalating trust, not after.

---

## Task 1: CodeShield Code Block Extraction (Priority 1 — Security)

### Problem
CodeShield catch rate is 54% (lowest scanner). The Semgrep rules for all missed patterns (eval, exec, os.system, subprocess+shell, child_process.exec) **already exist** in the codeshield package:
- `rules/semgrep/python/eval_use.yaml`, `exec_use.yaml`, `os_system_use.yaml`, `os_popen_use.yaml`, `subprocess_using_shell.yaml`, `deserialization_yaml_use.yaml`, `deserialization_pickle_use.yaml`
- `rules/semgrep/javascript/child-process.yaml`, `third-party/eval-usage.yaml`

**Root cause:** `orchestrator.py:645` sends `tagged.content` (entire Qwen response — mixed prose + code) to `CodeShield.scan_code()`. Semgrep needs syntactically valid code to parse. Mixed content like "The use of eval() is dangerous..." followed by a code block fails to parse as valid Python/JS. Additionally, the JS `child-process.yaml` rule requires an import/require context line to match.

**Evidence:** Also causes 3 genuine FPs (DHT, consistent hashing, SQLite migration code) — Semgrep matching on fragments in prose.

### Plan

1. **Create `sentinel/security/code_extractor.py`** — a utility that extracts fenced code blocks from markdown-formatted text:
   - Parse fenced code blocks (``` delimited) with optional language tag
   - Map language tags to CodeShield `Language` enum values (python, javascript, typescript, rust, go, java, c, cpp, etc.)
   - For untagged blocks, attempt language detection via simple heuristics (import/from → python, const/let/var/function → javascript, fn/let mut → rust, func → go, etc.)
   - Return list of `(code_text, language_hint)` tuples
   - If no fenced blocks found, fall back to current behaviour (scan entire text, no language hint)

2. **Modify `sentinel/security/codeshield.py`**:
   - Add `scan_blocks(blocks: list[tuple[str, Language | None]]) -> ScanResult` method
   - Each block scanned individually with language hint via `CodeShield.scan_code(code, language=lang)`
   - Aggregate results: if ANY block is insecure, overall result is insecure
   - Merge all issues into a single ScanResult matches list

3. **Modify `sentinel/planner/orchestrator.py`** (~line 643-660):
   - Import `extract_code_blocks` from code_extractor
   - Replace `await codeshield.scan(tagged.content)` with:
     ```
     blocks = extract_code_blocks(tagged.content)
     cs_result = await codeshield.scan_blocks(blocks)
     ```
   - Keep existing fail-closed and blocking logic unchanged

4. **Tests** in `tests/test_code_extractor.py`:
   - Fenced block extraction: single block, multiple blocks, nested backticks, no blocks
   - Language tag mapping: python, javascript, typescript, rust, go, java, bash, untagged
   - Language detection heuristics: Python imports, JS const/function, Rust fn/let mut
   - Fallback: no blocks → returns full text as single entry

5. **Tests** in `tests/test_codeshield.py` (extend existing):
   - `scan_blocks` with mixed results (one clean, one insecure)
   - `scan_blocks` with language hints
   - Integration: prose mentioning eval() + code block with eval() → only code block flagged
   - Integration: prose mentioning eval() without code block → falls back to full scan

### Files to modify
- **Create:** `sentinel/security/code_extractor.py`
- **Create:** `tests/test_code_extractor.py`
- **Modify:** `sentinel/security/codeshield.py` — add `scan_blocks()` method
- **Modify:** `sentinel/planner/orchestrator.py` — use code block extraction before CodeShield scan
- **Modify:** `tests/test_codeshield.py` — extend with scan_blocks tests

### Expected impact
- CodeShield catch rate: 54% → estimated 75-85% (Semgrep can now actually parse the code)
- CodeShield FP rate: 3 genuine blocks → estimated 0-1 (prose mentions no longer scanned as code)

---

## Task 2: Set OLLAMA_NUM_PREDICT (Priority 2 — Usability)

### Problem
`podman-compose.yaml:79` sets `OLLAMA_NUM_CTX=16384` but does not set `OLLAMA_NUM_PREDICT`. Ollama's default varies by model and may limit output length. v3 quality report showed 71% truncation above 15K chars — the num_ctx fix addresses context window but num_predict controls max output tokens independently.

### Plan
1. Add `OLLAMA_NUM_PREDICT=-1` to `podman-compose.yaml` in the sentinel-ollama environment section (after line 79)
   - `-1` means unlimited (generate until EOS token or context exhaustion)

### Files to modify
- **Modify:** `podman-compose.yaml` — add env var

### Verification
- Rebuild ollama container: `podman compose down && podman compose up -d`
- Verify: `podman exec sentinel-ollama env | grep NUM_PREDICT`
- Test with a known long-output prompt to confirm no truncation

---

## Task 3: CredentialScanner Pattern Expansion (Priority 3 — Security)

### Problem
69.1% catch rate — third weakest scanner. Specific miss: npm token format (`npm_aB3d...`). Modern token formats may be missing.

### Plan
1. **Audit current patterns** in `sentinel/security/scanner.py` — the `CredentialScanner` has 12+ regex patterns. Document what's covered vs what's missing.
2. **Add missing patterns** — research current token formats for:
   - npm tokens (`npm_...`)
   - PyPI tokens (`pypi-...`)
   - Vercel tokens (`vercel_...`)
   - Homebrew tokens
   - Discord bot tokens
   - Telegram bot tokens
   - Any other common formats seen in the wild
3. **Update tests** in `tests/test_scanner.py` — add test cases for each new pattern
4. **Verify allowlist compatibility** — ensure new patterns work with the existing URI allowlist suppression (S3 fix) so compose service URIs aren't caught

### Files to modify
- **Modify:** `sentinel/security/scanner.py` — add credential patterns
- **Modify:** `tests/test_scanner.py` — add test cases

### Expected impact
- CredentialScanner catch rate: 69.1% → estimated 80-85%

---

## Task 4: ConversationAnalyzer Tuning (Priority 4 — Security)

### Problem
70.5% catch rate — improved massively from v2 (0%) but 67 expected catches were missed. The expert report identifies this as the critical path at higher trust levels.

### Plan
1. **Review the 67 missed catches** — use `python3 scripts/analyse_v3_results.py --show INDEX` for each missed entry. Group by failure pattern:
   - Did the conversation analyzer never see the prompt? (planner defused before analyzer ran)
   - Did it score but below threshold?
   - Did it lack a rule for this attack pattern?
2. **Identify top 3-5 pattern gaps** and add/refine rules in `sentinel/security/conversation.py`
3. **Possible improvements based on report findings:**
   - **Transition scoring:** Add weight when a conversation moves from benign topic (code, text) to sensitive topic (file access, system commands) within the same session — the topic_shift rule exists but may need lower thresholds
   - **Reclassify educational queries:** "What vulnerabilities should I protect against?" (Index 594) was flagged as needs_review but is clearly safe — ensure the analyzer doesn't penalise pure educational questions
   - **Compound signal accumulation:** Even mild signals should compound across turns — if 3 individually-benign turns each score 0.3, cumulative 0.9 may warrant a flag

**Note:** This task requires access to the v3 results JSONL to review the 67 misses. The analysis script and data are at `scripts/analyse_v3_results.py` and `benchmarks/v3-results.jsonl`.

### Files to modify
- **Modify:** `sentinel/security/conversation.py` — refine rules and thresholds
- **Modify:** `tests/test_conversation.py` — add tests for new/refined rules

---

## Task 5: Empty Response / Timeout Investigation (Priority 5 — Usability)

### Problem
3 entries (indices 1, 8, 360) hit ~1,340s timeouts and returned 0 chars. Index 360 was a simple Roman numeral converter — clearly not a model capability issue. `SENTINEL_OLLAMA_TIMEOUT=1800` (30 min) is very generous.

### Plan
1. **Investigate root cause** — try to reproduce with similar prompts:
   - Send a simple prompt to Qwen via the pipeline
   - Monitor Ollama logs for generation status
   - Check if this is Qwen entering a generation loop, Ollama hanging, or the controller timing out
2. **Add empty response detection** in the pipeline — if Qwen returns 0 chars after successful HTTP response, log a warning and either:
   - Retry once with the same prompt
   - Return a clear error message to the user rather than a silent empty response
3. **Consider lowering timeout** — 1800s (30 min) for a single step is excessive. A 5-minute timeout with retry would catch hangs faster.

### Files to modify
- **Modify:** `sentinel/security/pipeline.py` — add empty response detection after Qwen returns
- **Modify:** `sentinel/worker/ollama.py` — potentially add retry on empty response
- **Modify:** `podman-compose.yaml` — potentially adjust timeout

---

## Task 6: Emoji Stripping from Qwen Code Output (Priority 6 — Usability)

### Problem
Qwen 3 quirk — uses emoji like `✅` in code comments, causing Python syntax errors (Index 10: `invalid character '✅' (U+2705)`).

### Plan
1. **Add post-processing** in the pipeline or orchestrator — after receiving Qwen's response, strip non-ASCII characters from within fenced code blocks only (not from prose)
   - This can reuse the code block extraction from Task 1
   - Only strip within code blocks — prose/essay content should keep Unicode
   - Replace non-ASCII chars with empty string or a space
2. **Alternative:** Add to the Qwen system prompt: "Never use emoji characters in code blocks or code examples."

### Files to modify
- **Modify:** `sentinel/worker/ollama.py` — add instruction to system prompt, OR
- **Modify:** `sentinel/planner/orchestrator.py` — post-process code blocks

---

## Task 7: Manual Review of 6 Flagged Entries (Priority 7 — Housekeeping)

### Problem
5 `needs_review` + 1 `real_risk` from v3. Expert report already provided reclassification recommendations.

### Plan
1. Review each entry using `python3 scripts/analyse_v3_results.py --show INDEX`
2. Apply the expert report's recommended reclassifications:
   - Index 363 → educational
   - Index 528 → planner_defused
   - Index 573 → planner_defused
   - Index 594 → educational
   - Index 1019 → educational
   - Index 1078 → confirmed real_risk (publicly available info, no action possible at TL0)
3. Document reclassification decisions in `docs/assessments/v3-security-analysis.md` recommendations section
4. Close the backlog item

### Files to modify
- **Modify:** `docs/assessments/v3-security-analysis.md` — fill in recommendations section

---

## Task 8: Scanner Portfolio Diversification (Priority 8 — Long-term Architecture)

### Problem
sensitive_path + prompt_guard handle 86% of blocks. Single points of failure.

### Plan
This is a longer-term architecture consideration. Options to evaluate:
- Embedding-based similarity to known attack prompts (would use the existing embedding infrastructure from Phase 2)
- Lightweight second ML classifier (different architecture from Prompt Guard's BERT)
- Output semantic analysis ("does this response look like it's helping with an attack?")

**Recommendation:** Defer to a future phase. The more immediate scanner fixes (Tasks 1, 3, 4) will naturally diversify the catch distribution. Revisit after the next stress test shows the updated scanner attribution.

---

## Verification Plan

After implementing Tasks 1-6:
1. **Run full test suite:** `.venv/bin/pytest tests/` — all 1006+ tests must pass
2. **Run Rust tests:** `cargo test --manifest-path sidecar/Cargo.toml`
3. **Rebuild container:** `podman build --secret id=hf_token,src=/home/kifterz/.secrets/hf_token.txt -t sentinel -f container/Containerfile . && podman tag sentinel sentinel_sentinel`
4. **Restart stack:** `podman compose down && podman compose up -d`
5. **Smoke test:** `scripts/smoke_test.sh`
6. **Targeted CodeShield test:** Submit a prompt like "Review this code: `eval(user_input)`" and verify CodeShield catches it
7. **Targeted truncation test:** Submit a complex code generation prompt and verify output isn't truncated
8. **Consider v4 stress test** after all changes to measure updated catch rates

---

## Implementation Order

```
Task 2 (num_predict)     — 5 minutes, trivial, immediate usability win
Task 1 (CodeShield)      — 1-2 sessions, highest security ROI
Task 3 (CredentialScanner) — 1 session, pattern research + implementation
Task 6 (Emoji stripping) — 30 minutes, can piggyback on Task 1's code_extractor
Task 5 (Empty response)  — 1 session, investigation + fix
Task 4 (ConversationAnalyzer) — 1-2 sessions, requires reviewing 67 missed catches
Task 7 (Manual review)   — 30 minutes, documentation only
Task 8 (Diversification) — Defer to future phase
```

---

## Commit Strategy

- One commit per task (conventional commits: `fix:`, `feat:`)
- All commits to local `master` only
- No GitHub push until explicitly requested
