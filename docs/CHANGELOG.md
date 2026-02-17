# Changelog

All notable changes to Sentinel, post v0.1 migration. Uses [Keep a Changelog](https://keepachangelog.com/) categories, grouped by date.

For v0.1 migration history (Phases 0-6), see `archive/2026-02-17_v0.1-migration-changelog.md`.

---

## 2026-02-17 (cont.)

### Changed
- **Script gate replaces strict ASCII gate** — expanded allowlist from printable ASCII to ASCII + Latin Extended + typographic symbols (smart quotes, em-dashes, math operators, currency, arrows, box drawing, etc.). Gate now always checks the prompt going to Qwen (not user_input), blocking CJK, Cyrillic, Arabic, Hangul, and other non-Latin scripts while allowing Claude's legitimate Unicode. Eliminates 45/60 false positives from v3 stress test (75% of all FPs)
- **4 new tests, 6 updated** (1090 → 1094) — smart quotes, math/currency, accented Latin pass-through; Hangul blocking; updated error message assertions

---

## 2026-02-17

### Added
- Assessment recommendations plan (`docs/design/2026-02-17_assessment-recommendations-plan.md`) — 8 tasks derived from v3 stress test reports
- **Code block extractor** (`sentinel/security/code_extractor.py`) — extracts fenced markdown code blocks with language detection (tag mapping + heuristics for Python, JS, Rust, Java, C, PHP) for targeted CodeShield scanning
- **`scan_blocks()` method** on CodeShield scanner — scans individual code blocks with language hints instead of entire mixed prose+code responses
- **10 new credential patterns** in `policies/sentinel-policy.yaml` — npm, PyPI, Hugging Face, Google API, Stripe, SendGrid, DigitalOcean, Vercel, Telegram, Grafana tokens
- **Emoji stripping** from Qwen code output — two-layer fix: system prompt rule + `strip_emoji_from_code_blocks()` post-processing (prose emoji preserved)
- **Empty response retry** in pipeline — if Qwen returns empty/whitespace, retries once then raises RuntimeError
- **First-turn instruction override detection** — ConversationAnalyzer now checks for override attempts on the very first turn (previously skipped)
- **7 new override patterns** — system override, safety mode off, bypass filters, new directive, disable filtering, restrictions lifted, programming revised
- **8 new sensitive topic terms** — `/root/`, `/home/`, `/var/log/`, `bash_history`, `.bashrc`, `sudoers`, `auth.log`, `system access`
- **84 new tests** (1006 → 1090) covering all new functionality

### Changed
- CodeShield now scans extracted code blocks instead of full Qwen response text (expected catch rate improvement: 54% → 75-85%)
- `OLLAMA_NUM_PREDICT=-1` added to `podman-compose.yaml` — unlimited output tokens (was using Ollama default)
- Container rebuilt and redeployed with all assessment plan changes (1090/1090 tests pass in-container)
- Archived migration-era docs (evolution tracker, evolution plan, old changelog) to `docs/archive/`
- Fresh changelog format: date-grouped with conventional categories

### Security
- Manual review of 6 flagged v3 entries complete — 5 reclassified (3 educational, 2 planner_defused), 1 confirmed real_risk (public info, no action at TL0). Revised real escape rate: **0.12%** (1/811 adversarial)
- Assessment plan Tasks 1-7 complete (Task 8 deferred per plan)
