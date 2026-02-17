# Code Fixer v2.5

A deterministic, multi-language code fixer that corrects common output errors from the worker LLM (Qwen). It runs after security scanning and before writing to disk, catching syntax issues, hallucinated imports, and truncation artifacts that would otherwise cause task failures.

## Key Design Decisions

- **Deterministic, not AI-based.** The fixer uses AST parsing, regex, and heuristics — no LLM calls. This keeps it fast, predictable, and independent of model availability.
- **Fail-safe by design.** Each fixer is wrapped in try/except, and the entire chain is wrapped again in the executor. A crash in any fixer results in the original content being written unchanged.
- **Gated by file type.** Only runs on known code extensions plus Dockerfile/Makefile by name. Data files and configuration are never modified.

## Fixers and Detectors

### Auto-Fixers (7)

| Fixer | Language | What It Fixes |
|-------|----------|---------------|
| Missing stdlib imports | Python | AST-based detection of used-but-unimported stdlib modules (allowlist-based) |
| Hallucinated import correction | Python | Removes imports of non-existent modules that Qwen invents |
| Bracket mismatch repair | Python | Swaps wrong bracket types, removes unmatched closers |
| Attribute quote normalisation | HTML | Normalises mixed quote styles in HTML attributes |
| Entity encoding | HTML | Fixes malformed HTML entities |
| Shebang repair | Shell | Adds or fixes shebang lines |
| Missing closers | Shell | Adds missing `fi`/`done`/`esac` closers |

### Detectors (6)

| Detector | Languages | What It Catches |
|----------|-----------|-----------------|
| Truncation detection | All 13 | Incomplete code (mid-statement, unclosed blocks) |
| Duplicate block detection | JS/TS/Rust/Go | Repeated function/class definitions |
| Unsafe shell patterns | Shell | `rm -rf /`, `chmod 777`, `curl | sh` |
| Python syntax validation | Python | Checks via `parso` AST parser |
| JSON repair | JSON | Attempts structural repair via `json-repair` |
| Cross-language bracket check | All | Unbalanced brackets/braces/parens |

### Coverage

13 languages: Python, JavaScript, TypeScript, HTML, CSS, Shell/Bash, Rust, Go, Java, C, C++, Ruby, PHP. Plus Dockerfile and Makefile by filename.

## Dependencies

- `parso>=0.8` — Python AST parsing (graceful degradation if missing)
- `json-repair>=0.30` — JSON structural repair (graceful degradation if missing)

## Where the Code Lives

| File | Purpose |
|------|---------|
| `sentinel/security/code_fixer.py` | All fixers, detectors, and the fixer chain |
| `sentinel/planner/tool_dispatch.py` | Integration point — calls fixer in `_file_write()` |
| `tests/test_code_fixer.py` | 270 unit tests |
| `tests/test_code_fixer_integration.py` | 7 integration tests |
