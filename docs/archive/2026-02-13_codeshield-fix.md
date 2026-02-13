# CodeShield Fix — Investigation & Resolution (2026-02-13)

## Problem

CodeShield was installed in the sentinel-controller container (`llamafirewall` + `codeshield` packages) but never actually worked. The `codeshield.py` module tried `from llamafirewall import CodeShieldScanner` which doesn't exist — so `is_loaded()` always returned `False` and CodeShield was silently skipped. This was the root cause of red team test 5.4 failing (surveillance script not caught).

## Investigation

### Wrong API

The original code assumed the API was:
```python
from llamafirewall import CodeShieldScanner  # Does not exist
scanner = CodeShieldScanner()
result = scanner.scan(code)
```

The actual API is:
```python
from codeshield.cs import CodeShield
result = await CodeShield.scan_code(code)  # async, class method
```

Key differences:
- Import path is `codeshield.cs`, not `llamafirewall`
- `scan_code()` is an **async class method**, not a sync instance method
- Result uses `issues_found` (not `issues`) and `cwe_id` (not `rule`)
- Result has `recommended_treatment` (Treatment.IGNORE / WARN / BLOCK)

### Deeper Issue: osemgrep Bug

Even after fixing the import, CodeShield's Semgrep rules returned **zero results** for known-insecure code. Investigation revealed:

1. The `codeshield` package internally uses `osemgrep --experimental` as the Semgrep command
2. `osemgrep` (the OCaml-native Semgrep binary) has a bug where `patterns` + `pattern-not` rules return zero results
3. Regular `semgrep` (same version 1.151.0, same rules) works perfectly

**Verification** (run inside the container):
```bash
# osemgrep — returns 0 findings (BUG)
echo 'import os; os.system(x)' > /tmp/test.py
osemgrep --experimental --json --config /path/to/rules /tmp/test.py
# → {"results": []}

# semgrep — returns correct findings
semgrep --json --config /path/to/rules /tmp/test.py
# → {"results": [{"check_id": "insecure-os-system-usage", ...}]}
```

Both binaries are version 1.151.0, installed by the same package. The bug is specifically in `osemgrep --experimental` mode with compound pattern rules.

## Fix

### 1. Semgrep command patch (`codeshield.py:initialize()`)

At init time, before any scanning occurs, patch the internal command:
```python
from codeshield.insecure_code_detector import oss
oss.SEMGREP_COMMAND = ["semgrep", "--json", "--quiet", "--metrics", "off", "--config"]
```

This replaces the default `["osemgrep", "--experimental", "--json", ...]` with the working `semgrep` binary.

### 2. Correct API usage (`codeshield.py:scan()`)

```python
from codeshield.cs import CodeShield

async def scan(code: str) -> ScanResult:
    result = await CodeShield.scan_code(code)
    # result.is_insecure: bool
    # result.issues_found: list[Issue] | None
    # Issue fields: .description, .cwe_id, .severity, .line, .rule, .pattern_id
```

### 3. Async propagation

`scan()` is now async, so `orchestrator.py` needed `await codeshield.scan(...)` and all test mocks needed `AsyncMock`.

### 4. Startup initialization (`main.py`)

Added `codeshield.initialize()` to the FastAPI lifespan startup, plus `codeshield_loaded` field in `/health` endpoint.

## Files Changed

| File | Change |
|------|--------|
| `controller/app/codeshield.py` | Full rewrite — correct API, semgrep patch, async scan |
| `controller/app/orchestrator.py` | `codeshield.scan()` → `await codeshield.scan()` |
| `controller/app/main.py` | Added init call + health check field |
| `controller/tests/test_codeshield.py` | All tests async, mock `CodeShield.scan_code`, new init test |
| `controller/tests/test_orchestrator.py` | 2 tests: `mock_cs.scan` → `AsyncMock` |
| `controller/tests/test_hardening.py` | 2 tests: `mock_cs.scan` → `AsyncMock` |

## Verification

- **315 tests passing** (was 314 — gained `test_successful_init`)
- **Health check**: `codeshield_loaded: true`
- Container restarted and serving with CodeShield active

## Known Limitation

The semgrep patch is a workaround for an upstream bug in `osemgrep --experimental`. If the `codeshield` package updates and fixes `osemgrep`, or changes the `SEMGREP_COMMAND` variable location, the patch may need revisiting. The patch is low-risk — it simply uses the stable `semgrep` binary instead of the experimental one.
