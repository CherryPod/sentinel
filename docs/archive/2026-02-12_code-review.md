# Code Review — 2026-02-12

> Initial review of the full Sentinel codebase at Phase 4a completion.
> Status: project is actively under construction — these are findings to address as development continues.

---

## Security Issues

### 1. No authentication on API endpoints — HIGH

**Files:** `main.py`, `podman-compose.yaml:25`

The FastAPI app has zero auth. Port 8000 is mapped to the host, and the UI proxy on 3001 forwards everything. Anyone who can reach those ports can submit tasks, approve plans, or deny them. The approval flow is meaningless if an attacker can just call `/approve/{id}` themselves.

**Fix:** Add a shared bearer token (loaded from Podman secrets) as middleware, or use an API key header check. Even a simple shared secret is better than nothing.

---

### 2. CodeShield is never initialized — MEDIUM

**File:** `main.py:30-92`

`codeshield.initialize()` is never called in the lifespan function. Prompt Guard and the pipeline are initialised, but CodeShield is skipped. This means `codeshield.is_loaded()` always returns `False`, and code-generating steps silently bypass static analysis. The check at `orchestrator.py:239` (`if step.expects_code and codeshield.is_loaded()`) always evaluates to False.

**Fix:** Add `codeshield.initialize()` call in the lifespan function alongside Prompt Guard init.

---

### 3. Tool executor doesn't enforce provenance trust checks — MEDIUM

**File:** `tools.py`

The build plan says "untrusted data cannot be passed to shell commands without scanning + human approval." But the tool executor never checks trust levels. The provenance module has `is_trust_safe_for_execution()` (`provenance.py:84-87`) but nothing calls it. Qwen output (tagged UNTRUSTED) flows into `file_write` content via variable resolution with no trust gate.

**Fix:** Before executing any tool, resolve the input variable IDs and call `is_trust_safe_for_execution()`. Block or require approval if any input is untrusted.

---

### 4. Path-constrained commands only check absolute paths — MEDIUM

**File:** `policy_engine.py:257-259`

The path-constrained command filter only checks arguments starting with `/`:
```python
path_args = [a for a in args if ... and a.startswith("/")]
```

Relative paths are ignored. `cat ../../../etc/passwd` passes because the path doesn't start with `/`. Same for `find . -name shadow`.

**Fix:** Resolve all non-flag arguments to absolute paths (using the workspace as CWD) before checking against the policy. Also check arguments that don't start with `/`.

---

### 5. Podman run/build don't check for dangerous flags — MEDIUM

**Files:** `tools.py:221-252`, policy YAML

The policy says "podman run with -p flag" and "podman run with -v flag" should require human approval. But `_podman_run` doesn't check for these flags. Currently the tool only passes `--name` and `-d`, but there's no enforcement preventing Claude from requesting port mappings or volume mounts via the args dict if the tool is extended.

**Fix:** Validate podman args against the approval policy before execution. If `-p` or `-v` are present, require approval.

---

### 6. No CSRF protection on WebUI — LOW-MEDIUM

**File:** `gateway/static/app.js:142-149`

The UI makes plain fetch() calls with no CSRF tokens. If a user visits a malicious website while on the same network, it could submit tasks/approvals to `http://thebeast:3001/api/task` via cross-origin requests.

**Fix:** Add a CSRF token mechanism, or at minimum check the `Origin`/`Referer` headers in the controller. API auth (issue #1) also mitigates this.

---

### 7. `hex_secret_64` credential pattern too broad — LOW

**File:** `policies/sentinel-policy.yaml:108`

The regex `[0-9a-f]{64}` matches every SHA-256 hash — Docker image digests, git commit hashes, SRI integrity values, etc. This will cause frequent false positives on legitimate Qwen output.

**Fix:** Make the pattern more specific (e.g. require a key-like prefix or context), or move it to a "warn but don't block" tier.

---

## Bugs

### 8. Approval ID embedded in `reason` field

**Files:** `orchestrator.py:136`, `app.js:194`

The approval ID is passed via `reason=f"approval_id:{approval_id}"` and the WebUI parses it with `data.reason.replace('approval_id:', '')`. This works but is fragile — `reason` is a human-readable field being used as structured data.

**Fix:** Add a dedicated `approval_id: str = ""` field to the `TaskResult` model.

---

### 9. `podman_run` policy check vs execution mismatch

**File:** `tools.py:225,231`

The policy check validates `"podman run --name {name} {image}"` but the actual subprocess runs `["podman", "run", "--name", name, "-d", image]`. The `-d` flag isn't in the validated string, so the policy engine validates a different command than what actually executes.

**Fix:** Build the full command list first, then derive the policy check string from it — or validate the actual list.

---

### 10. Tool executor not wired to orchestrator

**File:** `main.py:75-79`

The Orchestrator is created but never receives a `ToolExecutor` instance. This means all `tool_call` plan steps return "skipped" (`orchestrator.py:279-292`). The pipeline can plan and run LLM tasks but can't write files or run commands.

**Fix:** Create a `ToolExecutor(policy_engine=_engine)` and pass it to the Orchestrator constructor.

---

## Design Observations

These aren't bugs — just things to consider as the project matures.

### 11. In-memory provenance store grows unboundedly

**File:** `provenance.py:8`

`_store: dict[str, TaggedData] = {}` has no size limit or TTL. A long-running controller accumulates all tagged data in memory indefinitely.

**Recommendation:** Add an LRU cap (e.g. keep last 10,000 entries) or periodic cleanup of entries older than N hours.

---

### 12. In-memory approval queue lost on restart

**File:** `approval.py:34`

`_pending: dict[str, PendingApproval] = {}` — if the container restarts between task submission and user approval, pending approvals are silently lost.

**Recommendation:** Persist to a small SQLite DB or flat file if durability matters. Low priority since approval_timeout is only 300s.

---

### 13. No request size limits

The FastAPI app has no body size limits. A client could send a multi-GB payload to `/task` or `/scan`.

**Recommendation:** Add a size limit middleware or use nginx `client_max_body_size` in the gateway (currently not set in `nginx.conf`).

---

### 14. No rate limiting

No rate limiting on any endpoint, including `/task` which calls the paid Claude API. A runaway script or abuse could burn through Anthropic credit.

**Recommendation:** Add basic rate limiting (e.g. slowapi or nginx `limit_req`).

---

### 15. Stored HTML in localStorage

**File:** `gateway/static/app.js:296`

System messages store raw HTML in localStorage and re-render on page load. Currently safe because `escapeHtml()` is used consistently, but storing and re-rendering raw HTML is a latent XSS risk if any future code path skips escaping.

**Recommendation:** Store structured data (text + metadata) in localStorage rather than pre-rendered HTML.

---

## Strengths

- **Policy engine as the foundation** — deterministic, immune to prompt injection, and acts as the last line of defence. Correct design choice.
- **Path traversal handling** is thorough — iterative URL decoding, null byte stripping, symlink resolution, raw input scanning before normalisation.
- **Test coverage** on the policy engine and hostile simulations is solid and meaningful.
- **Provenance inheritance** (untrusted parent = untrusted child) is correctly implemented with cycle detection.
- **Graceful degradation** — when Prompt Guard or CodeShield aren't available, the system falls back to deterministic scanners rather than failing open.
- **Air gap enforcement** via `internal: true` on `sentinel_internal` network is sound.
- **The build plan** is genuinely excellent documentation.

---

## Suggested fix priority

| Priority | Issue | Effort |
|----------|-------|--------|
| 1 | #2 — Initialize CodeShield | Trivial (one line) |
| 2 | #10 — Wire ToolExecutor to orchestrator | Trivial (few lines) |
| 3 | #8 — Add `approval_id` field to TaskResult | Small |
| 4 | #9 — Fix podman policy check mismatch | Small |
| 5 | #3 — Add trust checks in tool executor | Medium |
| 6 | #4 — Fix relative path checking | Medium |
| 7 | #1 — Add API authentication | Medium |
| 8 | #5 — Check podman flags against approval policy | Medium |
| 9 | #7 — Refine hex_secret pattern | Small |
| 10 | #6 — CSRF protection | Medium |
