"""F4: Episodic memory store — PostgreSQL backend with in-memory fallback.

Provides long-term memory for the planner across sessions: what tasks were
completed, which files were affected, what errors occurred, and what facts
were extracted. All data is TRUSTED by construction — orchestrator-generated
metadata from F1 step_outcomes, never raw Qwen output.

PostgreSQL implementation notes:
- tsvector with plainto_tsquery and ts_rank_cd for full-text search
- search_vector is GENERATED ALWAYS AS STORED — no manual sync
- EXTRACT(EPOCH FROM ...) / 86400.0 for age calculation
- INSERT ... ON CONFLICT DO NOTHING for dedup
- JSON fields are JSONB — asyncpg returns native Python types
- FK ON DELETE CASCADE handles file_index + facts cleanup

When pool is None, falls back to in-memory dict (useful for tests).
"""

from __future__ import annotations

import json
import logging
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from sentinel.core.context import current_user_id, get_task_id

logger = logging.getLogger("sentinel.audit")


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


@dataclass
class EpisodicRecord:
    """A structured outcome record for a completed task."""

    record_id: str
    session_id: str
    task_id: str
    user_id: int
    user_request: str
    task_status: str
    plan_summary: str
    step_count: int
    success_count: int
    file_paths: list[str]
    error_patterns: list[str]
    defined_symbols: list[str]
    step_outcomes: list[dict] | None
    linked_records: list[dict]
    relevance_score: float
    access_count: int
    last_accessed: str | None
    task_domain: str | None = None
    memory_chunk_id: str | None = None
    created_at: str = ""


@dataclass
class EpisodicFact:
    """A short, keyword-rich extracted fact linked to an episodic record."""

    fact_id: str
    record_id: str
    fact_type: str
    content: str
    file_path: str | None
    created_at: str
    user_id: int = 1


# Tool name → domain mapping for task classification
TOOL_TO_DOMAIN: dict[str, str] = {
    # Code generation / file creation
    "file_write": "code_generation",
    "file_read": "file_ops",
    "mkdir": "file_ops",
    # Execution
    "shell": "code_generation",
    "shell_exec": "code_generation",
    # Messaging
    "signal_send": "messaging",
    "telegram_send": "messaging",
    "email_send": "messaging",
    "email_draft": "messaging",
    # Search
    "web_search": "search",
    "http_fetch": "search",
    "email_search": "search",
    "email_read": "search",
    "memory_search": "search",
    # Calendar
    "calendar_list_events": "calendar",
    "calendar_create_event": "calendar",
    "calendar_update_event": "calendar",
    "calendar_delete_event": "calendar",
    # System / internal
    "health_check": "system",
    "session_info": "system",
    "memory_store": "system",
    "memory_list": "system",
    "memory_recall_file": "system",
    "memory_recall_session": "system",
    "routine_list": "system",
    "routine_get": "system",
    "routine_history": "system",
    # Website
    "website": "code_generation",
}

# Valid domain values
TASK_DOMAINS = frozenset({
    "code_generation", "code_debugging", "messaging",
    "search", "file_ops", "system", "calendar", "composite",
})


def classify_task_domain(step_outcomes: list[dict]) -> str | None:
    """Classify a task into a domain based on the tools used in step_outcomes.

    Uses dominant-tool heuristic: if one domain accounts for >50% of tool_call
    steps, that's the domain. Otherwise "composite". Returns None if no
    tool_call steps exist (pure llm_task plans).
    """
    if not step_outcomes:
        return None

    domain_counts: dict[str, int] = {}
    tool_steps = 0

    for outcome in step_outcomes:
        if outcome.get("step_type") != "tool_call":
            continue
        tool = outcome.get("tool", "")
        if not tool:
            continue
        tool_steps += 1
        domain = TOOL_TO_DOMAIN.get(tool, "system")
        domain_counts[domain] = domain_counts.get(domain, 0) + 1

    if tool_steps == 0:
        return None

    # Check for debug pattern: file_read + llm_task + file_write sequence
    # indicates debugging even though tools map to code_generation/file_ops
    has_file_read = any(
        o.get("tool") == "file_read" for o in step_outcomes
        if o.get("step_type") == "tool_call"
    )
    has_file_write = any(
        o.get("tool") == "file_write" for o in step_outcomes
        if o.get("step_type") == "tool_call"
    )
    has_llm_task = any(
        o.get("step_type") == "llm_task" for o in step_outcomes
    )
    if has_file_read and has_file_write and has_llm_task:
        return "code_debugging"

    # Dominant domain: >50% of tool steps
    for domain, count in sorted(domain_counts.items(), key=lambda x: x[1], reverse=True):
        if count > tool_steps / 2:
            return domain

    return "composite"


def compute_relevance(age_days: float, access_count: int = 0) -> float:
    """Compute effective relevance score.

    Base: 1.0 / (1 + age_days * 0.1) — decays with time.
    Boost: 0.1 * access_count — active records stay alive.
    """
    base = 1.0 / (1.0 + age_days * 0.1)
    boost = 0.1 * access_count
    return round(base + boost, 4)


def _format_bytes(size: int) -> str:
    """Format byte count as human-readable string."""
    if size < 1024:
        return f"{size}B"
    return f"{size / 1024:.1f}K"


def _categorise_strategy(step_outcomes: list[dict]) -> str:
    """Categorise step sequence into a strategy pattern."""
    if not step_outcomes:
        return "empty"

    steps = []
    for o in step_outcomes:
        st = o.get("step_type", "")
        tool = o.get("tool", "")
        if st == "tool_call" and tool:
            steps.append(tool)
        elif st == "llm_task":
            steps.append("llm")

    if not steps:
        return "unknown"
    if len(steps) == 1:
        return "single-shot"

    # Simplify repeated tools into readable labels
    simplified = []
    for s in steps:
        label = s
        if s in ("file_read",):
            label = "read"
        elif s in ("file_write",):
            label = "write"
        elif s in ("shell", "shell_exec"):
            label = "exec"
        elif s == "llm":
            label = "generate"
        elif s in ("web_search", "email_search", "memory_search"):
            label = "search"
        elif s in ("signal_send", "telegram_send", "email_send"):
            label = "send"
        if not simplified or simplified[-1] != label:
            simplified.append(label)

    return " → ".join(simplified)


def render_episodic_text(
    user_request: str,
    task_status: str,
    step_count: int = 0,
    success_count: int = 0,
    file_paths: list[str] | None = None,
    plan_summary: str = "",
    error_patterns: list[str] | None = None,
    step_outcomes: list[dict] | None = None,
    task_domain: str | None = None,
    original_request: str | None = None,
    prior_error_summary: str | None = None,
) -> str:
    """Render outcome-aware text for embedding + planner context.

    Includes diagnostic detail so the planner can learn from past
    successes and failures: stderr output, exit codes, file sizes,
    diff stats, step-by-step outcomes. All data is F1 metadata
    (trusted by construction) — no raw Qwen output.

    For fix-cycle turns (retry after failure), ``original_request``
    carries the initial scenario prompt so the record is searchable
    by scenario content rather than the generic retry text.

    Scanner blocks are reported as "blocked" with no scanner names
    or internal details — the planner should not know which specific
    scanners exist.

    Budget: ~800 chars. nomic-embed-text handles up to 8192 tokens;
    the real constraint is the planner's token budget for episodic
    context (~2K tokens shared across multiple records).
    """
    _MAX_CHARS = 800

    # Line 1: [domain] request — use original scenario for fix-cycles
    # so the embedding/search key reflects the actual task, not the
    # generic "previous task failed" retry prompt.
    display_request = user_request
    is_fix_cycle = original_request is not None and original_request != user_request
    if is_fix_cycle:
        display_request = original_request

    if task_domain:
        header = f"[{task_domain}] {display_request[:140]}"
    else:
        header = display_request[:150]
    if is_fix_cycle:
        header += " (fix-cycle)"
    lines = [header]

    # Line 2: Result with duration
    total_duration = 0.0
    if step_outcomes:
        for o in step_outcomes:
            d = o.get("duration_s")
            if d is not None:
                total_duration += d
    duration_part = f", {total_duration:.0f}s" if total_duration > 0 else ""
    lines.append(
        f"Result: {task_status.upper()} ({success_count}/{step_count} steps{duration_part})"
    )

    # Line 3: Strategy pattern
    strategy = _categorise_strategy(step_outcomes or [])
    lines.append(f"Strategy: {strategy}")

    # Line 4: Files involved — basenames with size/diff when available
    if file_paths:
        import os
        basenames: list[str] = []
        seen_bases: set[str] = set()
        # Build a lookup for file metadata from step_outcomes
        file_meta: dict[str, dict] = {}
        if step_outcomes:
            for o in step_outcomes:
                fp = o.get("file_path")
                if fp:
                    bn = os.path.basename(fp)
                    # Keep the most informative (last) outcome per file
                    meta: dict[str, Any] = {}
                    if o.get("file_size_after") is not None:
                        meta["size"] = o["file_size_after"]
                    elif o.get("file_size_before") is not None:
                        meta["size"] = o["file_size_before"]
                    if o.get("diff_stats"):
                        meta["diff"] = o["diff_stats"]
                    if meta:
                        file_meta[bn] = meta
        for fp in file_paths:
            bn = os.path.basename(fp)
            if bn not in seen_bases:
                seen_bases.add(bn)
                meta = file_meta.get(bn)
                if meta:
                    parts = [bn]
                    if "size" in meta:
                        parts.append(f"{meta['size']}B")
                    if "diff" in meta:
                        parts.append(meta["diff"])
                    basenames.append(f"{parts[0]} ({', '.join(parts[1:])})" if len(parts) > 1 else bn)
                else:
                    basenames.append(bn)
            if len(basenames) >= 4:
                break
        if basenames:
            lines.append(f"Files: {', '.join(basenames)}")

    # Lines 5+: Per-step outcomes — show ALL steps so the planner
    # can learn the full execution trajectory, not just failures.
    # Scanner blocks say "blocked" only — no scanner names or details.
    if step_outcomes:
        for i, o in enumerate(step_outcomes, 1):
            step_status = o.get("status", "unknown")
            tool = o.get("tool") or o.get("step_type", "?")
            desc = o.get("description", "")[:50]
            exit_code = o.get("exit_code")

            # Build compact step summary
            status_label = step_status.upper()
            step_parts = [f"S{i}({tool}): {status_label}"]
            if desc:
                step_parts.append(desc)
            if exit_code is not None and exit_code != 0:
                step_parts.append(f"exit={exit_code}")

            # For failures: stderr is the most valuable diagnostic
            if step_status in ("failed", "error", "soft_failed"):
                stderr = o.get("stderr_preview", "")
                if stderr:
                    stderr_line = _extract_key_stderr_line(stderr)
                    if stderr_line:
                        step_parts.append(f"stderr: {stderr_line}")
                elif o.get("error_detail"):
                    step_parts.append(o["error_detail"][:60])
                if o.get("sandbox_timed_out"):
                    step_parts.append("sandbox_timeout")
                if o.get("sandbox_oom_killed"):
                    step_parts.append("sandbox_oom")

            # For blocks: say "blocked" only — no scanner internals
            elif step_status == "blocked":
                step_parts.append("blocked by security policy")

            # For success with exit code 0: note verification passed
            elif step_status == "success" and exit_code == 0 and tool in ("shell", "shell_exec"):
                step_parts.append("verified")

            line = "; ".join(step_parts)
            # Stop adding steps if we'd bust the budget
            current_len = sum(len(l) + 1 for l in lines) + len(line)
            if current_len > _MAX_CHARS - 100:  # reserve 100 chars for remaining fields
                lines.append(f"... +{len(step_outcomes) - i} more steps")
                break
            lines.append(line)

    # Prior error context — what failed in the previous turn that
    # prompted this fix-cycle. Gives the planner the error to learn from.
    if prior_error_summary:
        lines.append(f"Prior error: {prior_error_summary[:120]}")

    # Plan summary
    if plan_summary:
        lines.append(f"Plan: {plan_summary[:100]}")

    result = "\n".join(lines)
    if len(result) > _MAX_CHARS:
        result = result[:_MAX_CHARS - 3] + "..."
    return result


def _extract_key_stderr_line(stderr: str) -> str:
    """Extract the most informative line from stderr output.

    Looks for error class names (ImportError, SyntaxError, etc.),
    assertion failures, or the last non-empty line as fallback.
    Returns a single line, max 120 chars.
    """
    if not stderr:
        return ""
    lines = stderr.strip().splitlines()
    # Priority 1: lines starting with a Python error class
    for line in reversed(lines):
        stripped = line.strip()
        if any(stripped.startswith(e) for e in (
            "ImportError", "SyntaxError", "IndentationError", "TypeError",
            "NameError", "AttributeError", "ValueError", "KeyError",
            "ModuleNotFoundError", "FileNotFoundError", "OSError",
            "RuntimeError", "AssertionError", "ZeroDivisionError",
            "IndexError", "StopIteration", "RecursionError",
            "PermissionError", "ConnectionError", "TimeoutError",
        )):
            return stripped[:120]
    # Priority 2: lines containing 'Error:' or 'FAILED' or 'assert'
    for line in reversed(lines):
        stripped = line.strip()
        low = stripped.lower()
        if "error:" in low or "failed" in low or "assert" in low:
            return stripped[:120]
    # Fallback: last non-empty line
    for line in reversed(lines):
        stripped = line.strip()
        if stripped:
            return stripped[:120]
    return ""


def extract_episodic_facts(
    step_outcomes: list[dict],
    user_request: str,
    task_status: str,
) -> list[EpisodicFact]:
    """Extract notable facts from F1 step_outcomes — deterministic, no LLM.

    Examines each step outcome for notable patterns:
    - File creation (file_write where file_size_before is None)
    - File modification (file_write where file_size_before is not None)
    - Scanner blocks (scanner_result == "blocked")
    - Execution errors (non-zero exit_code)
    - Symbol definitions (non-empty defined_symbols)
    - Truncation warnings (token_usage_ratio >= 0.95)

    All extracted data comes from F1 metadata (TRUSTED, orchestrator-generated).
    No raw Qwen output crosses into facts.
    """
    facts: list[EpisodicFact] = []
    now = ""  # DB default handles timestamp

    for outcome in step_outcomes:
        file_path = outcome.get("file_path")

        # File creation: file_write with no prior file
        if (
            outcome.get("step_type") == "tool_call"
            and file_path
            and outcome.get("file_size_before") is None
            and outcome.get("file_size_after") is not None
        ):
            size = outcome["file_size_after"]
            lang = outcome.get("output_language", "")
            lang_part = f", {lang}" if lang else ""
            facts.append(EpisodicFact(
                fact_id=str(uuid.uuid4()),
                record_id="",  # linked at store time
                fact_type="file_create",
                content=f"{file_path} created ({size} bytes{lang_part})",
                file_path=file_path,
                created_at=now,
            ))
            continue  # don't also match as modification

        # File modification: file_write with prior file
        if (
            outcome.get("step_type") == "tool_call"
            and file_path
            and outcome.get("file_size_before") is not None
            and outcome.get("file_size_after") is not None
        ):
            before = outcome["file_size_before"]
            after = outcome["file_size_after"]
            diff = outcome.get("diff_stats", "")
            diff_part = f", {diff}" if diff else ""
            facts.append(EpisodicFact(
                fact_id=str(uuid.uuid4()),
                record_id="",
                fact_type="file_modify",
                content=f"{file_path} modified ({before}\u2192{after} bytes{diff_part})",
                file_path=file_path,
                created_at=now,
            ))

        # Scanner block — uses genericised error_detail (scanner_details redacted)
        if outcome.get("scanner_result") == "blocked":
            generic_err = outcome.get("error_detail", "blocked")
            facts.append(EpisodicFact(
                fact_id=str(uuid.uuid4()),
                record_id="",
                fact_type="scanner_block",
                content=f"Scanner block: {generic_err}",
                file_path=file_path,
                created_at=now,
            ))

        # Execution error
        exit_code = outcome.get("exit_code")
        if exit_code is not None and exit_code != 0:
            stderr = outcome.get("stderr_preview", "")
            stderr_part = f", {stderr[:100]}" if stderr else ""
            path_part = file_path or "shell"
            facts.append(EpisodicFact(
                fact_id=str(uuid.uuid4()),
                record_id="",
                fact_type="exec_error",
                content=f"{path_part}: exit {exit_code}{stderr_part}",
                file_path=file_path,
                created_at=now,
            ))

        # Symbol definitions
        symbols = outcome.get("defined_symbols")
        if symbols and isinstance(symbols, list) and len(symbols) > 0:
            symbol_list = ", ".join(symbols[:10])
            path_part = file_path or "code"
            facts.append(EpisodicFact(
                fact_id=str(uuid.uuid4()),
                record_id="",
                fact_type="symbol_def",
                content=f"{path_part} defines: [{symbol_list}]",
                file_path=file_path,
                created_at=now,
            ))

        # Truncation warning
        ratio = outcome.get("token_usage_ratio")
        if ratio is not None and ratio >= 0.95:
            size = outcome.get("output_size", "unknown")
            facts.append(EpisodicFact(
                fact_id=str(uuid.uuid4()),
                record_id="",
                fact_type="truncation",
                content=f"Truncation: output at {ratio * 100:.0f}% token cap ({size} chars, likely incomplete)",
                file_path=file_path,
                created_at=now,
            ))

    return facts


def _dt_to_iso(dt: datetime | None) -> str | None:
    if dt is None:
        return None
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _row_to_record(row: Any) -> EpisodicRecord:
    """Convert an asyncpg Record to an EpisodicRecord dataclass."""
    # JSONB fields come back as native Python types from asyncpg
    file_paths = row["file_paths"]
    if isinstance(file_paths, str):
        file_paths = json.loads(file_paths)

    error_patterns = row["error_patterns"]
    if isinstance(error_patterns, str):
        error_patterns = json.loads(error_patterns)

    defined_symbols = row["defined_symbols"]
    if isinstance(defined_symbols, str):
        defined_symbols = json.loads(defined_symbols)

    step_outcomes = row["step_outcomes"]
    if isinstance(step_outcomes, str):
        step_outcomes = json.loads(step_outcomes)

    linked_records = row["linked_records"]
    if isinstance(linked_records, str):
        linked_records = json.loads(linked_records)

    return EpisodicRecord(
        record_id=row["record_id"],
        session_id=row["session_id"],
        task_id=row["task_id"],
        user_id=row["user_id"],
        user_request=row["user_request"],
        task_status=row["task_status"],
        plan_summary=row["plan_summary"],
        step_count=row["step_count"],
        success_count=row["success_count"],
        file_paths=file_paths,
        error_patterns=error_patterns,
        defined_symbols=defined_symbols,
        step_outcomes=step_outcomes,
        linked_records=linked_records,
        relevance_score=row["relevance_score"],
        access_count=row["access_count"],
        last_accessed=_dt_to_iso(row["last_accessed"]),
        task_domain=row.get("task_domain") if hasattr(row, "get") else row["task_domain"],
        memory_chunk_id=row["memory_chunk_id"],
        created_at=_dt_to_iso(row["created_at"]) or "",
    )


def _row_to_fact(row: Any) -> EpisodicFact:
    """Convert an asyncpg Record to an EpisodicFact dataclass."""
    return EpisodicFact(
        fact_id=row["fact_id"],
        record_id=row["record_id"],
        fact_type=row["fact_type"],
        content=row["content"],
        file_path=row["file_path"],
        created_at=_dt_to_iso(row["created_at"]) or "",
        user_id=row.get("user_id", 1) if hasattr(row, "get") else 1,
    )


_RECORD_COLUMNS = (
    "record_id, session_id, task_id, user_id, user_request, "
    "task_status, plan_summary, step_count, success_count, "
    "file_paths, error_patterns, defined_symbols, step_outcomes, "
    "linked_records, relevance_score, access_count, last_accessed, "
    "task_domain, memory_chunk_id, created_at"
)


class EpisodicStore:
    """PostgreSQL episodic memory store with in-memory fallback for tests."""

    def __init__(self, pool: Any = None):
        self._pool = pool
        # In-memory fallback state
        self._mem: dict[str, EpisodicRecord] = {}
        self._file_index: dict[str, set[str]] = {}  # file_path → set of record_ids
        self._facts: dict[str, list[EpisodicFact]] = {}  # record_id → facts

    async def create(
        self,
        session_id: str,
        task_id: str = "",
        user_request: str = "",
        task_status: str = "",
        plan_summary: str = "",
        step_count: int = 0,
        success_count: int = 0,
        file_paths: list[str] | None = None,
        error_patterns: list[str] | None = None,
        defined_symbols: list[str] | None = None,
        step_outcomes: list[dict] | None = None,
        user_id: int = 1,
        task_domain: str | None = None,
    ) -> str:
        """Create an episodic record + file index entries. Returns record_id."""
        record_id = str(uuid.uuid4())
        file_paths = file_paths or []
        error_patterns = error_patterns or []
        defined_symbols = defined_symbols or []

        if self._pool is not None:
            async with self._pool.acquire() as conn:
                async with conn.transaction():
                    await conn.execute(
                        "INSERT INTO episodic_records "
                        "(record_id, session_id, task_id, user_id, user_request, "
                        "task_status, plan_summary, step_count, success_count, "
                        "file_paths, error_patterns, defined_symbols, step_outcomes, task_domain) "
                        "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, "
                        "$10::jsonb, $11::jsonb, $12::jsonb, $13::jsonb, $14)",
                        record_id, session_id, task_id, user_id, user_request,
                        task_status, plan_summary, step_count, success_count,
                        json.dumps(file_paths), json.dumps(error_patterns),
                        json.dumps(defined_symbols),
                        json.dumps(step_outcomes) if step_outcomes else None,
                        task_domain,
                    )

                    # Populate file index
                    for path in file_paths:
                        await conn.execute(
                            "INSERT INTO episodic_file_index (file_path, record_id, action, user_id) "
                            "VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING",
                            path, record_id, "modified", user_id,
                        )
        else:
            now = _now_iso()
            self._mem[record_id] = EpisodicRecord(
                record_id=record_id,
                session_id=session_id,
                task_id=task_id,
                user_id=user_id,
                user_request=user_request,
                task_status=task_status,
                plan_summary=plan_summary,
                step_count=step_count,
                success_count=success_count,
                file_paths=file_paths,
                error_patterns=error_patterns,
                defined_symbols=defined_symbols,
                step_outcomes=step_outcomes,
                linked_records=[],
                relevance_score=1.0,
                access_count=0,
                last_accessed=None,
                task_domain=task_domain,
                memory_chunk_id=None,
                created_at=now,
            )
            # Populate file index
            for path in file_paths:
                if path not in self._file_index:
                    self._file_index[path] = set()
                self._file_index[path].add(record_id)

        logger.info(
            "Episodic record created",
            extra={
                "event": "episodic_record_created",
                "record_id": record_id,
                "session_id": session_id,
                "task_status": task_status,
                "file_count": len(file_paths),
                "task_id": get_task_id(),
            },
        )
        return record_id

    async def get(self, record_id: str, user_id: int | None = None) -> EpisodicRecord | None:
        """Fetch a single episodic record by ID."""
        resolved_user_id = user_id if user_id is not None else current_user_id.get()
        if self._pool is not None:
            async with self._pool.acquire() as conn:
                row = await conn.fetchrow(
                    f"SELECT {_RECORD_COLUMNS} "
                    "FROM episodic_records WHERE record_id = $1 AND user_id = $2",
                    record_id, resolved_user_id,
                )
                if row is None:
                    return None
                return _row_to_record(row)

        record = self._mem.get(record_id)
        if record is not None and record.user_id != resolved_user_id:
            return None
        return record

    async def list_by_session(
        self, session_id: str, user_id: int | None = None, limit: int = 50,
    ) -> list[EpisodicRecord]:
        """List records for a session, newest first."""
        resolved_user_id = user_id if user_id is not None else current_user_id.get()
        if self._pool is not None:
            async with self._pool.acquire() as conn:
                rows = await conn.fetch(
                    f"SELECT {_RECORD_COLUMNS} "
                    "FROM episodic_records WHERE session_id = $1 "
                    "AND user_id = $2 "
                    "ORDER BY created_at DESC LIMIT $3",
                    session_id, resolved_user_id, limit,
                )
                return [_row_to_record(r) for r in rows]

        records = [
            r for r in self._mem.values()
            if r.session_id == session_id and r.user_id == resolved_user_id
        ]
        records.sort(key=lambda r: r.created_at, reverse=True)
        return records[:limit]

    async def list_by_file(
        self, file_path: str, user_id: int = 1, limit: int = 50,
    ) -> list[EpisodicRecord]:
        """List records that affected a given file path, newest first."""
        if self._pool is not None:
            async with self._pool.acquire() as conn:
                rows = await conn.fetch(
                    f"SELECT er.{', er.'.join(_RECORD_COLUMNS.split(', '))} "
                    "FROM episodic_records er "
                    "JOIN episodic_file_index efi ON er.record_id = efi.record_id "
                    "WHERE efi.file_path = $1 AND er.user_id = $2 "
                    "ORDER BY er.created_at DESC LIMIT $3",
                    file_path, user_id, limit,
                )
                return [_row_to_record(r) for r in rows]

        record_ids = self._file_index.get(file_path, set())
        records = [
            self._mem[rid] for rid in record_ids
            if rid in self._mem and self._mem[rid].user_id == user_id
        ]
        records.sort(key=lambda r: r.created_at, reverse=True)
        return records[:limit]

    async def list_by_domain(
        self, domain: str, user_id: int | None = None, limit: int = 100,
    ) -> list[EpisodicRecord]:
        """List episodic records for a specific task domain, newest first."""
        resolved_uid = user_id if user_id is not None else current_user_id.get()

        if self._pool is not None:
            async with self._pool.acquire() as conn:
                rows = await conn.fetch(
                    f"SELECT {_RECORD_COLUMNS} "
                    "FROM episodic_records "
                    "WHERE task_domain = $1 AND user_id = $2 "
                    "ORDER BY created_at DESC LIMIT $3",
                    domain, resolved_uid, limit,
                )
                return [_row_to_record(row) for row in rows]

        # In-memory fallback
        records = [
            r for r in self._mem.values()
            if r.user_id == resolved_uid and r.task_domain == domain
        ]
        records.sort(key=lambda r: r.created_at, reverse=True)
        return records[:limit]

    async def delete(self, record_id: str, user_id: int | None = None) -> bool:
        """Delete an episodic record. FK CASCADE handles file_index + facts."""
        resolved_user_id = user_id if user_id is not None else current_user_id.get()
        if self._pool is not None:
            async with self._pool.acquire() as conn:
                result = await conn.execute(
                    "DELETE FROM episodic_records WHERE record_id = $1 AND user_id = $2",
                    record_id, resolved_user_id,
                )
                return result == "DELETE 1"

        record = self._mem.get(record_id)
        if record is None or record.user_id != resolved_user_id:
            return False
        # Clean up file index
        for path in record.file_paths:
            ids = self._file_index.get(path)
            if ids:
                ids.discard(record_id)
                if not ids:
                    del self._file_index[path]
        # Clean up facts
        self._facts.pop(record_id, None)
        del self._mem[record_id]
        return True

    async def find_linked_records(
        self, file_paths: list[str], user_id: int = 1, exclude_record_id: str = "",
    ) -> list[str]:
        """Find existing record IDs that share any file paths."""
        if not file_paths:
            return []

        if self._pool is not None:
            async with self._pool.acquire() as conn:
                rows = await conn.fetch(
                    "SELECT DISTINCT record_id FROM episodic_file_index "
                    "WHERE file_path = ANY($1) AND record_id != $2 "
                    "AND user_id = $3",
                    file_paths, exclude_record_id, user_id,
                )
                return [r["record_id"] for r in rows]

        # In-memory path: filter by user_id via the parent record
        result_ids: set[str] = set()
        for path in file_paths:
            for rid in self._file_index.get(path, set()):
                if rid != exclude_record_id:
                    rec = self._mem.get(rid)
                    if rec is not None and rec.user_id == user_id:
                        result_ids.add(rid)
        return list(result_ids)

    async def _add_link(
        self, conn: Any, record_id: str, linked_id: str,
        link_type: str = "file", user_id: int | None = None,
    ) -> None:
        """Add a link entry to a record's linked_records JSONB array."""
        resolved_user_id = user_id if user_id is not None else current_user_id.get()
        if self._pool is not None:
            row = await conn.fetchrow(
                "SELECT linked_records FROM episodic_records "
                "WHERE record_id = $1 AND user_id = $2",
                record_id, resolved_user_id,
            )
            if row is None:
                return

            links = row["linked_records"]
            if isinstance(links, str):
                links = json.loads(links)

            # Avoid duplicates
            if not any(l["record_id"] == linked_id for l in links):
                links.append({"record_id": linked_id, "link_type": link_type})
                await conn.execute(
                    "UPDATE episodic_records SET linked_records = $1::jsonb "
                    "WHERE record_id = $2 AND user_id = $3",
                    json.dumps(links), record_id, resolved_user_id,
                )
        else:
            record = self._mem.get(record_id)
            if record is None or record.user_id != resolved_user_id:
                return
            if not any(l["record_id"] == linked_id for l in record.linked_records):
                record.linked_records.append({"record_id": linked_id, "link_type": link_type})

    async def prune_stale(
        self, threshold: float = 0.05, min_age_days: int = 30,
        user_id: int | None = None,
    ) -> int:
        """Remove old, unaccessed episodic records below relevance threshold.

        When user_id is None, prunes across all users (admin mode).
        When user_id is an int, only that user's records are considered.
        """
        if self._pool is not None:
            async with self._pool.acquire() as conn:
                if user_id is not None:
                    rows = await conn.fetch(
                        "SELECT record_id, "
                        "EXTRACT(EPOCH FROM NOW() - created_at) / 86400.0 AS age_days, "
                        "access_count, memory_chunk_id "
                        "FROM episodic_records "
                        "WHERE EXTRACT(EPOCH FROM NOW() - created_at) / 86400.0 > $1 "
                        "AND user_id = $2",
                        float(min_age_days), user_id,
                    )
                else:
                    rows = await conn.fetch(
                        "SELECT record_id, "
                        "EXTRACT(EPOCH FROM NOW() - created_at) / 86400.0 AS age_days, "
                        "access_count, memory_chunk_id "
                        "FROM episodic_records "
                        "WHERE EXTRACT(EPOCH FROM NOW() - created_at) / 86400.0 > $1",
                        float(min_age_days),
                    )

                # Collect IDs of records and shadow chunks to prune
                record_ids_to_prune: list[str] = []
                chunk_ids_to_prune: list[str] = []
                for row in rows:
                    effective = compute_relevance(row["age_days"], row["access_count"])
                    if effective < threshold:
                        record_ids_to_prune.append(row["record_id"])
                        chunk_id = row["memory_chunk_id"]
                        if chunk_id:
                            chunk_ids_to_prune.append(chunk_id)

                if not record_ids_to_prune:
                    return 0

                # Batch delete shadow chunks (best-effort — don't fail the prune)
                if chunk_ids_to_prune:
                    try:
                        await conn.execute(
                            "DELETE FROM memory_chunks WHERE chunk_id = ANY($1)",
                            chunk_ids_to_prune,
                        )
                    except Exception as exc:
                        logger.warning(
                            "Shadow chunk batch deletion failed",
                            extra={
                                "event": "prune_shadow_failed",
                                "chunk_count": len(chunk_ids_to_prune),
                                "error": str(exc),
                            },
                        )

                # Batch delete episodic records — FK CASCADE handles file_index + facts
                await conn.execute(
                    "DELETE FROM episodic_records WHERE record_id = ANY($1)",
                    record_ids_to_prune,
                )

                pruned = len(record_ids_to_prune)
                if pruned > 0:
                    logger.info(
                        "Episodic memory pruned",
                        extra={"event": "episodic_pruned", "count": pruned},
                    )

                return pruned

        # In-memory path
        now = datetime.now(timezone.utc)
        to_prune = []
        for record in self._mem.values():
            if user_id is not None and record.user_id != user_id:
                continue
            try:
                created = datetime.fromisoformat(record.created_at.replace("Z", "+00:00"))
                age_days = (now - created).total_seconds() / 86400.0
            except (ValueError, AttributeError):
                continue
            if age_days <= min_age_days:
                continue
            effective = compute_relevance(age_days, record.access_count)
            if effective < threshold:
                to_prune.append(record.record_id)

        for rid in to_prune:
            # Pass user_id through so the delete's user_id filter matches.
            # When user_id is None (admin/cross-user prune), use the record's
            # own user_id so the filter doesn't reject it.
            record = self._mem.get(rid)
            delete_uid = user_id if user_id is not None else (record.user_id if record else 0)
            await self.delete(rid, user_id=delete_uid)

        if to_prune:
            logger.info(
                "Episodic memory pruned",
                extra={"event": "episodic_pruned", "count": len(to_prune)},
            )
        return len(to_prune)

    async def update_access(self, record_id: str, user_id: int | None = None) -> None:
        """Bump access_count and last_accessed timestamp."""
        resolved_user_id = user_id if user_id is not None else current_user_id.get()
        if self._pool is not None:
            async with self._pool.acquire() as conn:
                await conn.execute(
                    "UPDATE episodic_records SET "
                    "access_count = access_count + 1, last_accessed = NOW() "
                    "WHERE record_id = $1 AND user_id = $2",
                    record_id, resolved_user_id,
                )
        else:
            record = self._mem.get(record_id)
            if record is not None and record.user_id == resolved_user_id:
                record.access_count += 1
                record.last_accessed = _now_iso()

    async def batch_update_access(self, record_ids: list[str], user_id: int | None = None) -> None:
        """Bump access_count for multiple records in a single query."""
        if not record_ids:
            return

        resolved_user_id = user_id if user_id is not None else current_user_id.get()
        if self._pool is not None:
            async with self._pool.acquire() as conn:
                await conn.execute(
                    "UPDATE episodic_records SET "
                    "access_count = access_count + 1, last_accessed = NOW() "
                    "WHERE record_id = ANY($1) AND user_id = $2",
                    record_ids, resolved_user_id,
                )
        else:
            now = _now_iso()
            for rid in record_ids:
                record = self._mem.get(rid)
                if record is not None and record.user_id == resolved_user_id:
                    record.access_count += 1
                    record.last_accessed = now

    async def set_memory_chunk_id(self, record_id: str, chunk_id: str, user_id: int | None = None) -> None:
        """Set the memory_chunks shadow entry ID for search integration."""
        resolved_user_id = user_id if user_id is not None else current_user_id.get()
        if self._pool is not None:
            async with self._pool.acquire() as conn:
                await conn.execute(
                    "UPDATE episodic_records SET memory_chunk_id = $1 "
                    "WHERE record_id = $2 AND user_id = $3",
                    chunk_id, record_id, resolved_user_id,
                )
        else:
            record = self._mem.get(record_id)
            if record is not None and record.user_id == resolved_user_id:
                record.memory_chunk_id = chunk_id

    async def create_with_shadow(
        self,
        memory_store,
        session_id: str,
        task_id: str = "",
        user_request: str = "",
        task_status: str = "",
        plan_summary: str = "",
        step_count: int = 0,
        success_count: int = 0,
        file_paths: list[str] | None = None,
        error_patterns: list[str] | None = None,
        defined_symbols: list[str] | None = None,
        step_outcomes: list[dict] | None = None,
        user_id: int = 1,
        embedding: list[float] | None = None,
        task_domain: str | None = None,
        original_request: str | None = None,
        prior_error_summary: str | None = None,
    ) -> str:
        """Create episodic record + memory_chunks shadow entry."""
        record_id = await self.create(
            session_id=session_id,
            task_id=task_id,
            user_request=user_request,
            task_status=task_status,
            plan_summary=plan_summary,
            step_count=step_count,
            success_count=success_count,
            file_paths=file_paths,
            error_patterns=error_patterns,
            defined_symbols=defined_symbols,
            step_outcomes=step_outcomes,
            user_id=user_id,
            task_domain=task_domain,
        )

        # Render text for shadow entry (include step_outcomes for enriched FTS/vector search)
        text = render_episodic_text(
            user_request=user_request,
            task_status=task_status,
            step_count=step_count,
            success_count=success_count,
            file_paths=file_paths,
            plan_summary=plan_summary,
            error_patterns=error_patterns,
            step_outcomes=step_outcomes,
            task_domain=task_domain,
            original_request=original_request,
            prior_error_summary=prior_error_summary,
        )

        metadata = {
            "record_id": record_id,
            "session_id": session_id,
            "task_status": task_status,
        }
        if task_domain:
            metadata["task_domain"] = task_domain

        # Store shadow with or without embedding
        if embedding is not None:
            chunk_id = await memory_store.store_with_embedding(
                content=text,
                embedding=embedding,
                source="system:episodic",
                metadata=metadata,
                user_id=user_id,
                task_domain=task_domain,
            )
        else:
            chunk_id = await memory_store.store(
                content=text,
                source="system:episodic",
                metadata=metadata,
                user_id=user_id,
                task_domain=task_domain,
            )

        await self.set_memory_chunk_id(record_id, chunk_id)

        # Cross-task file-path linking — bidirectional
        file_paths = file_paths or []
        linked_ids = await self.find_linked_records(
            file_paths, user_id=user_id, exclude_record_id=record_id,
        )
        if linked_ids:
            if self._pool is not None:
                async with self._pool.acquire() as conn:
                    for linked_id in linked_ids:
                        await self._add_link(conn, record_id, linked_id, "file", user_id=user_id)
                        await self._add_link(conn, linked_id, record_id, "file", user_id=user_id)
            else:
                for linked_id in linked_ids:
                    await self._add_link(None, record_id, linked_id, "file", user_id=user_id)
                    await self._add_link(None, linked_id, record_id, "file", user_id=user_id)

        return record_id

    async def store_facts(
        self, record_id: str, facts: list[EpisodicFact], user_id: int = 1,
    ) -> None:
        """Store extracted facts for a record.

        tsvector search_vector is GENERATED ALWAYS AS STORED — no manual sync.
        """
        if self._pool is not None:
            async with self._pool.acquire() as conn:
                async with conn.transaction():
                    for fact in facts:
                        fact_id = fact.fact_id or str(uuid.uuid4())
                        await conn.execute(
                            "INSERT INTO episodic_facts "
                            "(fact_id, record_id, fact_type, content, file_path, user_id) "
                            "VALUES ($1, $2, $3, $4, $5, $6)",
                            fact_id, record_id, fact.fact_type, fact.content, fact.file_path,
                            user_id,
                        )
        else:
            if record_id not in self._facts:
                self._facts[record_id] = []
            now = _now_iso()
            for fact in facts:
                stored = EpisodicFact(
                    fact_id=fact.fact_id or str(uuid.uuid4()),
                    record_id=record_id,
                    fact_type=fact.fact_type,
                    content=fact.content,
                    file_path=fact.file_path,
                    created_at=fact.created_at or now,
                    user_id=user_id,
                )
                self._facts[record_id].append(stored)

    async def search_facts(
        self, query: str, fact_type: str | None = None,
        user_id: int = 1, limit: int = 20,
    ) -> list[EpisodicFact]:
        """Search facts via tsvector full-text search."""
        if not query or not query.strip():
            return []

        if self._pool is not None:
            async with self._pool.acquire() as conn:
                if fact_type:
                    rows = await conn.fetch(
                        "SELECT fact_id, record_id, fact_type, content, file_path, "
                        "created_at, user_id "
                        "FROM episodic_facts "
                        "WHERE search_vector @@ plainto_tsquery('english', $1) "
                        "AND fact_type = $2 AND user_id = $3 "
                        "ORDER BY ts_rank_cd(search_vector, plainto_tsquery('english', $1)) DESC "
                        "LIMIT $4",
                        query, fact_type, user_id, limit,
                    )
                else:
                    rows = await conn.fetch(
                        "SELECT fact_id, record_id, fact_type, content, file_path, "
                        "created_at, user_id "
                        "FROM episodic_facts "
                        "WHERE search_vector @@ plainto_tsquery('english', $1) "
                        "AND user_id = $2 "
                        "ORDER BY ts_rank_cd(search_vector, plainto_tsquery('english', $1)) DESC "
                        "LIMIT $3",
                        query, user_id, limit,
                    )

                return [_row_to_fact(r) for r in rows]

        # In-memory fallback: simple case-insensitive substring match
        query_lower = query.lower()
        results: list[EpisodicFact] = []
        for fact_list in self._facts.values():
            for fact in fact_list:
                if fact.user_id != user_id:
                    continue
                if fact_type and fact.fact_type != fact_type:
                    continue
                if query_lower in fact.content.lower():
                    results.append(fact)
                    if len(results) >= limit:
                        return results
        return results
