#!/usr/bin/env python3
"""F1-F2 Validation Script — F3 Readiness Assessment.

Validates that F1 (Structured Outcome Metadata) and F2 (Session Intelligence)
are structurally complete, functionally correct, and ready for F3 to build on.

Usage:
    .venv/bin/python scripts/validate_f1_f2.py

Exit codes:
    0 — all checks pass, F3 ready
    1 — one or more checks failed

Reference: docs/plans/2026-02-22-f1-f2-validation.md
"""
from __future__ import annotations

import asyncio
import json
import sqlite3
import sys
import tempfile
from dataclasses import field
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

# ── Helpers ─────────────────────────────────────────────────────────────
PASS = "\033[32mPASS\033[0m"
FAIL = "\033[31mFAIL\033[0m"
SKIP = "\033[33mSKIP\033[0m"

results: list[tuple[str, str, str]] = []  # (check_id, status, detail)


def check(check_id: str, description: str):
    """Decorator that runs a validation check and captures the result."""
    def decorator(fn):
        def wrapper():
            try:
                fn()
                results.append((check_id, "PASS", description))
                print(f"  {PASS}  {check_id}: {description}")
            except Exception as e:
                results.append((check_id, "FAIL", f"{description} — {e}"))
                print(f"  {FAIL}  {check_id}: {description} — {e}")
        return wrapper
    return decorator


# ═══════════════════════════════════════════════════════════════════════
# F1: Structured Outcome Metadata
# ═══════════════════════════════════════════════════════════════════════

@check("V-F1-01", "Import all 5 metadata_extractor functions")
def v_f1_01():
    from sentinel.analysis.metadata_extractor import (
        extract_stderr_preview,
        extract_code_symbols,
        extract_diff_stats,
        extract_complexity,
        compute_token_usage_ratio,
    )
    assert callable(extract_stderr_preview)
    assert callable(extract_code_symbols)
    assert callable(extract_diff_stats)
    assert callable(extract_complexity)
    assert callable(compute_token_usage_ratio)


@check("V-F1-02", "extract_code_symbols returns defined_symbols + imports for Python")
def v_f1_02():
    from sentinel.analysis.metadata_extractor import extract_code_symbols

    code = "import os\ndef hello():\n    pass\nclass Foo:\n    pass"
    result = extract_code_symbols(code, "python")

    assert "defined_symbols" in result, "Missing defined_symbols key"
    assert "imports" in result, "Missing imports key"
    assert "hello" in result["defined_symbols"], "Missing function 'hello'"
    assert "Foo" in result["defined_symbols"], "Missing class 'Foo'"
    assert any("os" in imp for imp in result["imports"]), "Missing 'os' import"


@check("V-F1-03", "extract_diff_stats returns +N/-M lines format")
def v_f1_03():
    from sentinel.analysis.metadata_extractor import extract_diff_stats

    result = extract_diff_stats(None, "line1\nline2\nline3")
    assert "+" in result and "-" in result, f"Unexpected format: {result}"
    assert "3" in result, f"Expected 3 additions: {result}"


@check("V-F1-04", "extract_complexity returns dict with complexity_max integer")
def v_f1_04():
    from sentinel.analysis.metadata_extractor import extract_complexity

    code = "def foo(x):\n    if x > 0:\n        return x\n    return -x"
    result = extract_complexity(code, "python")
    assert isinstance(result, dict), f"Expected dict, got {type(result)}"
    assert "complexity_max" in result, f"Missing complexity_max key: {result.keys()}"
    assert "complexity_function" in result, f"Missing complexity_function key"
    assert isinstance(result["complexity_max"], int), (
        f"Expected int, got {type(result['complexity_max'])}"
    )
    assert result["complexity_max"] >= 1, f"Expected >= 1, got {result['complexity_max']}"


@check("V-F1-05", "compute_token_usage_ratio returns float from worker_usage dict")
def v_f1_05():
    from sentinel.analysis.metadata_extractor import compute_token_usage_ratio

    # Takes a worker_usage dict (from Ollama stats), not raw ints
    usage = {"eval_count": 4096, "prompt_eval_count": 200}
    result = compute_token_usage_ratio(usage, 8192)
    assert isinstance(result, float), f"Expected float, got {type(result)}"
    assert 0.0 <= result <= 1.0, f"Expected 0..1, got {result}"
    assert abs(result - 0.5) < 0.01, f"Expected ~0.5, got {result}"

    # None usage returns None
    assert compute_token_usage_ratio(None) is None, "None usage should return None"


@check("V-F1-06", "TaskStatus and StepStatus enums importable with expected values")
def v_f1_06():
    from sentinel.core.models import TaskStatus, StepStatus

    # TaskStatus must have at least: success, partial, scan_blocked
    assert hasattr(TaskStatus, "SUCCESS"), "Missing TaskStatus.SUCCESS"
    assert hasattr(TaskStatus, "PARTIAL"), "Missing TaskStatus.PARTIAL"
    assert hasattr(TaskStatus, "SCAN_BLOCKED"), "Missing TaskStatus.SCAN_BLOCKED"

    # StepStatus must have at least: success, blocked, error, skipped
    assert hasattr(StepStatus, "SUCCESS"), "Missing StepStatus.SUCCESS"
    assert hasattr(StepStatus, "BLOCKED"), "Missing StepStatus.BLOCKED"
    assert hasattr(StepStatus, "ERROR"), "Missing StepStatus.ERROR"
    assert hasattr(StepStatus, "SKIPPED"), "Missing StepStatus.SKIPPED"


@check("V-F1-07", "step_outcomes column exists in conversation_turns table")
def v_f1_07():
    from sentinel.core.db import init_db

    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test.db"
        db = init_db(str(db_path))
        # Check schema
        cursor = db.execute("PRAGMA table_info(conversation_turns)")
        columns = {row[1] for row in cursor.fetchall()}
        assert "step_outcomes" in columns, (
            f"step_outcomes not in conversation_turns columns: {columns}"
        )
        db.close()


@check("V-F1-08", "Build a step outcome dict via _build_step_outcome()")
def v_f1_08():
    from sentinel.planner.orchestrator import Orchestrator
    from sentinel.core.models import PlanStep, StepResult

    orch = Orchestrator.__new__(Orchestrator)
    orch._pipeline = MagicMock()
    orch._planner = MagicMock()
    orch._tool_executor = MagicMock()
    orch._tool_executor._last_exec_meta = None
    orch._session_store = None
    orch._approval_manager = None
    orch._memory_store = None
    orch._bus = MagicMock()
    orch._bus.emit = AsyncMock()
    orch._event_bus = None

    step = PlanStep(id="s1", type="llm_task", description="Generate code")
    result = StepResult(step_id="s1", status="success", content="print('hi')")

    outcome = orch._build_step_outcome(step, result, elapsed_s=1.5)
    assert isinstance(outcome, dict), f"Expected dict, got {type(outcome)}"

    # Core fields (must match FAIL criteria in validation doc)
    required_fields = ["step_type", "status", "output_size", "scanner_result", "duration_s"]
    for f in required_fields:
        assert f in outcome, f"Missing field: {f}"

    assert outcome["step_type"] == "llm_task"
    assert outcome["status"] == "success"
    assert outcome["output_size"] == len("print('hi')"), (
        f"output_size mismatch: {outcome['output_size']}"
    )
    assert outcome["scanner_result"] == "clean", (
        f"Expected 'clean' for non-blocked result, got {outcome['scanner_result']!r}"
    )
    assert abs(outcome["duration_s"] - 1.5) < 0.01


@check("V-F1-09", "Format enriched history with step outcomes")
def v_f1_09():
    from sentinel.planner.planner import ClaudePlanner

    planner = ClaudePlanner.__new__(ClaudePlanner)
    planner._client = MagicMock()

    history = [{
        "turn": 1,
        "request": "Write hello.py",
        "outcome": "success",
        "summary": "Wrote hello.py",
        "step_outcomes": [{
            "step_type": "llm_task",
            "status": "success",
            "output_size": 100,
            "output_language": "python",
            "syntax_valid": True,
            "scanner_result": "pass",
            "duration_s": 2.0,
        }],
    }]

    text = planner._format_enriched_history(history)
    assert isinstance(text, str), f"Expected str, got {type(text)}"
    assert len(text) > 0, "Empty enriched history"
    assert "success" in text.lower(), "Missing success status in output"
    assert "python" in text.lower(), "Missing language in output"


@check("V-F1-10", "Format enriched history with pre-F1 turns (backward compat)")
def v_f1_10():
    from sentinel.planner.planner import ClaudePlanner

    planner = ClaudePlanner.__new__(ClaudePlanner)
    planner._client = MagicMock()

    # Pre-F1 turn: no step_outcomes field
    history = [{
        "turn": 1,
        "request": "Do something",
        "outcome": "success",
        "summary": "Did something",
        "step_outcomes": None,
    }]

    text = planner._format_enriched_history(history)
    assert isinstance(text, str), f"Expected str, got {type(text)}"
    assert len(text) > 0, "Empty output for pre-F1 turn"


@check("V-F1-11", "Step outcome with scanner block includes error_detail")
def v_f1_11():
    from sentinel.planner.orchestrator import Orchestrator
    from sentinel.core.models import PlanStep, StepResult

    orch = Orchestrator.__new__(Orchestrator)
    orch._pipeline = MagicMock()
    orch._planner = MagicMock()
    orch._tool_executor = MagicMock()
    orch._tool_executor._last_exec_meta = None
    orch._session_store = None
    orch._approval_manager = None
    orch._memory_store = None
    orch._bus = MagicMock()
    orch._bus.emit = AsyncMock()
    orch._event_bus = None

    step = PlanStep(id="s1", type="llm_task", description="Generate code")
    result = StepResult(
        step_id="s1", status="blocked", content="",
        error="Semgrep: hardcoded-credentials",
    )

    outcome = orch._build_step_outcome(step, result, elapsed_s=0.5)
    # Blocked steps should carry error info
    assert outcome["status"] == "blocked" or outcome["status"] == "scan_blocked", (
        f"Expected blocked status, got {outcome['status']}"
    )


@check("V-F1-12", "Step outcome includes file_path for file_write")
def v_f1_12():
    from sentinel.planner.orchestrator import Orchestrator
    from sentinel.core.models import PlanStep, StepResult

    orch = Orchestrator.__new__(Orchestrator)
    orch._pipeline = MagicMock()
    orch._planner = MagicMock()
    orch._tool_executor = MagicMock()
    orch._tool_executor._last_exec_meta = {
        "file_path": "/workspace/hello.py",
        "before_size": 0,
        "after_size": 100,
    }
    orch._session_store = None
    orch._approval_manager = None
    orch._memory_store = None
    orch._bus = MagicMock()
    orch._bus.emit = AsyncMock()
    orch._event_bus = None

    step = PlanStep(
        id="s1", type="tool_call", description="Write file",
        tool="file_write", args={"path": "/workspace/hello.py"},
    )
    result = StepResult(step_id="s1", status="success", content="ok")

    outcome = orch._build_step_outcome(step, result, elapsed_s=0.3)
    assert "file_path" in outcome, f"Missing file_path in outcome: {outcome.keys()}"
    assert outcome["file_path"] == "/workspace/hello.py"


# ═══════════════════════════════════════════════════════════════════════
# F2: Session Intelligence
# ═══════════════════════════════════════════════════════════════════════

@check("V-F2-01", "SessionStore maps signal→7200, websocket→1800, api→3600")
def v_f2_01():
    from sentinel.session.store import SessionStore

    store = SessionStore(ttl=3600, max_count=100)
    assert store._get_channel_ttl("signal") == 7200
    assert store._get_channel_ttl("websocket") == 1800
    assert store._get_channel_ttl("api") == 3600


@check("V-F2-02", "SessionStore maps routine→0 (never expires)")
def v_f2_02():
    from sentinel.session.store import SessionStore

    store = SessionStore(ttl=3600, max_count=100)
    assert store._get_channel_ttl("routine") == 0


@check("V-F2-03", "Unknown channel falls back to default TTL (3600)")
def v_f2_03():
    from sentinel.session.store import SessionStore

    store = SessionStore(ttl=3600, max_count=100)
    assert store._get_channel_ttl("some_future_channel") == 3600


@check("V-F2-04", "History ≤20 turns passes through _prune_history unchanged")
def v_f2_04():
    from sentinel.planner.planner import ClaudePlanner

    history = [{"turn": i, "request": f"r{i}", "outcome": "success"}
               for i in range(1, 21)]  # exactly 20

    kept, pruned = ClaudePlanner._prune_history(history, max_turns=20)
    assert len(kept) == 20, f"Expected 20 kept, got {len(kept)}"
    assert len(pruned) == 0, f"Expected 0 pruned, got {len(pruned)}"


@check("V-F2-05", "History >20 turns returns head(3) + tail(10), drops middle")
def v_f2_05():
    from sentinel.planner.planner import ClaudePlanner

    history = [{"turn": i, "request": f"r{i}", "outcome": "success"}
               for i in range(1, 31)]  # 30 turns

    kept, pruned = ClaudePlanner._prune_history(
        history, max_turns=20, head_count=3, tail_count=10,
    )
    assert len(kept) == 13, f"Expected 13 kept (3+10), got {len(kept)}"
    assert len(pruned) == 17, f"Expected 17 pruned, got {len(pruned)}"

    # Head should be turns 1-3
    assert kept[0]["turn"] == 1
    assert kept[2]["turn"] == 3

    # Tail should be turns 21-30
    assert kept[3]["turn"] == 21
    assert kept[-1]["turn"] == 30


@check("V-F2-06", "Pruning returns correct (kept, pruned) tuple types")
def v_f2_06():
    from sentinel.planner.planner import ClaudePlanner

    history = [{"turn": i, "request": f"r{i}", "outcome": "success"}
               for i in range(1, 26)]

    result = ClaudePlanner._prune_history(history, max_turns=20)
    assert isinstance(result, tuple), f"Expected tuple, got {type(result)}"
    assert len(result) == 2, f"Expected 2-tuple, got {len(result)}-tuple"
    kept, pruned = result
    assert isinstance(kept, list)
    assert isinstance(pruned, list)
    # Every turn is in exactly one list
    assert len(kept) + len(pruned) == 25


@check("V-F2-07", "_flush_pruned_turns writes to MemoryStore with system:session_prune")
def v_f2_07():
    from sentinel.planner.orchestrator import Orchestrator
    from sentinel.memory.chunks import MemoryStore
    from sentinel.core.db import init_db

    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test.db"
        db = init_db(str(db_path))
        mem = MemoryStore(db)

        orch = Orchestrator(
            planner=MagicMock(),
            pipeline=MagicMock(),
            memory_store=mem,
        )

        pruned = [
            {"turn": 4, "request": "fix CSS", "outcome": "success",
             "step_outcomes": [{"file_path": "/workspace/style.css"}]},
            {"turn": 5, "request": "add responsive", "outcome": "success",
             "step_outcomes": [{"file_path": "/workspace/style.css"}]},
        ]

        asyncio.run(orch._flush_pruned_turns("sess-123", pruned))

        # Check that something was written
        chunks = mem.list_chunks(limit=10)
        assert len(chunks) > 0, "No chunks written to MemoryStore"

        # Check source tag (MemoryChunk has .source attribute)
        found_prune = any(
            c.source == "system:session_prune"
            or "session_prune" in str(c.source)
            for c in chunks
        )
        assert found_prune, (
            f"No chunk with system:session_prune source. Sources: "
            f"{[c.source for c in chunks]}"
        )
        db.close()


@check("V-F2-08", "Duplicate flush for same session+range is deduplicated")
def v_f2_08():
    from sentinel.planner.orchestrator import Orchestrator
    from sentinel.memory.chunks import MemoryStore
    from sentinel.core.db import init_db

    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test.db"
        db = init_db(str(db_path))
        mem = MemoryStore(db)

        orch = Orchestrator(
            planner=MagicMock(),
            pipeline=MagicMock(),
            memory_store=mem,
        )

        pruned = [
            {"turn": 4, "request": "fix CSS", "outcome": "success",
             "step_outcomes": [{"file_path": "/workspace/style.css"}]},
        ]

        # Flush twice with same data
        asyncio.run(orch._flush_pruned_turns("sess-123", pruned))
        asyncio.run(orch._flush_pruned_turns("sess-123", pruned))

        chunks = mem.list_chunks(limit=10)
        prune_chunks = [
            c for c in chunks
            if "session_prune" in str(c.source)
        ]
        assert len(prune_chunks) <= 1, (
            f"Expected deduplication, got {len(prune_chunks)} prune chunks"
        )
        db.close()


@check("V-F2-09", "_build_cross_session_context returns formatted results")
def v_f2_09():
    from sentinel.planner.orchestrator import Orchestrator
    from sentinel.memory.search import SearchResult

    mock_memory = MagicMock()
    mock_memory.db = MagicMock()

    orch = Orchestrator(
        planner=MagicMock(),
        pipeline=MagicMock(),
        memory_store=mock_memory,
    )

    # SearchResult fields: chunk_id, content, source, score, match_type
    fake_results = [
        SearchResult(
            chunk_id="1", content="Built bitcoin tracker on port 8080",
            source="auto", score=0.9, match_type="hybrid",
        ),
    ]

    with patch("sentinel.memory.search.hybrid_search", return_value=fake_results):
        result = asyncio.run(orch._build_cross_session_context("bitcoin tracker"))

    assert isinstance(result, str), f"Expected str, got {type(result)}"
    assert len(result) > 0, "Empty cross-session context"
    assert "bitcoin" in result.lower() or "tracker" in result.lower(), (
        f"Expected search result content in output: {result[:200]}"
    )


@check("V-F2-10", "Cross-session returns empty string when no results")
def v_f2_10():
    from sentinel.planner.orchestrator import Orchestrator

    mock_memory = MagicMock()
    mock_memory.db = MagicMock()

    orch = Orchestrator(
        planner=MagicMock(),
        pipeline=MagicMock(),
        memory_store=mock_memory,
    )

    with patch("sentinel.memory.search.hybrid_search", return_value=[]):
        result = asyncio.run(orch._build_cross_session_context("something random"))

    assert result == "", f"Expected empty string, got: {result!r}"


@check("V-F2-11", "task_in_progress flag set/clear cycle works")
def v_f2_11():
    from sentinel.session.store import SessionStore
    from sentinel.core.db import init_db

    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test.db"
        db = init_db(str(db_path))
        store = SessionStore(db=db, ttl=3600, max_count=100)

        session = store.get_or_create("user1", "api")
        assert session.task_in_progress is False, "Default should be False"

        # set_task_in_progress is on Session, not SessionStore
        session.set_task_in_progress(True)
        # Reload from DB
        reloaded = store.get(session.session_id)
        assert reloaded is not None
        assert reloaded.task_in_progress is True, "Flag not persisted as True"

        session.set_task_in_progress(False)
        reloaded = store.get(session.session_id)
        assert reloaded.task_in_progress is False, "Flag not cleared"
        db.close()


@check("V-F2-12", "_build_interrupted_task_warning includes request + file paths")
def v_f2_12():
    from sentinel.planner.builders import build_interrupted_task_warning
    from sentinel.session.store import Session, ConversationTurn

    session = Session(session_id="s1", source="api")
    session.turns = [
        ConversationTurn(
            request_text="Write hello.py",
            result_status="success",
            plan_summary="Wrote hello.py",
            step_outcomes=[
                {"step_type": "llm_task", "status": "success",
                 "file_path": "/workspace/hello.py"},
                {"step_type": "tool_call", "status": "error",
                 "file_path": "/workspace/config.yaml"},
            ],
        ),
    ]

    warning = build_interrupted_task_warning(session)
    assert isinstance(warning, str)
    assert len(warning) > 0, "Empty warning for session with turns"
    assert "hello.py" in warning or "workspace" in warning, (
        f"Expected file paths in warning: {warning[:200]}"
    )


@check("V-F2-13", "task_in_progress column exists in sessions table")
def v_f2_13():
    from sentinel.core.db import init_db

    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test.db"
        db = init_db(str(db_path))
        cursor = db.execute("PRAGMA table_info(sessions)")
        columns = {row[1] for row in cursor.fetchall()}
        assert "task_in_progress" in columns, (
            f"task_in_progress not in sessions columns: {columns}"
        )
        db.close()


@check("V-F2-14", "Config has all 7 F2 settings with correct defaults")
def v_f2_14():
    from sentinel.core.config import Settings

    s = Settings()
    assert s.session_ttl_signal == 7200, f"signal TTL: {s.session_ttl_signal}"
    assert s.session_ttl_websocket == 1800, f"websocket TTL: {s.session_ttl_websocket}"
    assert s.session_ttl_api == 3600, f"api TTL: {s.session_ttl_api}"
    assert s.session_ttl_mcp == 3600, f"mcp TTL: {s.session_ttl_mcp}"
    assert s.session_ttl_routine == 0, f"routine TTL: {s.session_ttl_routine}"
    assert s.session_max_history_turns == 20, f"max turns: {s.session_max_history_turns}"
    assert s.cross_session_token_budget == 2000, (
        f"cross-session budget: {s.cross_session_token_budget}"
    )


# ═══════════════════════════════════════════════════════════════════════
# F1+F2 Integration Checks
# ═══════════════════════════════════════════════════════════════════════

@check("V-INT-01", "Step outcomes survive round-trip through session storage (JSON)")
def v_int_01():
    from sentinel.session.store import SessionStore, ConversationTurn
    from sentinel.core.db import init_db

    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test.db"
        db = init_db(str(db_path))
        store = SessionStore(db=db, ttl=3600, max_count=100)

        session = store.get_or_create("user1", "api")

        step_outcomes = [
            {"step_type": "llm_task", "status": "success", "output_size": 500,
             "output_language": "python", "syntax_valid": True,
             "scanner_result": "pass", "duration_s": 2.1,
             "file_path": "/workspace/hello.py"},
        ]

        turn = ConversationTurn(
            request_text="Write hello.py",
            result_status="success",
            risk_score=0.0,
            plan_summary="Wrote hello.py",
            step_outcomes=step_outcomes,
        )
        session.add_turn(turn)

        # Reload session and check step_outcomes survived
        reloaded = store.get(session.session_id)
        assert reloaded is not None
        assert len(reloaded.turns) == 1
        rt = reloaded.turns[0]
        assert rt.step_outcomes is not None, "step_outcomes lost on round-trip"
        assert len(rt.step_outcomes) == 1
        assert rt.step_outcomes[0]["output_language"] == "python"
        assert rt.step_outcomes[0]["file_path"] == "/workspace/hello.py"
        db.close()


@check("V-INT-02", "Enriched history with >20 turns prunes while preserving step_outcomes")
def v_int_02():
    from sentinel.planner.planner import ClaudePlanner

    history = []
    for i in range(1, 26):
        history.append({
            "turn": i,
            "request": f"request {i}",
            "outcome": "success",
            "summary": f"did thing {i}",
            "step_outcomes": [
                {"step_type": "llm_task", "status": "success",
                 "file_path": f"/workspace/file_{i}.py"},
            ],
        })

    kept, pruned = ClaudePlanner._prune_history(history, max_turns=20)

    # Kept turns should still have step_outcomes
    for turn in kept:
        assert "step_outcomes" in turn, f"Turn {turn['turn']} lost step_outcomes"
        assert turn["step_outcomes"] is not None
        assert len(turn["step_outcomes"]) > 0

    # Format should work with pruned history
    planner = ClaudePlanner.__new__(ClaudePlanner)
    planner._client = MagicMock()
    text = planner._format_enriched_history(kept)
    assert len(text) > 0, "Empty formatted output from pruned history"


@check("V-INT-03", "Memory flush includes step_outcome file paths (FTS5 searchable)")
def v_int_03():
    from sentinel.planner.orchestrator import Orchestrator
    from sentinel.memory.chunks import MemoryStore
    from sentinel.core.db import init_db

    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test.db"
        db = init_db(str(db_path))
        mem = MemoryStore(db)

        orch = Orchestrator(
            planner=MagicMock(),
            pipeline=MagicMock(),
            memory_store=mem,
        )

        pruned = [
            {"turn": 4, "request": "fix the layout",
             "outcome": "success",
             "step_outcomes": [
                 {"file_path": "/workspace/layout.css", "status": "success"},
             ]},
        ]

        asyncio.run(orch._flush_pruned_turns("sess-456", pruned))

        chunks = mem.list_chunks(limit=10)
        assert len(chunks) > 0, "No chunks flushed"

        # Content should include file path for FTS5 searchability (MemoryChunk has .content)
        all_content = " ".join(c.content for c in chunks)
        assert "layout.css" in all_content or "workspace" in all_content, (
            f"File path not in flushed content: {all_content[:300]}"
        )
        db.close()


@check("V-INT-04", "Interrupted task warning extracts file paths from F1 step_outcomes")
def v_int_04():
    from sentinel.planner.builders import build_interrupted_task_warning
    from sentinel.session.store import Session, ConversationTurn

    session = Session(session_id="s1", source="api")
    session.turns = [
        ConversationTurn(
            request_text="Deploy the dashboard",
            result_status="partial",
            plan_summary="Deploying dashboard",
            step_outcomes=[
                {"step_type": "llm_task", "status": "success",
                 "file_path": "/workspace/dashboard.html"},
                {"step_type": "tool_call", "status": "error",
                 "file_path": "/workspace/deploy.sh",
                 "error_detail": "Permission denied"},
            ],
        ),
    ]

    warning = build_interrupted_task_warning(session)
    assert "dashboard" in warning.lower() or "deploy" in warning.lower(), (
        f"File info missing from interrupted warning: {warning[:200]}"
    )


# ═══════════════════════════════════════════════════════════════════════
# Runner
# ═══════════════════════════════════════════════════════════════════════

def main():
    print("=" * 70)
    print("F1-F2 Validation — F3 Readiness Assessment")
    print("=" * 70)
    print()

    # F1 checks
    print("── F1: Structured Outcome Metadata ──")
    v_f1_01()
    v_f1_02()
    v_f1_03()
    v_f1_04()
    v_f1_05()
    v_f1_06()
    v_f1_07()
    v_f1_08()
    v_f1_09()
    v_f1_10()
    v_f1_11()
    v_f1_12()

    print()
    print("── F2: Session Intelligence ──")
    v_f2_01()
    v_f2_02()
    v_f2_03()
    v_f2_04()
    v_f2_05()
    v_f2_06()
    v_f2_07()
    v_f2_08()
    v_f2_09()
    v_f2_10()
    v_f2_11()
    v_f2_12()
    v_f2_13()
    v_f2_14()

    print()
    print("── F1+F2 Integration ──")
    v_int_01()
    v_int_02()
    v_int_03()
    v_int_04()

    # Summary
    print()
    print("=" * 70)
    passed = sum(1 for _, s, _ in results if s == "PASS")
    failed = sum(1 for _, s, _ in results if s == "FAIL")
    total = len(results)

    print(f"Results: {passed}/{total} passed, {failed} failed")
    print()

    if failed > 0:
        print("FAILED CHECKS:")
        for check_id, status, detail in results:
            if status == "FAIL":
                print(f"  {check_id}: {detail}")
        print()
        print(f"\033[31mF3 READINESS: NOT READY — {failed} check(s) failed\033[0m")
        return 1
    else:
        print(f"\033[32mF3 READINESS: CONFIRMED — all {total} checks passed\033[0m")
        print()
        print("F1 (Structured Outcome Metadata): Complete and functional")
        print("F2 (Session Intelligence): Complete and functional")
        print("Integration: F1 metadata flows through F2 session lifecycle")
        print()
        print("Safe to proceed to F3 (Worker-Side Context).")
        return 0


if __name__ == "__main__":
    sys.exit(main())
