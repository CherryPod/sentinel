"""Tests for sentinel.api.metrics — aggregation logic against in-memory SQLite."""

import json
import sqlite3
from datetime import datetime, timedelta, timezone

import pytest

from sentinel.core.db import init_db
from sentinel.api.metrics import get_metrics


@pytest.fixture
def db():
    """In-memory database with schema ready."""
    conn = init_db(":memory:")
    yield conn
    conn.close()


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _ago_iso(hours: int = 0, days: int = 0) -> str:
    dt = datetime.now(timezone.utc) - timedelta(hours=hours, days=days)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _seed_session(db, session_id="s1"):
    db.execute(
        "INSERT OR IGNORE INTO sessions (session_id) VALUES (?)", (session_id,)
    )


def _seed_turn(db, session_id="s1", result_status="success", blocked_by=None,
               auto_approved=0, elapsed_s=None, created_at=None):
    _seed_session(db, session_id)
    db.execute(
        "INSERT INTO conversation_turns "
        "(session_id, request_text, result_status, blocked_by, auto_approved, elapsed_s, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (
            session_id, "test request", result_status,
            json.dumps(blocked_by or []),
            auto_approved,
            elapsed_s,
            created_at or _now_iso(),
        ),
    )
    db.commit()


def _seed_approval(db, status="approved", created_at=None):
    import uuid
    db.execute(
        "INSERT INTO approvals (approval_id, plan_json, status, expires_at, created_at) "
        "VALUES (?, ?, ?, ?, ?)",
        (str(uuid.uuid4()), '{"steps":[]}', status, "2099-01-01T00:00:00Z",
         created_at or _now_iso()),
    )
    db.commit()


def _seed_routine_execution(db, routine_id="r1", status="success",
                            started_at=None, completed_at=None):
    import uuid
    # Ensure routine exists
    db.execute(
        "INSERT OR IGNORE INTO routines (routine_id, name) VALUES (?, ?)",
        (routine_id, "test_routine"),
    )
    db.execute(
        "INSERT INTO routine_executions (execution_id, routine_id, status, started_at, completed_at) "
        "VALUES (?, ?, ?, ?, ?)",
        (str(uuid.uuid4()), routine_id, status,
         started_at or _now_iso(), completed_at),
    )
    db.commit()


class TestEmptyDatabase:
    def test_empty_database_returns_zeros(self, db):
        result = get_metrics(db, "24h")
        assert result["approval_funnel"]["auto_approved"] == 0
        assert result["approval_funnel"]["manually_approved"] == 0
        assert result["task_outcomes"]["success"] == 0
        assert result["scanner_blocks"] == []
        assert result["routine_health"]["total"] == 0
        assert result["session_health"]["active"] == 0
        assert result["response_times"]["count"] == 0
        assert result["response_times"]["avg_s"] == 0.0


class TestApprovalFunnel:
    def test_approval_funnel_counts(self, db):
        _seed_approval(db, status="approved")
        _seed_approval(db, status="approved")
        _seed_approval(db, status="denied")
        _seed_approval(db, status="expired")
        _seed_approval(db, status="pending")

        result = get_metrics(db, "24h")
        funnel = result["approval_funnel"]
        assert funnel["manually_approved"] == 2
        assert funnel["denied"] == 1
        assert funnel["expired"] == 1
        assert funnel["pending"] == 1

    def test_approval_funnel_window_filter(self, db):
        """Approvals older than 24h should not appear in 24h window."""
        _seed_approval(db, status="approved", created_at=_ago_iso(hours=2))
        _seed_approval(db, status="approved", created_at=_ago_iso(days=2))

        result_24h = get_metrics(db, "24h")
        assert result_24h["approval_funnel"]["manually_approved"] == 1

        result_all = get_metrics(db, "all")
        assert result_all["approval_funnel"]["manually_approved"] == 2

    def test_auto_approved_count(self, db):
        _seed_turn(db, auto_approved=1, elapsed_s=5.0)
        _seed_turn(db, auto_approved=1, elapsed_s=3.0)
        _seed_turn(db, auto_approved=0, elapsed_s=8.0)

        result = get_metrics(db, "24h")
        assert result["approval_funnel"]["auto_approved"] == 2


class TestTaskOutcomes:
    def test_task_outcomes_grouping(self, db):
        _seed_turn(db, result_status="success")
        _seed_turn(db, result_status="success")
        _seed_turn(db, result_status="blocked", blocked_by=["cred_scanner"])
        _seed_turn(db, result_status="error")
        _seed_turn(db, result_status="refused")

        result = get_metrics(db, "24h")
        outcomes = result["task_outcomes"]
        assert outcomes["success"] == 2
        assert outcomes["blocked"] == 1
        assert outcomes["error"] == 1
        assert outcomes["refused"] == 1


class TestScannerBlocks:
    def test_scanner_blocks_parsed_from_json(self, db):
        _seed_turn(db, result_status="blocked", blocked_by=["credential_scanner"])
        _seed_turn(db, result_status="blocked", blocked_by=["credential_scanner"])
        _seed_turn(db, result_status="blocked", blocked_by=["sensitive_path_scanner"])

        result = get_metrics(db, "24h")
        blocks = result["scanner_blocks"]
        assert len(blocks) == 2
        # Sorted by count desc
        assert blocks[0]["scanner"] == "credential_scanner"
        assert blocks[0]["count"] == 2
        assert blocks[1]["scanner"] == "sensitive_path_scanner"
        assert blocks[1]["count"] == 1

    def test_scanner_blocks_multi_scanner(self, db):
        """One turn blocked by 2 scanners counts for both."""
        _seed_turn(db, result_status="blocked",
                   blocked_by=["credential_scanner", "sensitive_path_scanner"])

        result = get_metrics(db, "24h")
        blocks = {b["scanner"]: b["count"] for b in result["scanner_blocks"]}
        assert blocks["credential_scanner"] == 1
        assert blocks["sensitive_path_scanner"] == 1


class TestRoutineHealth:
    def test_routine_health_aggregation(self, db):
        now = _now_iso()
        _seed_routine_execution(db, status="success", started_at=now)
        _seed_routine_execution(db, status="success", started_at=now)
        _seed_routine_execution(db, status="error", started_at=now)
        _seed_routine_execution(db, status="timeout", started_at=now)

        result = get_metrics(db, "24h")
        health = result["routine_health"]
        assert health["total"] == 4
        assert health["success"] == 2
        assert health["error"] == 1
        assert health["timeout"] == 1

    def test_routine_avg_duration(self, db):
        """Known timestamps should produce a known average duration."""
        t1 = "2026-02-20T10:00:00.000000Z"
        t1_end = "2026-02-20T10:00:10.000000Z"  # 10 seconds
        t2 = "2026-02-20T10:01:00.000000Z"
        t2_end = "2026-02-20T10:01:20.000000Z"  # 20 seconds

        _seed_routine_execution(db, status="success", started_at=t1, completed_at=t1_end)
        _seed_routine_execution(db, status="success", started_at=t2, completed_at=t2_end)

        result = get_metrics(db, "all")
        # Average of 10 and 20 = 15.0
        assert result["routine_health"]["avg_duration_s"] == 15.0


class TestSessionHealth:
    def test_session_health(self, db):
        db.execute(
            "INSERT INTO sessions (session_id, cumulative_risk, violation_count, is_locked) "
            "VALUES (?, ?, ?, ?)",
            ("s1", 0.3, 2, 0),
        )
        db.execute(
            "INSERT INTO sessions (session_id, cumulative_risk, violation_count, is_locked) "
            "VALUES (?, ?, ?, ?)",
            ("s2", 0.5, 1, 1),
        )
        db.commit()

        result = get_metrics(db, "24h")
        health = result["session_health"]
        assert health["active"] == 2
        assert health["locked"] == 1
        assert health["avg_risk"] == 0.4  # (0.3 + 0.5) / 2
        assert health["total_violations"] == 3


class TestResponseTimes:
    def test_response_times_percentiles(self, db):
        """Known values should produce known p50/p95."""
        # 10 values: 1, 2, 3, 4, 5, 6, 7, 8, 9, 10
        for i in range(1, 11):
            _seed_turn(db, elapsed_s=float(i))

        result = get_metrics(db, "24h")
        times = result["response_times"]
        assert times["count"] == 10
        assert times["avg_s"] == 5.5
        assert times["p50_s"] == 5.5  # median of 1..10
        # p95: index = min(int(0.95 * 10 + 0.5), 9) = min(10, 9) = 9 → value 10
        assert times["p95_s"] == 10.0

    def test_response_times_null_excluded(self, db):
        """Turns without elapsed_s should be skipped."""
        _seed_turn(db, elapsed_s=5.0)
        _seed_turn(db, elapsed_s=None)
        _seed_turn(db, elapsed_s=10.0)

        result = get_metrics(db, "24h")
        assert result["response_times"]["count"] == 2
        assert result["response_times"]["avg_s"] == 7.5

    def test_all_window_includes_everything(self, db):
        _seed_turn(db, elapsed_s=1.0, created_at=_ago_iso(days=60))
        _seed_turn(db, elapsed_s=2.0, created_at=_ago_iso(days=1))
        _seed_turn(db, elapsed_s=3.0)

        result = get_metrics(db, "all")
        assert result["response_times"]["count"] == 3

    def test_30d_window_boundary(self, db):
        _seed_turn(db, elapsed_s=1.0, created_at=_ago_iso(days=60))
        _seed_turn(db, elapsed_s=2.0, created_at=_ago_iso(days=15))
        _seed_turn(db, elapsed_s=3.0)

        result = get_metrics(db, "30d")
        assert result["response_times"]["count"] == 2
