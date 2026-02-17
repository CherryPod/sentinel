#!/usr/bin/env python3
"""Migrate Sentinel data from SQLite to PostgreSQL.

Run once when switching from sqlite to postgresql backend.

Usage:
    .venv/bin/python scripts/migrate_sqlite_to_pg.py \
        --sqlite /data/sentinel.db \
        --pg-dsn "postgresql://postgres@/sentinel?host=/tmp"

    # Or use config values:
    .venv/bin/python scripts/migrate_sqlite_to_pg.py --from-config
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sqlite3
import struct
import sys
from datetime import datetime, timezone
from pathlib import Path

# Add project root to path for config imports
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


# ── Type conversion helpers ──────────────────────────────────────

def _sqlite_bool_to_python(val: int | None) -> bool:
    """SQLite INTEGER boolean → Python bool."""
    if val is None:
        return False
    return bool(val)


def _sqlite_ts_to_datetime(val: str | None) -> datetime | None:
    """SQLite TEXT timestamp → Python datetime (for TIMESTAMPTZ columns)."""
    if val is None or val == "":
        return None
    try:
        s = val.replace("Z", "+00:00")
        return datetime.fromisoformat(s)
    except (ValueError, TypeError):
        return None


def _sqlite_json_to_dict(val: str | None) -> dict | list:
    """SQLite TEXT JSON → Python dict/list (for JSONB columns)."""
    if val is None or val == "":
        return {}
    try:
        return json.loads(val)
    except (json.JSONDecodeError, TypeError):
        return {}


def _vec_blob_to_pgvector(blob: bytes, dim: int = 768) -> str | None:
    """Convert sqlite-vec struct.pack float array to pgvector string format."""
    if blob is None or len(blob) == 0:
        return None
    try:
        floats = struct.unpack(f"{dim}f", blob)
        return "[" + ",".join(f"{f:.8f}" for f in floats) + "]"
    except struct.error:
        return None


# ── Table migration definitions ──────────────────────────────────

# Each entry: (table_name, sqlite_columns, pg_columns, column_converters)
# column_converters maps column index to converter function.
# Columns not in converters are passed through as-is (TEXT → TEXT).

TABLES = [
    # 1. sessions
    (
        "sessions",
        "session_id, user_id, source, cumulative_risk, violation_count, "
        "is_locked, created_at, last_active, task_in_progress",
        "session_id, user_id, source, cumulative_risk, violation_count, "
        "is_locked, created_at, last_active, task_in_progress",
        {5: _sqlite_bool_to_python, 6: _sqlite_ts_to_datetime, 7: _sqlite_ts_to_datetime, 8: _sqlite_bool_to_python},
    ),
    # 2. conversation_turns (skip id — PG uses GENERATED ALWAYS AS IDENTITY)
    (
        "conversation_turns",
        "session_id, user_id, request_text, result_status, blocked_by, "
        "risk_score, plan_summary, auto_approved, elapsed_s, step_outcomes, created_at",
        "session_id, user_id, request_text, result_status, blocked_by, "
        "risk_score, plan_summary, auto_approved, elapsed_s, step_outcomes, created_at",
        {4: _sqlite_json_to_dict, 7: _sqlite_bool_to_python, 9: _sqlite_json_to_dict, 10: _sqlite_ts_to_datetime},
    ),
    # 3. provenance
    (
        "provenance",
        "data_id, user_id, content, source, trust_level, originated_from, "
        "parent_ids, created_at",
        "data_id, user_id, content, source, trust_level, originated_from, "
        "parent_ids, created_at",
        {6: _sqlite_json_to_dict, 7: _sqlite_ts_to_datetime},
    ),
    # 4. file_provenance
    (
        "file_provenance",
        "file_path, user_id, writer_data_id, created_at",
        "file_path, user_id, writer_data_id, created_at",
        {3: _sqlite_ts_to_datetime},
    ),
    # 5. approvals
    (
        "approvals",
        "approval_id, user_id, task_id, plan_json, status, decided_at, "
        "decided_reason, decided_by, expires_at, source_key, user_request, created_at",
        "approval_id, user_id, task_id, plan_json, status, decided_at, "
        "decided_reason, decided_by, expires_at, source_key, user_request, created_at",
        {3: _sqlite_json_to_dict, 5: _sqlite_ts_to_datetime, 8: _sqlite_ts_to_datetime, 11: _sqlite_ts_to_datetime},
    ),
    # 6. memory_chunks (skip search_vector — GENERATED column)
    (
        "memory_chunks",
        "chunk_id, user_id, content, source, metadata, created_at, updated_at",
        "chunk_id, user_id, content, source, metadata, created_at, updated_at",
        {4: _sqlite_json_to_dict, 5: _sqlite_ts_to_datetime, 6: _sqlite_ts_to_datetime},
    ),
    # 7. routines
    (
        "routines",
        "routine_id, user_id, name, description, trigger_type, trigger_config, "
        "action_config, enabled, last_run_at, next_run_at, cooldown_s, created_at, updated_at",
        "routine_id, user_id, name, description, trigger_type, trigger_config, "
        "action_config, enabled, last_run_at, next_run_at, cooldown_s, created_at, updated_at",
        {5: _sqlite_json_to_dict, 6: _sqlite_json_to_dict, 7: _sqlite_bool_to_python,
         8: _sqlite_ts_to_datetime, 9: _sqlite_ts_to_datetime, 11: _sqlite_ts_to_datetime, 12: _sqlite_ts_to_datetime},
    ),
    # 8. routine_executions
    (
        "routine_executions",
        "execution_id, routine_id, user_id, triggered_by, started_at, "
        "completed_at, status, result_summary, error, task_id",
        "execution_id, routine_id, user_id, triggered_by, started_at, "
        "completed_at, status, result_summary, error, task_id",
        {4: _sqlite_ts_to_datetime, 5: _sqlite_ts_to_datetime},
    ),
    # 9. webhooks
    (
        "webhooks",
        "webhook_id, name, secret, enabled, user_id, created_at",
        "webhook_id, name, secret, enabled, user_id, created_at",
        {3: _sqlite_bool_to_python, 5: _sqlite_ts_to_datetime},
    ),
    # 10. audit_log (skip id — PG uses GENERATED ALWAYS AS IDENTITY)
    (
        "audit_log",
        "user_id, event_type, session_id, details, created_at",
        "user_id, event_type, session_id, details, created_at",
        {3: _sqlite_json_to_dict, 4: _sqlite_ts_to_datetime},
    ),
    # 11. episodic_records
    (
        "episodic_records",
        "record_id, session_id, task_id, user_id, user_request, task_status, "
        "plan_summary, step_count, success_count, file_paths, error_patterns, "
        "defined_symbols, step_outcomes, linked_records, relevance_score, "
        "access_count, last_accessed, memory_chunk_id, created_at",
        "record_id, session_id, task_id, user_id, user_request, task_status, "
        "plan_summary, step_count, success_count, file_paths, error_patterns, "
        "defined_symbols, step_outcomes, linked_records, relevance_score, "
        "access_count, last_accessed, memory_chunk_id, created_at",
        {9: _sqlite_json_to_dict, 10: _sqlite_json_to_dict, 11: _sqlite_json_to_dict,
         12: _sqlite_json_to_dict, 13: _sqlite_json_to_dict, 16: _sqlite_ts_to_datetime,
         18: _sqlite_ts_to_datetime},
    ),
    # 12. episodic_file_index
    (
        "episodic_file_index",
        "file_path, record_id, action",
        "file_path, record_id, action",
        {},
    ),
    # 13. episodic_facts (skip search_vector — GENERATED column)
    (
        "episodic_facts",
        "fact_id, record_id, fact_type, content, file_path, created_at",
        "fact_id, record_id, fact_type, content, file_path, created_at",
        {5: _sqlite_ts_to_datetime},
    ),
]


def _convert_row(row: tuple, converters: dict[int, callable]) -> tuple:
    """Apply type converters to a SQLite row."""
    result = list(row)
    for idx, converter in converters.items():
        if idx < len(result):
            result[idx] = converter(result[idx])
    return tuple(result)


def _build_insert_sql(table: str, pg_columns: str) -> str:
    """Build INSERT ... ON CONFLICT DO NOTHING SQL for asyncpg."""
    cols = [c.strip() for c in pg_columns.split(",")]
    placeholders = ", ".join(f"${i+1}" for i in range(len(cols)))
    return f"INSERT INTO {table} ({pg_columns}) VALUES ({placeholders}) ON CONFLICT DO NOTHING"


async def migrate_table(
    sqlite_conn: sqlite3.Connection,
    pg_pool,
    table: str,
    sqlite_columns: str,
    pg_columns: str,
    converters: dict[int, callable],
) -> int:
    """Migrate a single table from SQLite to PostgreSQL. Returns row count."""
    rows = sqlite_conn.execute(f"SELECT {sqlite_columns} FROM {table}").fetchall()
    if not rows:
        print(f"  {table}: 0 rows (empty)")
        return 0

    insert_sql = _build_insert_sql(table, pg_columns)
    converted = [_convert_row(row, converters) for row in rows]

    async with pg_pool.acquire() as conn:
        async with conn.transaction():
            for row in converted:
                await conn.execute(insert_sql, *row)

    print(f"  {table}: {len(converted)} rows migrated")
    return len(converted)


async def migrate_embeddings(
    sqlite_conn: sqlite3.Connection,
    pg_pool,
) -> int:
    """Migrate embeddings from memory_chunks_vec to memory_chunks.embedding in PG.

    Returns count of embeddings migrated, or 0 if no vec table or no data.
    """
    # Check if the vec table exists
    has_vec = sqlite_conn.execute(
        "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='memory_chunks_vec'"
    ).fetchone()[0]
    if not has_vec:
        print("  embeddings: no memory_chunks_vec table — skipping")
        return 0

    rows = sqlite_conn.execute(
        "SELECT chunk_id, embedding FROM memory_chunks_vec"
    ).fetchall()
    if not rows:
        print("  embeddings: no data in memory_chunks_vec — skipping")
        return 0

    count = 0
    async with pg_pool.acquire() as conn:
        async with conn.transaction():
            for chunk_id, blob in rows:
                vec_str = _vec_blob_to_pgvector(blob)
                if vec_str is not None:
                    await conn.execute(
                        "UPDATE memory_chunks SET embedding = $1::vector WHERE chunk_id = $2",
                        vec_str, chunk_id,
                    )
                    count += 1

    print(f"  embeddings: {count} vectors migrated to memory_chunks.embedding")
    return count


async def run_migration(sqlite_path: str, pg_dsn: str) -> None:
    """Run the full SQLite → PostgreSQL migration."""
    import asyncpg

    # Validate SQLite file exists
    if not Path(sqlite_path).exists():
        print(f"Error: SQLite database not found: {sqlite_path}")
        sys.exit(1)

    print(f"Source:      {sqlite_path}")
    print(f"Destination: {pg_dsn}")
    print()

    # Connect to both databases
    sqlite_conn = sqlite3.connect(sqlite_path)
    sqlite_conn.execute("PRAGMA foreign_keys=ON")

    pg_pool = await asyncpg.create_pool(pg_dsn, min_size=1, max_size=4)

    print("Migrating tables...")
    total_rows = 0
    for table, sqlite_cols, pg_cols, converters in TABLES:
        count = await migrate_table(sqlite_conn, pg_pool, table, sqlite_cols, pg_cols, converters)
        total_rows += count

    # Task 4.2: Embedding migration
    print()
    print("Checking embeddings...")
    embed_count = await migrate_embeddings(sqlite_conn, pg_pool)
    total_rows += embed_count

    print()
    print(f"Migration complete: {total_rows} total rows across {len(TABLES)} tables")

    sqlite_conn.close()
    await pg_pool.close()


def main():
    parser = argparse.ArgumentParser(description="Migrate Sentinel data from SQLite to PostgreSQL")
    parser.add_argument("--sqlite", help="Path to SQLite database file")
    parser.add_argument("--pg-dsn", help='PostgreSQL DSN (e.g. "postgresql://postgres@/sentinel?host=/tmp")')
    parser.add_argument("--from-config", action="store_true", help="Read paths from Sentinel config")
    args = parser.parse_args()

    if args.from_config:
        from sentinel.core.config import settings
        sqlite_path = settings.db_path
        pg_dsn = f"postgresql://{settings.pg_user}@/{settings.pg_dbname}?host={settings.pg_host}"
    elif args.sqlite and args.pg_dsn:
        sqlite_path = args.sqlite
        pg_dsn = args.pg_dsn
    else:
        parser.error("Provide --sqlite and --pg-dsn, or use --from-config")
        return

    asyncio.run(run_migration(sqlite_path, pg_dsn))


if __name__ == "__main__":
    main()
