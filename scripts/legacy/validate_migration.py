#!/usr/bin/env python3
"""Post-migration validation: compare row counts between SQLite and PostgreSQL.

Usage:
    .venv/bin/python scripts/validate_migration.py \
        --sqlite /data/sentinel.db \
        --pg-dsn "postgresql://postgres@/sentinel?host=/tmp"

    # Or use config values:
    .venv/bin/python scripts/validate_migration.py --from-config
"""

from __future__ import annotations

import argparse
import asyncio
import sqlite3
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# Tables to validate (same order as migration script)
TABLES = [
    "sessions",
    "conversation_turns",
    "provenance",
    "file_provenance",
    "approvals",
    "memory_chunks",
    "routines",
    "routine_executions",
    "webhooks",
    "audit_log",
    "episodic_records",
    "episodic_file_index",
    "episodic_facts",
]


async def compare_counts(sqlite_conn: sqlite3.Connection, pg_pool) -> bool:
    """Compare row counts per table. Returns True if all match."""
    all_match = True
    max_name_len = max(len(t) for t in TABLES)

    for table in TABLES:
        sqlite_count = sqlite_conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]

        async with pg_pool.acquire() as conn:
            pg_count = await conn.fetchval(f"SELECT COUNT(*) FROM {table}")

        match = sqlite_count == pg_count
        symbol = "ok" if match else "MISMATCH"
        print(f"  {table:<{max_name_len}}  {sqlite_count:>6} SQLite / {pg_count:>6} PG  {symbol}")

        if not match:
            all_match = False

    print()
    if all_match:
        print("Validation passed: all tables match.")
    else:
        print("Validation FAILED: some tables have mismatched row counts.")

    return all_match


async def validate(sqlite_path: str, pg_dsn: str) -> bool:
    """Connect to both databases and compare row counts."""
    import asyncpg

    if not Path(sqlite_path).exists():
        print(f"Error: SQLite database not found: {sqlite_path}")
        sys.exit(1)

    sqlite_conn = sqlite3.connect(sqlite_path)
    pg_pool = await asyncpg.create_pool(pg_dsn, min_size=1, max_size=2)

    result = await compare_counts(sqlite_conn, pg_pool)

    sqlite_conn.close()
    await pg_pool.close()
    return result


def main():
    parser = argparse.ArgumentParser(description="Validate SQLite → PostgreSQL migration")
    parser.add_argument("--sqlite", help="Path to SQLite database file")
    parser.add_argument("--pg-dsn", help="PostgreSQL DSN")
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

    success = asyncio.run(validate(sqlite_path, pg_dsn))
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
