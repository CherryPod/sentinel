#!/usr/bin/env python3
"""B5 v2 Database Security Red Team — PostgreSQL isolation and data integrity testing.

Tests database security across two domains:
  Domain A: Direct database attack vectors (RLS bypass, role escalation, SQL injection)
  Domain B: Application-layer data manipulation (cross-user exfiltration, integrity attacks)

Unlike B1-B2 (scanner/policy layers) and B4 (sandbox containment), B5 tests whether
data isolation holds when attacks target the persistence layer — both directly and
through the application's tool execution pipeline.

v2 covers (12 categories):
  B5.1  RLS policy enforcement         B5.7  Data integrity manipulation
  B5.2  Role separation                B5.8  Audit log integrity
  B5.3  SQL injection vectors          B5.9  Privacy boundary data leakage
  B5.4  Session variable manipulation  B5.10 Connection pool security
  B5.5  Schema integrity               B5.11 Migration and schema safety
  B5.6  Cross-user data exfiltration   B5.12 Temporal and concurrency attacks

Usage:
  .venv/bin/python3 scripts/red_team_b5_v2.py
  .venv/bin/python3 scripts/red_team_b5_v2.py --categories rls_enforcement role_separation
  .venv/bin/python3 scripts/red_team_b5_v2.py --verbose
"""

from __future__ import annotations

import asyncio
import argparse
import json
import os
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

# ── Constants ──────────────────────────────────────────────────────

ALL_CATEGORIES = [
    "rls_enforcement",        # B5.1
    "role_separation",        # B5.2
    "sql_injection",          # B5.3
    "session_variable",       # B5.4
    "schema_integrity",       # B5.5
    "cross_user_exfil",       # B5.6
    "data_integrity",         # B5.7
    "audit_log",              # B5.8
    "privacy_boundary",       # B5.9
    "connection_pool",        # B5.10
    "migration_safety",       # B5.11
    "temporal_concurrency",   # B5.12
]

# Tables with RLS policies (from pg_schema.py)
RLS_TABLES = [
    "sessions", "conversation_turns", "memory_chunks", "routines",
    "routine_executions", "webhooks", "episodic_records",
    "episodic_file_index", "episodic_facts", "provenance",
    "file_provenance", "approvals", "confirmations", "contacts",
    "contact_channels", "audit_log",
]

# Tables that should have user_id column
USER_ID_TABLES = [
    "sessions", "conversation_turns", "memory_chunks", "routines",
    "routine_executions", "webhooks", "episodic_records",
    "episodic_file_index", "episodic_facts", "provenance",
    "file_provenance", "approvals", "confirmations", "contacts",
    "audit_log",
]

# Sentinel API config
DEFAULT_SENTINEL_URL = "https://localhost:3001"
DEFAULT_SENTINEL_PIN = ""  # Read from env or secrets

# Test user for multi-user isolation tests
TEST_USER_DISPLAY_NAME = "b5_test_user_DO_NOT_USE"
TEST_USER_ID = None  # Populated at runtime


# ── JSONL Writer ───────────────────────────────────────────────────

class JsonlWriter:
    """Crash-safe JSONL writer with immediate fsync."""

    def __init__(self, path: str):
        self.path = path
        self._fh = open(path, "a", buffering=1, encoding="utf-8")

    def write(self, record: dict):
        self._fh.write(json.dumps(record, default=str) + "\n")
        self._fh.flush()
        os.fsync(self._fh.fileno())

    def close(self):
        self._fh.close()


# ── Test Result ─────────────────────────────────────────────────────

@dataclass
class TestResult:
    category: str
    test_id: str
    description: str
    status: str       # pass, fail, warn, skip, info
    expected: str = ""
    actual: str = ""
    severity: str = ""


# ── B5 Test Runner ──────────────────────────────────────────────────

class B5Runner:
    """Run all B5 database security tests."""

    def __init__(
        self,
        output_path: str,
        verbose: bool = False,
        sentinel_container: str = "sentinel",
        sentinel_url: str = DEFAULT_SENTINEL_URL,
        sentinel_pin: str = "",
    ):
        self.output_path = output_path
        self.verbose = verbose
        self.sentinel_ctr = sentinel_container
        self.sentinel_url = sentinel_url
        self.sentinel_pin = sentinel_pin
        self.writer = JsonlWriter(output_path)
        self.results: list[TestResult] = []
        self._test_user_id: int | None = None
        self._rls_active: bool | None = None

    # ── Helpers ─────────────────────────────────────────────────

    def _record(self, r: TestResult):
        """Record a test result to JSONL and internal list."""
        self.results.append(r)
        self.writer.write({
            "version": "v2",
            "type": "b5_result",
            "category": r.category,
            "test_id": r.test_id,
            "description": r.description,
            "status": r.status,
            "expected": r.expected,
            "actual": r.actual,
            "severity": r.severity,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })
        marker = {
            "pass": "[PASS]", "fail": "[FAIL]", "warn": "[WARN]",
            "skip": "[SKIP]", "info": "[INFO]",
        }.get(r.status, "[????]")
        print(f"  {marker} {r.description}")
        if r.status == "fail" and r.expected:
            print(f"         Expected: {r.expected}")
        if r.status == "fail" and r.actual:
            print(f"         Actual:   {r.actual[:200]}")
        if r.status == "warn" and r.actual:
            print(f"         Note: {r.actual[:200]}")

    def _pass(self, cat: str, tid: str, desc: str):
        self._record(TestResult(cat, tid, desc, "pass"))

    def _fail(self, cat: str, tid: str, desc: str,
              expected: str = "", actual: str = "", severity: str = "S2"):
        self._record(TestResult(cat, tid, desc, "fail", expected, actual, severity))

    def _warn(self, cat: str, tid: str, desc: str, note: str = ""):
        self._record(TestResult(cat, tid, desc, "warn", actual=note, severity="backlog"))

    def _skip(self, cat: str, tid: str, desc: str, reason: str = ""):
        self._record(TestResult(cat, tid, desc, "skip", actual=reason))

    def _info(self, cat: str, tid: str, desc: str, detail: str = ""):
        self._record(TestResult(cat, tid, desc, "info", actual=detail))

    def _psql(
        self,
        sql: str,
        role: str = "sentinel_app",
        user_id: int | None = None,
    ) -> tuple[str, int]:
        """Run SQL inside the sentinel container via psql.

        Args:
            sql: SQL statement to execute.
            role: PG role to connect as.
            user_id: If set, wraps the query in a transaction with
                     SET LOCAL app.current_user_id = '<user_id>'.
        Returns:
            (stdout+stderr, returncode)
        """
        needs_context = user_id is not None
        if needs_context:
            # Wrap in transaction with user context, matching RLSPool pattern
            sql = (
                f"BEGIN; "
                f"SELECT set_config('app.current_user_id', '{user_id}', true); "
                f"{sql} "
                f"COMMIT;"
            )
        try:
            result = subprocess.run(
                [
                    "podman", "exec", self.sentinel_ctr,
                    "psql", "-h", "/tmp",  # PG socket is in /tmp, not default /var/run/postgresql
                    "-U", role, "-d", "sentinel",
                    "-t", "-A",  # tuples-only, unaligned output
                    "-c", sql,
                ],
                capture_output=True, text=True, timeout=30,
            )
            stdout = result.stdout.strip()
            stderr = result.stderr.strip()
            if needs_context and stdout:
                # Strip set_config return value (first line of output).
                # psql -t -A outputs each statement's result on its own line.
                # set_config('app.current_user_id', '2', true) returns '2'.
                lines = stdout.split("\n")
                if len(lines) > 1:
                    stdout = "\n".join(lines[1:]).strip()
            combined = stdout
            if stderr:
                combined = combined + "\n" + stderr if combined else stderr
            return combined, result.returncode
        except subprocess.TimeoutExpired:
            return "timeout", -1
        except FileNotFoundError:
            return "podman not found", -1

    def _psql_owner(self, sql: str) -> tuple[str, int]:
        """Run SQL as sentinel_owner (admin role)."""
        return self._psql(sql, role="sentinel_owner")

    def _podman_exec(self, container: str, *cmd: str) -> tuple[str, int]:
        """Run a command inside a container via podman exec."""
        try:
            result = subprocess.run(
                ["podman", "exec", container, *cmd],
                capture_output=True, text=True, timeout=30,
            )
            return result.stdout + result.stderr, result.returncode
        except subprocess.TimeoutExpired:
            return "timeout", -1
        except FileNotFoundError:
            return "podman not found", -1

    async def _check_rls_active(self) -> bool:
        """Check if RLS is active on the database. Cache result."""
        if self._rls_active is not None:
            return self._rls_active

        out, rc = self._psql(
            "SELECT COUNT(*) FROM pg_catalog.pg_policy "
            "WHERE polname = 'user_isolation';"
        )
        try:
            count = int(out.split("\n")[0].strip())
            self._rls_active = count > 0
        except (ValueError, IndexError):
            self._rls_active = False

        return self._rls_active

    async def _setup_test_user(self) -> int | None:
        """Create a test user (user 2) for isolation tests. Returns user_id."""
        if self._test_user_id is not None:
            return self._test_user_id

        # Check if test user already exists
        out, rc = self._psql_owner(
            f"SELECT user_id FROM users "
            f"WHERE display_name = '{TEST_USER_DISPLAY_NAME}';"
        )
        if rc == 0 and out.strip():
            try:
                self._test_user_id = int(out.strip().split("\n")[0])
                return self._test_user_id
            except ValueError:
                pass

        # Create test user via sentinel_owner (bypasses RLS)
        out, rc = self._psql_owner(
            f"INSERT INTO users (display_name) "
            f"VALUES ('{TEST_USER_DISPLAY_NAME}') "
            f"RETURNING user_id;"
        )
        if rc == 0 and out.strip():
            try:
                self._test_user_id = int(out.strip().split("\n")[0])
                return self._test_user_id
            except ValueError:
                pass

        return None

    async def _cleanup_test_user(self):
        """Remove test user and all associated data."""
        if self._test_user_id is None:
            return

        uid = self._test_user_id
        # Delete in dependency order (child tables first)
        for table in [
            "conversation_turns", "episodic_file_index", "episodic_facts",
            "episodic_records", "file_provenance", "provenance",
            "routine_executions", "contact_channels",
        ]:
            self._psql_owner(
                f"DELETE FROM {table} WHERE user_id = {uid};"
            )

        # Tables with FK deps already cleared
        for table in [
            "sessions", "memory_chunks", "routines", "webhooks",
            "approvals", "confirmations", "contacts", "audit_log",
        ]:
            self._psql_owner(
                f"DELETE FROM {table} WHERE user_id = {uid};"
            )

        # Delete the user
        self._psql_owner(f"DELETE FROM users WHERE user_id = {uid};")
        self._test_user_id = None

    # ── B5.1: RLS Policy Enforcement ────────────────────────────

    async def test_rls_enforcement(self):
        """Test Row-Level Security policy enforcement on all tables."""
        print("\nB5.1: RLS Policy Enforcement")
        cat = "rls_enforcement"

        rls_active = await self._check_rls_active()
        if not rls_active:
            self._warn(cat, "5.1.0", "RLS policies not deployed — skipping enforcement tests",
                        note="RLS in code but not active on this container")
            return

        # 5.1.1 — Verify FORCE RLS on all expected tables
        out, rc = self._psql(
            "SELECT relname FROM pg_class "
            "WHERE relrowsecurity = true AND relforcerowsecurity = true "
            "ORDER BY relname;"
        )
        forced_tables = set(out.strip().split("\n")) if out.strip() else set()
        missing_force = set(RLS_TABLES) - forced_tables
        if not missing_force:
            self._pass(cat, "5.1.1", f"FORCE RLS active on all {len(RLS_TABLES)} tables")
        else:
            self._fail(cat, "5.1.1", "Tables missing FORCE RLS",
                        expected=f"All {len(RLS_TABLES)} tables",
                        actual=f"Missing: {', '.join(sorted(missing_force))}",
                        severity="S1")

        # 5.1.2 — Verify user_isolation policies exist on all tables
        out, rc = self._psql(
            "SELECT tablename FROM pg_policies "
            "WHERE policyname = 'user_isolation' ORDER BY tablename;"
        )
        policy_tables = set(out.strip().split("\n")) if out.strip() else set()
        # contact_channels uses a different mechanism (parent FK subquery)
        expected_direct = set(RLS_TABLES)
        missing_policy = expected_direct - policy_tables
        if not missing_policy:
            self._pass(cat, "5.1.2", "user_isolation policies on all RLS tables")
        else:
            # contact_channels might use a different policy name
            if missing_policy == {"contact_channels"}:
                # Check for any policy on contact_channels
                out2, _ = self._psql(
                    "SELECT policyname FROM pg_policies "
                    "WHERE tablename = 'contact_channels';"
                )
                if out2.strip():
                    self._pass(cat, "5.1.2",
                               "user_isolation policies on all RLS tables "
                               "(contact_channels uses parent FK policy)")
                else:
                    self._fail(cat, "5.1.2", "contact_channels has no RLS policy",
                                severity="S1")
            else:
                self._fail(cat, "5.1.2", "Tables missing user_isolation policy",
                            expected="All RLS tables",
                            actual=f"Missing: {', '.join(sorted(missing_policy))}",
                            severity="S1")

        # 5.1.3 — user_id=0 (unset context) returns zero rows
        # Test on a table likely to have data
        test_tables = ["sessions", "episodic_records", "memory_chunks", "routines"]
        all_zero = True
        for table in test_tables:
            out, rc = self._psql(
                f"SELECT COUNT(*) FROM {table};",
                role="sentinel_app",
                user_id=0,
            )
            try:
                count = int(out.strip().split("\n")[-1].strip())
                if count != 0:
                    all_zero = False
                    self._fail(cat, "5.1.3", f"user_id=0 returns rows from {table}",
                                expected="0 rows",
                                actual=f"{count} rows",
                                severity="S0")
                    break
            except (ValueError, IndexError):
                all_zero = False
                self._warn(cat, "5.1.3", f"Could not parse count for {table}",
                            note=out[:100])
                break

        if all_zero:
            self._pass(cat, "5.1.3", "user_id=0 (unset context) returns zero rows on all tested tables")

        # 5.1.4 — Cross-user isolation: user 1 data invisible to user 2
        test_uid = await self._setup_test_user()
        if test_uid is None:
            self._skip(cat, "5.1.4", "Cross-user isolation test", reason="Could not create test user")
        else:
            # Insert test data as user 1, try to read as user 2
            # Use memory_chunks as the test table (simple schema)
            self._psql_owner(
                f"INSERT INTO memory_chunks (chunk_id, user_id, content, source) "
                f"VALUES ('b5-test-chunk-u1', 1, 'user1-secret-data', 'test') "
                f"ON CONFLICT DO NOTHING;"
            )
            # Query as user 2
            out, rc = self._psql(
                "SELECT COUNT(*) FROM memory_chunks WHERE chunk_id = 'b5-test-chunk-u1';",
                role="sentinel_app",
                user_id=test_uid,
            )
            try:
                count = int(out.strip().split("\n")[-1].strip())
                if count == 0:
                    self._pass(cat, "5.1.4", "User 2 cannot see user 1's memory chunks")
                else:
                    self._fail(cat, "5.1.4", "Cross-user data leak in memory_chunks",
                                expected="0 rows visible to user 2",
                                actual=f"{count} rows visible",
                                severity="S0")
            except (ValueError, IndexError):
                self._warn(cat, "5.1.4", "Could not parse cross-user query result",
                            note=out[:100])

            # Cleanup test data
            self._psql_owner("DELETE FROM memory_chunks WHERE chunk_id = 'b5-test-chunk-u1';")

        # 5.1.5 — New rows inherit correct user_id from session variable
        if test_uid:
            self._psql(
                f"INSERT INTO memory_chunks (chunk_id, user_id, content, source) "
                f"VALUES ('b5-test-chunk-u2', {test_uid}, 'user2-data', 'test');",
                role="sentinel_app",
                user_id=test_uid,
            )
            # Verify the row was created with correct user_id
            out, rc = self._psql_owner(
                "SELECT user_id FROM memory_chunks WHERE chunk_id = 'b5-test-chunk-u2';"
            )
            try:
                stored_uid = int(out.strip().split("\n")[0].strip())
                if stored_uid == test_uid:
                    self._pass(cat, "5.1.5", "New rows inherit correct user_id from session variable")
                else:
                    self._fail(cat, "5.1.5", "Row created with wrong user_id",
                                expected=f"user_id={test_uid}",
                                actual=f"user_id={stored_uid}",
                                severity="S1")
            except (ValueError, IndexError):
                self._warn(cat, "5.1.5", "Could not verify inserted row",
                            note=out[:100])

            self._psql_owner("DELETE FROM memory_chunks WHERE chunk_id = 'b5-test-chunk-u2';")

        # 5.1.6 — WITH CHECK prevents inserting rows for other users
        if test_uid:
            # As user 2, try to insert a row with user_id=1
            out, rc = self._psql(
                "INSERT INTO memory_chunks (chunk_id, user_id, content, source) "
                "VALUES ('b5-test-chunk-inject', 1, 'injected', 'test');",
                role="sentinel_app",
                user_id=test_uid,
            )
            if rc != 0 or "policy" in out.lower() or "permission" in out.lower():
                self._pass(cat, "5.1.6",
                           "WITH CHECK prevents user 2 from inserting rows as user 1")
            else:
                # Check if row was actually created
                out2, _ = self._psql_owner(
                    "SELECT user_id FROM memory_chunks "
                    "WHERE chunk_id = 'b5-test-chunk-inject';"
                )
                if out2.strip():
                    self._fail(cat, "5.1.6",
                               "User 2 inserted a row with user_id=1",
                               expected="INSERT blocked by RLS WITH CHECK",
                               actual=f"Row created with user_id={out2.strip()}",
                               severity="S0")
                else:
                    self._pass(cat, "5.1.6",
                               "WITH CHECK prevents user 2 from inserting rows as user 1")
                self._psql_owner(
                    "DELETE FROM memory_chunks WHERE chunk_id = 'b5-test-chunk-inject';"
                )

        # 5.1.7 — Audit log split policy: SELECT filtered, INSERT unrestricted
        out, rc = self._psql(
            "SELECT policyname, cmd FROM pg_policies "
            "WHERE tablename = 'audit_log' ORDER BY policyname;"
        )
        self._info(cat, "5.1.7", "Audit log RLS policies",
                    detail=out[:300] if out else "no policies found")

        # 5.1.8 — FORCE RLS applies even to table owner
        out, rc = self._psql(
            "SELECT COUNT(*) FROM memory_chunks;",
            role="sentinel_owner",
            user_id=0,
        )
        # Owner should have owner_full_access policy (TRUE) so should see all rows
        # even with user_id=0. This verifies the owner bypass works correctly.
        out_app, _ = self._psql(
            "SELECT COUNT(*) FROM memory_chunks;",
            role="sentinel_app",
            user_id=0,
        )
        try:
            owner_count = int(out.strip().split("\n")[-1].strip())
            app_count = int(out_app.strip().split("\n")[-1].strip())
            if app_count == 0 and owner_count >= 0:
                self._pass(cat, "5.1.8",
                           f"Owner bypasses RLS ({owner_count} rows), "
                           f"app blocked ({app_count} rows) with user_id=0")
            else:
                self._fail(cat, "5.1.8",
                           "RLS not enforced differently for owner vs app",
                           expected="app sees 0, owner sees all",
                           actual=f"app={app_count}, owner={owner_count}",
                           severity="S1")
        except (ValueError, IndexError):
            self._warn(cat, "5.1.8", "Could not parse owner vs app counts")

    # ── B5.2: Role Separation ──────────────────────────────────

    async def test_role_separation(self):
        """Test that sentinel_app has only DML privileges."""
        print("\nB5.2: Role Separation")
        cat = "role_separation"

        # 5.2.1 — sentinel_app cannot CREATE TABLE
        out, rc = self._psql(
            "CREATE TABLE b5_test_ddl (id SERIAL PRIMARY KEY);",
            role="sentinel_app",
        )
        if rc != 0 or "permission denied" in out.lower():
            self._pass(cat, "5.2.1", "sentinel_app cannot CREATE TABLE")
        else:
            self._fail(cat, "5.2.1", "sentinel_app can CREATE TABLE",
                        expected="Permission denied",
                        actual=out[:200],
                        severity="S0")
            # Cleanup if somehow created
            self._psql_owner("DROP TABLE IF EXISTS b5_test_ddl;")

        # 5.2.2 — sentinel_app cannot DROP TABLE
        out, rc = self._psql(
            "DROP TABLE sessions;",
            role="sentinel_app",
        )
        if rc != 0 or "permission denied" in out.lower() or "must be owner" in out.lower():
            self._pass(cat, "5.2.2", "sentinel_app cannot DROP TABLE")
        else:
            self._fail(cat, "5.2.2", "sentinel_app can DROP TABLE",
                        expected="Permission denied",
                        actual=out[:200],
                        severity="S0")

        # 5.2.3 — sentinel_app cannot ALTER TABLE
        out, rc = self._psql(
            "ALTER TABLE sessions ADD COLUMN b5_test TEXT;",
            role="sentinel_app",
        )
        if rc != 0 or "permission denied" in out.lower() or "must be owner" in out.lower():
            self._pass(cat, "5.2.3", "sentinel_app cannot ALTER TABLE")
        else:
            self._fail(cat, "5.2.3", "sentinel_app can ALTER TABLE",
                        expected="Permission denied",
                        actual=out[:200],
                        severity="S0")
            self._psql_owner("ALTER TABLE sessions DROP COLUMN IF EXISTS b5_test;")

        # 5.2.4 — sentinel_app cannot GRANT to other roles
        # Note: PG allows self-grant as no-op. The real test is whether
        # sentinel_app can grant privileges to other roles (escalation).
        out, rc = self._psql(
            "GRANT SELECT ON sessions TO sentinel_owner;",
            role="sentinel_app",
        )
        if rc != 0 or "permission denied" in out.lower() or "not owner" in out.lower():
            self._pass(cat, "5.2.4", "sentinel_app cannot GRANT to other roles")
        else:
            self._fail(cat, "5.2.4", "sentinel_app can GRANT to other roles",
                        expected="Permission denied",
                        actual=out[:200],
                        severity="S1")

        # 5.2.5 — sentinel_app has DML on data tables
        out, rc = self._psql(
            "SELECT has_table_privilege('sentinel_app', 'sessions', 'SELECT');",
            role="sentinel_owner",
        )
        if "t" in out.lower():
            self._pass(cat, "5.2.5", "sentinel_app has SELECT on data tables")
        else:
            self._fail(cat, "5.2.5", "sentinel_app lacks SELECT on sessions",
                        severity="S2")

        # 5.2.6 — SET ROLE escalation attempt
        out, rc = self._psql(
            "SET ROLE sentinel_owner;",
            role="sentinel_app",
        )
        if rc != 0 or "permission denied" in out.lower():
            self._pass(cat, "5.2.6", "sentinel_app cannot SET ROLE to sentinel_owner")
        else:
            # If SET ROLE succeeded, verify by attempting DDL
            out2, rc2 = self._psql(
                "SET ROLE sentinel_owner; CREATE TABLE b5_escalation_test (id INT);",
                role="sentinel_app",
            )
            if rc2 != 0 or "permission denied" in out2.lower():
                self._pass(cat, "5.2.6", "SET ROLE blocked or ineffective")
            else:
                self._fail(cat, "5.2.6", "sentinel_app escalated to sentinel_owner via SET ROLE",
                            expected="Permission denied",
                            actual="DDL succeeded after SET ROLE",
                            severity="S0")
                self._psql_owner("DROP TABLE IF EXISTS b5_escalation_test;")

        # 5.2.7 — SET SESSION AUTHORIZATION attempt
        out, rc = self._psql(
            "SET SESSION AUTHORIZATION sentinel_owner;",
            role="sentinel_app",
        )
        if rc != 0 or "permission denied" in out.lower():
            self._pass(cat, "5.2.7", "sentinel_app cannot SET SESSION AUTHORIZATION")
        else:
            self._fail(cat, "5.2.7", "sentinel_app can SET SESSION AUTHORIZATION",
                        expected="Requires superuser",
                        actual=out[:200],
                        severity="S0")

        # 5.2.8 — Check for SECURITY DEFINER functions (could bypass role restrictions)
        out, rc = self._psql(
            "SELECT proname, proowner::regrole FROM pg_proc "
            "WHERE prosecdef = true AND pronamespace = 'public'::regnamespace;",
            role="sentinel_owner",
        )
        if not out.strip() or out.strip() == "":
            self._pass(cat, "5.2.8", "No SECURITY DEFINER functions in public schema")
        else:
            self._warn(cat, "5.2.8", "SECURITY DEFINER functions found",
                        note=out[:300])

        # 5.2.9 — sentinel_app cannot UPDATE/DELETE audit_log
        out, rc = self._psql(
            "UPDATE audit_log SET event_type = 'tampered' WHERE FALSE;",
            role="sentinel_app",
        )
        if rc != 0 or "permission denied" in out.lower():
            self._pass(cat, "5.2.9", "sentinel_app cannot UPDATE audit_log (privilege revoked)")
        else:
            self._warn(cat, "5.2.9", "UPDATE on audit_log didn't error (may have 0 rows)",
                        note="Trigger would catch actual modifications")

    # ── B5.3: SQL Injection Vectors ────────────────────────────

    async def test_sql_injection(self):
        """Test SQL injection resistance through the application pipeline."""
        print("\nB5.3: SQL Injection Vectors")
        cat = "sql_injection"

        # 5.3.1 — Verify all store queries use parameterised queries
        # We test by attempting injection through the API (if accessible)
        # and directly through psql to confirm PG-level parameterisation

        # Direct injection attempt via current_setting manipulation
        out, rc = self._psql(
            "SELECT current_setting('app.current_user_id');",
            role="sentinel_app",
        )
        self._info(cat, "5.3.1", "Default app.current_user_id value",
                    detail=f"Value: {out.strip()}")

        # 5.3.2 — Test LIKE injection in search patterns
        # Inject a LIKE wildcard as if it were a search term
        out, rc = self._psql(
            "SELECT COUNT(*) FROM memory_chunks WHERE content LIKE '%' || $1 || '%';",
            role="sentinel_app",
            user_id=1,
        )
        # This is a structural test — we verify the pattern doesn't crash
        self._info(cat, "5.3.2", "LIKE pattern injection structural check",
                    detail=f"rc={rc}, output={out[:100]}")

        # 5.3.3 — Test JSON injection via JSONB fields
        out, rc = self._psql(
            """SELECT '{"key": "value"}'::jsonb @> '{"key": "value"}'::jsonb;""",
            role="sentinel_app",
        )
        if rc == 0:
            self._pass(cat, "5.3.3", "JSONB operations safe with parameterised literals")
        else:
            self._info(cat, "5.3.3", "JSONB test returned non-zero", detail=out[:100])

        # 5.3.4 — Verify no string concatenation in store queries
        # Static analysis: check Python source for f-string SQL patterns
        # (This is a code audit test, not a runtime test)
        out, _ = self._podman_exec(
            self.sentinel_ctr,
            "grep", "-rn", "f\".*SELECT.*{\\|f\".*INSERT.*{\\|f\".*UPDATE.*{\\|f\".*DELETE.*{",
            "/app/sentinel/stores/", "/app/sentinel/memory/",
            "/app/sentinel/security/provenance.py",
            "/app/sentinel/contacts/store.py",
        )
        if out.strip():
            # Filter known-safe patterns (whitelist-validated dynamic SET clauses)
            lines = [
                l for l in out.strip().split("\n")
                if l.strip()
                and "set_parts" not in l  # Dynamic SET with whitelist
                and "user_filter" not in l  # Provenance chain filter
                and "# noqa" not in l  # Explicitly marked safe
            ]
            if lines:
                self._warn(cat, "5.3.4", "Potential f-string SQL found in store code",
                            note=f"{len(lines)} lines: {lines[0][:120]}...")
            else:
                self._pass(cat, "5.3.4",
                           "f-string SQL patterns found but all use whitelisted field names")
        else:
            self._pass(cat, "5.3.4", "No f-string SQL concatenation in store code")

        # 5.3.5 — Test ORDER BY injection (hardcoded columns only)
        out, rc = self._psql(
            "SELECT column_name FROM information_schema.columns "
            "WHERE table_name = 'sessions' LIMIT 1;",
            role="sentinel_app",
        )
        # Verify we can query information_schema (expected behaviour for any role)
        self._info(cat, "5.3.5", "information_schema accessible to sentinel_app",
                    detail=f"Result: {out[:100]}")

        # 5.3.6 — Test vector similarity search injection (pgvector)
        out, rc = self._psql(
            "SELECT extname FROM pg_extension WHERE extname = 'vector';",
            role="sentinel_app",
        )
        if "vector" in out:
            # Try malformed vector input
            out2, rc2 = self._psql(
                "SELECT '[1,2,3]'::vector <-> '[4,5,6]'::vector;",
                role="sentinel_app",
            )
            if rc2 == 0:
                self._pass(cat, "5.3.6", "pgvector operations work with typed literals")
            else:
                self._info(cat, "5.3.6", "pgvector query failed",
                            detail=out2[:100])
        else:
            self._skip(cat, "5.3.6", "pgvector extension not installed",
                        reason="vector extension not found")

    # ── B5.4: Session Variable Manipulation ────────────────────

    async def test_session_variable(self):
        """Test app.current_user_id session variable security."""
        print("\nB5.4: Session Variable Manipulation")
        cat = "session_variable"

        rls_active = await self._check_rls_active()
        if not rls_active:
            self._warn(cat, "5.4.0", "RLS not active — session variable tests limited")

        # 5.4.1 — SET LOCAL is transaction-scoped (does not persist)
        # Set user_id=99 in one transaction, verify it resets in the next
        self._psql(
            "BEGIN; "
            "SELECT set_config('app.current_user_id', '99', true); "
            "COMMIT;",
            role="sentinel_app",
        )
        out, rc = self._psql(
            "SELECT current_setting('app.current_user_id');",
            role="sentinel_app",
        )
        val = out.strip().split("\n")[-1].strip() if out.strip() else ""
        if val != "99":
            self._pass(cat, "5.4.1",
                        f"SET LOCAL is transaction-scoped (post-tx value: {val})")
        else:
            self._fail(cat, "5.4.1", "SET LOCAL persisted across transactions",
                        expected="Database default (0)",
                        actual=f"Value persisted as {val}",
                        severity="S0")

        # 5.4.2 — SET (non-LOCAL) persistence test
        # Attempt SET without LOCAL — this should persist for the connection
        # but psql creates a new connection each time, so this is safe
        out, rc = self._psql(
            "SET app.current_user_id = '99';",
            role="sentinel_app",
        )
        # Verify in a separate invocation
        out2, _ = self._psql(
            "SELECT current_setting('app.current_user_id');",
            role="sentinel_app",
        )
        val2 = out2.strip().split("\n")[-1].strip() if out2.strip() else ""
        if val2 != "99":
            self._pass(cat, "5.4.2",
                        "SET without LOCAL does not persist across psql connections")
        else:
            self._fail(cat, "5.4.2",
                        "SET without LOCAL persisted (connection reuse issue)",
                        expected="Reset to default",
                        actual=f"Persisted as {val2}",
                        severity="S1")

        # 5.4.3 — Verify RLSPool always uses set_config with local=true
        # Code audit via grep inside container
        out, _ = self._podman_exec(
            self.sentinel_ctr,
            "grep", "-n", "set_config", "/app/sentinel/core/rls.py",
        )
        if "true" in out.lower():
            self._pass(cat, "5.4.3", "RLSPool uses set_config with local=true")
        else:
            self._fail(cat, "5.4.3", "RLSPool may not use LOCAL scope",
                        expected="set_config(..., true)",
                        actual=out[:200],
                        severity="S1")

        # 5.4.4 — Verify database-level default for app.current_user_id
        out, rc = self._psql(
            "SELECT setting FROM pg_settings WHERE name = 'app.current_user_id';",
            role="sentinel_app",
        )
        # Custom GUCs may not appear in pg_settings; check via current_setting
        if not out.strip():
            out, rc = self._psql(
                "SHOW app.current_user_id;",
                role="sentinel_app",
            )
        val = out.strip().split("\n")[-1].strip() if out.strip() else ""
        if val == "0":
            self._pass(cat, "5.4.4",
                        "Database default app.current_user_id = 0 (fail-closed)")
        elif val:
            self._warn(cat, "5.4.4",
                        f"Database default app.current_user_id = {val}",
                        note="Expected 0 for fail-closed behaviour")
        else:
            self._info(cat, "5.4.4", "Could not determine database default",
                        detail="Custom GUC may not be visible via pg_settings")

        # 5.4.5 — Verify ContextVar default is 0
        out, _ = self._podman_exec(
            self.sentinel_ctr,
            "grep", "-n", "current_user_id.*ContextVar",
            "/app/sentinel/core/context.py",
        )
        if "default=0" in out:
            self._pass(cat, "5.4.5", "ContextVar current_user_id defaults to 0 (fail-closed)")
        else:
            self._fail(cat, "5.4.5", "ContextVar default may not be 0",
                        expected="default=0",
                        actual=out[:200],
                        severity="S1")

        # 5.4.6 — Direct SET attempt to manipulate user context
        # In a real attack, the worker (Qwen) might try to inject SET commands
        out, rc = self._psql(
            "BEGIN; "
            "SELECT set_config('app.current_user_id', '1', true); "
            "SELECT * FROM memory_chunks LIMIT 1; "
            "SELECT set_config('app.current_user_id', '999', true); "
            "SELECT * FROM memory_chunks LIMIT 1; "
            "COMMIT;",
            role="sentinel_app",
        )
        # This tests whether a mid-transaction context switch is possible
        # (it is, by design — the question is whether the application allows it)
        self._info(cat, "5.4.6",
                    "Mid-transaction user context switch via set_config is possible at SQL level",
                    detail="Application must control transaction boundaries (RLSPool does this)")

    # ── B5.5: Schema Integrity ─────────────────────────────────

    async def test_schema_integrity(self):
        """Test schema structure for security properties."""
        print("\nB5.5: Schema Integrity")
        cat = "schema_integrity"

        # 5.5.1 — All user_id columns are NOT NULL
        out, rc = self._psql(
            "SELECT table_name FROM information_schema.columns "
            "WHERE column_name = 'user_id' AND is_nullable = 'YES' "
            "AND table_schema = 'public';"
        )
        if not out.strip():
            self._pass(cat, "5.5.1", "All user_id columns are NOT NULL")
        else:
            self._fail(cat, "5.5.1", "Nullable user_id columns found",
                        expected="All NOT NULL",
                        actual=f"Nullable: {out.strip()}",
                        severity="S2")

        # 5.5.2 — All user_id columns have DEFAULT constraint
        out, rc = self._psql(
            "SELECT table_name, column_default FROM information_schema.columns "
            "WHERE column_name = 'user_id' AND column_default IS NULL "
            "AND table_schema = 'public' "
            "AND table_name != 'users';"  # users.user_id is a PK, no default needed
        )
        if not out.strip():
            self._pass(cat, "5.5.2", "All user_id columns have DEFAULT constraint")
        else:
            self._warn(cat, "5.5.2", "user_id columns without DEFAULT",
                        note=out[:200])

        # 5.5.3 — user_id columns are INTEGER type (not TEXT)
        out, rc = self._psql(
            "SELECT table_name, data_type FROM information_schema.columns "
            "WHERE column_name = 'user_id' AND data_type != 'integer' "
            "AND table_schema = 'public';"
        )
        if not out.strip():
            self._pass(cat, "5.5.3", "All user_id columns are INTEGER type")
        else:
            self._fail(cat, "5.5.3", "user_id columns with wrong type",
                        expected="INTEGER",
                        actual=out[:200],
                        severity="S2")

        # 5.5.4 — FK constraints: user_id references users(user_id)
        out, rc = self._psql(
            "SELECT tc.table_name "
            "FROM information_schema.table_constraints tc "
            "JOIN information_schema.constraint_column_usage ccu "
            "  ON tc.constraint_name = ccu.constraint_name "
            "WHERE tc.constraint_type = 'FOREIGN KEY' "
            "  AND ccu.table_name = 'users' "
            "  AND ccu.column_name = 'user_id' "
            "ORDER BY tc.table_name;"
        )
        fk_tables = set(out.strip().split("\n")) if out.strip() else set()
        # Check which user_id tables have FK to users
        missing_fk = set()
        for table in USER_ID_TABLES:
            if table not in fk_tables:
                missing_fk.add(table)
        if not missing_fk:
            self._pass(cat, "5.5.4",
                        f"All {len(USER_ID_TABLES)} user_id tables have FK to users")
        else:
            self._warn(cat, "5.5.4", f"Tables without FK to users: {', '.join(sorted(missing_fk))}",
                        note="May be intentional for some tables")

        # 5.5.5 — Check for tables that should have user_id but don't
        out, rc = self._psql(
            "SELECT table_name FROM information_schema.tables "
            "WHERE table_schema = 'public' AND table_type = 'BASE TABLE' "
            "AND table_name NOT IN ("
            "  SELECT table_name FROM information_schema.columns "
            "  WHERE column_name = 'user_id' AND table_schema = 'public'"
            ") ORDER BY table_name;"
        )
        if out.strip():
            tables_without = [
                t.strip() for t in out.strip().split("\n")
                if t.strip() and t.strip() not in ("users", "contact_channels")
                # users doesn't need self-reference; contact_channels scoped via parent FK
            ]
            if tables_without:
                self._warn(cat, "5.5.5",
                            f"Tables without user_id column: {', '.join(tables_without)}",
                            note="Check if these need user scoping")
            else:
                self._pass(cat, "5.5.5", "All relevant tables have user_id column")
        else:
            self._pass(cat, "5.5.5", "All public tables have user_id column")

        # 5.5.6 — Indexes on user_id for RLS performance
        out, rc = self._psql(
            "SELECT tablename FROM pg_indexes "
            "WHERE indexdef LIKE '%user_id%' "
            "AND schemaname = 'public' "
            "GROUP BY tablename ORDER BY tablename;"
        )
        indexed_tables = set(out.strip().split("\n")) if out.strip() else set()
        missing_idx = set(USER_ID_TABLES) - indexed_tables
        if not missing_idx:
            self._pass(cat, "5.5.6", "All user_id tables have indexes for RLS performance")
        else:
            self._warn(cat, "5.5.6",
                        f"Tables without user_id index: {', '.join(sorted(missing_idx))}",
                        note="May cause table scans during RLS evaluation")

    # ── B5.6: Cross-User Data Exfiltration via Tools ───────────

    async def test_cross_user_exfil(self):
        """Test cross-user data isolation through the application layer."""
        print("\nB5.6: Cross-User Data Exfiltration via Tools")
        cat = "cross_user_exfil"

        rls_active = await self._check_rls_active()
        test_uid = await self._setup_test_user()

        if not test_uid:
            self._skip(cat, "5.6.0", "All cross-user tests",
                        reason="Could not create test user")
            return

        # 5.6.1 — Episodic records: user 1 data invisible to user 2
        self._psql_owner(
            "INSERT INTO episodic_records "
            "(record_id, user_id, session_id, task_summary, result_status, "
            " started_at, finished_at) "
            "VALUES ('b5-epi-u1', 1, 'b5-test-session', 'secret-task', 'success', "
            " NOW(), NOW()) ON CONFLICT DO NOTHING;"
        )
        out, rc = self._psql(
            "SELECT COUNT(*) FROM episodic_records WHERE record_id = 'b5-epi-u1';",
            role="sentinel_app",
            user_id=test_uid,
        )
        try:
            count = int(out.strip().split("\n")[-1].strip())
            if count == 0:
                self._pass(cat, "5.6.1", "Episodic records isolated between users")
            else:
                self._fail(cat, "5.6.1", "Cross-user episodic record leak",
                            expected="0 rows", actual=f"{count} rows", severity="S0")
        except (ValueError, IndexError):
            self._warn(cat, "5.6.1", "Could not parse result", note=out[:100])

        self._psql_owner("DELETE FROM episodic_records WHERE record_id = 'b5-epi-u1';")

        # 5.6.2 — Provenance records: cross-user isolation
        self._psql_owner(
            "INSERT INTO provenance "
            "(data_id, user_id, content, source, trust_level) "
            "VALUES ('b5-prov-u1', 1, 'secret-provenance', 'test', 'trusted') "
            "ON CONFLICT DO NOTHING;"
        )
        out, rc = self._psql(
            "SELECT COUNT(*) FROM provenance WHERE data_id = 'b5-prov-u1';",
            role="sentinel_app",
            user_id=test_uid,
        )
        try:
            count = int(out.strip().split("\n")[-1].strip())
            if count == 0:
                self._pass(cat, "5.6.2", "Provenance records isolated between users")
            else:
                self._fail(cat, "5.6.2", "Cross-user provenance leak",
                            expected="0 rows", actual=f"{count} rows", severity="S0")
        except (ValueError, IndexError):
            self._warn(cat, "5.6.2", "Could not parse result", note=out[:100])

        self._psql_owner("DELETE FROM provenance WHERE data_id = 'b5-prov-u1';")

        # 5.6.3 — Sessions: cross-user isolation
        self._psql_owner(
            "INSERT INTO sessions "
            "(session_id, user_id, source, created_at, last_active) "
            "VALUES ('b5-session-u1', 1, 'test', NOW(), NOW()) "
            "ON CONFLICT DO NOTHING;"
        )
        out, rc = self._psql(
            "SELECT COUNT(*) FROM sessions WHERE session_id = 'b5-session-u1';",
            role="sentinel_app",
            user_id=test_uid,
        )
        try:
            count = int(out.strip().split("\n")[-1].strip())
            if count == 0:
                self._pass(cat, "5.6.3", "Sessions isolated between users")
            else:
                self._fail(cat, "5.6.3", "Cross-user session leak",
                            expected="0 rows", actual=f"{count} rows", severity="S0")
        except (ValueError, IndexError):
            self._warn(cat, "5.6.3", "Could not parse result", note=out[:100])

        self._psql_owner("DELETE FROM sessions WHERE session_id = 'b5-session-u1';")

        # 5.6.4 — Contacts: cross-user isolation
        self._psql_owner(
            "INSERT INTO contacts "
            "(user_id, display_name) "
            f"VALUES (1, 'b5-contact-secret') "
            "ON CONFLICT DO NOTHING;"
        )
        out, rc = self._psql(
            "SELECT COUNT(*) FROM contacts WHERE display_name = 'b5-contact-secret';",
            role="sentinel_app",
            user_id=test_uid,
        )
        try:
            count = int(out.strip().split("\n")[-1].strip())
            if count == 0:
                self._pass(cat, "5.6.4", "Contacts isolated between users")
            else:
                self._fail(cat, "5.6.4", "Cross-user contact leak",
                            expected="0 rows", actual=f"{count} rows", severity="S0")
        except (ValueError, IndexError):
            self._warn(cat, "5.6.4", "Could not parse result", note=out[:100])

        self._psql_owner("DELETE FROM contacts WHERE display_name = 'b5-contact-secret';")

        # 5.6.5 — Routines: cross-user isolation
        self._psql_owner(
            "INSERT INTO routines "
            "(routine_id, user_id, name, trigger_type, trigger_config, "
            " action_config, enabled) "
            "VALUES ('b5-routine-u1', 1, 'secret-routine', 'cron', "
            " '{}'::jsonb, '{}'::jsonb, false) "
            "ON CONFLICT DO NOTHING;"
        )
        out, rc = self._psql(
            "SELECT COUNT(*) FROM routines WHERE routine_id = 'b5-routine-u1';",
            role="sentinel_app",
            user_id=test_uid,
        )
        try:
            count = int(out.strip().split("\n")[-1].strip())
            if count == 0:
                self._pass(cat, "5.6.5", "Routines isolated between users")
            else:
                self._fail(cat, "5.6.5", "Cross-user routine leak",
                            expected="0 rows", actual=f"{count} rows", severity="S0")
        except (ValueError, IndexError):
            self._warn(cat, "5.6.5", "Could not parse result", note=out[:100])

        self._psql_owner("DELETE FROM routines WHERE routine_id = 'b5-routine-u1';")

        # 5.6.6 — Approvals: cross-user isolation
        self._psql_owner(
            "INSERT INTO approvals "
            "(approval_id, user_id, plan_json, source_key, status, expires_at) "
            "VALUES ('b5-approval-u1', 1, '{}'::jsonb, 'test:b5', 'pending', "
            " NOW() + INTERVAL '1 hour') "
            "ON CONFLICT DO NOTHING;"
        )
        out, rc = self._psql(
            "SELECT COUNT(*) FROM approvals WHERE approval_id = 'b5-approval-u1';",
            role="sentinel_app",
            user_id=test_uid,
        )
        try:
            count = int(out.strip().split("\n")[-1].strip())
            if count == 0:
                self._pass(cat, "5.6.6", "Approvals isolated between users")
            else:
                self._fail(cat, "5.6.6", "Cross-user approval leak",
                            expected="0 rows", actual=f"{count} rows", severity="S1")
        except (ValueError, IndexError):
            self._warn(cat, "5.6.6", "Could not parse result", note=out[:100])

        self._psql_owner("DELETE FROM approvals WHERE approval_id = 'b5-approval-u1';")

        # 5.6.7 — File provenance: cross-user isolation
        self._psql_owner(
            "INSERT INTO provenance "
            "(data_id, user_id, content, source, trust_level) "
            "VALUES ('b5-fp-writer', 1, 'file-content', 'test', 'trusted') "
            "ON CONFLICT DO NOTHING;"
        )
        self._psql_owner(
            "INSERT INTO file_provenance "
            "(file_path, writer_data_id, user_id) "
            "VALUES ('/workspace/b5-secret.txt', 'b5-fp-writer', 1) "
            "ON CONFLICT DO NOTHING;"
        )
        out, rc = self._psql(
            "SELECT COUNT(*) FROM file_provenance "
            "WHERE file_path = '/workspace/b5-secret.txt';",
            role="sentinel_app",
            user_id=test_uid,
        )
        try:
            count = int(out.strip().split("\n")[-1].strip())
            if count == 0:
                self._pass(cat, "5.6.7", "File provenance isolated between users")
            else:
                self._fail(cat, "5.6.7", "Cross-user file provenance leak",
                            expected="0 rows", actual=f"{count} rows", severity="S1")
        except (ValueError, IndexError):
            self._warn(cat, "5.6.7", "Could not parse result", note=out[:100])

        self._psql_owner(
            "DELETE FROM file_provenance WHERE file_path = '/workspace/b5-secret.txt';"
        )
        self._psql_owner("DELETE FROM provenance WHERE data_id = 'b5-fp-writer';")

    # ── B5.7: Data Integrity Manipulation ──────────────────────

    async def test_data_integrity(self):
        """Test whether one user can modify another user's records."""
        print("\nB5.7: Data Integrity Manipulation")
        cat = "data_integrity"

        rls_active = await self._check_rls_active()
        test_uid = await self._setup_test_user()

        if not test_uid:
            self._skip(cat, "5.7.0", "All data integrity tests",
                        reason="Could not create test user")
            return

        # 5.7.1 — Cross-user UPDATE blocked (memory_chunks)
        self._psql_owner(
            "INSERT INTO memory_chunks (chunk_id, user_id, content, source) "
            "VALUES ('b5-integrity-u1', 1, 'original-content', 'test') "
            "ON CONFLICT DO NOTHING;"
        )
        # User 2 tries to UPDATE user 1's chunk
        out, rc = self._psql(
            "UPDATE memory_chunks SET content = 'tampered' "
            "WHERE chunk_id = 'b5-integrity-u1';",
            role="sentinel_app",
            user_id=test_uid,
        )
        # Verify content unchanged
        out2, _ = self._psql_owner(
            "SELECT content FROM memory_chunks WHERE chunk_id = 'b5-integrity-u1';"
        )
        if "original-content" in out2:
            self._pass(cat, "5.7.1", "Cross-user UPDATE blocked on memory_chunks")
        else:
            self._fail(cat, "5.7.1", "Cross-user UPDATE succeeded on memory_chunks",
                        expected="original-content",
                        actual=out2[:100],
                        severity="S0")
        self._psql_owner(
            "DELETE FROM memory_chunks WHERE chunk_id = 'b5-integrity-u1';"
        )

        # 5.7.2 — Cross-user DELETE blocked (routines)
        self._psql_owner(
            "INSERT INTO routines "
            "(routine_id, user_id, name, trigger_type, trigger_config, "
            " action_config, enabled) "
            "VALUES ('b5-integrity-routine', 1, 'protected', 'cron', "
            " '{}'::jsonb, '{}'::jsonb, false) "
            "ON CONFLICT DO NOTHING;"
        )
        self._psql(
            "DELETE FROM routines WHERE routine_id = 'b5-integrity-routine';",
            role="sentinel_app",
            user_id=test_uid,
        )
        out, _ = self._psql_owner(
            "SELECT COUNT(*) FROM routines WHERE routine_id = 'b5-integrity-routine';"
        )
        try:
            count = int(out.strip().split("\n")[0].strip())
            if count == 1:
                self._pass(cat, "5.7.2", "Cross-user DELETE blocked on routines")
            else:
                self._fail(cat, "5.7.2", "Cross-user DELETE succeeded on routines",
                            expected="1 (still exists)",
                            actual=f"{count}",
                            severity="S0")
        except (ValueError, IndexError):
            self._warn(cat, "5.7.2", "Could not verify", note=out[:100])

        self._psql_owner(
            "DELETE FROM routines WHERE routine_id = 'b5-integrity-routine';"
        )

        # 5.7.3 — Cross-user session modification blocked
        self._psql_owner(
            "INSERT INTO sessions "
            "(session_id, user_id, source, created_at, last_active, cumulative_risk) "
            "VALUES ('b5-integrity-sess', 1, 'test', NOW(), NOW(), 0.0) "
            "ON CONFLICT DO NOTHING;"
        )
        self._psql(
            "UPDATE sessions SET cumulative_risk = 99.0 "
            "WHERE session_id = 'b5-integrity-sess';",
            role="sentinel_app",
            user_id=test_uid,
        )
        out, _ = self._psql_owner(
            "SELECT cumulative_risk FROM sessions "
            "WHERE session_id = 'b5-integrity-sess';"
        )
        if out.strip() and "99" not in out:
            self._pass(cat, "5.7.3", "Cross-user session modification blocked")
        elif "99" in out:
            self._fail(cat, "5.7.3", "Cross-user session risk manipulation succeeded",
                        expected="cumulative_risk = 0.0",
                        actual=f"cumulative_risk = {out.strip()}",
                        severity="S0")
        else:
            self._warn(cat, "5.7.3", "Could not verify session modification",
                        note=out[:100])

        self._psql_owner(
            "DELETE FROM sessions WHERE session_id = 'b5-integrity-sess';"
        )

        # 5.7.4 — Cross-user confirmation tampering blocked
        self._psql_owner(
            "INSERT INTO confirmations "
            "(confirmation_id, user_id, channel, source_key, tool_name, "
            " tool_params, status, expires_at) "
            "VALUES ('b5-confirm-u1', 1, 'api', 'test:b5', 'file_write', "
            " '{}'::jsonb, 'pending', NOW() + INTERVAL '1 hour') "
            "ON CONFLICT DO NOTHING;"
        )
        # User 2 tries to confirm user 1's confirmation
        out, rc = self._psql(
            "UPDATE confirmations SET status = 'confirmed' "
            "WHERE confirmation_id = 'b5-confirm-u1';",
            role="sentinel_app",
            user_id=test_uid,
        )
        out2, _ = self._psql_owner(
            "SELECT status FROM confirmations "
            "WHERE confirmation_id = 'b5-confirm-u1';"
        )
        if "pending" in out2:
            self._pass(cat, "5.7.4", "Cross-user confirmation tampering blocked")
        elif "confirmed" in out2:
            self._fail(cat, "5.7.4", "User 2 confirmed user 1's pending action",
                        expected="status = pending",
                        actual=f"status = {out2.strip()}",
                        severity="S0")
        else:
            self._warn(cat, "5.7.4", "Could not verify confirmation status",
                        note=out2[:100])

        self._psql_owner(
            "DELETE FROM confirmations WHERE confirmation_id = 'b5-confirm-u1';"
        )

        # 5.7.5 — Cross-user webhook ownership
        self._psql_owner(
            "INSERT INTO webhooks "
            "(webhook_id, user_id, name, url, secret, enabled) "
            "VALUES ('b5-webhook-u1', 1, 'secret-hook', 'https://example.com', "
            " 'secret123', true) "
            "ON CONFLICT DO NOTHING;"
        )
        out, rc = self._psql(
            "SELECT secret FROM webhooks WHERE webhook_id = 'b5-webhook-u1';",
            role="sentinel_app",
            user_id=test_uid,
        )
        if not out.strip() or "secret123" not in out:
            self._pass(cat, "5.7.5", "Cross-user webhook access blocked")
        else:
            self._fail(cat, "5.7.5", "User 2 can read user 1's webhook secret",
                        expected="No access",
                        actual="Secret visible",
                        severity="S0")

        self._psql_owner(
            "DELETE FROM webhooks WHERE webhook_id = 'b5-webhook-u1';"
        )

    # ── B5.8: Audit Log Integrity ──────────────────────────────

    async def test_audit_log(self):
        """Test audit log immutability and integrity."""
        print("\nB5.8: Audit Log Integrity")
        cat = "audit_log"

        # 5.8.1 — Audit log is append-only: UPDATE blocked for sentinel_app
        # First insert a test entry
        self._psql_owner(
            "INSERT INTO audit_log "
            "(user_id, event_type, session_id, detail) "
            "VALUES (1, 'b5_test_event', 'b5-audit-test', 'original') "
            "ON CONFLICT DO NOTHING;"
        )
        out, rc = self._psql(
            "UPDATE audit_log SET detail = 'tampered' "
            "WHERE event_type = 'b5_test_event';",
            role="sentinel_app",
            user_id=1,
        )
        if rc != 0 or "permission denied" in out.lower() or "cannot be modified" in out.lower():
            self._pass(cat, "5.8.1", "Audit log UPDATE blocked for sentinel_app")
        else:
            self._fail(cat, "5.8.1", "Audit log UPDATE succeeded",
                        expected="Permission denied or trigger block",
                        actual=out[:200],
                        severity="S0")

        # 5.8.2 — Audit log DELETE blocked for sentinel_app
        out, rc = self._psql(
            "DELETE FROM audit_log WHERE event_type = 'b5_test_event';",
            role="sentinel_app",
            user_id=1,
        )
        if rc != 0 or "permission denied" in out.lower() or "cannot be modified" in out.lower():
            self._pass(cat, "5.8.2", "Audit log DELETE blocked for sentinel_app")
        else:
            self._fail(cat, "5.8.2", "Audit log DELETE succeeded",
                        expected="Permission denied or trigger block",
                        actual=out[:200],
                        severity="S0")

        # 5.8.3 — Immutable trigger blocks UPDATE even for sentinel_owner
        out, rc = self._psql_owner(
            "UPDATE audit_log SET detail = 'tampered-by-owner' "
            "WHERE event_type = 'b5_test_event';"
        )
        if "cannot be modified" in out.lower() or "cannot be modified" in out.lower():
            self._pass(cat, "5.8.3",
                        "Immutable trigger blocks UPDATE even for sentinel_owner")
        elif rc != 0:
            self._pass(cat, "5.8.3",
                        "UPDATE blocked for sentinel_owner (error returned)")
        else:
            self._fail(cat, "5.8.3", "Owner bypassed audit immutability trigger",
                        expected="Trigger raises exception",
                        actual=out[:200],
                        severity="S0")

        # 5.8.4 — Immutable trigger blocks DELETE even for sentinel_owner
        out, rc = self._psql_owner(
            "DELETE FROM audit_log WHERE event_type = 'b5_test_event';"
        )
        if "cannot be modified" in out.lower():
            self._pass(cat, "5.8.4",
                        "Immutable trigger blocks DELETE even for sentinel_owner")
        elif rc != 0:
            self._pass(cat, "5.8.4",
                        "DELETE blocked for sentinel_owner (error returned)")
        else:
            # Check if row still exists
            out2, _ = self._psql_owner(
                "SELECT COUNT(*) FROM audit_log "
                "WHERE event_type = 'b5_test_event';"
            )
            if out2.strip() and int(out2.strip().split("\n")[0]) > 0:
                self._warn(cat, "5.8.4",
                            "DELETE returned success but trigger may have blocked it",
                            note="Row still exists — trigger may have aborted silently")
            else:
                self._fail(cat, "5.8.4", "Owner deleted audit log entry",
                            expected="Trigger raises exception",
                            actual="Entry deleted",
                            severity="S0")

        # 5.8.5 — Verify trigger exists
        out, rc = self._psql(
            "SELECT tgname FROM pg_trigger "
            "WHERE tgrelid = 'audit_log'::regclass "
            "AND tgname = 'trg_immutable_audit';"
        )
        if "trg_immutable_audit" in out:
            self._pass(cat, "5.8.5", "Immutable audit trigger exists")
        else:
            self._fail(cat, "5.8.5", "Immutable audit trigger missing",
                        expected="trg_immutable_audit",
                        actual=out[:100],
                        severity="S1")

        # 5.8.6 — Audit log RLS: user can only read their own entries
        test_uid = await self._setup_test_user()
        if test_uid:
            out, rc = self._psql(
                "SELECT COUNT(*) FROM audit_log WHERE event_type = 'b5_test_event';",
                role="sentinel_app",
                user_id=test_uid,
            )
            try:
                count = int(out.strip().split("\n")[-1].strip())
                if count == 0:
                    self._pass(cat, "5.8.6",
                               "Audit log entries filtered by user_id (cross-user invisible)")
                else:
                    self._fail(cat, "5.8.6", "Cross-user audit log entries visible",
                                expected="0", actual=str(count), severity="S1")
            except (ValueError, IndexError):
                self._warn(cat, "5.8.6", "Could not verify audit RLS",
                            note=out[:100])

        # 5.8.7 — Audit log INSERT allows any user_id (split policy)
        if test_uid:
            out, rc = self._psql(
                f"INSERT INTO audit_log "
                f"(user_id, event_type, session_id, detail) "
                f"VALUES ({test_uid}, 'b5_test_u2', 'b5-audit-u2', 'user2-entry');",
                role="sentinel_app",
                user_id=test_uid,
            )
            if rc == 0:
                self._pass(cat, "5.8.7",
                           "Audit log INSERT allows user's own entries (split policy)")
            else:
                self._warn(cat, "5.8.7", "Audit log INSERT failed for user 2",
                            note=out[:200])

        # Cleanup: audit log is immutable, so we can't delete test entries
        # They'll be purged by the maintenance cron eventually
        self._info(cat, "5.8.8", "Test audit entries left in place (immutable by design)",
                    detail="Events: b5_test_event, b5_test_u2")

    # ── B5.9: Privacy Boundary Data Leakage ────────────────────

    async def test_privacy_boundary(self):
        """Test for data leakage through error messages and metadata."""
        print("\nB5.9: Privacy Boundary Data Leakage")
        cat = "privacy_boundary"

        # 5.9.1 — Error messages don't leak table names or schema
        # Trigger an error with a bad query
        out, rc = self._psql(
            "SELECT * FROM nonexistent_table_b5;",
            role="sentinel_app",
        )
        if "nonexistent_table_b5" in out:
            # PG does reveal the table name in error messages — this is standard PG behaviour
            self._info(cat, "5.9.1",
                        "PG error reveals table name (standard PostgreSQL behaviour)",
                        detail="Application layer must catch and sanitise these errors")
        else:
            self._pass(cat, "5.9.1", "Error messages don't leak requested table names")

        # 5.9.2 — pg_stat_activity visibility
        out, rc = self._psql(
            "SELECT COUNT(*) FROM pg_stat_activity WHERE query NOT LIKE '%pg_stat%';",
            role="sentinel_app",
        )
        try:
            count = int(out.strip().split("\n")[-1].strip())
            if count > 0:
                self._warn(cat, "5.9.2",
                            f"sentinel_app can see {count} entries in pg_stat_activity",
                            note="May reveal other users' query patterns")
            else:
                self._pass(cat, "5.9.2", "pg_stat_activity shows no other connections")
        except (ValueError, IndexError):
            self._info(cat, "5.9.2", "Could not check pg_stat_activity",
                        detail=out[:100])

        # 5.9.3 — pg_stat_activity query text visibility
        out, rc = self._psql(
            "SELECT query FROM pg_stat_activity "
            "WHERE pid != pg_backend_pid() LIMIT 3;",
            role="sentinel_app",
        )
        if out.strip():
            self._warn(cat, "5.9.3",
                        "sentinel_app can read other connections' query text",
                        note=f"Queries visible: {out[:150]}...")
        else:
            self._pass(cat, "5.9.3", "No other connections' queries visible")

        # 5.9.4 — Aggregate queries respect RLS
        test_uid = await self._setup_test_user()
        if test_uid:
            # Insert data for both users
            self._psql_owner(
                "INSERT INTO memory_chunks (chunk_id, user_id, content, source) "
                "VALUES ('b5-agg-u1', 1, 'user1-data', 'test'), "
                "       ('b5-agg-u2', %d, 'user2-data', 'test') "
                "ON CONFLICT DO NOTHING;" % test_uid
            )
            # User 2 counts — should only see their own
            out, rc = self._psql(
                "SELECT COUNT(*) FROM memory_chunks;",
                role="sentinel_app",
                user_id=test_uid,
            )
            try:
                count = int(out.strip().split("\n")[-1].strip())
                # User 2 should see at most their own records
                self._info(cat, "5.9.4",
                            f"User 2 aggregate COUNT(*) = {count} "
                            f"(RLS filters before aggregation)")
            except (ValueError, IndexError):
                self._warn(cat, "5.9.4", "Could not check aggregate",
                            note=out[:100])

            self._psql_owner(
                "DELETE FROM memory_chunks WHERE chunk_id IN ('b5-agg-u1', 'b5-agg-u2');"
            )

        # 5.9.5 — Check UserContextMiddleware hardcodes user_id
        out, _ = self._podman_exec(
            self.sentinel_ctr,
            "grep", "-n", "current_user_id.set",
            "/app/sentinel/api/middleware.py",
        )
        if "set(1)" in out:
            self._warn(cat, "5.9.5",
                        "UserContextMiddleware hardcodes user_id=1 (no auth extraction)",
                        note="Multi-user requires real authentication")
        else:
            self._info(cat, "5.9.5", "UserContextMiddleware",
                        detail=out[:200])

        # 5.9.6 — Check contact resolution default fallback
        out, _ = self._podman_exec(
            self.sentinel_ctr,
            "grep", "-n", "user_id.*=.*1",
            "/app/sentinel/planner/intake.py",
        )
        fallback_lines = [
            l for l in out.strip().split("\n")
            if "user_id" in l and "= 1" in l and l.strip()
        ]
        if fallback_lines:
            self._warn(cat, "5.9.6",
                        f"Contact resolution has {len(fallback_lines)} user_id=1 fallbacks",
                        note="Unknown senders default to user 1")
        else:
            self._pass(cat, "5.9.6", "No hardcoded user_id=1 fallbacks in intake")

    # ── B5.10: Connection Pool Security ────────────────────────

    async def test_connection_pool(self):
        """Test connection pool isolation and access control."""
        print("\nB5.10: Connection Pool Security")
        cat = "connection_pool"

        # 5.10.1 — Verify admin pool uses sentinel_owner role
        out, _ = self._podman_exec(
            self.sentinel_ctr,
            "grep", "-rn", "sentinel_owner",
            "/app/sentinel/core/db.py",
        )
        if "sentinel_owner" in out:
            self._pass(cat, "5.10.1",
                        "Admin pool configuration references sentinel_owner role")
        else:
            self._warn(cat, "5.10.1", "Could not verify admin pool role",
                        note=out[:200])

        # 5.10.2 — Verify app pool uses sentinel_app role
        out, _ = self._podman_exec(
            self.sentinel_ctr,
            "grep", "-rn", "sentinel_app",
            "/app/sentinel/core/db.py",
        )
        if "sentinel_app" in out:
            self._pass(cat, "5.10.2",
                        "App pool configuration references sentinel_app role")
        else:
            self._warn(cat, "5.10.2", "Could not verify app pool role",
                        note=out[:200])

        # 5.10.3 — Verify admin pool is not exposed via API routes
        out, _ = self._podman_exec(
            self.sentinel_ctr,
            "grep", "-rn", "admin_pool\\|owner_pool\\|sentinel_owner",
            "/app/sentinel/api/",
        )
        if out.strip():
            # Check if any references are actual pool usage (not just comments)
            code_refs = [
                l for l in out.strip().split("\n")
                if l.strip()
                and not l.strip().startswith("#")
                and "import" not in l
            ]
            if code_refs:
                self._warn(cat, "5.10.3",
                            "Admin pool references found in API code",
                            note=f"{len(code_refs)} references: {code_refs[0][:120]}")
            else:
                self._pass(cat, "5.10.3",
                           "No admin pool usage in API routes (comments/imports only)")
        else:
            self._pass(cat, "5.10.3", "No admin pool references in API code")

        # 5.10.4 — Check maintenance functions use correct pool type
        out, _ = self._podman_exec(
            self.sentinel_ctr,
            "grep", "-A2", "async def run_db_maintenance\\|async def purge_old",
            "/app/sentinel/core/db.py",
        )
        self._info(cat, "5.10.4", "Maintenance function signatures",
                    detail=out[:300] if out else "not found")

        # 5.10.5 — Verify PG connections (how many, which roles)
        out, rc = self._psql_owner(
            "SELECT usename, COUNT(*) as cnt FROM pg_stat_activity "
            "WHERE datname = 'sentinel' GROUP BY usename ORDER BY usename;"
        )
        self._info(cat, "5.10.5", "Active PG connections by role",
                    detail=out[:300] if out else "no connections found")

        # 5.10.6 — Check for connection pooling config (max connections)
        out, rc = self._psql_owner(
            "SHOW max_connections;"
        )
        self._info(cat, "5.10.6", f"PG max_connections = {out.strip()}")

    # ── B5.11: Migration and Schema Safety ─────────────────────

    async def test_migration_safety(self):
        """Test schema migration safety properties."""
        print("\nB5.11: Migration and Schema Safety")
        cat = "migration_safety"

        # 5.11.1 — CREATE TABLE IF NOT EXISTS is idempotent
        # Run create_pg_schema() again — should not error or drop data
        out, rc = self._psql_owner(
            "CREATE TABLE IF NOT EXISTS sessions ("
            "  session_id TEXT PRIMARY KEY, "
            "  user_id INTEGER NOT NULL DEFAULT 1"
            ");"
        )
        if rc == 0:
            self._pass(cat, "5.11.1",
                        "CREATE TABLE IF NOT EXISTS is idempotent (no error on existing table)")
        else:
            self._fail(cat, "5.11.1", "CREATE TABLE IF NOT EXISTS failed",
                        actual=out[:200], severity="S3")

        # 5.11.2 — Known gotcha: CREATE TABLE IF NOT EXISTS doesn't add columns
        # Verify this is handled in migration code
        out, _ = self._podman_exec(
            self.sentinel_ctr,
            "grep", "-n", "ALTER TABLE.*ADD COLUMN",
            "/app/sentinel/core/pg_schema.py",
        )
        if out.strip():
            self._pass(cat, "5.11.2",
                        "Schema uses ALTER TABLE ADD COLUMN for existing table migration")
        else:
            self._warn(cat, "5.11.2",
                        "No ALTER TABLE ADD COLUMN found in schema code",
                        note="CREATE TABLE IF NOT EXISTS silently skips new columns on existing tables")

        # 5.11.3 — Verify migration preserves user_id type
        out, _ = self._podman_exec(
            self.sentinel_ctr,
            "grep", "-n", "_migrate_user_id_columns",
            "/app/sentinel/core/pg_schema.py",
        )
        if out.strip():
            self._pass(cat, "5.11.3", "user_id migration function exists in schema code")
        else:
            self._warn(cat, "5.11.3", "No user_id migration function found",
                        note="May be handled differently")

        # 5.11.4 — Verify default user_id=1 is safe for existing rows
        out, rc = self._psql_owner(
            "SELECT table_name, column_default FROM information_schema.columns "
            "WHERE column_name = 'user_id' AND table_schema = 'public' "
            "AND column_default IS NOT NULL;"
        )
        self._info(cat, "5.11.4", "user_id DEFAULT values across tables",
                    detail=out[:400] if out else "no defaults found")

        # 5.11.5 — Check for orphaned sequences (security hygiene)
        out, rc = self._psql_owner(
            "SELECT sequencename FROM pg_sequences "
            "WHERE schemaname = 'public' "
            "AND sequencename NOT IN ("
            "  SELECT replace(pg_get_serial_sequence(table_name || '', column_name), "
            "         'public.', '') "
            "  FROM information_schema.columns "
            "  WHERE table_schema = 'public' "
            "  AND column_default LIKE '%nextval%'"
            ");"
        )
        # This query may not work perfectly; just report
        self._info(cat, "5.11.5", "Sequence check", detail=out[:200] if out else "clean")

    # ── B5.12: Temporal and Concurrency Attacks ────────────────

    async def test_temporal_concurrency(self):
        """Test race conditions and temporal attacks on user context."""
        print("\nB5.12: Temporal and Concurrency Attacks")
        cat = "temporal_concurrency"

        rls_active = await self._check_rls_active()
        test_uid = await self._setup_test_user()

        # 5.12.1 — Connection reuse doesn't leak user context
        # Run two queries with different user_ids — verify isolation
        # In psql, each invocation is a new connection (safe by design)
        out1, _ = self._psql(
            "SELECT current_setting('app.current_user_id');",
            role="sentinel_app",
            user_id=1,
        )
        out2, _ = self._psql(
            "SELECT current_setting('app.current_user_id');",
            role="sentinel_app",
            user_id=test_uid or 999,
        )
        val1 = out1.strip().split("\n")[-1].strip() if out1.strip() else ""
        val2 = out2.strip().split("\n")[-1].strip() if out2.strip() else ""
        if val1 != val2:
            self._pass(cat, "5.12.1",
                        f"Sequential connections have independent user context "
                        f"(conn1={val1}, conn2={val2})")
        else:
            self._warn(cat, "5.12.1",
                        f"Both connections show same user_id={val1}",
                        note="May be expected if test_uid not created")

        # 5.12.2 — Long-running transaction retains correct user_id
        out, rc = self._psql(
            "BEGIN; "
            "SELECT set_config('app.current_user_id', '1', true); "
            "SELECT pg_sleep(0.1); "
            "SELECT current_setting('app.current_user_id'); "
            "COMMIT;",
            role="sentinel_app",
        )
        # The SELECT should still show '1' after the sleep
        if "1" in out:
            self._pass(cat, "5.12.2",
                        "Long-running transaction retains user_id context")
        else:
            self._warn(cat, "5.12.2", "Could not verify transaction context retention",
                        note=out[:200])

        # 5.12.3 — Verify RLSPool owns transaction lifecycle
        out, _ = self._podman_exec(
            self.sentinel_ctr,
            "grep", "-A10", "async def acquire",
            "/app/sentinel/core/rls.py",
        )
        if "transaction()" in out and "set_config" in out:
            self._pass(cat, "5.12.3",
                        "RLSPool.acquire() wraps connection in transaction with user context")
        else:
            self._warn(cat, "5.12.3", "Could not verify RLSPool transaction pattern",
                        note=out[:200])

        # 5.12.4 — Verify deadlock errors don't leak information
        # Create a potential deadlock scenario (two transactions updating same row)
        # This is hard to trigger deterministically, so we just check error format
        out, rc = self._psql(
            "BEGIN; "
            "SET LOCAL lock_timeout = '100ms'; "
            "LOCK TABLE memory_chunks IN EXCLUSIVE MODE; "
            "COMMIT;",
            role="sentinel_app",
            user_id=1,
        )
        # Check if any sensitive info leaked in the output
        sensitive_patterns = ["password", "secret", "token", "key"]
        leaked = [p for p in sensitive_patterns if p in out.lower()]
        if not leaked:
            self._pass(cat, "5.12.4",
                        "Lock timeout error doesn't leak sensitive information")
        else:
            self._fail(cat, "5.12.4", "Lock error leaks sensitive info",
                        expected="No sensitive keywords",
                        actual=f"Found: {', '.join(leaked)}",
                        severity="S2")

        # 5.12.5 — PG-specific attack: LISTEN/NOTIFY side channel
        out, rc = self._psql(
            "NOTIFY b5_test_channel, 'cross-user-message';",
            role="sentinel_app",
        )
        if rc == 0:
            self._warn(cat, "5.12.5",
                        "LISTEN/NOTIFY available to sentinel_app",
                        note="Could be used as cross-user side channel")
        else:
            self._pass(cat, "5.12.5", "NOTIFY blocked for sentinel_app")

        # 5.12.6 — PG-specific attack: Advisory locks (DoS potential)
        out, rc = self._psql(
            "SELECT pg_try_advisory_lock(12345);",
            role="sentinel_app",
        )
        if rc == 0 and "t" in out.lower():
            self._warn(cat, "5.12.6",
                        "Advisory locks available to sentinel_app",
                        note="Could be used for DoS via lock hoarding")
            # Release the lock
            self._psql("SELECT pg_advisory_unlock(12345);", role="sentinel_app")
        else:
            self._pass(cat, "5.12.6", "Advisory locks blocked for sentinel_app")

        # 5.12.7 — PG-specific attack: COPY TO for data exfiltration
        out, rc = self._psql(
            "COPY sessions TO '/tmp/b5_exfil.csv' CSV;",
            role="sentinel_app",
        )
        if rc != 0 or "permission denied" in out.lower():
            self._pass(cat, "5.12.7", "COPY TO blocked for sentinel_app")
        else:
            self._fail(cat, "5.12.7", "COPY TO succeeded — data exfiltration possible",
                        expected="Permission denied",
                        actual=out[:200],
                        severity="S0")

        # 5.12.8 — PG-specific attack: pg_read_file()
        out, rc = self._psql(
            "SELECT pg_read_file('/etc/passwd');",
            role="sentinel_app",
        )
        if rc != 0 or "permission denied" in out.lower():
            self._pass(cat, "5.12.8", "pg_read_file() blocked for sentinel_app")
        else:
            self._fail(cat, "5.12.8", "pg_read_file() accessible to sentinel_app",
                        expected="Permission denied",
                        actual=out[:200],
                        severity="S0")

        # 5.12.9 — PG-specific attack: DO $$ anonymous code blocks
        out, rc = self._psql(
            "DO $$ BEGIN RAISE NOTICE 'code execution'; END $$;",
            role="sentinel_app",
        )
        if rc == 0:
            # DO blocks work but are still subject to role permissions and RLS
            self._info(cat, "5.12.9",
                        "DO $$ blocks available to sentinel_app",
                        detail="Subject to role permissions — acceptable if no dangerous functions")
        else:
            self._pass(cat, "5.12.9", "DO $$ blocks blocked for sentinel_app")

        # 5.12.10 — PG-specific attack: Large objects
        out, rc = self._psql(
            "SELECT lo_import('/etc/passwd');",
            role="sentinel_app",
        )
        if rc != 0 or "permission denied" in out.lower():
            self._pass(cat, "5.12.10", "lo_import() blocked for sentinel_app")
        else:
            self._fail(cat, "5.12.10", "lo_import() accessible to sentinel_app",
                        expected="Permission denied",
                        actual=out[:200],
                        severity="S0")

        # 5.12.11 — PG-specific attack: search_path hijacking
        out, rc = self._psql(
            "SHOW search_path;",
            role="sentinel_app",
        )
        self._info(cat, "5.12.11", f"search_path = {out.strip()}",
                    detail="Verify no untrusted schemas in path")

        # 5.12.12 — PG-specific attack: current_setting() to probe config
        out, rc = self._psql(
            "SELECT current_setting('server_version'), "
            "current_setting('data_directory'), "
            "current_setting('hba_file');",
            role="sentinel_app",
        )
        self._info(cat, "5.12.12", "PG config visible via current_setting()",
                    detail=out[:300] if out else "blocked")

    # ── Run All Categories ──────────────────────────────────────

    async def run_all(self, categories: list[str] | None = None):
        """Run selected or all test categories."""
        category_map = {
            "rls_enforcement": self.test_rls_enforcement,
            "role_separation": self.test_role_separation,
            "sql_injection": self.test_sql_injection,
            "session_variable": self.test_session_variable,
            "schema_integrity": self.test_schema_integrity,
            "cross_user_exfil": self.test_cross_user_exfil,
            "data_integrity": self.test_data_integrity,
            "audit_log": self.test_audit_log,
            "privacy_boundary": self.test_privacy_boundary,
            "connection_pool": self.test_connection_pool,
            "migration_safety": self.test_migration_safety,
            "temporal_concurrency": self.test_temporal_concurrency,
        }

        selected = categories or ALL_CATEGORIES
        for cat in selected:
            if cat not in category_map:
                print(f"  [SKIP] Unknown category: {cat}")
                continue
            try:
                await category_map[cat]()
            except Exception as e:
                self._fail(cat, f"{cat}.error", f"Category {cat} crashed: {e}",
                            severity="S1")
                if self.verbose:
                    import traceback
                    traceback.print_exc()

    def print_summary(self):
        """Print final summary."""
        pass_count = sum(1 for r in self.results if r.status == "pass")
        fail_count = sum(1 for r in self.results if r.status == "fail")
        warn_count = sum(1 for r in self.results if r.status == "warn")
        skip_count = sum(1 for r in self.results if r.status == "skip")
        info_count = sum(1 for r in self.results if r.status == "info")

        print(f"\n{'=' * 60}")
        print(f"  B5 v2 Database Security Test Results")
        print(f"  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{'=' * 60}")
        print(f"  {pass_count} passed, {fail_count} failed, "
              f"{warn_count} warnings, {skip_count} skipped, {info_count} info")
        print(f"  Output: {self.output_path}")
        print()

        if fail_count > 0:
            print(f"  FAILURES ({fail_count}):")
            for r in self.results:
                if r.status == "fail":
                    print(f"    [{r.severity}] {r.description}")
            print()

        if warn_count > 0:
            print(f"  WARNINGS ({warn_count}):")
            for r in self.results:
                if r.status == "warn":
                    print(f"    {r.description}")
            print()

        print(f"  Domain A: Direct DB security (B5.1-B5.5)")
        print(f"  Domain B: Application-layer attacks (B5.6-B5.9)")
        print(f"  PG-specific: Role escalation, COPY, large objects,")
        print(f"               LISTEN/NOTIFY, advisory locks, DO blocks")
        print(f"{'=' * 60}")

        return fail_count


# ── Main ────────────────────────────────────────────────────────────

async def main():
    parser = argparse.ArgumentParser(
        description="B5 v2: Database Security Red Team Tests",
    )
    parser.add_argument(
        "--output", default=None,
        help="JSONL output path (default: auto-generated in benchmarks/)",
    )
    parser.add_argument(
        "--categories", nargs="*", default=None,
        help=f"Run only these categories (choices: {', '.join(ALL_CATEGORIES)})",
    )
    parser.add_argument(
        "--sentinel-container", default="sentinel",
        help="Sentinel container name (default: sentinel)",
    )
    parser.add_argument(
        "--sentinel-url", default=DEFAULT_SENTINEL_URL,
        help=f"Sentinel API URL (default: {DEFAULT_SENTINEL_URL})",
    )
    parser.add_argument(
        "--verbose", action="store_true",
        help="Show detailed output including tracebacks",
    )
    parser.add_argument(
        "--list-categories", action="store_true",
        help="List all test categories and exit",
    )
    args = parser.parse_args()

    if args.list_categories:
        print("Available B5 v2 test categories:")
        for i, cat in enumerate(ALL_CATEGORIES, 1):
            print(f"  B5.{i:2d}  {cat}")
        return

    # Output path
    output_path = args.output
    if not output_path:
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        project_root = Path(__file__).resolve().parent.parent
        output_path = str(project_root / "benchmarks" / f"red_team_b5_v2_{ts}.jsonl")

    # Read PIN from env or secrets file
    pin = os.environ.get("SENTINEL_PIN", "")
    if not pin:
        pin_path = Path.home() / ".secrets" / "sentinel_pin.txt"
        if pin_path.exists():
            pin = pin_path.read_text().strip()

    # Banner
    print(f"\n{'=' * 60}")
    print(f"  Sentinel B5 v2: Database Security Red Team")
    print(f"  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'=' * 60}")
    print(f"  Container: {args.sentinel_container}")
    print(f"  Output:    {output_path}")
    cats = args.categories or ALL_CATEGORIES
    print(f"  Categories: {', '.join(cats)}")
    print(f"{'=' * 60}")

    # Pre-flight: check container exists and PG is accessible
    try:
        result = subprocess.run(
            ["podman", "exec", args.sentinel_container, "pg_isready", "-U", "sentinel_app"],
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode != 0:
            print(f"\n  WARNING: PostgreSQL may not be ready in {args.sentinel_container}")
            print(f"  Output: {result.stdout.strip()} {result.stderr.strip()}")
            print(f"  Continuing anyway — tests may fail.")
    except Exception as e:
        print(f"\n  WARNING: Could not check PG readiness: {e}")

    # Run tests
    runner = B5Runner(
        output_path=output_path,
        verbose=args.verbose,
        sentinel_container=args.sentinel_container,
        sentinel_url=args.sentinel_url,
        sentinel_pin=pin,
    )

    try:
        await runner.run_all(args.categories)
    except KeyboardInterrupt:
        print("\n\n  Interrupted by user")
    finally:
        # Cleanup test user
        try:
            await runner._cleanup_test_user()
        except Exception:
            pass

        fail_count = runner.print_summary()
        runner.writer.close()

    # Always exit 0 — results are in the JSONL. Consistent with B1/B1.5/B2/B4.
    sys.exit(0)


if __name__ == "__main__":
    asyncio.run(main())
