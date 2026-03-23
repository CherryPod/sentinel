"""Tests for audit_log immutability guarantees in pg_schema.py.

Validates that the SQL definitions in _TRIGGERS, _ROLE_SETUP, and _RLS_POLICIES
enforce append-only semantics on the audit_log table. No live PG connection
needed — these tests inspect the SQL strings directly.
"""

import pytest

from sentinel.core.pg_schema import _TRIGGERS, _ROLE_SETUP, _RLS_POLICIES


# ── Trigger deployment ──────────────────────────────────────────────


class TestAuditTriggerDeployment:
    """Verify the immutable-audit trigger is deployed robustly."""

    def test_trigger_function_defined(self):
        """The prevent_audit_modification() function must exist in _TRIGGERS."""
        combined = " ".join(_TRIGGERS)
        assert "prevent_audit_modification" in combined
        assert "RAISE EXCEPTION" in combined

    def test_trigger_uses_drop_create_pattern(self):
        """Trigger must use DROP IF EXISTS + CREATE (not DO$$/IF NOT EXISTS).

        The DO$$ wrapper can swallow errors silently, leaving the trigger
        undeployed. DROP + CREATE is idempotent and fails loudly.
        """
        trigger_sql = " ".join(_TRIGGERS)

        # Must have the DROP IF EXISTS statement
        assert "DROP TRIGGER IF EXISTS trg_immutable_audit ON audit_log" in trigger_sql

        # Must have the CREATE TRIGGER (outside a DO$$ block)
        assert "CREATE TRIGGER trg_immutable_audit" in trigger_sql

        # Must NOT wrap the trigger creation in a DO$$ block
        # (the function definition uses DO$$ legitimately via plpgsql,
        #  so we check that no DO$$ appears AFTER the function definition)
        func_end_idx = trigger_sql.index("LANGUAGE plpgsql")
        remaining = trigger_sql[func_end_idx:]
        assert "DO $$" not in remaining, (
            "Trigger creation should not be wrapped in DO$$ block"
        )

    def test_trigger_covers_update_and_delete(self):
        """Trigger must fire on both UPDATE and DELETE."""
        combined = " ".join(_TRIGGERS)
        assert "BEFORE UPDATE OR DELETE ON audit_log" in combined

    def test_trigger_exempts_sentinel_owner(self):
        """sentinel_owner must be exempted for maintenance (purge_old_audit_log)."""
        combined = " ".join(_TRIGGERS)
        assert "current_user = 'sentinel_owner'" in combined
        assert "RETURN OLD" in combined


# ── REVOKE from sentinel_owner ──────────────────────────────────────


class TestAuditOwnerRevoke:
    """Verify sentinel_app cannot UPDATE or DELETE audit_log rows.

    sentinel_owner retains DELETE for maintenance (purge_old_audit_log).
    The trg_immutable_audit trigger blocks sentinel_app at trigger level.
    """

    def test_revoke_from_sentinel_app(self):
        """REVOKE UPDATE, DELETE must target sentinel_app."""
        combined = " ".join(_ROLE_SETUP)
        assert "REVOKE UPDATE, DELETE ON audit_log FROM sentinel_app" in combined

    def test_no_revoke_from_sentinel_owner(self):
        """sentinel_owner must NOT be revoked — needs DELETE for maintenance."""
        combined = " ".join(_ROLE_SETUP)
        assert "REVOKE UPDATE, DELETE ON audit_log FROM sentinel_owner" not in combined

    def test_revoke_order_after_grants(self):
        """REVOKEs must come AFTER the bulk GRANT ALL TABLES statement.

        Otherwise the GRANT re-grants what was revoked.
        """
        combined = " ".join(_ROLE_SETUP)
        grant_pos = combined.index(
            "GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES"
        )
        revoke_app_pos = combined.index(
            "REVOKE UPDATE, DELETE ON audit_log FROM sentinel_app"
        )
        assert revoke_app_pos > grant_pos, "sentinel_app REVOKE must follow GRANT"


# ── RLS policies ────────────────────────────────────────────────────


class TestAuditOwnerPolicies:
    """Verify owner policies are SELECT + INSERT only (no full access)."""

    def test_no_owner_full_access_policy_on_audit_log(self):
        """The old owner_full_access policy on audit_log must be dropped.

        A blanket USING(TRUE) + WITH CHECK(TRUE) policy on sentinel_owner
        would allow UPDATE/DELETE through RLS even if REVOKE is in place
        (REVOKE blocks at privilege level, but the policy shouldn't exist).
        Note: owner_full_access is legitimate on OTHER tables — only
        audit_log must not have it.
        """
        combined = " ".join(_RLS_POLICIES)
        # The DROP statement must exist
        assert "DROP POLICY IF EXISTS owner_full_access ON audit_log" in combined
        # No CREATE POLICY owner_full_access ON audit_log should exist
        assert "CREATE POLICY owner_full_access ON audit_log" not in combined

    def test_owner_read_access_policy_exists(self):
        """owner_read_access policy: SELECT-only for sentinel_owner."""
        combined = " ".join(_RLS_POLICIES)
        assert "owner_read_access" in combined
        # Find the policy creation and verify it's FOR SELECT
        idx = combined.index("CREATE POLICY owner_read_access")
        # Extract a chunk after the policy name to check FOR SELECT
        snippet = combined[idx : idx + 200]
        assert "FOR SELECT" in snippet
        assert "TO sentinel_owner" in snippet

    def test_owner_insert_access_policy_exists(self):
        """owner_insert_access policy: INSERT-only for sentinel_owner."""
        combined = " ".join(_RLS_POLICIES)
        assert "owner_insert_access" in combined
        idx = combined.index("CREATE POLICY owner_insert_access")
        snippet = combined[idx : idx + 200]
        assert "FOR INSERT" in snippet
        assert "TO sentinel_owner" in snippet

    def test_owner_policies_no_update_or_delete(self):
        """No owner policy on audit_log should permit UPDATE or DELETE."""
        combined = " ".join(_RLS_POLICIES)
        # Find all audit_log policy sections
        # There should be no FOR UPDATE or FOR DELETE policy for sentinel_owner
        # on audit_log (other than the trigger-level block)
        for keyword in ("FOR UPDATE", "FOR DELETE"):
            # Check if any policy creation for audit_log uses these
            search_start = 0
            while True:
                try:
                    idx = combined.index(
                        "CREATE POLICY", search_start
                    )
                except ValueError:
                    break
                snippet = combined[idx : idx + 300]
                if "audit_log" in snippet and "sentinel_owner" in snippet:
                    assert keyword not in snippet, (
                        f"Owner policy on audit_log must not use {keyword}"
                    )
                search_start = idx + 1


# ── Admin-read-only (Task 2) ──────────────────────────────────────


class TestAuditAdminReadOnly:
    """Verify audit_log is admin-read-only: sentinel_app can INSERT but not SELECT."""

    def test_user_isolation_select_dropped(self):
        """The user_isolation_select policy must be explicitly dropped."""
        combined = " ".join(_RLS_POLICIES)
        assert "DROP POLICY IF EXISTS user_isolation_select ON audit_log" in combined
        # Must not be re-created
        assert "CREATE POLICY user_isolation_select ON audit_log" not in combined

    def test_user_isolation_insert_dropped(self):
        """The user_isolation_insert policy must be explicitly dropped."""
        combined = " ".join(_RLS_POLICIES)
        assert "DROP POLICY IF EXISTS user_isolation_insert ON audit_log" in combined
        # Must not be re-created
        assert "CREATE POLICY user_isolation_insert ON audit_log" not in combined

    def test_app_insert_only_policy_exists(self):
        """app_insert_only policy: INSERT-only for sentinel_app on audit_log."""
        combined = " ".join(_RLS_POLICIES)
        assert "app_insert_only" in combined
        idx = combined.index("CREATE POLICY app_insert_only")
        snippet = combined[idx : idx + 200]
        assert "FOR INSERT" in snippet
        assert "TO sentinel_app" in snippet
        assert "WITH CHECK (TRUE)" in snippet

    def test_no_select_policy_for_sentinel_app(self):
        """No RLS policy on audit_log should grant SELECT to sentinel_app."""
        combined = " ".join(_RLS_POLICIES)
        search_start = 0
        while True:
            try:
                idx = combined.index("CREATE POLICY", search_start)
            except ValueError:
                break
            snippet = combined[idx : idx + 300]
            if "audit_log" in snippet and "sentinel_app" in snippet:
                assert "FOR SELECT" not in snippet, (
                    "sentinel_app must not have a SELECT policy on audit_log"
                )
            search_start = idx + 1

    def test_select_revoked_from_sentinel_app(self):
        """REVOKE SELECT ON audit_log FROM sentinel_app must be in _ROLE_SETUP."""
        combined = " ".join(_ROLE_SETUP)
        assert "REVOKE SELECT ON audit_log FROM sentinel_app" in combined

    def test_select_revoke_after_grants(self):
        """SELECT REVOKE must come after the bulk GRANT statement."""
        combined = " ".join(_ROLE_SETUP)
        grant_pos = combined.index(
            "GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES"
        )
        revoke_pos = combined.index(
            "REVOKE SELECT ON audit_log FROM sentinel_app"
        )
        assert revoke_pos > grant_pos, "SELECT REVOKE must follow bulk GRANT"


# ── GRANT OPTION revocation (B5-5.2.4) ────────────────────────────


class TestGrantOptionRevocation:
    """Verify sentinel_app cannot delegate its privileges to other roles.

    B5-5.2.4: Without GRANT OPTION revocation, a compromised sentinel_app
    could GRANT its own table/sequence privileges to arbitrary roles,
    undermining the role separation that audit immutability depends on.
    """

    def test_revoke_grant_option_tables(self):
        """REVOKE GRANT OPTION FOR ... ON ALL TABLES must target sentinel_app."""
        combined = " ".join(_ROLE_SETUP)
        assert (
            "REVOKE GRANT OPTION FOR SELECT, INSERT, UPDATE, DELETE "
            "ON ALL TABLES IN SCHEMA public FROM sentinel_app"
        ) in combined

    def test_revoke_grant_option_sequences(self):
        """REVOKE GRANT OPTION FOR ... ON ALL SEQUENCES must target sentinel_app."""
        combined = " ".join(_ROLE_SETUP)
        assert (
            "REVOKE GRANT OPTION FOR USAGE, SELECT "
            "ON ALL SEQUENCES IN SCHEMA public FROM sentinel_app"
        ) in combined

    def test_grant_option_revoke_after_grants(self):
        """GRANT OPTION revocations must come after the bulk GRANT statements.

        Otherwise the GRANT re-establishes WITH GRANT OPTION implicitly.
        """
        combined = " ".join(_ROLE_SETUP)
        grant_pos = combined.index(
            "GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES"
        )
        revoke_pos = combined.index(
            "REVOKE GRANT OPTION FOR SELECT, INSERT, UPDATE, DELETE"
        )
        assert revoke_pos > grant_pos, (
            "GRANT OPTION revoke must follow bulk GRANT"
        )

    def test_grant_option_revoke_before_default_privileges(self):
        """GRANT OPTION revocations must come before ALTER DEFAULT PRIVILEGES.

        The default privileges apply to future tables — if GRANT OPTION is
        revoked after DEFAULT PRIVILEGES, future tables would still allow
        delegation until the next schema migration.
        """
        combined = " ".join(_ROLE_SETUP)
        revoke_pos = combined.index(
            "REVOKE GRANT OPTION FOR SELECT, INSERT, UPDATE, DELETE"
        )
        default_pos = combined.index(
            "ALTER DEFAULT PRIVILEGES FOR ROLE sentinel_owner"
        )
        assert revoke_pos < default_pos, (
            "GRANT OPTION revoke must precede ALTER DEFAULT PRIVILEGES"
        )


# ── Audit log INSERT user isolation (B5-5.1.2) ────────────────────


class TestAuditInsertUserIsolation:
    """Verify audit_log INSERT policy enforces user_id matching.

    B5-5.1.2: sentinel_app can only INSERT audit entries where the user_id
    matches the session's app.current_user_id. Prevents a compromised worker
    from polluting another user's audit trail.
    """

    def test_app_insert_user_isolation_policy_exists(self):
        """app_insert_user_isolation policy must exist on audit_log."""
        combined = " ".join(_RLS_POLICIES)
        assert "app_insert_user_isolation" in combined

    def test_app_insert_user_isolation_is_insert_only(self):
        """app_insert_user_isolation policy must be FOR INSERT only."""
        combined = " ".join(_RLS_POLICIES)
        idx = combined.index("CREATE POLICY app_insert_user_isolation")
        snippet = combined[idx : idx + 300]
        assert "FOR INSERT" in snippet
        assert "TO sentinel_app" in snippet

    def test_app_insert_user_isolation_checks_user_id(self):
        """app_insert_user_isolation must check user_id against session var."""
        combined = " ".join(_RLS_POLICIES)
        idx = combined.index("CREATE POLICY app_insert_user_isolation")
        snippet = combined[idx : idx + 300]
        assert "current_setting('app.current_user_id'" in snippet
        assert "WITH CHECK" in snippet
        assert "user_id" in snippet

    def test_app_insert_user_isolation_uses_drop_create_pattern(self):
        """Policy must use DROP IF EXISTS + CREATE (idempotent deployment)."""
        combined = " ".join(_RLS_POLICIES)
        assert "DROP POLICY IF EXISTS app_insert_user_isolation ON audit_log" in combined
        assert "CREATE POLICY app_insert_user_isolation ON audit_log" in combined

    def test_app_insert_only_still_exists(self):
        """The existing app_insert_only policy must be preserved.

        app_insert_only (WITH CHECK TRUE) controls operation type.
        app_insert_user_isolation controls user_id matching.
        Both policies must pass for an INSERT to succeed (AND composition).
        """
        combined = " ".join(_RLS_POLICIES)
        assert "CREATE POLICY app_insert_only" in combined
        assert "CREATE POLICY app_insert_user_isolation" in combined

    def test_app_insert_user_isolation_missing_ok_true(self):
        """current_setting must use missing_ok=true for fail-closed behavior.

        When app.current_user_id is not set, current_setting returns NULL
        (instead of erroring), and NULL != any integer, so the INSERT is
        denied. This is the correct fail-closed default.
        """
        combined = " ".join(_RLS_POLICIES)
        idx = combined.index("CREATE POLICY app_insert_user_isolation")
        snippet = combined[idx : idx + 300]
        assert "current_setting('app.current_user_id', true)" in snippet


# ── B5 dependency chain (full integration — needs live PG) ─────────


@pytest.mark.integration
class TestB5DependencyChainIntegration:
    """Integration tests for the B5 hardening dependency chain.

    These tests require a live PostgreSQL instance with sentinel_owner and
    sentinel_app roles configured. They verify that the SQL definitions in
    pg_schema.py actually produce the expected runtime behavior.

    Run with: pytest -m integration tests/test_audit_immutability.py
    """

    def test_sentinel_app_cannot_grant(self):
        """sentinel_app must not be able to GRANT its privileges to others.

        B5-5.2.4: If sentinel_app can delegate, a compromised worker could
        create a new role with full audit_log access, bypassing immutability.
        Requires live PG connection as sentinel_app role.
        """
        # This test would connect as sentinel_app and attempt:
        #   GRANT SELECT ON audit_log TO some_test_role;
        # Expected: InsufficientPrivilegeError
        pytest.skip("Requires live PG with sentinel_app role — run in container")

    def test_audit_log_insert_requires_matching_user_id(self):
        """sentinel_app can only INSERT audit entries for the session user_id.

        B5-5.1.2: With app.current_user_id set to 1, INSERTing a row with
        user_id=2 must be denied by the app_insert_user_isolation policy.
        Requires live PG connection as sentinel_app role.
        """
        # This test would connect as sentinel_app, then:
        #   SET LOCAL app.current_user_id = '1';
        #   INSERT INTO audit_log (user_id, event_type, details)
        #       VALUES (2, 'test', '{}');
        # Expected: RLS policy violation
        pytest.skip("Requires live PG with sentinel_app role — run in container")

    def test_b5_full_dependency_chain(self):
        """End-to-end: sentinel_app cannot reach audit deletion.

        The full chain: REVOKE DELETE (privilege layer) + trigger (function
        layer) + RLS (row layer) + GRANT OPTION revoke (delegation layer).
        All four must hold for audit immutability to be sound.
        """
        # This test would:
        # 1. Connect as sentinel_app
        # 2. Attempt DELETE FROM audit_log → blocked by REVOKE
        # 3. Attempt GRANT DELETE ON audit_log TO ... → blocked by GRANT OPTION
        # 4. Verify INSERT with wrong user_id → blocked by RLS
        # 5. Verify INSERT with correct user_id → succeeds
        pytest.skip("Requires live PG with sentinel_app role — run in container")
