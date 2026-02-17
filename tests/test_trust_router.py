"""Tests for the trust router — operation classification."""

import pytest

from sentinel.planner.trust_router import SAFE_OPS, TrustTier, classify_operation


class TestTrustRouter:
    def test_health_check_is_safe(self):
        assert classify_operation("health_check") == TrustTier.SAFE

    def test_session_info_is_safe(self):
        assert classify_operation("session_info") == TrustTier.SAFE

    def test_unknown_op_is_dangerous(self):
        assert classify_operation("execute_shell") == TrustTier.DANGEROUS

    def test_empty_op_is_dangerous(self):
        assert classify_operation("") == TrustTier.DANGEROUS

    def test_file_write_is_dangerous(self):
        assert classify_operation("file_write") == TrustTier.DANGEROUS

    def test_shell_exec_is_dangerous(self):
        assert classify_operation("shell_exec") == TrustTier.DANGEROUS

    def test_safe_ops_is_frozenset(self):
        """SAFE_OPS must be immutable — prevent runtime tampering."""
        assert isinstance(SAFE_OPS, frozenset)

    def test_safe_ops_immutable(self):
        """Cannot add to SAFE_OPS at runtime."""
        with pytest.raises(AttributeError):
            SAFE_OPS.add("evil_op")

    def test_all_safe_ops_classify_correctly(self):
        """Every entry in SAFE_OPS should classify as SAFE."""
        for op in SAFE_OPS:
            assert classify_operation(op) == TrustTier.SAFE

    def test_trust_tier_values(self):
        assert TrustTier.SAFE.value == "safe"
        assert TrustTier.DANGEROUS.value == "dangerous"
