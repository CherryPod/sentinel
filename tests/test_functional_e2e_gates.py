"""Tests for the E2E functional test gate check logic.

Verifies that:
1. All 8 G3 scenarios pass the trust-level gate at TL4
2. The TL4 gate check retries on transient failures
"""

import importlib
import sys
import types
from pathlib import Path
from unittest.mock import patch

import pytest

# Import the test script as a module (it's not a package, so use importlib)
_SCRIPT_PATH = Path(__file__).resolve().parent.parent / "scripts" / "functional_test_e2e.py"


@pytest.fixture(scope="module")
def e2e_module():
    """Load functional_test_e2e.py as an importable module."""
    spec = importlib.util.spec_from_file_location("functional_test_e2e", _SCRIPT_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class TestG3TrustLevelGates:
    """Verify all G3 scenarios are allowed at TL4."""

    def test_all_scenarios_runnable_at_tl4(self, e2e_module):
        """Every G3 scenario should have trust_level_required <= 4,
        meaning none will be skipped when the system is running at TL4."""
        scenarios = e2e_module.E2E_SCENARIOS
        assert len(scenarios) == 8, f"Expected 8 scenarios, got {len(scenarios)}"

        for s in scenarios:
            sid = s["scenario_id"]
            tl_req = s["trust_level_required"]
            assert tl_req <= 4, (
                f"Scenario {sid} requires TL{tl_req} which exceeds TL4 — "
                f"it would be skipped at TL4"
            )

    def test_tl4_gate_retries_on_transient_failure(self, e2e_module):
        """The TL4 gate should retry and succeed if a transient failure
        is followed by a success, rather than failing permanently."""
        # First call returns error (transient), second returns success
        call_count = 0

        def mock_post_json(url, data, headers, timeout=120):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                # Transient failure
                return {"status": "error", "reason": "Request processing failed"}, 500
            else:
                # Success on retry
                return {
                    "status": "success",
                    "step_results": [
                        {"content": "hello\n", "step_id": "tool_call:shell_exec"}
                    ],
                }, 200

        with patch.object(e2e_module, "post_json", side_effect=mock_post_json), \
             patch.object(e2e_module.time, "sleep"):
            result = e2e_module.run_tl4_gate("https://localhost:3001", "test-pin")

        assert result is True, "Gate should pass after retry succeeds"
        assert call_count == 2, "Gate should have retried once after transient failure"
