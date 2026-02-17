"""Unit tests for the G7 Daily Smoke Test script.

Tests prompt definitions, verification logic, and stats tracking
WITHOUT requiring a running Sentinel stack. All tests operate on
the module's data structures and class methods directly.

Import uses importlib since the script lives in scripts/, not a package.
"""

import importlib.util
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

# ── Load the smoke script as a module ────────────────────────────
# The script is at scripts/functional_test_smoke.py in the project root.

_SCRIPT_PATH = (
    Path(__file__).resolve().parent.parent / "scripts" / "functional_test_smoke.py"
)
_spec = importlib.util.spec_from_file_location("functional_test_smoke", _SCRIPT_PATH)
smoke_mod = importlib.util.module_from_spec(_spec)
sys.modules["functional_test_smoke"] = smoke_mod
_spec.loader.exec_module(smoke_mod)

SMOKE_PROMPTS = smoke_mod.SMOKE_PROMPTS
DailySmokeTest = smoke_mod.DailySmokeTest


# ── Fixture: a DailySmokeTest instance (no network) ─────────────

@pytest.fixture
def runner():
    """Create a DailySmokeTest instance with dummy config.

    Uses MagicMock-free construction — just fake values for the
    constructor args that are never hit in unit-level tests.
    """
    return DailySmokeTest(
        base_url="https://localhost:9999",
        pin="0000",
        results_dir="/tmp/sentinel_test_smoke",
        version="unit-test",
        prompt_filter=None,
    )


# ═══════════════════════════════════════════════════════════════════
# 1. Prompt definition tests
# ═══════════════════════════════════════════════════════════════════

class TestPromptDefinitions:
    """Verify the SMOKE_PROMPTS list meets the G7 spec."""

    def test_exactly_five_prompts(self):
        """G7 spec requires exactly 5 smoke prompts."""
        assert len(SMOKE_PROMPTS) == 5

    def test_all_ids_prefixed_with_smoke(self):
        """Every prompt_id must start with 'smoke_'."""
        for p in SMOKE_PROMPTS:
            assert p["prompt_id"].startswith("smoke_"), (
                f"{p['prompt_id']} missing smoke_ prefix"
            )

    def test_covers_g1_through_g5(self):
        """Must have exactly one prompt from each of G1-G5."""
        suites = {p["source_suite"] for p in SMOKE_PROMPTS}
        assert suites == {"G1", "G2", "G3", "G4", "G5"}

    def test_no_g6_suite(self):
        """G6 (Security Tax) is excluded by design."""
        suites = [p["source_suite"] for p in SMOKE_PROMPTS]
        assert "G6" not in suites

    def test_unique_prompt_ids(self):
        """All prompt_ids must be unique."""
        ids = [p["prompt_id"] for p in SMOKE_PROMPTS]
        assert len(ids) == len(set(ids)), f"Duplicate IDs: {ids}"

    def test_required_fields_present(self):
        """Every prompt must have the core required fields."""
        required = {
            "prompt_id",
            "source_suite",
            "source_prompt_id",
            "prompt",
            "verification_type",
            "expected_outcome",
        }
        for p in SMOKE_PROMPTS:
            missing = required - set(p.keys())
            assert not missing, (
                f"{p['prompt_id']} missing required fields: {missing}"
            )

    def test_prompt_text_is_nonempty_string(self):
        """The prompt field must be a non-empty string."""
        for p in SMOKE_PROMPTS:
            assert isinstance(p["prompt"], str) and len(p["prompt"]) > 0, (
                f"{p['prompt_id']} has empty/non-string prompt"
            )

    def test_source_prompt_id_is_nonempty_string(self):
        """The source_prompt_id field must be a non-empty string."""
        for p in SMOKE_PROMPTS:
            assert isinstance(p["source_prompt_id"], str) and p["source_prompt_id"], (
                f"{p['prompt_id']} has empty/non-string source_prompt_id"
            )


# ═══════════════════════════════════════════════════════════════════
# 2. Prompt type validity tests
# ═══════════════════════════════════════════════════════════════════

class TestPromptTypeValidity:
    """Each verification_type must carry the fields it needs."""

    def test_verification_types_are_valid(self):
        """Only exec, multi_turn, response, plan are allowed."""
        valid_types = {"exec", "multi_turn", "response", "plan"}
        for p in SMOKE_PROMPTS:
            assert p["verification_type"] in valid_types, (
                f"{p['prompt_id']} has invalid type: {p['verification_type']}"
            )

    def test_multi_turn_has_followup(self):
        """multi_turn prompts must have debug_followup and max_turns."""
        for p in SMOKE_PROMPTS:
            if p["verification_type"] == "multi_turn":
                assert "debug_followup" in p, (
                    f"{p['prompt_id']}: multi_turn missing debug_followup"
                )
                assert isinstance(p["debug_followup"], str) and p["debug_followup"], (
                    f"{p['prompt_id']}: debug_followup must be non-empty string"
                )
                assert "max_turns" in p, (
                    f"{p['prompt_id']}: multi_turn missing max_turns"
                )
                assert isinstance(p["max_turns"], int) and p["max_turns"] > 1, (
                    f"{p['prompt_id']}: max_turns must be int > 1"
                )

    def test_response_check_has_must_contain(self):
        """response prompts must have response_must_contain list."""
        for p in SMOKE_PROMPTS:
            if p["verification_type"] == "response":
                assert "response_must_contain" in p, (
                    f"{p['prompt_id']}: response type missing response_must_contain"
                )
                mc = p["response_must_contain"]
                assert isinstance(mc, list) and len(mc) > 0, (
                    f"{p['prompt_id']}: response_must_contain must be non-empty list"
                )

    def test_plan_check_has_step_bounds(self):
        """plan prompts must have expected_steps_max."""
        for p in SMOKE_PROMPTS:
            if p["verification_type"] == "plan":
                assert "expected_steps_max" in p, (
                    f"{p['prompt_id']}: plan type missing expected_steps_max"
                )
                assert isinstance(p["expected_steps_max"], int), (
                    f"{p['prompt_id']}: expected_steps_max must be int"
                )
                assert p["expected_steps_max"] >= 1, (
                    f"{p['prompt_id']}: expected_steps_max must be >= 1"
                )

    def test_plan_check_has_must_contain(self):
        """plan prompts must also have response_must_contain."""
        for p in SMOKE_PROMPTS:
            if p["verification_type"] == "plan":
                assert "response_must_contain" in p, (
                    f"{p['prompt_id']}: plan type missing response_must_contain"
                )

    def test_e2e_has_preseed(self):
        """The smoke_e2e prompt (G3) must have a preseed dict."""
        e2e = [p for p in SMOKE_PROMPTS if p["prompt_id"] == "smoke_e2e"]
        assert len(e2e) == 1, "Expected exactly one smoke_e2e prompt"
        p = e2e[0]
        assert "preseed" in p, "smoke_e2e missing preseed"
        assert isinstance(p["preseed"], dict) and len(p["preseed"]) > 0, (
            "preseed must be a non-empty dict"
        )

    def test_exec_prompts_have_verification_command(self):
        """exec prompts must have a verification_command."""
        for p in SMOKE_PROMPTS:
            if p["verification_type"] == "exec":
                assert "verification_command" in p, (
                    f"{p['prompt_id']}: exec type missing verification_command"
                )
                assert isinstance(p["verification_command"], str), (
                    f"{p['prompt_id']}: verification_command must be string"
                )

    def test_multi_turn_has_verification_command(self):
        """multi_turn prompts must also have a verification_command for exec checks."""
        for p in SMOKE_PROMPTS:
            if p["verification_type"] == "multi_turn":
                assert "verification_command" in p, (
                    f"{p['prompt_id']}: multi_turn missing verification_command"
                )


# ═══════════════════════════════════════════════════════════════════
# 3. _verify_response tests
# ═══════════════════════════════════════════════════════════════════

class TestVerifyResponse:
    """Test the _verify_response method on DailySmokeTest.

    This method checks whether required keywords appear in the
    combined API response text (response + plan_summary + step content),
    case-insensitively.
    """

    def test_finds_required_terms_in_response(self, runner):
        """Keywords present in the response text -> True."""
        response = {
            "status": "success",
            "response": "The SYN packet initiates and ACK completes it.",
            "step_results": [],
        }
        item = {"response_must_contain": ["syn", "ack"]}
        assert runner._verify_response(response, item) is True

    def test_finds_terms_in_step_results(self, runner):
        """Keywords found in step worker_response/content -> True."""
        response = {
            "status": "success",
            "response": "",
            "plan_summary": "",
            "step_results": [
                {"worker_response": "Feature A is great", "content": ""},
                {"worker_response": "", "content": "Install with pip"},
            ],
        }
        item = {"response_must_contain": ["feature", "install"]}
        assert runner._verify_response(response, item) is True

    def test_finds_terms_in_plan_summary(self, runner):
        """Keywords found in plan_summary -> True."""
        response = {
            "status": "success",
            "response": "",
            "plan_summary": "Read the README to find features and installation guide",
            "step_results": [],
        }
        item = {"response_must_contain": ["feature", "install"]}
        assert runner._verify_response(response, item) is True

    def test_missing_terms_returns_false(self, runner):
        """One or more required terms absent -> False."""
        response = {
            "status": "success",
            "response": "The SYN flag is sent first.",
            "step_results": [],
        }
        # "syn" is present but "ack" is not (no substring match)
        item = {"response_must_contain": ["syn", "ack"]}
        assert runner._verify_response(response, item) is False

    def test_all_terms_missing_returns_false(self, runner):
        """None of the required terms present -> False."""
        response = {
            "status": "success",
            "response": "Unrelated text about weather.",
            "step_results": [],
        }
        item = {"response_must_contain": ["syn", "ack"]}
        assert runner._verify_response(response, item) is False

    def test_empty_response_text_returns_false(self, runner):
        """Empty response with required terms -> False."""
        response = {
            "status": "success",
            "response": "",
            "step_results": [],
        }
        item = {"response_must_contain": ["feature"]}
        assert runner._verify_response(response, item) is False

    def test_none_response_returns_false(self, runner):
        """None response with required terms -> False."""
        item = {"response_must_contain": ["feature"]}
        assert runner._verify_response(None, item) is False

    def test_case_insensitive_matching(self, runner):
        """Keywords match regardless of case."""
        response = {
            "status": "success",
            "response": "TCP uses SYN and ACK packets.",
            "step_results": [],
        }
        item = {"response_must_contain": ["syn", "ack"]}
        assert runner._verify_response(response, item) is True

    def test_mixed_case_keywords_match(self, runner):
        """Keywords themselves can be mixed case and still match."""
        response = {
            "status": "success",
            "response": "The features include installation steps.",
            "step_results": [],
        }
        item = {"response_must_contain": ["FEATURE", "Install"]}
        assert runner._verify_response(response, item) is True

    def test_no_must_contain_with_success_returns_true(self, runner):
        """No response_must_contain and success status -> True."""
        response = {"status": "success"}
        item = {}
        assert runner._verify_response(response, item) is True

    def test_no_must_contain_with_failure_returns_false(self, runner):
        """No response_must_contain but non-success status -> False."""
        response = {"status": "blocked"}
        item = {}
        assert runner._verify_response(response, item) is False

    def test_empty_must_contain_list_with_success(self, runner):
        """Empty response_must_contain list + success -> True."""
        response = {"status": "success"}
        item = {"response_must_contain": []}
        assert runner._verify_response(response, item) is True

    def test_none_fields_in_response_handled(self, runner):
        """None values for response/plan_summary don't crash."""
        response = {
            "status": "success",
            "response": None,
            "plan_summary": None,
            "step_results": [
                {"worker_response": None, "content": "feature install"},
            ],
        }
        item = {"response_must_contain": ["feature", "install"]}
        assert runner._verify_response(response, item) is True

    def test_partial_keyword_match_is_sufficient(self, runner):
        """Substring matching — 'feature' matches 'features'."""
        response = {
            "status": "success",
            "response": "The features list includes installation.",
            "step_results": [],
        }
        item = {"response_must_contain": ["feature", "install"]}
        assert runner._verify_response(response, item) is True


# ═══════════════════════════════════════════════════════════════════
# 4. _update_stats tests
# ═══════════════════════════════════════════════════════════════════

class TestUpdateStats:
    """Test the _update_stats method on DailySmokeTest.

    Verifies correct increment of passed/failed/error/blocked/skipped
    counters and by_suite tracking.
    """

    def test_passed_result_increments_smoke_passed(self, runner):
        """A passed result increments smoke_passed and total."""
        result = {
            "response_status": "success",
            "smoke_passed": True,
            "source_suite": "G1",
            "turns_actual": 1,
        }
        runner._update_stats(result)
        assert runner.stats["total"] == 1
        assert runner.stats["smoke_passed"] == 1
        assert runner.stats["smoke_failed"] == 0

    def test_failed_result_increments_smoke_failed(self, runner):
        """A failed result increments smoke_failed."""
        result = {
            "response_status": "success",
            "smoke_passed": False,
            "source_suite": "G1",
            "turns_actual": 1,
        }
        runner._update_stats(result)
        assert runner.stats["smoke_failed"] == 1
        assert runner.stats["smoke_passed"] == 0

    def test_error_status_increments_api_errors(self, runner):
        """An error response_status increments api_errors."""
        result = {
            "response_status": "error",
            "smoke_passed": None,
            "source_suite": "G2",
            "turns_actual": 1,
        }
        runner._update_stats(result)
        assert runner.stats["api_errors"] == 1
        assert runner.stats["smoke_passed"] == 0
        assert runner.stats["smoke_failed"] == 0

    def test_blocked_status_increments_blocked(self, runner):
        """A blocked response_status increments the blocked counter."""
        result = {
            "response_status": "blocked",
            "smoke_passed": None,
            "source_suite": "G3",
            "turns_actual": 1,
        }
        runner._update_stats(result)
        assert runner.stats["blocked"] == 1

    def test_skipped_result_increments_smoke_skipped(self, runner):
        """A None smoke_passed with non-error/blocked status -> skipped."""
        result = {
            "response_status": "success",
            "smoke_passed": None,
            "source_suite": "G4",
            "turns_actual": 1,
        }
        runner._update_stats(result)
        assert runner.stats["smoke_skipped"] == 1

    def test_by_suite_created_on_first_result(self, runner):
        """by_suite entry is created for a new suite."""
        result = {
            "response_status": "success",
            "smoke_passed": True,
            "source_suite": "G1",
            "turns_actual": 1,
        }
        runner._update_stats(result)
        assert "G1" in runner.stats["by_suite"]
        assert runner.stats["by_suite"]["G1"]["total"] == 1
        assert runner.stats["by_suite"]["G1"]["passed"] == 1
        assert runner.stats["by_suite"]["G1"]["failed"] == 0

    def test_by_suite_tracks_failures(self, runner):
        """Failed results increment by_suite failed counter."""
        result = {
            "response_status": "success",
            "smoke_passed": False,
            "source_suite": "G3",
            "turns_actual": 1,
        }
        runner._update_stats(result)
        assert runner.stats["by_suite"]["G3"]["failed"] == 1
        assert runner.stats["by_suite"]["G3"]["passed"] == 0
        assert runner.stats["by_suite"]["G3"]["total"] == 1

    def test_by_suite_accumulates_across_results(self, runner):
        """Multiple results for the same suite accumulate correctly."""
        runner._update_stats({
            "response_status": "success",
            "smoke_passed": True,
            "source_suite": "G1",
            "turns_actual": 1,
        })
        runner._update_stats({
            "response_status": "success",
            "smoke_passed": False,
            "source_suite": "G1",
            "turns_actual": 1,
        })
        assert runner.stats["by_suite"]["G1"]["total"] == 2
        assert runner.stats["by_suite"]["G1"]["passed"] == 1
        assert runner.stats["by_suite"]["G1"]["failed"] == 1

    def test_total_turns_accumulates(self, runner):
        """total_turns sums across all results."""
        runner._update_stats({
            "response_status": "success",
            "smoke_passed": True,
            "source_suite": "G1",
            "turns_actual": 1,
        })
        runner._update_stats({
            "response_status": "success",
            "smoke_passed": True,
            "source_suite": "G2",
            "turns_actual": 3,
        })
        assert runner.stats["total_turns"] == 4

    def test_missing_turns_actual_defaults_to_one(self, runner):
        """If turns_actual is missing, default to 1."""
        result = {
            "response_status": "success",
            "smoke_passed": True,
            "source_suite": "G1",
        }
        runner._update_stats(result)
        assert runner.stats["total_turns"] == 1

    def test_multiple_suites_tracked_independently(self, runner):
        """Different suites get independent by_suite entries."""
        runner._update_stats({
            "response_status": "success",
            "smoke_passed": True,
            "source_suite": "G1",
            "turns_actual": 1,
        })
        runner._update_stats({
            "response_status": "success",
            "smoke_passed": False,
            "source_suite": "G3",
            "turns_actual": 1,
        })
        assert set(runner.stats["by_suite"].keys()) == {"G1", "G3"}
        assert runner.stats["by_suite"]["G1"]["passed"] == 1
        assert runner.stats["by_suite"]["G3"]["failed"] == 1

    def test_error_does_not_increment_by_suite_passed_or_failed(self, runner):
        """Error status increments by_suite total but not passed/failed."""
        result = {
            "response_status": "error",
            "smoke_passed": None,
            "source_suite": "G5",
            "turns_actual": 1,
        }
        runner._update_stats(result)
        assert runner.stats["by_suite"]["G5"]["total"] == 1
        assert runner.stats["by_suite"]["G5"]["passed"] == 0
        assert runner.stats["by_suite"]["G5"]["failed"] == 0

    def test_full_suite_run_stats(self, runner):
        """Simulate a full 5-prompt run with mixed outcomes."""
        results = [
            {"response_status": "success", "smoke_passed": True,
             "source_suite": "G1", "turns_actual": 1},
            {"response_status": "success", "smoke_passed": True,
             "source_suite": "G2", "turns_actual": 3},
            {"response_status": "success", "smoke_passed": False,
             "source_suite": "G3", "turns_actual": 1},
            {"response_status": "error", "smoke_passed": None,
             "source_suite": "G4", "turns_actual": 1},
            {"response_status": "blocked", "smoke_passed": None,
             "source_suite": "G5", "turns_actual": 1},
        ]
        for r in results:
            runner._update_stats(r)

        assert runner.stats["total"] == 5
        assert runner.stats["smoke_passed"] == 2
        assert runner.stats["smoke_failed"] == 1
        assert runner.stats["api_errors"] == 1
        assert runner.stats["blocked"] == 1
        assert runner.stats["smoke_skipped"] == 0
        assert runner.stats["total_turns"] == 7
        assert len(runner.stats["by_suite"]) == 5
