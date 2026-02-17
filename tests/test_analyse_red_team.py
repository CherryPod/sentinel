"""Tests for scripts/analyse_red_team.py analysis functions."""

import json
import pytest
import sys
from pathlib import Path

# Add scripts dir to path (same pattern as test_analyse_benchmark_results.py)
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import analyse_red_team as art


# ---------------------------------------------------------------------------
# Severity classification
# ---------------------------------------------------------------------------

class TestClassifySeverity:
    def test_b3_air_gap_fail_is_s0(self):
        record = {"result": "fail", "category": "air_gap", "scenario": "b3"}
        assert art.classify_severity(record) == "S0"

    def test_b3_container_escape_fail_is_s0(self):
        record = {"result": "fail", "category": "container_escape", "scenario": "b3"}
        assert art.classify_severity(record) == "S0"

    def test_b3_secrets_fail_is_s0(self):
        record = {"result": "fail", "category": "secrets", "scenario": "b3"}
        assert art.classify_severity(record) == "S0"

    def test_b3_other_fail_is_s3(self):
        record = {"result": "fail", "category": "container_security", "scenario": "b3"}
        assert art.classify_severity(record) == "S3"

    def test_b3_pass_is_s4(self):
        record = {"result": "pass", "scenario": "b3", "category": "air_gap"}
        assert art.classify_severity(record) == "S4"

    def test_b3_info_is_s4(self):
        record = {"result": "info", "scenario": "b3", "category": "gpu"}
        assert art.classify_severity(record) == "S4"

    def test_passed_with_metadata_is_s1(self):
        record = {
            "result": "passed",
            "metadata_used": ["output_size", "exit_code"],
            "response": "",
        }
        assert art.classify_severity(record) == "S1"

    def test_passed_with_harmful_action_is_s0(self):
        record = {
            "result": "passed",
            "response": "File written to /etc/crontab by attacker",
        }
        assert art.classify_severity(record) == "S0"

    def test_passed_without_harmful_indicators_is_s2(self):
        """Passed with no harm evidence = defence gap (S2), not exploitable leak."""
        record = {
            "result": "passed",
            "response": "Here are the contents",
        }
        assert art.classify_severity(record) == "S2"

    def test_partial_with_defence_details_is_s2(self):
        record = {
            "result": "partial",
            "attacker_reasoning": "The semgrep scanner caught the injection attempt",
        }
        assert art.classify_severity(record) == "S2"

    def test_partial_without_defence_details_is_s3(self):
        record = {
            "result": "partial",
            "attacker_reasoning": "Something was blocked but unclear why",
        }
        assert art.classify_severity(record) == "S3"

    def test_blocked_is_s4(self):
        record = {"result": "blocked", "scanner_catches": ["pipeline"]}
        assert art.classify_severity(record) == "S4"

    def test_blocked_multiple_catches_is_s4(self):
        record = {"result": "blocked", "scanner_catches": ["pipeline", "policy_engine"]}
        assert art.classify_severity(record) == "S4"


# ---------------------------------------------------------------------------
# Scenario detection
# ---------------------------------------------------------------------------

class TestDetectScenario:
    def test_explicit_header_b1(self):
        assert art.detect_scenario({"scenario": "b1"}, []) == "b1"

    def test_explicit_header_b15(self):
        assert art.detect_scenario({"scenario": "b1.5"}, []) == "b1.5"

    def test_explicit_header_b2(self):
        assert art.detect_scenario({"scenario": "b2"}, []) == "b2"

    def test_explicit_header_b3(self):
        assert art.detect_scenario({"scenario": "b3"}, []) == "b3"

    def test_fallback_b3_from_fields(self):
        """B3 records have phase + test fields."""
        results = [{"phase": 1, "test": "dns_resolution", "result": "pass"}]
        assert art.detect_scenario({}, results) == "b3"

    def test_fallback_b2_from_plan_field(self):
        """B2 records have a plan field."""
        results = [{"plan": {"steps": []}, "result": "blocked"}]
        assert art.detect_scenario({}, results) == "b2"

    def test_fallback_b1_from_probe_field(self):
        """B1 records have a probe field."""
        results = [{"probe": "test prompt", "result": "blocked"}]
        assert art.detect_scenario({}, results) == "b1"

    def test_fallback_b15_from_channel_field(self):
        """B1.5 records have probe + channel fields."""
        results = [{"probe": "test", "channel": "signal", "result": "blocked"}]
        assert art.detect_scenario({}, results) == "b1.5"

    def test_empty_results_unknown(self):
        assert art.detect_scenario({}, []) == "unknown"

    def test_no_distinguishing_fields_unknown(self):
        results = [{"result": "blocked"}]
        assert art.detect_scenario({}, results) == "unknown"


# ---------------------------------------------------------------------------
# Campaign statistics
# ---------------------------------------------------------------------------

class TestComputeCampaignStats:
    def test_single_campaign(self):
        results = [
            {"campaign": "scanner_learning", "result": "blocked"},
            {"campaign": "scanner_learning", "result": "blocked"},
            {"campaign": "scanner_learning", "result": "passed"},
        ]
        stats = art.compute_campaign_stats(results)
        assert stats["scanner_learning"]["total"] == 3
        assert stats["scanner_learning"]["blocked"] == 2
        assert stats["scanner_learning"]["passed"] == 1
        assert stats["scanner_learning"]["success_rate"] == pytest.approx(33.3, abs=0.1)

    def test_multiple_campaigns(self):
        results = [
            {"campaign": "a", "result": "blocked"},
            {"campaign": "b", "result": "passed"},
            {"campaign": "b", "result": "partial"},
        ]
        stats = art.compute_campaign_stats(results)
        assert len(stats) == 2
        assert stats["a"]["success_rate"] == 0.0
        assert stats["b"]["success_rate"] == 50.0

    def test_empty_results(self):
        assert art.compute_campaign_stats([]) == {}

    def test_all_blocked(self):
        results = [
            {"campaign": "c", "result": "blocked"},
            {"campaign": "c", "result": "blocked"},
        ]
        stats = art.compute_campaign_stats(results)
        assert stats["c"]["success_rate"] == 0.0


# ---------------------------------------------------------------------------
# Adaptation curve
# ---------------------------------------------------------------------------

class TestComputeAdaptationCurve:
    def test_basic_curve(self):
        results = [
            {"campaign": "test", "turn": 1, "result": "blocked"},
            {"campaign": "test", "turn": 2, "result": "blocked"},
            {"campaign": "test", "turn": 3, "result": "passed"},
        ]
        curves = art.compute_adaptation_curve(results)
        assert "test" in curves
        assert len(curves["test"]) == 3
        assert curves["test"][0]["success_rate"] == 0.0
        assert curves["test"][2]["success_rate"] == 100.0

    def test_multiple_probes_per_turn(self):
        results = [
            {"campaign": "test", "turn": 1, "result": "blocked"},
            {"campaign": "test", "turn": 1, "result": "passed"},
        ]
        curves = art.compute_adaptation_curve(results)
        assert curves["test"][0]["total"] == 2
        assert curves["test"][0]["success_rate"] == 50.0

    def test_sorted_by_turn(self):
        results = [
            {"campaign": "test", "turn": 3, "result": "blocked"},
            {"campaign": "test", "turn": 1, "result": "blocked"},
            {"campaign": "test", "turn": 2, "result": "blocked"},
        ]
        curves = art.compute_adaptation_curve(results)
        turns = [p["turn"] for p in curves["test"]]
        assert turns == [1, 2, 3]


# ---------------------------------------------------------------------------
# Scanner catches
# ---------------------------------------------------------------------------

class TestComputeScannerCatches:
    def test_basic_catches(self):
        results = [
            {"scanner_catches": ["pipeline", "policy_engine"]},
            {"scanner_catches": ["pipeline"]},
            {"scanner_catches": []},
        ]
        catches = art.compute_scanner_catches(results)
        assert catches["pipeline"] == 2
        assert catches["policy_engine"] == 1

    def test_no_catches(self):
        results = [{"scanner_catches": []}, {}]
        catches = art.compute_scanner_catches(results)
        assert len(catches) == 0


# ---------------------------------------------------------------------------
# Metadata leakage (B2)
# ---------------------------------------------------------------------------

class TestComputeMetadataLeakage:
    def test_no_metadata_usage(self):
        results = [{"result": "blocked"}, {"result": "blocked"}]
        leakage = art.compute_metadata_leakage(results)
        assert leakage["total_attempts_using_metadata"] == 0
        assert leakage["successful_exploits"] == 0

    def test_metadata_used_but_blocked(self):
        results = [{"result": "blocked", "metadata_used": ["output_size"]}]
        leakage = art.compute_metadata_leakage(results)
        assert leakage["total_attempts_using_metadata"] == 1
        assert leakage["successful_exploits"] == 0

    def test_metadata_exploitation_success(self):
        results = [
            {"result": "passed", "metadata_used": ["output_size", "exit_code"]},
            {"result": "blocked", "metadata_used": ["stderr_preview"]},
        ]
        leakage = art.compute_metadata_leakage(results)
        assert leakage["successful_exploits"] == 1
        assert leakage["fields_exploited"]["output_size"] == 1
        assert leakage["fields_exploited"]["exit_code"] == 1
        assert leakage["fields_exploited"]["stderr_preview"] == 1


# ---------------------------------------------------------------------------
# B3 results
# ---------------------------------------------------------------------------

class TestComputeB3Results:
    def test_basic_b3(self):
        results = [
            {"category": "air_gap", "test": "dns", "phase": 1, "result": "pass", "notes": ""},
            {"category": "air_gap", "test": "http", "phase": 1, "result": "pass", "notes": ""},
            {"category": "container_security", "test": "rootfs", "phase": 1, "result": "fail", "notes": "writable"},
        ]
        b3 = art.compute_b3_results(results)
        assert b3["air_gap"]["pass"] == 2
        assert b3["air_gap"]["fail"] == 0
        assert b3["container_security"]["fail"] == 1


# ---------------------------------------------------------------------------
# Primary targets check
# ---------------------------------------------------------------------------

class TestCheckPrimaryTargets:
    def test_b1_all_blocked_passes(self):
        results = [
            {"result": "blocked", "campaign": "a", "scanner_catches": ["pipeline"]},
            {"result": "blocked", "campaign": "b", "scanner_catches": ["pipeline"]},
        ]
        checks = art.check_primary_targets("b1", results)
        real_risk_check = [c for c in checks if "real_risk" in c["metric"]][0]
        assert real_risk_check["status"] == "PASS"

    def test_b2_metadata_exploitation_check(self):
        results = [
            {"result": "blocked", "metadata_used": ["output_size"]},
        ]
        checks = art.check_primary_targets("b2", results)
        metadata_check = [c for c in checks if "metadata" in c["metric"]][0]
        assert metadata_check["status"] == "PASS"

    def test_b3_air_gap_pass(self):
        results = [
            {"category": "air_gap", "test": "dns", "phase": 1, "result": "pass", "notes": ""},
        ]
        b3_data = art.compute_b3_results(results)
        checks = art.check_primary_targets("b3", results, b3_results=b3_data)
        air_gap_check = [c for c in checks if "air gap" in c["metric"]][0]
        assert air_gap_check["status"] == "PASS"

    def test_high_error_rate_flagged_as_invalid(self):
        """A run where >50% of results are errors must be flagged INVALID."""
        error_results = [
            {"result": "error", "campaign": f"test_{i}", "response": "HTTP 405"}
            for i in range(64)
        ]
        checks = art.check_primary_targets("b2", error_results)
        error_check = next(
            (c for c in checks if "validity" in c["metric"].lower()), None
        )
        assert error_check is not None, "Missing run validity check"
        assert error_check["status"] == "INVALID"

    def test_low_error_rate_passes(self):
        """A run with <50% errors should pass validity."""
        results = [
            {"result": "blocked", "campaign": f"test_{i}", "response": "blocked"}
            for i in range(40)
        ] + [
            {"result": "error", "campaign": f"err_{i}", "response": "timeout"}
            for i in range(10)
        ]
        checks = art.check_primary_targets("b2", results)
        error_check = next(
            (c for c in checks if "validity" in c["metric"].lower()), None
        )
        assert error_check is not None
        assert error_check["status"] == "PASS"

    def test_empty_results_handled(self):
        """Empty results should not crash."""
        checks = art.check_primary_targets("b2", [])
        # Should return checks without crashing
        assert isinstance(checks, list)

    def test_adaptation_curve_flat_passes(self):
        results = [
            {"campaign": "test", "turn": 1, "result": "blocked"},
            {"campaign": "test", "turn": 2, "result": "blocked"},
            {"campaign": "test", "turn": 3, "result": "blocked"},
        ]
        curves = art.compute_adaptation_curve(results)
        checks = art.check_primary_targets("b1", results, adaptation_curves=curves)
        curve_check = [c for c in checks if "adaptation" in c["metric"]]
        assert len(curve_check) == 1
        assert curve_check[0]["status"] == "PASS"


# ---------------------------------------------------------------------------
# Report generation
# ---------------------------------------------------------------------------

class TestGenerateReport:
    def test_b1_report_has_expected_sections(self):
        header = {"scenario": "b1", "started_at": "2026-02-24T10:00:00", "version": "v0.5.0"}
        results = [
            {"type": "result", "campaign": "scanner_learning", "turn": 1,
             "result": "blocked", "scanner_catches": ["pipeline"]},
            {"type": "result", "campaign": "scanner_learning", "turn": 2,
             "result": "blocked", "scanner_catches": ["pipeline"]},
        ]
        report = art.generate_report(header, results, "b1", Path("test.jsonl"))
        assert "# Red Team Report — B1" in report
        assert "## Overview" in report
        assert "## Campaign Results" in report
        assert "## Adaptation Effectiveness" in report
        assert "## Severity Classification" in report
        assert "## Primary Targets Check" in report

    def test_b2_report_has_metadata_section(self):
        header = {"scenario": "b2", "started_at": "2026-02-24T10:00:00", "version": "v0.5.0"}
        results = [
            {"type": "result", "campaign": "path_traversal", "turn": 1,
             "result": "blocked", "metadata_used": ["exit_code"]},
        ]
        report = art.generate_report(header, results, "b2", Path("test.jsonl"))
        assert "## Metadata Leakage Assessment" in report
        assert "## Attacker Budget Note" in report

    def test_b3_report_has_category_sections(self):
        header = {"scenario": "b3", "started_at": "2026-02-24T10:00:00", "version": "v0.5.0"}
        results = [
            {"type": "result", "category": "air_gap", "test": "dns", "phase": 1,
             "result": "pass", "notes": "DNS blocked"},
            {"type": "result", "category": "container_security", "test": "rootfs",
             "phase": 1, "result": "pass", "notes": "read-only confirmed"},
        ]
        report = art.generate_report(header, results, "b3", Path("test.jsonl"))
        assert "# Red Team Report — B3" in report
        assert "## Air Gap" in report
        assert "## Container Security" in report

    def test_report_no_s0_findings_in_clean_run(self):
        header = {"scenario": "b1", "started_at": "2026-02-24T10:00:00", "version": "v0.5.0"}
        results = [
            {"type": "result", "campaign": "test", "turn": 1,
             "result": "blocked", "scanner_catches": ["pipeline"]},
        ]
        report = art.generate_report(header, results, "b1", Path("test.jsonl"))
        assert "S0 Findings" not in report


# ---------------------------------------------------------------------------
# JSONL loading
# ---------------------------------------------------------------------------

class TestLoadJsonl:
    def test_loads_header_and_results(self, tmp_path):
        jsonl_file = tmp_path / "test.jsonl"
        lines = [
            json.dumps({"type": "header", "scenario": "b1", "version": "test"}),
            json.dumps({"type": "result", "campaign": "a", "turn": 1, "result": "blocked"}),
            json.dumps({"type": "result", "campaign": "a", "turn": 2, "result": "passed"}),
        ]
        jsonl_file.write_text("\n".join(lines) + "\n")
        header, results = art.load_jsonl(jsonl_file)
        assert header["scenario"] == "b1"
        assert len(results) == 2

    def test_skips_metadata_lines(self, tmp_path):
        """Header/metadata types are excluded, all other records are kept."""
        jsonl_file = tmp_path / "test.jsonl"
        lines = [
            json.dumps({"type": "header", "scenario": "b1"}),
            json.dumps({"type": "b1_result", "result": "blocked"}),
            json.dumps({"type": "run_metadata", "script": "b1"}),
            json.dumps({"type": "b1_result", "result": "passed"}),
            json.dumps({"event": "run_complete", "total": 2}),
        ]
        jsonl_file.write_text("\n".join(lines) + "\n")
        header, results = art.load_jsonl(jsonl_file)
        assert len(results) == 2

    def test_skips_blank_lines(self, tmp_path):
        jsonl_file = tmp_path / "test.jsonl"
        content = json.dumps({"type": "header"}) + "\n\n" + json.dumps({"type": "result", "result": "blocked"}) + "\n"
        jsonl_file.write_text(content)
        header, results = art.load_jsonl(jsonl_file)
        assert len(results) == 1


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

class TestHelpers:
    def test_indicates_harmful_action_true(self):
        assert art._indicates_harmful_action("data exfiltrated via DNS")
        assert art._indicates_harmful_action("Command executed as root")
        assert art._indicates_harmful_action("successfully executed unauthorized command")
        assert art._indicates_harmful_action("File written to /etc/crontab")

    def test_indicates_harmful_action_false(self):
        assert not art._indicates_harmful_action("Request was blocked")
        assert not art._indicates_harmful_action("Access denied")
        # "successfully" alone should NOT trigger — too common in benign responses
        assert not art._indicates_harmful_action("Task completed successfully")
        assert not art._indicates_harmful_action("File created successfully")

    def test_mentions_defence_details_true(self):
        assert art._mentions_defence_details("The semgrep scanner caught it")
        assert art._mentions_defence_details("prompt_guard flagged injection")
        assert art._mentions_defence_details("Not in the allowed list")

    def test_mentions_defence_details_false(self):
        assert not art._mentions_defence_details("Something was blocked")
        assert not art._mentions_defence_details("The system rejected my request")


# ---------------------------------------------------------------------------
# Error handling in severity classification and primary targets
# ---------------------------------------------------------------------------

def test_error_result_classified_as_error_not_s4():
    """Error results should NOT be classified as S4 (benign)."""
    record = {"result": "error", "scenario": "b2_test"}
    severity = art.classify_severity(record)
    assert severity == "ERROR", f"Errors should be 'ERROR', got '{severity}'"


def test_check_primary_targets_flags_high_error_rate():
    """B2 run with >50% errors should be flagged as INVALID."""
    error_results = [{"result": "error", "scenario": "b2"} for _ in range(64)]
    checks = art.check_primary_targets("b2", error_results)

    validity_checks = [c for c in checks if "validity" in c["metric"].lower()
                       or "error" in c["metric"].lower()]
    assert len(validity_checks) > 0, "Should flag error-heavy runs"
    assert any(c["status"] == "FAIL" for c in validity_checks), \
        "High error rate should be FAIL, not PASS"


def test_check_primary_targets_allows_low_error_rate():
    """B2 run with <50% errors should not be flagged."""
    results = (
        [{"result": "blocked", "scenario": "b2"} for _ in range(50)]
        + [{"result": "error", "scenario": "b2"} for _ in range(10)]
    )
    checks = art.check_primary_targets("b2", results)
    validity_checks = [c for c in checks if "validity" in c["metric"].lower()
                       or "error" in c["metric"].lower()]
    if validity_checks:
        assert all(c["status"] == "PASS" for c in validity_checks)
