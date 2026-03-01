"""Tests for destination-aware output scanning."""
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from sentinel.core.models import OutputDestination, Plan, PlanStep, ScanMatch, ScanResult
from sentinel.security.pipeline import ScanPipeline, PipelineScanResult


class TestOutputDestinationEnum:
    def test_display_value(self):
        assert OutputDestination.DISPLAY.value == "display"

    def test_execution_value(self):
        assert OutputDestination.EXECUTION.value == "execution"

    def test_is_string_enum(self):
        assert isinstance(OutputDestination.DISPLAY, str)


class TestScanOutputDestination:
    """Tests for destination-aware scan_output()."""

    @pytest.fixture(autouse=True)
    def _disable_prompt_guard(self):
        with patch("sentinel.security.pipeline.settings") as mock_settings:
            mock_settings.prompt_guard_enabled = False
            mock_settings.require_prompt_guard = False
            mock_settings.prompt_guard_threshold = 0.5
            mock_settings.baseline_mode = False
            yield mock_settings

    @pytest.fixture
    def pipeline(self):
        return ScanPipeline.__new__(ScanPipeline)

    def _setup_scanners(self, pipeline):
        """Attach mock scanners that return clean results by default."""
        clean = ScanResult(found=False, scanner_name="mock")
        pipeline._cred_scanner = MagicMock()
        pipeline._cred_scanner.scan.return_value = clean
        pipeline._path_scanner = MagicMock()
        pipeline._path_scanner.scan_output_text.return_value = clean
        pipeline._cmd_scanner = MagicMock()
        pipeline._cmd_scanner.scan_output_text.return_value = ScanResult(
            found=True, scanner_name="command_pattern_scanner",
            matches=[ScanMatch(pattern_name="chmod_setuid", matched_text="chmod u+s")]
        )
        pipeline._encoding_scanner = MagicMock()
        pipeline._encoding_scanner.scan_output_text.return_value = clean

    def test_execution_destination_runs_cmd_scanner(self, pipeline):
        """CommandPatternScanner runs and blocks when destination=EXECUTION."""
        self._setup_scanners(pipeline)
        result = pipeline.scan_output("chmod u+s /usr/bin/foo", OutputDestination.EXECUTION)
        assert not result.is_clean
        assert "command_pattern_scanner" in result.violations

    def test_display_destination_skips_cmd_scanner(self, pipeline):
        """CommandPatternScanner skipped when destination=DISPLAY."""
        self._setup_scanners(pipeline)
        result = pipeline.scan_output("chmod u+s /usr/bin/foo", OutputDestination.DISPLAY)
        assert result.is_clean
        pipeline._cmd_scanner.scan_output_text.assert_not_called()

    def test_display_destination_still_runs_credential_scanner(self, pipeline):
        """CredentialScanner always runs regardless of destination."""
        self._setup_scanners(pipeline)
        pipeline._cred_scanner.scan.return_value = ScanResult(
            found=True, scanner_name="credential_scanner",
            matches=[ScanMatch(pattern_name="aws_key", matched_text="AKIA...")]
        )
        result = pipeline.scan_output("AKIAIOSFODNN7EXAMPLE", OutputDestination.DISPLAY)
        assert not result.is_clean
        assert "credential_scanner" in result.violations

    def test_default_destination_is_execution(self, pipeline):
        """Default destination is EXECUTION when not specified (backward compat)."""
        self._setup_scanners(pipeline)
        result = pipeline.scan_output("chmod u+s /usr/bin/foo")
        assert not result.is_clean  # cmd_scanner ran and blocked


class TestProcessWithQwenDestination:
    """Verify process_with_qwen threads destination to scan_output."""

    def _make_pipeline(self):
        """Create a pipeline with mock internals (bypasses __init__)."""
        pipeline = ScanPipeline.__new__(ScanPipeline)
        pipeline._worker = MagicMock()
        pipeline._worker.generate = AsyncMock(return_value="response text")
        pipeline._echo_scanner = MagicMock()
        return pipeline

    @pytest.mark.asyncio
    async def test_destination_threaded_to_scan_output(self):
        """process_with_qwen passes destination to scan_output."""
        pipeline = self._make_pipeline()
        with patch.object(pipeline, "scan_input"), \
             patch.object(pipeline, "scan_output", return_value=PipelineScanResult()) as mock_scan, \
             patch("sentinel.security.pipeline.create_tagged_data") as mock_tag, \
             patch("sentinel.security.pipeline.settings") as mock_settings:
            mock_settings.spotlighting_enabled = False
            mock_settings.prompt_guard_enabled = False
            mock_settings.ollama_model = "test"
            mock_tag.return_value = MagicMock(content="response text", scan_results={})

            await pipeline.process_with_qwen(
                prompt="test", destination=OutputDestination.DISPLAY
            )
            mock_scan.assert_called_once()
            _, kwargs = mock_scan.call_args
            assert kwargs.get("destination") == OutputDestination.DISPLAY

    @pytest.mark.asyncio
    async def test_default_destination_is_execution_in_process_with_qwen(self):
        """process_with_qwen defaults to EXECUTION when destination not specified."""
        pipeline = self._make_pipeline()
        with patch.object(pipeline, "scan_input"), \
             patch.object(pipeline, "scan_output", return_value=PipelineScanResult()) as mock_scan, \
             patch("sentinel.security.pipeline.create_tagged_data") as mock_tag, \
             patch("sentinel.security.pipeline.settings") as mock_settings:
            mock_settings.spotlighting_enabled = False
            mock_settings.prompt_guard_enabled = False
            mock_settings.ollama_model = "test"
            mock_tag.return_value = MagicMock(content="response text", scan_results={})

            await pipeline.process_with_qwen(prompt="test")
            mock_scan.assert_called_once()
            _, kwargs = mock_scan.call_args
            assert kwargs.get("destination") == OutputDestination.EXECUTION


class TestDestinationPrecomputation:
    """Tests for orchestrator destination assignment from plan structure."""

    def test_single_llm_task_is_display(self):
        """A standalone llm_task with no downstream tool_call gets DISPLAY."""
        from sentinel.planner.orchestrator import _compute_execution_vars, _get_destination
        plan = Plan(plan_summary="test", steps=[
            PlanStep(id="step_1", type="llm_task", prompt="explain setuid",
                     description="explain"),
        ])
        execution_vars = _compute_execution_vars(plan)
        assert _get_destination(plan.steps[0], execution_vars) == OutputDestination.DISPLAY

    def test_llm_task_chained_to_tool_call_is_execution(self):
        """llm_task whose output_var feeds a tool_call gets EXECUTION."""
        from sentinel.planner.orchestrator import _compute_execution_vars, _get_destination
        plan = Plan(plan_summary="test", steps=[
            PlanStep(id="step_1", type="llm_task", prompt="write code",
                     description="generate", output_var="$code"),
            PlanStep(id="step_2", type="tool_call", tool="file_write",
                     description="write file",
                     args={"path": "/workspace/x.py", "content": "$code"},
                     input_vars=["$code"]),
        ])
        execution_vars = _compute_execution_vars(plan)
        assert _get_destination(plan.steps[0], execution_vars) == OutputDestination.EXECUTION
        # tool_call steps always default to EXECUTION (doesn't matter, they don't scan)
        assert _get_destination(plan.steps[1], execution_vars) == OutputDestination.EXECUTION

    def test_llm_task_with_output_var_but_no_consumer_is_display(self):
        """llm_task with output_var that no tool_call references gets DISPLAY."""
        from sentinel.planner.orchestrator import _compute_execution_vars, _get_destination
        plan = Plan(plan_summary="test", steps=[
            PlanStep(id="step_1", type="llm_task", prompt="draft",
                     description="draft", output_var="$draft"),
            PlanStep(id="step_2", type="llm_task", prompt="refine $draft",
                     description="refine", input_vars=["$draft"]),
        ])
        execution_vars = _compute_execution_vars(plan)
        assert _get_destination(plan.steps[0], execution_vars) == OutputDestination.DISPLAY
        assert _get_destination(plan.steps[1], execution_vars) == OutputDestination.DISPLAY

    def test_multi_step_mixed(self):
        """Mixed plan: only the step feeding tool_call gets EXECUTION."""
        from sentinel.planner.orchestrator import _compute_execution_vars, _get_destination
        plan = Plan(plan_summary="test", steps=[
            PlanStep(id="step_1", type="llm_task", prompt="explain",
                     description="explain"),
            PlanStep(id="step_2", type="llm_task", prompt="write code",
                     description="generate", output_var="$code"),
            PlanStep(id="step_3", type="tool_call", tool="file_write",
                     description="write",
                     args={"path": "/workspace/x.py", "content": "$code"},
                     input_vars=["$code"]),
        ])
        execution_vars = _compute_execution_vars(plan)
        assert _get_destination(plan.steps[0], execution_vars) == OutputDestination.DISPLAY
        assert _get_destination(plan.steps[1], execution_vars) == OutputDestination.EXECUTION


class TestDestinationAwareScanningE2E:
    """End-to-end tests verifying the full pipeline path with real scanners."""

    @pytest.fixture(autouse=True)
    def _disable_prompt_guard(self):
        with patch("sentinel.security.pipeline.settings") as mock_settings:
            mock_settings.prompt_guard_enabled = False
            mock_settings.require_prompt_guard = False
            mock_settings.prompt_guard_threshold = 0.5
            mock_settings.baseline_mode = False
            yield mock_settings

    @pytest.fixture
    def pipeline(self):
        """Pipeline with real CommandPatternScanner, mocked others."""
        from sentinel.security.scanner import CommandPatternScanner
        p = ScanPipeline.__new__(ScanPipeline)
        p._cmd_scanner = CommandPatternScanner()
        clean = ScanResult(found=False, scanner_name="mock")
        p._cred_scanner = MagicMock()
        p._cred_scanner.scan.return_value = clean
        p._path_scanner = MagicMock()
        p._path_scanner.scan_output_text.return_value = clean
        p._encoding_scanner = MagicMock()
        p._encoding_scanner.scan_output_text.return_value = clean
        return p

    def test_display_output_with_cmd_pattern_passes(self, pipeline):
        """Educational content with command patterns passes on DISPLAY path."""
        text = "To set the setuid bit, use:\n```bash\nchmod u+s /usr/local/bin/myapp\n```"
        result = pipeline.scan_output(text, destination=OutputDestination.DISPLAY)
        assert result.is_clean

    def test_execution_output_with_cmd_pattern_blocks(self, pipeline):
        """Same content blocks on EXECUTION path."""
        text = "To set the setuid bit, use:\n```bash\nchmod u+s /usr/local/bin/myapp\n```"
        result = pipeline.scan_output(text, destination=OutputDestination.EXECUTION)
        assert not result.is_clean
        assert "command_pattern_scanner" in result.violations

    def test_display_still_blocks_credentials(self, pipeline):
        """CredentialScanner blocks even on DISPLAY."""
        pipeline._cred_scanner.scan.return_value = ScanResult(
            found=True, scanner_name="credential_scanner",
            matches=[ScanMatch(pattern_name="aws_access_key", matched_text="AKIAIOSFODNN7EXAMPLE")]
        )
        text = "Here is your key: AKIAIOSFODNN7EXAMPLE"
        result = pipeline.scan_output(text, destination=OutputDestination.DISPLAY)
        assert not result.is_clean
        assert "credential_scanner" in result.violations

    def test_display_cmd_scanner_result_present_but_clean(self, pipeline):
        """On DISPLAY, command_pattern_scanner result exists but has no matches."""
        text = "chmod u+s /usr/local/bin/myapp"
        result = pipeline.scan_output(text, destination=OutputDestination.DISPLAY)
        assert "command_pattern_scanner" in result.results
        assert not result.results["command_pattern_scanner"].found

    def test_log_contains_destination_field(self, pipeline):
        """Verify destination appears in scan_output log entry."""
        import logging
        with patch.object(logging.getLogger("sentinel.audit"), "info") as mock_log:
            pipeline.scan_output("hello world", destination=OutputDestination.DISPLAY)
            # Find the scan_output log call
            for call in mock_log.call_args_list:
                extra = call.kwargs.get("extra", {}) if call.kwargs else {}
                if extra.get("event") == "scan_output":
                    assert extra["destination"] == "display"
                    break
            else:
                pytest.fail("No scan_output log entry found")
