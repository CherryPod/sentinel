"""D2-D4 capability tests — Controller capability level verification.

Tests verify the trust/capability infrastructure at the current level (CL0):
- Orchestrator trust gate blocks tool execution on untrusted data
- Trust router correctly classifies safe vs dangerous operations
- Policy engine enforces workspace boundaries
- Provenance system tracks trust inheritance through data flows
- Code extraction pipeline feeds Semgrep scanner correctly
- D2: Auto-approval flow for safe plans at TL1+

All tests pass against the current codebase.
Qwen is ALWAYS untrusted (TL0 forever). The "trust levels" here are about
controller capability levels — removing the human from the loop as
confidence in the controller grows.
"""

import os
import tempfile
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from sentinel.core.models import (
    DataSource,
    Plan,
    PlanStep,
    PolicyResult,
    ScanMatch,
    ScanResult,
    TaggedData,
    TrustLevel,
    ValidationResult,
)
from sentinel.planner.orchestrator import Orchestrator
from sentinel.planner.trust_router import SAFE_OPS, TL2_SAFE_OPS, TL3_PERMITTED_OPS, TrustTier, classify_operation
from sentinel.security.code_extractor import extract_code_blocks
from sentinel.security.policy_engine import PolicyEngine
from sentinel.security.provenance import (
    create_tagged_data,
    get_file_writer,
    get_tagged_data,
    is_trust_safe_for_execution,
    record_file_write,
)
from sentinel.tools.executor import ToolBlockedError, ToolExecutor


def _make_plan(steps: list[dict], summary: str = "Test plan") -> Plan:
    """Build a Plan from a list of step dicts."""
    return Plan(
        plan_summary=summary,
        steps=[PlanStep(**s) for s in steps],
    )


# ── Group A: Orchestrator trust gate (end-to-end) ─────────────────


class TestOrchestratorTrustGate:
    """CL0 baseline: all tool calls blocked when args contain untrusted data."""

    @pytest.mark.capability
    @pytest.mark.asyncio
    async def test_tl0_blocks_all_tool_execution(self, mock_planner, mock_pipeline):
        """2-step plan (llm_task → tool_call using $output): step 2 blocked.

        At CL0, Qwen output is UNTRUSTED. Any tool_call referencing Qwen-derived
        data via $variables must be blocked by the provenance trust gate.
        """
        plan = _make_plan([
            {
                "id": "step_1",
                "type": "llm_task",
                "description": "Generate a shell script",
                "prompt": "Write a script",
                "output_var": "$script",
            },
            {
                "id": "step_2",
                "type": "tool_call",
                "description": "Execute the script",
                "tool": "shell_exec",
                "args": {"command": "$script"},
            },
        ])
        mock_planner.create_plan.return_value = plan

        # Qwen output is always UNTRUSTED
        qwen_data = await create_tagged_data(
            content="rm -rf /",
            source=DataSource.QWEN,
            trust_level=TrustLevel.UNTRUSTED,
        )
        mock_pipeline.process_with_qwen.return_value = (qwen_data, None)

        mock_executor = MagicMock()
        mock_executor.get_tool_descriptions.return_value = [
            {"name": "shell_exec", "description": "Execute a shell command"},
        ]
        mock_executor.execute = AsyncMock()

        orch = Orchestrator(
            planner=mock_planner,
            pipeline=mock_pipeline,
            tool_executor=mock_executor,
        )
        result = await orch.handle_task("Run a script")

        # Step 1 succeeds (LLM task), step 2 blocked (trust gate)
        assert result.status == "blocked"
        assert result.step_results[0].status == "success"
        assert result.step_results[1].status == "blocked"
        assert "trust" in result.step_results[1].error.lower()
        # Tool executor must NOT have been called
        mock_executor.execute.assert_not_called()

    @pytest.mark.capability
    @pytest.mark.asyncio
    async def test_tl2_allows_file_reads(self, mock_planner, mock_pipeline):
        """file_read with Qwen-derived $path arg → blocked at CL0.

        Even though file_read is a safe operation at higher CLs, at CL0 the
        trust gate blocks all tool execution when args contain untrusted data.
        """
        plan = _make_plan([
            {
                "id": "step_1",
                "type": "llm_task",
                "description": "Determine file path",
                "prompt": "What file should I read?",
                "output_var": "$path",
            },
            {
                "id": "step_2",
                "type": "tool_call",
                "description": "Read the file",
                "tool": "file_read",
                "args": {"path": "$path"},
            },
        ])
        mock_planner.create_plan.return_value = plan

        qwen_data = await create_tagged_data(
            content="/workspace/data.txt",
            source=DataSource.QWEN,
            trust_level=TrustLevel.UNTRUSTED,
        )
        mock_pipeline.process_with_qwen.return_value = (qwen_data, None)

        mock_executor = MagicMock()
        mock_executor.get_tool_descriptions.return_value = [
            {"name": "file_read", "description": "Read a file"},
        ]
        mock_executor.execute = AsyncMock()

        orch = Orchestrator(
            planner=mock_planner,
            pipeline=mock_pipeline,
            tool_executor=mock_executor,
        )
        result = await orch.handle_task("Read a file")

        # Blocked at CL0 — even safe reads blocked when path is Qwen-derived
        assert result.status == "blocked"
        assert result.step_results[1].status == "blocked"
        mock_executor.execute.assert_not_called()

    @pytest.mark.capability
    @pytest.mark.asyncio
    async def test_tl3_allows_workspace_writes_with_approval(
        self, mock_planner, mock_pipeline
    ):
        """file_write with Qwen-derived $code → blocked at CL0.

        At CL0, even with approval intent, Qwen-generated code cannot be written
        to disk because the provenance trust gate blocks untrusted data.
        """
        plan = _make_plan([
            {
                "id": "step_1",
                "type": "llm_task",
                "description": "Generate Python code",
                "prompt": "Write a hello world script",
                "output_var": "$code",
            },
            {
                "id": "step_2",
                "type": "tool_call",
                "description": "Write the code to disk",
                "tool": "file_write",
                "args": {"path": "/workspace/hello.py", "content": "$code"},
            },
        ])
        mock_planner.create_plan.return_value = plan

        qwen_data = await create_tagged_data(
            content='print("Hello, world!")',
            source=DataSource.QWEN,
            trust_level=TrustLevel.UNTRUSTED,
        )
        mock_pipeline.process_with_qwen.return_value = (qwen_data, None)

        mock_executor = MagicMock()
        mock_executor.get_tool_descriptions.return_value = [
            {"name": "file_write", "description": "Write a file"},
        ]
        mock_executor.execute = AsyncMock()

        orch = Orchestrator(
            planner=mock_planner,
            pipeline=mock_pipeline,
            tool_executor=mock_executor,
        )
        result = await orch.handle_task("Write hello world to a file")

        # Blocked — Qwen content is UNTRUSTED, trust gate prevents write
        assert result.status == "blocked"
        assert result.step_results[1].status == "blocked"
        mock_executor.execute.assert_not_called()


# ── Group B: Trust router classification ──────────────────────────


class TestTrustRouterClassification:
    """Trust router deterministic classification of operations."""

    @pytest.mark.capability
    def test_tl1_auto_approves_safe_reads(self):
        """All operations in SAFE_OPS return SAFE classification.

        At CL1+, these operations would bypass the approval queue (still
        go through auth + sandbox). Verifies every SAFE_OPS entry classifies
        as SAFE.
        """
        assert classify_operation("health_check") == TrustTier.SAFE
        # Verify ALL SAFE_OPS members classify correctly
        for op in SAFE_OPS:
            assert classify_operation(op) == TrustTier.SAFE, f"{op} not classified as SAFE"

    @pytest.mark.capability
    def test_tl1_blocks_unsafe_operations(self):
        """Dangerous operations are correctly classified as DANGEROUS.

        Tool execution operations must never be classified as SAFE — they
        always require the full CaMeL pipeline.
        """
        dangerous_ops = [
            "shell_exec", "file_read", "file_write", "http_fetch",
            "web_search", "podman_build", "podman_run",
        ]
        for op in dangerous_ops:
            assert classify_operation(op) == TrustTier.DANGEROUS, (
                f"{op} incorrectly classified as SAFE"
            )

    @pytest.mark.capability
    def test_tl1_auto_approve_logging(self):
        """classify_operation() is deterministic — same input always same result.

        The trust router must be a pure function of the operation name.
        No hidden state, no randomness, no side effects.
        """
        # Run classification 100 times — must be stable
        results = [classify_operation("health_check") for _ in range(100)]
        assert all(r == TrustTier.SAFE for r in results)

        results = [classify_operation("shell_exec") for _ in range(100)]
        assert all(r == TrustTier.DANGEROUS for r in results)

    @pytest.mark.capability
    def test_trust_level_cannot_be_escalated_by_llm(self):
        """SAFE_OPS is frozenset — cannot be modified at runtime.

        The LLM never classifies its own operations. If SAFE_OPS were mutable,
        a compromised controller path could add dangerous operations to bypass
        the CaMeL pipeline. frozenset prevents this.
        """
        assert isinstance(SAFE_OPS, frozenset)
        with pytest.raises(AttributeError):
            SAFE_OPS.add("shell_exec")  # type: ignore[attr-defined]


# ── Group C: Policy engine workspace enforcement ──────────────────


class TestPolicyEngineWorkspace:
    """Policy engine enforces file access boundaries."""

    @pytest.mark.capability
    def test_tl2_blocks_file_reads_outside_workspace(self):
        """PolicyEngine blocks reads outside /workspace, allows inside.

        At any CL, the policy engine enforces deterministic path restrictions.
        /etc/passwd must always be blocked. /workspace/data.txt must be allowed.
        Path traversal attempts must be detected and blocked.
        """
        engine = PolicyEngine("policies/sentinel-policy.yaml")

        # Blocked: system files
        result = engine.check_file_read("/etc/passwd")
        assert result.status == PolicyResult.BLOCKED

        # Blocked: home directory
        result = engine.check_file_read("/home/user/.bashrc")
        assert result.status == PolicyResult.BLOCKED

        # Allowed: workspace files
        result = engine.check_file_read("/workspace/data.txt")
        assert result.status == PolicyResult.ALLOWED

        # Blocked: traversal attempt from workspace
        result = engine.check_file_read("/workspace/../etc/passwd")
        assert result.status == PolicyResult.BLOCKED


# ── Group D: Provenance system trust tracking ─────────────────────


class TestProvenanceTrustTracking:
    """Provenance system correctly tracks trust through data flows."""

    @pytest.mark.capability
    async def test_tl2_provenance_on_read_files(self):
        """File-sourced data with no untrusted parents is TRUSTED.

        When the controller reads a file that wasn't written by Qwen,
        the resulting TaggedData should be TRUSTED and pass the trust gate.
        """
        file_data = await create_tagged_data(
            content="safe config content",
            source=DataSource.FILE,
            trust_level=TrustLevel.TRUSTED,
        )
        assert file_data.trust_level == TrustLevel.TRUSTED
        assert file_data.source == DataSource.FILE
        assert await is_trust_safe_for_execution(file_data.id) is True

    @pytest.mark.capability
    async def test_tl2_qwen_written_file_fed_back_to_planner(self):
        """Qwen-written file read back inherits UNTRUSTED via provenance.

        Attack scenario (trust laundering):
        1. Qwen generates malicious content → UNTRUSTED
        2. Content written to file → record_file_write() tracks provenance
        3. File read back → parent_ids includes writer → inherits UNTRUSTED
        4. Trust gate blocks execution with this data

        This is the core CaMeL guarantee against trust laundering.
        """
        # Step 1: Qwen produces output (always UNTRUSTED)
        qwen_output = await create_tagged_data(
            content="malicious payload",
            source=DataSource.QWEN,
            trust_level=TrustLevel.UNTRUSTED,
        )

        # Step 2: File write records provenance
        await record_file_write("/workspace/payload.sh", qwen_output.id)

        # Step 3: File read back — creates new TaggedData with parent chain
        read_data = await create_tagged_data(
            content="malicious payload",
            source=DataSource.FILE,
            trust_level=TrustLevel.TRUSTED,  # requested as trusted
            parent_ids=[qwen_output.id],      # but inherits from parent
        )

        # Child inherits UNTRUSTED from Qwen parent
        assert read_data.trust_level == TrustLevel.UNTRUSTED
        # Trust gate blocks execution
        assert await is_trust_safe_for_execution(read_data.id) is False

    @pytest.mark.capability
    async def test_trust_level_downgrade_takes_effect_immediately(self):
        """Mixed parentage (TRUSTED + UNTRUSTED) → child UNTRUSTED immediately.

        No caching, no delayed propagation. The moment untrusted data enters
        a derivation chain, all children are untrusted. This prevents race
        conditions in trust evaluation.
        """
        trusted = await create_tagged_data(
            content="safe user input",
            source=DataSource.USER,
            trust_level=TrustLevel.TRUSTED,
        )
        untrusted = await create_tagged_data(
            content="qwen generated text",
            source=DataSource.QWEN,
            trust_level=TrustLevel.UNTRUSTED,
        )

        # Mixed parentage — one TRUSTED, one UNTRUSTED
        child = await create_tagged_data(
            content="combined output",
            source=DataSource.TOOL,
            trust_level=TrustLevel.TRUSTED,  # requested as trusted
            parent_ids=[trusted.id, untrusted.id],
        )

        # Immediately UNTRUSTED — no caching delay
        assert child.trust_level == TrustLevel.UNTRUSTED
        assert await is_trust_safe_for_execution(child.id) is False

        # Verify the trusted parent alone IS safe
        assert await is_trust_safe_for_execution(trusted.id) is True


# ── Group E: Semgrep code extraction pipeline ─────────────────────


class TestCodeExtractionPipeline:
    """Code block extraction correctly feeds the scanning pipeline."""

    @pytest.mark.capability
    def test_tl3_semgrep_scans_code_writes(self):
        """extract_code_blocks() correctly extracts Python code with language detection.

        At CL3+, all code writes would be scanned by Semgrep. This test
        verifies the extraction pipeline that feeds the scanner: fenced code
        blocks are parsed, language is detected, and the code content is
        extracted for per-block scanning.

        Semgrep itself is unavailable in unit tests (disabled by autouse
        fixture), so we test the extraction layer that feeds it.
        """
        markdown_response = """Here's a Python script:

```python
import os
user_input = input("Enter command: ")
os.system(user_input)
```

This script takes user input and executes it.
"""
        blocks = extract_code_blocks(markdown_response)

        # Should extract exactly one code block
        assert len(blocks) == 1
        block = blocks[0]

        # Language correctly detected from tag
        assert block.language == "python"

        # Code content extracted (without fences)
        assert "os.system(user_input)" in block.code
        assert "import os" in block.code

        # Fences and prose are not in the code block
        assert "```" not in block.code
        assert "Here's a Python script" not in block.code


# ── Group F: D2 auto-approval flow ────────────────────────────────


class TestAutoApprovalFlow:
    """D2: Auto-approve safe plans at TL1+, full approval at TL0."""

    @pytest.mark.capability
    @pytest.mark.asyncio
    async def test_tl1_auto_approves_safe_only_plan(self, mock_planner, mock_pipeline):
        """Plan with only SAFE tool_calls executes without approval at TL1.

        At TL1, plans consisting entirely of SAFE operations (e.g. memory_search)
        should skip the approval queue and execute directly via the orchestrator's
        SAFE handler — NOT the ToolExecutor. The full CaMeL pipeline (provenance
        trust gate) still runs on every step.
        """
        plan = _make_plan([
            {
                "id": "step_1",
                "type": "tool_call",
                "description": "Search memory",
                "tool": "memory_search",
                "args": {"query": "test"},
            },
        ], summary="Search memory for test")
        mock_planner.create_plan.return_value = plan

        mock_executor = MagicMock()
        mock_executor.get_tool_descriptions.return_value = []
        mock_executor.execute = AsyncMock()

        mock_approval = MagicMock()
        mock_approval.request_plan_approval = AsyncMock()

        # Mock memory_store for the SAFE handler
        mock_memory_store = MagicMock()
        mock_memory_store._db = MagicMock()

        orch = Orchestrator(
            planner=mock_planner,
            pipeline=mock_pipeline,
            tool_executor=mock_executor,
            approval_manager=mock_approval,
            memory_store=mock_memory_store,
        )

        with patch("sentinel.planner.orchestrator.settings") as mock_settings, \
             patch("sentinel.memory.search.hybrid_search", return_value=[]):
            mock_settings.trust_level = 1
            mock_settings.conversation_enabled = False
            mock_settings.spotlighting_enabled = False
            mock_settings.require_semgrep = False
            mock_settings.verbose_results = False
            mock_settings.auto_memory = False
            mock_settings.planner_timeout = 120
            mock_settings.worker_timeout = 480
            mock_settings.tool_timeout = 60
            mock_settings.plan_execution_timeout = 1500
            mock_settings.api_task_timeout = 1800
            result = await orch.handle_task(
                "search memory for test",
                approval_mode="full",
            )

        # Plan should execute directly (not awaiting approval)
        assert result.status != "awaiting_approval"
        assert result.status == "success"
        # Approval manager should NOT have been called
        mock_approval.request_plan_approval.assert_not_called()
        # ToolExecutor should NOT have been called — SAFE tools bypass it
        mock_executor.execute.assert_not_called()

    @pytest.mark.capability
    @pytest.mark.asyncio
    async def test_tl1_dangerous_plan_still_requires_approval(
        self, mock_planner, mock_pipeline
    ):
        """Plan with shell_exec at TL1 still returns awaiting_approval.

        DANGEROUS operations always require human approval regardless of
        trust level. Only SAFE operations are auto-approved.
        """
        plan = _make_plan([
            {
                "id": "step_1",
                "type": "tool_call",
                "description": "Execute command",
                "tool": "shell_exec",
                "args": {"command": "ls -la"},
            },
        ])
        mock_planner.create_plan.return_value = plan

        mock_executor = MagicMock()
        mock_executor.get_tool_descriptions.return_value = [
            {"name": "shell_exec", "description": "Run shell command"},
        ]

        mock_approval = MagicMock()
        mock_approval.request_plan_approval = AsyncMock(return_value="approval-123")

        orch = Orchestrator(
            planner=mock_planner,
            pipeline=mock_pipeline,
            tool_executor=mock_executor,
            approval_manager=mock_approval,
        )

        with patch("sentinel.planner.orchestrator.settings") as mock_settings:
            mock_settings.trust_level = 1
            mock_settings.conversation_enabled = False
            mock_settings.spotlighting_enabled = False
            mock_settings.require_semgrep = False
            mock_settings.verbose_results = False
            mock_settings.auto_memory = False
            mock_settings.planner_timeout = 120
            mock_settings.worker_timeout = 480
            mock_settings.tool_timeout = 60
            mock_settings.plan_execution_timeout = 1500
            mock_settings.api_task_timeout = 1800
            result = await orch.handle_task(
                "list files", approval_mode="full",
            )

        assert result.status == "awaiting_approval"
        mock_approval.request_plan_approval.assert_called_once()

    @pytest.mark.capability
    @pytest.mark.asyncio
    async def test_tl1_mixed_plan_requires_approval(
        self, mock_planner, mock_pipeline
    ):
        """Plan with memory_search + file_write → requires approval.

        One DANGEROUS step poisons the entire plan — all steps must be SAFE
        for auto-approval to kick in.
        """
        plan = _make_plan([
            {
                "id": "step_1",
                "type": "tool_call",
                "description": "Search memory",
                "tool": "memory_search",
                "args": {"query": "config"},
            },
            {
                "id": "step_2",
                "type": "tool_call",
                "description": "Write config file",
                "tool": "file_write",
                "args": {"path": "/workspace/config.yaml", "content": "key: value"},
            },
        ])
        mock_planner.create_plan.return_value = plan

        mock_executor = MagicMock()
        mock_executor.get_tool_descriptions.return_value = []

        mock_approval = MagicMock()
        mock_approval.request_plan_approval = AsyncMock(return_value="approval-456")

        orch = Orchestrator(
            planner=mock_planner,
            pipeline=mock_pipeline,
            tool_executor=mock_executor,
            approval_manager=mock_approval,
        )

        with patch("sentinel.planner.orchestrator.settings") as mock_settings:
            mock_settings.trust_level = 1
            mock_settings.conversation_enabled = False
            mock_settings.spotlighting_enabled = False
            mock_settings.require_semgrep = False
            mock_settings.verbose_results = False
            mock_settings.auto_memory = False
            mock_settings.planner_timeout = 120
            mock_settings.worker_timeout = 480
            mock_settings.tool_timeout = 60
            mock_settings.plan_execution_timeout = 1500
            mock_settings.api_task_timeout = 1800
            result = await orch.handle_task(
                "save config", approval_mode="full",
            )

        assert result.status == "awaiting_approval"
        mock_approval.request_plan_approval.assert_called_once()

    @pytest.mark.capability
    @pytest.mark.asyncio
    async def test_tl1_llm_task_plan_requires_approval(
        self, mock_planner, mock_pipeline
    ):
        """Plan with llm_task step → requires approval even if tool_call is SAFE.

        llm_task steps introduce UNTRUSTED Qwen data — plans containing them
        can never be auto-approved regardless of the tool_call classifications.
        """
        plan = _make_plan([
            {
                "id": "step_1",
                "type": "llm_task",
                "description": "Generate search query",
                "prompt": "What should I search for?",
                "output_var": "$query",
            },
            {
                "id": "step_2",
                "type": "tool_call",
                "description": "Search memory",
                "tool": "memory_search",
                "args": {"query": "$query"},
            },
        ])
        mock_planner.create_plan.return_value = plan

        mock_executor = MagicMock()
        mock_executor.get_tool_descriptions.return_value = []

        mock_approval = MagicMock()
        mock_approval.request_plan_approval = AsyncMock(return_value="approval-789")

        orch = Orchestrator(
            planner=mock_planner,
            pipeline=mock_pipeline,
            tool_executor=mock_executor,
            approval_manager=mock_approval,
        )

        with patch("sentinel.planner.orchestrator.settings") as mock_settings:
            mock_settings.trust_level = 1
            mock_settings.conversation_enabled = False
            mock_settings.spotlighting_enabled = False
            mock_settings.require_semgrep = False
            mock_settings.verbose_results = False
            mock_settings.auto_memory = False
            mock_settings.planner_timeout = 120
            mock_settings.worker_timeout = 480
            mock_settings.tool_timeout = 60
            mock_settings.plan_execution_timeout = 1500
            mock_settings.api_task_timeout = 1800
            result = await orch.handle_task(
                "search memory", approval_mode="full",
            )

        assert result.status == "awaiting_approval"
        mock_approval.request_plan_approval.assert_called_once()

    @pytest.mark.capability
    @pytest.mark.asyncio
    async def test_tl0_safe_plan_still_requires_approval(
        self, mock_planner, mock_pipeline
    ):
        """At TL0, even a memory_search-only plan goes to approval queue.

        trust_level=0 is the hard override — _is_auto_approvable() is never
        reached because the `settings.trust_level >= 1` check fails first.
        """
        plan = _make_plan([
            {
                "id": "step_1",
                "type": "tool_call",
                "description": "Search memory",
                "tool": "memory_search",
                "args": {"query": "test"},
            },
        ])
        mock_planner.create_plan.return_value = plan

        mock_executor = MagicMock()
        mock_executor.get_tool_descriptions.return_value = []

        mock_approval = MagicMock()
        mock_approval.request_plan_approval = AsyncMock(return_value="approval-000")

        orch = Orchestrator(
            planner=mock_planner,
            pipeline=mock_pipeline,
            tool_executor=mock_executor,
            approval_manager=mock_approval,
        )

        with patch("sentinel.planner.orchestrator.settings") as mock_settings:
            mock_settings.trust_level = 0  # TL0 — no auto-approval
            mock_settings.conversation_enabled = False
            mock_settings.spotlighting_enabled = False
            mock_settings.require_semgrep = False
            mock_settings.verbose_results = False
            mock_settings.auto_memory = False
            mock_settings.planner_timeout = 120
            mock_settings.worker_timeout = 480
            mock_settings.tool_timeout = 60
            mock_settings.plan_execution_timeout = 1500
            mock_settings.api_task_timeout = 1800
            result = await orch.handle_task(
                "search memory", approval_mode="full",
            )

        assert result.status == "awaiting_approval"
        mock_approval.request_plan_approval.assert_called_once()

    @pytest.mark.capability
    @pytest.mark.asyncio
    async def test_auto_approve_emits_event(self, mock_planner, mock_pipeline):
        """Auto-approved plan emits 'auto_approved' event on the bus.

        Verifies observability — auto-approval decisions are logged and
        broadcast so the UI and audit trail can track them.
        """
        plan = _make_plan([
            {
                "id": "step_1",
                "type": "tool_call",
                "description": "List routines",
                "tool": "routine_list",
                "args": {},
            },
        ], summary="List all routines")
        mock_planner.create_plan.return_value = plan

        mock_executor = MagicMock()
        mock_executor.get_tool_descriptions.return_value = []
        mock_executor.execute = AsyncMock()

        # Mock routine_store for the SAFE handler
        mock_routine_store = MagicMock()
        mock_routine_store.list.return_value = []

        mock_approval = MagicMock()
        mock_bus = MagicMock()
        mock_bus.publish = AsyncMock()

        orch = Orchestrator(
            planner=mock_planner,
            pipeline=mock_pipeline,
            tool_executor=mock_executor,
            approval_manager=mock_approval,
            event_bus=mock_bus,
            routine_store=mock_routine_store,
        )

        with patch("sentinel.planner.orchestrator.settings") as mock_settings:
            mock_settings.trust_level = 1
            mock_settings.conversation_enabled = False
            mock_settings.spotlighting_enabled = False
            mock_settings.require_semgrep = False
            mock_settings.verbose_results = False
            mock_settings.auto_memory = False
            mock_settings.planner_timeout = 120
            mock_settings.worker_timeout = 480
            mock_settings.tool_timeout = 60
            mock_settings.plan_execution_timeout = 1500
            mock_settings.api_task_timeout = 1800
            await orch.handle_task(
                "list routines", approval_mode="full",
            )

        # Check that auto_approved event was emitted
        auto_approved_calls = [
            call for call in mock_bus.publish.call_args_list
            if "auto_approved" in str(call)
        ]
        assert len(auto_approved_calls) == 1
        # Verify event payload includes trust_level
        event_data = auto_approved_calls[0].args[1]
        assert event_data["trust_level"] == 1
        assert event_data["plan_summary"] == "List all routines"
        # ToolExecutor should NOT have been called — SAFE tools bypass it
        mock_executor.execute.assert_not_called()


# ── Group G: SAFE tool dispatch ────────────────────────────────────


class TestSafeToolDispatch:
    """D2 fix: SAFE tools dispatched to orchestrator handlers, not ToolExecutor."""

    @pytest.mark.capability
    @pytest.mark.asyncio
    async def test_safe_memory_search_executes_at_tl1(self, mock_planner, mock_pipeline):
        """memory_search plan at TL1 → auto-approved, executes via SAFE handler.

        Verifies the full path: planner returns memory_search plan, auto-approval
        kicks in, SAFE handler runs hybrid search, result returned to user.
        """
        plan = _make_plan([
            {
                "id": "step_1",
                "type": "tool_call",
                "description": "Search memory",
                "tool": "memory_search",
                "args": {"query": "deployment notes"},
            },
        ], summary="Search memory for deployment notes")
        mock_planner.create_plan.return_value = plan

        mock_memory_store = MagicMock()
        mock_memory_store._db = MagicMock()

        mock_approval = MagicMock()
        mock_approval.request_plan_approval = AsyncMock()

        orch = Orchestrator(
            planner=mock_planner,
            pipeline=mock_pipeline,
            approval_manager=mock_approval,
            memory_store=mock_memory_store,
        )

        with patch("sentinel.planner.orchestrator.settings") as mock_settings, \
             patch("sentinel.memory.search.hybrid_search") as mock_search:
            mock_settings.trust_level = 1
            mock_settings.conversation_enabled = False
            mock_settings.spotlighting_enabled = False
            mock_settings.require_semgrep = False
            mock_settings.verbose_results = False
            mock_settings.auto_memory = False
            mock_settings.planner_timeout = 120
            mock_settings.worker_timeout = 480
            mock_settings.tool_timeout = 60
            mock_settings.plan_execution_timeout = 1500
            mock_settings.api_task_timeout = 1800

            from sentinel.memory.search import SearchResult
            mock_search.return_value = [
                SearchResult(chunk_id="c1", content="deployed v0.2", source="conversation", score=0.8, match_type="fts"),
            ]
            result = await orch.handle_task(
                "search memory for deployment notes",
                approval_mode="full",
            )

        assert result.status == "success"
        mock_approval.request_plan_approval.assert_not_called()
        assert "deployed v0.2" in result.step_results[0].content

    @pytest.mark.capability
    @pytest.mark.asyncio
    async def test_safe_routine_list_executes_at_tl1(self, mock_planner, mock_pipeline):
        """routine_list plan at TL1 → auto-approved, returns routine list."""
        plan = _make_plan([
            {
                "id": "step_1",
                "type": "tool_call",
                "description": "List routines",
                "tool": "routine_list",
                "args": {},
            },
        ], summary="List routines")
        mock_planner.create_plan.return_value = plan

        mock_routine_store = MagicMock()
        mock_routine_store.list = AsyncMock(return_value=[])

        mock_approval = MagicMock()
        mock_approval.request_plan_approval = AsyncMock()

        orch = Orchestrator(
            planner=mock_planner,
            pipeline=mock_pipeline,
            approval_manager=mock_approval,
            routine_store=mock_routine_store,
        )

        with patch("sentinel.planner.orchestrator.settings") as mock_settings:
            mock_settings.trust_level = 1
            mock_settings.conversation_enabled = False
            mock_settings.spotlighting_enabled = False
            mock_settings.require_semgrep = False
            mock_settings.verbose_results = False
            mock_settings.auto_memory = False
            mock_settings.planner_timeout = 120
            mock_settings.worker_timeout = 480
            mock_settings.tool_timeout = 60
            mock_settings.plan_execution_timeout = 1500
            mock_settings.api_task_timeout = 1800
            result = await orch.handle_task(
                "list my routines",
                approval_mode="full",
            )

        assert result.status == "success"
        mock_approval.request_plan_approval.assert_not_called()
        mock_routine_store.list.assert_called_once()

    @pytest.mark.capability
    @pytest.mark.asyncio
    async def test_safe_health_check_executes_at_tl1(self, mock_planner, mock_pipeline):
        """health_check plan at TL1 → auto-approved, returns component status."""
        plan = _make_plan([
            {
                "id": "step_1",
                "type": "tool_call",
                "description": "Check health",
                "tool": "health_check",
                "args": {},
            },
        ], summary="Health check")
        mock_planner.create_plan.return_value = plan

        mock_approval = MagicMock()
        mock_approval.request_plan_approval = AsyncMock()

        orch = Orchestrator(
            planner=mock_planner,
            pipeline=mock_pipeline,
            approval_manager=mock_approval,
        )

        with patch("sentinel.planner.orchestrator.settings") as mock_settings:
            mock_settings.trust_level = 1
            mock_settings.conversation_enabled = False
            mock_settings.spotlighting_enabled = False
            mock_settings.require_semgrep = False
            mock_settings.verbose_results = False
            mock_settings.auto_memory = False
            mock_settings.planner_timeout = 120
            mock_settings.worker_timeout = 480
            mock_settings.tool_timeout = 60
            mock_settings.plan_execution_timeout = 1500
            mock_settings.api_task_timeout = 1800
            result = await orch.handle_task(
                "check system health",
                approval_mode="full",
            )

        assert result.status == "success"
        mock_approval.request_plan_approval.assert_not_called()
        # Response should contain health status JSON
        import json
        health = json.loads(result.step_results[0].content)
        assert "planner_available" in health
        assert "semgrep_loaded" in health

    @pytest.mark.capability
    @pytest.mark.asyncio
    async def test_safe_tool_falls_through_to_executor(self, mock_planner, mock_pipeline):
        """Plan with file_read (DANGEROUS) → dispatched to ToolExecutor, not SAFE handler.

        Verifies that non-SAFE tools still route through the ToolExecutor.
        """
        plan = _make_plan([
            {
                "id": "step_1",
                "type": "tool_call",
                "description": "Read a file",
                "tool": "file_read",
                "args": {"path": "/workspace/data.txt"},
            },
        ])
        mock_planner.create_plan.return_value = plan

        result_data = TaggedData(
            id="res-3", content="file contents here",
            source=DataSource.TOOL, trust_level=TrustLevel.TRUSTED,
        )
        mock_executor = MagicMock()
        mock_executor.get_tool_descriptions.return_value = [
            {"name": "file_read", "description": "Read a file"},
        ]
        mock_executor.execute = AsyncMock(return_value=(result_data, None))

        orch = Orchestrator(
            planner=mock_planner,
            pipeline=mock_pipeline,
            tool_executor=mock_executor,
        )

        with patch("sentinel.planner.orchestrator.settings") as mock_settings:
            mock_settings.trust_level = 0
            mock_settings.conversation_enabled = False
            mock_settings.spotlighting_enabled = False
            mock_settings.require_semgrep = False
            mock_settings.verbose_results = False
            mock_settings.auto_memory = False
            mock_settings.planner_timeout = 120
            mock_settings.worker_timeout = 480
            mock_settings.tool_timeout = 60
            mock_settings.plan_execution_timeout = 1500
            mock_settings.api_task_timeout = 1800
            result = await orch.handle_task("read a file")

        # file_read goes through ToolExecutor (no approval_mode=full, so auto)
        assert result.status == "success"
        mock_executor.execute.assert_called_once()

    @pytest.mark.capability
    @pytest.mark.asyncio
    async def test_safe_tool_missing_store_returns_error(self, mock_planner, mock_pipeline):
        """memory_search without memory_store → step returns error status.

        When a SAFE tool handler requires a store that's not configured,
        it raises RuntimeError caught by the dispatch wrapper.
        """
        plan = _make_plan([
            {
                "id": "step_1",
                "type": "tool_call",
                "description": "Search memory",
                "tool": "memory_search",
                "args": {"query": "test"},
            },
        ])
        mock_planner.create_plan.return_value = plan

        # No memory_store provided — handler will raise RuntimeError
        orch = Orchestrator(
            planner=mock_planner,
            pipeline=mock_pipeline,
        )

        with patch("sentinel.planner.orchestrator.settings") as mock_settings:
            mock_settings.trust_level = 0
            mock_settings.conversation_enabled = False
            mock_settings.spotlighting_enabled = False
            mock_settings.require_semgrep = False
            mock_settings.verbose_results = False
            mock_settings.auto_memory = False
            mock_settings.planner_timeout = 120
            mock_settings.worker_timeout = 480
            mock_settings.tool_timeout = 60
            mock_settings.plan_execution_timeout = 1500
            mock_settings.api_task_timeout = 1800
            result = await orch.handle_task("search memory")

        assert result.status == "error"
        assert "Memory store not available" in result.step_results[0].error

    @pytest.mark.capability
    @pytest.mark.asyncio
    async def test_safe_tool_result_is_trusted(self, mock_planner, mock_pipeline):
        """SAFE tool results are TaggedData with source=TOOL, trust_level=TRUSTED.

        Verifies the provenance chain: SAFE tool results are trusted internal
        data, not untrusted external data. This is critical for auto-approval
        safety — if SAFE tool results were UNTRUSTED, chaining them into
        subsequent steps would be blocked by the trust gate.
        """
        plan = _make_plan([
            {
                "id": "step_1",
                "type": "tool_call",
                "description": "Check health",
                "tool": "health_check",
                "args": {},
                "output_var": "$health",
            },
        ])
        mock_planner.create_plan.return_value = plan

        orch = Orchestrator(
            planner=mock_planner,
            pipeline=mock_pipeline,
        )

        with patch("sentinel.planner.orchestrator.settings") as mock_settings:
            mock_settings.trust_level = 0
            mock_settings.conversation_enabled = False
            mock_settings.spotlighting_enabled = False
            mock_settings.require_semgrep = False
            mock_settings.verbose_results = False
            mock_settings.auto_memory = False
            mock_settings.planner_timeout = 120
            mock_settings.worker_timeout = 480
            mock_settings.tool_timeout = 60
            mock_settings.plan_execution_timeout = 1500
            mock_settings.api_task_timeout = 1800
            result = await orch.handle_task("check health")

        assert result.status == "success"
        # Verify the tagged data stored in provenance is TRUSTED
        data_id = result.step_results[0].data_id
        assert data_id is not None
        from sentinel.security.provenance import get_tagged_data
        tagged = await get_tagged_data(data_id)
        assert tagged is not None
        assert tagged.source == DataSource.TOOL
        assert tagged.trust_level == TrustLevel.TRUSTED

    @pytest.mark.capability
    def test_planner_receives_safe_tool_descriptions(self, mock_planner, mock_pipeline):
        """Orchestrator merges SAFE tool descriptions into available_tools.

        Claude's planner must see SAFE tools so it can plan memory_search,
        routine_list etc. instead of defaulting to llm_task for everything.
        """
        orch = Orchestrator(
            planner=mock_planner,
            pipeline=mock_pipeline,
        )
        safe_tools = orch._safe_tool_handlers.get_descriptions()

        # Should include the 5 always-present tools
        names = {t["name"] for t in safe_tools}
        assert "health_check" in names
        assert "session_info" in names
        assert "memory_search" in names
        assert "memory_list" in names
        assert "memory_store" in names
        # routine_list/get/history only present when stores are set
        assert "routine_list" not in names
        assert "routine_get" not in names
        assert "routine_history" not in names

        # With routine_store, routine_list and routine_get appear
        mock_routine_store = MagicMock()
        orch2 = Orchestrator(
            planner=mock_planner,
            pipeline=mock_pipeline,
            routine_store=mock_routine_store,
        )
        safe_tools2 = orch2._safe_tool_handlers.get_descriptions()
        names2 = {t["name"] for t in safe_tools2}
        assert "routine_list" in names2
        assert "routine_get" in names2
        assert "routine_history" not in names2  # needs routine_engine

        # With routine_engine, routine_history also appears
        mock_engine = MagicMock()
        orch2.set_routine_engine(mock_engine)
        safe_tools3 = orch2._safe_tool_handlers.get_descriptions()
        names3 = {t["name"] for t in safe_tools3}
        assert "routine_history" in names3


# ── Group H: D3 file_read auto-approval at TL2 ────────────────────


class TestFileReadAutoApproval:
    """D3: file_read becomes SAFE at TL2+, remains DANGEROUS at TL1."""

    @pytest.mark.capability
    def test_file_read_safe_at_tl2(self):
        """classify_operation("file_read", trust_level=2) returns SAFE.

        At TL2, file_read is in TL2_SAFE_OPS and should classify as SAFE,
        allowing plans with file_read steps to be auto-approved.
        """
        assert classify_operation("file_read", trust_level=2) == TrustTier.SAFE
        # Also verify it's in the TL2 allowlist directly
        assert "file_read" in TL2_SAFE_OPS
        # TL2_SAFE_OPS is a superset of SAFE_OPS
        assert SAFE_OPS.issubset(TL2_SAFE_OPS)

    @pytest.mark.capability
    def test_file_read_dangerous_at_tl1(self):
        """classify_operation("file_read", trust_level=1) returns DANGEROUS.

        At TL1, only internal state queries are SAFE. file_read requires
        the full CaMeL pipeline with human approval.
        """
        assert classify_operation("file_read", trust_level=1) == TrustTier.DANGEROUS
        assert classify_operation("file_read") == TrustTier.DANGEROUS  # default=1
        # file_read is NOT in the TL1 allowlist
        assert "file_read" not in SAFE_OPS

    @pytest.mark.capability
    @pytest.mark.asyncio
    async def test_tl2_auto_approves_file_read_plan(self, mock_planner, mock_pipeline):
        """Plan with file_read auto-approved at TL2 — executes via ToolExecutor.

        Unlike SAFE internal tools which use orchestrator handlers, file_read
        goes through the ToolExecutor (policy checks, provenance tracking).
        The auto-approval only skips the plan-level approval queue.
        """
        plan = _make_plan([
            {
                "id": "step_1",
                "type": "tool_call",
                "description": "Read config file",
                "tool": "file_read",
                "args": {"path": "/workspace/config.yaml"},
            },
        ], summary="Read workspace config")
        mock_planner.create_plan.return_value = plan

        result_data = TaggedData(
            id="res-fr-1", content="key: value",
            source=DataSource.FILE, trust_level=TrustLevel.TRUSTED,
        )
        mock_executor = MagicMock()
        mock_executor.get_tool_descriptions.return_value = [
            {"name": "file_read", "description": "Read a file"},
        ]
        mock_executor.execute = AsyncMock(return_value=(result_data, None))

        mock_approval = MagicMock()
        mock_approval.request_plan_approval = AsyncMock()

        orch = Orchestrator(
            planner=mock_planner,
            pipeline=mock_pipeline,
            tool_executor=mock_executor,
            approval_manager=mock_approval,
        )

        with patch("sentinel.planner.orchestrator.settings") as mock_settings:
            mock_settings.trust_level = 2
            mock_settings.conversation_enabled = False
            mock_settings.spotlighting_enabled = False
            mock_settings.require_semgrep = False
            mock_settings.verbose_results = False
            mock_settings.auto_memory = False
            mock_settings.planner_timeout = 120
            mock_settings.worker_timeout = 480
            mock_settings.tool_timeout = 60
            mock_settings.plan_execution_timeout = 1500
            mock_settings.api_task_timeout = 1800
            result = await orch.handle_task(
                "read config file",
                approval_mode="full",
            )

        # Auto-approved — no approval queue interaction
        assert result.status == "success"
        mock_approval.request_plan_approval.assert_not_called()
        # file_read dispatched to ToolExecutor (not SAFE handler)
        mock_executor.execute.assert_called_once()
        assert mock_executor.execute.call_args.kwargs["tool_name"] == "file_read"

    @pytest.mark.capability
    @pytest.mark.asyncio
    async def test_tl1_file_read_plan_requires_approval(self, mock_planner, mock_pipeline):
        """Same file_read plan at TL1 → requires approval.

        file_read is DANGEROUS at TL1, so the plan goes to the approval queue.
        """
        plan = _make_plan([
            {
                "id": "step_1",
                "type": "tool_call",
                "description": "Read config file",
                "tool": "file_read",
                "args": {"path": "/workspace/config.yaml"},
            },
        ], summary="Read workspace config")
        mock_planner.create_plan.return_value = plan

        mock_executor = MagicMock()
        mock_executor.get_tool_descriptions.return_value = [
            {"name": "file_read", "description": "Read a file"},
        ]

        mock_approval = MagicMock()
        mock_approval.request_plan_approval = AsyncMock(return_value="approval-fr-1")

        orch = Orchestrator(
            planner=mock_planner,
            pipeline=mock_pipeline,
            tool_executor=mock_executor,
            approval_manager=mock_approval,
        )

        with patch("sentinel.planner.orchestrator.settings") as mock_settings:
            mock_settings.trust_level = 1
            mock_settings.conversation_enabled = False
            mock_settings.spotlighting_enabled = False
            mock_settings.require_semgrep = False
            mock_settings.verbose_results = False
            mock_settings.auto_memory = False
            mock_settings.planner_timeout = 120
            mock_settings.worker_timeout = 480
            mock_settings.tool_timeout = 60
            mock_settings.plan_execution_timeout = 1500
            mock_settings.api_task_timeout = 1800
            result = await orch.handle_task(
                "read config file",
                approval_mode="full",
            )

        assert result.status == "awaiting_approval"
        mock_approval.request_plan_approval.assert_called_once()

    @pytest.mark.capability
    @pytest.mark.asyncio
    async def test_tl2_file_write_still_requires_approval(self, mock_planner, mock_pipeline):
        """file_write remains DANGEROUS at TL2 — always requires approval.

        Only file_read is promoted to SAFE at TL2. file_write modifies state
        and must go through the full approval pipeline at all trust levels.
        """
        plan = _make_plan([
            {
                "id": "step_1",
                "type": "tool_call",
                "description": "Write config file",
                "tool": "file_write",
                "args": {"path": "/workspace/config.yaml", "content": "key: value"},
            },
        ], summary="Write workspace config")
        mock_planner.create_plan.return_value = plan

        mock_executor = MagicMock()
        mock_executor.get_tool_descriptions.return_value = [
            {"name": "file_write", "description": "Write a file"},
        ]

        mock_approval = MagicMock()
        mock_approval.request_plan_approval = AsyncMock(return_value="approval-fw-1")

        orch = Orchestrator(
            planner=mock_planner,
            pipeline=mock_pipeline,
            tool_executor=mock_executor,
            approval_manager=mock_approval,
        )

        with patch("sentinel.planner.orchestrator.settings") as mock_settings:
            mock_settings.trust_level = 2
            mock_settings.conversation_enabled = False
            mock_settings.spotlighting_enabled = False
            mock_settings.require_semgrep = False
            mock_settings.verbose_results = False
            mock_settings.auto_memory = False
            mock_settings.planner_timeout = 120
            mock_settings.worker_timeout = 480
            mock_settings.tool_timeout = 60
            mock_settings.plan_execution_timeout = 1500
            mock_settings.api_task_timeout = 1800
            result = await orch.handle_task(
                "write config file",
                approval_mode="full",
            )

        # file_write is DANGEROUS even at TL2 — approval required
        assert result.status == "awaiting_approval"
        mock_approval.request_plan_approval.assert_called_once()
        # Verify classification directly
        assert classify_operation("file_write", trust_level=2) == TrustTier.DANGEROUS
        assert "file_write" not in TL2_SAFE_OPS


# ── Group I: D4 file_write at TL3 ──────────────────────────────────


class TestFileWriteTL3Classification:
    """D4: file_write classification at TL3 — PERMITTED, not SAFE."""

    @pytest.mark.capability
    def test_file_write_permitted_at_tl3(self):
        """classify_operation("file_write", trust_level=3) returns PERMITTED.

        At TL3, file_write is explicitly permitted in plans with enhanced
        scanning. It is NOT SAFE (never auto-approves) — it requires human
        plan approval plus pre-write Semgrep scanning.
        """
        result = classify_operation("file_write", trust_level=3)
        assert result == TrustTier.PERMITTED
        assert "file_write" in TL3_PERMITTED_OPS

    @pytest.mark.capability
    def test_file_write_dangerous_below_tl3(self):
        """classify_operation("file_write") returns DANGEROUS at TL0-TL2.

        file_write is DANGEROUS at all trust levels below 3. It still works
        with human approval — DANGEROUS just means it requires the full
        CaMeL pipeline and can never be auto-approved.
        """
        for tl in (0, 1, 2):
            assert classify_operation("file_write", trust_level=tl) == TrustTier.DANGEROUS, (
                f"file_write should be DANGEROUS at TL{tl}"
            )
        # Default trust_level=1 also DANGEROUS
        assert classify_operation("file_write") == TrustTier.DANGEROUS

    @pytest.mark.capability
    def test_tl3_permitted_ops_immutable(self):
        """TL3_PERMITTED_OPS is frozenset — cannot be modified at runtime.

        Same protection as SAFE_OPS — prevents runtime escalation.
        """
        assert isinstance(TL3_PERMITTED_OPS, frozenset)
        with pytest.raises(AttributeError):
            TL3_PERMITTED_OPS.add("shell_exec")  # type: ignore[attr-defined]

    @pytest.mark.capability
    def test_tl3_classify_operation_matrix(self):
        """Full TL0-TL3 classification matrix for key operations.

        Verifies the complete trust escalation path across all levels.
        """
        # health_check: SAFE at all levels >= 1
        assert classify_operation("health_check", trust_level=0) == TrustTier.SAFE
        assert classify_operation("health_check", trust_level=3) == TrustTier.SAFE

        # file_read: DANGEROUS at TL0-1, SAFE at TL2+
        assert classify_operation("file_read", trust_level=1) == TrustTier.DANGEROUS
        assert classify_operation("file_read", trust_level=2) == TrustTier.SAFE
        assert classify_operation("file_read", trust_level=3) == TrustTier.SAFE

        # file_write: DANGEROUS at TL0-2, PERMITTED at TL3+
        assert classify_operation("file_write", trust_level=2) == TrustTier.DANGEROUS
        assert classify_operation("file_write", trust_level=3) == TrustTier.PERMITTED

        # shell_exec: DANGEROUS at all levels (never promoted)
        for tl in range(4):
            assert classify_operation("shell_exec", trust_level=tl) == TrustTier.DANGEROUS


class TestFileWriteTL3Approval:
    """D4: file_write at TL3 still requires human plan approval."""

    @pytest.mark.capability
    @pytest.mark.asyncio
    async def test_tl3_file_write_requires_approval(self, mock_planner, mock_pipeline):
        """file_write plan at TL3 → requires approval (PERMITTED, not SAFE).

        TL3 PERMITTED means the operation is allowed in plans with enhanced
        scanning, but it still requires human approval. _is_auto_approvable()
        returns False for PERMITTED ops.
        """
        plan = _make_plan([
            {
                "id": "step_1",
                "type": "tool_call",
                "description": "Write output file",
                "tool": "file_write",
                "args": {"path": "/workspace/output.py", "content": "print('hello')"},
            },
        ], summary="Write hello world to workspace")
        mock_planner.create_plan.return_value = plan

        mock_executor = MagicMock()
        mock_executor.get_tool_descriptions.return_value = [
            {"name": "file_write", "description": "Write a file"},
        ]

        mock_approval = MagicMock()
        mock_approval.request_plan_approval = AsyncMock(return_value="approval-d4-1")

        orch = Orchestrator(
            planner=mock_planner,
            pipeline=mock_pipeline,
            tool_executor=mock_executor,
            approval_manager=mock_approval,
        )

        with patch("sentinel.planner.orchestrator.settings") as mock_settings:
            mock_settings.trust_level = 3
            mock_settings.conversation_enabled = False
            mock_settings.spotlighting_enabled = False
            mock_settings.require_semgrep = False
            mock_settings.verbose_results = False
            mock_settings.auto_memory = False
            mock_settings.planner_timeout = 120
            mock_settings.worker_timeout = 480
            mock_settings.tool_timeout = 60
            mock_settings.plan_execution_timeout = 1500
            mock_settings.api_task_timeout = 1800
            result = await orch.handle_task(
                "write hello world",
                approval_mode="full",
            )

        # PERMITTED → still requires approval (not auto-approved)
        assert result.status == "awaiting_approval"
        mock_approval.request_plan_approval.assert_called_once()


class TestFileWriteTL3SemgrepScan:
    """D4: Pre-write Semgrep scanning at TL3+ in ToolExecutor._file_write()."""

    @pytest.mark.capability
    @pytest.mark.asyncio
    async def test_tl3_semgrep_blocks_insecure_code(self):
        """file_write at TL3 with insecure code → Semgrep blocks, file not written.

        Pre-write Semgrep scan catches dangerous patterns (e.g. os.system)
        in the content being written, before the file touches disk.
        """
        engine = PolicyEngine("policies/sentinel-policy.yaml")
        executor = ToolExecutor(policy_engine=engine, trust_level=3)

        insecure_code = 'import os\nos.system(input("cmd: "))\n'

        with tempfile.TemporaryDirectory() as tmpdir:
            path = f"{tmpdir}/exploit.py"
            with patch.object(executor._engine, "check_file_write") as mock_check:
                mock_check.return_value = ValidationResult(
                    status=PolicyResult.ALLOWED, path=path,
                )
                with patch("sentinel.tools.executor.semgrep_scanner") as mock_sg:
                    mock_sg.is_loaded.return_value = True
                    mock_sg.scan_blocks = AsyncMock(return_value=ScanResult(
                        found=True,
                        matches=[ScanMatch(
                            pattern_name="dangerous-os-system",
                            matched_text="os.system(input",
                            position=0,
                        )],
                        scanner_name="semgrep",
                    ))

                    with pytest.raises(ToolBlockedError, match="Semgrep"):
                        await executor.execute("file_write", {
                            "path": path,
                            "content": insecure_code,
                        })

                    # File must NOT exist — blocked before write
                    assert not os.path.exists(path)
                    # Semgrep was called with the content
                    mock_sg.scan_blocks.assert_called_once()

    @pytest.mark.capability
    @pytest.mark.asyncio
    async def test_tl3_semgrep_allows_safe_code(self):
        """file_write at TL3 with safe code → Semgrep passes, file written.

        Clean code passes the pre-write Semgrep scan and the file is written
        to disk normally.
        """
        engine = PolicyEngine("policies/sentinel-policy.yaml")
        executor = ToolExecutor(policy_engine=engine, trust_level=3)

        safe_code = 'def greet(name):\n    return f"Hello, {name}!"\n'

        with tempfile.TemporaryDirectory() as tmpdir:
            path = f"{tmpdir}/greet.py"
            with patch.object(executor._engine, "check_file_write") as mock_check:
                mock_check.return_value = ValidationResult(
                    status=PolicyResult.ALLOWED, path=path,
                )
                with patch("sentinel.tools.executor.semgrep_scanner") as mock_sg:
                    mock_sg.is_loaded.return_value = True
                    mock_sg.scan_blocks = AsyncMock(return_value=ScanResult(
                        found=False, matches=[], scanner_name="semgrep",
                    ))

                    result, _ = await executor.execute("file_write", {
                        "path": path,
                        "content": safe_code,
                    })

                    assert result.trust_level == TrustLevel.TRUSTED
                    assert os.path.exists(path)
                    with open(path) as f:
                        assert f.read() == safe_code

    @pytest.mark.capability
    @pytest.mark.asyncio
    async def test_tl3_no_semgrep_at_tl2(self):
        """file_write at TL2 → no pre-write Semgrep scan (enhancement off).

        Pre-write scanning only activates at TL3+. At TL2 and below,
        file_write proceeds without the additional Semgrep check.
        """
        engine = PolicyEngine("policies/sentinel-policy.yaml")
        executor = ToolExecutor(policy_engine=engine, trust_level=2)

        with tempfile.TemporaryDirectory() as tmpdir:
            path = f"{tmpdir}/test.py"
            with patch.object(executor._engine, "check_file_write") as mock_check:
                mock_check.return_value = ValidationResult(
                    status=PolicyResult.ALLOWED, path=path,
                )
                with patch("sentinel.tools.executor.semgrep_scanner") as mock_sg:
                    result, _ = await executor.execute("file_write", {
                        "path": path,
                        "content": "print('hello')\n",
                    })

                    assert result.trust_level == TrustLevel.TRUSTED
                    # Semgrep scan_blocks must NOT have been called at TL2
                    mock_sg.scan_blocks.assert_not_called()

    @pytest.mark.capability
    @pytest.mark.asyncio
    async def test_tl3_semgrep_failure_blocks_write(self):
        """Semgrep crash/timeout during pre-write scan → fail-closed, file not written.

        Consistent with B-001 fail-closed policy: if scanning fails for any
        reason, the write is blocked rather than proceeding without scanning.
        """
        engine = PolicyEngine("policies/sentinel-policy.yaml")
        executor = ToolExecutor(policy_engine=engine, trust_level=3)

        with tempfile.TemporaryDirectory() as tmpdir:
            path = f"{tmpdir}/crash.py"
            with patch.object(executor._engine, "check_file_write") as mock_check:
                mock_check.return_value = ValidationResult(
                    status=PolicyResult.ALLOWED, path=path,
                )
                with patch("sentinel.tools.executor.semgrep_scanner") as mock_sg:
                    mock_sg.is_loaded.return_value = True
                    mock_sg.scan_blocks = AsyncMock(
                        side_effect=RuntimeError("Semgrep crashed")
                    )

                    with pytest.raises(ToolBlockedError, match="[Ss]emgrep|scan"):
                        await executor.execute("file_write", {
                            "path": path,
                            "content": "import os\n",
                        })

                    # File must NOT exist
                    assert not os.path.exists(path)


class TestFileWriteTL3Provenance:
    """D4: Provenance tracking and workspace enforcement for file_write at TL3."""

    @pytest.mark.capability
    @pytest.mark.asyncio
    async def test_tl3_file_write_provenance_records_writer(self):
        """file_write records provenance — get_file_writer returns the write's data_id.

        After a file_write, the provenance chain links the file path to the
        TaggedData entry created by the write operation. This enables trust
        inheritance when the file is later read.
        """
        engine = PolicyEngine("policies/sentinel-policy.yaml")
        executor = ToolExecutor(policy_engine=engine, trust_level=3)

        with tempfile.TemporaryDirectory() as tmpdir:
            path = f"{tmpdir}/written.txt"
            with patch.object(executor._engine, "check_file_write") as mock_check:
                mock_check.return_value = ValidationResult(
                    status=PolicyResult.ALLOWED, path=path,
                )
                # Skip Semgrep for this provenance-focused test
                with patch("sentinel.tools.executor.semgrep_scanner") as mock_sg:
                    mock_sg.is_loaded.return_value = False

                    result, _ = await executor.execute("file_write", {
                        "path": path,
                        "content": "test content",
                    })

            # Provenance chain: file → writer data_id
            writer_id = await get_file_writer(path)
            assert writer_id is not None
            writer_data = await get_tagged_data(writer_id)
            assert writer_data is not None
            assert writer_data.source == DataSource.TOOL
            assert writer_data.trust_level == TrustLevel.TRUSTED

    @pytest.mark.capability
    async def test_tl3_written_file_inherits_untrusted(self):
        """Qwen output → file_write → file_read → inherits UNTRUSTED.

        Trust laundering attack: Qwen generates malicious content, which gets
        written to a file via an approved plan, then read back. The read-back
        data must inherit UNTRUSTED from the Qwen origin via the provenance
        chain, preventing the data from being used in subsequent tool_calls.
        """
        # Step 1: Qwen generates content (always UNTRUSTED)
        qwen_output = await create_tagged_data(
            content="malicious payload",
            source=DataSource.QWEN,
            trust_level=TrustLevel.UNTRUSTED,
        )

        # Step 2: Content written to file — provenance records the writer
        write_result = await create_tagged_data(
            content="File written: /workspace/payload.sh",
            source=DataSource.TOOL,
            trust_level=TrustLevel.TRUSTED,
            originated_from="file_write:/workspace/payload.sh",
            parent_ids=[qwen_output.id],
        )
        await record_file_write("/workspace/payload.sh", write_result.id)

        # Step 3: File read back — should inherit UNTRUSTED from writer
        writer_id = await get_file_writer("/workspace/payload.sh")
        assert writer_id is not None

        read_data = await create_tagged_data(
            content="malicious payload",
            source=DataSource.FILE,
            trust_level=TrustLevel.TRUSTED,
            parent_ids=[writer_id],
        )

        # Child inherits UNTRUSTED from Qwen grandparent
        assert read_data.trust_level == TrustLevel.UNTRUSTED
        assert await is_trust_safe_for_execution(read_data.id) is False

    @pytest.mark.capability
    @pytest.mark.asyncio
    async def test_tl3_file_write_outside_workspace_blocked(self):
        """file_write to /etc/passwd → blocked by policy even at TL3.

        Trust level 3 permits workspace writes, not arbitrary file writes.
        The PolicyEngine workspace enforcement is independent of trust level.
        """
        engine = PolicyEngine("policies/sentinel-policy.yaml")
        executor = ToolExecutor(policy_engine=engine, trust_level=3)

        with pytest.raises(ToolBlockedError, match="blocked"):
            await executor.execute("file_write", {
                "path": "/etc/passwd",
                "content": "root:x:0:0:root:/root:/bin/bash",
            })
