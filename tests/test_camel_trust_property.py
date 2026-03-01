"""End-to-end CaMeL provenance trust property tests.

V-003: The core CaMeL guarantee — untrusted Qwen output cannot flow through
to tool execution — is asserted by design but tested here empirically.

These tests exercise the full provenance chain: data creation → trust
inheritance → trust gate check, using the in-memory ProvenanceStore.
"""

from unittest.mock import AsyncMock, MagicMock

import pytest

from sentinel.core.models import (
    DataSource,
    Plan,
    PlanStep,
    ScanResult,
    TaggedData,
    TrustLevel,
)
from sentinel.planner.orchestrator import ExecutionContext, Orchestrator
from sentinel.security.pipeline import PipelineScanResult, ScanPipeline
from sentinel.planner.planner import ClaudePlanner
from sentinel.security.provenance import (
    ProvenanceStore,
    create_tagged_data,
    get_tagged_data,
    is_trust_safe_for_execution,
    reset_store,
)


@pytest.fixture(autouse=True)
def _reset_provenance():
    """Clean slate for each test."""
    reset_store()
    yield
    reset_store()


@pytest.fixture
def mock_planner():
    planner = MagicMock(spec=ClaudePlanner)
    planner.create_plan = AsyncMock()
    return planner


@pytest.fixture
def mock_pipeline():
    pipeline = MagicMock(spec=ScanPipeline)
    clean = PipelineScanResult()
    pipeline.scan_input.return_value = clean
    pipeline.process_with_qwen = AsyncMock()
    return pipeline


@pytest.fixture(autouse=True)
def _disable_semgrep_requirement():
    from sentinel.core.config import settings
    original = settings.require_semgrep
    settings.require_semgrep = False
    yield
    settings.require_semgrep = original


def _make_plan(steps: list[dict], summary: str = "Test plan") -> Plan:
    return Plan(
        plan_summary=summary,
        steps=[PlanStep(**s) for s in steps],
    )


class TestCaMeLTrustGate:
    """Regression guard: CaMeL trust gate blocks untrusted data at tool execution."""

    @pytest.mark.asyncio
    async def test_untrusted_qwen_output_blocked_at_tool_execution(
        self, mock_planner, mock_pipeline
    ):
        """Core CaMeL test: UNTRUSTED Qwen output used as tool arg → blocked.

        Flow: user request → Claude plans two steps → step 1 (llm_task) produces
        UNTRUSTED output from Qwen → step 2 (tool_call) tries to use that output
        as file_write content → trust gate blocks before executor runs.
        """
        plan = _make_plan([
            {
                "id": "step_1",
                "type": "llm_task",
                "description": "Generate a script",
                "prompt": "Write a bash script",
                "output_var": "$script",
            },
            {
                "id": "step_2",
                "type": "tool_call",
                "description": "Write script to disk",
                "tool": "file_write",
                "args": {"path": "/workspace/out.sh", "content": "$script"},
            },
        ])
        mock_planner.create_plan.return_value = plan

        # Qwen produces UNTRUSTED output (simulating the worker LLM)
        qwen_output = create_tagged_data(
            content="#!/bin/bash\necho pwned",
            source=DataSource.QWEN,
            trust_level=TrustLevel.UNTRUSTED,
        )
        mock_pipeline.process_with_qwen.return_value = qwen_output

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
        result = await orch.handle_task("Write a script to disk")

        # Regression guard: step 1 succeeds (LLM output), step 2 blocked (trust gate)
        assert result.status == "blocked"
        assert result.step_results[0].status == "success"
        assert result.step_results[1].status == "blocked"
        assert "trust" in result.step_results[1].error.lower()
        # Tool executor must NOT have been called — the gate fires before dispatch
        mock_executor.execute.assert_not_called()

    @pytest.mark.asyncio
    async def test_trusted_planner_output_allowed_through_trust_gate(
        self, mock_planner, mock_pipeline
    ):
        """Trusted data (from Claude planner / user) CAN reach tool execution.

        This verifies the positive path: when all args in a tool_call resolve to
        TRUSTED provenance entries, the trust gate allows execution.
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

        read_result = create_tagged_data(
            content="file contents here",
            source=DataSource.TOOL,
            trust_level=TrustLevel.TRUSTED,
        )
        mock_executor = MagicMock()
        mock_executor.get_tool_descriptions.return_value = [
            {"name": "file_read", "description": "Read a file"},
        ]
        mock_executor.execute = AsyncMock(return_value=read_result)

        orch = Orchestrator(
            planner=mock_planner,
            pipeline=mock_pipeline,
            tool_executor=mock_executor,
        )
        result = await orch.handle_task("Read a data file")

        # Regression guard: literal args (no $var references) pass the trust gate
        assert result.status == "success"
        mock_executor.execute.assert_called_once()


class TestTrustContamination:
    """Regression guard: trust contamination propagates through the full chain."""

    def test_trusted_input_through_qwen_becomes_untrusted(self):
        """TRUSTED input → Qwen processing → output is UNTRUSTED.

        Even though the original user input was trusted, once Qwen processes it,
        the output is UNTRUSTED because Qwen is an assumed-compromised worker.
        Derived data from that output must also be UNTRUSTED.
        """
        # Step 1: User provides trusted input
        user_input = create_tagged_data(
            content="Write me a hello world script",
            source=DataSource.USER,
            trust_level=TrustLevel.TRUSTED,
        )
        assert user_input.trust_level == TrustLevel.TRUSTED

        # Step 2: Qwen processes it → output is UNTRUSTED
        qwen_output = create_tagged_data(
            content="#!/bin/bash\necho hello",
            source=DataSource.QWEN,
            trust_level=TrustLevel.UNTRUSTED,
        )
        assert qwen_output.trust_level == TrustLevel.UNTRUSTED

        # Step 3: Derived data inherits UNTRUSTED from Qwen output
        derived = create_tagged_data(
            content="processed version of script",
            source=DataSource.TOOL,
            trust_level=TrustLevel.TRUSTED,  # requested TRUSTED
            parent_ids=[qwen_output.id],      # but parent is UNTRUSTED
        )
        # Regression guard: child inherits UNTRUSTED from parent
        assert derived.trust_level == TrustLevel.UNTRUSTED

        # Step 4: The trust gate should block this derived data
        assert is_trust_safe_for_execution(derived.id) is False

    def test_deeply_nested_contamination_propagates(self):
        """UNTRUSTED at depth N propagates all the way up the chain.

        Even if there are multiple TRUSTED intermediaries, a single UNTRUSTED
        ancestor should make all descendants unsafe for execution.
        """
        # Root: UNTRUSTED Qwen output
        qwen = create_tagged_data(
            content="malicious payload",
            source=DataSource.QWEN,
            trust_level=TrustLevel.UNTRUSTED,
        )

        # Layer 1: tool processes it → inherits UNTRUSTED
        layer1 = create_tagged_data(
            content="processed once",
            source=DataSource.TOOL,
            trust_level=TrustLevel.TRUSTED,
            parent_ids=[qwen.id],
        )
        assert layer1.trust_level == TrustLevel.UNTRUSTED

        # Layer 2: another tool processes layer1 → still UNTRUSTED
        layer2 = create_tagged_data(
            content="processed twice",
            source=DataSource.TOOL,
            trust_level=TrustLevel.TRUSTED,
            parent_ids=[layer1.id],
        )
        assert layer2.trust_level == TrustLevel.UNTRUSTED

        # Layer 3: further derivation → still UNTRUSTED
        layer3 = create_tagged_data(
            content="processed thrice",
            source=DataSource.TOOL,
            trust_level=TrustLevel.TRUSTED,
            parent_ids=[layer2.id],
        )
        assert layer3.trust_level == TrustLevel.UNTRUSTED

        # Regression guard: the full chain is unsafe for execution
        assert is_trust_safe_for_execution(layer3.id) is False

    def test_mixed_parentage_one_untrusted_contaminates(self):
        """Multiple parents — one UNTRUSTED parent contaminates the child.

        Even if 9 parents are TRUSTED, one UNTRUSTED parent makes the child
        UNTRUSTED (conservative CaMeL property).
        """
        trusted_parents = [
            create_tagged_data(
                content=f"trusted data {i}",
                source=DataSource.USER,
                trust_level=TrustLevel.TRUSTED,
            )
            for i in range(5)
        ]
        untrusted_parent = create_tagged_data(
            content="qwen output",
            source=DataSource.QWEN,
            trust_level=TrustLevel.UNTRUSTED,
        )

        all_parent_ids = [p.id for p in trusted_parents] + [untrusted_parent.id]
        child = create_tagged_data(
            content="aggregated data",
            source=DataSource.TOOL,
            trust_level=TrustLevel.TRUSTED,
            parent_ids=all_parent_ids,
        )

        # Regression guard: one bad apple spoils the batch
        assert child.trust_level == TrustLevel.UNTRUSTED
        assert is_trust_safe_for_execution(child.id) is False


class TestMissingParentDefault:
    """Regression guard: C-001 fix — missing parent defaults to UNTRUSTED."""

    def test_evicted_parent_defaults_to_untrusted(self):
        """When a parent provenance entry is missing (evicted), child defaults
        to UNTRUSTED.

        This is the C-001 fix: in-memory mode can evict old entries, and if we
        can't verify the trust chain, we default to the safe CaMeL assumption.
        """
        # Create a store with a very small capacity to force eviction
        store = ProvenanceStore(db=None)

        # Create parent, record its ID, then evict it
        parent = store.create_tagged_data(
            content="will be evicted",
            source=DataSource.USER,
            trust_level=TrustLevel.TRUSTED,
        )
        parent_id = parent.id

        # Force eviction by filling the store beyond MAX_PROVENANCE_ENTRIES
        # (Instead, we directly remove it to simulate eviction)
        del store._store[parent_id]

        # Verify parent is gone
        assert store.get_tagged_data(parent_id) is None

        # Create child referencing the evicted parent
        child = store.create_tagged_data(
            content="child of evicted parent",
            source=DataSource.TOOL,
            trust_level=TrustLevel.TRUSTED,  # requested TRUSTED
            parent_ids=[parent_id],           # parent is missing
        )

        # Regression guard: C-001 — missing parent → UNTRUSTED
        assert child.trust_level == TrustLevel.UNTRUSTED

    def test_nonexistent_parent_id_defaults_to_untrusted(self):
        """Referencing a completely nonexistent parent ID → child UNTRUSTED.

        This could happen if parent_ids contain a typo or come from a different
        store instance. The safe default is UNTRUSTED.
        """
        child = create_tagged_data(
            content="child data",
            source=DataSource.TOOL,
            trust_level=TrustLevel.TRUSTED,
            parent_ids=["nonexistent-parent-id-12345"],
        )

        # Regression guard: nonexistent parent → UNTRUSTED
        assert child.trust_level == TrustLevel.UNTRUSTED
