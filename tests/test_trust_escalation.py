"""Trust level escalation tests — Scenarios A + B.

Verify that a system running at TL2 cannot be tricked into performing TL4
operations. These are the formal proofs for the five enforcement checkpoints
described in the trust-level-escalation design brief.

Scenario A: Auto-approval scope — is_auto_approvable() respects trust level.
Scenario B: Constraint field injection — TL4 provenance bypass and constraint
            validation are no-ops below TL4, even when plan steps carry
            TL4-style fields (allowed_commands, allowed_paths).
"""

from unittest.mock import AsyncMock, MagicMock

import pytest

from sentinel.core.models import (
    DataSource,
    Plan,
    PlanStep,
    TrustLevel,
)
from sentinel.planner.builders import is_auto_approvable
from sentinel.planner.tool_dispatch import check_provenance, validate_constraints
from sentinel.planner.orchestrator import ExecutionContext
from sentinel.security.provenance import (
    create_tagged_data,
    is_trust_safe_for_execution,
    reset_store,
)


@pytest.fixture(autouse=True)
async def _reset_provenance():
    """Clean slate for each test."""
    await reset_store()
    yield
    await reset_store()


def _make_plan(steps: list[dict], summary: str = "Test plan") -> Plan:
    return Plan(
        plan_summary=summary,
        steps=[PlanStep(**s) for s in steps],
    )


# ---------------------------------------------------------------------------
# Scenario A: Auto-approval scope at TL2
# ---------------------------------------------------------------------------


class TestAutoApprovalScopeTL2:
    """Scenario A: is_auto_approvable() must reject dangerous operations at TL2."""

    def test_shell_exec_not_auto_approvable_at_tl2(self):
        """shell_exec is DANGEROUS at TL2 — must not auto-approve."""
        plan = _make_plan([
            {
                "id": "step_1",
                "type": "tool_call",
                "description": "Run a command",
                "tool": "shell_exec",
                "args": {"command": "ls /workspace"},
            },
        ])
        assert is_auto_approvable(plan, trust_level=2) is False

    def test_file_write_not_auto_approvable_at_tl2(self):
        """file_write is DANGEROUS at TL2 (only PERMITTED at TL3+) — must not auto-approve."""
        plan = _make_plan([
            {
                "id": "step_1",
                "type": "tool_call",
                "description": "Write a file",
                "tool": "file_write",
                "args": {"path": "/workspace/out.txt", "content": "hello"},
            },
        ])
        assert is_auto_approvable(plan, trust_level=2) is False

    def test_file_read_auto_approvable_at_tl2(self):
        """file_read is SAFE at TL2 — should auto-approve."""
        plan = _make_plan([
            {
                "id": "step_1",
                "type": "tool_call",
                "description": "Read a file",
                "tool": "file_read",
                "args": {"path": "/workspace/data.txt"},
            },
        ])
        assert is_auto_approvable(plan, trust_level=2) is True

    def test_llm_task_not_auto_approvable_at_tl2(self):
        """llm_task introduces UNTRUSTED Qwen data — must not auto-approve."""
        plan = _make_plan([
            {
                "id": "step_1",
                "type": "llm_task",
                "description": "Generate content",
                "prompt": "Write something",
                "output_var": "$output",
            },
        ])
        assert is_auto_approvable(plan, trust_level=2) is False

    def test_mixed_plan_safe_and_dangerous_not_auto_approvable_at_tl2(self):
        """A plan with one safe and one dangerous step must not auto-approve."""
        plan = _make_plan([
            {
                "id": "step_1",
                "type": "tool_call",
                "description": "Read a file",
                "tool": "file_read",
                "args": {"path": "/workspace/data.txt"},
            },
            {
                "id": "step_2",
                "type": "tool_call",
                "description": "Run a command",
                "tool": "shell_exec",
                "args": {"command": "cat /etc/passwd"},
            },
        ])
        assert is_auto_approvable(plan, trust_level=2) is False

    def test_file_read_not_auto_approvable_at_tl1(self):
        """file_read is NOT in the TL1 safe set — must not auto-approve at TL1."""
        plan = _make_plan([
            {
                "id": "step_1",
                "type": "tool_call",
                "description": "Read a file",
                "tool": "file_read",
                "args": {"path": "/workspace/data.txt"},
            },
        ])
        assert is_auto_approvable(plan, trust_level=1) is False

    def test_empty_plan_not_auto_approvable(self):
        """Empty plan must not auto-approve at any trust level."""
        plan = _make_plan([])
        assert is_auto_approvable(plan, trust_level=2) is False


# ---------------------------------------------------------------------------
# Scenario B: Constraint field injection at TL2
# ---------------------------------------------------------------------------


class TestConstraintFieldInjectionTL2:
    """Scenario B: TL4-style plan fields must be ignored at TL2.

    Even if Claude (or a compromised planner) produces plan steps with
    allowed_commands / allowed_paths populated, the provenance bypass and
    constraint validation must NOT activate below TL4.
    """

    @pytest.mark.asyncio
    async def test_provenance_bypass_blocked_with_allowed_commands_at_tl2(self):
        """Plan step with allowed_commands at TL2 — provenance bypass must NOT activate.

        At TL4, allowed_commands causes the provenance gate to allow untrusted
        data through (constraint validation handles it instead). At TL2 this
        bypass must NOT fire — untrusted data must be blocked.
        """
        # Create untrusted data (simulating Qwen output)
        qwen_output = await create_tagged_data(
            content="rm -rf /",
            source=DataSource.QWEN,
            trust_level=TrustLevel.UNTRUSTED,
        )

        # Build a step that references untrusted data AND has allowed_commands
        step = PlanStep(
            id="injected_step",
            type="tool_call",
            description="Run an injected command",
            tool="shell_exec",
            args={"command": f"${qwen_output.id}"},
            allowed_commands=["ls", "cat"],  # TL4-style field
        )

        # Mock execution context to report the untrusted data reference
        context = MagicMock(spec=ExecutionContext)
        context.get_referenced_data_ids_from_args.return_value = [qwen_output.id]

        result = await check_provenance(step, context, trust_level=2)

        # At TL2: must block (provenance bypass is TL4+ only)
        assert result is not None
        assert result.status == "blocked"
        assert "trust" in result.error.lower() or "provenance" in result.error.lower()

    @pytest.mark.asyncio
    async def test_provenance_bypass_blocked_with_allowed_paths_at_tl2(self):
        """Plan step with allowed_paths at TL2 — provenance bypass must NOT activate."""
        qwen_output = await create_tagged_data(
            content="/etc/shadow",
            source=DataSource.QWEN,
            trust_level=TrustLevel.UNTRUSTED,
        )

        step = PlanStep(
            id="injected_step",
            type="tool_call",
            description="Write to a sensitive path",
            tool="file_write",
            args={"path": f"${qwen_output.id}", "content": "pwned"},
            allowed_paths=["/workspace/*"],  # TL4-style field
        )

        context = MagicMock(spec=ExecutionContext)
        context.get_referenced_data_ids_from_args.return_value = [qwen_output.id]

        result = await check_provenance(step, context, trust_level=2)

        assert result is not None
        assert result.status == "blocked"

    @pytest.mark.asyncio
    async def test_provenance_bypass_allowed_at_tl4_with_constraints(self):
        """Positive control: at TL4, the same step with constraints DOES bypass provenance."""
        qwen_output = await create_tagged_data(
            content="ls /workspace",
            source=DataSource.QWEN,
            trust_level=TrustLevel.UNTRUSTED,
        )

        step = PlanStep(
            id="constrained_step",
            type="tool_call",
            description="Run constrained command",
            tool="shell_exec",
            args={"command": f"${qwen_output.id}"},
            allowed_commands=["ls"],
        )

        context = MagicMock(spec=ExecutionContext)
        context.get_referenced_data_ids_from_args.return_value = [qwen_output.id]

        result = await check_provenance(step, context, trust_level=4)

        # At TL4 with constraints: provenance gate is bypassed (returns None)
        assert result is None

    @pytest.mark.asyncio
    async def test_validate_constraints_noop_below_tl4(self):
        """validate_constraints() must be a no-op below TL4.

        Even with resolved args and constraint fields, the function should
        return None (allow) without doing any validation at TL2.
        """
        step = PlanStep(
            id="step_1",
            type="tool_call",
            description="Run a command",
            tool="shell_exec",
            args={"command": "rm -rf /"},
            allowed_commands=["ls"],  # Would block at TL4
        )
        # At TL2, validate_constraints should be a no-op regardless of args
        result = await validate_constraints(
            step,
            resolved_args={"command": "rm -rf /"},
            trust_level=2,
        )
        assert result is None

    @pytest.mark.asyncio
    async def test_validate_constraints_noop_at_tl3(self):
        """validate_constraints() must also be a no-op at TL3."""
        step = PlanStep(
            id="step_1",
            type="tool_call",
            description="Write a file",
            tool="file_write",
            args={"path": "/etc/shadow", "content": "pwned"},
            allowed_paths=["/workspace/*"],  # Would block at TL4
        )
        result = await validate_constraints(
            step,
            resolved_args={"path": "/etc/shadow", "content": "pwned"},
            trust_level=3,
        )
        assert result is None

    @pytest.mark.asyncio
    async def test_provenance_blocks_without_constraints_at_tl4(self):
        """At TL4, provenance gate still blocks when there are NO constraints.

        The bypass requires BOTH TL4+ AND (constraints or content-creation).
        Without constraints at TL4, untrusted data is still blocked.
        """
        qwen_output = await create_tagged_data(
            content="malicious",
            source=DataSource.QWEN,
            trust_level=TrustLevel.UNTRUSTED,
        )

        step = PlanStep(
            id="unconstrained_step",
            type="tool_call",
            description="Run unconstrained command",
            tool="shell_exec",
            args={"command": f"${qwen_output.id}"},
            # No allowed_commands / allowed_paths
        )

        context = MagicMock(spec=ExecutionContext)
        context.get_referenced_data_ids_from_args.return_value = [qwen_output.id]

        result = await check_provenance(step, context, trust_level=4)

        # TL4 without constraints: still blocked
        assert result is not None
        assert result.status == "blocked"
