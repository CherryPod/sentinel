import logging
import re
import time

from .models import (
    ConversationInfo,
    DataSource,
    Plan,
    PlanStep,
    StepResult,
    TaggedData,
    TaskResult,
    TrustLevel,
)
from . import codeshield
from .config import settings
from .conversation import ConversationAnalyzer
from .pipeline import ScanPipeline, SecurityViolation
from .planner import ClaudePlanner, PlannerError
from .provenance import create_tagged_data
from .session import ConversationTurn, SessionStore

logger = logging.getLogger("sentinel.audit")


class ExecutionContext:
    """Tracks variable bindings during plan execution."""

    def __init__(self):
        self._vars: dict[str, TaggedData] = {}

    def set(self, var_name: str, data: TaggedData) -> None:
        self._vars[var_name] = data

    def get(self, var_name: str) -> TaggedData | None:
        return self._vars.get(var_name)

    def resolve_text(self, text: str) -> str:
        """Replace $var_name references with their content."""
        if not text:
            return text

        def replacer(match: re.Match) -> str:
            var_name = match.group(0)
            data = self._vars.get(var_name)
            if data is not None:
                return data.content
            return var_name  # leave unresolved refs as-is

        return re.sub(r"\$\w+", replacer, text)

    def resolve_args(self, args: dict) -> dict:
        """Replace $var_name references in dict values."""
        resolved = {}
        for key, value in args.items():
            if isinstance(value, str):
                resolved[key] = self.resolve_text(value)
            else:
                resolved[key] = value
        return resolved


class Orchestrator:
    """Main CaMeL execution loop: plan → execute → scan → return."""

    def __init__(
        self,
        planner: ClaudePlanner,
        pipeline: ScanPipeline,
        tool_executor=None,
        approval_manager=None,
        session_store: SessionStore | None = None,
        conversation_analyzer: ConversationAnalyzer | None = None,
    ):
        self._planner = planner
        self._pipeline = pipeline
        self._tool_executor = tool_executor
        self._approval_manager = approval_manager
        self._session_store = session_store
        self._conversation_analyzer = conversation_analyzer

    async def handle_task(
        self,
        user_request: str,
        source: str = "api",
        approval_mode: str = "auto",
        session_id: str | None = None,
    ) -> TaskResult:
        """Full CaMeL pipeline: conversation check → scan → plan → execute → return."""
        task_t0 = time.monotonic()
        logger.info(
            "Task received",
            extra={
                "event": "task_received",
                "source": source,
                "session_id": session_id,
                "request_length": len(user_request),
                "request_preview": user_request[:200],
            },
        )

        # 0. Conversation analysis (multi-turn attack detection)
        conv_info = None
        session = None
        if (
            settings.conversation_enabled
            and self._session_store is not None
            and self._conversation_analyzer is not None
        ):
            session = self._session_store.get_or_create(session_id, source=source)

            # Locked sessions get immediate rejection
            if session.is_locked:
                conv_info = ConversationInfo(
                    session_id=session.session_id,
                    turn_number=len(session.turns),
                    risk_score=session.cumulative_risk,
                    action="block",
                    warnings=["Session is locked due to accumulated violations"],
                )
                return TaskResult(
                    status="blocked",
                    reason="Session locked — too many security violations",
                    conversation=conv_info,
                )

            analysis = self._conversation_analyzer.analyze(session, user_request)
            conv_info = ConversationInfo(
                session_id=session.session_id,
                turn_number=len(session.turns),
                risk_score=analysis.total_score,
                action=analysis.action,
                warnings=analysis.warnings,
            )

            if analysis.action == "block":
                session.cumulative_risk = analysis.total_score
                session.lock()
                turn = ConversationTurn(
                    request_text=user_request,
                    result_status="blocked",
                    blocked_by=["conversation_analyzer"],
                    risk_score=analysis.total_score,
                )
                session.add_turn(turn)
                return TaskResult(
                    status="blocked",
                    reason="Blocked by multi-turn conversation analysis",
                    conversation=conv_info,
                )

            # For "warn", we continue processing but include warnings
            # Update cumulative risk (carries forward to next turn)
            if analysis.total_score > session.cumulative_risk:
                session.cumulative_risk = analysis.total_score

        # 1. Scan user input
        try:
            input_scan = self._pipeline.scan_input(user_request)
            if not input_scan.is_clean:
                logger.warning(
                    "Task input blocked by scan",
                    extra={
                        "event": "task_input_blocked",
                        "violations": list(input_scan.violations.keys()),
                    },
                )
                if session is not None:
                    turn = ConversationTurn(
                        request_text=user_request,
                        result_status="blocked",
                        blocked_by=list(input_scan.violations.keys()),
                        risk_score=conv_info.risk_score if conv_info else 0.0,
                    )
                    session.add_turn(turn)
                return TaskResult(
                    status="blocked",
                    reason="Input blocked by security scan",
                    conversation=conv_info,
                )
        except Exception as exc:
            logger.error(
                "Input scan failed",
                extra={"event": "input_scan_error", "error": str(exc)},
            )
            return TaskResult(
                status="error",
                reason=f"Input scan failed: {exc}",
                conversation=conv_info,
            )

        # 2. Get tool descriptions if a tool executor is available
        available_tools = []
        if self._tool_executor is not None:
            available_tools = self._tool_executor.get_tool_descriptions()

        # 3. Create plan via Claude
        try:
            plan = await self._planner.create_plan(
                user_request=user_request,
                available_tools=available_tools,
            )
        except PlannerError as exc:
            logger.error(
                "Planning failed",
                extra={"event": "planner_error", "error": str(exc)},
            )
            return TaskResult(
                status="error",
                reason=f"Planning failed: {exc}",
                conversation=conv_info,
            )

        # 4. Check if approval is needed
        if approval_mode == "full" and self._approval_manager is not None:
            approval_id = await self._approval_manager.request_plan_approval(plan)
            return TaskResult(
                status="awaiting_approval",
                plan_summary=plan.plan_summary,
                reason=f"approval_id:{approval_id}",
                conversation=conv_info,
            )

        # 5. Execute plan
        result = await self._execute_plan(plan)
        result.conversation = conv_info

        task_elapsed = time.monotonic() - task_t0
        logger.info(
            "Task completed",
            extra={
                "event": "task_completed",
                "status": result.status,
                "plan_summary": plan.plan_summary,
                "step_count": len(plan.steps),
                "elapsed_s": round(task_elapsed, 2),
            },
        )

        # Record turn
        if session is not None:
            turn = ConversationTurn(
                request_text=user_request,
                result_status=result.status,
                risk_score=conv_info.risk_score if conv_info else 0.0,
            )
            session.add_turn(turn)

        return result

    async def execute_approved_plan(self, approval_id: str) -> TaskResult:
        """Execute a plan that has been approved via the approval flow."""
        if self._approval_manager is None:
            return TaskResult(status="error", reason="Approval manager not configured")

        is_approved = self._approval_manager.is_approved(approval_id)
        if is_approved is None:
            return TaskResult(status="error", reason="Approval not found or still pending")
        if not is_approved:
            return TaskResult(status="denied", reason="Plan was denied")

        plan = self._approval_manager.get_plan(approval_id)
        if plan is None:
            return TaskResult(status="error", reason="Plan not found for approval")

        return await self._execute_plan(plan)

    async def _execute_plan(self, plan: Plan) -> TaskResult:
        """Execute all steps in a plan sequentially."""
        context = ExecutionContext()
        step_results: list[StepResult] = []

        for step in plan.steps:
            step_t0 = time.monotonic()
            logger.info(
                "Executing step",
                extra={
                    "event": "step_start",
                    "step_id": step.id,
                    "step_type": step.type,
                    "description": step.description,
                },
            )

            result = await self._execute_step(step, context)
            step_results.append(result)
            step_elapsed = time.monotonic() - step_t0

            logger.info(
                "Step completed",
                extra={
                    "event": "step_complete",
                    "step_id": step.id,
                    "status": result.status,
                    "elapsed_s": round(step_elapsed, 2),
                },
            )

            # Store result in context if step has output_var
            if result.status == "success" and step.output_var and result.data_id:
                data = self._get_tagged_data(result.data_id)
                if data:
                    context.set(step.output_var, data)
                    logger.debug(
                        "Variable stored in context",
                        extra={
                            "event": "context_var_set",
                            "var_name": step.output_var,
                            "data_id": result.data_id,
                            "trust_level": data.trust_level.value,
                        },
                    )

            # Stop on blocking errors
            if result.status in ("blocked", "error"):
                return TaskResult(
                    status=result.status,
                    plan_summary=plan.plan_summary,
                    step_results=step_results,
                    reason=result.error,
                )

        return TaskResult(
            status="success",
            plan_summary=plan.plan_summary,
            step_results=step_results,
        )

    async def _execute_step(
        self, step: PlanStep, context: ExecutionContext
    ) -> StepResult:
        """Execute a single plan step."""
        if step.type == "llm_task":
            return await self._execute_llm_task(step, context)
        elif step.type == "tool_call":
            return await self._execute_tool_call(step, context)
        else:
            return StepResult(
                step_id=step.id,
                status="error",
                error=f"Unknown step type: {step.type}",
            )

    async def _execute_llm_task(
        self, step: PlanStep, context: ExecutionContext
    ) -> StepResult:
        """Send a prompt to Qwen via the scan pipeline."""
        if not step.prompt:
            return StepResult(
                step_id=step.id,
                status="error",
                error="LLM task step has no prompt",
            )

        resolved_prompt = context.resolve_text(step.prompt)

        try:
            tagged = await self._pipeline.process_with_qwen(prompt=resolved_prompt)

            # CodeShield scan on ALL Qwen output (not just expects_code steps)
            if codeshield.is_loaded():
                cs_result = await codeshield.scan(tagged.content)
                if cs_result.found:
                    logger.warning(
                        "CodeShield blocked generated code",
                        extra={
                            "event": "codeshield_blocked",
                            "step_id": step.id,
                            "matches": len(cs_result.matches),
                        },
                    )
                    return StepResult(
                        step_id=step.id,
                        status="blocked",
                        error=f"CodeShield: insecure code detected ({len(cs_result.matches)} issues)",
                    )

            return StepResult(
                step_id=step.id,
                status="success",
                data_id=tagged.id,
                content=tagged.content,
            )
        except SecurityViolation as exc:
            return StepResult(
                step_id=step.id,
                status="blocked",
                error=f"Security violation: {exc}",
            )
        except Exception as exc:
            return StepResult(
                step_id=step.id,
                status="error",
                error=f"LLM task failed: {exc}",
            )

    async def _execute_tool_call(
        self, step: PlanStep, context: ExecutionContext
    ) -> StepResult:
        """Execute a tool call step."""
        if self._tool_executor is None:
            logger.info(
                "Tool execution not available — skipping",
                extra={
                    "event": "tool_skipped",
                    "step_id": step.id,
                    "tool": step.tool,
                },
            )
            return StepResult(
                step_id=step.id,
                status="skipped",
                error="Tool execution not yet available",
            )

        if not step.tool:
            return StepResult(
                step_id=step.id,
                status="error",
                error="Tool call step has no tool specified",
            )

        resolved_args = context.resolve_args(step.args)

        try:
            tagged = await self._tool_executor.execute(
                tool_name=step.tool,
                args=resolved_args,
            )
            return StepResult(
                step_id=step.id,
                status="success",
                data_id=tagged.id,
                content=tagged.content,
            )
        except Exception as exc:
            from .tools import ToolBlockedError
            status = "blocked" if isinstance(exc, ToolBlockedError) else "error"
            return StepResult(
                step_id=step.id,
                status=status,
                error=f"Tool execution failed: {exc}",
            )

    @staticmethod
    def _get_tagged_data(data_id: str) -> TaggedData | None:
        from .provenance import get_tagged_data
        return get_tagged_data(data_id)
