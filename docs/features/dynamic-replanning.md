# Dynamic Replanning

Sentinel supports two independent replanning mechanisms that allow multi-step tasks to adapt when they discover new information or encounter failures. Both mechanisms have independent budgets and never bypass security scanning.

## Key Design Decisions

- **Security is never bypassed.** Scanner blocks always trigger a hard abort, regardless of replan budget. Only non-security failures (exit codes, missing files, unexpected output) trigger replanning.
- **Independent budgets** of 3 each for discovery and failure replans. This prevents runaway replan loops while allowing meaningful recovery.
- **Failure replanning shows full context.** The planner receives a FAILURE DIAGNOSTIC header with the complete shell output, exit code, and stderr, enabling informed recovery decisions.

## Two Replan Mechanisms

### Discovery Replanning

Steps can be marked with `replan_after: true` in the plan. When such a step completes, the orchestrator sends the step's output back to the planner with a continuation prompt, allowing the planner to generate additional steps based on what was discovered.

**Use case:** A step that lists directory contents discovers unexpected files. The planner can then generate follow-up steps to handle them.

### Failure Replanning

When a tool execution returns a non-zero exit code, the step is marked `soft_failed` (not hard-aborted). The orchestrator then triggers `_request_continuation(failure_trigger=True)`, sending the planner:

- A FAILURE DIAGNOSTIC header
- The original step that failed
- Full shell output (stdout + stderr)
- The exit code (genericised to "non-zero exit" to prevent information leakage)

The planner can then generate fix steps — install missing dependencies, correct syntax errors, adjust file paths — and continue the task.

**Use case:** A Python script fails because a dependency isn't installed. The planner generates a `pip install` step, then retries the script.

### What Doesn't Trigger Replanning

- **Scanner blocks** — security violations always hard-abort
- **Planner refusals** — if the planner refuses to plan, no replan
- **Budget exhaustion** — after 3 discovery or 3 failure replans, the task completes with what it has

## Where the Code Lives

| File | Purpose |
|------|---------|
| `sentinel/planner/orchestrator.py` | `_request_continuation()` — both replan mechanisms |
| `sentinel/planner/tool_dispatch.py` | `soft_failed` status detection for non-zero exits |
| `sentinel/planner/builders.py` | Failure diagnostic prompt construction |
