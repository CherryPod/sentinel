# Orchestrator Refactor

The orchestrator was split from a 2,662-line monolith into 5 focused modules, reducing the core to 1,390 lines (48% reduction). The refactor preserved all security invariants and was validated at every phase by a dedicated safety-net test suite.

## Key Design Decisions

- **Security invariants are non-negotiable.** Five invariants (S1-S5) were defined before the refactor started, verified at every phase. The `_execute_tool_call()` method is deliberately kept to 23 lines so the S3→resolve→S4→S5 chain is visible at a glance.
- **Extract by responsibility, not by size.** Each module has a clear domain.
- **Safety-net tests prevent regressions.** 8 canary tests verify security-critical code paths. These tests are never modified.

## Module Breakdown

**orchestrator.py (1,390 lines)** — Core execution loop. Plan execution, step sequencing, dynamic replanning, LLM interactions, task lifecycle.

**builders.py (564 lines)** — Prompt construction and metadata. Step outcome summaries, session context, cross-session memory, output format enforcement, trust-tier classification.

**intake.py (260 lines)** — Intake pipeline. Session binding, lock checks, conversation analysis for multi-turn attack detection, contact resolution.

**tool_dispatch.py (384 lines)** — Provenance verification (S3), constraint validation (S4), tool execution with output scanning (S5). Security ordering is an invariant.

**safe_tools.py (451 lines)** — Internal tools that never involve the worker LLM: health checks, session info, memory operations, routine queries, episodic recall.

## Security Invariants

| ID | Invariant | Where Enforced |
|----|-----------|----------------|
| S1 | Input scan before planning | `intake.py` |
| S2 | Output scan after LLM generation | `orchestrator.py` |
| S3 | Provenance check before arg resolution | `tool_dispatch.py` |
| S4 | Constraint validation on resolved args | `tool_dispatch.py` |
| S5 | Output scan before result return | `tool_dispatch.py` |

## Where the Code Lives

| File | Purpose |
|------|---------|
| `sentinel/planner/orchestrator.py` | Core execution loop, plan management, replanning |
| `sentinel/planner/builders.py` | Prompt construction, metadata, format enforcement |
| `sentinel/planner/intake.py` | Session binding, input scan, contact resolution |
| `sentinel/planner/tool_dispatch.py` | S3/S4/S5 enforcement, tool execution |
| `sentinel/planner/safe_tools.py` | Internal tool handlers |
| `tests/test_refactor_safety_net.py` | 8 canary tests (never modify) |
