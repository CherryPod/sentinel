"""Task success verification — facade re-exporting from focused sub-modules.

Tier 1: Deterministic signals computed after every plan execution (zero cost).
Tier 2: Planner-as-judge invoked when Tier 1 is ambiguous (one API call).

Design doc: docs/design/tasksuccessful-confirmations-20260326.md

Sub-modules:
    _tool_scanning      — tool output scanning, goal action checks, mutations
    _path_normalisation — workspace path rewriting and containment checks
    _evaluators         — assertion evaluator registry (hub)
    _evaluator_fns      — assertion evaluator functions (leaf)
    _evaluation         — sync/async assertion evaluation orchestration
    _classification     — task category classification
    _tier1_consensus    — deterministic signal consensus check
    _judge_payload      — judge prompt construction
    _judge_verdict      — verdict processing and false-positive filtering
"""

# Re-export public API for backward compatibility.
# Consumers should import from sentinel.planner.verification as before.

from sentinel.planner._classification import classify_task_category  # noqa: F401
from sentinel.planner._evaluation import (  # noqa: F401
    evaluate_assertions,
    evaluate_assertions_async,
)
from sentinel.planner._evaluators import EVALUATORS as _EVALUATORS  # noqa: F401
from sentinel.planner._evaluators import AssertionResult  # noqa: F401
from sentinel.planner._judge_payload import (  # noqa: F401
    _format_manifest,
    build_judge_payload,
)
from sentinel.planner._judge_verdict import (  # noqa: F401
    _is_false_positive_gap,
    process_judge_verdict,
)
from sentinel.planner._path_normalisation import (  # noqa: F401
    check_path_in_workspace as _check_path_in_workspace,
)
from sentinel.planner._path_normalisation import (
    normalise_assertion_path as _normalise_assertion_path,
)
from sentinel.planner._path_normalisation import (
    normalise_cmd_paths as _normalise_cmd_paths,
)
from sentinel.planner._tier1_consensus import (  # noqa: F401
    TIER1_CONSENSUS_INSTRUCTION as _TIER1_CONSENSUS_INSTRUCTION,
)
from sentinel.planner._tier1_consensus import (
    check_tier1_consensus as _check_tier1_consensus,
)
from sentinel.planner._tool_scanning import (
    ToolOutputWarning,
    check_goal_actions_executed,
    check_stagnation,
    detect_idempotent_calls,
    extract_file_mutations,
    scan_tool_output,
)

__all__ = [
    # _tool_scanning
    "scan_tool_output",
    "check_goal_actions_executed",
    "extract_file_mutations",
    "check_stagnation",
    "detect_idempotent_calls",
    "ToolOutputWarning",
    # _evaluators
    "AssertionResult",
    "_EVALUATORS",
    # _evaluation
    "evaluate_assertions",
    "evaluate_assertions_async",
    # _path_normalisation (underscore aliases for backward compat)
    "_normalise_assertion_path",
    "_normalise_cmd_paths",
    "_check_path_in_workspace",
    # _classification
    "classify_task_category",
    # _tier1_consensus (underscore aliases for backward compat)
    "_check_tier1_consensus",
    "_TIER1_CONSENSUS_INSTRUCTION",
    # _judge_payload
    "build_judge_payload",
    "_format_manifest",
    # _judge_verdict
    "process_judge_verdict",
    "_is_false_positive_gap",
]
