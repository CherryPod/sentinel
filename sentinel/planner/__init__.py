"""Sentinel Planner package.

Logger discipline (Q16-FL6 / C42 + D28): no forbidden value-pattern may
appear inside ``logger.*`` extras-dict values OR positional arguments within
this package. Forbidden patterns are **direct Attribute access**
(``<expr>.<attr>``) AND **getattr() Call** (``getattr(<expr>, "<attr>", ...)``)
for any attribute in the class-scoped denylist::

    FORBIDDEN_VALUE_ATTRS = {
        "plan_summary",       # C42 lineage
        "user_request",       # D28 extension
        "user_request_full",  # D28 extension
        "file_path",          # D28 extension
    }

Sibling extras-key bypasses are covered because the check is keyed on the
**value AST shape**, not literal key names. The CI invariant is enforced by
``tests/test_planner_logger_extras_drift.py`` (static denylist); the
cure-shape regression pin lives at
``tests/test_planner_logger_extras_cure_shape.py``.

Allowed surrogate shapes — use these in logger extras:
  * ``len(plan.plan_summary) if plan.plan_summary else 0``
  * ``log_hash(getattr(fact, "file_path", None) or "")``
  * ``len(getattr(fact, "file_path", "") or "")``
  * ``len(record.user_request) if record.user_request else 0``
"""

import logging

logger = logging.getLogger(__name__)
