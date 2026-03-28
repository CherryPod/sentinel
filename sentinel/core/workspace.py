"""Centralised workspace path construction for per-user isolation.

ALL workspace path construction MUST go through get_user_workspace().
This is the single place where user_id maps to a filesystem path.
"""

from __future__ import annotations

from pathlib import Path

from sentinel.core.config import settings
from sentinel.core.context import current_user_id


def get_user_workspace(
    user_id: int | None = None,
    base_path: str | None = None,
) -> Path:
    """Return the workspace directory for a user.

    Args:
        user_id: Explicit user ID. If None, reads from current_user_id ContextVar.
        base_path: Override base workspace path. Defaults to settings.workspace_path.

    Returns:
        Path like /workspace/3 for user_id=3.

    Raises:
        ValueError: If user_id is 0 (unset ContextVar / no auth context).
    """
    if user_id is None:
        user_id = current_user_id.get()
    if user_id == 0:
        raise ValueError(
            "No user context — cannot construct workspace path. "
            "Ensure request has been authenticated before accessing workspace."
        )
    base = Path(base_path) if base_path else Path(settings.workspace_path)
    return base / str(user_id)
