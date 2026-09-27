"""Protocol defining the contract handler mixins expect from ToolExecutor.

Each handler mixin (FileHandlerMixin, WebsiteHandlerMixin, etc.) accesses
shared state on ``self`` that is actually defined in ToolExecutor.  This
Protocol makes those accesses type-safe — mypy can catch typos and IDE
autocomplete works across mixin boundaries.

Handler mixins should type-hint ``self: ToolExecutorServices`` on methods
that access parent state.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    from sentinel.security.policy_engine import PolicyEngine
    from sentinel.tools.sandbox import PodmanSandbox
    from sentinel.tools.sidecar import SidecarClient


@runtime_checkable
class ToolExecutorServices(Protocol):
    """Attributes and methods that handler mixins expect from ToolExecutor.

    Attributes are set in ``ToolExecutor.__init__()`` or via ``set_*()``
    wiring methods during startup.  Methods are defined on ToolExecutor
    itself and used by handler mixins.
    """

    # ------------------------------------------------------------------
    # Core services (set in __init__)
    # ------------------------------------------------------------------
    _engine: PolicyEngine
    _sidecar: SidecarClient | None
    _sandbox: PodmanSandbox | None
    _trust_level: int
    _google_oauth: object | None

    # ------------------------------------------------------------------
    # Wired post-init (set via set_channel_registry / set_* methods)
    # ------------------------------------------------------------------
    _channel_registry: object | None
    _credential_store: object | None
    _episodic_store: object | None
    _ingester: object | None

    # ------------------------------------------------------------------
    # Methods used by handler mixins
    # ------------------------------------------------------------------

    async def _resolve_credentials(self, service: str) -> dict | None:
        """Look up per-user credentials for a service."""
        ...
