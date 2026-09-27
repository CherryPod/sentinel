"""Context provider protocol for learning context assembly.

Each context source (domain summary, planning insights, canonical trajectory,
episodic records, detailed plan history, anchor maps) implements the
ContextProvider protocol. The builder iterates over providers in priority
order, assembling sections within a token budget.

Adding a new context source = implementing ContextProvider + adding it
to _default_providers() in builders.py.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    from sentinel.memory.chunks import MemoryStore
    from sentinel.worker.base import EmbeddingBase


@dataclass(frozen=True)
class ContextBuildArgs:
    """Shared arguments passed to every context provider.

    Providers pick what they need and ignore the rest. All fields are
    optional (None) so providers degrade gracefully when a dependency
    is unavailable.
    """

    user_request: str
    domain: str | None
    user_id: int | None
    memory_store: MemoryStore | None = None
    embedding_client: EmbeddingBase | None = None
    reranker: object | None = None
    domain_summary_store: object | None = None
    episodic_store: object | None = None
    insight_store: object | None = None
    # Populated by the episodic search provider, consumed by downstream
    # providers (detailed plan history, record accumulation).
    search_results: list | None = None


@dataclass(frozen=True)
class ContextSection:
    """A single section of learning context returned by a provider.

    Attributes:
        name: Provider name (for logging/debugging).
        text: The formatted section text (or "" if nothing to contribute).
        priority: Assembly order (lower = earlier in context). Providers
            with the same priority preserve registration order.
        budget_aware: If True, the builder may trim this section to fit
            remaining budget (e.g. anchor maps). If False, included in
            full or not at all.
    """

    name: str
    text: str
    priority: int = 50
    budget_aware: bool = False


@runtime_checkable
class ContextProvider(Protocol):
    """Protocol for context providers.

    Each provider fetches one section of learning context. Providers are
    called concurrently where possible, then assembled in priority order.
    """

    @property
    def name(self) -> str:
        """Short identifier for logging (e.g. 'domain_summary')."""
        ...

    @property
    def priority(self) -> int:
        """Assembly order — lower values appear earlier in context."""
        ...

    async def build(self, args: ContextBuildArgs) -> ContextSection:
        """Build this context section.

        Must be non-fatal: swallow errors internally and return an empty
        ContextSection on failure. The builder never catches provider
        exceptions — providers are responsible for their own error handling.
        """
        ...
