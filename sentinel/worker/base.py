"""Abstract base classes for LLM providers.

Defines the interface that all worker, planner, and embedding providers must
implement. Concrete implementations (Ollama, Claude, etc.) subclass these.
"""

import logging
from abc import ABC, abstractmethod

# Exception classes moved to sentinel.core.exceptions (SH-3) — re-exported here.
from sentinel.core.exceptions import (  # noqa: F401
    ProviderConnectionError,
    ProviderError,
    ProviderModelNotFound,
    ProviderTimeoutError,
)
from sentinel.core.models import Plan

logger = logging.getLogger(__name__)

# -- Abstract base classes --


class WorkerBase(ABC):
    """Text generation provider (worker role).

    Implementations must handle retries, timeouts, and connection errors
    internally, raising ProviderError subclasses on failure.
    """

    @abstractmethod
    async def generate(
        self,
        prompt: str,
        system_prompt: str | None = None,
        model: str | None = None,
        marker: str = "^",
    ) -> tuple[str, dict | None]:
        """Generate text from a prompt.

        Args:
            prompt: The user/task prompt to generate from.
            system_prompt: Optional system prompt override.
            model: Optional model name override.
            marker: Spotlighting marker character(s).

        Returns:
            Tuple of (generated_text, token_stats_or_None).
        """
        ...


class PlannerBase(ABC):
    """Task planning provider.

    Implementations take a user request and produce a structured Plan
    with steps for the CaMeL execution loop.
    """

    @abstractmethod
    async def create_plan(
        self,
        user_request: str,
        available_tools: list[dict] | None = None,
        policy_summary: str = "",
        conversation_history: list[dict] | None = None,
    ) -> Plan:
        """Create a structured execution plan from a user request.

        Args:
            user_request: The user's natural language request.
            available_tools: Tool descriptions the planner can reference.
            policy_summary: Security policy summary for context.
            conversation_history: Prior conversation turns for multi-turn context.

        Returns:
            A Plan with steps to execute.
        """
        ...


class EmbeddingBase(ABC):
    """Vector embedding provider.

    Implementations produce fixed-dimension vectors from text for
    semantic search.
    """

    @abstractmethod
    async def embed(self, text: str, prefix: str | None = None) -> list[float]:
        """Embed a single text string.

        Args:
            text: Text to embed.
            prefix: Optional prefix to prepend (e.g. "search_document: ").

        Returns:
            Vector of floats (dimension depends on model).
        """
        ...

    @abstractmethod
    async def embed_batch(
        self, texts: list[str], prefix: str | None = None
    ) -> list[list[float]]:
        """Embed multiple texts in a single call.

        Args:
            texts: List of texts to embed.
            prefix: Optional prefix to prepend to each text.

        Returns:
            List of vectors, one per input text, in the same order.
        """
        ...
