"""Config-driven provider factory.

Creates worker, planner, and embedding provider instances based on
settings.  Keeps construction logic in one place so app.py lifespan
doesn't need to know about concrete classes.
"""

from sentinel.core.config import Settings
from sentinel.worker.base import EmbeddingBase, PlannerBase, WorkerBase


def create_worker(s: Settings) -> WorkerBase:
    """Create a worker provider based on config."""
    if s.worker_provider == "ollama":
        from sentinel.worker.ollama import OllamaWorker

        return OllamaWorker(base_url=s.ollama_url, timeout=s.ollama_timeout)
    raise ValueError(f"Unknown worker provider: {s.worker_provider}")


def create_planner(s: Settings) -> PlannerBase:
    """Create a planner provider based on config."""
    if s.planner_provider == "claude":
        from sentinel.planner.planner import ClaudePlanner

        return ClaudePlanner()
    raise ValueError(f"Unknown planner provider: {s.planner_provider}")


def create_embedding_client(s: Settings) -> EmbeddingBase:
    """Create an embedding provider based on config."""
    if s.embedding_provider == "ollama":
        from sentinel.memory.embeddings import EmbeddingClient

        return EmbeddingClient(
            base_url=s.ollama_url,
            model=s.embeddings_model,
            timeout=s.embeddings_timeout,
        )
    raise ValueError(f"Unknown embedding provider: {s.embedding_provider}")
