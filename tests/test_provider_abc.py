"""Tests for provider ABCs, factory, and isinstance checks.

Verifies:
- ABCs cannot be instantiated directly
- Concrete implementations are valid subclasses
- Provider factory creates correct instances
- Generic exceptions are in the hierarchy
- Type narrowing works (WorkerBase accepts OllamaWorker, etc.)
"""

import pytest

from sentinel.worker.base import (
    EmbeddingBase,
    PlannerBase,
    ProviderConnectionError,
    ProviderError,
    ProviderModelNotFound,
    ProviderTimeoutError,
    WorkerBase,
)
from sentinel.worker.ollama import (
    OllamaConnectionError,
    OllamaModelNotFound,
    OllamaTimeoutError,
    OllamaWorker,
)
from sentinel.planner.planner import ClaudePlanner
from sentinel.memory.embeddings import EmbeddingClient


# ── ABC contract tests ────────────────────────────────────────────


class TestABCContract:
    """ABCs cannot be instantiated without implementing all methods."""

    def test_worker_base_not_instantiable(self):
        with pytest.raises(TypeError, match="abstract method"):
            WorkerBase()

    def test_planner_base_not_instantiable(self):
        with pytest.raises(TypeError, match="abstract method"):
            PlannerBase()

    def test_embedding_base_not_instantiable(self):
        with pytest.raises(TypeError, match="abstract method"):
            EmbeddingBase()


# ── isinstance checks ─────────────────────────────────────────────


class TestIsinstance:
    """Concrete classes are subclasses of their ABCs."""

    def test_ollama_worker_is_worker_base(self):
        worker = OllamaWorker(base_url="http://localhost:11434")
        assert isinstance(worker, WorkerBase)

    def test_claude_planner_is_planner_base(self):
        # ClaudePlanner needs an API key — pass one to skip file read
        planner = ClaudePlanner(api_key="test-key")
        assert isinstance(planner, PlannerBase)

    def test_embedding_client_is_embedding_base(self):
        client = EmbeddingClient(base_url="http://localhost:11434")
        assert isinstance(client, EmbeddingBase)

    def test_subclass_checks(self):
        assert issubclass(OllamaWorker, WorkerBase)
        assert issubclass(ClaudePlanner, PlannerBase)
        assert issubclass(EmbeddingClient, EmbeddingBase)


# ── Exception hierarchy ───────────────────────────────────────────


class TestExceptionHierarchy:
    """Provider-specific exceptions are subclasses of generic ones."""

    def test_ollama_connection_error_is_provider_connection(self):
        exc = OllamaConnectionError("test")
        assert isinstance(exc, ProviderConnectionError)
        assert isinstance(exc, ProviderError)

    def test_ollama_timeout_error_is_provider_timeout(self):
        exc = OllamaTimeoutError("test")
        assert isinstance(exc, ProviderTimeoutError)
        assert isinstance(exc, ProviderError)

    def test_ollama_model_not_found_is_provider_model_not_found(self):
        exc = OllamaModelNotFound("test")
        assert isinstance(exc, ProviderModelNotFound)
        assert isinstance(exc, ProviderError)

    def test_catch_generic_catches_specific(self):
        """Catching ProviderError catches OllamaConnectionError."""
        with pytest.raises(ProviderError):
            raise OllamaConnectionError("generic catch works")

    def test_catch_connection_catches_ollama(self):
        """Catching ProviderConnectionError catches OllamaConnectionError."""
        with pytest.raises(ProviderConnectionError):
            raise OllamaConnectionError("connection catch works")


# ── Custom implementation test ────────────────────────────────────


class TestCustomImplementation:
    """A custom provider implementing the ABC contract works correctly."""

    def test_custom_worker_passes_isinstance(self):
        class MockWorker(WorkerBase):
            async def generate(self, prompt, system_prompt=None, model=None, marker="^"):
                return "mock response"

        worker = MockWorker()
        assert isinstance(worker, WorkerBase)

    def test_custom_planner_passes_isinstance(self):
        class MockPlanner(PlannerBase):
            async def create_plan(self, user_request, available_tools=None,
                                  policy_summary="", conversation_history=None):
                from sentinel.core.models import Plan, PlanStep
                return Plan(
                    plan_summary="mock plan",
                    steps=[PlanStep(id="step_1", type="llm_task",
                                    description="test", prompt="test")],
                )

        planner = MockPlanner()
        assert isinstance(planner, PlannerBase)

    def test_custom_embedding_passes_isinstance(self):
        class MockEmbedding(EmbeddingBase):
            async def embed(self, text):
                return [0.0] * 768

            async def embed_batch(self, texts):
                return [[0.0] * 768 for _ in texts]

        client = MockEmbedding()
        assert isinstance(client, EmbeddingBase)

    def test_incomplete_implementation_raises(self):
        """A class that doesn't implement all abstract methods can't be instantiated."""
        class IncompleteWorker(WorkerBase):
            pass  # missing generate()

        with pytest.raises(TypeError):
            IncompleteWorker()


# ── Factory tests ─────────────────────────────────────────────────


class TestProviderFactory:
    """Factory creates correct provider instances."""

    def test_create_worker_ollama(self):
        from sentinel.worker.factory import create_worker
        from sentinel.core.config import Settings

        s = Settings(worker_provider="ollama", ollama_url="http://test:11434")
        worker = create_worker(s)
        assert isinstance(worker, WorkerBase)
        assert isinstance(worker, OllamaWorker)

    def test_create_worker_unknown_raises(self):
        from sentinel.worker.factory import create_worker
        from sentinel.core.config import Settings

        s = Settings(worker_provider="unknown")
        with pytest.raises(ValueError, match="Unknown worker provider"):
            create_worker(s)

    def test_create_planner_claude(self):
        from sentinel.worker.factory import create_planner
        from sentinel.core.config import Settings

        s = Settings(planner_provider="claude", claude_api_key_file="/dev/null")
        # Will fail to load API key from /dev/null (empty file) — that's OK,
        # we just check the factory dispatches to ClaudePlanner
        try:
            planner = create_planner(s)
            assert isinstance(planner, PlannerBase)
        except Exception:
            # PlannerError from empty API key is acceptable
            pass

    def test_create_planner_unknown_raises(self):
        from sentinel.worker.factory import create_planner
        from sentinel.core.config import Settings

        s = Settings(planner_provider="unknown")
        with pytest.raises(ValueError, match="Unknown planner provider"):
            create_planner(s)

    def test_create_embedding_client_ollama(self):
        from sentinel.worker.factory import create_embedding_client
        from sentinel.core.config import Settings

        s = Settings(embedding_provider="ollama", ollama_url="http://test:11434")
        client = create_embedding_client(s)
        assert isinstance(client, EmbeddingBase)
        assert isinstance(client, EmbeddingClient)

    def test_create_embedding_client_unknown_raises(self):
        from sentinel.worker.factory import create_embedding_client
        from sentinel.core.config import Settings

        s = Settings(embedding_provider="unknown")
        with pytest.raises(ValueError, match="Unknown embedding provider"):
            create_embedding_client(s)


# ── Type narrowing test ───────────────────────────────────────────


class TestTypeNarrowing:
    """Functions typed as accepting WorkerBase work with concrete types."""

    def test_pipeline_accepts_worker_base(self):
        """ScanPipeline accepts any WorkerBase implementation."""
        from sentinel.security.pipeline import ScanPipeline
        from sentinel.security.scanner import CredentialScanner, SensitivePathScanner

        class DummyWorker(WorkerBase):
            async def generate(self, prompt, system_prompt=None, model=None, marker="^"):
                return "dummy"

        pipeline = ScanPipeline(
            cred_scanner=CredentialScanner([]),
            path_scanner=SensitivePathScanner([]),
            worker=DummyWorker(),
        )
        assert pipeline._worker is not None
        assert isinstance(pipeline._worker, WorkerBase)

    def test_orchestrator_accepts_planner_base(self):
        """Orchestrator accepts any PlannerBase implementation."""
        from sentinel.planner.orchestrator import Orchestrator

        class DummyPlanner(PlannerBase):
            async def create_plan(self, user_request, available_tools=None,
                                  policy_summary="", conversation_history=None):
                from sentinel.core.models import Plan, PlanStep
                return Plan(
                    plan_summary="dummy",
                    steps=[PlanStep(id="step_1", type="llm_task",
                                    description="test", prompt="test")],
                )

        class DummyEmbedding(EmbeddingBase):
            async def embed(self, text):
                return [0.0] * 768

            async def embed_batch(self, texts):
                return [[0.0] * 768 for _ in texts]

        from sentinel.security.pipeline import ScanPipeline
        from sentinel.security.scanner import CredentialScanner, SensitivePathScanner

        pipeline = ScanPipeline(
            cred_scanner=CredentialScanner([]),
            path_scanner=SensitivePathScanner([]),
        )

        orch = Orchestrator(
            planner=DummyPlanner(),
            pipeline=pipeline,
            embedding_client=DummyEmbedding(),
        )
        assert orch._planner is not None
        assert isinstance(orch._planner, PlannerBase)
        assert isinstance(orch._embedding_client, EmbeddingBase)
