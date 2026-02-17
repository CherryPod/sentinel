# Episodic Learning

Sentinel maintains long-term episodic memory that records task outcomes, tool usage, errors, and successful strategies. This memory provides the planner with relevant context from past sessions, improving plan quality over time without retraining the LLM.

## Key Design Decisions

- **All episodic data is trusted by construction.** Records are built from orchestrator-generated metadata (step outcomes, tool status, exit codes), never from raw worker output.
- **Embedding on CPU, not GPU.** nomic-embed-text (274MB, 768-dim) is pinned to CPU via `num_gpu: 0` to avoid VRAM contention with the worker LLM.
- **Hybrid retrieval** combines full-text search (PostgreSQL tsvector) with vector similarity (pgvector HNSW), followed by cross-encoder reranking and MMR diversity filtering.
- **Source filtering** excludes noise from heartbeat routines and maintenance operations.

## How It Works

### Record Creation

After each task completes, an `EpisodicRecord` is created containing:
- The user's original request and plan summary
- Step-by-step outcomes (tool name, status, exit code, stderr preview)
- File paths affected, error patterns encountered
- Task domain classification (e.g., `code_generation`, `file_ops`, `messaging`)
- Fix-cycle context when the code fixer or failure replan was involved

### Retrieval Pipeline

1. **Full-text search** via PostgreSQL `plainto_tsquery` with `ts_rank_cd` scoring
2. **Vector similarity** via pgvector cosine similarity on the HNSW index
3. **Hybrid merge** combines both result sets with configurable weighting
4. **Cross-encoder reranking** via FlashRank (ms-marco-MiniLM-L-12-v2, CPU-only) with `max_length=512`
5. **MMR diversity filtering** (`lambda=0.7`) ensures top-k results are diverse, not near-duplicates

### Supporting Structures

- **Strategy patterns** track recurring tool sequences per domain
- **Domain summaries** aggregate episodic intelligence per domain per user
- **Canonical trajectories** provide reference examples for common task types

## Where the Code Lives

| File | Purpose |
|------|---------|
| `sentinel/memory/episodic.py` | `EpisodicStore` — record CRUD, search, fact extraction |
| `sentinel/memory/embeddings.py` | Async Ollama client for nomic-embed-text |
| `sentinel/memory/reranker.py` | Cross-encoder reranking + MMR diversity |
| `sentinel/memory/search.py` | Hybrid retrieval (full-text + vector) |
| `sentinel/memory/strategy_store.py` | Strategy pattern tracking |
