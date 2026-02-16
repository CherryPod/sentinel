import uuid
from datetime import datetime, timezone

from sentinel.core.models import DataSource, TaggedData, TrustLevel

MAX_PROVENANCE_ENTRIES = 10_000
MAX_FILE_PROVENANCE_ENTRIES = 10_000

# In-memory store for provenance tracking — replaced with a DB in production
_store: dict[str, TaggedData] = {}

# File provenance registry: maps file paths to the data_id of the write that created them.
# Used to prevent trust laundering — file_read inherits trust from the writer, not a default.
_file_provenance: dict[str, str] = {}


def _evict_oldest(store: dict, max_size: int) -> None:
    """Remove oldest entries (by insertion order) when store exceeds max_size."""
    if len(store) > max_size:
        excess = len(store) - max_size
        for key in list(store.keys())[:excess]:
            del store[key]


def reset_store() -> None:
    """Clear the provenance store and file provenance registry (used in tests)."""
    _store.clear()
    _file_provenance.clear()


def create_tagged_data(
    content: str,
    source: DataSource,
    trust_level: TrustLevel,
    originated_from: str = "",
    parent_ids: list[str] | None = None,
) -> TaggedData:
    """Create a new TaggedData entry with trust inheritance.

    If any parent is untrusted, the child inherits untrusted regardless
    of the explicitly passed trust_level.
    """
    effective_trust = trust_level
    derived = []

    if parent_ids:
        derived = list(parent_ids)
        for pid in parent_ids:
            parent = _store.get(pid)
            if parent and parent.trust_level == TrustLevel.UNTRUSTED:
                effective_trust = TrustLevel.UNTRUSTED
                break

    tagged = TaggedData(
        id=str(uuid.uuid4()),
        content=content,
        trust_level=effective_trust,
        source=source,
        originated_from=originated_from,
        timestamp=datetime.now(timezone.utc),
        derived_from=derived,
    )
    _store[tagged.id] = tagged
    _evict_oldest(_store, MAX_PROVENANCE_ENTRIES)
    return tagged


def get_tagged_data(data_id: str) -> TaggedData | None:
    return _store.get(data_id)


def get_provenance_chain(data_id: str, max_depth: int = 50) -> list[TaggedData]:
    """Walk the provenance chain back to the roots.

    Returns a list ordered from the given item back to its oldest ancestor.
    Includes cycle detection via a visited set.
    """
    chain: list[TaggedData] = []
    visited: set[str] = set()
    queue = [data_id]

    while queue and len(chain) < max_depth:
        current_id = queue.pop(0)
        if current_id in visited:
            continue
        visited.add(current_id)

        item = _store.get(current_id)
        if item is None:
            continue

        chain.append(item)
        for parent_id in item.derived_from:
            if parent_id not in visited:
                queue.append(parent_id)

    return chain


def is_trust_safe_for_execution(data_id: str) -> bool:
    """Check whether data (and all its ancestors) are trusted."""
    chain = get_provenance_chain(data_id)
    return all(item.trust_level == TrustLevel.TRUSTED for item in chain)


def record_file_write(path: str, data_id: str) -> None:
    """Record that a file was written by a specific provenance chain entry."""
    _file_provenance[path] = data_id
    _evict_oldest(_file_provenance, MAX_FILE_PROVENANCE_ENTRIES)


def get_file_writer(path: str) -> str | None:
    """Get the data_id of the provenance entry that last wrote to this file."""
    return _file_provenance.get(path)
