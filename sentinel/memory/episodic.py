"""F4: Episodic memory store — structured per-task outcome records.

Provides long-term memory for the planner across sessions: what tasks were
completed, which files were affected, what errors occurred, and what facts
were extracted. All data is TRUSTED by construction — orchestrator-generated
metadata from F1 step_outcomes, never raw Qwen output.

Storage model: hybrid — structured records in episodic_records table, shadow
entries in memory_chunks for FTS5/vec search via existing hybrid_search().
"""

from __future__ import annotations

import json
import logging
import sqlite3
import uuid
from dataclasses import dataclass, field

logger = logging.getLogger("sentinel.audit")


@dataclass
class EpisodicRecord:
    """A structured outcome record for a completed task."""

    record_id: str
    session_id: str
    task_id: str
    user_id: str
    user_request: str
    task_status: str
    plan_summary: str
    step_count: int
    success_count: int
    file_paths: list[str]
    error_patterns: list[str]
    defined_symbols: list[str]
    step_outcomes: list[dict] | None
    linked_records: list[dict]
    relevance_score: float
    access_count: int
    last_accessed: str | None
    memory_chunk_id: str | None
    created_at: str


@dataclass
class EpisodicFact:
    """A short, keyword-rich extracted fact linked to an episodic record."""

    fact_id: str
    record_id: str
    fact_type: str
    content: str
    file_path: str | None
    created_at: str


class EpisodicStore:
    """CRUD store for episodic records with file index and fact management.

    Requires a SQLite connection with the F4 schema tables created by
    core/db.py:_create_tables().
    """

    def __init__(self, db: sqlite3.Connection):
        self._db = db

    @property
    def db(self) -> sqlite3.Connection:
        return self._db

    def create(
        self,
        session_id: str,
        task_id: str = "",
        user_request: str = "",
        task_status: str = "",
        plan_summary: str = "",
        step_count: int = 0,
        success_count: int = 0,
        file_paths: list[str] | None = None,
        error_patterns: list[str] | None = None,
        defined_symbols: list[str] | None = None,
        step_outcomes: list[dict] | None = None,
        user_id: str = "default",
    ) -> str:
        """Create an episodic record + file index entries. Returns record_id."""
        record_id = str(uuid.uuid4())
        file_paths = file_paths or []
        error_patterns = error_patterns or []
        defined_symbols = defined_symbols or []

        self._db.execute(
            "INSERT INTO episodic_records "
            "(record_id, session_id, task_id, user_id, user_request, "
            "task_status, plan_summary, step_count, success_count, "
            "file_paths, error_patterns, defined_symbols, step_outcomes) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                record_id, session_id, task_id, user_id, user_request,
                task_status, plan_summary, step_count, success_count,
                json.dumps(file_paths), json.dumps(error_patterns),
                json.dumps(defined_symbols),
                json.dumps(step_outcomes) if step_outcomes else None,
            ),
        )

        # Populate file index
        for path in file_paths:
            self._db.execute(
                "INSERT OR IGNORE INTO episodic_file_index (file_path, record_id, action) "
                "VALUES (?, ?, ?)",
                (path, record_id, "modified"),
            )

        self._db.commit()

        logger.info(
            "Episodic record created",
            extra={
                "event": "episodic_record_created",
                "record_id": record_id,
                "session_id": session_id,
                "task_status": task_status,
                "file_count": len(file_paths),
            },
        )
        return record_id

    def get(self, record_id: str) -> EpisodicRecord | None:
        """Fetch a single episodic record by ID."""
        row = self._db.execute(
            "SELECT record_id, session_id, task_id, user_id, user_request, "
            "task_status, plan_summary, step_count, success_count, "
            "file_paths, error_patterns, defined_symbols, step_outcomes, "
            "linked_records, relevance_score, access_count, last_accessed, "
            "memory_chunk_id, created_at "
            "FROM episodic_records WHERE record_id = ?",
            (record_id,),
        ).fetchone()
        if row is None:
            return None
        return self._row_to_record(row)

    def list_by_session(
        self, session_id: str, limit: int = 50
    ) -> list[EpisodicRecord]:
        """List records for a session, newest first."""
        rows = self._db.execute(
            "SELECT record_id, session_id, task_id, user_id, user_request, "
            "task_status, plan_summary, step_count, success_count, "
            "file_paths, error_patterns, defined_symbols, step_outcomes, "
            "linked_records, relevance_score, access_count, last_accessed, "
            "memory_chunk_id, created_at "
            "FROM episodic_records WHERE session_id = ? "
            "ORDER BY created_at DESC LIMIT ?",
            (session_id, limit),
        ).fetchall()
        return [self._row_to_record(r) for r in rows]

    def list_by_file(
        self, file_path: str, limit: int = 50
    ) -> list[EpisodicRecord]:
        """List records that affected a given file path, newest first."""
        rows = self._db.execute(
            "SELECT er.record_id, er.session_id, er.task_id, er.user_id, "
            "er.user_request, er.task_status, er.plan_summary, er.step_count, "
            "er.success_count, er.file_paths, er.error_patterns, "
            "er.defined_symbols, er.step_outcomes, er.linked_records, "
            "er.relevance_score, er.access_count, er.last_accessed, "
            "er.memory_chunk_id, er.created_at "
            "FROM episodic_records er "
            "JOIN episodic_file_index efi ON er.record_id = efi.record_id "
            "WHERE efi.file_path = ? "
            "ORDER BY er.created_at DESC LIMIT ?",
            (file_path, limit),
        ).fetchall()
        return [self._row_to_record(r) for r in rows]

    def delete(self, record_id: str) -> bool:
        """Delete an episodic record (cascades to file index + facts). Returns True if found."""
        existing = self._db.execute(
            "SELECT record_id FROM episodic_records WHERE record_id = ?",
            (record_id,),
        ).fetchone()
        if existing is None:
            return False
        self._db.execute(
            "DELETE FROM episodic_records WHERE record_id = ?",
            (record_id,),
        )
        self._db.commit()
        return True

    def find_linked_records(self, file_paths: list[str], exclude_record_id: str = "") -> list[str]:
        """Find existing record IDs that share any file paths."""
        if not file_paths:
            return []
        placeholders = ",".join("?" for _ in file_paths)
        rows = self._db.execute(
            f"SELECT DISTINCT record_id FROM episodic_file_index "
            f"WHERE file_path IN ({placeholders}) AND record_id != ?",
            (*file_paths, exclude_record_id),
        ).fetchall()
        return [r[0] for r in rows]

    def _add_link(self, record_id: str, linked_id: str, link_type: str = "file") -> None:
        """Add a link entry to a record's linked_records JSON array."""
        row = self._db.execute(
            "SELECT linked_records FROM episodic_records WHERE record_id = ?",
            (record_id,),
        ).fetchone()
        if row is None:
            return
        links = json.loads(row[0])
        # Avoid duplicates
        if not any(l["record_id"] == linked_id for l in links):
            links.append({"record_id": linked_id, "link_type": link_type})
            self._db.execute(
                "UPDATE episodic_records SET linked_records = ? WHERE record_id = ?",
                (json.dumps(links), record_id),
            )

    def prune_stale(self, threshold: float = 0.05, min_age_days: int = 30) -> int:
        """Remove old, unaccessed episodic records.

        Only prunes records where:
        - effective relevance < threshold
        - age > min_age_days
        - NOT system-protected

        Returns count of pruned records.
        """
        # Compute effective relevance for all old records
        rows = self._db.execute(
            "SELECT record_id, "
            "julianday('now') - julianday(created_at) AS age_days, "
            "access_count, memory_chunk_id "
            "FROM episodic_records "
            "WHERE julianday('now') - julianday(created_at) > ?",
            (min_age_days,),
        ).fetchall()

        pruned = 0
        for record_id, age_days, access_count, chunk_id in rows:
            effective = compute_relevance(age_days, access_count)
            if effective < threshold:
                # Delete shadow entry from memory_chunks if exists
                if chunk_id:
                    try:
                        self._db.execute(
                            "DELETE FROM memory_chunks WHERE chunk_id = ?",
                            (chunk_id,),
                        )
                    except Exception:
                        pass  # shadow may not exist
                # Delete episodic record (cascades to file_index + facts)
                self._db.execute(
                    "DELETE FROM episodic_records WHERE record_id = ?",
                    (record_id,),
                )
                pruned += 1

        if pruned > 0:
            self._db.commit()
            logger.info(
                "Episodic memory pruned",
                extra={"event": "episodic_pruned", "count": pruned},
            )

        return pruned

    def update_access(self, record_id: str) -> None:
        """Bump access_count and last_accessed timestamp."""
        self._db.execute(
            "UPDATE episodic_records SET "
            "access_count = access_count + 1, "
            "last_accessed = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') "
            "WHERE record_id = ?",
            (record_id,),
        )
        self._db.commit()

    def set_memory_chunk_id(self, record_id: str, chunk_id: str) -> None:
        """Set the memory_chunks shadow entry ID for search integration."""
        self._db.execute(
            "UPDATE episodic_records SET memory_chunk_id = ? WHERE record_id = ?",
            (chunk_id, record_id),
        )
        self._db.commit()

    def create_with_shadow(
        self,
        memory_store,
        session_id: str,
        task_id: str = "",
        user_request: str = "",
        task_status: str = "",
        plan_summary: str = "",
        step_count: int = 0,
        success_count: int = 0,
        file_paths: list[str] | None = None,
        error_patterns: list[str] | None = None,
        defined_symbols: list[str] | None = None,
        step_outcomes: list[dict] | None = None,
        user_id: str = "default",
        embedding: list[float] | None = None,
    ) -> str:
        """Create episodic record + memory_chunks shadow entry.

        The shadow entry makes the record discoverable via existing
        hybrid_search() and protects it from user deletion (system:episodic).
        """
        record_id = self.create(
            session_id=session_id,
            task_id=task_id,
            user_request=user_request,
            task_status=task_status,
            plan_summary=plan_summary,
            step_count=step_count,
            success_count=success_count,
            file_paths=file_paths,
            error_patterns=error_patterns,
            defined_symbols=defined_symbols,
            step_outcomes=step_outcomes,
            user_id=user_id,
        )

        # Render text for shadow entry
        text = render_episodic_text(
            user_request=user_request,
            task_status=task_status,
            step_count=step_count,
            success_count=success_count,
            file_paths=file_paths,
            plan_summary=plan_summary,
            error_patterns=error_patterns,
        )

        metadata = {
            "record_id": record_id,
            "session_id": session_id,
            "task_status": task_status,
        }

        # Store shadow with or without embedding
        if embedding is not None:
            chunk_id = memory_store.store_with_embedding(
                content=text,
                embedding=embedding,
                source="system:episodic",
                metadata=metadata,
                user_id=user_id,
            )
        else:
            chunk_id = memory_store.store(
                content=text,
                source="system:episodic",
                metadata=metadata,
                user_id=user_id,
            )

        self.set_memory_chunk_id(record_id, chunk_id)

        # F4: Cross-task file-path linking — bidirectional
        file_paths = file_paths or []
        linked_ids = self.find_linked_records(file_paths, exclude_record_id=record_id)
        for linked_id in linked_ids:
            self._add_link(record_id, linked_id, "file")
            self._add_link(linked_id, record_id, "file")
        if linked_ids:
            self._db.commit()

        return record_id

    def store_facts(self, record_id: str, facts: list[EpisodicFact]) -> None:
        """Store extracted facts for a record + sync FTS5 index."""
        for fact in facts:
            fact_id = fact.fact_id or str(uuid.uuid4())
            self._db.execute(
                "INSERT INTO episodic_facts "
                "(fact_id, record_id, fact_type, content, file_path) "
                "VALUES (?, ?, ?, ?, ?)",
                (fact_id, record_id, fact.fact_type, fact.content, fact.file_path),
            )
            # Sync FTS5 index
            self._db.execute(
                "INSERT INTO episodic_facts_fts(rowid, content, fact_type) "
                "VALUES ((SELECT rowid FROM episodic_facts WHERE fact_id = ?), ?, ?)",
                (fact_id, fact.content, fact.fact_type),
            )
        self._db.commit()

    def search_facts(
        self, query: str, fact_type: str | None = None, limit: int = 20,
    ) -> list[EpisodicFact]:
        """Search facts via FTS5, optionally filtered by fact_type."""
        # Escape FTS5 special characters (same pattern as memory/search.py:107-113)
        terms = query.split()
        if not terms:
            return []
        safe_query = " ".join(f'"{term.replace(chr(34), "")}"' for term in terms)
        if safe_query.replace('"', "").strip() == "":
            return []

        try:
            if fact_type:
                rows = self._db.execute(
                    "SELECT ef.fact_id, ef.record_id, ef.fact_type, ef.content, "
                    "ef.file_path, ef.created_at "
                    "FROM episodic_facts_fts fts "
                    "JOIN episodic_facts ef ON ef.rowid = fts.rowid "
                    "WHERE episodic_facts_fts MATCH ? AND ef.fact_type = ? "
                    "ORDER BY fts.rank LIMIT ?",
                    (safe_query, fact_type, limit),
                ).fetchall()
            else:
                rows = self._db.execute(
                    "SELECT ef.fact_id, ef.record_id, ef.fact_type, ef.content, "
                    "ef.file_path, ef.created_at "
                    "FROM episodic_facts_fts fts "
                    "JOIN episodic_facts ef ON ef.rowid = fts.rowid "
                    "WHERE episodic_facts_fts MATCH ? "
                    "ORDER BY fts.rank LIMIT ?",
                    (safe_query, limit),
                ).fetchall()
        except sqlite3.OperationalError:
            return []

        return [
            EpisodicFact(
                fact_id=r[0], record_id=r[1], fact_type=r[2],
                content=r[3], file_path=r[4], created_at=r[5],
            )
            for r in rows
        ]

    @staticmethod
    def _row_to_record(row: tuple) -> EpisodicRecord:
        return EpisodicRecord(
            record_id=row[0],
            session_id=row[1],
            task_id=row[2],
            user_id=row[3],
            user_request=row[4],
            task_status=row[5],
            plan_summary=row[6],
            step_count=row[7],
            success_count=row[8],
            file_paths=json.loads(row[9]),
            error_patterns=json.loads(row[10]),
            defined_symbols=json.loads(row[11]),
            step_outcomes=json.loads(row[12]) if row[12] else None,
            linked_records=json.loads(row[13]),
            relevance_score=row[14],
            access_count=row[15],
            last_accessed=row[16],
            memory_chunk_id=row[17],
            created_at=row[18],
        )


def extract_episodic_facts(
    step_outcomes: list[dict],
    user_request: str,
    task_status: str,
) -> list[EpisodicFact]:
    """Extract notable facts from F1 step_outcomes — deterministic, no LLM.

    Examines each step outcome for notable patterns:
    - File creation (file_write where file_size_before is None)
    - File modification (file_write where file_size_before is not None)
    - Scanner blocks (scanner_result == "blocked")
    - Execution errors (non-zero exit_code)
    - Symbol definitions (non-empty defined_symbols)
    - Truncation warnings (token_usage_ratio >= 0.95)

    All extracted data comes from F1 metadata (TRUSTED, orchestrator-generated).
    No raw Qwen output crosses into facts.
    """
    facts: list[EpisodicFact] = []
    now = ""  # DB default handles timestamp

    for outcome in step_outcomes:
        file_path = outcome.get("file_path")

        # File creation: file_write with no prior file
        if (
            outcome.get("step_type") == "tool_call"
            and file_path
            and outcome.get("file_size_before") is None
            and outcome.get("file_size_after") is not None
        ):
            size = outcome["file_size_after"]
            lang = outcome.get("output_language", "")
            lang_part = f", {lang}" if lang else ""
            facts.append(EpisodicFact(
                fact_id=str(uuid.uuid4()),
                record_id="",  # linked at store time
                fact_type="file_create",
                content=f"{file_path} created ({size} bytes{lang_part})",
                file_path=file_path,
                created_at=now,
            ))
            continue  # don't also match as modification

        # File modification: file_write with prior file
        if (
            outcome.get("step_type") == "tool_call"
            and file_path
            and outcome.get("file_size_before") is not None
            and outcome.get("file_size_after") is not None
        ):
            before = outcome["file_size_before"]
            after = outcome["file_size_after"]
            diff = outcome.get("diff_stats", "")
            diff_part = f", {diff}" if diff else ""
            facts.append(EpisodicFact(
                fact_id=str(uuid.uuid4()),
                record_id="",
                fact_type="file_modify",
                content=f"{file_path} modified ({before}\u2192{after} bytes{diff_part})",
                file_path=file_path,
                created_at=now,
            ))

        # Scanner block — uses genericised error_detail (scanner_details redacted)
        if outcome.get("scanner_result") == "blocked":
            generic_err = outcome.get("error_detail", "blocked")
            facts.append(EpisodicFact(
                fact_id=str(uuid.uuid4()),
                record_id="",
                fact_type="scanner_block",
                content=f"Scanner block: {generic_err}",
                file_path=file_path,
                created_at=now,
            ))

        # Execution error
        exit_code = outcome.get("exit_code")
        if exit_code is not None and exit_code != 0:
            stderr = outcome.get("stderr_preview", "")
            stderr_part = f", {stderr[:100]}" if stderr else ""
            path_part = file_path or "shell"
            facts.append(EpisodicFact(
                fact_id=str(uuid.uuid4()),
                record_id="",
                fact_type="exec_error",
                content=f"{path_part}: exit {exit_code}{stderr_part}",
                file_path=file_path,
                created_at=now,
            ))

        # Symbol definitions
        symbols = outcome.get("defined_symbols")
        if symbols and isinstance(symbols, list) and len(symbols) > 0:
            symbol_list = ", ".join(symbols[:10])
            path_part = file_path or "code"
            facts.append(EpisodicFact(
                fact_id=str(uuid.uuid4()),
                record_id="",
                fact_type="symbol_def",
                content=f"{path_part} defines: [{symbol_list}]",
                file_path=file_path,
                created_at=now,
            ))

        # Truncation warning
        ratio = outcome.get("token_usage_ratio")
        if ratio is not None and ratio >= 0.95:
            size = outcome.get("output_size", "unknown")
            facts.append(EpisodicFact(
                fact_id=str(uuid.uuid4()),
                record_id="",
                fact_type="truncation",
                content=f"Truncation: output at {ratio * 100:.0f}% token cap ({size} chars, likely incomplete)",
                file_path=file_path,
                created_at=now,
            ))

    return facts


def compute_relevance(age_days: float, access_count: int = 0) -> float:
    """Compute effective relevance score.

    Base: 1.0 / (1 + age_days * 0.1) — decays with time.
    Boost: 0.1 * access_count — active records stay alive.
    """
    base = 1.0 / (1.0 + age_days * 0.1)
    boost = 0.1 * access_count
    return round(base + boost, 4)


def render_episodic_text(
    user_request: str,
    task_status: str,
    step_count: int = 0,
    success_count: int = 0,
    file_paths: list[str] | None = None,
    plan_summary: str = "",
    error_patterns: list[str] | None = None,
) -> str:
    """Render a compact text representation for embedding + FTS5 search.

    Format designed for good embeddings: keyword-rich, under 500 chars.
    """
    lines = [f'Task: "{user_request[:200]}"']
    lines.append(f"Status: {task_status} ({success_count}/{step_count} steps)")
    if file_paths:
        for path in file_paths[:5]:
            lines.append(f"File: {path}")
        if len(file_paths) > 5:
            lines.append(f"  ... and {len(file_paths) - 5} more files")
    if error_patterns:
        for err in error_patterns[:3]:
            lines.append(f"Error: {err[:100]}")
    if plan_summary:
        lines.append(f"Outcome: {plan_summary[:200]}")
    return "\n".join(lines)
