# PostgreSQL Migration

Sentinel migrated from SQLite to PostgreSQL 17 with pgvector, removing ~3,200 lines of SQLite code and consolidating 11 stores into PostgreSQL-only implementations. The migration added row-level security (RLS) across all 17 tables, enforcing user isolation at the database level.

## Key Design Decisions

- **Two database roles** separate concerns: `sentinel_owner` handles DDL, migrations, and maintenance; `sentinel_app` is DML-only and subject to RLS. This limits the application's database privileges to the minimum required.
- **FORCE ROW LEVEL SECURITY** on every table means even the table owner obeys policies. Each table has a `user_isolation` policy: `USING (user_id = current_setting('app.current_user_id')::INTEGER)`.
- **Fail-closed default** — the safe default for `app.current_user_id` is `0`, which matches zero rows. An unset context returns empty results rather than leaking data.
- **pgvector for embeddings** replaces sqlite-vec. HNSW indexes (`m=16, ef_construction=64`) provide approximate nearest-neighbour search for the episodic learning system.

## How It Works

### Connection Management

The `RLSPool` wrapper in `sentinel/core/rls.py` injects user context on every connection:

1. On `acquire()`, starts a transaction
2. Calls `SET LOCAL app.current_user_id` from the Python `ContextVar`
3. Yields the connection — all queries are now RLS-scoped
4. Commits on success, rolls back on exception
5. `SET LOCAL` automatically resets when the transaction ends

Callers must not call `conn.commit()` or `conn.rollback()` directly — the pool owns the transaction lifecycle.

### Schema

Tables are created in dependency order: extensions first (pgvector), then base tables (users, sessions, memory_chunks, routines), then FK-dependent tables (conversation_turns, file_provenance, episodic_records, contacts, contact_channels).

Key table features:
- `memory_chunks` has a `tsvector` generated column for full-text search and a `vector(768)` column for embedding similarity
- `episodic_records` stores structured task outcomes with JSONB fields
- `audit_log` has an immutability trigger preventing deletes by the application role
- GIN indexes on tsvector columns, HNSW index on vector columns, partial indexes on frequently filtered columns

### Maintenance

Periodic purges run via the admin pool (`sentinel_owner`): audit logs (7 days), routine executions (30 days), provenance records (7 days), and expired approvals (7 days).

## Where the Code Lives

| File | Purpose |
|------|---------|
| `sentinel/core/pg_schema.py` | All DDL: tables, indexes, extensions, RLS policies |
| `sentinel/core/rls.py` | `RLSPool` wrapper — injects user context per connection |
| `sentinel/core/db.py` | Connection pool setup, periodic maintenance |
| `container/entrypoint.sh` | PostgreSQL startup, role creation, privilege management |
