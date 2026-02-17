# Routine Scheduling

Sentinel includes a built-in scheduler that executes tasks automatically based on time, events, or intervals. Routines bypass the router and call the orchestrator directly — they represent pre-approved, recurring tasks.

## Key Design Decisions

- **Three trigger types** cover different scheduling needs: cron for fixed schedules, interval for periodic tasks with cooldown, and event for reactive triggers.
- **Routines bypass the router** because they are pre-defined tasks with known intent — there's nothing to classify. They call `orchestrator.run()` directly.
- **Security pipeline still applies.** Even though routines bypass the router, the orchestrator's full security pipeline (input scan, output scan, provenance, constraints) runs on every step.
- **Multi-user aware.** The scheduler uses an admin pool to discover all users' due routines, then sets the `ContextVar` to each routine's `user_id` before execution, ensuring RLS scoping is correct.

## Trigger Types

### Cron

Standard cron expressions (e.g., `0 9 * * MON-FRI` for weekday mornings). Evaluated every scheduler tick against the routine's `next_run` timestamp.

### Interval

Executes every N seconds with a cooldown period. The cooldown prevents overlapping executions if a routine takes longer than its interval. Example: check email every 5 minutes, but don't start a new check if the previous one is still running.

### Event

Fires in response to specific system events (e.g., new message received, task completed). Event routines register with the event bus and execute when their trigger event is emitted.

## How It Works

### Scheduler Loop

1. The scheduler runs as an async background task, ticking every 60 seconds
2. On each tick, `list_due_all_users()` queries for routines where `enabled = TRUE` and `next_run <= NOW()` — using the admin pool to see all users' routines
3. For each due routine, the scheduler:
   - Sets `ContextVar` to the routine's `user_id`
   - Updates the routine's `last_run` and `next_run` timestamps
   - Submits the routine's prompt to `orchestrator.run()`
   - Records the execution result

### Management UI

The Routines page in the web UI shows all routines with their status, schedule, last/next run times, and execution history. Users can create, enable/disable, run immediately, or delete routines.

### API

CRUD endpoints at `/api/routines` with fields for name, prompt, trigger type, schedule expression, enabled flag, and cooldown.

## Where the Code Lives

| File | Purpose |
|------|---------|
| `sentinel/routines/scheduler.py` | Scheduler loop, due-routine discovery, execution |
| `sentinel/routines/store.py` | `RoutineStore` — CRUD, list_due, update_run_state |
| `sentinel/routines/models.py` | Routine data models and trigger types |
| `sentinel/core/pg_schema.py` | Routines and routine_executions table definitions |
