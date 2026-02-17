# Contact Registry & PII Boundary

The contact registry enforces the privacy boundary between the planner (Claude API) and real-world identifiers. The planner never sees names, email addresses, phone numbers, or chat IDs — it works with opaque references like "user 1" and "user 2", which are resolved to real identifiers only at the execution edge, after security scanning.

## Key Design Decisions

- **Opaque IDs everywhere inside, real identifiers only at edges.** Even if the planner's context were leaked, it contains no PII.
- **Resolution happens in two places** with different trust properties: intake (pre-planner, names to opaque IDs) and tool dispatch (post-security, opaque IDs to channel identifiers).
- **Per-user contact scoping** via RLS. Each user's address book is isolated at the database level, not just in application logic.

## How It Works

### Inbound Flow (Intake)

1. A message arrives from any channel (Signal, Telegram, WebSocket, etc.)
2. `resolve_sender()` maps the channel identifier to a `user_id` via the `contact_channels` table
3. `rewrite_message()` replaces known contact names and pronouns with opaque "user N" references
4. The rewritten message is passed to the planner, which plans using opaque IDs only

### Outbound Flow (Tool Dispatch)

1. The planner creates a step like `signal_send(recipient="user 3", message="...")`
2. After security scanning (S3 provenance, S4 constraints, S5 output scan), tool dispatch resolves "user 3"
3. `resolve_tool_recipient()` looks up the contact's default channel and returns the real identifier
4. The message is sent to the real recipient

### Data Model

- **users** — system identity (user_id, display_name, role, trust_level)
- **contacts** — address book entries per user, with optional `linked_user_id` for contacts that are also system users
- **contact_channels** — channel-specific identifiers (Signal UUID, Telegram chat ID, email address) linked to contacts

### API

CRUD endpoints at `/api/users`, `/api/contacts`, and `/api/contacts/{id}/channels`.

## Where the Code Lives

| File | Purpose |
|------|---------|
| `sentinel/contacts/store.py` | `ContactStore` — CRUD for users, contacts, channels |
| `sentinel/contacts/resolver.py` | Resolution functions: sender lookup, name-to-ID, recipient-to-channel |
| `sentinel/planner/intake.py` | Intake-stage rewriting before planner |
| `sentinel/planner/tool_dispatch.py` | Post-security resolution of opaque IDs to real identifiers |
