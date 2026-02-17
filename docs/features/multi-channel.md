# Multi-Channel Access

Sentinel supports 6 input/output channels plus an MCP server endpoint. All channels feed through the same security pipeline — the channel determines how messages arrive and depart, not how they're processed.

## Channels

| Channel | Protocol | Direction | Notes |
|---------|----------|-----------|-------|
| WebSocket | WSS | Bidirectional | Primary UI transport, real-time updates |
| SSE | HTTPS | Server→Client | Fallback for environments that don't support WebSocket |
| Signal | signal-cli daemon | Bidirectional | Via JSON-RPC over Unix socket |
| Telegram | Bot API | Bidirectional | Via python-telegram-bot v21 |
| Email | IMAP/SMTP | Bidirectional | IMAP polling for inbound, SMTP for outbound |
| Calendar | CalDAV | Read/Write | Event reading and creation |
| MCP | HTTP | Bidirectional | Model Context Protocol server endpoint |

## Key Design Decisions

- **Channel-agnostic processing.** The orchestrator and security pipeline don't know or care which channel originated a request. Channel-specific logic is isolated to receivers and senders.
- **Contact resolution at edges.** Inbound messages map channel identifiers (Signal UUID, Telegram chat ID) to user IDs via the contact registry. Outbound messages resolve opaque IDs back to channel-specific identifiers.
- **Independent receivers and senders.** Each channel has a dedicated receiver (polls or listens for inbound messages) and sender (delivers outbound messages). They share no state beyond the event bus.

## How It Works

### Inbound Flow

1. Channel receiver picks up a message (WebSocket frame, Signal JSON-RPC event, Telegram update, etc.)
2. Receiver resolves the sender to a user_id via the contact registry
3. Message is submitted to the orchestrator (or router for fast-path classification)
4. The security pipeline processes it identically regardless of source channel

### Outbound Flow

1. The orchestrator (or fast path) determines a message needs to be sent
2. Tool dispatch resolves the recipient's opaque ID to a channel-specific identifier
3. The appropriate channel sender delivers the message
4. Delivery status is recorded in the conversation turn

### Signal Integration

Signal uses a `signal-cli` daemon running inside the sentinel container, communicating via a Unix domain socket (`/tmp/signal.sock`) using JSON-RPC. The daemon holds the registration lock, so all Signal operations must go through it — spawning separate `signal-cli` processes would block indefinitely.

## Where the Code Lives

| File | Purpose |
|------|---------|
| `sentinel/channels/websocket.py` | WebSocket handler |
| `sentinel/channels/sse.py` | Server-Sent Events handler |
| `sentinel/channels/signal_receiver.py` | Signal inbound (daemon socket) |
| `sentinel/channels/signal_sender.py` | Signal outbound |
| `sentinel/channels/telegram_receiver.py` | Telegram bot inbound |
| `sentinel/channels/telegram_sender.py` | Telegram bot outbound |
| `sentinel/channels/email.py` | IMAP polling + SMTP sending |
| `sentinel/channels/calendar.py` | CalDAV integration |
| `sentinel/channels/mcp_server.py` | MCP server endpoint |
