# Router & Fast Path

The router enables simple, single-tool requests to skip the Claude planner entirely, reducing latency and cost. A local Qwen classifier determines whether a request matches one of 9 predefined templates. If it does, the fast path executes the template directly — the same security pipeline applies regardless of path.

## Key Design Decisions

- **Security is path-independent.** The fast path applies the identical 10-layer security pipeline as the planner path. Skipping the planner never means skipping security.
- **Every failure falls back to the planner.** If classification times out, returns invalid JSON, or is ambiguous, the request goes to the planner.
- **Planner override keywords** let users explicitly request the full planner: "use the planner", "plan this", "think about this".
- **Ollama warmup on startup** prevents the first request from timing out (model loading takes 15-20s, exceeding the 10s classifier timeout).

## How It Works

### Classification

The `Classifier` sends the user message to Qwen with a system prompt listing available templates. Qwen returns JSON indicating either a fast route (with template name and extracted parameters) or a planner route (with reason).

### Templates

| Template | Tool | Side Effect |
|----------|------|-------------|
| `calendar_read` | calendar_read | No |
| `calendar_add` | calendar_add | Yes |
| `email_search` | email_search | No |
| `email_read` | email_search + email_read | No |
| `web_search` | web_search | No |
| `x_search` | x_search | No |
| `signal_send` | signal_send | Yes |
| `telegram_send` | telegram_send | Yes |
| `memory_search` | memory_search | No |

Templates support chained tools and a confirmation gate for side-effect operations.

### Routing Flow

1. Feature flag check — if disabled, all requests go to the orchestrator
2. Session binding and lock check
3. Input scanning (security pipeline)
4. Classification (Qwen)
5. Dispatch — fast path executor or full orchestrator

## Where the Code Lives

| File | Purpose |
|------|---------|
| `sentinel/router/router.py` | `MessageRouter` — scan, classify, dispatch |
| `sentinel/router/classifier.py` | `Classifier` — Qwen-based request classification |
| `sentinel/router/templates.py` | `Template` dataclass and `TemplateRegistry` |
| `sentinel/router/fast_path.py` | `FastPathExecutor` — template execution with security scanning |
