"""Safe tool registry — handler mapping and constants.

Maps tool names to handler method names on SafeToolHandlers. Adding a new
safe tool requires registering it here and implementing the handler method
in the appropriate category mixin (_safe_memory_tools or _safe_session_tools).
"""

# Embedding calls go to Ollama over HTTP — bound them so a stalled
# inference server doesn't block safe tool execution indefinitely.
EMBEDDING_TIMEOUT = 30.0

# Handler mapping: tool name -> method name on SafeToolHandlers
SAFE_HANDLERS: dict[str, str] = {
    "health_check": "health_check",
    "session_info": "session_info",
    "memory_search": "memory_search",
    "memory_list": "memory_list",
    "memory_store": "memory_store",
    "routine_list": "routine_list",
    "routine_get": "routine_get",
    "routine_history": "routine_history",
    "memory_recall_file": "memory_recall_file",
    "memory_recall_session": "memory_recall_session",
}
