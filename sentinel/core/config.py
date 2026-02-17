from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    model_config = {"env_prefix": "SENTINEL_"}

    # Controller
    policy_file: str = "/policies/sentinel-policy.yaml"
    workspace_path: str = "/workspace"
    log_level: str = "INFO"
    log_dir: str = "/logs"

    # API
    host: str = "0.0.0.0"
    port: int = 8000

    # Approval
    approval_mode: str = "full"  # full | smart | auto

    # Database
    db_path: str = "/data/sentinel.db"

    # Static files + TLS
    static_dir: str = "/app/ui"
    tls_cert_file: str = ""  # empty = no TLS (plain HTTP)
    tls_key_file: str = ""
    https_port: int = 8443
    http_port: int = 8080
    redirect_enabled: bool = True  # HTTP→HTTPS redirect
    external_https_port: int = 3001  # external-facing port for redirect Location header

    # Qwen worker — model is user-configurable (any Ollama-served model)
    ollama_url: str = "http://sentinel-qwen:11434"
    ollama_model: str = "qwen3:14b"
    ollama_timeout: int = 120

    # Spotlighting (Phase 2) — marker is now generated per-request in pipeline.py
    spotlighting_enabled: bool = True

    # Prompt Guard (Phase 2)
    prompt_guard_enabled: bool = True
    prompt_guard_model: str = "meta-llama/Llama-Prompt-Guard-2-86M"
    prompt_guard_threshold: float = 0.9
    require_prompt_guard: bool = True  # fail-closed: block if PG unavailable

    # Claude planner (Phase 3)
    claude_api_key_file: str = "/run/secrets/claude_api_key"
    claude_model: str = "claude-sonnet-4-5-20250929"
    claude_max_tokens: int = 4096
    claude_timeout: int = 60

    # Approval (Phase 3)
    approval_timeout: int = 300

    # PIN authentication
    pin_required: bool = True
    pin_file: str = "/run/secrets/sentinel_pin"

    # CodeShield (Phase 5)
    require_codeshield: bool = True  # fail-closed: block if CodeShield unavailable

    # Conversation tracking (Phase 5)
    session_ttl: int = 3600  # 1 hour
    session_max_count: int = 1000
    conversation_warn_threshold: float = 3.0
    conversation_block_threshold: float = 5.0
    conversation_enabled: bool = True

    # Embeddings (Phase 2) — uses Ollama /api/embed with a lightweight model on CPU
    embeddings_model: str = "nomic-embed-text"
    embeddings_timeout: int = 30
    auto_memory: bool = True  # auto-store conversation summaries after tasks

    # MCP server (Phase 3)
    mcp_enabled: bool = True

    # Signal channel (Phase 3) — disabled until registered
    signal_enabled: bool = False
    signal_cli_path: str = "/usr/bin/signal-cli"
    signal_account: str = ""

    # Verbose results (stress testing) — exposes defence internals (spotlighting
    # markers, sandwich text, UNTRUSTED_DATA structure). Off by default.
    verbose_results: bool = False

    # CSRF protection (Tier 4) — comma-separated list of allowed origins.
    # Add your hostname/IP origins for non-localhost access, e.g.:
    #   SENTINEL_ALLOWED_ORIGINS="https://localhost:3001,...,https://myhost:3001"
    allowed_origins: str = "https://localhost:3001,https://localhost:3002,https://localhost:3003,https://localhost:3004"

    # Request size limit (Tier 4, code review #13) — 1MB
    max_request_bytes: int = 1_048_576

    # Provider selection (Phase 5) — which backend for each LLM role
    worker_provider: str = "ollama"
    planner_provider: str = "claude"
    embedding_provider: str = "ollama"

    # Routine scheduling (Phase 5) — opt-in, disabled by default
    routine_enabled: bool = False
    routine_max_concurrent: int = 3
    routine_scheduler_interval: int = 15  # seconds between scheduler ticks
    routine_execution_timeout: int = 300  # 5 minutes max per routine execution
    routine_max_per_user: int = 50

    # WASM sidecar (Phase 4) — opt-in, disabled by default
    sidecar_enabled: bool = False
    sidecar_socket: str = "/tmp/sentinel-sidecar.sock"
    sidecar_binary: str = "./sidecar/target/release/sentinel-sidecar"
    sidecar_timeout: int = 30
    sidecar_tool_dir: str = "./sidecar/wasm"


settings = Settings()
