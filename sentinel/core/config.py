from pydantic import Field, model_validator
from pydantic_settings import BaseSettings

# Ollama num_predict cap — shared between OllamaWorker and quality_gate.
# Pinned to prevent runaway generation loops and ensure reproducible output.
OLLAMA_NUM_PREDICT = 8192


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
    rate_limit_tasks: str = "10/minute"
    rate_limit_routines: str = "5/minute"
    heartbeat_interval: int = Field(default=1800, ge=60)  # 30 minutes

    # Approval
    approval_mode: str = "full"  # full | smart | auto

    # Trust level (Phase D) — controls auto-approval of safe operations
    # 0=TL0 (all plans need approval), 1=TL1 (safe reads auto), 2=TL2 (file_read),
    # 3=TL3 (file_write + pre-write Semgrep), 4=TL4 (plan-policy constraint enforcement)
    trust_level: int = Field(default=0, ge=0, le=4)

    # PostgreSQL
    pg_host: str = "/tmp"              # Unix socket directory (or hostname for TCP)
    pg_port: int = 5432                # Only used for TCP connections
    pg_dbname: str = "sentinel"
    pg_user: str = "postgres"
    pg_password_file: str = ""         # Empty = no password (peer/trust auth)
    pg_owner_user: str = "sentinel_owner"  # Used for migrations only
    pg_pool_min: int = 2
    pg_pool_max: int = 5

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
    ollama_timeout: int = 600

    # Spotlighting (Phase 2) — marker is now generated per-request in pipeline.py
    spotlighting_enabled: bool = True

    # Prompt Guard (Phase 2)
    prompt_guard_enabled: bool = True
    prompt_guard_model: str = "meta-llama/Llama-Prompt-Guard-2-86M"
    prompt_guard_threshold: float = 0.96
    require_prompt_guard: bool = True  # fail-closed: block if PG unavailable

    # Claude planner (Phase 3)
    claude_api_key_file: str = "/run/secrets/claude_api_key"
    claude_model: str = "claude-opus-4-6"
    claude_max_tokens: int = 8192
    claude_timeout: int = 180

    # Approval (Phase 3)
    approval_timeout: int = 300

    # Confirmation gate (V1) — TTL for pending action confirmations
    confirmation_timeout: int = 600  # 10 minutes

    # Execution timeouts (SYS-2) — prevent hung calls from blocking tasks indefinitely
    # Worker/plan/API values sized from Run 8 data: P95=146s, max=220s across 46 steps.
    # 480s gives ~2x headroom over observed max for model variance and future model swaps.
    planner_timeout: int = 120          # Claude API create_plan() — 2 min
    worker_timeout: int = 480           # Worker inference per step — 8 min (Run 8 max was 220s)
    tool_timeout: int = 60              # Tool executor per-tool call — 1 min
    plan_execution_timeout: int = 1500  # Overall plan step loop — 25 min (8 steps × ~3 min avg)
    api_task_timeout: int = 1800        # API entry point handle_task() — matches test harness
    channel_send_timeout: int = 30      # Channel message send — 30s (Telegram API, Signal socket)
    shell_timeout: int = Field(default=30, ge=5)  # Direct shell exec (non-sandbox) — 30s

    # PIN authentication
    pin_required: bool = True
    pin_file: str = "/run/secrets/sentinel_pin"

    # Semgrep scanner (replaces CodeShield)
    require_semgrep: bool = True  # fail-closed: block if Semgrep unavailable
    semgrep_timeout: int = 30     # per-scan timeout in seconds

    # Conversation tracking (Phase 5)
    session_ttl: int = Field(default=3600, ge=0)  # 1 hour
    session_max_count: int = Field(default=1000, ge=1)
    conversation_warn_threshold: float = 3.0
    conversation_block_threshold: float = 5.0
    conversation_enabled: bool = True
    session_risk_decay_per_minute: float = Field(default=2.0, ge=0)  # Risk decays 2.0 per minute of inactivity
    session_lock_timeout_s: int = Field(default=300, ge=0)  # Auto-unlock locked sessions after 5 minutes

    # Per-channel session timeouts (F2) — override session_ttl for specific channels
    session_ttl_signal: int = 7200      # 2hr — async messaging, long gaps
    session_ttl_websocket: int = 1800   # 30min — active browser session
    session_ttl_api: int = 3600         # 1hr — programmatic access
    session_ttl_mcp: int = 3600         # 1hr — tool-based access
    session_ttl_routine: int = 0        # never — system-managed lifecycle

    # History pruning (F2) — max turns before head-and-tail pruning kicks in
    session_max_history_turns: int = 20

    # Cross-session context injection (F2) — token budget for memory search results
    cross_session_token_budget: int = 2000  # ~500 words at 4 chars/token

    # Worker turn buffer (F3) — per-session ring buffer of prior worker output summaries
    worker_turn_buffer_size: int = 10     # max prior turns to keep
    worker_context_token_budget: int = 2000  # token limit for injected context (~4 chars/token)

    # Embeddings (Phase 2) — uses Ollama /api/embed with a lightweight model on CPU
    embeddings_model: str = "nomic-embed-text"
    embeddings_timeout: int = 30
    auto_memory: bool = False  # auto-store conversation summaries after tasks (disabled: episodic pipeline provides richer data)

    # MCP server (Phase 3)
    mcp_enabled: bool = True
    mcp_auth_token: str = ""  # Bearer token for MCP auth. Empty = reject all (fail-closed)

    # Signal channel (Phase 3) — disabled until registered
    signal_enabled: bool = False
    signal_cli_path: str = "/usr/local/bin/signal-cli"
    signal_cli_config: str = "/app/signal-data"   # data directory (keys + trust store)
    signal_socket_path: str = "/tmp/signal.sock"  # Unix socket for daemon mode
    signal_account: str = ""
    signal_allowed_senders: str = ""           # comma-separated phone numbers, empty = allow all
    signal_rate_limit: int = 10               # messages per minute per sender
    signal_max_message_length: int = 2000     # Signal's practical limit

    # Telegram channel — disabled until bot token configured
    telegram_enabled: bool = False
    telegram_bot_token_file: str = "/run/secrets/telegram_bot_token"
    telegram_allowed_chat_ids: str = ""    # comma-separated chat IDs, empty = allow all
    telegram_rate_limit: int = 10          # messages per minute per chat
    telegram_max_message_length: int = 4096  # Telegram's limit
    telegram_polling_timeout: int = 30     # long-poll timeout seconds

    # Web search (Phase B) — disabled by default
    web_search_enabled: bool = False
    web_search_backend: str = "brave"  # brave | searxng
    web_search_api_url: str = "https://api.search.brave.com/res/v1"
    web_search_api_key_file: str = "/run/secrets/brave_api_key"
    web_search_max_results: int = 5
    web_search_timeout: int = 10

    # X search via Grok API — disabled by default
    x_search_enabled: bool = False
    x_search_api_key_file: str = "/run/secrets/grok_api_key"
    x_search_model: str = "grok-4-1-fast-reasoning"
    x_search_api_url: str = "https://api.x.ai/v1"
    x_search_timeout: int = 30
    x_search_max_results: int = 10

    # Google OAuth2 (Phase B) — disabled until configured
    google_oauth_client_id: str = ""
    google_oauth_client_secret_file: str = ""
    google_oauth_refresh_token_file: str = ""
    google_oauth_scopes: str = ""  # comma-separated

    # Gmail integration (Phase B4) — disabled by default
    gmail_enabled: bool = False
    gmail_api_timeout: int = 15
    gmail_max_search_results: int = 20
    gmail_max_body_length: int = 50000

    # Google Calendar integration (Phase B5) — disabled by default
    calendar_enabled: bool = False
    calendar_api_timeout: int = 15
    calendar_max_results: int = 50

    # Generic email backend selection — "gmail" uses Google OAuth2/REST API,
    # "imap" uses IMAP/SMTP (Proton Bridge, Fastmail, self-hosted, etc.)
    email_backend: str = "gmail"  # gmail | imap

    # IMAP/SMTP settings — used when email_backend="imap"
    imap_host: str = ""
    imap_port: int = 993
    imap_username: str = ""
    imap_password_file: str = "/run/secrets/imap_password"
    imap_tls_mode: str = "ssl"  # ssl | starttls | none
    imap_tls_cert_file: str = ""  # path to CA cert for self-signed (Proton Bridge)
    imap_timeout: int = 30
    imap_drafts_folder: str = "Drafts"
    smtp_host: str = ""
    smtp_port: int = 465
    smtp_username: str = ""
    smtp_password_file: str = "/run/secrets/smtp_password"
    smtp_tls_mode: str = "ssl"  # ssl | starttls
    smtp_from_address: str = ""
    smtp_timeout: int = 30

    # Generic calendar backend selection — "google" uses Google OAuth2/REST API,
    # "caldav" uses CalDAV protocol (Nextcloud, Radicale, Fastmail, etc.)
    calendar_backend: str = "google"  # google | caldav

    # CalDAV settings — used when calendar_backend="caldav"
    caldav_url: str = ""
    caldav_username: str = ""
    caldav_password_file: str = "/run/secrets/caldav_password"
    caldav_calendar_name: str = ""
    caldav_tls_cert_file: str = ""  # path to CA cert for self-signed servers
    caldav_timeout: int = 30

    # Baseline mode (G6 security tax testing) — disables scanning layers to
    # measure utility without security overhead.  Skips: input scanning, Prompt
    # Guard, script gate, spotlighting, output scanning.  Keeps: provenance,
    # constraint validation.  NEVER enable in production.
    baseline_mode: bool = False

    # Verbose results (stress testing) — exposes defence internals (spotlighting
    # markers, sandwich text, UNTRUSTED_DATA structure). Off by default.
    verbose_results: bool = False

    # Benchmark mode — allows arbitrary source values in /api/task so the stress
    # test can create unique sessions per prompt.  Without this, all sources are
    # normalised to "api" (security: prevents session-key rotation attacks per
    # H-003).  ONLY enable during benchmark runs via run_benchmark.sh.
    benchmark_mode: bool = False

    # Red team mode — registers POST /api/test/execute-plan for B2 compromised
    # planner testing. ONLY enable during red team runs via run_red_team.sh.
    red_team_mode: bool = False

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

    # Router — fast-path classification and template execution
    router_enabled: bool = True
    router_classifier_timeout: float = 10.0
    router_classifier_model: str = ""  # empty = use default ollama_model

    # WASM sidecar (Phase 4) — opt-in, disabled by default
    sidecar_enabled: bool = False
    sidecar_socket: str = "/tmp/sentinel-sidecar.sock"
    sidecar_binary: str = "./sidecar/target/release/sentinel-sidecar"
    sidecar_timeout: int = 30
    sidecar_tool_dir: str = "./sidecar/wasm"

    # Podman sandbox (E5) — disposable containers for shell commands at TL2+
    sandbox_enabled: bool = False
    sandbox_socket: str = "/run/podman/podman.sock"
    # Custom image with pre-installed libraries (worker deps + common packages).
    # Stock python:3.12-slim has no third-party packages and sandboxes can't
    # pip install (network disabled + read-only rootfs).
    # Build with: podman build -t sentinel-sandbox -f container/Containerfile.sandbox .
    sandbox_image: str = "sentinel-sandbox:latest"

    # Podman proxy — restricts socket access to sandbox operations only
    podman_proxy_upstream: str = "/run/podman/podman-host.sock"
    podman_proxy_listen: str = "/tmp/podman-proxy.sock"
    sandbox_timeout: int = Field(default=30, ge=1)
    sandbox_max_timeout: int = Field(default=300, ge=1)
    sandbox_api_timeout: int = 30          # per-request Podman API timeout (seconds)
    sandbox_memory_limit: int = 268435456    # 256MB
    sandbox_cpu_quota: int = 100000          # 1 CPU core
    sandbox_output_limit: int = 65536        # 64KB
    sandbox_workspace_volume: str = "sentinel-workspace"

    @model_validator(mode="after")
    def _check_thresholds(self) -> "Settings":
        if self.conversation_block_threshold <= self.conversation_warn_threshold:
            raise ValueError(
                "conversation_block_threshold must be greater than conversation_warn_threshold"
            )
        return self


settings = Settings()
