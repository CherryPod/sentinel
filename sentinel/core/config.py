"""Application settings loaded from environment variables.

Uses pydantic-settings with SENTINEL_ prefix. All thresholds, timeouts,
feature flags, and secret paths are centralised here.
"""

import logging

from pydantic import Field, model_validator
from pydantic_settings import BaseSettings

from sentinel.audit.events import CATEGORY_DEFAULTS, AuditCategoryConfig

logger = logging.getLogger(__name__)


class ConfigInvariantError(ValueError):
    """Raised at boot when a cross-field config invariant is violated.

    Q10 design D8: approval_timeout / confirmation_timeout must be strictly
    less than the shortest active session_ttl_* so a pending gate cannot
    outlive its session and survive an auto-unlock / TTL boundary.
    Subclasses ValueError so pydantic surfaces it at Settings() construction.
    """


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
    host: str = "0.0.0.0"  # nosec B104 — container networking requires 0.0.0.0 bind
    port: int = 8000
    rate_limit_tasks: str = "10/minute"
    rate_limit_routines: str = "5/minute"
    heartbeat_interval: int = Field(default=1800, ge=60)  # 30 minutes

    # Q13.fix.e (F3) — webhook signature migration. v2 signatures
    # (timestamp-dot-body HMAC) are always accepted. Legacy sha256=
    # (body-only HMAC) verifies only while this flag is True.
    # Deprecation path:
    #   * DEFAULT True on first-deploy release (current) — accepts both
    #     v2= and sha256= so existing producers do not break.
    #   * SUNSET RELEASE (flip default to False): operators must set
    #     True explicitly to keep accepting legacy signatures and will
    #     receive a startup-warning audit event on every boot.
    #   * REMOVAL RELEASE: setting removed, legacy-verification code
    #     path deleted.
    # Design: docs/hardening/2026-04-20-hardening-Q13-protocol-auth-findings.md
    # §Design Cluster 1 — Q13.fix.design-webhook-replay.
    webhook_legacy_signature_enabled: bool = Field(default=True)

    # Login failure lockout — per-IP brute-force protection
    login_max_failed_attempts: int = Field(default=5, ge=1)
    login_lockout_seconds: int = Field(default=60, ge=1)

    # Approval
    approval_mode: str = "full"  # full | smart | auto

    # Trust level (Phase D) — controls auto-approval of safe operations
    # 0=TL0 (all plans need approval), 1=TL1 (safe reads auto), 2=TL2 (file_read),
    # 3=TL3 (file_write + pre-write Semgrep), 4=TL4 (plan-policy constraint enforcement)
    trust_level: int = Field(default=0, ge=0, le=4)

    # PostgreSQL
    pg_host: str = "/tmp"  # Unix socket directory (or hostname for TCP)
    pg_port: int = 5432  # Only used for TCP connections
    pg_dbname: str = "sentinel"
    pg_user: str = "postgres"
    pg_password_file: str = ""  # Empty = no password (peer/trust auth)
    pg_owner_user: str = "sentinel_owner"  # Used for migrations only
    pg_pool_min: int = 2
    pg_pool_max: int = 5
    # Q11-F3: asyncpg.connect() connect-phase deadline. 5s assumes unix-socket
    # deployments (the default pg_host='/tmp'). Production environments with
    # remote Postgres must override via SENTINEL_PG_CONNECT_TIMEOUT.
    pg_connect_timeout: float = 5.0
    # Q11-F3: shared command_timeout applied to every asyncpg pool (app, admin,
    # audit) and migration-conn. Replaces 4× hard-coded 60.0 literals.
    pg_command_timeout: float = 60.0
    # D48: maximum wall-clock for AuditEmitter._write_to_db (pool-acquire +
    # RLS transaction setup + INSERT). On timeout the emit routes through the
    # existing file-fallback warning path. Tighter than pg_command_timeout so
    # audit-DB slowness cannot hold callers / startup / shutdown beyond this
    # bound. Remote Postgres deployments may need a higher value.
    # gt=0 guard: timeout=0 causes asyncio.wait_for to raise TimeoutError
    # immediately on every emit, silently gutting all DB audit writes.
    audit_db_write_timeout: float = Field(default=5.0, gt=0)
    # Periodic DB maintenance cadence (Q5.fix.a / F7).
    # Default 1h; minimum 60s (test scenarios); maximum 86400s (1 day)
    # to prevent silent disablement via INT_MAX-style misconfig.
    db_maintenance_interval_s: int = Field(default=3600, ge=60, le=86400)
    audit_categories: dict[str, AuditCategoryConfig] = Field(
        default_factory=lambda: {
            key: value.model_copy(deep=True) for key, value in CATEGORY_DEFAULTS.items()
        }
    )

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
    planner_timeout: int = 120  # Claude API create_plan() — 2 min
    worker_timeout: int = 480  # Worker inference per step — 8 min (Run 8 max was 220s)
    tool_timeout: int = (
        60  # Tool executor per-tool call — 1 min (shared by planner + fast-path)
    )
    # Q11-F1: Google OAuth2 token refresh HTTP deadline. Same provider family
    # as gmail/calendar APIs, distinct knob to let ops tune independently.
    google_api_timeout: int = 30
    plan_execution_timeout: int = (
        1500  # Overall plan step loop — 25 min (8 steps × ~3 min avg)
    )
    api_task_timeout: int = 1800  # API entry point handle_task() — matches test harness

    # Loop controller — persistent goal-pursuit retry loop
    loop_max_iterations: int = 5  # Max orchestrator passes per loop
    loop_timeout_seconds: int = 3600  # 1 hour wall-clock per loop
    loop_max_per_request: int = 10  # Upper bound clients can request
    channel_send_timeout: int = (
        30  # Channel message send — 30s (Telegram API, Signal socket)
    )
    shell_timeout: int = Field(
        default=30, ge=5
    )  # Direct shell exec (non-sandbox) — 30s

    # PIN authentication
    pin_required: bool = True
    pin_file: str = "/run/secrets/sentinel_pin"

    # Bootstrap — display name for the owner account seeded on first run
    bootstrap_username: str = "Admin"

    # Semgrep scanner (replaces CodeShield)
    require_semgrep: bool = True  # fail-closed: block if Semgrep unavailable
    semgrep_timeout: int = 30  # per-scan timeout in seconds

    # Conversation tracking (Phase 5)
    session_ttl: int = Field(default=3600, ge=0)  # 1 hour
    session_max_count: int = Field(default=1000, ge=1)
    conversation_warn_threshold: float = 3.0
    conversation_block_threshold: float = 5.0
    max_success_forgives: int = Field(default=2, ge=0)
    conversation_enabled: bool = True
    session_risk_decay_per_minute: float = Field(
        default=2.0, ge=0
    )  # Risk decays 2.0 per minute of inactivity
    session_lock_timeout_s: int = Field(
        default=300, ge=0
    )  # Auto-unlock locked sessions after 5 minutes

    # Per-channel session timeouts (F2) — override session_ttl for specific channels
    session_ttl_signal: int = 7200  # 2hr — async messaging, long gaps
    session_ttl_websocket: int = 1800  # 30min — active browser session
    session_ttl_api: int = 3600  # 1hr — programmatic access
    session_ttl_mcp: int = 3600  # 1hr — tool-based access
    session_ttl_routine: int = 0  # never — system-managed lifecycle

    # History pruning (F2) — max turns before head-and-tail pruning kicks in
    session_max_history_turns: int = 20

    # Cross-session context injection (F2) — token budget for memory search results
    cross_session_token_budget: int = 2000  # ~500 words at 4 chars/token

    # Worker turn buffer (F3) — per-session ring buffer of prior worker output summaries
    worker_turn_buffer_size: int = 10  # max prior turns to keep
    worker_context_token_budget: int = (
        2000  # token limit for injected context (~4 chars/token)
    )

    # Embeddings (Phase 2) — uses Ollama /api/embed with a lightweight model on CPU
    embeddings_model: str = "nomic-embed-text"
    embeddings_timeout: int = 30
    auto_memory: bool = False  # auto-store conversation summaries after tasks (disabled: episodic pipeline provides richer data)

    # Anchor allocator — places deterministic named markers in files for file_patch
    anchor_allocator_enabled: bool = True
    anchor_allocator_tier: str = "block"  # "section", "block", or "detail"

    # Media attachments — ingestion from Signal/Telegram/email
    attachment_max_file_bytes: int = 52_428_800  # 50 MB
    attachment_retention_days: int = 30  # auto-cleanup age
    attachment_enabled: bool = True  # master switch

    # MCP server (Phase 3)
    mcp_enabled: bool = True
    mcp_auth_token: str = (
        ""  # Bearer token for MCP auth. Empty = reject all (fail-closed)
    )

    # Q13.fix.f — Unix socket hardening (design cluster 2, 2026-04-22).
    # Root directory for Sentinel's internal Unix sockets (sidecar + signal-cli).
    # Must be 0700-perms and owned by the sentinel process UID at runtime;
    # tmpfs is recommended for socket-lifetime ephemerality but is not enforced
    # by the validator. Container deploys: mounted via podman-compose tmpfs
    # entry; bare-metal / systemd deploys override with SENTINEL_RUNTIME_DIR.
    # Both sidecar_socket and signal_socket_path defaults re-rooted under this
    # path. Operators overriding individual socket paths must keep them
    # consistent with this dir (or re-export SENTINEL_RUNTIME_DIR). Validator
    # in sentinel/core/socket_auth.py asserts perms + owner at init time.
    runtime_dir: str = "/run/sentinel"

    # Signal channel (Phase 3) — disabled until registered
    signal_enabled: bool = False
    signal_cli_path: str = "/usr/local/bin/signal-cli"
    signal_cli_config: str = "/app/signal-data"  # data directory (keys + trust store)
    # Q13.fix.f — default re-rooted under settings.runtime_dir. Operators overriding
    # signal_socket_path explicitly must ensure the path's directory is a 0700
    # runtime-dir (or override runtime_dir to match).
    signal_socket_path: str = "/run/sentinel/signal.sock"  # Unix socket for daemon mode
    signal_account: str = ""
    signal_allowed_senders: str = (
        ""  # comma-separated phone numbers. Q13.fix.f: empty = deny-all (fail-closed)
    )
    signal_rate_limit: int = 10  # messages per minute per sender
    signal_max_message_length: int = 2000  # Signal's practical limit
    # DEPRECATED (2026-04-24 Q11.fix.c): superseded by signal_read_timeout.
    # The Q13-F2 framing envelope (600s) was subsumed by the tighter Q11-F6a
    # per-readline deadline (300s) — the tighter value catches both daemon-hang
    # and partial-frame stalls. Setting retained to avoid breaking operator
    # env/compose files; scheduled for removal in a post-pass Q16-class cleanup
    # commit. Not read by any current code path.
    signal_framing_timeout_s: float = 600.0
    # Q11-F6a: per-readline deadline on signal-cli Unix socket. Catches both
    # daemon-hang and partial-frame stalls (subsumes the former
    # signal_framing_timeout_s envelope per Q11.fix.c Option A adjudication
    # 2026-04-24).
    signal_read_timeout: float = 300.0
    # Q11-F6b: drain() deadline on keepalive ping write. Tighter than reads
    # because ping writes are bounded to <100 bytes.
    signal_ping_timeout: float = 10.0
    # Q11-U1 (cleanup-C49): signal-cli daemon socket-connect retry policy.
    # Operator-tunable for slow-system / first-run daemon initialisation.
    signal_socket_connect_interval_s: float = 0.5
    signal_socket_connect_timeout: float = 10.0
    # Q11-U1 (cleanup-C49): signal-cli health-ping cadence; tighter values
    # reduce hung-daemon detection latency at the cost of higher polling load.
    signal_ping_interval_s: float = 60.0
    # Q11-U1 (cleanup-C49): grace deadline on signal-cli subprocess.wait
    # after SIGTERM (graceful shutdown) and after process.kill (post ping
    # failure restart).
    signal_process_wait_timeout: float = 5.0

    # Telegram channel — disabled until bot token configured
    telegram_enabled: bool = False
    telegram_bot_token_file: str = "/run/secrets/telegram_bot_token"
    telegram_allowed_chat_ids: str = (
        ""  # comma-separated chat IDs. Q13-F8: empty = deny-all (fail-closed)
    )
    telegram_rate_limit: int = 10  # messages per minute per chat
    telegram_max_message_length: int = 4096  # Telegram's limit
    telegram_polling_timeout: int = 30  # long-poll timeout seconds
    # Q11-FL5 (Q11-U2 umbrella): PTB ApplicationBuilder HTTP transport surface.
    # Defaults match PTB 22.x's library defaults at C56 verification time so
    # behaviour is byte-identical to the pre-fix production stack at the
    # resolved version under default settings — the cure is operator
    # visibility and audit control over the timeout + connection-pool
    # transport knobs PTB exposes, not a value change. C67 widened the
    # pyproject pin from 21.x → 22.x; resolved version is whatever 22.x
    # pip resolves to at install time (>=22.0,<23.0).
    # Contract test at tests/test_telegram_ptb_contract.py asserts the
    # chain surface holds for whatever 22.x pip resolves to. The closure
    # invariant enforced by C56.fix is: no PTB library default reachable
    # for Telegram HTTP timeout and connection-pool controls —
    # connect/read/write/pool timeout plus connection pool size, for both
    # Bot API and getUpdates. Proxy, socket options, and HTTP version are
    # reachable PTB transport knobs but intentionally out of scope;
    # Sentinel currently has no proxy/socket/HTTP-version policy surface.
    #
    # Bot API (send / fetch / lifecycle / get_me / non-getUpdates):
    telegram_connect_timeout: float = 5.0
    telegram_read_timeout: float = 5.0
    telegram_write_timeout: float = 5.0
    telegram_pool_timeout: float = 1.0
    # ge=1 is load-bearing — PTB resolves a passed-in 0 via
    # `DefaultValue.get_value(...) or 256` (telegram.ext._applicationbuilder),
    # silently restoring the library default and falsifying the closure
    # invariant. Reject 0 at config-load time so the closure holds for any
    # accepted Sentinel setting value.
    telegram_connection_pool_size: int = Field(default=256, ge=1)
    # getUpdates long-poll — semantically separate budgets per the PTB Updater
    # convention. The read_timeout below is the SLACK added on top of
    # telegram_polling_timeout, not the total long-poll HTTP read budget.
    # PTB 22.x Bot.get_updates() formula (verified at C56.design time against
    # PTB 22.6 internals at telegram._bot.Bot.get_updates):
    # effective_read = configured_read + polling_timeout. Example:
    # telegram_get_updates_read_timeout=5.0 against telegram_polling_timeout=30
    # produces a 35s effective long-poll. Don't set above ~10 — it is NOT the
    # long-poll budget itself, it is the network-slack on top of the
    # server-held polling window. FL-C67-a is the deferred row that
    # contract-tests this formula across 22.x patches via a fake-BaseRequest
    # harness; until it lands, a future PTB 22.x patch that quietly changes
    # this formula would silently break Sentinel's getUpdates timeout budget
    # without the C67 contract test catching it.
    telegram_get_updates_connect_timeout: float = 5.0
    telegram_get_updates_read_timeout: float = 5.0
    telegram_get_updates_write_timeout: float = 5.0
    telegram_get_updates_pool_timeout: float = 1.0
    # ge=1 — same rationale as telegram_connection_pool_size above; PTB
    # resolves a passed-in 0 to its library default of 1 for getUpdates.
    telegram_get_updates_connection_pool_size: int = Field(default=1, ge=1)

    # Matrix channel — connects to external Tuwunel homeserver over HTTPS
    matrix_enabled: bool = False
    matrix_homeserver_url: str = ""  # e.g. https://matrix.example.org
    matrix_user_id: str = ""  # e.g. @sentinel:matrix.example.org
    matrix_password_file: str = "/run/secrets/matrix_password"
    matrix_store_path: str = "/app/matrix-store"  # nio Olm/Megolm key persistence
    matrix_room_id: str = ""  # primary room for conversational interaction
    matrix_alerts_room_id: str = ""  # security alerts (optional, falls back to room_id)
    matrix_maintenance_room_id: str = (
        ""  # health/status (optional, falls back to room_id)
    )
    matrix_routines_room_id: str = (
        ""  # routine results (optional, falls back to room_id)
    )
    matrix_allowed_senders: str = (
        ""  # comma-separated Matrix user IDs. Q13-F8: empty = deny-all (fail-closed)
    )
    matrix_rate_limit: int = 10  # messages per minute per sender
    matrix_max_message_length: int = 30000  # ~30KB safe under 65KB E2EE event limit
    # Q12-F2 rollback: True reverts to vanilla AsyncClient (aiohttp default
    # allow_redirects=True). Default False enforces redirect-deny on every
    # outbound request including login.
    matrix_allow_redirects: bool = False
    # Q13-F7 + Q12-FL6 (cleanup-pass C40): single Matrix encryption-
    # posture operator knob. matrix_ignore_unverified_devices_on_send
    # allows opt-in relaxation of outbound megolm session-key sharing
    # to unverified-not-blacklisted device keys. On public homeservers
    # (matrix.org etc.) MUST remain False — flipping it leaks
    # plaintext-to-E2EE-device to unknown devices.
    matrix_ignore_unverified_devices_on_send: bool = False
    # Q11-U1 (cleanup-C49): server-side long-poll deadline on Matrix /sync.
    # Protocol-native unit is milliseconds (kept as `_ms` suffix for
    # honesty); composes with channel_send_timeout at matrix_channel.py:242.
    matrix_sync_timeout_ms: int = 30000

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

    # Crypto price — both backends always available, no API key needed
    crypto_enabled: bool = False
    crypto_coingecko_api_url: str = "https://api.coingecko.com/api/v3"
    crypto_binance_api_url: str = "https://api.binance.com/api/v3"
    crypto_timeout: int = 10

    # Weather — Met Office for UK (requires API key), Open-Meteo for worldwide
    weather_enabled: bool = False
    weather_metoffice_api_url: str = (
        "https://data.hub.api.metoffice.gov.uk/sitespecific/v0"
    )
    weather_metoffice_api_key_file: str = "/run/secrets/metoffice_api_key"
    weather_openmeteo_api_url: str = "https://api.open-meteo.com/v1"
    weather_geocoding_api_url: str = "https://geocoding-api.open-meteo.com/v1"
    weather_default_location: str = "Aylesbury"
    weather_timeout: int = 10

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
    email_channel_enabled: bool = False  # IMAP polling channel for attachments
    email_channel_poll_interval: int = 120  # seconds between inbox checks
    email_channel_allowed_senders: str = ""  # comma-separated email addresses; empty = deny all senders (Q13-F14 alignment)
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

    # Q12-F1 — CalDAV URL SSRF policy. Comma-separated allowlists, deny-all
    # by default. Validator runs syntactic-at-PUT + DNS+private-IP at use.
    # Allowlist syntax: literal ``foo.example.com``, suffix glob
    # ``*.example.com`` (dot-boundary enforced), or ``*`` for full-allow
    # rollback. Private-host allowlist opts specific private-IP hosts in
    # (self-hosted NAS case); names and IPs accepted.
    ssrf_caldav_allowlist: str = ""
    ssrf_caldav_private_host_allowlist: str = ""
    ssrf_allow_http: bool = False  # HTTPS-only by default; opt-in to HTTP

    # Baseline mode (G6 security tax testing) — disables scanning layers to
    # measure utility without security overhead.  Skips: input scanning, Prompt
    # Guard, script gate, spotlighting, output scanning.  Keeps: provenance,
    # constraint validation.  NEVER enable in production.
    baseline_mode: bool = False

    # Verbose results (stress testing) — exposes defence internals (spotlighting
    # markers, sandwich text, UNTRUSTED_DATA structure). Off by default.
    verbose_results: bool = False

    # Off in normal operation. When set, /api/task accepts caller-supplied
    # source values instead of normalising them to "api".
    benchmark_mode: bool = False

    # Off in normal operation. Kept so existing deployments that set the
    # variable still parse. The public tree does not register a bypass route.
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
    # Q13.fix.f — default re-rooted under settings.runtime_dir. Operators overriding
    # sidecar_socket explicitly must ensure the path's directory is a 0700 runtime-dir
    # (or override runtime_dir to match). SENTINEL_SIDECAR_SOCKET env var flows through
    # to the Rust binary at sidecar.py:start_sidecar (per design cluster 2 §Rust sidecar
    # coordination — Rust binary honours the env var at sidecar/src/main.rs:37-39).
    sidecar_socket: str = "/run/sentinel/sentinel-sidecar.sock"
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
    sandbox_api_timeout: int = 30  # per-request Podman API timeout (seconds)
    sandbox_memory_limit: int = 268435456  # 256MB
    sandbox_cpu_quota: int = 100000  # 1 CPU core
    sandbox_output_limit: int = 65536  # 64KB
    sandbox_workspace_volume: str = "sentinel-workspace"
    # Q11-U1 (cleanup-C49): Podman lifecycle timeouts; operator-tunable per
    # build/run/stop workload. sandbox_podman_build_timeout cross-couples to
    # SENTINEL_PODMAN_PROXY_FORWARD_TIMEOUT (must be <= the standalone
    # podman_proxy outer-bound; defaults match by construction at 300).
    sandbox_podman_build_timeout: int = 300
    sandbox_podman_run_timeout: int = 60
    sandbox_podman_stop_timeout: int = 30

    # --- Encryption at Rest ---
    crypto_key_path: str = "/run/secrets/credential_key"
    crypto_key_version: int = 1
    crypto_require_production_key: bool = False
    crypto_hkdf_algorithm: str = "SHA256"
    crypto_hkdf_salt_bytes: int = 16
    crypto_hkdf_info_prefix: str = "sentinel"
    crypto_gcm_nonce_bytes: int = 12
    crypto_aes_key_bits: int = 256
    crypto_hmac_algorithm: str = "SHA256"
    crypto_old_key_path: str = ""
    crypto_rotation_batch_size: int = 100
    crypto_audit_enabled: bool = True
    crypto_audit_capture_level: str = "full"

    # Multi-Turn Monitor (MTM) — tuneable constants loaded by MTMConfig.from_settings()
    mtm_enabled: str = "false"  # "true" | "false" | "shadow"
    mtm_alpha: float = Field(default=2.0, ge=0.0, le=5.0)
    mtm_delta: float = Field(default=0.4, ge=0.0, le=1.0)
    mtm_beta_e: float = Field(default=0.5, ge=0.0, le=2.0)
    mtm_low_threshold: float = Field(default=0.5, ge=0.0, le=2.0)
    mtm_warn_threshold: float = Field(default=4.0, ge=1.0, le=10.0)
    mtm_block_threshold: float = Field(default=7.0, ge=2.0, le=15.0)
    mtm_window_size: int = Field(default=8, ge=3, le=20)
    mtm_benign_floor_turns: int = Field(default=3, ge=1, le=10)
    mtm_benign_floor_discount: float = Field(default=0.7, ge=0.3, le=1.0)
    mtm_signal_weights: str = "{}"  # JSON string: {"signal_name": weight}
    mtm_benign_anchors: str = ""  # JSON string: ["keyword", ...] or empty for defaults
    mtm_dangerous_keywords: str = (
        ""  # JSON string: ["keyword", ...] or empty for defaults
    )

    @model_validator(mode="after")
    def _check_thresholds(self) -> "Settings":
        if self.conversation_block_threshold <= self.conversation_warn_threshold:
            raise ValueError(
                "conversation_block_threshold must be greater than conversation_warn_threshold"
            )
        if self.mtm_block_threshold <= self.mtm_warn_threshold:
            raise ValueError(
                "mtm_block_threshold must be greater than mtm_warn_threshold"
            )
        if self.mtm_enabled not in ("true", "false", "shadow"):
            raise ValueError("mtm_enabled must be 'true', 'false', or 'shadow'")
        return self

    @model_validator(mode="after")
    def _derive_socket_defaults_from_runtime_dir(self) -> "Settings":
        """Q13.fix.f (Cx-1) — re-root socket defaults under runtime_dir.

        When the operator overrides SENTINEL_RUNTIME_DIR without also
        overriding SENTINEL_SIDECAR_SOCKET / SENTINEL_SIGNAL_SOCKET_PATH,
        the socket paths must follow runtime_dir — otherwise validate_runtime_dir
        gates on /var/run/sentinel-test/ while the client connects to the
        hardcoded /run/sentinel/..., breaking bare-metal / systemd deploys.

        Derivation rule: if the user explicitly set the socket path (via
        env var or constructor kwarg), respect it. Otherwise compute the
        default from runtime_dir. Detected via ``model_fields_set`` which
        pydantic populates only for explicitly supplied fields.
        """
        explicit = self.model_fields_set
        if "sidecar_socket" not in explicit:
            self.sidecar_socket = f"{self.runtime_dir}/sentinel-sidecar.sock"
        if "signal_socket_path" not in explicit:
            self.signal_socket_path = f"{self.runtime_dir}/signal.sock"
        return self

    @model_validator(mode="after")
    def _check_pending_action_timeouts(self) -> "Settings":
        """Q10 design D8: approval_timeout / confirmation_timeout must be
        strictly less than the shortest active session_ttl_*.

        If a pending approval or confirmation can outlive its session, the
        submit-time precondition recheck (Q10-F2/F3) cannot see the session
        state for the TTL-elapsed branch: the session has been auto-unlocked
        or purged, the recheck helper sees ``session is None``, and D7's
        permissive-on-missing branch lets the submit proceed. Enforcing
        strict ``<`` at boot closes that window.

        ``session_ttl_*`` values of 0 mean "never expire" (e.g.
        ``session_ttl_routine = 0`` — system-managed lifecycle) and are
        excluded from the minimum. If every active session TTL is 0 the
        check is vacuously satisfied.
        """
        logger.debug(
            "_check_pending_action_timeouts called",
            extra={"event": "core.config._check_pending_action_timeouts"},
        )  # auto:entry
        active_ttls = [
            self.session_ttl,
            self.session_ttl_signal,
            self.session_ttl_websocket,
            self.session_ttl_api,
            self.session_ttl_mcp,
            self.session_ttl_routine,
        ]
        # Exclude 0 == "never" per per-channel semantics (session_ttl_routine
        # is the canonical example).
        bounded_ttls = [ttl for ttl in active_ttls if ttl > 0]
        if not bounded_ttls:
            return self
        shortest_ttl = min(bounded_ttls)
        if self.approval_timeout >= shortest_ttl:
            raise ConfigInvariantError(
                "approval_timeout must be strictly less than the shortest "
                "active session_ttl_* — otherwise a pending approval can "
                "outlive its session and the submit-time precondition "
                "recheck sees `session is None` instead of `is_locked=True`. "
                f"approval_timeout={self.approval_timeout}, "
                f"shortest_session_ttl={shortest_ttl}"
            )
        if self.confirmation_timeout >= shortest_ttl:
            raise ConfigInvariantError(
                "confirmation_timeout must be strictly less than the shortest "
                "active session_ttl_* — otherwise a pending confirmation can "
                "outlive its session and the submit-time precondition "
                "recheck sees `session is None` instead of `is_locked=True`. "
                f"confirmation_timeout={self.confirmation_timeout}, "
                f"shortest_session_ttl={shortest_ttl}"
            )
        return self


settings = Settings()
