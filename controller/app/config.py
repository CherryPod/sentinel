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

    # Qwen worker (Phase 2)
    ollama_url: str = "http://sentinel-qwen:11434"
    ollama_model: str = "qwen3:14b"
    ollama_timeout: int = 120

    # Spotlighting (Phase 2)
    spotlighting_enabled: bool = True
    spotlighting_marker: str = "^"

    # Prompt Guard (Phase 2)
    prompt_guard_enabled: bool = True
    prompt_guard_model: str = "meta-llama/Llama-Prompt-Guard-2-86M"
    prompt_guard_threshold: float = 0.9

    # Claude planner (Phase 3)
    claude_api_key_file: str = "/run/secrets/claude_api_key"
    claude_model: str = "claude-sonnet-4-5-20250929"
    claude_max_tokens: int = 4096
    claude_timeout: int = 60

    # Approval (Phase 3)
    approval_timeout: int = 300

    # MQTT (Phase 3)
    mqtt_broker: str = "host.containers.internal"
    mqtt_port: int = 1883
    mqtt_topic_in: str = "sentinel/tasks"
    mqtt_topic_out: str = "sentinel/results"
    mqtt_topic_approval: str = "sentinel/approval"

    # Conversation tracking (Phase 5)
    session_ttl: int = 3600  # 1 hour
    session_max_count: int = 1000
    conversation_warn_threshold: float = 5.0
    conversation_block_threshold: float = 10.0
    conversation_enabled: bool = True


settings = Settings()
