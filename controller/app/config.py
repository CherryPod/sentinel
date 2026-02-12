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

    # Claude planner (Phase 3)
    claude_api_key_file: str = "/run/secrets/claude_api_key"

    # MQTT (Phase 3)
    mqtt_broker: str = "host.containers.internal"
    mqtt_port: int = 1883
    mqtt_topic_in: str = "sentinel/tasks"
    mqtt_topic_out: str = "sentinel/results"
    mqtt_topic_approval: str = "sentinel/approval"


settings = Settings()
