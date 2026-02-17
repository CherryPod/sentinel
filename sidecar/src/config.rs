//! Resource limits and sidecar configuration.
//!
//! All settings can be overridden via SENTINEL_SIDECAR_* environment variables.

use std::path::PathBuf;

/// Configuration for the sidecar's sandbox engine and host functions.
pub struct SidecarConfig {
    /// Maximum WASM memory in bytes (default: 64 MiB).
    pub max_memory_bytes: u64,
    /// Maximum fuel (instruction count) per execution (default: 1 billion).
    pub max_fuel: u64,
    /// Execution timeout in milliseconds (default: 30 seconds).
    pub timeout_ms: u64,
    /// Directory containing .wasm files and tool.toml metadata.
    pub tool_dir: PathBuf,
    /// Directories that tools are allowed to read/write.
    pub allowed_paths: Vec<String>,
    /// Default HTTP request timeout in milliseconds.
    pub http_default_timeout_ms: u64,
    /// Maximum HTTP response body size in bytes.
    pub http_max_response_bytes: u64,
    /// Shell command timeout in milliseconds.
    pub shell_timeout_ms: u64,
    /// Maximum shell output size in bytes.
    pub shell_max_output_bytes: u64,
}

impl SidecarConfig {
    /// Load configuration from environment variables with defaults.
    pub fn from_env() -> Self {
        Self {
            max_memory_bytes: env_u64("SENTINEL_SIDECAR_MAX_MEMORY_BYTES", 64 * 1024 * 1024),
            max_fuel: env_u64("SENTINEL_SIDECAR_MAX_FUEL", 1_000_000_000),
            timeout_ms: env_u64("SENTINEL_SIDECAR_TIMEOUT_MS", 30_000),
            tool_dir: PathBuf::from(
                std::env::var("SENTINEL_SIDECAR_TOOL_DIR").unwrap_or_else(|_| "./wasm".into()),
            ),
            allowed_paths: std::env::var("SENTINEL_SIDECAR_ALLOWED_PATHS")
                .unwrap_or_else(|_| "/workspace".into())
                .split(',')
                .map(|s| s.trim().to_string())
                .collect(),
            http_default_timeout_ms: env_u64("SENTINEL_SIDECAR_HTTP_TIMEOUT_MS", 30_000),
            http_max_response_bytes: env_u64(
                "SENTINEL_SIDECAR_HTTP_MAX_RESPONSE_BYTES",
                10 * 1024 * 1024,
            ),
            shell_timeout_ms: env_u64("SENTINEL_SIDECAR_SHELL_TIMEOUT_MS", 30_000),
            shell_max_output_bytes: env_u64("SENTINEL_SIDECAR_SHELL_MAX_OUTPUT_BYTES", 1024 * 1024),
        }
    }
}

impl Default for SidecarConfig {
    fn default() -> Self {
        Self {
            max_memory_bytes: 64 * 1024 * 1024,       // 64 MiB
            max_fuel: 1_000_000_000,                    // 1 billion instructions
            timeout_ms: 30_000,                         // 30 seconds
            tool_dir: PathBuf::from("./wasm"),
            allowed_paths: vec!["/workspace".to_string()],
            http_default_timeout_ms: 30_000,
            http_max_response_bytes: 10 * 1024 * 1024,  // 10 MiB
            shell_timeout_ms: 30_000,
            shell_max_output_bytes: 1024 * 1024,         // 1 MiB
        }
    }
}

/// Read a u64 from an env var, falling back to a default.
fn env_u64(key: &str, default: u64) -> u64 {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}
