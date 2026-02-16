//! Resource limits and sidecar configuration.

/// Configuration for the sidecar's sandbox engine.
pub struct SidecarConfig {
    /// Maximum WASM memory in bytes (default: 64 MiB).
    pub max_memory_bytes: u64,
    /// Maximum fuel (instruction count) per execution (default: 1 billion).
    pub max_fuel: u64,
    /// Execution timeout in milliseconds (default: 30 seconds).
    pub timeout_ms: u64,
}

impl Default for SidecarConfig {
    fn default() -> Self {
        Self {
            max_memory_bytes: 64 * 1024 * 1024,  // 64 MiB
            max_fuel: 1_000_000_000,               // 1 billion instructions
            timeout_ms: 30_000,                    // 30 seconds
        }
    }
}
